import socket
import threading
import datetime
import hashlib
import hmac
import base64
import json
import requests
import argparse
import redis
import geoip2.database
import subprocess 
import time
from concurrent.futures import ThreadPoolExecutor

# ===== ARG PARSING =====
parser = argparse.ArgumentParser(description="Syslog to Microsoft Sentinel Forwarder")
parser.add_argument('--debug', action='store_true', help='Enable debug output')
args = parser.parse_args()
DEBUG = args.debug

# ===== CONFIG FILE READ =====
with open("sentinel_config.json") as f:
    config = json.load(f)

WORKSPACE_ID = config["workspace_id"]
SHARED_KEY = config["shared_key"]
LOG_TYPE = config.get("log_type", "PensandoFlowLog")
MAPPORT = config.get("mapport", True)
MAXMIND_ENABLED = config.get("maxmind_enabled", True)
MAXMIND_DB_PATH = config.get("maxmind_db_path", "GeoLite2-City.mmdb")  # Path to MaxMind database file, use the geoipupdate program to install. Files will be in /var/lib/GeoIP/, automate upgrades to this also following maxmind instructions
MAX_BATCH_SIZE = config.get("max_batch_size", 25)

UDP_IP = "0.0.0.0"
UDP_PORT = 5514

# ===== REDIS CLIENT =====
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0)
    redis_client.ping()
    REDIS_AVAILABLE = True
    if DEBUG:
        print("[DEBUG] Connected to Redis at localhost:6379")
except Exception as e:
    print(f"[!] Redis unavailable: {e}")
    REDIS_AVAILABLE = False

# ===== LOG BUFFER =====
log_buffer = []
buffer_lock = threading.Lock()

# ===== THREAD POOL =====
executor = ThreadPoolExecutor(max_workers=10)

# ===== AZURE SENTINEL SIGNATURE CREATION =====
def build_signature(date, content_length, method, content_type, resource):
    string_to_hash = f"{method}\n{content_length}\n{content_type}\nx-ms-date:{date}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(SHARED_KEY)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    return f'SharedKey {WORKSPACE_ID}:{encoded_hash}'

# ===== SEND TO SENTINEL =====
def send_logs(entries):
    body = json.dumps(entries)
    rfc1123date = datetime.datetime.now(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    headers = {
        "Content-Type": "application/json",
        "Log-Type": LOG_TYPE,
        "x-ms-date": rfc1123date,
        "time-generated-field": "timestamp",
        "Authorization": build_signature(rfc1123date, len(body), 'POST', 'application/json', '/api/logs')
    }
    url = f'https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01'

    for attempt in range(3):
        try:
            response = requests.post(url, headers=headers, data=body, timeout=10)
            if response.status_code == 200:
                if REDIS_AVAILABLE:
                    redis_client.incr("sentinel:logs:success")
                break
            else:
                if REDIS_AVAILABLE:
                    redis_client.incr("sentinel:logs:failure")
                if DEBUG:
                    print(f"[!] Failed HTTP {response.status_code}: {response.text}")
        except Exception as e:
            if REDIS_AVAILABLE:
                redis_client.incr("sentinel:logs:failure")
            if DEBUG:
                print(f"[!] Retry {attempt+1} failed: {e}")
            time.sleep(2 ** attempt)

    if DEBUG:
        print(f"[+] Sent {len(entries)} log(s) → {response.status_code if 'response' in locals() else 'N/A'}")

# ===== MAXMIND GEOIP LOOKUP FUNCTION USING LOCAL DATABASE =====
def geoip_lookup(ip_address):
    geo_info = {
        "geo_country": "Unknown",
        "geo_city": "Unknown",
        "geo_latitude": 0.0,
        "geo_longitude": 0.0
    }

    # Perform the lookup if MaxMind is enabled in the config file (set to true)
    if MAXMIND_ENABLED:
        try:
            reader = geoip2.database.Reader(MAXMIND_DB_PATH)
            response = reader.city(ip_address)

            geo_info = {
                "geo_country": response.country.name,
                "geo_city": response.city.name if response.city else "Unknown",
                "geo_latitude": response.location.latitude if response.location.latitude else 0.0,
                "geo_longitude": response.location.longitude if response.location.longitude else 0.0
            }
        except Exception as e:
            print(f"[!] MaxMind lookup failed for {ip_address}: {e}")

    return geo_info

# ===== GET APPLICATION NAME BASED ON DESTINATION PORT USING WHATPORTIS USING OS DIRECTLY =====
def get_application_by_port(port):
    try:
        # Run the 'whatportis' command to get the service information for the port
        result = subprocess.run(
            ['whatportis', str(port), '--json'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )

        # Parse the JSON output
        data = json.loads(result.stdout.decode('utf-8'))

        if data:
            # Return the name and description of the service if available
            app_name = data[0].get('name', 'Unknown Application')
            app_description = data[0].get('description', 'No description available')
            return app_name, app_description
        else:
            return "Unknown Application", "No description available"
    except subprocess.CalledProcessError as e:
        print(f"[!] Error with whatportis lookup: {e}")
        return "Unknown Application", "No description available"

# ===== PARSE INCOMING SYSLOG LINE =====
def parse_syslog_line(line):
    try:
        for part in line.split():
            if ',' in part and part[:4].isdigit():
                csv_start = line.find(part)
                message = line[csv_start:].strip()
                fields = message.split(',')

                if len(fields) < 38:
                    if DEBUG:
                        print(f"[-] Not enough fields in message (found {len(fields)}): {message}")
                        print(len(fields))
                    return None

                
                flags = int(fields[37]) 

                parsed_log = {
                    "timestamp": datetime.datetime.fromisoformat(fields[0].replace("Z", "+00:00")).strftime('%Y-%m-%dT%H:%M:%SZ'),  # ts: Flow record timestamp, RFC3339
                    "flow_action": fields[1],                                # flowaction: flow_create or flow_delete
                    "rule_action": fields[2],                                # act: Allow or Deny
                    "vrf": fields[3],                                        # vpcid: Source VRF UUID
                    "SourceIP": fields[4],                                   # sip: Source IP address, field name should align to Sentinel expectations for threat intel
                    "source_port": int(fields[5]),                           # sport: Source port
                    "DestinationIP": fields[6],                              # dip: Destination IP address, field name should align to Sentinel expectations for threat intel
                    "destination_port": int(fields[7]),                      # dport: Destination port
                    "protocol": int(fields[8]),                              # proto: IP protocol number
                    "session_id": int(fields[9]),                            # sessionid: Flow session ID
                    "security_policy_id": fields[10],                        # securitypolicyid: Security policy UUID
                    "rule_id": int(fields[11]),                              # ruleid: Rule hash
                    "rule_name": fields[12],                                 # rulename: Rule name
                    "iflow_packets": int(fields[13]),                        # iflowpkts: Initiator → Responder packets
                    "iflow_bytes": int(fields[14]),                          # iflowbytes: Initiator → Responder bytes
                    "rflow_packets": int(fields[15]),                        # rflowpkts: Responder → Initiator packets
                    "rflow_bytes": int(fields[16]),                          # rflowbytes: Responder → Initiator bytes
                    "vlan": int(fields[17]),                                 # vlan: VLAN ID
                    "product": fields[18],                                   # producttype: DSS
                    "sw_version": fields[19],                                # softwareversion: AOS-CX version
                    "serial_number": fields[20],                             # serialnumber: Serial number of DSS
                    "device_mac": fields[21],                                # devicemac: MAC address of DSS
                    "unit_id": int(fields[22]),                              # unitid: DSM unit ID (1 or 2)
                    "version": fields[23],                                   # version: V3
                    "policy_name": fields[24],                               # policyname: Security policy name
                    "policy_display_name": fields[25],                       # policydisplayname: Policy display name
                    "nat_translated_src_ip": fields[26],                     # nattranslatedsrcip: NAT source IP (IPv4)
                    "nat_translated_dst_ip": fields[27],                     # nattranslateddestip: NAT destination IP (IPv4)
                    "nat_translated_dst_port": fields[28],                   # nattranslateddestport: NAT destination port
                    "encrypted": fields[29].lower() == "true",               # encrypted: IPsec encryption true/false
                    "direction": fields[30],                                 # direction: from-host / uplink
                    "create_reason": fields[31],                             # createreason: Why flow was created
                    "delete_reason": fields[32],                             # deletereason: Why flow was deleted
                    "src_vrf": fields[33],                                   # srcvpcname: Pre-routed VRF name
                    "dst_vrf": fields[34],                                   # dstvpcname: Post-routed VRF name
                    "dst_vrf_id": fields[35],                                # dstvpcid: Destination VRF UUID
                    "dst_vlan": int(fields[36]),                             # dstvlan: Post-routed VLAN
                    "session_flags": flags,                                  # sessionflags: 64-bit session bitmap
                    "src_primary_vlan": int(fields[38]),                     # sourceprimaryvlan
                    "dst_primary_vlan": int(fields[39]),                     # destprimaryvlan

                    # Derived from session_flags bitmap
                    "session_stateless": bool(flags & (1 << 0)),             # Bit 0: Stateless session
                    "session_encrypted": bool(flags & (1 << 1)),             # Bit 1: IPsec encrypted
                    "session_fragmented": bool(flags & (1 << 2))             # Bit 2: IP fragment seen
                }

                # Perform GeoIP lookup if enabled
                if MAXMIND_ENABLED:
                    src_geo = geoip_lookup(fields[4])                        # Lookup the source IP
                    dst_geo = geoip_lookup(fields[6])                        # Lookup the destination IP

                    parsed_log.update({
                        **src_geo,
                        "geo_src_country": src_geo["geo_country"],
                        "geo_src_city": src_geo["geo_city"],
                        "geo_src_latitude": src_geo["geo_latitude"],
                        "geo_src_longitude": src_geo["geo_longitude"],
                        **dst_geo,
                        "geo_dst_country": dst_geo["geo_country"],
                        "geo_dst_city": dst_geo["geo_city"],
                        "geo_dst_latitude": dst_geo["geo_latitude"],
                        "geo_dst_longitude": dst_geo["geo_longitude"]
                    })

                # Add application name and description based on destination port
                if MAPPORT:
                    app_name, app_description = get_application_by_port(int(fields[7]))  # Use destination port form the log 
                    parsed_log["app_name"] = app_name
                    parsed_log["app_description"] = app_description

                if DEBUG:
                    print(f"[DEBUG] Parsed log with GeoIP info and Application:\n{json.dumps(parsed_log, indent=2)}")

                return parsed_log

        if DEBUG:
            print("[-] No valid CSV section found in syslog line.")
        return None

    except Exception as e:
        print(f"[!] Parsing error: {e}")
        return None

# ===== HANDLE SYSLOG MESSAGE =====
def handle_syslog_message(data, addr):
    try:
        log_line = data.decode('utf-8').strip()
        if DEBUG:
            print(f"[DEBUG] Raw syslog line from {addr[0]}: {log_line}")
        parsed = parse_syslog_line(log_line)
        if parsed:
            with buffer_lock:
                log_buffer.append(parsed)
                if len(log_buffer) >= MAX_BATCH_SIZE:
                    batch = log_buffer.copy()
                    log_buffer.clear()
                    executor.submit(send_logs, batch)
        else:
            if DEBUG:
                print("[-] Skipped invalid log")
    except Exception as e:
        if DEBUG:
            print(f"[!] Error handling syslog: {e}")

# ===== START SYSLOG SERVER =====
def start_syslog_server():
    print(f"[+] Syslog server on UDP {UDP_PORT} (debug={'on' if DEBUG else 'off'})")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    while True:
        data, addr = sock.recvfrom(4096)
        executor.submit(handle_syslog_message, data, addr)

if __name__ == "__main__":
    start_syslog_server()
