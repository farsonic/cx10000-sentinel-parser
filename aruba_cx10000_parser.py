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

# ===== Known protocols as listed by IANA ==========
PROTOCOL_MAP = {
    6: "TCP", 17: "UDP", 1: "ICMP"
    # Add more as needed
}

# ===== ARG PARSING =====
parser = argparse.ArgumentParser(description="Syslog to Microsoft Sentinel Forwarder")
parser.add_argument('--debug', action='store_true', help='Enable debug output')
parser.add_argument('--json', action='store_true', help='Dump the JSON payload being sent to Sentinel')
parser.add_argument('--header', action='store_true', help='Dump the HTTP headers being used to send logs')
parser.add_argument('--url', action='store_true', help='Print the Sentinel URL being posted to')
args = parser.parse_args()
DEBUG = args.debug
DUMP_JSON = args.json
DUMP_HEADER = args.header
DUMP_URL = args.url

# ===== CONFIG FILE READ =====
with open("sentinel_config.json") as f:
    config = json.load(f)

WORKSPACE_ID = config["workspace_id"]
SHARED_KEY = config["shared_key"]
LOG_TYPE = config.get("log_type", "PensandoFlowLog")
MAPPORT = config.get("mapport", True)
MAXMIND_ENABLED = config.get("maxmind_enabled", True)
MAXMIND_DB_PATH = config.get("maxmind_db_path", "GeoLite2-City.mmdb")
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
    body = json.dumps(entries, indent=2 if DUMP_JSON else None)
    rfc1123date = datetime.datetime.now(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    headers = {
        "Content-Type": "application/json",
        "Log-Type": LOG_TYPE,
        "x-ms-date": rfc1123date,
        "time-generated-field": "timestamp",
        "Authorization": build_signature(rfc1123date, len(body), 'POST', 'application/json', '/api/logs')
    }
    url = f'https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01'

    if DUMP_HEADER:
        print("[HEADER DUMP] HTTP headers being sent to Sentinel:")
        print(json.dumps(headers, indent=2))

    if DUMP_JSON:
        print("[JSON DUMP] Payload being sent:")
        print(body)

    if DUMP_URL:
        print(f"[URL] {url}")

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

# ===== PARSE INCOMING SYSLOG LINE =====
def parse_syslog_line(line):
    try:
        parts = line.split(" ", 7)
        if len(parts) >= 7:
            hostname = parts[2]
            message = parts[7].strip()
        else:
            hostname = "Unknown"
            message = line.strip()

        for part in line.split():
            if ',' in part and part[:4].isdigit():
                fields = message.split(',')

                if len(fields) < 40:
                    if DEBUG:
                        print(f"[-] Not enough fields in message (found {len(fields)}): {message}")
                    return None

                flags = int(fields[37])
                protocol_number = int(fields[8])

                parsed_log = {
                    "timestamp": datetime.datetime.fromisoformat(fields[0].replace("Z", "+00:00")).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    "EventCount": 1,
                    "EventVendor": "Aruba/HPE Networking",
                    "EventProduct": "DSS",
                    "EventSchema": "CX10000",
                    "EventSchemaVersion": "10.15",
                    "Dvc": hostname,
                    "DvcHostname": hostname,
                    "DvcOs": "CX-OS",
                    "DvcOsVersion": fields[19],
                    "DvcId": fields[20],
                    "DvcMacAddr": fields[21],
                    "DvcAction": fields[1],
                    "UnitID": int(fields[22]),
                    "Version": fields[23],
                    "vrf": fields[3],
                    "rule_action": fields[2],
                    "SourceIP": fields[4],
                    "SourcePort": int(fields[5]),
                    "DestinationIP": fields[6],
                    "DestinationPort": int(fields[7]),
                    "NetworkProtocol": PROTOCOL_MAP.get(protocol_number, "Unknown"),
                    "SessionId": int(fields[9]),
                    "security_policy_id": fields[10],
                    "RuleID": int(fields[11]),
                    "RuleName": fields[12],
                    "IFlowPackets": int(fields[13]),
                    "IFlowBytes": int(fields[14]),
                    "RFlowPackets": int(fields[15]),
                    "RFlowBytes": int(fields[16]),
                    "VLAN": int(fields[17]),
                    "PolicyName": fields[24],
                    "PolicyDisplayName": fields[25],
                    "NatTranslatedSourceIP": fields[26],
                    "NatTranslatedDestinationIP": fields[27],
                    "NatTranslatedDestinationPort": int(fields[28]),
                    "EncryptionStatus": fields[29].lower() == "true",
                    "NetworkDirection": fields[30].replace("-", "").capitalize(),
                    "EventType": "FlowInitiated" if fields[1] == "flow_create" else "FlowTerminated",
                    "EventResult": "Success" if fields[2].lower() == "allow" else "Failure",
                    "CreateReason": fields[31],
                    "DeleteReason": fields[32],
                    "SourceVrf": fields[33],
                    "DestinationVrf": fields[34],
                    "DestinationVrfID": fields[35],
                    "DestinationVLAN": int(fields[36]),
                    "SessionFlags": flags,
                    "SourcePrimaryVLAN": int(fields[38]),
                    "DestinationPrimaryVLAN": int(fields[39]),
                    "SessionStateless": bool(flags & (1 << 0)),
                    "SesssionEncrypted": bool(flags & (1 << 1)),
                    "SessionFragmented": bool(flags & (1 << 2))
                }

                return parsed_log

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
            parsed["DvcIpAddr"] = addr[0]
            if DEBUG:
                print(f"[DEBUG] Parsed log after adding DvcIpAddr:\n{json.dumps(parsed, indent=2)}")
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
    print(f"[+] Syslog forwarder is running successfully and listening on {UDP_IP}:{UDP_PORT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    while True:
        data, addr = sock.recvfrom(4096)
        executor.submit(handle_syslog_message, data, addr)

if __name__ == "__main__":
    start_syslog_server()
