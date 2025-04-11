import socket
import threading
import datetime
import hashlib
import hmac
import base64
import json
import requests
import argparse
import geoip2.database
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

# ===== Known protocols as listed by IANA ===========
PROTOCOL_MAP = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 5: "ST", 6: "TCP", 7: "CBT",
    8: "EGP", 9: "IGP", 10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS", 14: "EMCON",
    15: "XNET", 16: "CHAOS", 17: "UDP", 18: "MUX", 19: "DCN-MEAS", 20: "HMP", 21: "PRM",
    22: "XNS-IDP", 23: "TRUNK-1", 24: "TRUNK-2", 25: "LEAF-1", 26: "LEAF-2", 27: "RDP",
    28: "IRTP", 29: "ISO-TP4", 30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP",
    34: "3PC", 35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++", 40: "IL",
    41: "IPv6", 42: "SDRP", 43: "IPv6-Route", 44: "IPv6-Frag", 45: "IDRP", 46: "RSVP",
    47: "GRE", 48: "DSR", 49: "BNA", 50: "ESP", 51: "AH", 52: "I-NLSP", 53: "SWIPE",
    54: "NARP", 55: "Min-IPv4", 56: "TLSP", 57: "SKIP", 58: "IPv6-ICMP", 59: "IPv6-NoNxt",
    60: "IPv6-Opts", 61: "any host internal protocol", 62: "CFTP", 63: "any local network",
    64: "SAT-EXPAK", 65: "KRYPTOLAN", 66: "RVD", 67: "IPPC", 68: "any distributed file system",
    69: "SAT-MON", 70: "VISA", 71: "IPCV", 72: "CPNX", 73: "CPHB", 74: "WSN", 75: "PVP",
    76: "BR-SAT-MON", 77: "SUN-ND", 78: "WB-MON", 79: "WB-EXPAK", 80: "ISO-IP", 81: "VMTP",
    82: "SECURE-VMTP", 83: "VINES", 84: "IPTM", 85: "NSFNET-IGP", 86: "DGP", 87: "TCF",
    88: "EIGRP", 89: "OSPFIGP", 90: "Sprite-RPC", 91: "LARP", 92: "MTP", 93: "AX.25",
    94: "IPIP", 95: "MICP", 96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP", 99: "any private encryption scheme",
    100: "GMTP", 101: "IFMP", 102: "PNNI", 103: "PIM", 104: "ARIS", 105: "SCPS", 106: "QNX",
    107: "A/N", 108: "IPComp", 109: "SNP", 110: "Compaq-Peer", 111: "IPX-in-IP", 112: "VRRP",
    113: "PGM", 114: "any 0-hop protocol", 115: "L2TP", 116: "DDX", 117: "IATP", 118: "STP",
    119: "SRP", 120: "UTI", 121: "SMP", 122: "SM", 123: "PTP", 124: "ISIS over IPv4", 125: "FIRE",
    126: "CRTP", 127: "CRUDP", 128: "SSCOPMCE", 129: "IPLT", 130: "SPS", 131: "PIPE", 132: "SCTP",
    133: "FC", 134: "RSVP-E2E-IGNORE", 135: "Mobility Header", 136: "UDPLite", 137: "MPLS-in-IP",
    138: "manet", 139: "HIP", 140: "Shim6", 141: "WESP", 142: "ROHC", 143: "Ethernet",
    144: "AGGFRAG", 145: "NSH", 146: "Homa", 147: "BIT-EMU", 253: "experimental", 254: "experimental",
    255: "Reserved"
}

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
MAXMIND_DB_PATH = config.get("maxmind_db_path", "GeoLite2-City.mmdb")  # Path to MaxMind database file
MAX_BATCH_SIZE = config.get("max_batch_size", 25)

UDP_IP = "0.0.0.0"
UDP_PORT = 5514

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
                break
            else:
                if DEBUG:
                    print(f"[!] Failed HTTP {response.status_code}: {response.text}")
        except Exception as e:
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

# ===== GET APPLICATION NAME BASED ON DESTINATION PORT USING WHATPORTIS =====
def get_application_by_port(port):
    try:
        result = subprocess.run(
            ['whatportis', str(port), '--json'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
        data = json.loads(result.stdout.decode('utf-8'))

        if data:
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
        # Split the syslog header (RFC5424 format)
        parts = line.split(" ", 7)
        if len(parts) >= 7:
            # Corrected extraction: hostname is the third field (index 2)
            hostname = parts[2]
            message = parts[7].strip()
        else:
            hostname = "Unknown"
            message = line.strip()

        # Find the start of the CSV message (RFC3339 timestamp + comma)
        for part in line.split():
            if ',' in part and part[:4].isdigit():
                fields = message.split(',')

                if len(fields) < 38:
                    if DEBUG:
                        print(f"[-] Not enough fields in message (found {len(fields)}): {message}")
                    return None

                flags = int(fields[37])
                protocol_number = int(fields[8])

                # Build the parsed log with detailed field descriptions
                parsed_log = {
                    "timestamp": datetime.datetime.fromisoformat(fields[0].replace("Z", "+00:00")).strftime('%Y-%m-%dT%H:%M:%SZ'),  # ts: Flow record timestamp, RFC3339
                    "EventCount": 1,
                    "EventVendor": "Aruba/HPE Networking",
                    "EventProduct": "CX10000",
                    "EventSchema": "CX10000",
                    "EventSchemaVersion": "10.15",
                    "EventProduct": fields[18],                                         # ASIM: EventProduct
                    "Dvc": hostname,
                    "DvcHostname": hostname,                                            # Hostname extracted from syslog header (e.g., CX10K-C)
                    "DvcOs": "CX-OS",
                    "DvcOsVersion": fields[19],                                         # ASIM: EventProductVersion
                    "DvcId": fields[20],                                                # ASIM: DvcId (e.g. serial number)
                    "DvcMacAddr": fields[21],                                           # ASIM: DvcMacAddr
                    "DvcAction": fields[1],                                             # ASIM flowaction: flow_create or flow_delete
                    "UnitID": int(fields[22]),                                          # Unit ID, this is the individual DPU in the chassis
                    "Version": fields[23],                                              # Version        
                    "vrf": fields[3],                                                   # vpcid: Source VRF UUID
                    "rule_action": fields[2],                                           # act: Allow or Deny
                    "SourceIP": fields[4],                                              # ASIM: SrcIpAddr
                    "SourcePort": int(fields[5]),                                       # Source Port
                    "DestinationIP": fields[6],                                         # ASIM: DstIpAddr
                    "DestinationPort": int(fields[7]),                                  # Destination Port
                    "NetworkProtocol": PROTOCOL_MAP.get(protocol_number, "Unknown"),    # ASIM: Network Protocol
                    "SessionId": int(fields[9]),                                        # ASIM: SessionId
                    "security_policy_id": fields[10],                                   # Security Policy ID
                    "RuleID": int(fields[11]),                                          # Rule ID
                    "RuleName": fields[12],                                             # Human readable rule name
                    "IFlowPackets": int(fields[13]),                                    # iflowpkts
                    "IFlowBytes": int(fields[14]),                                      # iflowbytes
                    "RFlowPackets": int(fields[15]),                                    # rflowpkts
                    "RFlowBytes": int(fields[16]),                                      # rflowbytes
                    "VLAN": int(fields[17]),                                            # VLAN Tag ID
                    "PolicyName": fields[24],                                           # Human readable Policy name
                    "PolicyDisplayName": fields[25],                                    # Policy name, if configured
                    "NatTranslatedSourceIP": fields[26],                                # NAT Translated source IP Address
                    "NatTranslatedDestinationIP": fields[27],                           # NAT Translated destination IP address
                    "NatTranslatedDestinationPort": int(fields[28]),                    # NAT Translated destination port
                    "EncryptionStatus": fields[29].lower() == "true",                   # Encrypted status
                    "NetworkDirection": fields[30].replace("-", "").capitalize(),       # ASIM: NetworkDirection (e.g. Fromhost)
                    "EventType": "FlowInitiated" if fields[1] == "flow_create" else "FlowTerminated",  # ASIM: EventType
                    "EventResult": "Success" if fields[2].lower() == "allow" else "Failure",  # ASIM: EventResult
                    "CreateReason": fields[31],                                         # Flow create reason
                    "DeleteReason": fields[32],                                         # Flow delete Reason
                    "SourceVrf": fields[33],                                            # Source VRF
                    "DestinationVrf": fields[34],                                       # Destination VRF
                    "DestinationVrfID": fields[35],                                     # Destination VRF ID
                    "DestinationVLAN": int(fields[36]),                                 # Destination VLAN Tag
                    "SessionFlags": flags,                                              # Session flags 64-bit bitmap
                    "SourcePrimaryVLAN": int(fields[38]),                               # Source Primary VLAN Tag
                    "DestinationPrimaryVLAN": int(fields[39]),                          # Destination Primary VLAN Tag
                    # Extracted from session_flags bitmap
                    "SessionStateless": bool(flags & (1 << 0)),                         # Bit 0: Stateless session
                    "SesssionEncrypted": bool(flags & (1 << 1)),                        # Bit 1: IPsec encrypted
                    "SessionFragmented": bool(flags & (1 << 2))                         # Bit 2: IP fragment seen
                }

                if MAXMIND_ENABLED:
                    src_geo = geoip_lookup(fields[4])
                    dst_geo = geoip_lookup(fields[6])
                    parsed_log.update({
                        **src_geo,
                        "geo_src_country": src_geo["geo_country"],
                        "geo_src_city": src_geo["geo_city"],
                        "geo_src_latitude": src_geo["geo_latitude"],
                        "geo_src_longitude": src_geo["geo_src_longitude"] if "geo_src_longitude" in src_geo else src_geo["geo_longitude"],
                        **dst_geo,
                        "geo_dst_country": dst_geo["geo_country"],
                        "geo_dst_city": dst_geo["geo_city"],
                        "geo_dst_latitude": dst_geo["geo_latitude"],
                        "geo_dst_longitude": dst_geo["geo_dst_longitude"] if "geo_dst_longitude" in dst_geo else dst_geo["geo_longitude"]
                    })

                if MAPPORT:
                    app_name, app_description = get_application_by_port(int(fields[7]))
                    parsed_log["app_name"] = app_name                                   # Application name determined by destination port
                    parsed_log["app_description"] = app_description                     # Application description determined by destination port

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
            # Add the DvcIpAddr field with the source IP from the UDP packet
            parsed["DvcIpAddr"] = addr[0]
            # Debug print after adding the DvcIpAddr field
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
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    while True:
        data, addr = sock.recvfrom(4096)
        executor.submit(handle_syslog_message, data, addr)

if __name__ == "__main__":
    start_syslog_server()
