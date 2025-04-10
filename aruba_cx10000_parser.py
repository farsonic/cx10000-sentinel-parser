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
import time
from concurrent.futures import ThreadPoolExecutor

# ===== ARG PARSING =====
parser = argparse.ArgumentParser(description="Syslog to Microsoft Sentinel Forwarder")
parser.add_argument('--debug', action='store_true', help='Enable debug output')
args = parser.parse_args()
DEBUG = args.debug

# ===== CONFIG =====
with open("sentinel_config.json") as f:
    config = json.load(f)

WORKSPACE_ID = config["workspace_id"]
SHARED_KEY = config["shared_key"]
LOG_TYPE = config.get("log_type", "PensandoFlowLog")
UDP_IP = "0.0.0.0"
UDP_PORT = 5514
MAX_BATCH_SIZE = 25

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

# ===== AZURE SIGNATURE =====
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

# ===== PARSE SYSLOG LINE =====
def parse_syslog_line(line):
    try:
        for part in line.split():
            if ',' in part and part[:4].isdigit():
                csv_start = line.find(part)
                message = line[csv_start:].strip()
                fields = message.split(',')
                if len(fields) < 30:
                    return None
                return {
                    "timestamp": datetime.datetime.fromisoformat(fields[0].replace("Z", "+00:00")).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    "flow_action": fields[1],
                    "fw_action": fields[2],
                    "vrf": fields[3],
                    "source_ip": fields[4],
                    "source_port": int(fields[5]),
                    "destination_ip": fields[6],
                    "destination_port": int(fields[7]),
                    "protocol": int(fields[8]),
                    "session_id": int(fields[9]),
                    "security_policy_id": fields[10],
                    "rule_id": int(fields[11]),
                    "rule_name": fields[12],
                    "iflow_packets": int(fields[13]),
                    "iflow_bytes": int(fields[14]),
                    "rflow_packets": int(fields[15]),
                    "rflow_bytes": int(fields[16]),
                    "source_vlan": int(fields[17]),
                    "sw_version": fields[18],
                    "serial_number": fields[19],
                    "device_name": fields[20],
                    "unit_id": int(fields[21]),
                    "policy_name": fields[22],
                    "policy_display_name": fields[23],
                    "nat_translated_src_ip": fields[24],
                    "nat_translated_dst_ip": fields[25],
                    "nat_translated_dst_port": fields[26],
                    "encrypted": fields[27].lower() == "true",
                    "direction": fields[28],
                    "create_reason": fields[29]
                }
        return None
    except Exception as e:
        if DEBUG:
            print(f"[!] Parse error: {e}")
        return None

# ===== HANDLE SYSLOG MESSAGE =====
def handle_syslog_message(data, addr):
    try:
        log_line = data.decode('utf-8').strip()
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
            print(f"[!] Error handling message: {e}")

# ===== START SERVER =====
def start_syslog_server():
    print(f"[+] Syslog server on UDP {UDP_PORT} (debug={'on' if DEBUG else 'off'})")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    while True:
        data, addr = sock.recvfrom(4096)
        executor.submit(handle_syslog_message, data, addr)

if __name__ == "__main__":
    start_syslog_server()
