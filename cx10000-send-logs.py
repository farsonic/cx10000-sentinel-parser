import socket
import datetime
import uuid
import random
import time
import argparse

# === ARG PARSING ===
parser = argparse.ArgumentParser(description="Send Pensando-style syslog to local listener")
parser.add_argument('--count', type=int, default=10, help='Total number of logs to send')
parser.add_argument('--rate', type=int, default=10, help='Logs per second (1-1000)')
parser.add_argument('--host', default="127.0.0.1", help='Syslog target IP')
parser.add_argument('--port', type=int, default=5514, help='Syslog target port')
parser.add_argument('--offset', type=int, default=48, help='Timestamp offset in hours')
args = parser.parse_args()

COUNT = args.count
RATE = max(1, min(args.rate, 1000))
SYSLOG_HOST = args.host
SYSLOG_PORT = args.port
OFFSET_HOURS = args.offset
DELAY = 1.0 / RATE

# === Generate 30-field CSV payload (as strings) ===
def generate_payload(past_time):
    timestamp = past_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    fields = [
        timestamp,
        random.choice(["flow_create", "flow_delete"]),
        random.choice(["allow", "deny"]),
        str(uuid.uuid4()),                            # vrf
        f"10.29.21.{random.randint(1, 254)}",          # source_ip
        str(random.randint(1000, 65535)),              # source_port
        f"10.29.22.{random.randint(1, 254)}",          # destination_ip
        str(random.choice([22, 53, 80, 443, 3306])),   # destination_port
        str(random.choice([6, 17])),                   # protocol
        str(random.randint(100000, 999999)),           # session_id
        str(uuid.uuid4()),                             # security_policy_id
        str(random.randint(1, 99999)),                 # rule_id
        random.choice(["allow-ssh", "allow-http", "allow-mysql", "deny-all"]),
        str(random.randint(0, 1000)),                  # iflow_packets
        str(random.randint(0, 50000)),                 # iflow_bytes
        str(random.randint(0, 1000)),                  # rflow_packets
        str(random.randint(0, 50000)),                 # rflow_bytes
        str(random.randint(1, 4094)),                  # source_vlan
        "DL.10.15.1005",                               # sw_version
        "FSJ21440004",                                 # serial_number
        "0490.8100.54ce",                              # device_name
        str(random.randint(1, 10)),                    # unit_id
        "pod1-vlan21-egress",                          # policy_name
        "pod1-vlan21-egress",                          # policy_display_name
        "192.168.1.100",                               # NAT src
        "192.168.1.200",                               # NAT dst
        "8080",                                        # NAT dst port
        random.choice(["true", "false"]),              # encrypted
        "from-host",                                   # direction
        random.choice(["tcp_full_close", "aged-out", "tcp-reset", "other"])
    ]
    return ",".join(fields)

# === Format RFC5424 syslog message ===
def generate_syslog_message(payload, past_time):
    timestamp = past_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    pri = 14
    version = 1
    hostname = "myhost"
    appname = "pen-netagent"
    procid = str(random.randint(1000, 999999))
    msgid = "-"
    return f"<{pri}>{version} {timestamp} {hostname} {appname} {procid} {msgid} - {payload}"

# === MAIN ===
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for i in range(COUNT):
        past_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=OFFSET_HOURS)
        payload = generate_payload(past_time)
        syslog_message = generate_syslog_message(payload, past_time)
        sock.sendto(syslog_message.encode('utf-8'), (SYSLOG_HOST, SYSLOG_PORT))
        print(f"[+] Sent log {i + 1}/{COUNT}: {payload}")
        time.sleep(DELAY)

    sock.close()
    print(f"[✓] Sent {COUNT} logs to {SYSLOG_HOST}:{SYSLOG_PORT} at ~{RATE} logs/sec")

if __name__ == "__main__":
    main()
