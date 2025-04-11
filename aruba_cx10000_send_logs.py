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

# === Generate a random public or private IP ===
def generate_ip(is_public=True):
    if is_public:
        return f"8.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    else:
        ip_ranges = [
            f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        ]
        return random.choice(ip_ranges)

# === Generate aligned 40-field CSV payload ===
def generate_payload(past_time):
    timestamp = past_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Session flags (64-bit bitmap)
    stateless = random.choice([0, 1])    # bit 0
    encrypted = random.choice([0, 1])    # bit 1
    fragmented = random.choice([0, 1])   # bit 2
    session_flags = (stateless << 0) | (encrypted << 1) | (fragmented << 2)

    fields = [
        timestamp,                                     # 0 - ts
        random.choice(["flow_create", "flow_delete"]),# 1 - flowaction
        random.choice(["allow", "deny"]),             # 2 - act
        str(uuid.uuid4()),                             # 3 - vpcid
        generate_ip(is_public=False),                  # 4 - sip
        str(random.randint(1000, 65535)),              # 5 - sport
        generate_ip(is_public=True),                   # 6 - dip
        str(random.choice([22, 53, 80, 443, 3306])),   # 7 - dport
        str(random.choice([6, 17])),                   # 8 - proto
        str(random.randint(100000, 999999)),           # 9 - sessionid
        str(uuid.uuid4()),                             # 10 - securitypolicyid
        str(random.randint(1, 99999)),                 # 11 - ruleid
        random.choice(["allow-ssh", "allow-http", "allow-mysql", "deny-all"]),  # 12 - rulename
        str(random.randint(0, 1000)),                  # 13 - iflowpkts
        str(random.randint(0, 50000)),                 # 14 - iflowbytes
        str(random.randint(0, 1000)),                  # 15 - rflowpkts
        str(random.randint(0, 50000)),                 # 16 - rflowbytes
        str(random.randint(1, 4094)),                  # 17 - vlan
        "DSS",                                         # 18 - producttype
        "10.14.1001",                                  # 19 - softwareversion
        "SN0123456789",                                # 20 - serialnumber
        "00:11:22:33:44:55",                           # 21 - devicemac
        str(random.randint(1, 2)),                     # 22 - unitid
        "V3",                                          # 23 - version
        "policy-1",                                    # 24 - policyname
        "Policy Display Name",                         # 25 - policydisplayname
        "192.168.100.1",                               # 26 - nattranslatedsrcip
        "192.168.200.1",                               # 27 - nattranslateddestip
        "8080",                                        # 28 - nattranslateddestport
        random.choice(["true", "false"]),              # 29 - encrypted
        random.choice(["from-host", "uplink"]),        # 30 - direction
        random.choice(["flow_miss", "flow_sync", "vmotion"]),         # 31 - createreason
        random.choice(["aging", "tcp_full_close", "tcp_rst"]),        # 32 - deletereason
        str(uuid.uuid4()),                             # 33 - srcvpcname
        str(uuid.uuid4()),                             # 34 - dstvpcname
        str(uuid.uuid4()),                             # 35 - dstvpcid
        str(random.randint(1, 4094)),                  # 36 - dstvlan
        str(session_flags),                            # 37 - sessionflags
        str(random.randint(1, 4094)),                  # 38 - sourceprimaryvlan
        str(random.randint(1, 4094))                   # 39 - destprimaryvlan
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
