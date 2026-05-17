from scapy.all import *
from collections import defaultdict
import socket
import datetime
import json
import time
import tracemalloc

tracemalloc.start()

PROFILES = {
    "server": {
        "syn_floor":  500,
        "udp_floor":  300,
        "icmp_floor": 200,
        "K":          4.0,
    },
    "workstation": {
        "syn_floor":  150,
        "udp_floor":  80,
        "icmp_floor": 60,
        "K":          3.0,
    },
    "home_iot": {
        "syn_floor":  30,
        "udp_floor":  20,
        "icmp_floor": 15,
        "K":          2.5,
    },
}

ACTIVE_PROFILE = "workstation"
PROFILE        = PROFILES[ACTIVE_PROFILE]


EMA_ALPHA = 0.4


KNOWN_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68,
    80, 110, 143, 161, 162, 179, 194,
    389, 443, 445, 465, 500, 514, 515,
    554, 587, 631, 636, 873, 993, 995,
    1080, 1194, 1433, 1434, 1521, 1723,
    3306, 3389, 5432, 5900, 6379,
    8080, 8443, 8888, 9200, 9300, 27017,
}

UNCOMMON_PORT_THRESHOLD = 6   # flag if uncommon port hits cross this


INACTIVITY_TIMEOUT = 8 * 60   # 8 minutes in seconds

BASELINE_FILE = "baseline.json"
 
def load_baseline():
    try:
        with open(BASELINE_FILE) as f:
            b = json.load(f)
        print(f"   Baseline loaded — "
              f"SYN: {b['syn']} | UDP: {b['udp']} | ICMP: {b['icmp']}")
        return b
    except FileNotFoundError:
        print(f"   WARNING: {BASELINE_FILE} not found.")
        print(f"   Run baseline_capture.py during peak traffic first.")
        print(f"   Falling back to threshold floor only.\n")
        return None

baseline = load_baseline()

def get_baseline(signal):
    if baseline is None:
        return None
    return baseline.get(signal, None)

ema_syn  = defaultdict(float)
ema_udp  = defaultdict(float)
ema_icmp = defaultdict(float)

count_syn  = defaultdict(int)
count_udp  = defaultdict(int)
count_icmp = defaultdict(int)

uncommon_port_count = defaultdict(int)

last_seen = defaultdict(float)

blocklist         = set()
blocklist_reasons = {}


SMALL_WINDOW = 5   # seconds — EMA update + flood detection
small_time   = time.time()


SUSPICIOUS_LOG = "suspicious.log"
CONFIRMED_LOG  = "confirmed.log"

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return None
    finally:
        s.close()

my_host = get_local_ip()

def get_severity(ema_val, floor):
    if ema_val >= floor * 3:  return "HIGH"
    if ema_val >= floor * 1.5: return "MEDIUM"
    return "LOW"

def log_event(level, ip, attack_type, detail=""):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = (
        f"[{timestamp}] {level} | "
        f"IP: {ip} | Profile: {ACTIVE_PROFILE} | "
        f"Type: {attack_type}"
        + (f" | {detail}" if detail else "") + "\n"
    )
    print(line, end="")
    log_file = CONFIRMED_LOG if level == "BLOCKED" else SUSPICIOUS_LOG
    with open(log_file, "a") as f:
        f.write(line)


def all_dicts():
    return [
        ema_syn, ema_udp, ema_icmp,
        count_syn, count_udp, count_icmp,
        uncommon_port_count,
        last_seen,
    ]

def purge_ip(ip):
    """Remove IP from all tracking structures."""
    for d in all_dicts():
        d.pop(ip, None)

def blocklist_ip(ip, reason, detail=""):
    blocklist.add(ip)
    blocklist_reasons[ip] = reason
    purge_ip(ip)
    log_event("BLOCKED", ip, reason, detail)


def update_ema(old_ema, new_count):
    return EMA_ALPHA * new_count + (1 - EMA_ALPHA) * old_ema

def is_anomalous(ema_val, signal_name, floor):
    if ema_val >= floor:
        return True
    b = get_baseline(signal_name)
    if b is not None and b > 0:
        if ema_val > b * PROFILE["K"]:
            return True
    return False

def detect_floods(ip):
    findings = []
    p = PROFILE

    if is_anomalous(ema_syn[ip], "syn", p["syn_floor"]):
        findings.append((
            "SYN flood",
            f"EMA={ema_syn[ip]:.1f} floor={p['syn_floor']}"
        ))

    if is_anomalous(ema_udp[ip], "udp", p["udp_floor"]):
        findings.append((
            "UDP flood",
            f"EMA={ema_udp[ip]:.1f} floor={p['udp_floor']}"
        ))

    if is_anomalous(ema_icmp[ip], "icmp", p["icmp_floor"]):
        findings.append((
            "ICMP flood",
            f"EMA={ema_icmp[ip]:.1f} floor={p['icmp_floor']}"
        ))

    return findings


def check_small_window():
    now = time.time()

    all_ips = set(
        list(count_syn.keys()) +
        list(count_udp.keys()) +
        list(count_icmp.keys())
    )

    for ip in all_ips:
        if ip in blocklist:
            continue

        ema_syn[ip]  = update_ema(ema_syn[ip],  count_syn[ip])
        ema_udp[ip]  = update_ema(ema_udp[ip],  count_udp[ip])
        ema_icmp[ip] = update_ema(ema_icmp[ip], count_icmp[ip])

        findings = detect_floods(ip)
        if findings:
            labels  = [label  for label, _      in findings]
            details = [detail for _,     detail in findings]
            blocklist_ip(ip, labels, " | ".join(details))

    for ip in list(last_seen.keys()):
        if ip in blocklist:
            continue
        if now - last_seen[ip] > INACTIVITY_TIMEOUT:
            purge_ip(ip)

    count_syn.clear()
    count_udp.clear()
    count_icmp.clear()


def catchpacket(packet):
    global small_time, my_host

    if my_host is None:
        my_host = get_local_ip()
        if my_host is None:
            return

    if not packet.haslayer(IP):
        return

    #TCP
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if src_ip in blocklist:
        return

    if dst_ip != my_host:
        return

    last_seen[src_ip] = time.time()

    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        dport = packet[TCP].dport

        if flags & 0x02 and not flags & 0x10:   # SYN only
            count_syn[src_ip] += 1

        if dport not in KNOWN_PORTS:
            uncommon_port_count[src_ip] += 1
            if uncommon_port_count[src_ip] >= UNCOMMON_PORT_THRESHOLD:
                blocklist_ip(
                    src_ip,
                    "Port scan",
                    f"uncommon ports hit={uncommon_port_count[src_ip]}"
                )
                return

    # UDP
    if packet.haslayer(UDP):
        count_udp[src_ip] += 1
        if packet[UDP].dport not in KNOWN_PORTS:
            uncommon_port_count[src_ip] += 1
            if uncommon_port_count[src_ip] >= UNCOMMON_PORT_THRESHOLD:
                blocklist_ip(
                    src_ip,
                    "Port scan",
                    f"uncommon ports hit={uncommon_port_count[src_ip]}"
                )
                return

    # ICMP echo requests only
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        count_icmp[src_ip] += 1

    # 5s window
    now = time.time()
    if now - small_time >= SMALL_WINDOW:
        check_small_window()
        small_time = now


print("=" * 55)
print("  IDS v4")
print("=" * 55)
print(f"   Host:    {my_host}")
print(f"   Profile: {ACTIVE_PROFILE}  (K={PROFILE['K']}x deviation)")
print(f"   Floors:  SYN {PROFILE['syn_floor']} | "
      f"UDP {PROFILE['udp_floor']} | "
      f"ICMP {PROFILE['icmp_floor']}")
print(f"   Port scan threshold: {UNCOMMON_PORT_THRESHOLD} uncommon ports")
print(f"   Inactivity timeout:  {INACTIVITY_TIMEOUT // 60} minutes")
print()

sniff(
    iface=["eth0", "lo"],
    prn=catchpacket,
    store=False,
)


snapshot = tracemalloc.take_snapshot()
stats = snapshot.statistics("lineno")
print("\n=== Top 5 Memory Allocations ===")
for stat in stats[:5]:
    print(stat)
current, peak = tracemalloc.get_traced_memory()
print(f"\nCurrent: {current / 1024:.2f} KB")
print(f"Peak:    {peak / 1024:.2f} KB")
