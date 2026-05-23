from scapy.all import *
from collections import defaultdict
import socket
import datetime
import json
import time
import tracemalloc
import subprocess

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

def choose_profile():
    print("Select a profile:")
    print("  1. server")
    print("  2. workstation")
    print("  3. home_iot")
    choice = input("Enter choice (1/2/3): ").strip()
    mapping = {"1": "server", "2": "workstation", "3": "home_iot"}
    if choice in mapping:
        return mapping[choice]
    else:
        print("   Invalid choice, defaulting to workstation.")
        return "workstation"

ACTIVE_PROFILE = choose_profile()
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

UNCOMMON_PORT_THRESHOLD = 6

INACTIVITY_TIMEOUT = 8 * 60   # 8 minutes

# DDoS rate limit — packets/sec allowed through when global flood detected
# iptables will DROP everything above this
DDOS_RATE_LIMIT     = "100/sec"
DDOS_RATE_BURST     = 200
ddos_rate_limit_on  = False    # track so we don't re-apply the rule repeatedly

BASELINE_FILE = "baseline.json"

def load_baseline():
    try:
        with open(BASELINE_FILE) as f:
            b = json.load(f)
        print(f"   Baseline loaded — "
              f"SYN: {b['syn']} | UDP: {b['udp']} | ICMP: {b['icmp']} | "
              f"SYN_total: {b.get('syn_total', 'N/A')} | UDP_total: {b.get('udp_total', 'N/A')}")
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

# ── Per-IP tracking ───────────────────────────────────────────────
ema_syn  = defaultdict(float)
ema_udp  = defaultdict(float)
ema_icmp = defaultdict(float)

count_syn  = defaultdict(int)
count_udp  = defaultdict(int)
count_icmp = defaultdict(int)

uncommon_port_count = defaultdict(int)
last_seen           = defaultdict(float)

blocklist         = set()
blocklist_reasons = {}

# ── Global traffic tracking (for DDoS detection) ──────────────────
global_syn_count = 0
global_udp_count = 0
global_ema_syn   = 0.0
global_ema_udp   = 0.0

SMALL_WINDOW = 5
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
    if ema_val >= floor * 3:   return "HIGH"
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

def firewall_block(ip):
    """Drop all packets from IP using iptables."""
    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
    except subprocess.CalledProcessError as e:
        print(f"   [iptables ERROR] Could not block {ip}: {e.stderr.decode().strip()}")

def firewall_rate_limit():
    """Apply global SYN+UDP rate limiting for DDoS mitigation. Manual lift required."""
    global ddos_rate_limit_on
    if ddos_rate_limit_on:
        return  # already applied

    try:
        # Allow up to DDOS_RATE_LIMIT SYNs/sec, drop the rest
        subprocess.run([
            "iptables", "-A", "INPUT",
            "-p", "tcp", "--syn",
            "-m", "limit",
            "--limit", DDOS_RATE_LIMIT,
            "--limit-burst", str(DDOS_RATE_BURST),
            "-j", "ACCEPT"
        ], check=True, capture_output=True)

        subprocess.run([
            "iptables", "-A", "INPUT",
            "-p", "tcp", "--syn",
            "-j", "DROP"
        ], check=True, capture_output=True)

        # Same for UDP
        subprocess.run([
            "iptables", "-A", "INPUT",
            "-p", "udp",
            "-m", "limit",
            "--limit", DDOS_RATE_LIMIT,
            "--limit-burst", str(DDOS_RATE_BURST),
            "-j", "ACCEPT"
        ], check=True, capture_output=True)

        subprocess.run([
            "iptables", "-A", "INPUT",
            "-p", "udp",
            "-j", "DROP"
        ], check=True, capture_output=True)

        ddos_rate_limit_on = True
        print("\n   [!] DDoS rate limiting ACTIVE — manual lift required (iptables -F)\n")

    except subprocess.CalledProcessError as e:
        print(f"   [iptables ERROR] Rate limit failed: {e.stderr.decode().strip()}")

def all_dicts():
    return [
        ema_syn, ema_udp, ema_icmp,
        count_syn, count_udp, count_icmp,
        uncommon_port_count,
        last_seen,
    ]

def purge_ip(ip):
    for d in all_dicts():
        d.pop(ip, None)

def blocklist_ip(ip, reason, detail=""):
    blocklist.add(ip)
    blocklist_reasons[ip] = reason
    purge_ip(ip)
    firewall_block(ip)
    log_event("BLOCKED", ip, reason, detail)

def update_ema(old_ema, new_count):
    return EMA_ALPHA * new_count + (1 - EMA_ALPHA) * old_ema

def is_flood(ema_val, floor):
    """Floods hit the absolute floor — direct block, no baseline check needed."""
    return ema_val >= floor

def check_small_window():
    global small_time, global_syn_count, global_udp_count
    global global_ema_syn, global_ema_udp

    now = time.time()

    # ── Per-IP flood detection ────────────────────────────────────
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

        findings = []
        p = PROFILE

        if is_flood(ema_syn[ip],  p["syn_floor"]):
            findings.append(("SYN flood",  f"EMA={ema_syn[ip]:.1f}  floor={p['syn_floor']}"))
        if is_flood(ema_udp[ip],  p["udp_floor"]):
            findings.append(("UDP flood",  f"EMA={ema_udp[ip]:.1f}  floor={p['udp_floor']}"))
        if is_flood(ema_icmp[ip], p["icmp_floor"]):
            findings.append(("ICMP flood", f"EMA={ema_icmp[ip]:.1f} floor={p['icmp_floor']}"))

        if findings:
            labels  = [l for l, _ in findings]
            details = [d for _, d in findings]
            blocklist_ip(ip, labels, " | ".join(details))

    # ── Global DDoS detection ─────────────────────────────────────
    global_ema_syn = update_ema(global_ema_syn, global_syn_count)
    global_ema_udp = update_ema(global_ema_udp, global_udp_count)

    syn_total_baseline = get_baseline("syn_total")
    udp_total_baseline = get_baseline("udp_total")

    ddos_triggered = False
    ddos_detail    = []

    if syn_total_baseline and syn_total_baseline > 0:
        if global_ema_syn > PROFILE["K"] * syn_total_baseline:
            ddos_triggered = True
            ddos_detail.append(
                f"global SYN EMA={global_ema_syn:.1f} > "
                f"{PROFILE['K']}x baseline={syn_total_baseline}"
            )

    if udp_total_baseline and udp_total_baseline > 0:
        if global_ema_udp > PROFILE["K"] * udp_total_baseline:
            ddos_triggered = True
            ddos_detail.append(
                f"global UDP EMA={global_ema_udp:.1f} > "
                f"{PROFILE['K']}x baseline={udp_total_baseline}"
            )

    if ddos_triggered:
        log_event("SUSPICIOUS", "GLOBAL", "Possible DDoS", " | ".join(ddos_detail))
        firewall_rate_limit()

    # Reset global counters
    global_syn_count = 0
    global_udp_count = 0

    # ── Inactivity eviction ───────────────────────────────────────
    for ip in list(last_seen.keys()):
        if ip in blocklist:
            continue
        if now - last_seen[ip] > INACTIVITY_TIMEOUT:
            purge_ip(ip)

    # Reset per-IP window counts
    count_syn.clear()
    count_udp.clear()
    count_icmp.clear()


def catchpacket(packet):
    global small_time, my_host
    global global_syn_count, global_udp_count

    if my_host is None:
        my_host = get_local_ip()
        if my_host is None:
            return

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if src_ip in blocklist:
        return

    if dst_ip != my_host:
        return

    last_seen[src_ip] = time.time()

    # ── TCP ───────────────────────────────────────────────────────
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        dport = packet[TCP].dport

        if flags & 0x02 and not flags & 0x10:   # SYN only
            count_syn[src_ip]  += 1
            global_syn_count   += 1

        if dport not in KNOWN_PORTS:
            uncommon_port_count[src_ip] += 1

            # Port scan: uncommon ports + baseline deviation = immediate block
            b = get_baseline("syn")
            baseline_crossed = (
                b is not None and b > 0 and
                ema_syn[src_ip] > PROFILE["K"] * b
            )
            if (uncommon_port_count[src_ip] >= UNCOMMON_PORT_THRESHOLD
                    and baseline_crossed):
                blocklist_ip(
                    src_ip,
                    "Port scan",
                    f"uncommon ports={uncommon_port_count[src_ip]} | "
                    f"SYN EMA={ema_syn[src_ip]:.1f} > {PROFILE['K']}x baseline={b}"
                )
                return

            # Uncommon ports threshold alone (no baseline file)
            elif (uncommon_port_count[src_ip] >= UNCOMMON_PORT_THRESHOLD
                    and baseline is None):
                blocklist_ip(
                    src_ip,
                    "Port scan",
                    f"uncommon ports={uncommon_port_count[src_ip]} (no baseline)"
                )
                return
            elif uncommon_port_count[src_ip] >= UNCOMMON_PORT_THRESHOLD:
                blocklist_ip(
                    src_ip, "Port scan (stealth)",
                    f"uncommon ports={uncommon_port_count[src_ip]} | no SYN (FIN/NULL/Xmas)"
                )
                return


    # ── UDP ───────────────────────────────────────────────────────
    if packet.haslayer(UDP):
        count_udp[src_ip]  += 1
        global_udp_count   += 1

        if packet[UDP].dport not in KNOWN_PORTS:
            uncommon_port_count[src_ip] += 1

            b = get_baseline("udp")
            baseline_crossed = (
                b is not None and b > 0 and
                ema_udp[src_ip] > PROFILE["K"] * b
            )
            if (uncommon_port_count[src_ip] >= UNCOMMON_PORT_THRESHOLD
                    and baseline_crossed):
                blocklist_ip(
                    src_ip,
                    "Port scan (UDP)",
                    f"uncommon ports={uncommon_port_count[src_ip]} | "
                    f"UDP EMA={ema_udp[src_ip]:.1f} > {PROFILE['K']}x baseline={b}"
                )
                return

            elif (uncommon_port_count[src_ip] >= UNCOMMON_PORT_THRESHOLD
                    and baseline is None):
                blocklist_ip(
                    src_ip,
                    "Port scan (UDP)",
                    f"uncommon ports={uncommon_port_count[src_ip]} (no baseline)"
                )
                return
            elif uncommon_port_count[src_ip] >= UNCOMMON_PORT_THRESHOLD:
                blocklist_ip(
                    src_ip, "Port scan (stealth)",
                    f"uncommon ports={uncommon_port_count[src_ip]} | no SYN (FIN/NULL/Xmas)"
                )
                return

    # ── ICMP ──────────────────────────────────────────────────────
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        count_icmp[src_ip] += 1

    # ── 5s window ─────────────────────────────────────────────────
    now = time.time()
    if now - small_time >= SMALL_WINDOW:
        check_small_window()
        small_time = now


print("=" * 55)
print("  IDS v5")
print("=" * 55)
print(f"   Host:    {my_host}")
print(f"   Profile: {ACTIVE_PROFILE}  (K={PROFILE['K']}x deviation)")
print(f"   Floors:  SYN {PROFILE['syn_floor']} | "
      f"UDP {PROFILE['udp_floor']} | "
      f"ICMP {PROFILE['icmp_floor']}")
print(f"   Port scan threshold: {UNCOMMON_PORT_THRESHOLD} uncommon ports + baseline cross")
print(f"   Inactivity timeout:  {INACTIVITY_TIMEOUT // 60} minutes")
print(f"   DDoS rate limit:     {DDOS_RATE_LIMIT} (manual lift: iptables -F)")
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
