from scapy.all import *
import socket
import json
import time
from collections import defaultdict

# ── How long to capture (seconds) ────────────────────────────────
# Run this during your busiest traffic period (e.g. 9pm peak).
# Longer = more accurate baseline. 30 minutes recommended.
CAPTURE_DURATION = 30 * 60   # 30 minutes

WINDOW_SIZE = 5               # same as IDS — counts bucketed per 5s
OUTPUT_FILE = "baseline.json"
# ─────────────────────────────────────────────────────────────────

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

# Raw counters for current window
count_syn  = defaultdict(int)
count_udp  = defaultdict(int)
count_icmp = defaultdict(int)

# All per-window observations across all IPs
# Each entry is one IP's count for one window
all_syn_obs  = []
all_udp_obs  = []
all_icmp_obs = []

window_start  = time.time()
capture_start = time.time()
windows_seen  = 0

def flush_window():
    """
    At end of each 5s window, record every active IP's counts
    as individual observations. These represent what a normal
    IP looks like in a single window.
    """
    global windows_seen

    all_ips = set(
        list(count_syn.keys()) +
        list(count_udp.keys()) +
        list(count_icmp.keys())
    )

    for ip in all_ips:
        all_syn_obs.append(count_syn[ip])
        all_udp_obs.append(count_udp[ip])
        all_icmp_obs.append(count_icmp[ip])

    count_syn.clear()
    count_udp.clear()
    count_icmp.clear()

    windows_seen += 1
    elapsed = int(time.time() - capture_start)
    print(f"\r   Capturing... {elapsed}s / {CAPTURE_DURATION}s | "
          f"windows: {windows_seen} | "
          f"observations: {len(all_syn_obs)}", end="", flush=True)

def catchpacket(packet):
    global window_start

    if my_host is None:
        return
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if dst_ip != my_host:
        return

    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if flags & 0x02 and not flags & 0x10:  # SYN only
            count_syn[src_ip] += 1

    if packet.haslayer(UDP):
        count_udp[src_ip] += 1

    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        count_icmp[src_ip] += 1

    if time.time() - window_start >= WINDOW_SIZE:
        flush_window()
        window_start = time.time()

    # Stop sniffing after capture duration
    if time.time() - capture_start >= CAPTURE_DURATION:
        return True  # signals scapy to stop

def compute_mean(observations):
    if not observations:
        return 0.0
    return round(sum(observations) / len(observations), 4)

# ── Main ──────────────────────────────────────────────────────────

print("=" * 55)
print("  Baseline Capture")
print("=" * 55)
print(f"  Host:     {my_host}")
print(f"  Duration: {CAPTURE_DURATION // 60} minutes")
print(f"  Output:   {OUTPUT_FILE}")
print(f"\n  Run this during your peak traffic window.")
print(f"  Starting capture...\n")

sniff(
    iface=["eth0", "lo"],
    prn=catchpacket,
    store=False,
    timeout=CAPTURE_DURATION + 10,
)

# Flush any remaining partial window
flush_window()

baseline = {
    "syn":  compute_mean(all_syn_obs),
    "udp":  compute_mean(all_udp_obs),
    "icmp": compute_mean(all_icmp_obs),
    "meta": {
        "capture_duration_s": CAPTURE_DURATION,
        "windows_captured":   windows_seen,
        "total_observations": len(all_syn_obs),
        "captured_at":        time.strftime("%Y-%m-%d %H:%M:%S"),
    }
}

with open(OUTPUT_FILE, "w") as f:
    json.dump(baseline, f, indent=2)

print(f"\n\n  Baseline saved to {OUTPUT_FILE}")
print(f"  SYN  mean: {baseline['syn']}  packets/window")
print(f"  UDP  mean: {baseline['udp']}  packets/window")
print(f"  ICMP mean: {baseline['icmp']} packets/window")
print(f"  Windows captured: {windows_seen}")
