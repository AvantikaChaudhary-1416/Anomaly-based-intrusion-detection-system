"""
infer_my_host.py

Infers `my_host` (your machine's IP) for each pcap in a directory, using:
  1. College subnet prefixes (172.19.76.x, 172.23.x.x) as a hard filter
  2. External-destination fanout as a tiebreaker (your host talks to many
     external IPs; other LAN devices like the gateway/AP usually don't)

Usage:
    python infer_my_host.py /path/to/pcap_folder

Requires scapy (same dependency you already use for baseline_capture.py).
Outputs a filename -> inferred_ip mapping printed to stdout AND saved to
inferred_hosts.json, so you can spot-check it before trusting it.

IMPORTANT: Edit KNOWN_PREFIXES below to match your actual DHCP scope(s)
before running. If you're not sure whether it's a /24 or wider, start
broad (e.g. "172.19.76." and "172.23.") and narrow later.
"""

import sys
import os
import glob
import json
import ipaddress
from collections import defaultdict
from scapy.all import PcapReader, IP

# ── Config — EDIT THIS to match your actual networks ──────────────
# One list covering every network you've ever captured on. The script
# doesn't care which network a given pcap came from — it just looks for
# ANY ip matching ANY of these prefixes, per pcap, independently.
KNOWN_PREFIXES = [
    "172.19.76.",   # college
    "172.27.",      # college
    "192.168.43.",  # home (your phone hotspot / router subnet)
]
# ────────────────────────────────────────────────────────────────


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def matches_known_prefix(ip):
    return any(ip.startswith(p) for p in KNOWN_PREFIXES)


def analyze_pcap(path):
    """Returns list of (ip, external_fanout, total_packets) for candidate
    IPs in this pcap, sorted by external_fanout descending."""
    # candidate_ip -> set of external dst ips it talked to
    fanout = defaultdict(set)
    # candidate_ip -> total packet count where it appears as src or dst
    pkt_count = defaultdict(int)

    try:
        reader = PcapReader(path)
    except Exception as e:
        print(f"  [error] could not open {path}: {e}")
        return []

    for pkt in reader:
        if not pkt.haslayer(IP):
            continue
        src, dst = pkt[IP].src, pkt[IP].dst

        for ip in (src, dst):
            if matches_known_prefix(ip):
                pkt_count[ip] += 1

        # fanout: count external (non-private) destinations reached FROM
        # a candidate source
        if matches_known_prefix(src) and not is_private(dst):
            fanout[src].add(dst)
        if matches_known_prefix(dst) and not is_private(src):
            fanout[dst].add(src)

    reader.close()

    candidates = []
    all_ips = set(pkt_count.keys()) | set(fanout.keys())
    for ip in all_ips:
        candidates.append((ip, len(fanout.get(ip, set())), pkt_count.get(ip, 0)))

    candidates.sort(key=lambda x: (-x[1], -x[2]))
    return candidates


def main():
    if len(sys.argv) < 2:
        print("Usage: python infer_my_host.py /path/to/pcap_folder")
        sys.exit(1)

    target = sys.argv[1]
    if os.path.isdir(target):
        pcap_files = sorted(glob.glob(os.path.join(target, "*.pcap")))
    else:
        pcap_files = [target]

    if not pcap_files:
        print(f"No .pcap files found in {target}")
        sys.exit(1)

    print(f"Analyzing {len(pcap_files)} pcap(s)...\n")
    print(f"Known network prefixes in use: {KNOWN_PREFIXES}\n")

    results = {}
    ambiguous = []

    for path in pcap_files:
        fname = os.path.basename(path)
        candidates = analyze_pcap(path)

        if not candidates:
            print(f"{fname:40s} -> NO MATCH (no IP in given prefixes found — check prefixes or capture)")
            results[fname] = None
            continue

        top = candidates[0]
        results[fname] = top[0]

        # flag as ambiguous if the top two candidates are close in fanout
        # (within 20% of each other) — worth a manual look
        note = ""
        if len(candidates) > 1:
            second = candidates[1]
            if top[1] > 0 and second[1] >= 0.8 * top[1]:
                note = f"  [ambiguous — runner-up {second[0]} had fanout {second[1]} vs top {top[1]}]"
                ambiguous.append(fname)

        print(f"{fname:40s} -> {top[0]:16s} "
              f"(external fanout: {top[1]}, packets: {top[2]}){note}")

        # show up to 3 runner-ups for transparency
        if len(candidates) > 1:
            for ip, fo, pc in candidates[1:4]:
                print(f"{'':40s}    runner-up: {ip:16s} fanout={fo} packets={pc}")

    out_path = os.path.join(os.path.dirname(os.path.abspath(target)) if not os.path.isdir(target) else target,
                             "inferred_hosts.json")
    # always write next to script invocation dir if target dir isn't writable
    try:
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)
    except Exception:
        out_path = "inferred_hosts.json"
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)

    print(f"\nSaved mapping to {out_path}")
    print(f"\n{len(results)} files processed, {sum(1 for v in results.values() if v)} resolved, "
          f"{sum(1 for v in results.values() if v is None)} unresolved.")
    if ambiguous:
        print(f"\n{len(ambiguous)} file(s) flagged ambiguous — worth a manual double-check:")
        for f in ambiguous:
            print(f"  - {f}")


if __name__ == "__main__":
    main()