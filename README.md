# IDS v5 — Intrusion Detection System

A Python-based network IDS using Scapy that detects and blocks SYN floods, UDP floods, ICMP floods, port scans (including stealth scans), and global DDoS attacks in real time.

---

## Requirements

```bash
pip install scapy
sudo apt install iptables
```

> Must be run as **root** (required for raw packet capture and iptables).

---

## Setup

### 1. Capture a baseline (recommended)

Run `baseline_capture.py` during normal/peak traffic first. This generates `baseline.json` which enables anomaly-based detection on top of the flood thresholds.

```bash
sudo python3 baseline_capture.py
```

Without a baseline, the IDS falls back to **threshold-floor-only** detection.

### 2. Choose a profile

Edit `ids.py` and set `ACTIVE_PROFILE` to match your environment:

| Profile | Use case | SYN floor | UDP floor | ICMP floor |
|---|---|---|---|---|
| `server` | High-traffic servers | 500 | 300 | 200 |
| `workstation` | Office machines | 150 | 80 | 60 |
| `home_iot` | Home / IoT devices | 30 | 20 | 15 |

```python
ACTIVE_PROFILE = "workstation"   # change this
```

### 3. Run

```bash
sudo python3 ids.py
```

---

## Detection Capabilities

| Attack | Method | Action |
|---|---|---|
| SYN flood | EMA > floor threshold | Block IP via iptables |
| UDP flood | EMA > floor threshold | Block IP via iptables |
| ICMP flood | EMA > floor threshold | Block IP via iptables |
| Port scan (`-sS`) | Uncommon ports + SYN EMA crosses baseline | Block IP |
| Stealth scan (`-sN`, `-sF`, `-sX`, `-sW`, `-sA`) | Uncommon ports ≥ threshold (no SYN needed) | Block IP |
| Global DDoS | Global EMA > K × baseline | Rate limit via iptables |

---

## How It Works

### EMA (Exponential Moving Average)
Traffic is tracked per IP using EMA with `alpha=0.4` over a 5-second window. This smooths out spikes while staying responsive to sustained floods.

### Flood detection
If a per-IP EMA crosses the profile floor, the IP is immediately blocked regardless of baseline.

### Port scan detection
Tracks uncommon ports (ports not in the known-good list) per IP. Blocking triggers on:
- `uncommon_ports ≥ 6` **and** SYN EMA crosses `K × baseline` (when baseline file exists)
- `uncommon_ports ≥ 6` **and** no baseline file loaded
- `uncommon_ports ≥ 6` **alone** — catches stealth scans (NULL/FIN/Xmas) where SYN EMA never rises

### Global DDoS detection
Aggregates SYN and UDP counts globally. If the global EMA exceeds `K × baseline`, a rate-limit rule is applied via iptables allowing only `100/sec` through (burst 200). **Manual lift required:**
```bash
sudo iptables -F
```

### Inactivity eviction
IPs with no traffic for 8 minutes are purged from memory to prevent unbounded growth.

---

## Logs

| File | Contains |
|---|---|
| `suspicious.log` | Anomaly alerts (not yet blocked) |
| `confirmed.log` | Blocked IPs with reason and detail |

Log format:
```
[2026-05-23 06:43:00] BLOCKED | IP: 10.0.0.5 | Profile: workstation | Type: Port scan (stealth) | uncommon ports=8 | FIN/NULL/Xmas
```

---

## Configuration Reference

```python
EMA_ALPHA = 0.4                  # Smoothing factor (higher = more reactive)
UNCOMMON_PORT_THRESHOLD = 6      # Uncommon port hits before port scan block
INACTIVITY_TIMEOUT = 8 * 60     # Seconds before evicting idle IPs
DDOS_RATE_LIMIT = "100/sec"     # Packets/sec allowed during DDoS mitigation
DDOS_RATE_BURST = 200           # Burst allowance
SMALL_WINDOW = 5                # Seconds per EMA evaluation window
K = 3.0                         # Baseline multiplier (set per profile)
```

### Known ports list
The IDS treats ~50 well-known ports (22, 80, 443, 3306, etc.) as normal. TCP/UDP traffic to any port outside this list increments the uncommon port counter per IP.

---

## Lifting Blocks

**Unblock a specific IP:**
```bash
sudo iptables -D INPUT -s <IP> -j DROP
```

**Lift DDoS rate limiting (flush all rules):**
```bash
sudo iptables -F
```

**View current rules:**
```bash
sudo iptables -L -n -v
```

---

## Notes

- Tested on Kali Linux with VirtualBox NAT networking
- Scapy sniffs on `eth0` and `lo` by default — change the `iface` list in `sniff()` if your interface differs (`ip a` to check)
- NULL/FIN/Xmas scans may show as `open|filtered` in nmap on Linux targets (RFC 793 behaviour) — this is expected and does not affect IDS detection
