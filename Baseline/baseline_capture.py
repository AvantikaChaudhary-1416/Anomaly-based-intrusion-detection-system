import socket
import ipaddress
import os
import glob as glob_module   
import datetime as dt_module   
import json
from collections import defaultdict
from scapy.all import *

# ── Config ────────────────────────────────────────────────────────
WINDOW_SIZE       = 5         # window bucket size (seconds)—matches live IDS
FLOW_IDLE_TIMEOUT = 120       # seconds of inactivity before a flow is "closed"
IP_WINDOW_SIZE_S  = 300       # 5 minutes — exceeds FLOW_IDLE_TIMEOUT so flows rarely fragment
                               # across window boundaries; avoids sparsity vs. per-5s granularity
BASELINE_FILE     = "baseline.json"
FLOWS_FILE        = "flows.json"
WINDOWS_FILE      = "windows.json"     # raw per-5s-window feature rows for ML training
IP_WINDOWS_FILE   = "ip_windows.json"  # NEW: raw per-IP, per-5min feature rows for ML training
AUTOSAVE_EVERY_N_WINDOWS = 60   # write files every ~5min (60 * 5s) so nothing is lost on a hard kill
# No fixed capture duration — runs until you stop it with Ctrl+C.
# ─────────────────────────────────────────────────────────────────

TIME_BUCKETS = [
    (0, 6,  'night'),
    (6, 9,  'early_morning'),
    (9, 12, 'morning'),
    (12, 17, 'afternoon'),
    (17, 21, 'evening'),
    (21, 24, 'late_night'),
]


def get_time_bucket(ts=None):
    hour = dt_module.datetime.fromtimestamp(ts if ts is not None else time.time()).hour
    for start, end, name in TIME_BUCKETS:
        if start <= hour < end:
            return name
    return 'night'


TIME_BUCKET_NAMES = [name for _, _, name in TIME_BUCKETS]

FLAGS = ['syn', 'ack', 'fin', 'rst', 'psh', 'urg']
TCP_FLAG_BITS = {'fin': 0x01, 'syn': 0x02, 'rst': 0x04,
                 'psh': 0x08, 'ack': 0x10, 'urg': 0x20}
DIRECTIONS = ['inbound', 'outbound']
CLASSES = ['internal', 'external']

COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143,
    443, 445, 465, 587, 993, 995, 3306, 3389, 5353, 8080, 8443,
}

EMA_ALPHA = 0.3
HALF_OPEN_STALE_S = 3


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None
    finally:
        s.close()


def get_active_iface():
    try:
        iface = conf.route.route("8.8.8.8")[0]
        if iface:
            return iface
    except Exception:
        pass
    local_ip = get_local_ip()
    if local_ip:
        for ifname in get_if_list():
            try:
                if get_if_addr(ifname) == local_ip:
                    return ifname
            except Exception:
                continue
    return None


def is_internal(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


my_host = get_local_ip()
my_iface = get_active_iface()

# ── Simulated time (packet-clock, not wall-clock) ──────────────────
# time.time() only reflects real elapsed seconds. During OFFLINE replay
# of a pcap, thousands of packets get processed in a fraction of a real
# second, so time.time()-based window flushing and flow-idle-expiry
# never fire correctly — windows never close, flows never expire, and
# peak_concurrent_flows balloons to nonsense (this is what caused the
# 570/490 peak_concurrent_flows values). Live capture still uses real
# wall-clock time (sim_time stays None until the first offline packet
# sets it), so this doesn't change live-capture behavior at all.
sim_time = None


def now():
    """Current time for all window/expiry/handshake logic. Uses the pcap's
    own packet timestamps when replaying offline; falls back to real
    wall-clock time during live capture."""
    return sim_time if sim_time is not None else time.time()
# ─────────────────────────────────────────────────────────────────

# Single-file override still works: python baseline_capture.py file.pcap 172.19.76.166
if len(sys.argv) > 2:
    my_host = sys.argv[2]
    print(f"  [override] Using explicit host IP for this pcap: {my_host}")

# ============================================================
# PART 1 — WINDOW-LEVEL STATS
# ============================================================
window_counts = {
    'inbound':  defaultdict(lambda: defaultdict(int)),
    'outbound': defaultdict(lambda: defaultdict(int)),
}
window_start = None

per_ip_obs = {
    b: {d: {c: defaultdict(list) for c in CLASSES} for d in DIRECTIONS} for b in TIME_BUCKET_NAMES
}
global_obs = {
    b: {d: {c: defaultdict(list) for c in CLASSES} for d in DIRECTIONS} for b in TIME_BUCKET_NAMES
}
ip_class_cache = {}

window_records = []

window_ports = {d: {c: set() for c in CLASSES} for d in DIRECTIONS}
window_uncommon = {d: {c: 0 for c in CLASSES} for d in DIRECTIONS}

ema_state = {d: {c: {} for c in CLASSES} for d in DIRECTIONS}


def update_ema(direction, cls, feature, value):
    prev = ema_state[direction][cls].get(feature)
    ema = value if prev is None else (EMA_ALPHA * value + (1 - EMA_ALPHA) * prev)
    ema_state[direction][cls][feature] = ema
    return round(ema, 4)


def classify(ip):
    cls = ip_class_cache.get(ip)
    if cls is None:
        cls = 'internal' if is_internal(ip) else 'external'
        ip_class_cache[ip] = cls
    return cls


handshake_state = {}
half_open_by_ip = defaultdict(set)


def track_handshake(pkt, key, src_ep, dst_ep):
    if not pkt.haslayer(TCP):
        return
    flags = pkt[TCP].flags
    is_syn    = bool(flags & TCP_FLAG_BITS['syn']) and not bool(flags & TCP_FLAG_BITS['ack'])
    is_synack = bool(flags & TCP_FLAG_BITS['syn']) and bool(flags & TCP_FLAG_BITS['ack'])
    is_ack    = bool(flags & TCP_FLAG_BITS['ack']) and not bool(flags & TCP_FLAG_BITS['syn'])
    is_rstfin = bool(flags & (TCP_FLAG_BITS['rst'] | TCP_FLAG_BITS['fin']))

    if is_syn:
        role = 'we_initiated' if src_ep[0] == my_host else 'they_initiated'
        handshake_state[key] = {
            'src_ip': src_ep[0], 'dst_ip': dst_ep[0], 'syn_time': now(),
            'seen_synack': False, 'seen_finalack': False, 'role': role,
        }
        if role == 'they_initiated':
            half_open_by_ip[src_ep[0]].add(key)
            n = len(half_open_by_ip[src_ep[0]])
            if n > ip_summary[src_ep[0]]['peak_concurrent_half_open']:
                ip_summary[src_ep[0]]['peak_concurrent_half_open'] = n
        return

    st = handshake_state.get(key)
    if st is None:
        return

    if is_synack:
        st['seen_synack'] = True
    elif is_ack and st['seen_synack'] and not st['seen_finalack']:
        st['seen_finalack'] = True
        half_open_by_ip[st['src_ip']].discard(key)
        handshake_state.pop(key, None)
    elif is_rstfin:
        half_open_by_ip[st['src_ip']].discard(key)
        handshake_state.pop(key, None)


def sweep_stale_handshakes():
    now_t = now()
    stale = [k for k, st in handshake_state.items() if now_t - st['syn_time'] > HALF_OPEN_STALE_S]
    for k in stale:
        st = handshake_state[k]
        if st['role'] == 'we_initiated' and not st['seen_synack']:
            handshake_state.pop(k, None)


ip_summary = defaultdict(lambda: {
    'total_flows': 0, 'total_bytes': 0, 'total_duration_s': 0.0,
    'currently_active_flows': 0, 'peak_concurrent_flows': 0,
    'peak_concurrent_half_open': 0,
    'unique_dst_ports_total': 0, 'unique_dst_ips_total': 0,
    'dns_queries_sent_to_this_ip': 0, 'dns_responses_unmatched': 0,
    'flag_counts': defaultdict(int),
})
ip_window_start = None
ip_window_records = []

scan_track = defaultdict(lambda: {'dst_ports': set(), 'dst_ips': set()})


def track_scan_shape(src_ip, dst_ip, dst_port):
    t = scan_track[src_ip]
    t['dst_ports'].add(dst_port)
    t['dst_ips'].add(dst_ip)
    ip_summary[src_ip]['unique_dst_ports_total'] = len(t['dst_ports'])
    ip_summary[src_ip]['unique_dst_ips_total'] = len(t['dst_ips'])


pending_dns = {}
DNS_PENDING_TIMEOUT_S = 10


def track_dns(pkt):
    if not (pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return

    if pkt[UDP].sport == 5353 or pkt[UDP].dport == 5353:
        return   # mDNS is gratuitous/multicast — not real query/response pairs, skip it
    dns = pkt[DNS]
    ip = pkt[IP]
    now_t = now()

    if dns.qr == 0:
        if ip.src == my_host:
            pending_dns[(ip.dst, dns.id)] = now_t
            ip_summary[ip.dst]['dns_queries_sent_to_this_ip'] += 1
        return

    resp_size = len(pkt)
    key = (ip.src, dns.id)
    had_pending = pending_dns.pop(key, None) is not None

    dns_window_stats['responses'] += 1
    dns_window_stats['bytes'] += resp_size
    if not had_pending:
        dns_window_stats['unmatched'] += 1
        ip_summary[ip.src]['dns_responses_unmatched'] += 1

    if len(pending_dns) > 500:
        stale = [k for k, t in pending_dns.items() if now_t - t > DNS_PENDING_TIMEOUT_S]
        for k in stale:
            pending_dns.pop(k, None)


dns_window_stats = {'responses': 0, 'bytes': 0, 'unmatched': 0}


def flush_window():
    global window_start

    bucket = get_time_bucket(window_start)

    window_totals = {
        d: {c: defaultdict(int) for c in CLASSES} for d in DIRECTIONS
    }
    unique_ips = {d: {c: set() for c in CLASSES} for d in DIRECTIONS}

    for direction in DIRECTIONS:
        for ip, flagcounts in window_counts[direction].items():
            cls = classify(ip)
            unique_ips[direction][cls].add(ip)
            for flag in flagcounts:
                c = flagcounts.get(flag, 0)
                per_ip_obs[bucket][direction][cls][flag].append(c)
                window_totals[direction][cls][flag] += c

    for direction in DIRECTIONS:
        for cls in CLASSES:
            for flag in FLAGS + ['udp', 'icmp']:
                global_obs[bucket][direction][cls][flag].append(window_totals[direction][cls][flag])

    row = {'timestamp': window_start, 'window_size_s': WINDOW_SIZE, 'time_bucket': bucket}
    for direction in DIRECTIONS:
        for cls in CLASSES:
            prefix = f'{direction}_{cls}'

            for flag in FLAGS + ['udp', 'icmp']:
                val = window_totals[direction][cls][flag]
                row[f'{prefix}_{flag}'] = val
                row[f'ema_{prefix}_{flag}'] = update_ema(direction, cls, flag, val)

            row[f'{prefix}_unique_dst_ips']   = len(unique_ips[direction][cls])
            row[f'{prefix}_unique_dst_ports'] = len(window_ports[direction][cls])
            row[f'{prefix}_uncommon_port_count'] = window_uncommon[direction][cls]

            row[f'ema_{prefix}_unique_dst_ports'] = update_ema(
                direction, cls, 'unique_dst_ports', len(window_ports[direction][cls]))
            row[f'ema_{prefix}_uncommon_port_count'] = update_ema(
                direction, cls, 'uncommon_port_count', window_uncommon[direction][cls])

    row['half_open_conns_active'] = sum(len(v) for v in half_open_by_ip.values())
    row['ema_half_open_conns_active'] = update_ema(
        'outbound', 'external', 'half_open_conns_active', row['half_open_conns_active'])
    row['dns_responses'] = dns_window_stats['responses']
    row['dns_responses_unmatched'] = dns_window_stats['unmatched']
    row['dns_bytes_total'] = dns_window_stats['bytes']
    dns_window_stats['responses'] = 0
    dns_window_stats['bytes'] = 0
    dns_window_stats['unmatched'] = 0

    window_records.append(row)

    window_counts['inbound'].clear()
    window_counts['outbound'].clear()
    for cls in CLASSES:
        window_ports['inbound'][cls].clear()
        window_ports['outbound'][cls].clear()
        window_uncommon['inbound'][cls] = 0
        window_uncommon['outbound'][cls] = 0
    window_start = now()

    sweep_stale_handshakes()
    expire_idle_flows()


flows = {}
completed_flows = []


def flow_key_and_endpoint(pkt):
    ip = pkt[IP]
    proto = ip.proto
    sport = dport = 0
    if pkt.haslayer(TCP):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport

    src_ep = (ip.src, sport)
    dst_ep = (ip.dst, dport)
    key = tuple(sorted([src_ep, dst_ep])) + (proto,)
    return key, src_ep, dst_ep


def update_flow(pkt):
    key, src_ep, dst_ep = flow_key_and_endpoint(pkt)
    now_t = now()

    # If a flow already exists under this key but its last packet was
    # longer ago than FLOW_IDLE_TIMEOUT, it's not a continuation — it's
    # a stale leftover (very likely from an earlier, unrelated pcap file,
    # since ephemeral ports and common server IP:port pairs get reused
    # across sessions). Close it out properly first, so this packet
    # starts a fresh flow instead of silently stretching the old one's
    # duration across the gap between sessions.
    existing = flows.get(key)
    if existing is not None and (now_t - existing['last']) > FLOW_IDLE_TIMEOUT:
        close_flow(key)

    if key not in flows:
        flows[key] = {
            'initiator': src_ep,
            'responder': dst_ep,
            'proto': pkt[IP].proto,
            'start': now_t,
            'last': now_t,
            'fwd_pkts': 0, 'bwd_pkts': 0,
            'fwd_bytes': 0, 'bwd_bytes': 0,
            'flags': {f: 0 for f in FLAGS},
            'internal_initiator': is_internal(src_ep[0]),
            'internal_responder': is_internal(dst_ep[0]),
            'window_start_at_creation': window_start,
            'ip_window_start_at_creation': ip_window_start,
        }
        s = ip_summary[src_ep[0]]
        s['currently_active_flows'] += 1
        if s['currently_active_flows'] > s['peak_concurrent_flows']:
            s['peak_concurrent_flows'] = s['currently_active_flows']

    f = flows[key]
    f['last'] = now_t
    size = len(pkt)
    forward = (src_ep == f['initiator'])

    if forward:
        f['fwd_pkts'] += 1
        f['fwd_bytes'] += size
    else:
        f['bwd_pkts'] += 1
        f['bwd_bytes'] += size

    track_handshake(pkt, key, src_ep, dst_ep)

    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        for name, bit in TCP_FLAG_BITS.items():
            if flags & bit:
                f['flags'][name] += 1
                ip_summary[src_ep[0]]['flag_counts'][name] += 1
        if (flags & TCP_FLAG_BITS['fin']) or (flags & TCP_FLAG_BITS['rst']):
            close_flow(key)


def close_flow(key):
    f = flows.pop(key, None)
    if f is None:
        return

    src_ip = f['initiator'][0]

    duration = max(f['last'] - f['start'], 1e-6)
    total_pkts = f['fwd_pkts'] + f['bwd_pkts']
    total_bytes = f['fwd_bytes'] + f['bwd_bytes']

    s = ip_summary[src_ip]
    s['total_flows'] += 1
    s['total_bytes'] += total_bytes
    s['total_duration_s'] += duration
    s['currently_active_flows'] = max(0, s['currently_active_flows'] - 1)

    record = {
        'time_bucket': get_time_bucket(f['start']),
        'flow_start_ts': round(f['start'], 4),   # A tmestamp so tht we can find this row in other features like ip and windows during analysis
        'flow_end_ts':   round(f['last'], 4), 
        'window_start_ts': round(f['window_start_at_creation'], 4),            
        'ip_window_start_ts': round(f['ip_window_start_at_creation'], 4),      
        'src_ip':   f['initiator'][0], 'src_port': f['initiator'][1],
        'dst_ip':   f['responder'][0], 'dst_port': f['responder'][1],
        'proto':    f['proto'],
        'internal_src': f['internal_initiator'],
        'internal_dst': f['internal_responder'],
        'direction': ('outbound' if f['initiator'][0] == my_host else
                      'inbound' if f['responder'][0] == my_host else 'lan_local'),
        'flow_duration_s': round(duration, 4),

        'fwd_packets': f['fwd_pkts'], 'bwd_packets': f['bwd_pkts'],
        'fwd_bytes':   f['fwd_bytes'], 'bwd_bytes':   f['bwd_bytes'],

        'flow_packets_per_s': round(total_pkts / duration, 4),
        'flow_bytes_per_s':   round(total_bytes / duration, 4),
        'fwd_bytes_per_s':    round(f['fwd_bytes'] / duration, 4),
        'bwd_bytes_per_s':    round(f['bwd_bytes'] / duration, 4),
        'fwd_packets_per_s':  round(f['fwd_pkts'] / duration, 4),
        'bwd_packets_per_s':  round(f['bwd_pkts'] / duration, 4),
        'avg_fwd_pkt_size': round(f['fwd_bytes'] / f['fwd_pkts'], 4) if f['fwd_pkts'] else 0.0,  
        'avg_bwd_pkt_size': round(f['bwd_bytes'] / f['bwd_pkts'], 4) if f['bwd_pkts'] else 0.0,  
    }
    for flag in FLAGS:
        record[f'{flag}_count'] = f['flags'][flag]

    completed_flows.append(record)


def flush_ip_windows():
    global ip_window_start
    bucket = get_time_bucket(ip_window_start)
    inactive_ips = []

    for ip, s in ip_summary.items():
        scan = scan_track.get(ip, {'dst_ports': set(), 'dst_ips': set()})
        had_activity = (s['total_flows'] > 0 or s['dns_queries_sent_to_this_ip'] > 0
                         or s['dns_responses_unmatched'] > 0 or len(scan['dst_ports']) > 0
                         or s['currently_active_flows'] > 0)

        if had_activity:
            ip_window_records.append({
                'ip': ip,
                'window_start': ip_window_start,
                'time_bucket': bucket,
                'total_flows': s['total_flows'],
                'total_bytes': s['total_bytes'],
                'total_duration_s': round(s['total_duration_s'], 4),
                'currently_active_flows': s['currently_active_flows'],
                'peak_concurrent_flows': s['peak_concurrent_flows'],
                'peak_concurrent_half_open': s['peak_concurrent_half_open'],
                'unique_dst_ports_this_window': len(scan['dst_ports']),
                'unique_dst_ips_this_window': len(scan['dst_ips']),
                'dns_queries_sent_to_this_ip': s['dns_queries_sent_to_this_ip'],
                'dns_responses_unmatched': s['dns_responses_unmatched'],
                'syn_count': s['flag_counts'].get('syn', 0),  
                'ack_count': s['flag_counts'].get('ack', 0),   
                'fin_count': s['flag_counts'].get('fin', 0),   
                'rst_count': s['flag_counts'].get('rst', 0),   
                'psh_count': s['flag_counts'].get('psh', 0),   
                'urg_count': s['flag_counts'].get('urg', 0),   
            })

        # Reset window-scoped counters. currently_active_flows carries over
        # as-is (a flow genuinely is or isn't open right now); everything
        # else restarts fresh for the next 5-minute window.
        s['total_flows'] = 0
        s['total_bytes'] = 0
        s['total_duration_s'] = 0.0
        s['peak_concurrent_flows'] = s['currently_active_flows']
        s['peak_concurrent_half_open'] = len(half_open_by_ip.get(ip, []))
        s['dns_queries_sent_to_this_ip'] = 0
        s['dns_responses_unmatched'] = 0
        s['flag_counts'].clear()
        

        if ip in scan_track:
            scan_track[ip]['dst_ports'].clear()
            scan_track[ip]['dst_ips'].clear()

        # Fully inactive AND not currently holding an open flow — drop it,
        # so it doesn't keep reappearing as a zero row in every future window.
        if not had_activity and s['currently_active_flows'] == 0:
            inactive_ips.append(ip)

    for ip in inactive_ips:
        del ip_summary[ip]
        scan_track.pop(ip, None)

    ip_window_start = now()


def expire_idle_flows():
    now_t = now()
    stale = [k for k, f in flows.items() if now_t - f['last'] > FLOW_IDLE_TIMEOUT]
    for k in stale:
        close_flow(k)


capture_start = time.time()
windows_seen = 0


def catchpacket(packet):
    global window_start, windows_seen, sim_time, ip_window_start

    # Advance simulated time from THIS packet's own timestamp, not
    # wall-clock. Set before any early-return so time stays continuous
    # across ARP/non-IP packets too, matching the pcap's real timeline.
    try:
        sim_time = float(packet.time)
    except Exception:
        pass  # malformed/missing timestamp — keep previous sim_time

    if window_start is None:
        window_start = sim_time
    if ip_window_start is None:
        ip_window_start = sim_time

    if my_host is None or not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if src_ip == my_host or dst_ip == my_host:
        update_flow(packet)

    track_dns(packet)

    direction = None
    remote_ip = None
    if dst_ip == my_host and src_ip != my_host:
        direction, remote_ip = 'inbound', src_ip
    elif src_ip == my_host and dst_ip != my_host:
        direction, remote_ip = 'outbound', dst_ip

    if direction:
        cls = classify(remote_ip)

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            for name, bit in TCP_FLAG_BITS.items():
                if flags & bit:
                    window_counts[direction][remote_ip][name] += 1
            dport = packet[TCP].dport
            window_ports[direction][cls].add(dport)
            if dport not in COMMON_PORTS:
                window_uncommon[direction][cls] += 1
            track_scan_shape(src_ip, dst_ip, dport)

        if packet.haslayer(UDP):
            window_counts[direction][remote_ip]['udp'] += 1
            dport = packet[UDP].dport
            window_ports[direction][cls].add(dport)
            if dport not in COMMON_PORTS:
                window_uncommon[direction][cls] += 1

        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            window_counts[direction][remote_ip]['icmp'] += 1

    if now() - window_start >= WINDOW_SIZE:
        flush_window()
        windows_seen += 1
        elapsed = int(time.time() - capture_start)   # wall-clock, for the live progress print only
        print(f"\r   Capturing... {elapsed}s elapsed | "
              f"windows: {windows_seen} | open flows: {len(flows)} | "
              f"completed flows: {len(completed_flows)}", end="", flush=True)

        if windows_seen % AUTOSAVE_EVERY_N_WINDOWS == 0:
            save_outputs()

    if now() - ip_window_start >= IP_WINDOW_SIZE_S:
        flush_ip_windows()


def compute_mean(observations):
    if not observations:
        return 0.0
    return round(sum(observations) / len(observations), 4)


def compute_percentile(observations, p=95):
    if not observations:
        return {'value': 0.0, 'raw_percentile': 0.0, 'damped': False}
    mean = compute_mean(observations)
    sorted_obs = sorted(observations)
    idx = int(len(sorted_obs) * p / 100)
    percentile = round(sorted_obs[min(idx, len(sorted_obs) - 1)], 4)
    raw_percentile = percentile
    if percentile >= 2 * mean and mean > 0:
        mid = len(sorted_obs) // 2
        percentile = round(sum(sorted_obs[:mid]) / mid, 4) if mid else percentile
    return {'value': percentile, 'raw_percentile': raw_percentile, 'damped': percentile != raw_percentile}


def save_outputs(final=False):
    if final:
        for k in list(flows.keys()):
            close_flow(k)

    baseline = {}
    for bucket in TIME_BUCKET_NAMES:
        baseline[bucket] = {d: {c: {} for c in CLASSES} for d in DIRECTIONS}
        for direction in DIRECTIONS:
            for cls in CLASSES:
                for flag in FLAGS + ['udp', 'icmp']:
                    baseline[bucket][direction][cls][f'{flag}_per_ip'] = compute_percentile(
                        per_ip_obs[bucket][direction][cls].get(flag, []))
                    baseline[bucket][direction][cls][f'{flag}_global'] = compute_percentile(
                        global_obs[bucket][direction][cls].get(flag, []))

    baseline_host_features = {}
    windows_by_bucket = defaultdict(list)
    for r in window_records:
        windows_by_bucket[r['time_bucket']].append(r)

    for bucket in TIME_BUCKET_NAMES:
        rows = windows_by_bucket.get(bucket, [])
        baseline_host_features[bucket] = {
            'half_open_conns_active': compute_percentile([r['half_open_conns_active'] for r in rows]),
            'dns_responses_unmatched': compute_percentile([r['dns_responses_unmatched'] for r in rows]),
            'windows_observed': len(rows),
        }

    baseline['host_features'] = baseline_host_features

    baseline['meta'] = {
        'interface':             my_iface,
        'local_ip':              my_host,   # NOTE: reflects last-processed file's host in multi-file runs;
                                             # see per-file host_map above for the full record
        'window_size_s':        WINDOW_SIZE,
        'ip_window_size_s':     IP_WINDOW_SIZE_S,
        'windows_captured':     windows_seen,
        'flow_idle_timeout_s':  FLOW_IDLE_TIMEOUT,
        'total_flows_captured': len(completed_flows),
        'open_flows':           len(flows),
        'elapsed_s':            round(time.time() - capture_start, 1),
        'last_saved_at':        time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)    
    with open(FLOWS_FILE, "w") as f:
        json.dump(completed_flows, f, indent=2)
    with open(WINDOWS_FILE, "w") as f:
        json.dump(window_records, f, indent=2)
    with open(IP_WINDOWS_FILE, "w") as f:
        json.dump(ip_window_records, f, indent=2)

    return baseline


print("=" * 55)
print("  Baseline Capture v2 (inbound/outbound x internal/external + flows)")
print("=" * 55)
print(f"  Host:      {my_host}")
print(f"  Interface: {my_iface or '(auto-detect failed — falling back to scapy default)'}")
print(f"  Window:    {WINDOW_SIZE}s  |  IP window: {IP_WINDOW_SIZE_S}s")
print(f"  Outputs:   {BASELINE_FILE}, {FLOWS_FILE}, {WINDOWS_FILE}, {IP_WINDOWS_FILE} "
      f"(autosaved every {AUTOSAVE_EVERY_N_WINDOWS * WINDOW_SIZE}s, and on Ctrl+C)")
print(f"\n  No fixed duration — press Ctrl+C to stop and save.")
print(f"  Starting capture...\n")

try:
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if os.path.isdir(target):
            pcap_files = sorted(glob_module.glob(os.path.join(target, "*.pcap")))
            if not pcap_files:
                print(f"  No .pcap files found in {target}")
            else:
                # ── Per-file host mapping ──────────────────────────────
                host_map = {}
                hosts_json_path = os.path.join(target, "inferred_hosts.json")
                if os.path.exists(hosts_json_path):
                    with open(hosts_json_path) as hf:
                        host_map = json.load(hf)
                    print(f"  Loaded per-file host map from {hosts_json_path} "
                          f"({sum(1 for v in host_map.values() if v)} resolved)")
                else:
                    print(f"  No inferred_hosts.json found in {target} — "
                          f"every file will use my_host={my_host}")

                print(f"  Found {len(pcap_files)} pcap file(s) — processing all in one run:")

                processed_dir = os.path.join(target, "processed")
                os.makedirs(processed_dir, exist_ok=True)

                skipped = []
                empty_files = []
                processed_count = 0
                for p in pcap_files:
                    fname = os.path.basename(p)

                    # Catch genuinely empty pcaps (header only, no packets) up
                    # front — these contribute nothing regardless of my_host,
                    # so don't bother resolving a host or sniffing them.
                    if os.path.getsize(p) < 400:
                        empty_files.append(fname)
                        dest = os.path.join(processed_dir, fname)
                        try:
                            os.replace(p, dest)
                        except OSError as e:
                            print(f"      [warn] could not move {fname} to processed/: {e}")
                        continue

                    if fname not in host_map:
                        print(f"    [warn] {fname} not found in inferred_hosts.json — "
                              f"skipping rather than guessing a stale host")
                        skipped.append(fname)
                        continue

                    file_host = host_map[fname]
                    if not file_host:
                        skipped.append(fname)
                        continue

                    my_host = file_host   # swap BEFORE reading this file's packets
                    print(f"    - {fname}  (my_host={my_host})")

                    windows_before = windows_seen
                    flows_before = len(completed_flows)
                    open_flows_before = len(flows)

                    sniff(offline=p, prn=catchpacket, store=False)
                    flush_window()       # close out this file's trailing partial 5s window
                    flush_ip_windows()   # close out this file's trailing partial 5min IP window

                    # Explicit, unconditional per-file report — independent of
                    # the \r-based "Capturing..." line, which only prints on
                    # a window flush and can be invisible in pasted/buffered
                    # terminal output. This always prints, so there's no
                    # ambiguity about whether a file actually contributed data.
                    windows_added = windows_seen - windows_before
                    flows_added = len(completed_flows) - flows_before
                    still_open = len(flows) - open_flows_before
                    print(f"      -> done: +{windows_added} windows, "
                          f"+{flows_added} completed flows, "
                          f"{len(flows)} total open flows now ({still_open:+d} this file)")
                    if windows_added == 0 and flows_added == 0 and still_open == 0:
                        print(f"      [warn] {fname} contributed ZERO data — "
                              f"check this file specifically (wrong host? empty? read error?)")

                    # Move to processed/ right after a successful read, so a
                    # crash mid-run or a later re-run doesn't reprocess (and
                    # double-count) files already folded into the baseline.
                    dest = os.path.join(processed_dir, fname)
                    try:
                        os.replace(p, dest)
                        processed_count += 1
                    except OSError as e:
                        print(f"[warn] could not move {fname} to processed/: {e}")

                print(f"\n  Moved {processed_count} file(s) to {processed_dir}")
                if empty_files:
                    print(f"\n  {len(empty_files)} empty pcap(s) (no packets) moved without processing: {empty_files}")
                if skipped:
                    print(f"\n  Skipped {len(skipped)} file(s) with no resolved host "
                          f"(fix in inferred_hosts.json or delete if empty/unresolved): {skipped}")
        else:
            sniff(offline=target, prn=catchpacket, store=False)
    elif my_iface:
        sniff(iface=my_iface, prn=catchpacket, store=False)
    else:
        sniff(prn=catchpacket, store=False)
except KeyboardInterrupt:
    pass

flush_window()
flush_ip_windows()
baseline = save_outputs(final=True)

print(f"\n\n  Baseline saved to {BASELINE_FILE}")
print(f"  Flows saved to {FLOWS_FILE}  ({len(completed_flows)} flows)")
print(f"  Window feature rows saved to {WINDOWS_FILE}  ({len(window_records)} rows)")
print(f"  Per-IP, per-5min window rows saved to {IP_WINDOWS_FILE}  ({len(ip_window_records)} rows)")
print(f"  Windows captured: {windows_seen}")

print(f"\n  Time-bucket coverage this run:")
for bucket in TIME_BUCKET_NAMES:
    n = baseline['host_features'][bucket]['windows_observed']
    flag = "  (too little data — treat this bucket's thresholds as unreliable)" if 0 < n < 20 else \
           "  (no data captured in this bucket)" if n == 0 else ""
    print(f"    {bucket:15s}: {n:4d} windows{flag}")

current_bucket = get_time_bucket()
if current_bucket in baseline and baseline[current_bucket]['inbound']['external'].get('syn_per_ip'):
    print(f"\n  Sample — inbound external SYN (per-IP, p95) for current bucket "
          f"'{current_bucket}': {baseline[current_bucket]['inbound']['external']['syn_per_ip']['value']}")

if window_records:
    last = window_records[-1]
    print(f"\n  Last window sample features (bucket: {last['time_bucket']}):")
    print(f"    inbound_external_unique_dst_ports:  {last['inbound_external_unique_dst_ports']}")
    print(f"    inbound_external_uncommon_port_count: {last['inbound_external_uncommon_port_count']}")
    print(f"    ema_inbound_external_syn: {last['ema_inbound_external_syn']}")