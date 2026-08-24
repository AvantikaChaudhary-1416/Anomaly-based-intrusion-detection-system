import socket
import ipaddress
import os
import glob as glob_module
import datetime as dt_module
import json
import time
import sys
import csv
from collections import defaultdict, deque

import joblib
import pandas as pd
from scapy.all import *

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from preprocess import preprocess_windows, preprocess_flows, preprocess_ip_windows

# ── Config ────────────────────────────────────────────────────────
WINDOW_SIZE       = 5
FLOW_IDLE_TIMEOUT = 120
IP_WINDOW_SIZE_S  = 300

FLOWS_FILE        = "detect_flows.json"        
WINDOWS_FILE      = "detect_windows.json"
IP_WINDOWS_FILE   = "detect_ip_windows.json"
ALERTS_LOG_FILE   = "alerts_realtime.csv"      
AUTOSAVE_EVERY_N_WINDOWS = 60

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pre_Trained_models")
FLOWS_MODEL_PATH      = os.path.join(MODEL_DIR, "flows_model.joblib")
IP_WINDOWS_MODEL_PATH = os.path.join(MODEL_DIR, "ip_windows_model.joblib")
WINDOWS_MODEL_PATH    = os.path.join(MODEL_DIR, "windows_model.joblib")

FEATUREMEAN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Baseline", "Featuremean.json")

WEIGHTS = {'flow': 0.2, 'ipwin': 0.4, 'global': 0.4}
SEVERITY_ALERT_THRESHOLD = 0.6

# how long to keep scored window/ip_window rows around for late-arriving joins
WINDOW_CACHE_RETENTION_S    = WINDOW_SIZE * 20        # ~100s of window history
IPWINDOW_CACHE_RETENTION_S  = IP_WINDOW_SIZE_S * 2     # ~10min of ip_window history
EXPLAIN_TOP_N = 3
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
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  #opens a udp connection
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

sim_time = None


def now():
    return sim_time if sim_time is not None else time.time()


if len(sys.argv) > 2:
    my_host = sys.argv[2]
    print(f"  [override] Using explicit host IP for this pcap: {my_host}")

window_counts = {
    'inbound':  defaultdict(lambda: defaultdict(int)),
    'outbound': defaultdict(lambda: defaultdict(int)),
}
window_start = None
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
    if pkt[UDP].sport == 5353 or pkt[UDP].dport == 5353: #to avoid mdns
        return
    dns = pkt[DNS]
    ip = pkt[IP]
    now_t = now()

    if dns.qr == 0:    #dns query
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
    key = tuple(sorted([src_ep, dst_ep])) + (proto,)    #no seperation of inbound and outbound traffic both are same key
    return key, src_ep, dst_ep   


#flows['key][all features]
def update_flow(pkt):
    key, src_ep, dst_ep = flow_key_and_endpoint(pkt)
    now_t = now()

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

#flows[key][st]
def close_flow(key):
    f = flows.pop(key, None)  #f=st of the key that was popped
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
        'flow_start_ts': round(f['start'], 4),
        'flow_end_ts':   round(f['last'], 4),
        'window_start_ts': round(f['window_start_at_creation'], 4) if f['window_start_at_creation'] is not None else None,
        'ip_window_start_ts': round(f['ip_window_start_at_creation'], 4) if f['ip_window_start_at_creation'] is not None else None,
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
    on_flow_closed(record)     # <-- real-time scoring hook


def flush_ip_windows():
    global ip_window_start
    bucket = get_time_bucket(ip_window_start)
    inactive_ips = []

    for ip, s in ip_summary.items():
        scan = scan_track.get(ip, {'dst_ports': set(), 'dst_ips': set()})
        had_activity = (s['total_flows'] > 0 or s['dns_queries_sent_to_this_ip'] > 0 or s['dns_responses_unmatched'] > 0 or len(scan['dst_ports']) > 0 or s['currently_active_flows'] > 0)

        if had_activity:
            record = {
                'ip': ip,
                'window_start': round(ip_window_start, 4),
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
            }
            ip_window_records.append(record)
            on_ipwindow_flushed(record)     # <-- real-time scoring hook

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

        if not had_activity and s['currently_active_flows'] == 0:
            inactive_ips.append(ip)

    for ip in inactive_ips:
        del ip_summary[ip]
        scan_track.pop(ip, None)

    ip_window_start = now()


def flush_window():
    global window_start

    bucket = get_time_bucket(window_start)

    window_totals = {d: {c: defaultdict(int) for c in CLASSES} for d in DIRECTIONS}
    unique_ips = {d: {c: set() for c in CLASSES} for d in DIRECTIONS}

    for direction in DIRECTIONS:
        for ip, flagcounts in window_counts[direction].items():
            cls = classify(ip)
            unique_ips[direction][cls].add(ip)
            for flag in flagcounts:
                c = flagcounts.get(flag, 0)
                window_totals[direction][cls][flag] += c

    row = {'timestamp': round(window_start, 4), 'window_size_s': WINDOW_SIZE, 'time_bucket': bucket}
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
    on_window_flushed(row)     # <-- real-time scoring hook

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


def expire_idle_flows():
    now_t = now()
    stale = [k for k, f in flows.items() if now_t - f['last'] > FLOW_IDLE_TIMEOUT]
    for k in stale:
        close_flow(k)


# ============================================================
# SCORING LAYER
# ============================================================

print("Loading models + Featuremean.json...")
flows_bundle    = joblib.load(FLOWS_MODEL_PATH)
ipwindow_bundle = joblib.load(IP_WINDOWS_MODEL_PATH)
window_bundle   = joblib.load(WINDOWS_MODEL_PATH)

featuremeans = {}
if os.path.exists(FEATUREMEAN_PATH):
    with open(FEATUREMEAN_PATH) as f:
        featuremeans = json.load(f)
    print(f"  loaded Featuremean.json from {FEATUREMEAN_PATH}")
else:
    print(f"  [warn] {FEATUREMEAN_PATH} not found -- alerts will fire without an 'explain' string. "
          f"Fix FEATUREMEAN_PATH at the top of this file.")


def score_one(record, bundle, preprocess_fn):
    """Score a single record (dict) with a trained model bundle.
    Returns (score, flag, preprocessed_row_dict)."""
    model, feature_cols = bundle['model'], bundle['feature_cols']
    df = pd.DataFrame([record])
    df, _ = preprocess_fn(df)
    for c in feature_cols:
        if c not in df.columns:
            df[c] = 0   # schema safety net -- shouldn't normally trigger
    X = df[feature_cols].fillna(0)
    score = float(model.decision_function(X)[0])
    flag = int(model.predict(X)[0])
    return score, flag, df.iloc[0].to_dict()


def explain(prep_row, feature_cols, model_key, top_n=EXPLAIN_TOP_N):
    """Top-N features (by |deviation| from the flag==1/normal mean) for this
    model. Values are in the same (possibly log1p) space Featuremean.json
    was computed in -- see module docstring."""
    means_for_model = featuremeans.get(model_key, {})
    devs = []
    for feat in feature_cols:
        normal_mean = means_for_model.get(1,{}).get(feat,0.0)
        val = prep_row.get(feat, 0.0)
        try:
            val = float(val)
            normal_mean = float(normal_mean)
        except (TypeError, ValueError):
            continue
        devs.append((feat, val, normal_mean, val - normal_mean))
    devs.sort(key=lambda x: abs(x[3]), reverse=True)
    return "; ".join(f"{feat}={val:.2f}(normal~{mean:.2f})" for feat, val, mean, _ in devs[:top_n])


# caches for late-arriving joins: {key -> {'score','flag','explain','ts'}}
recent_window_scores = {}
recent_ipwindow_scores = {}
pending_flows = deque()   # flow dicts still waiting on a window/ipwindow join

os.makedirs(os.path.dirname(os.path.abspath(ALERTS_LOG_FILE)) or ".", exist_ok=True)
# Alert fieldnames for CSV - supports all 3 types
_alert_fieldnames = [
    'tier', 'alert_type', 'alert_time', 
    'severity',
    # Flow fields
    'src_ip', 'src_port', 'dst_ip', 'dst_port',
    'flow_start_ts', 'flow_duration_s',
    'flag_flow', 'reason_flow',
    # IP Window fields
    'ip', 'ip_window_start', 'ip_window_duration_s',
    'flag_ipwin', 'reason_ipwin',
    # Global Window fields
    'window_timestamp', 'window_duration_s',
    'flag_global', 'reason_global',
    # Combined severity
    'corroborated_severity'
]

# Track alerted items to prevent duplicates
_alerted_flows = set()
_alerted_ipwindows = set()
_alerted_windows = set()
#if tracked in fast no need to track in corroborated

def _write_alert_row(row):
    #Write alert to CSV with all fields
    with open(ALERTS_LOG_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=_alert_fieldnames, extrasaction='ignore')
        writer.writerow(row)

#FAST flow analyzed
def emit_fast_flow(flow_state, flag_flow, reason_flow):
    """FAST alert for flow anomaly - fires immediately"""
    
    # Deduplicate
    flow_key = f"{flow_state['flow_start_ts']}_{flow_state['src_ip']}_{flow_state['dst_ip']}"
    if flow_key in _alerted_flows:
        return
    _alerted_flows.add(flow_key)
    
    # Calculate severity based on flow alone (renormalized)
    severity = compute_severity(flag_flow, None, None)
    
    if severity < SEVERITY_ALERT_THRESHOLD:
        return
    
    row = {
        'tier': 'FAST_FLOW',
        'alert_type': 'flow',
        'alert_time': round(now(), 4),
        'severity': severity,
        'src_ip': flow_state['src_ip'],
        'src_port': flow_state['src_port'],
        'dst_ip': flow_state['dst_ip'],
        'dst_port': flow_state['dst_port'],
        'flow_start_ts': flow_state['flow_start_ts'],
        'flow_duration_s': flow_state['flow_duration_s'],
        'flag_flow': flag_flow,
        'reason_flow': reason_flow,
        'corroborated_severity': None,
    }
    _write_alert_row(row)
    
    print(f"\n [FAST_FLOW] severity={severity:.2f} {flow_state['src_ip']}:{flow_state['src_port']} -> "
          f"{flow_state['dst_ip']}:{flow_state['dst_port']}")
    print(f"     → {reason_flow}")

#FAST ip window analyzed
def emit_fast_ipwindow(ip_row, flag_ipwin, reason_ipwin):
    """FAST alert for IP window anomaly - fires immediately when IP window flushes"""
    
    # Deduplicate
    ip_key = f"{ip_row['ip']}_{ip_row['window_start']}"
    if ip_key in _alerted_ipwindows:
        return
    _alerted_ipwindows.add(ip_key)
    
    # Calculate severity based on IP window alone
    severity = compute_severity(None, flag_ipwin, None)
    
    if severity < SEVERITY_ALERT_THRESHOLD:
        return
    
    row = {
        'tier': 'FAST_IPWIN',
        'alert_type': 'ip_window',
        'alert_time': round(now(), 4),
        'severity': severity,
        'ip': ip_row['ip'],
        'ip_window_start': ip_row['window_start'],
        'flag_ipwin': flag_ipwin,
        'reason_ipwin': reason_ipwin,
        'corroborated_severity': None,
    }
    _write_alert_row(row)
    
    print(f"\n  [FAST_IPWIN] severity={severity:.2f} IP: {ip_row['ip']}")
    print(f"     → {reason_ipwin}")

#FAST window analyzed
def emit_fast_window(window_row, flag_global, reason_global):
    """FAST alert for global window anomaly - fires immediately when window flushes"""
    
    # Deduplicate
    window_key = window_row['timestamp']
    if window_key in _alerted_windows:
        return
    _alerted_windows.add(window_key)
    
    # Calculate severity based on global window alone
    severity = compute_severity(None, None, flag_global)
    
    if severity < SEVERITY_ALERT_THRESHOLD:
        return
    
    row = {
        'tier': 'FAST_GLOBAL',
        'alert_type': 'window',
        'alert_time': round(now(), 4),
        'severity': severity,
        'window_timestamp': window_row['timestamp'],
        'flag_global': flag_global,
        'reason_global': reason_global,
        'corroborated_severity': None,
    }
    _write_alert_row(row)
    
    print(f"\n  [FAST_GLOBAL] severity={severity:.2f} at timestamp {window_row['timestamp']}")
    print(f"     → {reason_global}")


# ============================================================
# CORROBORATED ALERT - All 3 types combined
# ============================================================

def emit_corroborated(flow_state, flag_ipwin, flag_global, 
                      reason_ipwin, reason_global, tier='CORROBORATED'):
    """
    Corroborated alert combining all available data.
    Called when:
    1. Flow closes and both window + IP window are available
    2. Pending flows are rechecked and have both components
    3. Partial corroboration when data ages out
    """
    
    flow_key = f"{flow_state['flow_start_ts']}_{flow_state['src_ip']}_{flow_state['dst_ip']}"
    if flow_key in _alerted_flows:
        return  # Already alerted as FAST_FLOW, but we want to update with corroboration
    
    # Calculate corroborated severity with all available components
    severity = compute_severity(
        flow_state.get('flag_flow'),
        flag_ipwin,
        flag_global
    )
    
    if severity < SEVERITY_ALERT_THRESHOLD:
        return
    
    row = {
        'tier': tier,  # 'CORROBORATED' or 'CORROBORATED_PARTIAL'
        'alert_type': 'corroborated',
        'alert_time': round(now(), 4),
        'severity': severity,
        # Flow fields
        'src_ip': flow_state['src_ip'],
        'src_port': flow_state['src_port'],
        'dst_ip': flow_state['dst_ip'],
        'dst_port': flow_state['dst_port'],
        'flow_start_ts': flow_state['flow_start_ts'],
        'flow_duration_s': flow_state['flow_duration_s'],
        'flag_flow': flow_state.get('flag_flow'),
        'reason_flow': flow_state.get('reason_flow'),
        # IP Window fields
        'flag_ipwin': flag_ipwin,
        'reason_ipwin': reason_ipwin,
        # Global Window fields
        'flag_global': flag_global,
        'reason_global': reason_global,
        # Combined severity (for tracking)
        'corroborated_severity': severity,
    }
    
    # Add IP if available
    if flag_ipwin is not None:
        ipw_hit = _lookup_ipwindow(flow_state['src_ip'], flow_state.get('ip_window_start_ts'))
        if ipw_hit:
            row['ip'] = flow_state['src_ip']
            row['ip_window_start'] = flow_state.get('ip_window_start_ts')
    
    _write_alert_row(row)

    # Print rich alert
    print(f"\n  🔗 [{tier}] severity={severity:.2f} {flow_state['src_ip']}:{flow_state['src_port']} -> "
          f"{flow_state['dst_ip']}:{flow_state['dst_port']}")
    
    # Show breakdown
    components = []
    if flow_state.get('flag_flow') == -1:
        components.append(f"FLOW: {flow_state.get('reason_flow')}")
    if flag_ipwin == -1:
        components.append(f"IPWIN: {reason_ipwin}")
    if flag_global == -1:
        components.append(f"GLOBAL: {reason_global}")
    
    for comp in components:
        print(f"     • {comp}")


def compute_severity(flag_flow=None, flag_ipwin=None, flag_global=None):
    """
    Weighted corroboration with renormalization.
    Now handles any combination of the 3 types.
    """
    available = {}
    if flag_flow is not None:
        available['flow'] = WEIGHTS['flow']
    if flag_ipwin is not None:
        available['ipwin'] = WEIGHTS['ipwin']
    if flag_global is not None:
        available['global'] = WEIGHTS['global']
    
    total_w = sum(available.values())
    if total_w == 0:
        return 0.0
    
    s = 0.0
    if flag_flow is not None:
        s += available['flow'] * (1 if flag_flow == -1 else 0)
    if flag_ipwin is not None:
        s += available['ipwin'] * (1 if flag_ipwin == -1 else 0)
    if flag_global is not None:
        s += available['global'] * (1 if flag_global == -1 else 0)
    
    return round(s / total_w, 4)


def _lookup_ipwindow(src_ip, ip_window_start_ts):
    if ip_window_start_ts is None:
        return None
    return recent_ipwindow_scores.get((src_ip, round(ip_window_start_ts, 4)))


def _lookup_window(window_start_ts):
    if window_start_ts is None:
        return None
    return recent_window_scores.get(round(window_start_ts, 4))


def on_flow_closed(record):
    """Score and alert on flow closure"""
    score_flow, flag_flow, prep_row = score_one(record, flows_bundle, preprocess_flows)
    reason_flow = explain(prep_row, flows_bundle['feature_cols'], 'flows')
    
    flow_state = dict(record)
    flow_state.update(
        score_flow=score_flow,
        flag_flow=flag_flow,
        reason_flow=reason_flow,
        queued_at=now()
    )
    
    # FAST alert - flow only
    if flag_flow == -1:
        emit_fast_flow(flow_state, flag_flow, reason_flow)
    
    # Try immediate join
    ipw_hit = _lookup_ipwindow(record['src_ip'], record.get('ip_window_start_ts'))
    win_hit = _lookup_window(record.get('window_start_ts'))
    
    if ipw_hit is not None and win_hit is not None:
        # Both available - immediate corroborated
        emit_corroborated(
            flow_state,
            ipw_hit['flag'], win_hit['flag'],
            ipw_hit['explain'], win_hit['explain'],
            tier='CORROBORATED'
        )
    else:
        # Queue for later
        pending_flows.append(flow_state)


def on_window_flushed(row):
    """Score and alert on global window flush"""
    score, flag, prep_row = score_one(row, window_bundle, preprocess_windows)
    reason = explain(prep_row, window_bundle['feature_cols'], 'window')
    
    # Store in cache for joins
    recent_window_scores[row['timestamp']] = {
        'score': score, 'flag': flag, 'explain': reason, 'ts': now(),
    }
    
    # FAST alert - global window only
    if flag == -1:
        emit_fast_window(row, flag, reason)
    
    _evict_old(recent_window_scores, WINDOW_CACHE_RETENTION_S)
    _recheck_pending()


def on_ipwindow_flushed(row):
    """Score and alert on IP window flush"""
    score, flag, prep_row = score_one(row, ipwindow_bundle, preprocess_ip_windows)
    reason = explain(prep_row, ipwindow_bundle['feature_cols'], 'ipw')
    
    # Store in cache for joins
    recent_ipwindow_scores[(row['ip'], row['window_start'])] = {
        'score': score, 'flag': flag, 'explain': reason, 'ts': now(),
    }
    
    # FAST alert - IP window only
    if flag == -1:
        emit_fast_ipwindow(row, flag, reason)
    
    _evict_old_ipwindow(IPWINDOW_CACHE_RETENTION_S)
    _recheck_pending()


def _evict_old(cache, retention_s):
    cutoff = now() - retention_s
    for k in [k for k, v in cache.items() if v['ts'] < cutoff]:
        del cache[k]


def _evict_old_ipwindow(retention_s):
    cutoff = now() - retention_s
    for k in [k for k, v in recent_ipwindow_scores.items() if v['ts'] < cutoff]:
        del recent_ipwindow_scores[k]


def _recheck_pending():
    """Re-join any pending flows against the caches."""
    still_pending = deque()
    now_t = now()
    
    while pending_flows:
        flow_state = pending_flows.popleft()
        ipw_hit = _lookup_ipwindow(flow_state['src_ip'], flow_state.get('ip_window_start_ts'))
        win_hit = _lookup_window(flow_state.get('window_start_ts'))
        
        aged_out = (now_t - flow_state['queued_at']) > IPWINDOW_CACHE_RETENTION_S
        have_both = ipw_hit is not None and win_hit is not None
        
        if have_both:
            # Both components available - full corroboration
            emit_corroborated(
                flow_state,
                ipw_hit['flag'], win_hit['flag'],
                ipw_hit['explain'], win_hit['explain'],
                tier='CORROBORATED'
            )
        elif aged_out:
            # Aged out - emit with what we have
            emit_corroborated(
                flow_state,
                ipw_hit['flag'] if ipw_hit else None,
                win_hit['flag'] if win_hit else None,
                ipw_hit['explain'] if ipw_hit else None,
                win_hit['explain'] if win_hit else None,
                tier='CORROBORATED_PARTIAL'
            )
        else:
            # Still waiting
            still_pending.append(flow_state)
    
    pending_flows.extend(still_pending)

def print_alert_summary():
    """Print summary of all alerts by type and tier"""
    try:
        df = pd.read_csv(ALERTS_LOG_FILE)
        
        print("\n" + "="*60)
        print("ALERT SUMMARY")
        print("="*60)
        
        # By tier
        tier_counts = df['tier'].value_counts()
        print(f"\nBy Alert Tier:")
        for tier, count in tier_counts.items():
            print(f"  {tier}: {count}")
        
        # By severity
        print(f"\nSeverity Distribution:")
        print(f"  High (>0.8): {len(df[df['severity'] > 0.8])}")
        print(f"  Medium (0.6-0.8): {len(df[(df['severity'] >= 0.6) & (df['severity'] <= 0.8)])}")
        print(f"  Low (<0.6): {len(df[df['severity'] < 0.6])}")
        
        # Top offending IPs
        if 'src_ip' in df.columns:
            top_ips = df['src_ip'].value_counts().head(5)
            print(f"\nTop Source IPs:")
            for ip, count in top_ips.items():
                print(f"  {ip}: {count}")
        
        print("="*60)
        
    except Exception as e:
        print(f"Could not generate summary: {e}")

# ============================================================
# USAGE - At the end of capture
# ============================================================

# After capture completes:
print_alert_summary()


# ============================================================
# CAPTURE LOOP
# ============================================================

capture_start = time.time()
windows_seen = 0


def catchpacket(packet):
    global window_start, windows_seen, sim_time, ip_window_start

    try:
        sim_time = float(packet.time)
    except Exception:
        pass

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
        elapsed = int(time.time() - capture_start)
        print(f"\r   Capturing... {elapsed}s elapsed | "
              f"windows: {windows_seen} | open flows: {len(flows)} | "
              f"completed flows: {len(completed_flows)} | pending joins: {len(pending_flows)}",
              end="", flush=True)
        if windows_seen % AUTOSAVE_EVERY_N_WINDOWS == 0:
            save_outputs()

    if now() - ip_window_start >= IP_WINDOW_SIZE_S:
        flush_ip_windows()


def save_outputs(final=False):
    if final:
        for k in list(flows.keys()):
            close_flow(k)

    with open(FLOWS_FILE, "w") as f:
        json.dump(completed_flows, f, indent=2)
    with open(WINDOWS_FILE, "w") as f:
        json.dump(window_records, f, indent=2)
    with open(IP_WINDOWS_FILE, "w") as f:
        json.dump(ip_window_records, f, indent=2)


print("=" * 55)
print("  Real-Time Detection (scores on every flow/window/ip_window flush)")
print("=" * 55)
print(f"  Host:      {my_host}")
print(f"  Interface: {my_iface or '(auto-detect failed — falling back to scapy default)'}")
print(f"  Window:    {WINDOW_SIZE}s  |  IP window: {IP_WINDOW_SIZE_S}s")
print(f"  Alert threshold: {SEVERITY_ALERT_THRESHOLD}  |  Live alerts -> {ALERTS_LOG_FILE}")
print(f"\n  Starting capture...\n")

try:
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if os.path.isdir(target):
            pcap_files = sorted(glob_module.glob(os.path.join(target, "*.pcap")))
            #glob module to find files and folders whose name match a pattern
            if not pcap_files:
                print(f"  No .pcap files found in {target}")
            else:
                host_map = {}
                hosts_json_path = os.path.join(target, "inferred_hosts.json")
                if os.path.exists(hosts_json_path):
                    with open(hosts_json_path) as hf:
                        host_map = json.load(hf)
                    print(f"  Loaded per-file host map ({sum(1 for v in host_map.values() if v)} resolved)")
                else:
                    print(f"  No inferred_hosts.json found — every file will use my_host={my_host}")

                print(f"  Found {len(pcap_files)} pcap file(s):")
                processed_dir = os.path.join(target, "processed")
                os.makedirs(processed_dir, exist_ok=True)

                for p in pcap_files:
                    fname = os.path.basename(p) #basename=extracts the filename the last part of the path
                    if os.path.getsize(p) < 400:
                        os.replace(p, os.path.join(processed_dir, fname))
                        continue
                    if fname not in host_map or not host_map[fname]:
                        print(f"    [warn] {fname} — no resolved host, skipping")
                        continue

                    my_host = host_map[fname]
                    print(f"    - {fname}  (my_host={my_host})")
                    sniff(offline=p, prn=catchpacket, store=False)
                    flush_window()
                    flush_ip_windows()
                    os.replace(p, os.path.join(processed_dir, fname)) #processed_dir/fname
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
_recheck_pending()   # flush out anything still waiting on a join, partial or not
save_outputs(final=True)

print(f"\n\n  Flows saved to {FLOWS_FILE}  ({len(completed_flows)} flows)")
print(f"  Window rows saved to {WINDOWS_FILE}  ({len(window_records)} rows)")
print(f"  IP-window rows saved to {IP_WINDOWS_FILE}  ({len(ip_window_records)} rows)")
print(f"  Windows captured: {windows_seen}")
print(f"  Live alert log: {ALERTS_LOG_FILE}")