import pandas as pd
import joblib
import json
import os
import csv
import time
import datetime as dt_module
import numpy as np


ALERTS_LOG_FILE       = "alerts_realtime.csv"        # FAST tier only
CORROBORATED_LOG_FILE = "alerts_corroborated.csv"    # CORROBORATED tier only      
FEATURESTAT_FILE = os.path.join(os.path.dir(os.path.abspath(__file__)),"..","FeatureStat.json")
SEVERITY_ALERT_THRESHOLD = 0.6
EXPLAIN_TOP_N = 3
WEIGHTS = {'flow': 0.2, 'ipwin': 0.4, 'global': 0.4}

WINDOW_SIZE       = 5
IP_WINDOW_SIZE_S  = 300

# how long to keep scored window/ip_window rows around for late-arriving joins
WINDOW_CACHE_RETENTION_S    = WINDOW_SIZE * 20        # ~100s of window history
IPWINDOW_CACHE_RETENTION_S  = IP_WINDOW_SIZE_S * 2     # ~10min of ip_window history

# ─────────────────────────────────────────────────────────────────

featureStats={}

with open(FEATURESTAT_FILE) as f:
    featureStats=json.load(f)

os.makedirs(os.path.dirname(os.path.abspath(ALERTS_LOG_FILE)) or ".", exist_ok=True)
os.makedirs(os.path.dirname(os.path.abspath(CORROBORATED_LOG_FILE)) or ".", exist_ok=True)

# FAST alert fieldnames — flow / ip_window / window, one tier per row
_fast_fieldnames = [
    'tier', 'alert_type', 'alert_time', 'severity',
    'src_ip', 'src_port', 'dst_ip', 'dst_port',
    'flow_start_ts', 'flow_duration_s', 'flag_flow', 'reason_flow',
    'ip', 'ip_window_start', 'flag_ipwin', 'reason_ipwin',
    'window_timestamp', 'flag_global', 'reason_global',
]

# CORROBORATED fieldnames — always has flow identity, plus whichever of
# ipwin/global joined (None where a component never arrived / partial)
_corroborated_fieldnames = [
    'tier', 'alert_type', 'alert_time', 'severity',
    'src_ip', 'src_port', 'dst_ip', 'dst_port',
    'flow_start_ts', 'flow_duration_s',
    'flag_flow', 'reason_flow',
    'ip', 'ip_window_start', 'flag_ipwin', 'reason_ipwin',
    'window_timestamp', 'flag_global', 'reason_global',
    'corroborated_severity',
]

def _write_fast_row(row):
    is_new = not os.path.exists(ALERTS_LOG_FILE)
    with open(ALERTS_LOG_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=_fast_fieldnames, extrasaction='ignore')
        #creates a writer object bound to handle file f. fieldnames is the ordered list of columns
        #every row we write must be a dict and the values get written under the corresponding column name
        if is_new:
            writer.writeheader()  #writes the column names
        writer.writerow(row)

def _write_corroborated_row(row):
    is_new = not os.path.exists(CORROBORATED_LOG_FILE)
    with open(CORROBORATED_LOG_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=_corroborated_fieldnames, extrasaction='ignore')
        if is_new:
            writer.writeheader()
        writer.writerow(row)

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


def explain(prep_row, feature_cols, model_key):
    """Top-N features (by |deviation| from the flag==1/normal mean) for this
    model. Values are in the same (possibly log1p) space Featuremean.json
    was computed in -- see module docstring."""

    model_feature_stat=featureStats[model_key]
    mean=pd.Series(model_feature_stat['mu'])
    sigma_inv=np.array(model_feature_stat['sigma_inv'])
    nonzero_cols=model_feature_stat['nonzero_cols']
    zero_cols=model_feature_stat['zero_cols']

    reasons = []

    for c in zero_cols:
        val = prep_row.get(c, 0)
        if val and val != 0:
            reasons.append(f"{c} as a feature had no appearance in training data")

    if nonzero_cols:
        d=np.array([prep_row.get(c,0) for c in nonzero_cols])
        w=sigma_inv@d # @ is for matrix multiplication
        contributor=d*w

        

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
_alerted_corroborated=set()
#if tracked in fast no need to track in corroborated


#FAST flow analyzed
def emit_fast_flow(flow_state, flag_flow, reason_flow):
    """FAST alert for flow anomaly - fires immediately"""
    
    # Deduplicate
    flow_key = f"{flow_state['flow_start_ts']}_{flow_state['src_ip']}_{flow_state['dst_ip']}"
    if flow_key in _alerted_flows:
        return
    
    # Calculate severity based on flow alone (renormalized)
    severity = compute_severity(flag_flow, None, None)
    
    if severity < SEVERITY_ALERT_THRESHOLD:
        return
    
    _alerted_flows.add(flow_key)
    
    row = {
        'tier': 'FAST_FLOW',
        'alert_type': 'flow',
        'alert_time': round(time.time(), 4),
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
    _write_fast_row(row)
    
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
    
    # Calculate severity based on IP window alone
    severity = compute_severity(None, flag_ipwin, None)
    
    if severity < SEVERITY_ALERT_THRESHOLD:
        return
    
    _alerted_ipwindows.add(ip_key)
    row = {
        'tier': 'FAST_IPWIN',
        'alert_type': 'ip_window',
        'alert_time': round(time.time(), 4),
        'severity': severity,
        'ip': ip_row['ip'],
        'ip_window_start': ip_row['window_start'],
        'flag_ipwin': flag_ipwin,
        'reason_ipwin': reason_ipwin,
        'corroborated_severity': None,
    }
    _write_fast_row(row)
    
    print(f"\n  [FAST_IPWIN] severity={severity:.2f} IP: {ip_row['ip']}")
    print(f"     → {reason_ipwin}")

#FAST window analyzed
def emit_fast_window(window_row, flag_global, reason_global):
    """FAST alert for global window anomaly - fires immediately when window flushes"""
    
    # Deduplicate
    window_key = window_row['timestamp']
    if window_key in _alerted_windows:
        return
    
    # Calculate severity based on global window alone
    severity = compute_severity(None, None, flag_global)
    
    if severity < SEVERITY_ALERT_THRESHOLD:
        return

    _alerted_windows.add(window_key)
    
    row = {
        'tier': 'FAST_GLOBAL',
        'alert_type': 'window',
        'alert_time': round(time.time(), 4),
        'severity': severity,
        'window_timestamp': window_row['timestamp'],
        'flag_global': flag_global,
        'reason_global': reason_global,
        'corroborated_severity': None,
    }
    _write_fast_row(row)
    
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
    if flow_key in _alerted_corroborated:
        return  # Already alerted as FAST_FLOW, but we want to update with corroboration
    
    # Calculate corroborated severity with all available components
    severity = compute_severity(
        flow_state.get('flag_flow'),
        flag_ipwin,
        flag_global
    )
    
    if severity < SEVERITY_ALERT_THRESHOLD:
        return
    _alerted_corroborated.add(flow_key)
    row = {
        'tier': tier,  # 'CORROBORATED' or 'CORROBORATED_PARTIAL'
        'alert_type': 'corroborated',
        'alert_time': round(time.time(), 4),
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
    
    _write_corroborated_row(row)

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


def _lookup_ipwindow(src_ip, ip_window_start_ts,recent_ipwindow_scores):
    if ip_window_start_ts is None:
        return None
    return recent_ipwindow_scores.get((src_ip, round(ip_window_start_ts, 4)))


def _lookup_window(window_start_ts,recent_window_scores):
    if window_start_ts is None:
        return None
    return recent_window_scores.get(round(window_start_ts, 4))




def _evict_old(cache, retention_s):
    cutoff = time.time() - retention_s
    for k in [k for k, v in cache.items() if v['ts'] < cutoff]:
        del cache[k]
# k for k,v in cache.items() if v['ts']<cutoff    this gives list as a result and then the outer for loop iterates over that list
#for k,v in cache.items() if v['ts']<cutoff: del cache[k]   does not work because we cannot modify the size of data structures while iterating in it because say {10,20,30,40} k at 20 if we delete 20 30 and 40 moved to left and k now points to 30 ad we do k++ and go to 40 we miss 30 

def _evict_old_ipwindow(cache,retention_s):
    cutoff = time.time() - retention_s
    for k in [k for k, v in cache.items() if v['ts'] < cutoff]:
        del cache[k]


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
    for label, path in [('FAST', ALERTS_LOG_FILE), ('CORROBORATED', CORROBORATED_LOG_FILE)]:
        try:
            df = pd.read_csv(path)
        except Exception as e:
            print(f"\n[{label}] Could not read {path}: {e}")
            continue

        print(f"\n{'='*60}\n{label} ALERT SUMMARY\n{'='*60}")
        print(df['tier'].value_counts().to_string())
        print(f"\nSeverity: high(>0.8)={len(df[df['severity']>0.8])}  "
              f"medium(0.6-0.8)={len(df[(df['severity']>=0.6)&(df['severity']<=0.8)])}  "
              f"low(<0.6)={len(df[df['severity']<0.6])}")
        if 'src_ip' in df.columns:
            print("\nTop source IPs:")
            print(df['src_ip'].value_counts().head(5).to_string())

# ============================================================
# USAGE - At the end of capture
# ============================================================

# After capture completes:
print_alert_summary()

