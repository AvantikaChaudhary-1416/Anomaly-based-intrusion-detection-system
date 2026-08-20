import pandas as pd
import json
import joblib
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from preprocess import(preprocess_ip_windows,preprocess_flows,preprocess_windows)

# ── Config ────────────────────────────────────────────────────────
DETECT_FLOWS_FILE      = "detect_flows.json"
DETECT_WINDOWS_FILE    = "detect_windows.json"
DETECT_IP_WINDOWS_FILE = "detect_ip_windows.json"

# models live in ids/pre_Trained_models/, this script lives in ids/Detect/
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pre_Trained_models")
FLOWS_MODEL_PATH      = os.path.join(MODEL_DIR, "flows_model.joblib")
IP_WINDOWS_MODEL_PATH = os.path.join(MODEL_DIR, "ip_windows_model.joblib")
WINDOWS_MODEL_PATH    = os.path.join(MODEL_DIR, "windows_model.joblib")

WEIGHTS = {'flow': 0.2, 'ipwin': 0.4, 'global': 0.4}
SEVERITY_ALERT_THRESHOLD = 0.6
# ─────────────────────────────────────────────────────────────────

def score(df, json_path, model_path):
    bundle = joblib.load(model_path)
    model, feature_cols = bundle['model'], bundle['feature_cols']

    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"{json_path} is missing trained feature columns: {missing}")

    X = df[feature_cols].fillna(0)
    df['score'] = model.decision_function(X)
    df['flag'] = model.predict(X)   # -1 anomaly, 1 normal
    return df


def build_severity(merged):
    """Weighted corroboration score across the three models' flags."""
    def row_severity(row):
        s = 0.0
        s += WEIGHTS['flow']   * (1 if row.get('flag_flow') == -1 else 0)
        s += WEIGHTS['ipwin']  * (1 if row.get('flag_ipwin') == -1 else 0)
        s += WEIGHTS['global'] * (1 if row.get('flag_global') == -1 else 0)
        return round(s, 4)
    merged['severity'] = merged.apply(row_severity, axis=1)
    return merged


def main():
    print("Loading and scoring flows...")
    with open(DETECT_FLOWS_FILE) as f:
        fl = pd.DataFrame(json.load(f))

    if fl.empty:
        print(f"[warn] {DETECT_FLOWS_FILE} is empty — no rows to score")

    fl, fl_feature = preprocess_flows(fl)
    flows = score(fl, DETECT_FLOWS_FILE, FLOWS_MODEL_PATH)
    print(f"  {len(flows)} flows scored")

    print("Loading and scoring ip_windows...")
    with open(DETECT_IP_WINDOWS_FILE) as f:
        ipw = pd.DataFrame(json.load(f))

    if ipw.empty:
        print(f"[warn] {DETECT_IP_WINDOWS_FILE} is empty — no rows to score")

    ipw, ipw_feature = preprocess_ip_windows(ipw)
    ip_windows = score(ipw, DETECT_IP_WINDOWS_FILE, IP_WINDOWS_MODEL_PATH)
    print(f"  {len(ip_windows)} ip_window rows scored")

    print("Loading and scoring windows...")
    with open(DETECT_WINDOWS_FILE) as f:
        w = pd.DataFrame(json.load(f))

    if w.empty:
        print(f"[warn] {DETECT_WINDOWS_FILE} is empty — no rows to score")

    w, w_feature = preprocess_windows(w)
    windows = score(w, DETECT_WINDOWS_FILE, WINDOWS_MODEL_PATH)
    print(f"  {len(windows)} global window rows scored")

    if flows.empty:
        print("No flows to evaluate. Exiting.")
        return

    flows['ip_window_start_ts'] = flows['ip_window_start_ts'].round(4)
    ip_windows['window_start'] = ip_windows['window_start'].round(4)
    windows['timestamp'] = windows['timestamp'].round(4)

    flows = flows.rename(columns={'score': 'score_flow', 'flag': 'flag_flow'})

    # ── Join flows -> ip_windows ────────────────────────────────
    # flow['ip_window_start_ts'] was captured verbatim from the live
    # ip_window_start value at flow-creation time (in baseline_capture.py),
    # so it exact-matches ip_windows['window_start'] — no range logic needed.
    if not ip_windows.empty:
        ip_win_scored = ip_windows[['ip', 'window_start', 'score', 'flag']].rename(
            columns={'score': 'score_ipwin', 'flag': 'flag_ipwin'}
        )
        merged = flows.merge(
            ip_win_scored,
            left_on=['src_ip', 'ip_window_start_ts'],
            right_on=['ip', 'window_start'],
            how='left'
        )
    else:
        merged = flows.copy()
        merged['score_ipwin'] = None
        merged['flag_ipwin'] = None

    # ── Join -> windows (global, no IP) ─────────────────────────
    # flow['window_start_ts'] exact-matches windows['timestamp'] for the
    # same reason (captured verbatim from the live window_start).
    if not windows.empty:
        win_scored = windows[['timestamp', 'score', 'flag']].rename(
            columns={'score': 'score_global', 'flag': 'flag_global'}
        )
        merged = merged.merge(
            win_scored,
            left_on='window_start_ts',
            right_on='timestamp',
            how='left'
        )
    else:
        merged['score_global'] = None
        merged['flag_global'] = None

    # ── Severity ─────────────────────────────────────────────────
    merged = build_severity(merged)

    unmatched_ipwin = merged['flag_ipwin'].isna().sum()
    unmatched_global = merged['flag_global'].isna().sum()
    if unmatched_ipwin > 0:
        print(f"[warn] {unmatched_ipwin}/{len(merged)} flows had no matching ip_windows row "
              f"(check ip_window_start_ts alignment / IP_WINDOW_SIZE_S consistency)")
    if unmatched_global > 0:
        print(f"[warn] {unmatched_global}/{len(merged)} flows had no matching windows row "
              f"(check window_start_ts alignment / WINDOW_SIZE consistency)")

    alerts = merged[merged['severity'] >= SEVERITY_ALERT_THRESHOLD].sort_values(
        'severity', ascending=False
    )

    print(f"\n{'='*60}")
    print(f"Total flows evaluated: {len(merged)}")
    print(f"Flows flagged by flows_model alone:      {(merged['flag_flow']==-1).sum()}")
    print(f"High-severity (>= {SEVERITY_ALERT_THRESHOLD}) corroborated alerts: {len(alerts)}")
    print(f"{'='*60}\n")

    display_cols = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'flow_start_ts',
                     'flow_duration_s', 'bwd_bytes', 'fwd_bytes',
                     'flag_flow', 'flag_ipwin', 'flag_global', 'severity']
    display_cols = [c for c in display_cols if c in alerts.columns]

    if not alerts.empty:
        print(alerts[display_cols].head(30).to_string(index=False))
        alerts.to_csv("alerts.csv", index=False)
        print(f"\nFull alert list saved to alerts.csv ({len(alerts)} rows)")
    else:
        print("No high-severity alerts.")

    merged.to_csv("full_evaluation.csv", index=False)
    print(f"All scored+joined flows saved to full_evaluation.csv ({len(merged)} rows)")


if __name__ == "__main__":
    main()