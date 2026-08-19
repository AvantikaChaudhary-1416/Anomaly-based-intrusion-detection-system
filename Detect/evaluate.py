import pandas as pd
import json
import joblib

# ── Config ────────────────────────────────────────────────────────
DETECT_FLOWS_FILE      = "detect_flows.json"
DETECT_WINDOWS_FILE    = "detect_windows.json"
DETECT_IP_WINDOWS_FILE = "detect_ip_windows.json"

FLOWS_MODEL_PATH      = "flows_model.joblib"
IP_WINDOWS_MODEL_PATH = "ip_windows_model.joblib"
WINDOWS_MODEL_PATH    = "windows_model.joblib"

# corroboration weights — flows_model is volume-biased/noisy (see project notes),
# ip_windows/windows are structurally harder to fool with a single large transfer
WEIGHTS = {'flow': 0.2, 'ipwin': 0.4, 'global': 0.4}
SEVERITY_ALERT_THRESHOLD = 0.6
# ─────────────────────────────────────────────────────────────────


def load_and_score(json_path, model_path):
    """Load a detection-data JSON, score it with its trained model.
    Uses the (model, feature_cols) bundle saved at training time so
    the feature set/order is guaranteed to match what the model was fit on."""
    with open(json_path) as f:
        df = pd.DataFrame(json.load(f))

    if df.empty:
        print(f"[warn] {json_path} is empty — no rows to score")
        return df

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
    flows = load_and_score(DETECT_FLOWS_FILE, FLOWS_MODEL_PATH)
    print(f"  {len(flows)} flows scored")

    print("Loading and scoring ip_windows...")
    ip_windows = load_and_score(DETECT_IP_WINDOWS_FILE, IP_WINDOWS_MODEL_PATH)
    print(f"  {len(ip_windows)} ip_window rows scored")

    print("Loading and scoring windows...")
    windows = load_and_score(DETECT_WINDOWS_FILE, WINDOWS_MODEL_PATH)
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
            columns={'score': 'score_ipwin', 'flag': 'flag_ipwin'}   #only taking particular columns form ip_windows
        )
        merged = flows.merge(
            ip_win_scored,
            left_on=['src_ip', 'ip_window_start_ts'],
            right_on=['ip', 'window_start'],
            how='left'
        )
        #in flows, we have src_ip and ip_window_start_ts, in ip_windows we have ip and window_start, so we are merging on those columns to get the score and flag from ip_windows into flows 
        # flows is the left df and ip the right df left_on=> feature name in flow right_on=> feature name in ip_windows
        # how='left' means we want to keep all rows from flows and only matching rows from ip_windows, if there is no match we will have NaN in the new columns


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