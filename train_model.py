"""
Trains three Isolation Forest models:
  1. windows_model   -> windows.json     (5s traffic windows, burst detection)
  2. flows_model     -> flows.json       (per-flow/connection behavior)
  3. ip_windows_model -> ip_windows.json (per-IP, 5-min behavioral windows)

Run: python3 train_models.py
"""

import json
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

RANDOM_STATE = 42
CONTAMINATION = "auto"   # let IF decide; tune later once you have labeled/known anomalies to check against

TIME_BUCKETS = ['night', 'early_morning', 'morning', 'afternoon', 'evening', 'late_night']


def load(path):
    with open(path) as f:
        return pd.DataFrame(json.load(f))


def log_transform(df, cols):
    for c in cols:
        if c in df.columns:
            df[c] = np.log1p(df[c].clip(lower=0))
    return df


def one_hot_bucket(df):
    if 'time_bucket' in df.columns:
        for b in TIME_BUCKETS:
            df[f'bucket_{b}'] = (df['time_bucket'] == b).astype(int)
        df = df.drop(columns=['time_bucket'])
    return df


def train_and_report(df, feature_cols, name):
    X = df[feature_cols].fillna(0)
    model = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X)
    scores = model.decision_function(X)       # higher = more normal
    preds = model.predict(X)                  # -1 = anomaly, 1 = normal
    anomaly_rate = (preds == -1).mean()

    print(f"\n=== {name} ===")
    print(f"  rows trained on: {len(X)}")
    print(f"  features used:   {len(feature_cols)}")
    print(f"  flagged anomaly: {anomaly_rate:.2%}")
    print(f"  score range:     [{scores.min():.4f}, {scores.max():.4f}]")

    joblib.dump(model, f"{name}.joblib")
    print(f"  saved -> {name}.joblib")
    return model


# ── 1. windows.json (5s traffic windows) ──────────────────────────
print("Loading windows.json...")
w = load("windows.json")
w = one_hot_bucket(w)
drop_cols = ['timestamp', 'window_size_s']
w_features = [c for c in w.columns if c not in drop_cols]
# EMA + raw columns are both present; keeping both is fine for IF (redundant but not harmful),
# drop this line if you'd rather train on EMA-only or raw-only:
# w_features = [c for c in w_features if not c.startswith('ema_')]
train_and_report(w, w_features, "windows_model")


# ── 2. flows.json (per-flow records) ──────────────────────────────
print("\nLoading flows.json...")
fl = load("flows.json")
fl = one_hot_bucket(fl)
# log-transform the skewed byte/rate/duration columns
skew_cols = ['flow_duration_s', 'fwd_bytes', 'bwd_bytes',
             'flow_packets_per_s', 'flow_bytes_per_s',
             'fwd_bytes_per_s', 'bwd_bytes_per_s',
             'fwd_packets_per_s', 'bwd_packets_per_s']
fl = log_transform(fl, skew_cols)
# drop identifiers / non-numeric columns not meant as features
drop_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
fl_features = [c for c in fl.columns if c not in drop_cols]
# encode remaining categoricals
for cat_col in ['direction']:
    if cat_col in fl.columns:
        dummies = pd.get_dummies(fl[cat_col], prefix=cat_col)
        fl = pd.concat([fl, dummies], axis=1)
        fl_features = [c for c in fl_features if c != cat_col] + list(dummies.columns)
for bool_col in ['internal_src', 'internal_dst']:
    if bool_col in fl.columns:
        fl[bool_col] = fl[bool_col].astype(int)
train_and_report(fl, fl_features, "flows_model")


# ── 3. ip_windows.json (per-IP, 5-min windows) ─────────────────────
print("\nLoading ip_windows.json...")
ipw = load("ip_windows.json")
ipw = one_hot_bucket(ipw)
skew_cols = ['total_bytes', 'total_duration_s']
ipw = log_transform(ipw, skew_cols)
# IP itself is deliberately excluded as a feature (not a stable identity across networks/DHCP)
drop_cols = ['ip', 'window_start']
ipw_features = [c for c in ipw.columns if c not in drop_cols]
train_and_report(ipw, ipw_features, "ip_windows_model")

print("\nDone. Three .joblib model files saved in this directory.")