import json
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from preprocess import(preprocess_windows,preprocess_flows,preprocess_ip_windows)

RANDOM_STATE = 42
CONTAMINATION = 0.05  # curated benign training data -> assume ~5% edge-case-but-benign patterns

# models are saved to ids/pre Trained models/ regardless of which script runs this,
# since this script lives in ids/Baseline/
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pre_Trained_models")
os.makedirs(MODEL_DIR, exist_ok=True)


def load(path):
    with open(path) as f:
        return pd.DataFrame(json.load(f))


def train_and_report(df, feature_cols, name):
    X = df[feature_cols].fillna(0)      #keeps only required features and fills 0 where there is NaN
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

    save_path = os.path.join(MODEL_DIR, f"{name}.joblib")
    joblib.dump({'model': model, 'feature_cols': feature_cols}, save_path)
    print(f"  saved -> {save_path}")
    return model


# ── 1. windows.json (5s traffic windows) ──────────────────────────
print("Loading windows.json...")
w = load("windows.json")
w,w_features=preprocess_windows(w)
print(w_features)
train_and_report(w, w_features, "windows_model")


# ── 2. flows.json (per-flow records) ──────────────────────────────
print("\nLoading flows.json...")
fl = load("flows.json")
fl,fl_features=preprocess_flows(fl)
print(fl_features)
train_and_report(fl, fl_features, "flows_model")


# ── 3. ip_windows.json (per-IP, 5-min windows) ─────────────────────
print("\nLoading ip_windows.json...")
ipw = load("ip_windows.json")
ipw,ipw_features=preprocess_ip_windows(ipw)
print(ipw_features)
train_and_report(ipw, ipw_features, "ip_windows_model")

print(f"\nDone. Three .joblib model files saved in '{MODEL_DIR}'.")