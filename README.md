# Anomaly-Based Network Intrusion Detection System

Unsupervised IDS using three Isolation Forest models trained on real captured traffic, operating at different granularities: per-flow, per-IP (5-min window), and global (5-sec window). Flags from all three are combined into a weighted severity score per flow.

## Pipeline

```
pcap → baseline_capture.py → flows/ip_windows/windows.json → train_model.py → *.joblib
pcap → detect_capture.py   → detect_*.json                 → evaluate.py    → alerts.csv
```

`preprocess.py` holds shared feature engineering used by both training and detection, so the two stay in sync.

## Why three models

A single anomaly can show up at different scales — an odd single connection, one IP acting up over a few minutes, or a network-wide shift. Each model catches a different one; corroboration across models (weighted severity: flow 0.2, ip-window 0.4, global 0.4) is a stronger signal than any single flag.

## Key design decisions

- **Log-transform on skewed columns** (byte counts, packet counts, ACK/PSH counts, rates) — raw values are heavy-tailed, and IsolationForest's random splits tend to isolate large-but-legitimate flows just for being numerically far from the bulk.
- **Manual one-hot for time buckets & direction**, not `pd.get_dummies` — a capture missing a category (e.g. no LAN-local traffic) would otherwise silently drop a feature column the model was trained on.
- **Raw timestamps excluded from features** — they don't generalize across capture sessions and were previously leaking in unintentionally.
- **`contamination=0.05`**, set explicitly instead of `"auto"` — training data is curated benign traffic, so this reflects an assumed ~5% baseline of atypical-but-benign patterns rather than a data-dependent heuristic.

## What the model actually detects

Verified via feature-mean comparison between flagged/normal groups (consistent across train and detect data): the dominant signal is **flow volume** — ACK count, PSH count, packet count, avg packet size. This is a "moved unusually large/sustained data" detector, not a semantic attack classifier.

## Limitations

- Anomaly detection, not attack detection — no labeled/injected attack data to validate precision/recall.
- No timing-based features, so Slowloris-style low-and-slow attacks aren't well covered.
- Flagged rates on short detection captures are less statistically stable than on the larger training set.
- Models are trained on one home network's traffic; running against a very different network will likely shift flagged rates for reasons unrelated to actual anomalies.

## Usage

```bash
# retrain on your own capture
cd Baseline
python baseline_capture.py <capture.pcap>
python train_model.py

# evaluate a new capture
cd Detect
python detect_capture.py <capture.pcap>
python evaluate.py
```

Pretrained models are included in `pre Trained models/` so `evaluate.py` works out of the box without retraining.

## Repo layout

```
Baseline/            baseline_capture.py, train_model.py
Detect/               detect_capture.py, evaluate.py, rule_based.py (stub, not implemented)
pre Trained models/   flows_model.joblib, ip_windows_model.joblib, windows_model.joblib
tools to evaluate/    diagnostic scripts used during model debugging
preprocess.py         shared feature engineering
```

`*.json` and `*.csv` are gitignored — raw/derived captures from a specific network, not meant to be redistributed.

## Future work

- Integrate `rule_based.py` (signature/threshold rules) alongside the ML layer
- Timing features for slow-attack coverage
- Labeled attack validation set
- Bidirectional flow merging (currently client→server and server→client legs are separate rows)