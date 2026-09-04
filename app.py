"""
Local IDS Anomaly Dashboard
============================
Reads the two CSV files your real_time_detection.py / evaluate.py pipeline
already writes:

    alerts_realtime.csv        (FAST tier alerts — flow / ip-window / window)
    alerts_corroborated.csv    (CORROBORATED tier alerts — joined evidence)

...and serves a live-updating local dashboard (dark HUD style) showing:
  - High / Medium / Low severity alert counts
  - Anomalies-over-time chart (last 7 days)
  - Top 5 source IPs by anomaly count
  - A live table of the most recent alerts

Nothing about your detection script needs to change — this just tails
the CSVs it already produces. Run it while real_time_detection.py is
running (or after a batch/pcap run) and refresh the browser.

Usage:
    python app.py
    python app.py --fast-file /path/to/alerts_realtime.csv \
                   --corroborated-file /path/to/alerts_corroborated.csv \
                   --port 5050
"""

import os
import time
import argparse
from datetime import datetime, timedelta

import pandas as pd
from flask import Flask, jsonify, render_template

app = Flask(__name__)

# ---- Config (overridden by CLI args in __main__) ----
ALERTS_FAST_FILE = os.environ.get("ALERTS_FAST_FILE", "alerts_realtime.csv")
ALERTS_CORR_FILE = os.environ.get("ALERTS_CORROBORATED_FILE", "alerts_corroborated.csv")

HIGH_THRESHOLD = 0.8
MEDIUM_THRESHOLD = 0.6


def _safe_read_csv(path):
    if not path or not os.path.exists(path):
        return pd.DataFrame()
    try:
        return pd.read_csv(path, encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return pd.read_csv(path, encoding="cp1252")
        except Exception as e:
            print(f"[WARN] failed to read {path} as cp1252 fallback: {e}")
            return pd.DataFrame()
    except Exception as e:
        print(f"[WARN] failed to read {path}: {e}")
        return pd.DataFrame()


def _load_alerts():
    """Load + normalize both alert tiers into one common-shape dataframe."""
    fast = _safe_read_csv(ALERTS_FAST_FILE)
    corr = _safe_read_csv(ALERTS_CORR_FILE)

    rows = []

    for _, r in fast.iterrows():
        rows.append({
            "tier": r.get("tier"),
            "alert_time": r.get("alert_time"),
            "severity": r.get("severity"),
            "src_ip": r.get("src_ip"),
            "dst_ip": r.get("dst_ip"),
            "attack": r.get("attack") if pd.notna(r.get("attack")) else "Unclassified anomaly",
            "confidence": r.get("confidence"),
            "reason": r.get("reason"),
        })

    for _, r in corr.iterrows():
        reason = r.get("reason_flow")
        if pd.isna(reason) or not reason:
            reason = r.get("reason_ipwin")
        if pd.isna(reason) or not reason:
            reason = r.get("reason_global")
        sev = r.get("severity")
        if pd.isna(sev):
            sev = r.get("corroborated_severity")
        rows.append({
            "tier": r.get("tier"),
            "alert_time": r.get("alert_time"),
            "severity": sev,
            "src_ip": r.get("src_ip"),
            "dst_ip": r.get("dst_ip"),
            "attack": "Corroborated anomaly",
            "confidence": None,
            "reason": reason,
        })

    cols = ["tier", "alert_time", "severity", "src_ip", "dst_ip", "attack", "confidence", "reason"]
    if not rows:
        return pd.DataFrame(columns=cols)

    df = pd.DataFrame(rows, columns=cols)
    df["severity"] = pd.to_numeric(df["severity"], errors="coerce")  #errors=coerce tells a funcion to convert invalid data into missing values (NaN) rather than throwing an error
    df["alert_time"] = pd.to_numeric(df["alert_time"], errors="coerce")
    df = df.dropna(subset=["alert_time"]) # drop rows where alert_time is NULL
    return df


def _severity_bucket(s):
    if pd.isna(s):
        return "low"
    if s > HIGH_THRESHOLD:
        return "high"
    if s >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def _last_7_day_buckets():
    today = datetime.now().date()
    return [today - timedelta(days=i) for i in range(6, -1, -1)]


def _daily_counts(df):
    buckets = {d: 0 for d in _last_7_day_buckets()}
    for t in df["alert_time"]:
        d = datetime.fromtimestamp(t).date()
        if d in buckets:
            buckets[d] += 1
    return [{"day": d.strftime("%a"), "date": d.isoformat(), "count": c} for d, c in buckets.items()]


ALERT_BUCKET_TITLES = {
    "high": "High Severity Alerts",
    "medium": "Medium Severity Alerts",
    "low": "Low Severity Alerts",
}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/alerts/<bucket>")
def alert_details(bucket):
    """Detail page for one severity bucket (high/medium/low)."""
    if bucket not in ALERT_BUCKET_TITLES:
        return "Unknown severity bucket", 404
    return render_template(
        "alert_details.html",
        bucket=bucket,
        title=ALERT_BUCKET_TITLES[bucket],
    )


@app.route("/api/alerts/<bucket>")
def api_alerts_by_bucket(bucket):
    """Full (non-truncated) alert list for one severity bucket, newest first."""
    if bucket not in ALERT_BUCKET_TITLES:
        return jsonify({"error": "unknown bucket"}), 404

    df = _load_alerts()
    if df.empty:
        return jsonify([])

    df["bucket"] = df["severity"].apply(_severity_bucket)
    df = df[df["bucket"] == bucket].sort_values("alert_time", ascending=False)

    out = []
    for _, r in df.iterrows():
        out.append({
            "time": datetime.fromtimestamp(r["alert_time"]).strftime("%Y-%m-%d %H:%M:%S"),
            "tier": r["tier"] if pd.notna(r["tier"]) else "—",
            "src_ip": r["src_ip"] if pd.notna(r["src_ip"]) else "—",
            "dst_ip": r["dst_ip"] if pd.notna(r["dst_ip"]) else "—",
            "attack": r["attack"],
            "severity": round(float(r["severity"]), 2) if pd.notna(r["severity"]) else None,
            "confidence": r["confidence"] if pd.notna(r["confidence"]) else "—",
            "reason": r["reason"] if pd.notna(r["reason"]) else "",
        })
    return jsonify(out)


@app.route("/ip/<ip>")
def ip_details(ip):
    """Detail page for one source IP's activity."""
    return render_template("IP_details.html", ip=ip)


@app.route("/api/ip/<ip>")
def api_ip_details(ip):
    """All events, attack breakdown, and timeline for a single source IP."""
    df = _load_alerts()
    df = df[df["src_ip"] == ip]

    if df.empty:
        return jsonify({
            "ip": ip,
            "total_events": 0,
            "first_seen": None,
            "last_active": None,
            "avg_severity": None,
            "attack_breakdown": [],
            "timeline": [],
            "events": [],
        })

    df["bucket"] = df["severity"].apply(_severity_bucket)
    df = df.sort_values("alert_time", ascending=False)

    first_seen = float(df["alert_time"].min())
    last_active = float(df["alert_time"].max())
    avg_severity = df["severity"].dropna()
    avg_severity = round(float(avg_severity.mean()), 2) if not avg_severity.empty else None

    attack_counts = df["attack"].value_counts()
    attack_breakdown = [{"attack": a, "count": int(c)} for a, c in attack_counts.items()]

    # Daily counts over the span this IP actually has data for (capped at 14 days)
    today = datetime.now().date()
    span_days = min(14, max(1, (today - datetime.fromtimestamp(first_seen).date()).days + 1))
    buckets = {today - timedelta(days=i): 0 for i in range(span_days - 1, -1, -1)}
    for t in df["alert_time"]:
        d = datetime.fromtimestamp(t).date()
        if d in buckets:
            buckets[d] += 1
    timeline = [{"day": d.strftime("%b %d"), "date": d.isoformat(), "count": c} for d, c in buckets.items()]

    events = []
    for _, r in df.iterrows():
        events.append({
            "time": datetime.fromtimestamp(r["alert_time"]).strftime("%Y-%m-%d %H:%M:%S"),
            "tier": r["tier"] if pd.notna(r["tier"]) else "—",
            "dst_ip": r["dst_ip"] if pd.notna(r["dst_ip"]) else "—",
            "attack": r["attack"],
            "severity": round(float(r["severity"]), 2) if pd.notna(r["severity"]) else None,
            "bucket": r["bucket"],
            "confidence": r["confidence"] if pd.notna(r["confidence"]) else "—",
            "reason": r["reason"] if pd.notna(r["reason"]) else "",
        })

    return jsonify({
        "ip": ip,
        "total_events": int(len(df)),
        "first_seen": first_seen,
        "last_active": last_active,
        "avg_severity": avg_severity,
        "attack_breakdown": attack_breakdown,
        "timeline": timeline,
        "events": events,
    })


@app.route("/api/summary")
def summary():
    df = _load_alerts()
    now = time.time()

    if df.empty:
        return jsonify({
            "high": 0, "medium": 0, "low": 0,
            "high_delta": 0, "medium_delta": 0, "low_delta": 0,
            "daily": [{"day": d.strftime("%a"), "date": d.isoformat(), "count": 0} for d in _last_7_day_buckets()],
            "top_ips": [],
            "total_alerts": 0,
            "last_alert_time": None,
            "monitoring": _is_monitoring(None),
        })

    df["bucket"] = df["severity"].apply(_severity_bucket)
    counts = df["bucket"].value_counts().to_dict()

    last_24h = df[df["alert_time"] >= now - 86400]
    deltas = last_24h["bucket"].value_counts().to_dict()

    top_ips = df["src_ip"].dropna().value_counts().head(5).reset_index()
    top_ips.columns = ["ip", "count"]

    last_alert_time = float(df["alert_time"].max())

    return jsonify({
        "high": int(counts.get("high", 0)),
        "medium": int(counts.get("medium", 0)),
        "low": int(counts.get("low", 0)),
        "high_delta": int(deltas.get("high", 0)),
        "medium_delta": int(deltas.get("medium", 0)),
        "low_delta": int(deltas.get("low", 0)),
        "daily": _daily_counts(df),
        "top_ips": top_ips.to_dict(orient="records"),
        "total_alerts": int(len(df)),
        "last_alert_time": last_alert_time,
        "monitoring": _is_monitoring(last_alert_time),
    })


@app.route("/api/recent")
def recent():
    df = _load_alerts()
    if df.empty:
        return jsonify([])
    df["bucket"] = df["severity"].apply(_severity_bucket)
    df = df.sort_values("alert_time", ascending=False).head(30)
    out = []
    for _, r in df.iterrows():
        out.append({
            "time": datetime.fromtimestamp(r["alert_time"]).strftime("%Y-%m-%d %H:%M:%S"),
            "tier": r["tier"],
            "src_ip": r["src_ip"] if pd.notna(r["src_ip"]) else "—",
            "attack": r["attack"],
            "severity": round(float(r["severity"]), 2) if pd.notna(r["severity"]) else None,
            "bucket": r["bucket"],
            "reason": r["reason"] if pd.notna(r["reason"]) else "",
        })
    return jsonify(out)


def _is_monitoring(last_alert_time, idle_ok_s=300):
    """Best-effort 'is the pipeline live' flag: files touched recently."""
    for path in (ALERTS_FAST_FILE, ALERTS_CORR_FILE):
        if path and os.path.exists(path):
            if (time.time() - os.path.getmtime(path)) < idle_ok_s:
                return True
    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Local IDS anomaly dashboard")
    parser.add_argument("--fast-file", default=ALERTS_FAST_FILE,
                         help="Path to alerts_realtime.csv")
    parser.add_argument("--corroborated-file", default=ALERTS_CORR_FILE,
                         help="Path to alerts_corroborated.csv")
    parser.add_argument("--port", type=int, default=5050)
    args = parser.parse_args()

    ALERTS_FAST_FILE = args.fast_file
    ALERTS_CORR_FILE = args.corroborated_file

    print("=" * 55)
    print("  Local Anomaly Detection Dashboard")
    print("=" * 55)
    print(f"  FAST alerts file:         {os.path.abspath(ALERTS_FAST_FILE)}")
    print(f"  CORROBORATED alerts file: {os.path.abspath(ALERTS_CORR_FILE)}")
    print(f"  Open: http://127.0.0.1:{args.port}")
    app.run(debug=False, port=args.port)