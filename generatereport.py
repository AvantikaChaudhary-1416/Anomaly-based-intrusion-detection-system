"""
generate_report.py

Standalone analysis/reporting tool. Run AFTER evaluate.py has produced
full_evaluation.csv and alerts.csv in the current directory.

Usage:
    python generate_report.py
    python generate_report.py --dir path/to/Detect --top 5

Outputs:
    report.html
    report.pdf
"""
import argparse
import base64
import io
import os
from datetime import datetime

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, Image as RLImage, PageBreak)

plt.style.use("dark_background")
ACCENT = "#4fd1c5"
DANGER = "#ef5b5b"
DIM = "#8a97a8"

# ── Heuristic signature rules ───────────────────────────────────────
# Each rule: (name, condition(features_dict) -> bool, explanation, benign_alt)
# `features_dict` maps feature name -> z-score (flagged IP mean vs normal pop mean/std)
# Applied against the TOP deviating features for that IP, not the raw data,
# so these are pattern-matches on "what stood out", not ground truth labels.

def _get(z, *names):
    return max((z.get(n, 0) for n in names), default=0)


def classify_pattern(z, extra):
    """extra: dict with unique_dst_ports, unique_src_ports, flow_count, avg_duration"""
    findings = []

    high_ports_fanout = extra.get('unique_dst_ports', 0) >= 5 and extra.get('avg_duration', 999) < 0.5
    if high_ports_fanout:
        findings.append((
            "Port-scan-like fan-out",
            f"This IP touched {extra['unique_dst_ports']} distinct destination ports with very short "
            f"average flow duration ({extra['avg_duration']:.3f}s) — a pattern consistent with port "
            f"scanning or service enumeration.",
            "Could also be a legitimate service probe (health checks, monitoring tools) or a client "
            "app briefly touching several ports on startup."
        ))

    high_src_ports_one_dst = extra.get('unique_src_ports', 0) >= 5 and extra.get('unique_dst_ips', 1) <= 2
    if high_src_ports_one_dst and not high_ports_fanout:
        findings.append((
            "Parallel-connection burst",
            f"This IP opened {extra['unique_src_ports']} separate connections to essentially the same "
            f"destination(s) in a short window — typical of a browser/app loading many resources in "
            f"parallel, or a resumed/retried session.",
            "Usually benign (page load, video/app sync). Worth checking if destination is an "
            "unfamiliar or newly-seen external host."
        ))

    high_volume = _get(z, 'ack_count', 'psh_count', 'fwd_packets', 'bwd_packets') > 2.0
    if high_volume:
        findings.append((
            "High-volume sustained transfer",
            "Packet/ACK/PSH counts for this IP's flows are well above the trained baseline mean — "
            "consistent with a large, sustained data transfer.",
            "Commonly a legitimate bulk download, video stream, or cloud backup/sync. Also the "
            "pattern expected from data exfiltration if the destination or timing is unexpected."
        ))

    short_burst_same_dst = extra.get('avg_duration', 999) < 0.05 and extra.get('flow_count', 0) >= 4
    if short_burst_same_dst:
        findings.append((
            "Rapid repeated short connections",
            f"{extra['flow_count']} very short flows ({extra['avg_duration']*1000:.1f}ms avg) to the "
            f"same destination in the window — resembles TLS session resumption/keep-alive churn, "
            f"but can also resemble beaconing (periodic C2 check-ins) if it recurs across many windows.",
            "Check whether this recurs at regular intervals across multiple capture windows — a "
            "single burst is more likely benign resumption than beaconing."
        ))

    if not findings:
        top_feat = max(z.items(), key=lambda kv: abs(kv[1])) if z else ("n/a", 0)
        findings.append((
            "No specific known pattern matched",
            f"Flagged primarily on '{top_feat[0]}' (z={top_feat[1]:.2f} vs baseline) without matching "
            f"a recognized signature shape. Likely a generic statistical outlier on that feature.",
            "Manual inspection of the raw flow is recommended — could be a novel legitimate app "
            "behavior not present in training data, or something worth a closer look."
        ))

    return findings


# ── Data loading & analysis ─────────────────────────────────────────
def load_data(data_dir):
    full = pd.read_csv(os.path.join(data_dir, "full_evaluation.csv"))
    alerts_path = os.path.join(data_dir, "alerts.csv")
    alerts = pd.read_csv(alerts_path) if os.path.exists(alerts_path) else full.iloc[0:0]
    return full, alerts


NUMERIC_FEATURES = [
    'flow_duration_s', 'fwd_bytes', 'bwd_bytes', 'flow_packets_per_s',
    'flow_bytes_per_s', 'fwd_bytes_per_s', 'bwd_bytes_per_s', 'fwd_packets_per_s',
    'bwd_packets_per_s', 'fwd_packets', 'bwd_packets', 'avg_fwd_pkt_size',
    'avg_bwd_pkt_size', 'syn_count', 'ack_count', 'fin_count', 'rst_count', 'psh_count'
]


def analyze_top_ips(full, alerts, top_n=5):
    if alerts.empty:
        return []

    normal = full[full['flag_flow'] == 1]
    present_features = [f for f in NUMERIC_FEATURES if f in full.columns]
    norm_mean = normal[present_features].mean()
    norm_std = normal[present_features].std().replace(0, 1)

    top_ips = alerts['src_ip'].value_counts().head(top_n)

    results = []
    for ip, count in top_ips.items():
        ip_alerts = alerts[alerts['src_ip'] == ip]
        ip_mean = ip_alerts[present_features].mean()
        z = ((ip_mean - norm_mean) / norm_std).to_dict()
        top_z = dict(sorted(z.items(), key=lambda kv: -abs(kv[1]))[:6])

        extra = {
            'unique_dst_ports': ip_alerts['dst_port'].nunique() if 'dst_port' in ip_alerts else 0,
            'unique_src_ports': ip_alerts['src_port'].nunique() if 'src_port' in ip_alerts else 0,
            'unique_dst_ips': ip_alerts['dst_ip'].nunique() if 'dst_ip' in ip_alerts else 0,
            'flow_count': len(ip_alerts),
            'avg_duration': ip_alerts['flow_duration_s'].mean() if 'flow_duration_s' in ip_alerts else 999,
        }
        findings = classify_pattern(top_z, extra)

        results.append({
            'ip': ip,
            'alert_count': int(count),
            'top_z': top_z,
            'extra': extra,
            'findings': findings,
            'sample_dst_ips': ip_alerts['dst_ip'].value_counts().head(3).to_dict() if 'dst_ip' in ip_alerts else {},
            'max_severity': float(ip_alerts['severity'].max()),
        })
    return results


# ── Charts (matplotlib -> PNG bytes) ────────────────────────────────
def _fig_to_png_bytes(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=140, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def chart_severity_distribution(full):
    counts = full['severity'].value_counts().sort_index()
    fig, ax = plt.subplots(figsize=(6, 3.2))
    ax.bar(counts.index.astype(str), counts.values, color=ACCENT, width=0.6)
    ax.set_xlabel("Severity score")
    ax.set_ylabel("Flow count")
    ax.set_title("Severity distribution across all evaluated flows")
    fig.tight_layout()
    return _fig_to_png_bytes(fig)


def chart_top_talkers(alerts, top_n=5):
    counts = alerts['src_ip'].value_counts().head(top_n)
    fig, ax = plt.subplots(figsize=(6, 3.2))
    ax.barh(counts.index[::-1], counts.values[::-1], color=DANGER)
    ax.set_xlabel("Number of high-severity alerts")
    ax.set_title(f"Top {top_n} source IPs by alert count")
    fig.tight_layout()
    return _fig_to_png_bytes(fig)


def chart_ip_feature_deviation(ip_result):
    z = ip_result['top_z']
    names = list(z.keys())
    values = list(z.values())
    colors_ = [DANGER if v > 0 else ACCENT for v in values]
    fig, ax = plt.subplots(figsize=(6, 2.6))
    ax.barh(names[::-1], values[::-1], color=colors_[::-1])
    ax.axvline(0, color=DIM, linewidth=0.8)
    ax.set_xlabel("z-score vs. normal baseline")
    ax.set_title(f"Top deviating features — {ip_result['ip']}")
    fig.tight_layout()
    return _fig_to_png_bytes(fig)


def png_to_b64(png_bytes):
    return base64.b64encode(png_bytes).decode('ascii')


# ── HTML report ──────────────────────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>IDS Anomaly Report</title>
<style>
  body {{ background:#0b0f14; color:#e5eaf0; font-family:'Segoe UI',system-ui,sans-serif; max-width:900px; margin:0 auto; padding:2rem; }}
  h1 {{ font-size:1.4rem; }}
  h2 {{ font-size:1.1rem; border-bottom:1px solid #1f2a37; padding-bottom:0.4rem; margin-top:2rem; }}
  .meta {{ color:#8a97a8; font-size:0.85rem; margin-bottom:2rem; }}
  .stat-row {{ display:flex; gap:1rem; margin:1rem 0; }}
  .stat {{ background:#121820; border:1px solid #1f2a37; border-radius:8px; padding:1rem 1.3rem; flex:1; }}
  .stat .num {{ font-size:1.4rem; font-weight:700; color:#4fd1c5; }}
  .stat .label {{ font-size:0.75rem; color:#8a97a8; text-transform:uppercase; }}
  .ip-block {{ background:#121820; border:1px solid #1f2a37; border-radius:8px; padding:1.2rem; margin:1rem 0; }}
  .ip-block h3 {{ margin-top:0; color:#4fd1c5; }}
  .finding {{ margin:0.8rem 0; padding:0.7rem 1rem; background:#0e141b; border-left:3px solid #ef5b5b; border-radius:4px; }}
  .finding .title {{ font-weight:600; }}
  .finding .alt {{ color:#8a97a8; font-size:0.85rem; margin-top:0.4rem; }}
  img {{ max-width:100%; border-radius:6px; margin:0.5rem 0; }}
  table {{ width:100%; border-collapse:collapse; font-size:0.85rem; margin-top:0.5rem;}}
  td, th {{ padding:0.35rem 0.6rem; border-bottom:1px solid #1f2a37; text-align:left; }}
</style></head>
<body>
<h1>Anomaly Detection Report</h1>
<div class="meta">Generated {generated_at} &middot; source: {data_dir}</div>

<div class="stat-row">
  <div class="stat"><div class="num">{total_flows}</div><div class="label">Flows evaluated</div></div>
  <div class="stat"><div class="num">{alert_count}</div><div class="label">High-severity alerts</div></div>
  <div class="stat"><div class="num">{unique_ips}</div><div class="label">Distinct flagged IPs</div></div>
</div>

<h2>Severity distribution</h2>
<img src="data:image/png;base64,{sev_chart}">

<h2>Top {top_n} talkers</h2>
<img src="data:image/png;base64,{talker_chart}">

<h2>Why these were flagged</h2>
{ip_sections}

<h2>Notes on interpretation</h2>
<p style="color:#8a97a8; font-size:0.85rem;">
This is an unsupervised anomaly detector (IsolationForest), not a labeled attack classifier.
Findings above describe <em>statistical deviation from the trained baseline</em> and pattern-match
that deviation against known suspicious shapes (port-scan-like, beaconing-like, etc.) purely as a
heuristic aid. Each finding lists a plausible benign explanation alongside the potential-attack
framing — treat this report as a triage starting point, not a verdict.
</p>

</body></html>
"""

IP_SECTION_TEMPLATE = """
<div class="ip-block">
  <h3>{ip}  &nbsp;<span style="color:#8a97a8; font-size:0.8rem;">({alert_count} alerts, max severity {max_severity:.1f})</span></h3>
  <img src="data:image/png;base64,{chart}">
  {findings_html}
  <table>
    <tr><th>Sample destinations</th><th>Count</th></tr>
    {dst_rows}
  </table>
</div>
"""

FINDING_TEMPLATE = """
<div class="finding">
  <div class="title">{title}</div>
  <div>{explanation}</div>
  <div class="alt"><strong>Alternative benign explanation:</strong> {benign_alt}</div>
</div>
"""


def build_html_report(full, alerts, ip_results, data_dir, top_n, out_path):
    sev_chart = png_to_b64(chart_severity_distribution(full))
    talker_chart = png_to_b64(chart_top_talkers(alerts, top_n)) if not alerts.empty else ""

    ip_sections = ""
    for r in ip_results:
        chart = png_to_b64(chart_ip_feature_deviation(r))
        findings_html = "".join(
            FINDING_TEMPLATE.format(title=t, explanation=e, benign_alt=b)
            for t, e, b in r['findings']
        )
        dst_rows = "".join(f"<tr><td>{d}</td><td>{c}</td></tr>" for d, c in r['sample_dst_ips'].items())
        ip_sections += IP_SECTION_TEMPLATE.format(
            ip=r['ip'], alert_count=r['alert_count'], max_severity=r['max_severity'],
            chart=chart, findings_html=findings_html, dst_rows=dst_rows
        )

    html = HTML_TEMPLATE.format(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        data_dir=os.path.abspath(data_dir),
        total_flows=len(full),
        alert_count=len(alerts),
        unique_ips=alerts['src_ip'].nunique() if not alerts.empty else 0,
        sev_chart=sev_chart,
        talker_chart=talker_chart,
        top_n=top_n,
        ip_sections=ip_sections if ip_results else "<p>No alerts to analyze.</p>",
    )
    with open(out_path, "w") as f:
        f.write(html)


# ── PDF report ────────────────────────────────────────────────────────
def build_pdf_report(full, alerts, ip_results, data_dir, top_n, out_path):
    doc = SimpleDocTemplate(out_path, pagesize=letter,
                             topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('T', parent=styles['Title'], fontSize=18)
    h2 = ParagraphStyle('H2', parent=styles['Heading2'], spaceBefore=14)
    body = styles['Normal']
    dim = ParagraphStyle('Dim', parent=styles['Normal'], textColor=colors.grey, fontSize=8)
    finding_title = ParagraphStyle('FT', parent=styles['Normal'], fontName='Helvetica-Bold')

    story = []
    story.append(Paragraph("Anomaly Detection Report", title_style))
    story.append(Paragraph(
        f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} &middot; source: {os.path.abspath(data_dir)}",
        dim))
    story.append(Spacer(1, 12))

    stat_table = Table([
        ["Flows evaluated", "High-severity alerts", "Distinct flagged IPs"],
        [str(len(full)), str(len(alerts)),
         str(alerts['src_ip'].nunique() if not alerts.empty else 0)]
    ], colWidths=[2.5 * inch] * 3)
    stat_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f2a37')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(stat_table)

    story.append(Paragraph("Severity distribution", h2))
    sev_png = chart_severity_distribution(full)
    story.append(RLImage(io.BytesIO(sev_png), width=5.5 * inch, height=2.9 * inch))

    if not alerts.empty:
        story.append(Paragraph(f"Top {top_n} talkers", h2))
        talker_png = chart_top_talkers(alerts, top_n)
        story.append(RLImage(io.BytesIO(talker_png), width=5.5 * inch, height=2.9 * inch))

    story.append(PageBreak())
    story.append(Paragraph("Why these were flagged", h2))

    for r in ip_results:
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            f"<b>{r['ip']}</b> — {r['alert_count']} alerts, max severity {r['max_severity']:.1f}",
            styles['Heading3']))
        chart_png = chart_ip_feature_deviation(r)
        story.append(RLImage(io.BytesIO(chart_png), width=5.5 * inch, height=2.4 * inch))
        for t, e, b in r['findings']:
            story.append(Paragraph(t, finding_title))
            story.append(Paragraph(e, body))
            story.append(Paragraph(f"<i>Alternative benign explanation:</i> {b}", dim))
            story.append(Spacer(1, 6))

    story.append(PageBreak())
    story.append(Paragraph("Notes on interpretation", h2))
    story.append(Paragraph(
        "This is an unsupervised anomaly detector (IsolationForest), not a labeled attack "
        "classifier. Findings describe statistical deviation from the trained baseline and "
        "pattern-match that deviation against known suspicious shapes (port-scan-like, "
        "beaconing-like, etc.) purely as a heuristic aid. Each finding lists a plausible benign "
        "explanation alongside the potential-attack framing — treat this report as a triage "
        "starting point, not a verdict.", body))

    doc.build(story)


def main():
    parser = argparse.ArgumentParser(description="Generate an anomaly analysis report.")
    parser.add_argument("--dir", default=".", help="Directory containing full_evaluation.csv / alerts.csv")
    parser.add_argument("--top", type=int, default=5, help="Number of top IPs to analyze")
    args = parser.parse_args()

    full, alerts = load_data(args.dir)
    ip_results = analyze_top_ips(full, alerts, top_n=args.top)

    html_path = os.path.join(args.dir, "report.html")
    pdf_path = os.path.join(args.dir, "report.pdf")

    build_html_report(full, alerts, ip_results, args.dir, args.top, html_path)
    build_pdf_report(full, alerts, ip_results, args.dir, args.top, pdf_path)

    print(f"Report written to:\n  {html_path}\n  {pdf_path}")
    if not alerts.empty:
        print(f"\nTop {len(ip_results)} flagged IPs:")
        for r in ip_results:
            print(f"  {r['ip']:20s}  {r['alert_count']:3d} alerts  -> {r['findings'][0][0]}")


if __name__ == "__main__":
    main()