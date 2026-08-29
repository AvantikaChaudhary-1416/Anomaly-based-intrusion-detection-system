# ============================================================
# check_signature.py
# Rule-based signature matching on top of Mahalanobis top-N features.
# top_features: list of feature names that were top contributors
#               (from explain()'s top-3, or pass more if you want
#               broader matching — see note at bottom)
# row: the raw/preprocessed row dict, used to pull actual values
#      for the "reason" text and to distinguish direction (high vs low)
# ============================================================

matches = []
reasons =[]

def _has_all(top_features, *cols):
    return all(c in top_features for c in cols)


def _has_any(top_features, *cols):
    return any(c in top_features for c in cols)


def checkSignatures(row, top_features):
    matches.clear()  # reset per-row; caller should read matches right after calling
    reasons.clear()

    # ============================================================
    # WINDOW-MODEL SIGNATURES (global 5s window features)
    # ============================================================

    # ---- Port scans (SYN / FIN / NULL / XMAS variants), inbound external ----
    if _has_all(top_features, "inbound_external_syn", "inbound_external_unique_dst_ports", "inbound_external_uncommon_port_count"):
        matches.append({
            "attack": "SYN port scan (inbound, external source)",
            "confidence": "high",
            "reason": "External SYN traffic anomalous together with destination-port diversity and uncommon-port activity."
        })
        reasons.append('port scan')

    if _has_all(top_features, "inbound_external_fin", "inbound_external_unique_dst_ports", "inbound_external_uncommon_port_count"):
        matches.append({
            "attack": "FIN port scan (inbound, external source)",
            "confidence": "high",
            "reason": "External FIN traffic anomalous together with destination-port diversity — classic stealth scan signature (no full handshake)."
        })
        reasons.append('port scan')

    if _has_all(top_features, "inbound_external_syn", "inbound_external_ack") and not _has_any(top_features, "inbound_external_unique_dst_ports"):
        matches.append({
            "attack": "Possible SYN flood (single target, not a scan)",
            "confidence": "medium",
            "reason": "SYN/ACK anomaly without accompanying port diversity — looks like volume against one service rather than reconnaissance."
        })
        reasons.append('syn flood')

    # ---- Outbound scanning (compromised internal host scanning out) ----
    if _has_all(top_features, "outbound_external_syn", "outbound_external_unique_dst_ports"):
        matches.append({
            "attack": "Outbound SYN scan (possible compromised internal host)",
            "confidence": "high",
            "reason": "Internal source generating anomalous SYN traffic across many ports of an external device."
        })
        reasons.append('outbound port scan')

    if _has_all(top_features,"outbound_external_syn", "outbound_external_unique_dst_ips"):
        matches.append({
                    "attack": "Outbound vertical SYN scan (possible compromised internal host)",
                    "confidence": "high",
                    "reason": "Internal source generating anomalous SYN traffic across many external devices."
                })

    if _has_all(top_features, "outbound_internal_syn", "outbound_internal_unique_dst_ports"):
        matches.append({
            "attack": "Internal device port  scan",
            "confidence": "high",
            "reason": "Anomalous SYN traffic spreading across many internal destination IPs/ports — consistent with lateral scanning inside the network."
        })

    if _has_all(top_features,"outbound_internal_syn", "outbound_internal_unique_dst_ips"):
        matches.append({
            "attack": "internal lateral movement",
            "confidence": "high",
            "reason": "Internal source generating anomalous SYN traffic across many external devices."
        })

    # ---- ICMP / ping sweep ----
    if _has_all(top_features, "outbound_external_icmp", "outbound_external_unique_dst_ips"):
        matches.append({
            "attack": "ICMP ping sweep (outbound)",
            "confidence": "medium",
            "reason": "Anomalous outbound ICMP volume spread across many destination IPs — host/network discovery pattern."
        })

    if _has_all(top_features, "inbound_external_icmp", "inbound_external_unique_dst_ips"):
        matches.append({
            "attack": "ICMP ping sweep (inbound)",
            "confidence": "medium",
            "reason": "Anomalous inbound ICMP from many sources/targets — possible reconnaissance sweep."
        })

    # ---- Half-open connection flood (SYN flood at the handshake-tracking level) ----
    if _has_any(top_features, "half_open_conns_active", "ema_half_open_conns_active"):
        matches.append({
            "attack": "SYN flood / half-open connection exhaustion",
            "confidence": "high",
            "reason": "Anomalous number of concurrent half-open TCP handshakes — connections initiated but never completed, consistent with a SYN flood."
        })

    # ---- DNS-based signatures ----
    if _has_all(top_features, "dns_responses_unmatched", "dns_bytes_total"):
        matches.append({
            "attack": "DNS amplification / reflection",
            "confidence": "high",
            "reason": "Large volume of unmatched DNS responses with high DNS byte volume — consistent with amplification attack traffic or response spoofing."
        })
    elif "dns_responses_unmatched" in top_features:
        matches.append({
            "attack": "Unsolicited / spoofed DNS responses",
            "confidence": "medium",
            "reason": "DNS responses with no matching outbound query — possible cache poisoning attempt or spoofed traffic."
        })

    if "dns_responses" in top_features and "dns_bytes_total" in top_features:
        matches.append({
            "attack": "DNS tunneling / abnormal DNS volume",
            "confidence": "low",
            "reason": "Unusually high DNS response volume/bytes — worth checking for tunneling or exfiltration over DNS."
        })

    # ============================================================
    # FLOW-MODEL SIGNATURES (per-flow features)
    # ============================================================

    if _has_all(top_features, "flow_bytes_per_s", "flow_packets_per_s") and _has_any(top_features, "fwd_bytes_per_s", "bwd_bytes_per_s"):
        direction = "outbound (fwd)" if row.get("fwd_bytes_per_s", 0) > row.get("bwd_bytes_per_s", 0) else "inbound (bwd)"
        matches.append({
            "attack": "High-rate single flow (possible flood or exfiltration)",
            "confidence": "medium",
            "reason": f"Single flow shows anomalous byte/packet rate, dominated by {direction} traffic."
        })

    if _has_all(top_features, "syn_count", "fin_count") and row.get("flow_duration_s", 999) < 1:
        matches.append({
            "attack": "Very short-lived flow with handshake anomaly",
            "confidence": "medium",
            "reason": "Flow completed its handshake/teardown unusually fast — consistent with scan traffic rather than real sessions."
        })

    if _has_all(top_features,"avg_fwd_pkt_size","fwd_packets_per_s") and row.get("avg_fwd_pkt_size", 0) < 100:
        matches.append({
            "attack": "Small-packet flood (possible scan or DoS probe)",
            "confidence": "low",
            "reason": "Forward packets are anomalously small on average — consistent with scanning or low-payload flood traffic rather than real data transfer."
        })

        

    # ============================================================
    # IP-WINDOW-MODEL SIGNATURES (per-IP, 5-min windows)
    # ============================================================

    if _has_all(top_features, "unique_dst_ports_this_window", "unique_dst_ips_this_window"):
        matches.append({
            "attack": "Broad scan by single IP (ports + hosts)",
            "confidence": "high",
            "reason": "One IP touched anomalously many distinct destination ports AND destination IPs within the window — classic scanning behavior."
        })
    elif "unique_dst_ports_this_window" in top_features and not "port scan" in reasons:
        matches.append({
            "attack": "Port scan by single IP",
            "confidence": "high",
            "reason": "One IP probed an anomalously high number of distinct destination ports."
        })
    elif "unique_dst_ips_this_window" in top_features:
        matches.append({
            "attack": "Host sweep by single IP",
            "confidence": "medium",
            "reason": "One IP contacted an anomalously high number of distinct destination IPs — network sweep pattern."
        })

    if _has_all(top_features, "peak_concurrent_flows", "total_flows"):
        matches.append({
            "attack": "Connection flood from single IP",
            "confidence": "high",
            "reason": "IP opened an anomalous number of concurrent and total flows — consistent with a flood or resource-exhaustion attempt."
        })

    if "peak_concurrent_half_open" in top_features and "syn flood" not in reasons:
        matches.append({
            "attack": "SYN flood from single IP",
            "confidence": "high",
            "reason": "IP has an anomalous number of concurrent half-open (incomplete handshake) connections."
        })

    if _has_all(top_features, "dns_queries_sent_to_this_ip", "dns_responses_unmatched"):
        matches.append({
            "attack": "DNS resolver abuse / possible amplification source",
            "confidence": "medium",
            "reason": "This IP is associated with anomalous DNS query volume and unmatched responses."
        })

    # ============================================================
    # TIME-BUCKET COMBINATION SIGNATURES
    # (any bucket_* feature co-firing with a volume/count feature ->
    #  "not seen at this magnitude during this time window before")
    # ============================================================

    BUCKET_COLS = ['bucket_night', 'bucket_early_morning', 'bucket_morning',
                   'bucket_afternoon', 'bucket_evening', 'bucket_late_night']
    active_bucket = None

    for b in BUCKET_COLS:
        if b in top_features:
            active_bucket=b
            break

    VOLUME_LIKE = [
        'flow_bytes_per_s', 'flow_packets_per_s', 'total_bytes', 'total_flows',
        'dns_bytes_total', 'peak_concurrent_flows', 'unique_dst_ports_this_window',
        'unique_dst_ips_this_window', 'half_open_conns_active',
    ]

    if active_bucket:
        co_firing = [f for f in top_features if f in VOLUME_LIKE]
        if co_firing:
            bucket_label = active_bucket.replace('bucket_', '')
            feature_list = ", ".join(co_firing)
            matches.append({
                "attack": "Time-anomalous activity",
                "confidence": "medium",
                "reason": (
                    f"'{feature_list}' reached a magnitude not seen during "
                    f"the '{bucket_label}' window in training data — activity "
                    f"level is unusual specifically for this time of day."
                )
            })

    # ============================================================
    # FALLBACK — nothing matched a known pattern
    # ============================================================

    if not matches:
        matches.append({
            "attack": "Unclassified anomaly",
            "confidence": "low",
            "reason": f"No known signature matched. Top contributing features: {', '.join(top_features)}."
        })

    return matches