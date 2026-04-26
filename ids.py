from scapy.all import *
from collections import defaultdict
import socket
import datetime
import time


port_set_tcp = defaultdict(lambda: defaultdict(int))
port_set_udp = defaultdict(set)

packet_count_tcp = defaultdict(int)
packet_count_udp = defaultdict(int)
packet_count_icmp = defaultdict(int)

syn_count = defaultdict(int)
ack_count = defaultdict(int)
fin_count = defaultdict(int)
xmas_count = defaultdict(int)
null_flags_exist = defaultdict(int)

cumulative_port_tcp = defaultdict(set)
cumulative_port_udp = defaultdict(set)

score = defaultdict(int)
cumulative_score = defaultdict(int)
inactive_windows = defaultdict(int)

blocklist = set()
blocklist_reasons = {}


SMALL_ALERT_THRESHOLD = 20
CUMULATIVE_ALERT_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 15
SLOW_SCAN_THRESHOLD = 25

SYN_COUNT_THRESHOLD = 100
SYN_FLOOD_THRESHOLD = 2000
FIN_COUNT_THRESHOLD = 200
XMAS_COUNT_THRESHOLD = 200
ACK_COUNT_THRESHOLD = 300
NULL_SCAN_RATIO = 0.6

UDP_FLOOD_THRESHOLD = 50
ICMP_FLOOD_THRESHOLD = 50


small_window = 5
slow_window = 60

small_time = time.time()
slow_time = time.time()


SUSPICIOUS_LOG = "suspicious.log"
CONFIRMED_LOG = "confirmed.log"


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()

my_host = get_local_ip()

def get_severity(val):
    if val >= 80:
        return "HIGH"
    elif val >= 40:
        return "MEDIUM"
    return "LOW"

def log_suspicious(ip, labels, ip_score):
    severity = get_severity(ip_score)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] SUSPICIOUS | {severity} | IP: {ip} | Type: {labels} | Score: {ip_score}\n"
    print(line, end="")
    with open(SUSPICIOUS_LOG, "a") as f:
        f.write(line)

def log_confirmed(ip, labels, ip_score):
    severity = get_severity(ip_score)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] CONFIRMED | {severity} | IP: {ip} | Type: {labels} | Score: {ip_score}\n"
    print(line, end="")
    with open(CONFIRMED_LOG, "a") as f:
        f.write(line)


def find_max_port(ip):
    if not port_set_tcp[ip]:
        return None
    return max(port_set_tcp[ip], key=port_set_tcp[ip].get)

def detect_syn(ip):
    syn = syn_count[ip]
    ack = ack_count[ip]
    ratio = syn / (syn + ack + 0.001)
    unique_ports = len(port_set_tcp[ip])

    if syn > SYN_FLOOD_THRESHOLD and ratio > 0.9:
        if unique_ports <= 3:
            port = find_max_port(ip)
            return f"SYN flood (port {port})"
        return "SYN flood"


    if syn > SYN_COUNT_THRESHOLD and ratio > 0.7:
        if unique_ports <= 3:
            port = find_max_port(ip)
            return f"SYN probing (port {port})"
        return "SYN scan"

    return None

def detect_tcp_scan(ip):
    if len(port_set_tcp[ip]) > PORT_SCAN_THRESHOLD:
        return "TCP port scan"
    return None

def detect_flag_scan(ip):
    if xmas_count[ip] > XMAS_COUNT_THRESHOLD:
        return "XMAS scan"
    if fin_count[ip] > FIN_COUNT_THRESHOLD:
        return "FIN scan"
    if ack_count[ip] > ACK_COUNT_THRESHOLD:
        return "ACK scan"
    if packet_count_tcp[ip] > 0 and (null_flags_exist[ip] / (packet_count_tcp[ip] + 0.01)) > NULL_SCAN_RATIO:
        return "NULL scan"
    return None

def detect_udp(ip):
    ports = len(port_set_udp[ip])
    total = packet_count_udp[ip]

    if ports > PORT_SCAN_THRESHOLD:
        return "UDP scan"
    if total > UDP_FLOOD_THRESHOLD and ports <= 3:
        return "UDP flood"
    return None

def detect_icmp(ip):
    if packet_count_icmp[ip] > ICMP_FLOOD_THRESHOLD:
        return "ICMP flood"
    return None


def evaluate_ip(ip):
    labels = []
    ip_score = 0

    for fn, weight in [
        (detect_syn, 30),
        (detect_tcp_scan, 20),
        (detect_flag_scan, 20),
        (detect_udp, 20),
        (detect_icmp, 20),
    ]:
        res = fn(ip)
        if res:
            labels.append(res)
            ip_score += weight

    return ip_score, labels


def check_small_window():
    all_ips = set(
        list(packet_count_tcp.keys()) +
        list(packet_count_udp.keys()) +
        list(packet_count_icmp.keys())
    )

    for ip in all_ips:

        if ip in blocklist:
            continue

        ip_score, labels = evaluate_ip(ip)

        if ip_score > 0:
            score[ip] = ip_score
            cumulative_score[ip] += ip_score
            inactive_windows[ip] = 0
        else:
            inactive_windows[ip] += 1

        if score[ip] >= SMALL_ALERT_THRESHOLD:
            log_suspicious(ip, labels, score[ip])

def check_slow_window():
    for ip in list(cumulative_score.keys()):
        
        if ip in blocklist:
            continue

        if len(cumulative_port_tcp[ip]) > SLOW_SCAN_THRESHOLD:
            cumulative_score[ip] += 20
            log_suspicious(ip, "Slow TCP scan", cumulative_score[ip])

        if len(cumulative_port_udp[ip]) > SLOW_SCAN_THRESHOLD:
            cumulative_score[ip] += 20
            log_suspicious(ip, "Slow UDP scan", cumulative_score[ip])

        if cumulative_score[ip] >= CUMULATIVE_ALERT_THRESHOLD and ip not in blocklist:
            blocklist.add(ip)
            blocklist_reasons[ip] = "Long-term suspicious behavior"
            log_confirmed(ip, "Long-term suspicious behavior", cumulative_score[ip])


        inactive_windows[ip] = min(inactive_windows[ip], 5)

        if inactive_windows[ip] < 3:
            cumulative_score[ip] = int(cumulative_score[ip] * 0.98)
        elif inactive_windows[ip] < 5:
            cumulative_score[ip] = int(cumulative_score[ip] * 0.92)
        else:
            cumulative_score[ip] = int(cumulative_score[ip] * 0.85)

        if cumulative_score[ip] <= 0 and ip not in blocklist:
            del cumulative_score[ip]
            inactive_windows.pop(ip, None)


def catchpacket(packet):
    global small_time, slow_time, my_host

    if my_host is None:
        my_host = get_local_ip()
        if my_host is None:
            return

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip in blocklist:
             return

        if packet.haslayer(TCP) and dst_ip == my_host:
            packet_count_tcp[src_ip] += 1
            port = packet[TCP].dport

            port_set_tcp[src_ip][port] += 1
            cumulative_port_tcp[src_ip].add(port)

            flags = packet[TCP].flags

            if flags & 0x02 and not flags & 0x10:
                syn_count[src_ip] += 1
            elif flags & 0x10 and not flags & 0x02:
                ack_count[src_ip] += 1
            elif 'F' in str(flags) and 'P' in str(flags) and 'U' in str(flags):
                xmas_count[src_ip] += 1
            elif flags & 0x01 and not flags & 0x10:
                fin_count[src_ip] += 1
            elif not flags:
                null_flags_exist[src_ip] += 1

        if packet.haslayer(UDP) and dst_ip == my_host:
            packet_count_udp[src_ip] += 1
            port = packet[UDP].dport
            port_set_udp[src_ip].add(port)
            cumulative_port_udp[src_ip].add(port)

        if packet.haslayer(ICMP) and dst_ip == my_host and packet[ICMP].type == 8:
            packet_count_icmp[src_ip] += 1


    if time.time() - small_time > small_window:
        check_small_window()

        packet_count_tcp.clear()
        packet_count_udp.clear()
        packet_count_icmp.clear()
        port_set_tcp.clear()
        port_set_udp.clear()
        syn_count.clear()
        ack_count.clear()
        fin_count.clear()
        xmas_count.clear()
        null_flags_exist.clear()
        score.clear()

        small_time = time.time()

    if time.time() - slow_time > slow_window:
        check_slow_window()

        cumulative_port_tcp.clear()
        cumulative_port_udp.clear()

        slow_time = time.time()


print("📡 IDS Running...")
print(f"   Monitoring host: {my_host}")
print(f"   Suspicious log : {SUSPICIOUS_LOG}")
print(f"   Confirmed log  : {CONFIRMED_LOG}\n")

sniff(
    iface=["eth0", "lo"],
    prn=catchpacket,
    store=False
)
