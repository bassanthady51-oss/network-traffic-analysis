#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time
import threading
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

THRESHOLDS = {
    'connections_per_ip': 50,
    'syn_flood_ratio': 10,
    'icmp_flood': 50,
    'udp_flood': 200,
}

traffic_data = {
    'total_packets': 0,
    'ip_connections': defaultdict(int),
    'syn_count': defaultdict(int),
    'ack_count': defaultdict(int),
    'icmp_count': defaultdict(int),
    'udp_count': defaultdict(int),
    'alerts': [],
    'blocked_ips': set(),
    'start_time': time.time(),
}

lock = threading.Lock()

def print_banner():
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════╗
║     🛡️  DOS ATTACK DETECTION SYSTEM      ║
║        Real-time Network Monitor          ║
╚══════════════════════════════════════════╝""")

def trigger_alert(attack_type, source_ip, details):
    timestamp = datetime.now().strftime("%H:%M:%S")
    alert_msg = f"[{timestamp}] {attack_type} from {source_ip} | {details}"
    with lock:
        traffic_data['alerts'].append(alert_msg)
        traffic_data['blocked_ips'].add(source_ip)
    print(f"{Fore.RED}{'='*60}")
    print(f"  ALERT: {attack_type}")
    print(f"  Source IP: {source_ip}")
    print(f"  Details: {details}")
    print(f"  Time: {timestamp}")
    print(f"{'='*60}")

def analyze_packet(packet):
    with lock:
        traffic_data['total_packets'] += 1
    if not packet.haslayer(IP):
        return
    src_ip = packet[IP].src
    if src_ip in traffic_data['blocked_ips']:
        return
    with lock:
        traffic_data['ip_connections'][src_ip] += 1

    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        with lock:
            if flags == 'S':
                traffic_data['syn_count'][src_ip] += 1
            elif flags == 'SA':
                traffic_data['ack_count'][src_ip] += 1
        syn = traffic_data['syn_count'].get(src_ip, 0)
        ack = traffic_data['ack_count'].get(src_ip, 0)
        if syn > 30:
            ratio = syn / (ack + 1)
            if ratio > THRESHOLDS['syn_flood_ratio']:
                trigger_alert("SYN FLOOD ATTACK", src_ip, f"SYN={syn}, ACK={ack}, Ratio={ratio:.2f}")

    if packet.haslayer(ICMP):
        with lock:
            traffic_data['icmp_count'][src_ip] += 1
        if traffic_data['icmp_count'].get(src_ip, 0) > THRESHOLDS['icmp_flood']:
            trigger_alert("ICMP FLOOD ATTACK", src_ip, f"ICMP={traffic_data['icmp_count'][src_ip]}")

    if packet.haslayer(UDP):
        with lock:
            traffic_data['udp_count'][src_ip] += 1
        if traffic_data['udp_count'].get(src_ip, 0) > THRESHOLDS['udp_flood']:
            trigger_alert("UDP FLOOD ATTACK", src_ip, f"UDP={traffic_data['udp_count'][src_ip]}")

    if traffic_data['ip_connections'].get(src_ip, 0) > THRESHOLDS['connections_per_ip']:
        trigger_alert("HIGH CONNECTION RATE", src_ip, f"Connections={traffic_data['ip_connections'][src_ip]}")

def display_stats():
    while True:
        time.sleep(5)
        with lock:
            total = traffic_data['total_packets']
            elapsed = time.time() - traffic_data['start_time']
            pps = total / elapsed if elapsed > 0 else 0
            blocked = len(traffic_data['blocked_ips'])
            alerts = len(traffic_data['alerts'])
        print(f"{Fore.YELLOW}📊 Packets: {total} | Rate: {pps:.1f}/s | Blocked IPs: {blocked} | Alerts: {alerts}")

def generate_report():
    print(f"\n{Fore.CYAN}{'='*50}")
    print("           FINAL REPORT")
    print(f"{'='*50}")
    elapsed = time.time() - traffic_data['start_time']
    print(f"Duration     : {elapsed:.1f} seconds")
    print(f"Total Packets: {traffic_data['total_packets']}")
    print(f"Blocked IPs  : {len(traffic_data['blocked_ips'])}")
    print(f"Total Alerts : {len(traffic_data['alerts'])}")
    if traffic_data['blocked_ips']:
        print(f"\n{Fore.RED}Blocked IP List:")
        for ip in traffic_data['blocked_ips']:
            print(f"   - {ip}")
    if traffic_data['alerts']:
        print(f"\n{Fore.YELLOW}Alert Log:")
        for alert in traffic_data['alerts']:
            print(f"   {alert}")

def main():
    print_banner()
    print(f"{Fore.GREEN}Starting DOS Detection System...")
    print(f"{Fore.GREEN}Listening on network...\n")
    stats_thread = threading.Thread(target=display_stats, daemon=True)
    stats_thread.start()
    try:
        print(f"{Fore.CYAN}Sniffing packets... (Press Ctrl+C to stop)\n")
        sniff(prn=analyze_packet, store=False, filter="ip")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Stopping...")
        generate_report()

if __name__ == "__main__":
    main()