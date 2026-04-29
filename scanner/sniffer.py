import json
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
from dotenv import load_dotenv

load_dotenv()

INTERFACE = "ens33"

PCI_PORTS = {
    21:  "FTP - Unencrypted file transfer (PCI DSS 4.2.1)",
    23:  "Telnet - Unencrypted remote access (PCI DSS 4.2.1)",
    80:  "HTTP - Unencrypted web traffic (PCI DSS 4.2.1)",
    143: "IMAP - Unencrypted email (PCI DSS 4.2.1)",
    110: "POP3 - Unencrypted email (PCI DSS 4.2.1)",
    3389: "RDP - Remote desktop exposed (PCI DSS 1.3.2)",
    8080: "HTTP Alt - Unencrypted web traffic (PCI DSS 4.2.1)",
}

captured_packets = []

def extract_packet_info(packet):
    info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "pci_violation": None,
        "violation_detail": None,
    }

    if IP in packet:
        info["src_ip"] = packet[IP].src
        info["dst_ip"] = packet[IP].dst

        if TCP in packet:
            info["protocol"] = "TCP"
            info["src_port"] = packet[TCP].sport
            info["dst_port"] = packet[TCP].dport
        elif UDP in packet:
            info["protocol"] = "UDP"
            info["src_port"] = packet[UDP].sport
            info["dst_port"] = packet[UDP].dport

        for port in [info["src_port"], info["dst_port"]]:
            if port in PCI_PORTS:
                info["pci_violation"] = True
                info["violation_detail"] = PCI_PORTS[port]
                break

    return info

def packet_callback(packet):
    info = extract_packet_info(packet)
    if info["src_ip"] is not None:
        captured_packets.append(info)
        status = "VIOLATION" if info["pci_violation"] else "OK"
        print(f"[{status}] {info['timestamp']} | {info['src_ip']}:{info['src_port']} -> {info['dst_ip']}:{info['dst_port']} | {info['protocol']}")
        if info["pci_violation"]:
            print(f"  PCI DSS VIOLATION: {info['violation_detail']}")

def save_results(filename="scan_results.json"):
    with open(filename, "w") as f:
        json.dump(captured_packets, f, indent=2)
    print(f"\nResults saved to {filename}")
    print(f"Total packets captured: {len(captured_packets)}")
    print(f"Total violations found: {sum(1 for p in captured_packets if p['pci_violation'])}")

def start_sniffing(packet_count=300):
    print(f"Starting Max-Guard scan on interface: {INTERFACE}")
    print(f"Capturing {packet_count} packets...")
    print("Press Ctrl+C to stop early\n")
    try:
        sniff(iface=INTERFACE, prn=packet_callback, count=packet_count, store=False)
    except KeyboardInterrupt:
        print("\nScan stopped by user.")
    finally:
        save_results()

if __name__ == "__main__":
    start_sniffing(packet_count=300)