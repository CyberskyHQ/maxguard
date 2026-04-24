import json
import os
import threading
import time
import urllib.request
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, get_if_list
from dotenv import load_dotenv

load_dotenv()

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


def resolve_interface() -> str | None:
    """Pick a usable network interface, with env override support."""
    configured = os.getenv("MAX_GUARD_INTERFACE")
    interfaces = get_if_list()

    if configured:
        if configured in interfaces:
            return configured
        raise ValueError(
            f"Configured interface '{configured}' was not found. "
            f"Available interfaces: {', '.join(interfaces)}"
        )

    preferred_prefixes = ("en0", "en1", "eth0", "wlan0", "Wi-Fi")
    for preferred in preferred_prefixes:
        for iface in interfaces:
            if iface == preferred:
                return iface

    for iface in interfaces:
        if not iface.startswith(("lo", "utun", "gif", "stf", "anpi", "awdl", "llw")):
            return iface

    return interfaces[0] if interfaces else None


def normalize_site_url(site: str) -> str:
    site = site.strip()
    if not site.startswith(("http://", "https://")):
        return f"https://{site}"
    return site


def build_site_requests(sites: list[str]) -> list[str]:
    return [normalize_site_url(site) for site in sites if site.strip()]


def generate_site_traffic(sites: list[str], request_timeout: int = 5) -> None:
    """Generate predictable web traffic for website-targeted scans."""
    if not sites:
        return

    # Give the sniffer a moment to attach before traffic starts.
    time.sleep(1)

    for site in build_site_requests(sites):
        try:
            request = urllib.request.Request(
                site,
                headers={"User-Agent": "Max-Guard Website Scan/1.0"},
            )
            with urllib.request.urlopen(request, timeout=request_timeout):
                print(f"[SITE] Requested {site}")
        except Exception as exc:
            print(f"[SITE] Failed to request {site}: {exc}")

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
        "requested_site": None,
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

def start_sniffing(packet_count=300, interface=None, sites=None, timeout=None):
    selected_interface = interface or resolve_interface()
    if not selected_interface:
        raise RuntimeError("No usable network interface found for packet capture.")

    print(f"Starting Max-Guard scan on interface: {selected_interface}")
    print(f"Capturing {packet_count} packets...")
    print("Press Ctrl+C to stop early\n")

    if sites:
        normalized_sites = build_site_requests(sites)
        site_label = ", ".join(normalized_sites)
        traffic_thread = threading.Thread(
            target=generate_site_traffic,
            args=(normalized_sites,),
            daemon=True,
        )
        traffic_thread.start()
    else:
        site_label = None

    def capture_callback(packet):
        info = extract_packet_info(packet)
        if site_label and info["src_ip"] is not None:
            info["requested_site"] = site_label
            captured_packets.append(info)
            status = "VIOLATION" if info["pci_violation"] else "OK"
            print(
                f"[{status}] {info['timestamp']} | {info['src_ip']}:{info['src_port']} -> "
                f"{info['dst_ip']}:{info['dst_port']} | {info['protocol']} | sites={site_label}"
            )
            if info["pci_violation"]:
                print(f"  PCI DSS VIOLATION: {info['violation_detail']}")
        elif site_label:
            return
        else:
            packet_callback(packet)

    try:
        sniff(
            iface=selected_interface,
            prn=capture_callback,
            count=packet_count,
            store=False,
            timeout=timeout,
        )
    except KeyboardInterrupt:
        print("\nScan stopped by user.")
    finally:
        save_results()

if __name__ == "__main__":
    start_sniffing(packet_count=300)
