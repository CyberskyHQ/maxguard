import os
import json
import platform
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, get_if_list
from dotenv import load_dotenv

load_dotenv()


# ============================================================
# MAXGUARD NETWORK INTERFACE DETECTION
# ============================================================

def get_scan_interface():
    """
    Automatically determine the best network interface.

    Supports common interface names across:
    - macOS
    - Windows
    - Linux
    - Virtual machines
    - Cloud/container environments

    You can override automatic detection with:

        MAXGUARD_INTERFACE=en0

    or:

        MAXGUARD_INTERFACE=Ethernet
    """

    # Allow manual override through environment variable
    configured_interface = os.getenv("MAXGUARD_INTERFACE")

    available_interfaces = get_if_list()

    if configured_interface:
        if configured_interface in available_interfaces:
            return configured_interface

        print(
            f"WARNING: MAXGUARD_INTERFACE='{configured_interface}' "
            f"was not found."
        )

    system = platform.system()

    # Common interface names by operating system
    if system == "Darwin":
        preferred_interfaces = [
            "en0",
            "en1",
            "en2",
            "en3",
        ]

    elif system == "Windows":
        preferred_interfaces = [
            "Ethernet",
            "Wi-Fi",
            "WiFi",
        ]

    elif system == "Linux":
        preferred_interfaces = [
            "eth0",
            "ens33",
            "ens160",
            "enp0s3",
            "enp0s8",
            "wlan0",
            "wlp2s0",
        ]

    else:
        preferred_interfaces = []

    # First try OS-specific interfaces
    for interface in preferred_interfaces:
        if interface in available_interfaces:
            return interface

    # Fall back to the first interface Scapy can see
    if available_interfaces:
        return available_interfaces[0]

    return None


INTERFACE = get_scan_interface()


# ============================================================
# PCI DSS PORT DEFINITIONS
# ============================================================

PCI_PORTS = {
    21: "FTP - Unencrypted file transfer (PCI DSS 4.2.1)",
    23: "Telnet - Unencrypted remote access (PCI DSS 4.2.1)",
    80: "HTTP - Unencrypted web traffic (PCI DSS 4.2.1)",
    143: "IMAP - Unencrypted email (PCI DSS 4.2.1)",
    110: "POP3 - Unencrypted email (PCI DSS 4.2.1)",
    3389: "RDP - Remote desktop exposed (PCI DSS 1.3.2)",
    8080: "HTTP Alt - Unencrypted web traffic (PCI DSS 4.2.1)",
}


# ============================================================
# PACKET STORAGE
# ============================================================

captured_packets = []


# ============================================================
# PACKET ANALYSIS
# ============================================================

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

        # Check both source and destination ports
        for port in [info["src_port"], info["dst_port"]]:

            if port in PCI_PORTS:

                info["pci_violation"] = True
                info["violation_detail"] = PCI_PORTS[port]

                break

    return info


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    info = extract_packet_info(packet)

    if info["src_ip"] is not None:

        captured_packets.append(info)

        status = (
            "VIOLATION"
            if info["pci_violation"]
            else "OK"
        )

        print(
            f"[{status}] "
            f"{info['timestamp']} | "
            f"{info['src_ip']}:{info['src_port']} -> "
            f"{info['dst_ip']}:{info['dst_port']} | "
            f"{info['protocol']}"
        )

        if info["pci_violation"]:

            print(
                f"  PCI DSS VIOLATION: "
                f"{info['violation_detail']}"
            )


# ============================================================
# SAVE SCAN RESULTS
# ============================================================

def save_results(filename="scan_results.json"):

    with open(filename, "w") as f:

        json.dump(
            captured_packets,
            f,
            indent=2
        )

    print(
        f"\nResults saved to {filename}"
    )

    print(
        f"Total packets captured: "
        f"{len(captured_packets)}"
    )

    print(
        f"Total violations found: "
        f"{sum(1 for p in captured_packets if p['pci_violation'])}"
    )


# ============================================================
# START NETWORK SCAN
# ============================================================

def start_sniffing(packet_count=300):

    if not INTERFACE:

        raise RuntimeError(
            "MaxGuard could not find a usable "
            "network interface."
        )

    print(
        f"Starting MaxGuard scan on interface: "
        f"{INTERFACE}"
    )

    print(
        f"Operating system: "
        f"{platform.system()}"
    )

    print(
        f"Capturing {packet_count} packets..."
    )

    print(
        "Press Ctrl+C to stop early\n"
    )

    try:

        sniff(
            iface=INTERFACE,
            prn=packet_callback,
            count=packet_count,
            store=False
        )

    except KeyboardInterrupt:

        print(
            "\nScan stopped by user."
        )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    start_sniffing(
        packet_count=300
    )import os
import json
import platform
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, get_if_list
from dotenv import load_dotenv

load_dotenv()


# ============================================================
# MAXGUARD NETWORK INTERFACE DETECTION
# ============================================================

def get_scan_interface():
    """
    Automatically determine the best network interface.

    Supports common interface names across:
    - macOS
    - Windows
    - Linux
    - Virtual machines
    - Cloud/container environments

    You can override automatic detection with:

        MAXGUARD_INTERFACE=en0

    or:

        MAXGUARD_INTERFACE=Ethernet
    """

    # Allow manual override through environment variable
    configured_interface = os.getenv("MAXGUARD_INTERFACE")

    available_interfaces = get_if_list()

    if configured_interface:
        if configured_interface in available_interfaces:
            return configured_interface

        print(
            f"WARNING: MAXGUARD_INTERFACE='{configured_interface}' "
            f"was not found."
        )

    system = platform.system()

    # Common interface names by operating system
    if system == "Darwin":
        preferred_interfaces = [
            "en0",
            "en1",
            "en2",
            "en3",
        ]

    elif system == "Windows":
        preferred_interfaces = [
            "Ethernet",
            "Wi-Fi",
            "WiFi",
        ]

    elif system == "Linux":
        preferred_interfaces = [
            "eth0",
            "ens33",
            "ens160",
            "enp0s3",
            "enp0s8",
            "wlan0",
            "wlp2s0",
        ]

    else:
        preferred_interfaces = []

    # First try OS-specific interfaces
    for interface in preferred_interfaces:
        if interface in available_interfaces:
            return interface

    # Fall back to the first interface Scapy can see
    if available_interfaces:
        return available_interfaces[0]

    return None


INTERFACE = get_scan_interface()


# ============================================================
# PCI DSS PORT DEFINITIONS
# ============================================================

PCI_PORTS = {
    21: "FTP - Unencrypted file transfer (PCI DSS 4.2.1)",
    23: "Telnet - Unencrypted remote access (PCI DSS 4.2.1)",
    80: "HTTP - Unencrypted web traffic (PCI DSS 4.2.1)",
    143: "IMAP - Unencrypted email (PCI DSS 4.2.1)",
    110: "POP3 - Unencrypted email (PCI DSS 4.2.1)",
    3389: "RDP - Remote desktop exposed (PCI DSS 1.3.2)",
    8080: "HTTP Alt - Unencrypted web traffic (PCI DSS 4.2.1)",
}


# ============================================================
# PACKET STORAGE
# ============================================================

captured_packets = []


# ============================================================
# PACKET ANALYSIS
# ============================================================

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

        # Check both source and destination ports
        for port in [info["src_port"], info["dst_port"]]:

            if port in PCI_PORTS:

                info["pci_violation"] = True
                info["violation_detail"] = PCI_PORTS[port]

                break

    return info


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    info = extract_packet_info(packet)

    if info["src_ip"] is not None:

        captured_packets.append(info)

        status = (
            "VIOLATION"
            if info["pci_violation"]
            else "OK"
        )

        print(
            f"[{status}] "
            f"{info['timestamp']} | "
            f"{info['src_ip']}:{info['src_port']} -> "
            f"{info['dst_ip']}:{info['dst_port']} | "
            f"{info['protocol']}"
        )

        if info["pci_violation"]:

            print(
                f"  PCI DSS VIOLATION: "
                f"{info['violation_detail']}"
            )


# ============================================================
# SAVE SCAN RESULTS
# ============================================================

def save_results(filename="scan_results.json"):

    with open(filename, "w") as f:

        json.dump(
            captured_packets,
            f,
            indent=2
        )

    print(
        f"\nResults saved to {filename}"
    )

    print(
        f"Total packets captured: "
        f"{len(captured_packets)}"
    )

    print(
        f"Total violations found: "
        f"{sum(1 for p in captured_packets if p['pci_violation'])}"
    )


# ============================================================
# START NETWORK SCAN
# ============================================================

def start_sniffing(packet_count=300):

    if not INTERFACE:

        raise RuntimeError(
            "MaxGuard could not find a usable "
            "network interface."
        )

    print(
        f"Starting MaxGuard scan on interface: "
        f"{INTERFACE}"
    )

    print(
        f"Operating system: "
        f"{platform.system()}"
    )

    print(
        f"Capturing {packet_count} packets..."
    )

    print(
        "Press Ctrl+C to stop early\n"
    )

    try:

        sniff(
            iface=INTERFACE,
            prn=packet_callback,
            count=packet_count,
            store=False
        )

    except KeyboardInterrupt:

        print(
            "\nScan stopped by user."
        )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    start_sniffing(
        packet_count=300
    )
