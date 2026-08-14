import os
import json
import platform
import socket
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP
from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------
# Automatically detect the network interface
# ---------------------------------------------------------

def get_default_interface():
    """
    Detect a usable network interface across macOS, Linux,
    and Windows instead of hard-coding something like ens33.
    """

    system = platform.system()

    # User-defined interface takes priority
    configured_interface = os.getenv("MAXGUARD_INTERFACE")

    if configured_interface:
        return configured_interface

    if system == "Darwin":
        # macOS commonly uses en0/en1 for Wi-Fi/Ethernet.
        try:
            import subprocess

            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True,
                text=True,
                check=False,
            )

            for line in result.stdout.splitlines():
                if "interface:" in line:
                    interface = line.split(":", 1)[1].strip()
                    if interface:
                        return interface

        except Exception:
            pass

        return "en0"

    elif system == "Windows":
        # Scapy can generally determine the appropriate interface.
        return None

    else:
        # Linux: determine interface used by default route.
        try:
            import subprocess

            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=False,
            )

            parts = result.stdout.split()

            if "dev" in parts:
                return parts[parts.index("dev") + 1]

        except Exception:
            pass

        return None


INTERFACE = get_default_interface()


# ---------------------------------------------------------
# PCI-related ports
# ---------------------------------------------------------

PCI_PORTS = {
    21: "FTP - Unencrypted file transfer (PCI DSS 4.2.1)",
    23: "Telnet - Unencrypted remote access (PCI DSS 4.2.1)",
    80: "HTTP - Unencrypted web traffic (PCI DSS 4.2.1)",
    110: "POP3 - Unencrypted email (PCI DSS 4.2.1)",
    143: "IMAP - Unencrypted email (PCI DSS 4.2.1)",
    3389: "RDP - Remote desktop exposed (PCI DSS 1.3.2)",
    8080: "HTTP Alt - Unencrypted web traffic (PCI DSS 4.2.1)",
}


# ---------------------------------------------------------
# Packet storage
# ---------------------------------------------------------

captured_packets = []


# ---------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------

def extract_packet_info(packet):
    info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "pci_violation": False,
        "violation_detail": None,
    }

    if IP not in packet:
        return info

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

    ports = [
        info["src_port"],
        info["dst_port"],
    ]

    for port in ports:
        if port in PCI_PORTS:
            info["pci_violation"] = True
            info["violation_detail"] = PCI_PORTS[port]
            break

    return info


# ---------------------------------------------------------
# Packet callback
# ---------------------------------------------------------

def packet_callback(packet):
    info = extract_packet_info(packet)

    if info["src_ip"] is None:
        return

    captured_packets.append(info)

    status = "VIOLATION" if info["pci_violation"] else "OK"

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


# ---------------------------------------------------------
# Save results
# ---------------------------------------------------------

def save_results(filename="scan_results.json"):
    with open(filename, "w") as f:
        json.dump(captured_packets, f, indent=2)

    violations = sum(
        1
        for packet in captured_packets
        if packet["pci_violation"]
    )

    print(f"\nResults saved to {filename}")
    print(f"Total packets captured: {len(captured_packets)}")
    print(f"Total violations found: {violations}")


# ---------------------------------------------------------
# Start packet capture
# ---------------------------------------------------------

def start_sniffing(packet_count=300):
    global captured_packets

    # Clear results from previous scan
    captured_packets.clear()

    system = platform.system()

    if INTERFACE:
        print(
            f"Starting MaxGuard scan on "
            f"{system} interface: {INTERFACE}"
        )
    else:
        print(
            f"Starting MaxGuard scan on {system} "
            f"using Scapy's default interface"
        )

    print(f"Capturing {packet_count} packets...")
    print("Press Ctrl+C to stop early\n")

    try:

        if INTERFACE:
            sniff(
                iface=INTERFACE,
                prn=packet_callback,
                count=packet_count,
                store=False,
            )

        else:
            sniff(
                prn=packet_callback,
                count=packet_count,
                store=False,
            )

    except KeyboardInterrupt:
        print("\nScan stopped by user.")

    except PermissionError:
        print(
            "\nPermission denied while attempting "
            "to capture network traffic."
        )
        print(
            "Packet capture may require administrator/root "
            "permissions on the local machine."
        )

    except Exception as e:
        print(
            f"\nUnable to capture packets: {e}"
        )
        raise


# ---------------------------------------------------------
# Standalone execution
# ---------------------------------------------------------

if __name__ == "__main__":
    start_sniffing(packet_count=300)
