import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def analyze_packets_for_threats(packets: list) -> str:
    if not packets:
        return "No packets to analyze."

    violations = [p for p in packets if p.get("pci_violation")]
    total = len(packets)
    total_violations = len(violations)

    packet_summary = json.dumps(violations[:20], indent=2)

    prompt = f"""You are a PCI-DSS v4.0 security analyst reviewing network scan results from a retail environment.

SCAN SUMMARY:
- Total packets captured: {total}
- Total PCI-DSS violations detected: {total_violations}

VIOLATION DETAILS (up to 20 shown):
{packet_summary}

Provide a structured security analysis with the following sections:

1. THREAT LEVEL: (CRITICAL / HIGH / MEDIUM / LOW / NONE)
2. EXECUTIVE SUMMARY: 2-3 sentences summarizing the security posture.
3. VIOLATIONS FOUND: List each unique violation with the PCI-DSS requirement number it violates.
4. RISK EXPLANATION: Explain why each violation is dangerous in a retail/cardholder data environment.
5. REMEDIATION STEPS: Specific actionable steps to fix each violation.
6. COMPLIANCE STATUS: Overall PCI-DSS v4.0 compliance assessment.

Be specific, technical, and professional. Reference exact PCI-DSS v4.0 requirement numbers."""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": "You are a certified PCI-DSS security analyst specializing in retail network security. Provide precise, actionable analysis."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.2,
        max_tokens=1500
    )

    return response.choices[0].message.content

def get_threat_summary(packets: list) -> dict:
    if not packets:
        return {
            "threat_level": "NONE",
            "total_packets": 0,
            "total_violations": 0,
            "violation_types": [],
            "analysis": "No packets to analyze."
        }

    violations = [p for p in packets if p.get("pci_violation")]
    violation_types = list(set([
        p["violation_detail"] for p in violations
        if p.get("violation_detail")
    ]))

    analysis = analyze_packets_for_threats(packets)

    threat_level = "NONE"
    if "CRITICAL" in analysis:
        threat_level = "CRITICAL"
    elif "HIGH" in analysis:
        threat_level = "HIGH"
    elif "MEDIUM" in analysis:
        threat_level = "MEDIUM"
    elif "LOW" in analysis:
        threat_level = "LOW"

    return {
        "threat_level": threat_level,
        "total_packets": len(packets),
        "total_violations": len(violations),
        "violation_types": violation_types,
        "analysis": analysis
    }

if __name__ == "__main__":
    test_packets = [
        {
            "timestamp": "2025-04-20 10:00:01",
            "src_ip": "192.168.1.105",
            "dst_ip": "192.168.1.1",
            "protocol": "TCP",
            "src_port": 52341,
            "dst_port": 23,
            "pci_violation": True,
            "violation_detail": "Telnet - Unencrypted remote access (PCI DSS 4.2.1)"
        },
        {
            "timestamp": "2025-04-20 10:00:02",
            "src_ip": "192.168.1.105",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "src_port": 54231,
            "dst_port": 80,
            "pci_violation": True,
            "violation_detail": "HTTP - Unencrypted web traffic (PCI DSS 4.2.1)"
        },
        {
            "timestamp": "2025-04-20 10:00:03",
            "src_ip": "192.168.1.105",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "src_port": 54232,
            "dst_port": 443,
            "pci_violation": False,
            "violation_detail": None
        }
    ]

    print("Testing Max-Guard Threat Engine...")
    print("Sending packets to GPT-4o-mini for analysis...\n")
    result = get_threat_summary(test_packets)
    print(f"THREAT LEVEL: {result['threat_level']}")
    print(f"Total Packets: {result['total_packets']}")
    print(f"Total Violations: {result['total_violations']}")
    print(f"Violation Types: {result['violation_types']}")
    print(f"\nFULL ANALYSIS:\n{result['analysis']}")