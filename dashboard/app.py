import streamlit as st
import pandas as pd
import plotly.express as px
import json
import os
import sys
from dotenv import load_dotenv

load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer.threat_engine import get_threat_summary

IS_CLOUD = os.getenv("STREAMLIT_CLOUD", "false").lower() == "true"

st.set_page_config(
    page_title="Max-Guard Security Scanner",
    page_icon="shield",
    layout="wide"
)

st.title("Max-Guard: PCI-DSS Network Security Scanner")
st.markdown("AI-driven network security scanner for retail PCI-DSS compliance")

st.sidebar.title("Scan Controls")
st.sidebar.markdown(f"**Mode:** {'Cloud' if IS_CLOUD else 'Local'}")

def run_local_scan(packet_count):
    from scanner.sniffer import start_sniffing, captured_packets
    with st.spinner(f"Scanning network... capturing {packet_count} packets"):
        start_sniffing(packet_count=packet_count)
    return captured_packets

def load_packets_from_file(uploaded_file):
    content = uploaded_file.read().decode("utf-8")
    return json.loads(content)

def display_results(packets):
    if not packets:
        st.warning("No packets captured.")
        return

    df = pd.DataFrame(packets)

    total_packets = len(packets)
    violations = [p for p in packets if p.get("pci_violation")]
    total_violations = len(violations)
    violation_rate = round((total_violations / total_packets) * 100, 1) if total_packets > 0 else 0

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Packets", total_packets)
    col2.metric("PCI Violations", total_violations)
    col3.metric("Violation Rate", f"{violation_rate}%")

    st.subheader("Captured Packets")
    st.dataframe(df, use_container_width=True)

    st.subheader("Protocol Distribution")
    if "protocol" in df.columns:
        protocol_counts = df["protocol"].value_counts().reset_index()
        protocol_counts.columns = ["Protocol", "Count"]
        fig = px.pie(protocol_counts, values="Count", names="Protocol", title="Traffic by Protocol")
        st.plotly_chart(fig, use_container_width=True)

    if total_violations > 0:
        st.subheader("PCI-DSS Violations Detected")
        violations_df = df[df["pci_violation"] == True]
        st.dataframe(violations_df[["timestamp", "src_ip", "dst_ip", "protocol", "dst_port", "violation_detail"]], use_container_width=True)

    st.subheader("AI Threat Analysis")
    with st.spinner("Analyzing threats with GPT-4o-mini..."):
        result = get_threat_summary(packets)

    threat_color = {
        "CRITICAL": "red",
        "HIGH": "orange",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "NONE": "green"
    }

    level = result["threat_level"]
    color = threat_color.get(level, "gray")
    st.markdown(f"### Threat Level: :{color}[{level}]")
    st.markdown(result["analysis"])

    st.subheader("Export Results")
    json_str = json.dumps(packets, indent=2)
    st.download_button(
        label="Download scan_results.json",
        data=json_str,
        file_name="scan_results.json",
        mime="application/json"
    )

if IS_CLOUD:
    st.sidebar.markdown("### Upload Scan Results")
    uploaded_file = st.sidebar.file_uploader("Upload scan_results.json", type="json")
    if uploaded_file is not None:
        packets = load_packets_from_file(uploaded_file)
        st.success(f"Loaded {len(packets)} packets from file.")
        display_results(packets)
    else:
        st.info("Upload a scan_results.json file from the sidebar to begin analysis.")
else:
    st.sidebar.markdown("### Scan Settings")
    packet_count = st.sidebar.slider("Packets to capture", 10, 500, 100)
    if st.sidebar.button("Start Live Scan"):
        packets = run_local_scan(packet_count)
        display_results(packets)
    else:
        st.info("Click 'Start Live Scan' in the sidebar to begin scanning your network.")