import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import os
import sys
import csv
import io
from datetime import datetime
from dotenv import load_dotenv
from voice_engine import listen_for_command, get_voice_response

load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer.threat_engine import get_threat_summary

IS_CLOUD = os.getenv("STREAMLIT_CLOUD", "false").lower() == "true"

st.set_page_config(
    page_title="Max-Guard Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .metric-card {
        background: #1e1e2e;
        border-radius: 10px;
        padding: 20px;
        border: 1px solid #333;
    }
    .violation-critical { color: #ff4444; font-weight: bold; }
    .violation-high { color: #ff8800; font-weight: bold; }
    .violation-medium { color: #ffcc00; font-weight: bold; }
    .violation-low { color: #4499ff; font-weight: bold; }
    .violation-none { color: #44ff88; font-weight: bold; }
    .section-header {
        border-left: 4px solid #3B8BD4;
        padding-left: 12px;
        margin: 20px 0 10px 0;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Max-Guard: PCI-DSS Network Security Scanner")
st.markdown("**AI-driven network security scanner for retail PCI-DSS compliance** | Sprint 2 | CCSU")
st.divider()

st.sidebar.image("https://img.shields.io/badge/Max--Guard-v1.0-blue", width=150)
st.sidebar.title("Scan Controls")
st.divider()
st.sidebar.subheader(" 🔊 Voice Assistance ")
voice_enabled = st.sidebar.toggle("Enable Siri-style Responses", value=True)

if st.sidebar.button("Give Voice Command"):
    with st.spinner("Listening...."):
        cmd = listen_for_commad()
        if cmd and "scan" in cmd:
            st.sidebar.success(f"Command received: {cmd}")
            packets = run_local_scan(packet_count)
            display_results(packets)
st.sidebar.markdown(f"**Mode:** {'☁️ Cloud' if IS_CLOUD else '💻 Local'}")
st.sidebar.divider()

def run_local_scan(packet_count):
    from scanner.sniffer import start_sniffing, captured_packets
    captured_packets.clear()
    with st.spinner(f"Scanning network... capturing {packet_count} packets"):
        start_sniffing(packet_count=packet_count)
    return captured_packets

def load_packets_from_file(uploaded_file):
    content = uploaded_file.read().decode("utf-8")
    return json.loads(content)

def render_threat_badge(level):
    colors = {
        "CRITICAL": "#ff4444",
        "HIGH":     "#ff8800",
        "MEDIUM":   "#ffcc00",
        "LOW":      "#4499ff",
        "NONE":     "#44ff88"
    }
    color = colors.get(level, "#888888")
    st.markdown(f"""
    <div style="display:inline-block; background:{color}22; border:2px solid {color};
    border-radius:8px; padding:8px 24px; margin:10px 0;">
        <span style="color:{color}; font-size:24px; font-weight:bold;">
            {level}
        </span>
    </div>
    """, unsafe_allow_html=True)

def render_severity_gauge(score):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": "Severity Score", "font": {"size": 16}},
        gauge={
            "axis": {"range": [0, 10], "tickwidth": 1},
            "bar": {"color": "#3B8BD4"},
            "steps": [
                {"range": [0, 3],  "color": "#1a4a2e"},
                {"range": [3, 5],  "color": "#1a3a5c"},
                {"range": [5, 7],  "color": "#4a3a00"},
                {"range": [7, 9],  "color": "#4a2000"},
                {"range": [9, 10], "color": "#4a0000"},
            ],
            "threshold": {
                "line": {"color": "white", "width": 3},
                "thickness": 0.8,
                "value": score
            }
        }
    ))
    fig.update_layout(height=250, margin=dict(t=40, b=0, l=20, r=20),
                      paper_bgcolor="rgba(0,0,0,0)", font_color="white")
    st.plotly_chart(fig, use_container_width=True)

def render_overview_metrics(packets, result):
    col1, col2, col3, col4, col5 = st.columns(5)
    total = result["total_packets"]
    violations = result["total_violations"]
    rate = round((violations / total * 100), 1) if total > 0 else 0
    score = result["severity"]["overall_score"]
    devices = len(result["affected_devices"])

    col1.metric("Total Packets", total)
    col2.metric("PCI Violations", violations, delta=f"{rate}% of traffic" if violations > 0 else None, delta_color="inverse")
    col3.metric("Affected Devices", devices)
    col4.metric("Severity Score", f"{score}/10")
    col5.metric("Threat Level", result["threat_level"])

def render_charts(packets, result):
    df = pd.DataFrame(packets)

    st.markdown('<div class="section-header"><h3>Traffic Analysis</h3></div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        if "protocol" in df.columns:
            protocol_counts = df["protocol"].value_counts().reset_index()
            protocol_counts.columns = ["Protocol", "Count"]
            fig = px.pie(
                protocol_counts, values="Count", names="Protocol",
                title="Protocol Distribution",
                color_discrete_sequence=["#3B8BD4", "#1D9E75", "#E8593C", "#9F6BDD"]
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        render_severity_gauge(result["severity"]["overall_score"])

    col3, col4 = st.columns(2)

    with col3:
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            violations_df = df[df["pci_violation"] == True].copy()
            if not violations_df.empty:
                violations_df["minute"] = violations_df["timestamp"].dt.floor("s")
                timeline = violations_df.groupby("minute").size().reset_index(name="count")
                fig = px.line(
                    timeline, x="minute", y="count",
                    title="Violation Timeline",
                    labels={"minute": "Time", "count": "Violations"},
                    color_discrete_sequence=["#ff4444"]
                )
                fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No violations to plot on timeline.")

    with col4:
        patterns = result.get("patterns", {})
        top_talkers = patterns.get("top_talkers", [])
        if top_talkers:
            talkers_df = pd.DataFrame(top_talkers)
            fig = px.bar(
                talkers_df, x="ip", y="count",
                title="Top Talkers (by packet count)",
                labels={"ip": "IP Address", "count": "Packets"},
                color="count",
                color_continuous_scale="Blues"
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)

    top_ports = patterns.get("top_ports", [])
    if top_ports:
        ports_df = pd.DataFrame(top_ports)
        fig = px.bar(
            ports_df, x="port", y="count",
            title="Top Destination Ports",
            labels={"port": "Port", "count": "Packet Count"},
            color="count",
            color_continuous_scale="Reds"
        )
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig, use_container_width=True)

def render_violations_table(packets):
    df = pd.DataFrame(packets)
    violations_df = df[df["pci_violation"] == True]
    if not violations_df.empty:
        st.markdown('<div class="section-header"><h3>PCI-DSS Violations Detected</h3></div>', unsafe_allow_html=True)
        st.dataframe(
            violations_df[["timestamp", "src_ip", "dst_ip", "protocol", "dst_port", "violation_detail"]],
            use_container_width=True
        )
    else:
        st.success("No PCI-DSS violations detected in this scan.")

def render_affected_devices(result):
    devices = result.get("affected_devices", [])
    if not devices:
        return
    st.markdown('<div class="section-header"><h3>Affected Devices</h3></div>', unsafe_allow_html=True)
    for device in devices:
        with st.expander(f"{device['ip']} — {device['device_type']} — {device['violation_count']} violations"):
            st.markdown(f"**IP Address:** `{device['ip']}`")
            st.markdown(f"**Device Type:** {device['device_type']}")
            st.markdown(f"**Total Violations:** {device['violation_count']}")
            st.markdown("**Violations Found:**")
            for v in device["violations"]:
                st.markdown(f"- {v}")

def render_investigation_guides(result):
    guides = result.get("investigation_guides", {})
    if not guides:
        return
    st.markdown('<div class="section-header"><h3>Investigation & Remediation Guides</h3></div>', unsafe_allow_html=True)
    st.markdown("Step-by-step guidance for each violation found in this scan.")
    for protocol, guide in guides.items():
        with st.expander(f"How to investigate and fix: {protocol}"):
            st.markdown(f"**PCI-DSS Requirement:** `{guide['pci_requirement']}`")
            st.divider()
            st.markdown("**What it is:**")
            st.info(guide["what_it_is"])
            st.markdown("**How to investigate:**")
            for step in guide["how_to_investigate"]:
                st.markdown(f"- {step}")
            st.markdown("**How to fix:**")
            for step in guide["how_to_fix"]:
                st.markdown(f"- {step}")

def render_ai_analysis(result):
    st.markdown('<div class="section-header"><h3>AI Threat Analysis (GPT-4o-mini)</h3></div>', unsafe_allow_html=True)
    render_threat_badge(result["threat_level"])
    st.markdown(result["analysis"])

def render_exports(packets, result):
    st.markdown('<div class="section-header"><h3>Export Reports</h3></div>', unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)

    with col1:
        json_str = json.dumps(packets, indent=2)
        st.download_button(
            label="Download scan_results.json",
            data=json_str,
            file_name=f"maxguard_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

    with col2:
        violations = [p for p in packets if p.get("pci_violation")]
        if violations:
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=violations[0].keys())
            writer.writeheader()
            writer.writerows(violations)
            st.download_button(
                label="Download violations.csv",
                data=output.getvalue(),
                file_name=f"maxguard_violations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

    with col3:
        summary = f"""MAX-GUARD EXECUTIVE SUMMARY
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*50}

THREAT LEVEL: {result['threat_level']}
SEVERITY SCORE: {result['severity']['overall_score']}/10
TOTAL PACKETS: {result['total_packets']}
TOTAL VIOLATIONS: {result['total_violations']}

VIOLATIONS FOUND:
{chr(10).join(f'- {v}' for v in result['violation_types'])}

AFFECTED DEVICES:
{chr(10).join(f"- {d['ip']} ({d['device_type']}): {d['violation_count']} violations" for d in result['affected_devices'])}

FULL AI ANALYSIS:
{result['analysis']}
"""
        st.download_button(
            label="Download executive_summary.txt",
            data=summary,
            file_name=f"maxguard_executive_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )

def display_results(packets):
    if not packets:
        st.warning("No packets captured.")
        return

    with st.spinner("Running AI threat analysis..."):
        result = get_threat_summary(packets)

    render_overview_metrics(packets, result)
    st.divider()
    render_charts(packets, result)
    st.divider()

    st.markdown('<div class="section-header"><h3>All Captured Packets</h3></div>', unsafe_allow_html=True)
    st.dataframe(pd.DataFrame(packets), use_container_width=True)
    st.divider()

    render_violations_table(packets)
    st.divider()
    render_affected_devices(result)
    st.divider()
    render_investigation_guides(result)
    st.divider()
    render_ai_analysis(result)
    st.divider()
    render_exports(packets, result)

if voice_enabled:
    with st.spinner("Generating voice briefing..."):
        summary_text = result["analysis"].split('\n\n')[0]
        audio_bytes = get_voice_response(summary_text)
        st.audio(audio_bytes, format="audio/mp3", autoplay=True)

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
    packet_count = st.sidebar.slider("Packets to capture", 10, 500, 100, step=10)
    st.sidebar.divider()
    st.sidebar.markdown("### Load Previous Scan")
    uploaded_file = st.sidebar.file_uploader("Upload scan_results.json", type="json")

    if uploaded_file is not None:
        packets = load_packets_from_file(uploaded_file)
        st.success(f"Loaded {len(packets)} packets from uploaded file.")
        display_results(packets)
    elif st.sidebar.button("Start Live Scan", type="primary"):
        packets = run_local_scan(packet_count)
        display_results(packets)
    else:
        st.markdown("""
        ### Welcome to Max-Guard
        **Two ways to use this dashboard:**
        - **Live Scan:** Click *Start Live Scan* in the sidebar to capture real network traffic
        - **Upload Results:** Upload a previously saved `scan_results.json` file

        This tool scans your network for PCI-DSS v4.0 violations and uses GPT-4o-mini
        to generate a professional compliance analysis report.
        """)
