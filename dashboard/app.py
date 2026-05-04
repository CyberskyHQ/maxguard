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
    .ir-step-box {
        border-radius: 8px;
        padding: 14px 16px;
        margin-bottom: 10px;
        border: 1px solid;
    }
    .ir-step-title {
        font-weight: 700;
        font-size: 13px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 6px;
    }
    .ir-step-desc {
        font-size: 12px;
        margin-bottom: 8px;
        opacity: 0.75;
    }
    .ir-step-body {
        font-size: 13px;
        color: #c0c0c0;
        line-height: 1.65;
    }
    .ir-step-body ul { margin: 4px 0 0 18px; padding: 0; }
    .ir-step-body li { margin-bottom: 4px; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Max-Guard: PCI-DSS Network Security Scanner")
st.markdown("**AI-driven network security scanner for retail PCI-DSS compliance** | Sprint 2 | CCSU")
st.divider()

st.sidebar.title("Scan Controls")
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
            "axis": {"range": [0, 10], "tickwidth": 1, "tickcolor": "white", "nticks": 11},
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
    fig.update_layout(
        height=280,
        margin=dict(t=60, b=20, l=40, r=40),
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="white",
        font=dict(size=12)
    )
    st.plotly_chart(fig, use_container_width=True)


def render_overview_metrics(packets, result):
    col1, col2, col3, col4, col5 = st.columns(5)
    total      = result["total_packets"]
    violations = result["total_violations"]
    rate       = round((violations / total * 100), 1) if total > 0 else 0
    score      = result["severity"]["overall_score"]
    devices    = len(result["affected_devices"])

    col1.metric("Total Packets",    total)
    col2.metric("PCI Violations",   violations,
                delta=f"{rate}% of traffic" if violations > 0 else None,
                delta_color="inverse")
    col3.metric("Affected Devices", devices)
    col4.metric("Severity Score",   f"{score}/10")
    col5.metric("Threat Level",     result["threat_level"])


def render_charts(packets, result):
    df = pd.DataFrame(packets)

    st.markdown('<div class="section-header"><h3>Traffic Analysis</h3></div>',
                unsafe_allow_html=True)

    # ── Row 1: Protocol pie  |  Severity gauge ────────────────────────────────
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

    # ── Row 2: Violation timeline  |  Top Talkers ─────────────────────────────
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
        patterns    = result.get("patterns", {})
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

    # ── Row 3: Violations by Protocol ─────────────────────────────────────────
    # Replaces the old "Top Destination Ports" full-width bar chart.
    # Raw port numbers (21, 23, 80) carry no meaning to a stakeholder or professor.
    # Protocol names (FTP, Telnet, HTTP) map directly to PCI-DSS requirements and
    # communicate risk at a glance. Color-coded by severity level.
    violations_df = df[df["pci_violation"] == True].copy() if "pci_violation" in df.columns else pd.DataFrame()

    if not violations_df.empty and "protocol" in violations_df.columns:
        viol_proto = violations_df["protocol"].value_counts().reset_index()
        viol_proto.columns = ["Protocol", "Violations"]

        PROTO_COLORS = {
            "FTP":    "#E53E3E",
            "TELNET": "#C53030",
            "HTTP":   "#DD6B20",
            "RDP":    "#D69E2E",
            "IMAP":   "#B7791F",
            "POP3":   "#B7791F",
            "TCP":    "#E53E3E",
            "UDP":    "#DD6B20",
        }
        color_map = {
            row["Protocol"]: PROTO_COLORS.get(row["Protocol"].upper(), "#718096")
            for _, row in viol_proto.iterrows()
        }

        fig = px.bar(
            viol_proto, x="Protocol", y="Violations",
            title="PCI-DSS Violations by Protocol",
            labels={"Protocol": "Protocol / Service", "Violations": "Violation Count"},
            color="Protocol",
            color_discrete_map=color_map,
            text="Violations"
        )
        fig.update_traces(textposition="outside")
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="white",
            title_font_color="white",
            showlegend=False
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("✅ No PCI-DSS violations detected — violations by protocol chart not applicable.")


def render_violations_table(packets):
    df = pd.DataFrame(packets)
    violations_df = df[df["pci_violation"] == True]
    if not violations_df.empty:
        st.markdown('<div class="section-header"><h3>PCI-DSS Violations Detected</h3></div>',
                    unsafe_allow_html=True)
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
    st.markdown('<div class="section-header"><h3>Affected Devices</h3></div>',
                unsafe_allow_html=True)
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
    st.markdown('<div class="section-header"><h3>Investigation & Remediation Guides</h3></div>',
                unsafe_allow_html=True)
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


def render_ir_section(result):
    """
    5-step AI Incident Response Advisor.
    Sits directly below the AI analysis output inside render_ai_analysis().
    Sends actual detected threat data to GPT-4o-mini and returns a plan
    structured around: Identify, Assess Risk, Contain, Eradicate, Recover.
    """
    st.markdown('<div class="section-header"><h3>🚨 AI Incident Response Advisor</h3></div>',
                unsafe_allow_html=True)
    st.markdown(
        "Based on the threats detected in this scan, the AI generates a concrete "
        "5-step incident response plan tailored to the exact violations found."
    )

    # Reference strip showing all 5 steps
    IR_META = [
        ("01", "Identify",    "#E67E22",
         "Review alerts, monitor for prevented activity, and hunt for malicious behavior."),
        ("02", "Assess Risk", "#E74C3C",
         "Determine impact based on targeted asset and notify relevant partners."),
        ("03", "Contain",     "#8E44AD",
         "Stop the attack from spreading or getting worse."),
        ("04", "Eradicate",   "#C0392B",
         "Remove the threat, disable unauthorized access, notify state/federal partners."),
        ("05", "Recover",     "#27AE60",
         "Fix architecture weaknesses and update Security Awareness Training."),
    ]
    ref_cols = st.columns(5)
    for i, (num, name, color, desc) in enumerate(IR_META):
        with ref_cols[i]:
            st.markdown(f"""
<div style="background:{color}15; border:1px solid {color}44; border-radius:8px;
            padding:10px; text-align:center; min-height:110px;">
    <div style="font-size:10px; font-weight:700; color:{color};
                text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px;">Step {num}</div>
    <div style="font-size:13px; font-weight:700; color:{color}; margin-bottom:6px;">{name}</div>
    <div style="font-size:10px; color:#888; line-height:1.4;">{desc[:65]}...</div>
</div>
""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col_a, col_b = st.columns([4, 1])
    with col_a:
        extra = st.text_input(
            "Add extra context (optional)",
            placeholder="e.g. violations on POS terminal at register 3, scan ran at 2:14 AM...",
            key="ir_extra_context"
        )
    with col_b:
        st.markdown("<br>", unsafe_allow_html=True)
        run_ir = st.button("🛡️ Generate IR Plan", type="primary", key="ir_run_btn")

    if run_ir:
        threat_context = (
            f"Threat level: {result.get('threat_level', 'UNKNOWN')}\n"
            f"Total violations: {result.get('total_violations', 0)}\n"
            f"Violation types detected: {', '.join(result.get('violation_types', []))}\n"
            f"Affected devices: {len(result.get('affected_devices', []))}\n"
            f"AI analysis summary: {result.get('analysis', '')[:600]}"
        )
        if extra:
            threat_context += f"\nAdditional context: {extra}"

        with st.spinner("Generating 5-step incident response plan..."):
            try:
                from openai import OpenAI
                client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

                ir_prompt = f"""You are a PCI-DSS v4.0 incident response expert for a retail environment.
A network security scanner (Max-Guard) detected the following:

{threat_context}

Generate a 5-step incident response plan. Respond ONLY in valid JSON, no markdown, no preamble.

Required structure:
{{
  "identify":    {{ "actions": ["...", "...", "...", "..."] }},
  "assess_risk": {{ "actions": ["...", "...", "..."] }},
  "contain":     {{ "actions": ["...", "...", "...", "..."] }},
  "eradicate":   {{ "actions": ["...", "...", "..."] }},
  "recover":     {{ "actions": ["...", "...", "...", "..."] }}
}}

Rules:
- Actions must be specific to the exact violation types detected (FTP, HTTP, Telnet, etc.)
- Reference the PCI-DSS v4.0 requirement number in at least one action per step
- Actions must be immediately executable by a retail security team, not generic advice
- Each step should have 3 to 4 actions"""

                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a PCI-DSS incident response expert. Respond only in valid JSON."},
                        {"role": "user",   "content": ir_prompt}
                    ],
                    max_tokens=1000,
                    temperature=0.2
                )
                raw     = response.choices[0].message.content.strip()
                clean   = raw.replace("```json", "").replace("```", "").strip()
                ir_plan = json.loads(clean)
                st.session_state["ir_plan"] = ir_plan
                st.rerun()

            except Exception as e:
                st.error(f"IR plan generation failed: {str(e)}")

    # ── Render IR plan cards ───────────────────────────────────────────────────
    if "ir_plan" in st.session_state:
        ir = st.session_state["ir_plan"]

        STEPS = [
            ("identify",    "Step 1: Identify",    "#E67E22",
             "Review alerts, monitor for prevented activity, and hunt for malicious behavior."),
            ("assess_risk", "Step 2: Assess Risk",  "#E74C3C",
             "Determine the potential impact based on the targeted asset (device, application, data, or department) and notify relevant partners."),
            ("contain",     "Step 3: Contain",      "#8E44AD",
             "Stop the attack from spreading or getting worse."),
            ("eradicate",   "Step 4: Eradicate",    "#C0392B",
             "Remove the threat (e.g. viruses), disable unauthorized access, and notify state/federal/utility partners."),
            ("recover",     "Step 5: Recover",      "#27AE60",
             "Identify architecture weaknesses, evaluate new technologies or process changes, and incorporate lessons learned into Security Awareness Training."),
        ]

        st.markdown("---")
        st.markdown("#### AI-Generated Incident Response Plan")
        st.caption(
            f"Tailored to this scan — Threat Level: **{result.get('threat_level', '?')}** | "
            f"Violations: **{result.get('total_violations', 0)}** | PCI-DSS v4.0 references included."
        )

        for key, label, color, description in STEPS:
            step_data    = ir.get(key, {})
            actions      = step_data.get("actions", [])
            actions_html = "".join([f"<li>{a}</li>" for a in actions])

            st.markdown(f"""
<div class="ir-step-box" style="background:{color}12; border-color:{color}55;">
    <div class="ir-step-title" style="color:{color};">{label}</div>
    <div class="ir-step-desc" style="color:#999;">{description}</div>
    <div class="ir-step-body"><ul>{actions_html}</ul></div>
</div>
""", unsafe_allow_html=True)

        st.caption(
            "For authorized networks only. All IR actions should be reviewed "
            "by a qualified security professional before execution."
        )


def render_ai_analysis(result):
    st.markdown('<div class="section-header"><h3>AI Threat Analysis (GPT-4o-mini)</h3></div>',
                unsafe_allow_html=True)
    render_threat_badge(result["threat_level"])
    st.markdown(result["analysis"])

    st.divider()

    # IR Advisor lives directly below the AI analysis output
    render_ir_section(result)


def render_exports(packets, result):
    st.markdown('<div class="section-header"><h3>Export Reports</h3></div>',
                unsafe_allow_html=True)
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

    st.markdown('<div class="section-header"><h3>All Captured Packets</h3></div>',
                unsafe_allow_html=True)
    st.dataframe(pd.DataFrame(packets), use_container_width=True)
    st.divider()

    render_violations_table(packets)
    st.divider()
    render_affected_devices(result)
    st.divider()
    render_investigation_guides(result)
    st.divider()
    render_ai_analysis(result)   # IR section lives inside here
    st.divider()
    render_exports(packets, result)


# ── Entrypoint ─────────────────────────────────────────────────────────────────
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