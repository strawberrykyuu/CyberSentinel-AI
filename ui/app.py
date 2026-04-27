"""
ui/app.py
=========
Streamlit dashboard for the Agentic AI Cybersecurity System.

Run with:
    streamlit run ui/app.py

Layout
------
  Sidebar        : controls (start/stop, batch size, thresholds)
  Row 1          : KPI cards (events, anomalies, blocked IPs, malware)
  Row 2 (charts) : Anomaly score trend | Alerts over time
  Row 3 (chart)  : Normal vs Anomalous distribution (pie)
  Row 4          : Severity breakdown bar chart
  Row 5          : Live event table with colour-coded rows
  Row 6          : Agent pipeline status
"""

import sys
import os
import time
import random
from collections import deque

# Add project root to path so imports work from ui/ subfolder
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

import config
from orchestrator.main_orchestrator import MainOrchestrator

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="CyberSentinel AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    /* Dark header bar */
    .main-header {
        background: linear-gradient(90deg, #0f0f23 0%, #1a1a3e 50%, #0f0f23 100%);
        padding: 1.2rem 2rem;
        border-radius: 10px;
        margin-bottom: 1.5rem;
        border: 1px solid #2d2d6b;
    }
    .main-header h1 { color: #00d4ff; margin: 0; font-size: 1.8rem; }
    .main-header p  { color: #8888aa; margin: 0.3rem 0 0 0; font-size: 0.9rem; }

    /* KPI cards */
    .kpi-card {
        background: #12122a;
        border: 1px solid #2a2a5a;
        border-radius: 10px;
        padding: 1rem 1.5rem;
        text-align: center;
    }
    .kpi-value { font-size: 2.2rem; font-weight: 700; color: #00d4ff; }
    .kpi-label { font-size: 0.85rem; color: #8888aa; margin-top: 0.2rem; }
    .kpi-card.danger  .kpi-value { color: #ff4b4b; }
    .kpi-card.warning .kpi-value { color: #ffa500; }
    .kpi-card.ok      .kpi-value { color: #00cc88; }

    /* Severity badge */
    .badge-critical { background:#ff4b4b; color:#fff; padding:2px 8px;
                       border-radius:4px; font-size:0.75rem; }
    .badge-high     { background:#ff8c00; color:#fff; padding:2px 8px;
                       border-radius:4px; font-size:0.75rem; }
    .badge-medium   { background:#ffd700; color:#000; padding:2px 8px;
                       border-radius:4px; font-size:0.75rem; }
    .badge-low      { background:#00cc88; color:#fff; padding:2px 8px;
                       border-radius:4px; font-size:0.75rem; }

    /* Section headers */
    .section-header {
        color: #00d4ff;
        font-size: 1rem;
        font-weight: 600;
        border-bottom: 1px solid #2a2a5a;
        padding-bottom: 0.4rem;
        margin: 1rem 0 0.8rem 0;
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Session-state initialisation
# ---------------------------------------------------------------------------
def _init_state():
    if "orchestrator" not in st.session_state:
        st.session_state.orchestrator = MainOrchestrator()
    if "running" not in st.session_state:
        st.session_state.running = False
    if "all_events" not in st.session_state:
        st.session_state.all_events: list = []
    if "score_history" not in st.session_state:
        # deque of (tick, avg_score) for the trend chart
        st.session_state.score_history = deque(maxlen=120)
    if "alert_history" not in st.session_state:
        # deque of (tick, alert_count)
        st.session_state.alert_history = deque(maxlen=120)
    if "tick_count" not in st.session_state:
        st.session_state.tick_count = 0

_init_state()

orc: MainOrchestrator = st.session_state.orchestrator

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ CyberSentinel AI")
    st.markdown("---")

    col_run, col_stop = st.columns(2)
    with col_run:
        if st.button("▶ Start", use_container_width=True, type="primary"):
            st.session_state.running = True
    with col_stop:
        if st.button("⏹ Stop", use_container_width=True):
            st.session_state.running = False

    if st.button("🔄 Reset Session", use_container_width=True):
        for key in ("orchestrator", "all_events", "score_history",
                    "alert_history", "tick_count", "running"):
            st.session_state.pop(key, None)
        st.rerun()

    st.markdown("---")
    st.markdown("### ⚙️ Settings")

    refresh_rate = st.slider(
        "Refresh interval (s)", min_value=1, max_value=10,
        value=int(config.SIMULATION_INTERVAL_SEC), step=1,
    )
    batch_size = st.slider(
        "Events per batch", min_value=5, max_value=100,
        value=config.SIMULATION_BATCH_SIZE, step=5,
    )
    anomaly_threshold = st.slider(
        "Anomaly threshold", min_value=0.1, max_value=0.9,
        value=config.ANOMALY_SCORE_THRESHOLD, step=0.05,
    )

    # Write slider values back to config (runtime override)
    config.SIMULATION_BATCH_SIZE    = batch_size
    config.ANOMALY_SCORE_THRESHOLD  = anomaly_threshold

    st.markdown("---")
    st.markdown("### 📊 Pipeline Status")
    stats = orc.stats
    st.metric("Total Batches",   stats["batches_processed"])
    st.metric("Events Processed", stats["monitoring"].get("total_received", 0))
    st.metric("Anomalies Found",  stats["detection"].get("total_anomalies", 0))
    st.metric("IPs Blocked",      len(stats["blocked_ips"]))
    st.metric("Hosts Isolated",   len(stats["isolated_hosts"]))

    st.markdown("---")
    if stats["blocked_ips"]:
        st.markdown("**🚫 Blocked IPs**")
        for ip in list(stats["blocked_ips"])[:10]:
            st.code(ip, language=None)

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown("""
<div class="main-header">
  <h1>🛡️ CyberSentinel AI — Agentic Cybersecurity System</h1>
  <p>Real-time event monitoring · Anomaly detection · Automated response</p>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Tick (process one batch when running)
# ---------------------------------------------------------------------------
if st.session_state.running:
    new_events = orc.tick()
    st.session_state.all_events.extend(new_events)
    # Keep only the most recent 2000 events for display
    if len(st.session_state.all_events) > 2000:
        st.session_state.all_events = st.session_state.all_events[-2000:]

    t = st.session_state.tick_count
    if new_events:
        avg_score = sum(e.get("anomaly_score", 0) for e in new_events) / len(new_events)
        alerts    = sum(1 for e in new_events if e.get("is_anomaly"))
        st.session_state.score_history.append((t, round(avg_score, 4)))
        st.session_state.alert_history.append((t, alerts))
    st.session_state.tick_count += 1

all_events = st.session_state.all_events

# ---------------------------------------------------------------------------
# KPI cards
# ---------------------------------------------------------------------------
total_events   = len(all_events)
total_anomalies= sum(1 for e in all_events if e.get("is_anomaly"))
total_blocked  = sum(1 for e in all_events if e.get("is_blocked"))
total_malware  = sum(1 for e in all_events if e.get("malware_is_threat"))
normal_pct     = round((1 - total_anomalies / max(total_events, 1)) * 100, 1)

c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    st.markdown(f"""
    <div class="kpi-card ok">
      <div class="kpi-value">{total_events:,}</div>
      <div class="kpi-label">Total Events</div>
    </div>""", unsafe_allow_html=True)
with c2:
    st.markdown(f"""
    <div class="kpi-card warning">
      <div class="kpi-value">{total_anomalies:,}</div>
      <div class="kpi-label">Anomalies Detected</div>
    </div>""", unsafe_allow_html=True)
with c3:
    st.markdown(f"""
    <div class="kpi-card danger">
      <div class="kpi-value">{total_blocked:,}</div>
      <div class="kpi-label">IPs Blocked</div>
    </div>""", unsafe_allow_html=True)
with c4:
    st.markdown(f"""
    <div class="kpi-card danger">
      <div class="kpi-value">{total_malware:,}</div>
      <div class="kpi-label">Malware Confirmed</div>
    </div>""", unsafe_allow_html=True)
with c5:
    st.markdown(f"""
    <div class="kpi-card ok">
      <div class="kpi-value">{normal_pct}%</div>
      <div class="kpi-label">Normal Traffic</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Charts row 1: Anomaly score trend + Alerts over time
# ---------------------------------------------------------------------------
st.markdown('<div class="section-header">📈 Real-Time Analytics</div>', unsafe_allow_html=True)

ch1, ch2 = st.columns(2)

with ch1:
    score_hist = list(st.session_state.score_history)
    if score_hist:
        df_score = pd.DataFrame(score_hist, columns=["tick", "avg_anomaly_score"])
        fig_score = go.Figure()
        fig_score.add_trace(go.Scatter(
            x=df_score["tick"], y=df_score["avg_anomaly_score"],
            mode="lines+markers",
            line=dict(color="#00d4ff", width=2),
            marker=dict(size=4),
            fill="tozeroy",
            fillcolor="rgba(0,212,255,0.08)",
            name="Avg Anomaly Score",
        ))
        fig_score.add_hline(
            y=config.ANOMALY_SCORE_THRESHOLD,
            line_dash="dash",
            line_color="#ff4b4b",
            annotation_text=f"Threshold ({config.ANOMALY_SCORE_THRESHOLD})",
            annotation_font_color="#ff4b4b",
        )
        fig_score.update_layout(
            title="Anomaly Score Trend",
            xaxis_title="Batch",
            yaxis_title="Avg Score",
            yaxis_range=[0, 1],
            template="plotly_dark",
            height=280,
            margin=dict(l=10, r=10, t=40, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_score, use_container_width=True)
    else:
        st.info("Start the simulation to see the anomaly score trend.")

with ch2:
    alert_hist = list(st.session_state.alert_history)
    if alert_hist:
        df_alert = pd.DataFrame(alert_hist, columns=["tick", "alert_count"])
        fig_alert = px.bar(
            df_alert, x="tick", y="alert_count",
            color="alert_count",
            color_continuous_scale=["#00cc88", "#ffa500", "#ff4b4b"],
            title="Alerts per Batch",
            labels={"tick": "Batch", "alert_count": "Alerts"},
            template="plotly_dark",
            height=280,
        )
        fig_alert.update_layout(
            showlegend=False,
            margin=dict(l=10, r=10, t=40, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_alert, use_container_width=True)
    else:
        st.info("Start the simulation to see the alerts chart.")

# ---------------------------------------------------------------------------
# Charts row 2: Normal vs Anomalous pie + Severity breakdown
# ---------------------------------------------------------------------------
ch3, ch4 = st.columns(2)

with ch3:
    if all_events:
        n_normal = total_events - total_anomalies
        fig_pie = go.Figure(go.Pie(
            labels=["Normal", "Anomalous"],
            values=[n_normal, total_anomalies],
            marker_colors=["#00cc88", "#ff4b4b"],
            hole=0.45,
            textinfo="label+percent",
        ))
        fig_pie.update_layout(
            title="Normal vs Anomalous Events",
            template="plotly_dark",
            height=280,
            margin=dict(l=10, r=10, t=40, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.info("No data yet.")

with ch4:
    if all_events:
        sev_counts = orc.stats["decision_severity"]
        sev_order  = ["critical", "high", "medium", "low"]
        sev_colors = {"critical": "#ff4b4b", "high": "#ff8c00",
                      "medium": "#ffd700", "low": "#00cc88"}
        df_sev = pd.DataFrame([
            {"severity": s, "count": sev_counts.get(s, 0)}
            for s in sev_order
        ])
        fig_sev = px.bar(
            df_sev, x="severity", y="count",
            color="severity",
            color_discrete_map=sev_colors,
            title="Events by Severity",
            template="plotly_dark",
            height=280,
        )
        fig_sev.update_layout(
            showlegend=False,
            margin=dict(l=10, r=10, t=40, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_sev, use_container_width=True)
    else:
        st.info("No data yet.")

# ---------------------------------------------------------------------------
# Malware label distribution (when malware events exist)
# ---------------------------------------------------------------------------
malware_events = [e for e in all_events if e.get("malware_label")]
if malware_events:
    st.markdown('<div class="section-header">🦠 Malware Classification Results</div>',
                unsafe_allow_html=True)
    from collections import Counter
    label_counts = Counter(e["malware_label"] for e in malware_events)
    df_ml = pd.DataFrame(label_counts.items(), columns=["label", "count"])
    df_ml = df_ml.sort_values("count", ascending=False)
    fig_ml = px.bar(
        df_ml, x="label", y="count",
        color="label",
        title="Malware Type Distribution (CV Model)",
        template="plotly_dark",
        height=250,
    )
    fig_ml.update_layout(
        showlegend=False,
        margin=dict(l=10, r=10, t=40, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig_ml, use_container_width=True)

# ---------------------------------------------------------------------------
# Live events table
# ---------------------------------------------------------------------------
st.markdown('<div class="section-header">📋 Live Event Feed</div>', unsafe_allow_html=True)

if all_events:
    # Show the 200 most recent events
    recent = all_events[-200:][::-1]

    table_rows = []
    for ev in recent:
        sev = ev.get("severity", "low") or "low"
        badge_html = f'<span class="badge-{sev}">{sev.upper()}</span>'
        table_rows.append({
            "Time":          ev.get("timestamp", "")[-8:],   # HH:MM:SS
            "Source IP":     ev.get("source_ip", ""),
            "User":          ev.get("user", ""),
            "Event Type":    ev.get("event_type", ""),
            "Score":         f"{ev.get('anomaly_score', 0):.3f}",
            "Severity":      sev.upper(),
            "Action":        ev.get("response_action", "").replace("_", " "),
            "Malware":       ev.get("malware_label", "—"),
        })

    df_table = pd.DataFrame(table_rows)

    def _row_style(row):
        sev = row["Severity"].lower()
        bg_map = {
            "critical": "background-color: rgba(255,75,75,0.15)",
            "high":     "background-color: rgba(255,140,0,0.12)",
            "medium":   "background-color: rgba(255,215,0,0.08)",
            "low":      "",
        }
        style = bg_map.get(sev, "")
        return [style] * len(row)

    styled = df_table.style.apply(_row_style, axis=1)
    st.dataframe(styled, use_container_width=True, height=350)
else:
    st.info("▶ Press **Start** in the sidebar to begin the simulation.")

# ---------------------------------------------------------------------------
# Agent pipeline status
# ---------------------------------------------------------------------------
st.markdown('<div class="section-header">🤖 Agent Pipeline</div>', unsafe_allow_html=True)

pipeline_cols = st.columns(5)
agents_info = [
    ("🔍 Monitoring", "Cleans & validates events",
     orc.stats["monitoring"].get("total_forwarded", 0), "events forwarded"),
    ("🧠 Detection", "IF + Z-Score + UBA models",
     orc.stats["detection"].get("total_anomalies", 0), "anomalies found"),
    ("⚖️ Decision", "Severity & routing logic",
     sum(orc.stats["decision_severity"].values()), "events classified"),
    ("🦠 Malware", "Byte-image CV classifier",
     orc.stats["malware"].get("total_analysed", 0), "files analysed"),
    ("🚨 Response", "Automated remediation",
     sum(orc.stats["response_actions"].values()), "actions taken"),
]
for col, (name, desc, val, unit) in zip(pipeline_cols, agents_info):
    with col:
        st.markdown(f"""
        <div class="kpi-card">
          <div style="font-size:1.3rem;">{name}</div>
          <div class="kpi-value" style="font-size:1.6rem;">{val:,}</div>
          <div class="kpi-label">{unit}</div>
          <div style="color:#555;font-size:0.75rem;margin-top:0.3rem;">{desc}</div>
        </div>""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Auto-refresh when running
# ---------------------------------------------------------------------------
if st.session_state.running:
    time.sleep(refresh_rate)
    st.rerun()
else:
    st.markdown(
        "<p style='color:#555;text-align:center;margin-top:2rem;'>"
        "⏸ Simulation paused — press ▶ Start to resume.</p>",
        unsafe_allow_html=True,
    )
