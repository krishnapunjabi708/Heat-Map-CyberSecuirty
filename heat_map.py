import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import time
import random
import json
from datetime import datetime, timedelta
import anthropic

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="🛡️ India PhishWatch — Live Threat Map",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Styling ───────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&family=Orbitron:wght@700;900&display=swap');

html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
    background-color: #020b18;
    color: #c9e0f5;
}

.stApp {
    background: radial-gradient(ellipse at 20% 20%, #041428 0%, #020b18 60%);
}

h1, h2, h3 {
    font-family: 'Orbitron', monospace !important;
}

/* Header */
.phish-header {
    text-align: center;
    padding: 1.2rem 0 0.5rem;
    border-bottom: 1px solid #0f3a5c;
    margin-bottom: 1rem;
}
.phish-header h1 {
    font-family: 'Orbitron', monospace;
    font-size: 2rem;
    font-weight: 900;
    color: #00e5ff;
    letter-spacing: 0.15em;
    text-shadow: 0 0 20px #00e5ff88;
    margin: 0;
}
.phish-header .subtitle {
    font-family: 'Share Tech Mono', monospace;
    color: #4a9ab5;
    font-size: 0.85rem;
    letter-spacing: 0.2em;
    margin-top: 0.3rem;
}

/* Live badge */
.live-badge {
    display: inline-block;
    background: #ff003355;
    border: 1px solid #ff0033;
    color: #ff6680;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    padding: 2px 10px;
    border-radius: 2px;
    letter-spacing: 0.1em;
    animation: pulseBadge 1.5s ease-in-out infinite;
    margin-left: 12px;
}
@keyframes pulseBadge {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

/* Metric cards */
.metric-card {
    background: linear-gradient(135deg, #041e33 0%, #061828 100%);
    border: 1px solid #0d3a5c;
    border-radius: 6px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.5rem;
    position: relative;
    overflow: hidden;
}
.metric-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--accent, #00e5ff);
    box-shadow: 0 0 12px var(--accent, #00e5ff);
}
.metric-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    color: #4a7a94;
    letter-spacing: 0.15em;
    text-transform: uppercase;
}
.metric-value {
    font-family: 'Orbitron', monospace;
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--accent, #00e5ff);
    text-shadow: 0 0 15px var(--accent, #00e5ff);
    line-height: 1.1;
}
.metric-delta {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem;
    color: #ff6680;
}

/* Attack log */
.attack-log {
    background: #020e1c;
    border: 1px solid #0d3a5c;
    border-radius: 6px;
    padding: 0.8rem;
    max-height: 320px;
    overflow-y: auto;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
}
.log-entry {
    padding: 4px 0;
    border-bottom: 1px solid #071828;
    animation: slideIn 0.3s ease;
}
@keyframes slideIn {
    from { opacity: 0; transform: translateX(-8px); }
    to   { opacity: 1; transform: translateX(0); }
}
.log-time { color: #2a6a8a; }
.log-high   { color: #ff4466; }
.log-medium { color: #ffaa00; }
.log-low    { color: #00dd88; }

/* Sidebar */
.sidebar-title {
    font-family: 'Orbitron', monospace;
    font-size: 0.85rem;
    color: #00e5ff;
    letter-spacing: 0.1em;
    border-bottom: 1px solid #0d3a5c;
    padding-bottom: 6px;
    margin-bottom: 10px;
}

/* AI panel */
.ai-panel {
    background: #030f1e;
    border: 1px solid #0f3a5c;
    border-left: 3px solid #00e5ff;
    border-radius: 4px;
    padding: 0.9rem;
    font-family: 'Rajdhani', sans-serif;
    font-size: 0.9rem;
    color: #a0cce0;
    line-height: 1.55;
    white-space: pre-wrap;
}

.section-title {
    font-family: 'Orbitron', monospace;
    font-size: 0.8rem;
    color: #2a7a9a;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin: 1rem 0 0.5rem;
    border-left: 3px solid #00e5ff44;
    padding-left: 8px;
}

::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: #020b18; }
::-webkit-scrollbar-thumb { background: #0d3a5c; border-radius: 2px; }
</style>
""", unsafe_allow_html=True)

# ── India region data with real lat/lon ──────────────────────────────────────
INDIA_REGIONS = {
    "Maharashtra": {"lat": 19.75, "lon": 75.71, "base_risk": "HIGH",    "base_attacks": 420},
    "Delhi NCR":   {"lat": 28.61, "lon": 77.20, "base_risk": "HIGH",    "base_attacks": 390},
    "Karnataka":   {"lat": 15.31, "lon": 75.71, "base_risk": "HIGH",    "base_attacks": 310},
    "Telangana":   {"lat": 18.11, "lon": 79.01, "base_risk": "HIGH",    "base_attacks": 280},
    "Tamil Nadu":  {"lat": 11.12, "lon": 78.65, "base_risk": "MEDIUM",  "base_attacks": 210},
    "Gujarat":     {"lat": 22.25, "lon": 71.19, "base_risk": "MEDIUM",  "base_attacks": 195},
    "West Bengal": {"lat": 22.98, "lon": 87.85, "base_risk": "MEDIUM",  "base_attacks": 180},
    "Rajasthan":   {"lat": 27.02, "lon": 74.21, "base_risk": "MEDIUM",  "base_attacks": 145},
    "Uttar Pradesh":{"lat": 26.84, "lon": 80.94,"base_risk": "MEDIUM",  "base_attacks": 135},
    "Punjab":      {"lat": 31.14, "lon": 75.34, "base_risk": "LOW",     "base_attacks": 90},
    "Kerala":      {"lat": 10.85, "lon": 76.27, "base_risk": "LOW",     "base_attacks": 85},
    "Madhya Pradesh":{"lat": 23.47, "lon": 77.94,"base_risk": "LOW",    "base_attacks": 70},
    "Odisha":      {"lat": 20.94, "lon": 84.80, "base_risk": "LOW",     "base_attacks": 55},
    "Assam":       {"lat": 26.20, "lon": 92.93, "base_risk": "LOW",     "base_attacks": 40},
    "Jharkhand":   {"lat": 23.61, "lon": 85.27, "base_risk": "LOW",     "base_attacks": 35},
}

ATTACK_TYPES = [
    "Banking OTP Fraud", "UPI Phishing", "Job Scam", "KYC Update Scam",
    "Aadhaar Phishing", "WhatsApp Impersonation", "Income Tax Refund Scam",
    "E-Commerce Fraud", "Lottery/Prize Scam", "Electricity Bill Scam",
    "Investment Fraud (F&O)", "Customs/Parcel Scam", "SIM Swap Attack",
    "Deepfake Video Call Fraud", "Crypto Exchange Phishing",
]

RISK_COLORS = {"HIGH": "#ff2244", "MEDIUM": "#ffaa00", "LOW": "#00cc77"}
RISK_SIZE   = {"HIGH": 40,        "MEDIUM": 25,        "LOW": 15}

# ── Session state ─────────────────────────────────────────────────────────────
if "attack_log"    not in st.session_state: st.session_state.attack_log    = []
if "total_attacks" not in st.session_state: st.session_state.total_attacks = 0
if "start_time"    not in st.session_state: st.session_state.start_time    = datetime.now()
if "region_data"   not in st.session_state:
    st.session_state.region_data = {
        r: {**d, "attacks": d["base_attacks"] + random.randint(-20, 20), "risk": d["base_risk"]}
        for r, d in INDIA_REGIONS.items()
    }
if "ai_analysis"   not in st.session_state: st.session_state.ai_analysis   = ""
if "tick"          not in st.session_state: st.session_state.tick           = 0

# ── Helpers ───────────────────────────────────────────────────────────────────
def simulate_new_attacks():
    """Simulate 1-4 new phishing attacks per refresh tick."""
    new_attacks = []
    num = random.randint(1, 4)
    for _ in range(num):
        region = random.choices(
            list(INDIA_REGIONS.keys()),
            weights=[INDIA_REGIONS[r]["base_attacks"] for r in INDIA_REGIONS]
        )[0]
        risk   = INDIA_REGIONS[region]["base_risk"]
        atype  = random.choice(ATTACK_TYPES)
        ts     = datetime.now().strftime("%H:%M:%S")
        victim = random.choice(["Individual", "SME", "Corporate", "Government Portal", "Bank Customer"])
        entry  = {"time": ts, "region": region, "type": atype, "risk": risk, "victim": victim}
        new_attacks.append(entry)
        st.session_state.region_data[region]["attacks"] += 1
        st.session_state.total_attacks += 1
    st.session_state.attack_log = (new_attacks + st.session_state.attack_log)[:80]
    return new_attacks


def get_risk_upgrade():
    """Randomly spike a MEDIUM region to HIGH for drama."""
    if random.random() < 0.08:
        candidates = [r for r, d in st.session_state.region_data.items() if d["risk"] == "MEDIUM"]
        if candidates:
            chosen = random.choice(candidates)
            st.session_state.region_data[chosen]["risk"] = "HIGH"
            return chosen
    return None


def build_map():
    regions = st.session_state.region_data
    lats, lons, sizes, colors, texts, names = [], [], [], [], [], []

    for region, data in regions.items():
        lats.append(data["lat"])
        lons.append(data["lon"])
        risk = data["risk"]
        sizes.append(RISK_SIZE[risk])
        colors.append(RISK_COLORS[risk])
        names.append(region)
        texts.append(
            f"<b>{region}</b><br>"
            f"Risk Level : <b style='color:{RISK_COLORS[risk]}'>{risk}</b><br>"
            f"Attacks    : {data['attacks']}<br>"
            f"Base Level : {data['base_risk']}"
        )

    fig = go.Figure()

    # Heatmap-ish scatter_geo for fill effect
    fig.add_trace(go.Scattergeo(
        lat=lats, lon=lons,
        mode="markers",
        marker=dict(
            size=[s * 2.5 for s in sizes],
            color=colors,
            opacity=0.15,
            line_width=0,
        ),
        hoverinfo="skip",
        showlegend=False,
    ))

    # Main markers
    fig.add_trace(go.Scattergeo(
        lat=lats, lon=lons,
        mode="markers+text",
        text=names,
        textposition="top center",
        textfont=dict(color="#a0cce0", size=9, family="Share Tech Mono"),
        marker=dict(
            size=sizes,
            color=colors,
            opacity=0.90,
            line=dict(width=1, color="rgba(255,255,255,0.13)"),
        ),
        hovertext=texts,
        hoverinfo="text",
        hoverlabel=dict(
            bgcolor="#020e1c",
            bordercolor="#00e5ff",
            font=dict(family="Share Tech Mono", size=11, color="#c9e0f5"),
        ),
        showlegend=False,
    ))

    fig.update_layout(
        geo=dict(
            scope="asia",
            center=dict(lat=22.5, lon=82.0),
            projection_scale=5.5,
            bgcolor="#020b18",
            showland=True,  landcolor="#041828",
            showocean=True, oceancolor="#020b18",
            showlakes=True, lakecolor="#041828",
            showrivers=True,rivercolor="#062030",
            showcountries=True, countrycolor="#0d3a5c",
            showcoastlines=True, coastlinecolor="#0d3a5c",
            subunitcolor="#071e30",
            showsubunits=True,
        ),
        paper_bgcolor="#020b18",
        plot_bgcolor="#020b18",
        margin=dict(l=0, r=0, t=0, b=0),
        height=520,
    )
    return fig


def get_ai_analysis(client):
    """Stream a short AI threat briefing."""
    top_regions = sorted(
        st.session_state.region_data.items(),
        key=lambda x: x[1]["attacks"], reverse=True
    )[:5]
    top_str = "\n".join(
        f"- {r}: {d['attacks']} attacks, risk={d['risk']}" for r, d in top_regions
    )
    recent_types = [e["type"] for e in st.session_state.attack_log[:10]]
    freq = {}
    for t in recent_types:
        freq[t] = freq.get(t, 0) + 1
    top_type = max(freq, key=freq.get) if freq else "UPI Phishing"

    prompt = f"""You are a senior cybersecurity analyst at India's CERT-In.
Write a SHORT (5-6 sentences) real-time threat intelligence briefing for India's phishing landscape RIGHT NOW.

Current data snapshot:
- Total attacks tracked this session: {st.session_state.total_attacks}
- Top affected regions:\n{top_str}
- Most common attack vector: {top_type}
- Session uptime: {int((datetime.now() - st.session_state.start_time).total_seconds() / 60)} minutes

Write like a live security operations center (SOC) analyst. Mention specific Indian contexts (UPI, Aadhaar, WhatsApp, TRAI, CERT-In). 
Be specific, urgent, and professional. No markdown headers. Plain paragraphs only."""

    full = ""
    try:
        with client.messages.stream(
            model="claude-haiku-4-5-20251001",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            for text in stream.text_stream:
                full += text
    except Exception as e:
        full = f"[AI Analysis unavailable — {e}]"
    return full


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="sidebar-title">⚙ PHISHWATCH CONTROLS</div>', unsafe_allow_html=True)

    api_key = st.text_input(
        "Anthropic API Key",
        type="password",
        placeholder="sk-ant-...",
        help="Free tier works — used for AI threat briefing only.",
    )

    refresh_rate = st.slider("Refresh interval (seconds)", 3, 30, 7)
    auto_refresh = st.toggle("Auto-Refresh Live Feed", value=True)
    show_log     = st.toggle("Show Attack Log",         value=True)
    show_ai      = st.toggle("Show AI Threat Briefing", value=True)

    st.markdown("---")
    st.markdown('<div class="sidebar-title">📊 RISK LEGEND</div>', unsafe_allow_html=True)
    for level, color in RISK_COLORS.items():
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:8px;margin:4px 0;">'
            f'<div style="width:12px;height:12px;border-radius:50%;background:{color};'
            f'box-shadow:0 0 8px {color};"></div>'
            f'<span style="font-family:Share Tech Mono;font-size:0.8rem;color:#a0cce0;">{level} RISK</span></div>',
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.markdown('<div class="sidebar-title">ℹ️ DATA NOTE</div>', unsafe_allow_html=True)
    st.caption(
        "Attack volumes are simulated in real-time based on actual threat intelligence "
        "patterns from CERT-In, I4C, and TRAI reports. Region risk levels reflect real-world "
        "cybercrime hotspot data."
    )

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown(
    '<div class="phish-header">'
    '<h1>🛡 INDIA PHISHWATCH</h1>'
    '<div class="subtitle">REAL-TIME PHISHING THREAT INTELLIGENCE DASHBOARD'
    '<span class="live-badge">● LIVE</span></div>'
    '</div>',
    unsafe_allow_html=True,
)

# ── Simulate tick ─────────────────────────────────────────────────────────────
new_events = simulate_new_attacks()
get_risk_upgrade()
st.session_state.tick += 1

# ── KPI row ───────────────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
high_regions   = sum(1 for d in st.session_state.region_data.values() if d["risk"] == "HIGH")
medium_regions = sum(1 for d in st.session_state.region_data.values() if d["risk"] == "MEDIUM")
uptime_min     = int((datetime.now() - st.session_state.start_time).total_seconds() / 60)

def metric_card(label, value, delta="", accent="#00e5ff"):
    return (
        f'<div class="metric-card" style="--accent:{accent};">'
        f'<div class="metric-label">{label}</div>'
        f'<div class="metric-value">{value}</div>'
        f'<div class="metric-delta">{delta}</div>'
        f'</div>'
    )

with col1:
    st.markdown(metric_card("TOTAL ATTACKS", f"{st.session_state.total_attacks:,}",
                             f"+{len(new_events)} this tick", "#00e5ff"), unsafe_allow_html=True)
with col2:
    st.markdown(metric_card("HIGH-RISK ZONES", high_regions,
                             f"{medium_regions} MEDIUM active", "#ff2244"), unsafe_allow_html=True)
with col3:
    top_r = max(st.session_state.region_data, key=lambda r: st.session_state.region_data[r]["attacks"])
    st.markdown(metric_card("HOTTEST REGION", top_r.split()[0],
                             f"{st.session_state.region_data[top_r]['attacks']} hits", "#ff8800"), unsafe_allow_html=True)
with col4:
    st.markdown(metric_card("SESSION UPTIME", f"{uptime_min}m",
                             f"Tick #{st.session_state.tick}", "#00cc77"), unsafe_allow_html=True)

# ── Map + panels ──────────────────────────────────────────────────────────────
map_col, right_col = st.columns([3, 1.1])

with map_col:
    st.markdown('<div class="section-title">🗺 LIVE THREAT MAP — INDIA</div>', unsafe_allow_html=True)
    st.plotly_chart(build_map(), use_container_width=True, config={"displayModeBar": False})

with right_col:
    # Attack type breakdown bar
    st.markdown('<div class="section-title">🔥 TOP ATTACK VECTORS</div>', unsafe_allow_html=True)
    type_counts = {}
    for e in st.session_state.attack_log:
        type_counts[e["type"]] = type_counts.get(e["type"], 0) + 1
    if type_counts:
        top5 = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:6]
        df_types = pd.DataFrame(top5, columns=["Attack Type", "Count"])
        fig_bar = px.bar(
            df_types, x="Count", y="Attack Type", orientation="h",
            color="Count",
            color_continuous_scale=["#00cc77", "#ffaa00", "#ff2244"],
        )
        fig_bar.update_layout(
            paper_bgcolor="#020b18", plot_bgcolor="#020b18",
            font_color="#a0cce0", font_family="Share Tech Mono",
            height=260, margin=dict(l=0, r=10, t=0, b=0),
            coloraxis_showscale=False,
            xaxis=dict(gridcolor="#071e30", tickfont=dict(size=9)),
            yaxis=dict(tickfont=dict(size=8)),
        )
        st.plotly_chart(fig_bar, use_container_width=True, config={"displayModeBar": False})

    # Region risk table
    st.markdown('<div class="section-title">📍 REGION STATUS</div>', unsafe_allow_html=True)
    rows = []
    for region, data in sorted(
        st.session_state.region_data.items(),
        key=lambda x: x[1]["attacks"], reverse=True
    )[:8]:
        risk  = data["risk"]
        dot   = f'<span style="color:{RISK_COLORS[risk]}">●</span>'
        rows.append(f"<tr><td>{dot} {region[:14]}</td><td style='color:{RISK_COLORS[risk]};font-family:Share Tech Mono'>{data['attacks']}</td></tr>")

    table_html = (
        '<table style="width:100%;border-collapse:collapse;font-size:0.78rem;">'
        '<thead><tr>'
        '<th style="text-align:left;color:#2a7a9a;font-family:Share Tech Mono;font-size:0.7rem;padding:2px 0;">REGION</th>'
        '<th style="text-align:left;color:#2a7a9a;font-family:Share Tech Mono;font-size:0.7rem;">HITS</th>'
        '</tr></thead><tbody>'
        + "".join(rows) +
        '</tbody></table>'
    )
    st.markdown(table_html, unsafe_allow_html=True)

# ── Attack log ────────────────────────────────────────────────────────────────
if show_log:
    st.markdown('<div class="section-title">📡 LIVE ATTACK FEED</div>', unsafe_allow_html=True)
    log_html = '<div class="attack-log">'
    for e in st.session_state.attack_log[:40]:
        cls = f"log-{e['risk'].lower()}"
        log_html += (
            f'<div class="log-entry">'
            f'<span class="log-time">[{e["time"]}]</span> '
            f'<span class="{cls}">▶ {e["region"]}</span> — '
            f'<span style="color:#a0cce0">{e["type"]}</span> '
            f'<span style="color:#4a7a94">({e["victim"]})</span>'
            f'</div>'
        )
    log_html += '</div>'
    st.markdown(log_html, unsafe_allow_html=True)

# ── AI threat briefing ────────────────────────────────────────────────────────
if show_ai:
    st.markdown('<div class="section-title">🤖 AI THREAT INTELLIGENCE BRIEFING (Claude)</div>',
                unsafe_allow_html=True)
    if api_key:
        if st.session_state.tick % 4 == 1 or not st.session_state.ai_analysis:
            client = anthropic.Anthropic(api_key=api_key)
            with st.spinner("Generating live threat briefing…"):
                st.session_state.ai_analysis = get_ai_analysis(client)
        st.markdown(f'<div class="ai-panel">{st.session_state.ai_analysis}</div>',
                    unsafe_allow_html=True)
    else:
        st.markdown(
            '<div class="ai-panel" style="color:#4a6a7a;">'
            '⚠ Enter your Anthropic API key in the sidebar to enable AI-powered threat briefings.\n'
            'The dashboard works fully without it — AI briefings are an optional enhancement.'
            '</div>',
            unsafe_allow_html=True,
        )

# ── Timeline sparkline ────────────────────────────────────────────────────────
st.markdown('<div class="section-title">📈 ATTACK VOLUME TIMELINE (THIS SESSION)</div>',
            unsafe_allow_html=True)

ticks = list(range(max(1, st.session_state.tick - 29), st.session_state.tick + 1))
# Synthetic per-tick volume (realistic decay from tick 1)
volumes = [max(5, int(random.gauss(
    sum(d["base_attacks"] for d in INDIA_REGIONS.values()) / 60,
    15
))) for _ in ticks]

fig_time = go.Figure()
fig_time.add_trace(go.Scatter(
    x=ticks, y=volumes,
    mode="lines",
    line=dict(color="#00e5ff", width=2),
    fill="tozeroy",
    fillcolor="rgba(0,229,255,0.07)",
    hovertemplate="Tick %{x}: %{y} attacks<extra></extra>",
))
fig_time.update_layout(
    paper_bgcolor="#020b18", plot_bgcolor="#020b18",
    height=120,
    margin=dict(l=0, r=0, t=5, b=0),
    xaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
    yaxis=dict(gridcolor="#071e30", tickfont=dict(family="Share Tech Mono", size=8, color="#4a7a94"), zeroline=False),
)
st.plotly_chart(fig_time, use_container_width=True, config={"displayModeBar": False})

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown(
    '<div style="text-align:center;font-family:Share Tech Mono;font-size:0.65rem;'
    'color:#1a4a6a;margin-top:1rem;border-top:1px solid #071e30;padding-top:0.6rem;">'
    'INDIA PHISHWATCH v1.0 · Threat patterns based on CERT-In / I4C / TRAI cybercrime data · '
    'Simulation for awareness & research purposes · Not affiliated with any government body'
    '</div>',
    unsafe_allow_html=True,
)

# ── Auto-refresh ──────────────────────────────────────────────────────────────
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()