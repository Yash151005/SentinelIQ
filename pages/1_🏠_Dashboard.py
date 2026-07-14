"""
SentinelIQ — Page 1: Real-Time Behavioural Dashboard
=====================================================
Live feed of privileged user sessions with:
- Colour-coded risk scores (GREEN / AMBER / RED)
- Plotly gauge charts per admin
- Metrics: login time deviation, data volume, command frequency,
  geo-location anomaly, off-hours flag
- 7-day timeline heatmap
- AI Insight card with Groq summary
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import datetime
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utils import mongo_client, groq_client, anomaly_engine, data_simulator

st.set_page_config(page_title="SentinelIQ — Dashboard", page_icon="🏠", layout="wide")

# ---------------------------------------------------------------------------
# Auth Guard
# ---------------------------------------------------------------------------
if not st.session_state.get("authenticated"):
    st.warning("🔒 Please login from the main page.")
    st.stop()

# Ensure data is initialized
if "initialized" not in st.session_state:
    data_simulator.seed_database()
    st.session_state["initialized"] = True


# ---------------------------------------------------------------------------
# Page Header
# ---------------------------------------------------------------------------
st.markdown("""
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
        <span style="font-size: 2rem;">🏠</span>
        <div>
            <div style="font-weight: 800; font-size: 1.6rem; color: #1E293B;
                        font-family: 'Inter', sans-serif;">
                Real-Time Behavioural Dashboard
            </div>
            <div style="color: #64748B; font-size: 0.85rem;">
                Live risk monitoring for privileged user sessions
            </div>
        </div>
    </div>
""", unsafe_allow_html=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# Top Metrics Row
# ---------------------------------------------------------------------------
sessions = mongo_client.find("sessions", sort=[("start_time", -1)], limit=500)
users = mongo_client.find("users")
alerts = mongo_client.find("alerts", sort=[("timestamp", -1)], limit=50)

total_sessions = len(sessions)
flagged_sessions = len([s for s in sessions if s.get("flagged")])
avg_risk = sum(s.get("anomaly_score", 0) for s in sessions) / max(1, total_sessions)
active_alerts = len([a for a in alerts if not a.get("resolved")])
off_hours_count = len([s for s in sessions if s.get("start_time") and
                       isinstance(s["start_time"], datetime.datetime) and
                       (s["start_time"].hour < 7 or s["start_time"].hour > 19)])

col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.metric("📊 Total Sessions", total_sessions, delta=f"+{len(sessions[:10])}")
with col2:
    st.metric("⚠️ Flagged Sessions", flagged_sessions,
              delta=f"{round(flagged_sessions/max(1,total_sessions)*100,1)}%")
with col3:
    st.metric("📈 Avg Risk Score", f"{avg_risk:.1f}",
              delta="↑" if avg_risk > 40 else "↓", delta_color="inverse")
with col4:
    st.metric("🚨 Active Alerts", active_alerts)
with col5:
    st.metric("🌙 Off-Hours Access", off_hours_count)

st.markdown("---")

# ---------------------------------------------------------------------------
# Risk Gauge Charts (per user)
# ---------------------------------------------------------------------------
st.markdown("### 📊 User Risk Gauges — Current Session Risk")

user_latest_scores = {}
for session in sessions:
    uid = session.get("user_id", "")
    if uid not in user_latest_scores:
        user_latest_scores[uid] = session.get("anomaly_score", 0)

# Create gauge charts in rows of 5
user_items = list(user_latest_scores.items())
for row_start in range(0, len(user_items), 5):
    cols = st.columns(5)
    for i, col in enumerate(cols):
        idx = row_start + i
        if idx < len(user_items):
            username, score = user_items[idx]
            # Find user role
            user_info = next((u for u in users if u.get("username") == username), {})
            role = user_info.get("role", "UNKNOWN")

            # Determine color
            if score <= 40:
                bar_color, level = "#00C896", "GREEN"
            elif score <= 70:
                bar_color, level = "#FFB84D", "AMBER"
            else:
                bar_color, level = "#FF4C4C", "RED"

            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                number={'suffix': '', 'font': {'size': 28, 'color': bar_color,
                         'family': 'JetBrains Mono'}},
                gauge={
                    'axis': {'range': [0, 100], 'tickwidth': 1,
                             'tickcolor': '#E2E8F0', 'dtick': 25},
                    'bar': {'color': bar_color, 'thickness': 0.7},
                    'bgcolor': '#F8FAFC',
                    'borderwidth': 1,
                    'bordercolor': '#E2E8F0',
                    'steps': [
                        {'range': [0, 40], 'color': 'rgba(0,200,150,0.05)'},
                        {'range': [40, 70], 'color': 'rgba(255,184,77,0.05)'},
                        {'range': [70, 100], 'color': 'rgba(255,76,76,0.05)'},
                    ],
                    'threshold': {
                        'line': {'color': '#FF4C4C', 'width': 2},
                        'thickness': 0.8,
                        'value': 70,
                    },
                },
                title={'text': f"<b>{username.split('.')[0].title()}</b><br>"
                               f"<span style='font-size:0.7em;color:#64748B'>{role}</span>",
                       'font': {'size': 13, 'color': '#1E293B', 'family': 'Inter'}},
            ))
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                height=200,
                margin=dict(t=60, b=10, l=20, r=20),
            )
            with col:
                st.plotly_chart(fig, use_container_width=True, key=f"gauge_{idx}")

st.markdown("---")

# ---------------------------------------------------------------------------
# Live Session Feed
# ---------------------------------------------------------------------------
st.markdown("### 📡 Live Session Feed")

# Simulate new session button
col_refresh, col_sim = st.columns([3, 1])
with col_sim:
    if st.button("▶️ Simulate New Session"):
        result = data_simulator.generate_live_session()
        st.toast(f"New session: {result['session']['user_id']} — "
                 f"Risk: {result['score']:.1f} ({result['risk_level']})")
        st.rerun()

# Session table
recent_sessions = sessions[:20]
if recent_sessions:
    session_data = []
    for s in recent_sessions:
        score = s.get("anomaly_score", 0)
        if score <= 40:
            risk_badge = "🟢 GREEN"
        elif score <= 70:
            risk_badge = "🟡 AMBER"
        else:
            risk_badge = "🔴 RED"

        start = s.get("start_time", "")
        if isinstance(start, datetime.datetime):
            start_str = start.strftime("%Y-%m-%d %H:%M")
        else:
            start_str = str(start)

        session_data.append({
            "User": s.get("user_id", ""),
            "Start Time": start_str,
            "Risk Score": score,
            "Risk Level": risk_badge,
            "Commands": len(s.get("commands", [])),
            "Data (MB)": s.get("data_mb", 0),
            "IP": s.get("ip", ""),
            "Location": s.get("geo", ""),
            "Flagged": "🚩" if s.get("flagged") else "✅",
        })

    df = pd.DataFrame(session_data)
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Risk Score": st.column_config.ProgressColumn(
                "Risk Score", min_value=0, max_value=100, format="%.1f"
            ),
            "Data (MB)": st.column_config.NumberColumn(
                "Data (MB)", format="%.2f"
            ),
        },
    )

st.markdown("---")

# ---------------------------------------------------------------------------
# 7-Day Timeline Heatmap
# ---------------------------------------------------------------------------
st.markdown("### 🗓️ 7-Day Access Pattern Heatmap")

# Build heatmap data: hours (x) vs days (y) vs count of sessions
now = datetime.datetime.now(datetime.timezone.utc)
heatmap_data = []
day_labels = []

for day_offset in range(6, -1, -1):
    day = now - datetime.timedelta(days=day_offset)
    day_label = day.strftime("%a %m/%d")
    day_labels.append(day_label)

    for hour in range(24):
        count = 0
        risk_sum = 0
        for s in sessions:
            st_time = s.get("start_time")
            if isinstance(st_time, datetime.datetime):
                if (st_time.date() == day.date() and st_time.hour == hour):
                    count += 1
                    risk_sum += s.get("anomaly_score", 0)

        heatmap_data.append({
            "Day": day_label,
            "Hour": f"{hour:02d}:00",
            "Sessions": count,
            "Avg Risk": round(risk_sum / max(1, count), 1),
        })

heatmap_df = pd.DataFrame(heatmap_data)

if not heatmap_df.empty and heatmap_df["Sessions"].sum() > 0:
    pivot = heatmap_df.pivot(index="Day", columns="Hour", values="Sessions").fillna(0)

    fig_heatmap = go.Figure(data=go.Heatmap(
        z=pivot.values,
        x=pivot.columns.tolist(),
        y=pivot.index.tolist(),
        colorscale=[
            [0, '#F8FAFC'],
            [0.25, '#E2E8F0'],
            [0.5, '#0066CC'],
            [0.75, '#F59E0B'],
            [1, '#EF4444'],
        ],
        showscale=True,
        colorbar=dict(
            title="Sessions",
            title_font=dict(color='#64748B', family='Inter'),
            tickfont=dict(color='#64748B', family='JetBrains Mono'),
        ),
        hovertemplate="<b>%{y}</b> at %{x}<br>Sessions: %{z}<extra></extra>",
    ))

    fig_heatmap.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=300,
        margin=dict(t=20, b=40, l=80, r=20),
        xaxis=dict(title="Hour of Day", tickfont=dict(color='#64748B', size=10,
                   family='JetBrains Mono'), title_font=dict(color='#64748B', family='Inter')),
        yaxis=dict(title="", tickfont=dict(color='#64748B', size=11, family='Inter')),
    )

    st.plotly_chart(fig_heatmap, use_container_width=True)
else:
    st.info("📊 Heatmap will populate as sessions are recorded over the next 7 days.")

st.markdown("---")

# ---------------------------------------------------------------------------
# AI Insight Card
# ---------------------------------------------------------------------------
st.markdown("### 🤖 AI Threat Landscape Insight")

with st.expander("📡 Generate AI Analysis of Current Threat Landscape", expanded=False):
    if st.button("🧠 Generate Insight", key="dashboard_insight"):
        stats = {
            "total_sessions": total_sessions,
            "flagged_sessions": flagged_sessions,
            "avg_risk_score": round(avg_risk, 1),
            "active_alerts": active_alerts,
            "off_hours_accesses": off_hours_count,
            "high_risk_users": len([u for u, s in user_latest_scores.items() if s > 70]),
            "timestamp": datetime.datetime.now().isoformat(),
        }
        with st.spinner("🤖 Analyzing threat landscape with Groq AI..."):
            insight = groq_client.generate_dashboard_insight(stats)

        st.markdown(f"""
            <div class="ai-insight-card">
                <div style="font-weight: 700; color: #0066CC; margin-bottom: 12px;
                            font-size: 1rem;">
                    🤖 AI Threat Landscape Analysis
                </div>
                <div style="color: #334155; font-size: 0.95rem; line-height: 1.7;">
                    {insight}
                </div>
                <div style="color: #64748B; font-size: 0.75rem; margin-top: 12px;
                            font-family: 'JetBrains Mono', monospace;">
                    Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
                    Model: llama-3.3-70b-versatile
                </div>
            </div>
        """, unsafe_allow_html=True)
