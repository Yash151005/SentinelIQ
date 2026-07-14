"""
SentinelIQ — Page 2: AI Anomaly Detection Engine
==================================================
- Isolation Forest visualization
- River online model status
- Live anomaly feed with AI Threat Brief cards
- Model performance metrics
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
import datetime
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utils import mongo_client, groq_client, anomaly_engine, data_simulator

st.set_page_config(page_title="SentinelIQ — Anomaly Engine", page_icon="🔍", layout="wide")

if not st.session_state.get("authenticated"):
    st.warning("🔒 Please login from the main page.")
    st.stop()

if "initialized" not in st.session_state:
    data_simulator.seed_database()
    st.session_state["initialized"] = True

# ---------------------------------------------------------------------------
# Page Header
# ---------------------------------------------------------------------------
st.markdown("""
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
        <span style="font-size: 2rem;">🔍</span>
        <div>
            <div style="font-weight: 800; font-size: 1.6rem; color: #1E293B;">
                AI Anomaly Detection Engine
            </div>
            <div style="color: #64748B; font-size: 0.85rem;">
                Dual-model architecture: Isolation Forest + River Online Learning
            </div>
        </div>
    </div>
""", unsafe_allow_html=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# Model Status Cards
# ---------------------------------------------------------------------------
st.markdown("### ⚙️ Model Status")

model_status = anomaly_engine.get_model_status()
online_stats = anomaly_engine.get_online_model_stats()

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("🌳 Isolation Forest",
              "✅ Trained" if model_status["isolation_forest"]["trained"] else "❌ Not Trained")
with col2:
    st.metric("🌊 Online Model",
              "✅ Active" if online_stats["status"] == "active" else "⏳ Init")
with col3:
    st.metric("📊 Samples Processed", online_stats["samples_processed"])
with col4:
    st.metric("🚨 Anomalies Detected", online_stats["anomalies_detected"])

st.markdown("---")

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs(["🚨 Live Anomaly Feed", "📊 Model Visualization",
                                    "🧠 AI Threat Briefs", "📈 Performance Metrics"])

# ===== TAB 1: Live Anomaly Feed =====
with tab1:
    st.markdown("#### 🚨 Recent Anomaly Detections")

    # Simulate new session
    if st.button("▶️ Run New Session Through Engine", key="anomaly_sim"):
        result = data_simulator.generate_live_session()
        st.toast(f"Session scored: {result['session']['user_id']} — "
                 f"Score: {result['score']:.1f} ({result['risk_level']})")
        st.rerun()

    # Get recent behaviours
    behaviours = mongo_client.find("behaviours", sort=[("timestamp", -1)], limit=100)

    if behaviours:
        behaviour_data = []
        for b in behaviours:
            score = b.get("isolation_score", 0)
            if score <= 40:
                level = "🟢 GREEN"
            elif score <= 70:
                level = "🟡 AMBER"
            else:
                level = "🔴 RED"

            fv = b.get("feature_vector", {})
            ts = b.get("timestamp", "")
            if isinstance(ts, datetime.datetime):
                ts_str = ts.strftime("%Y-%m-%d %H:%M")
            else:
                ts_str = str(ts)

            behaviour_data.append({
                "User": b.get("user_id", ""),
                "Score": score,
                "Risk": level,
                "Hour": fv.get("hour_of_login", ""),
                "Cmds/Min": fv.get("commands_per_min", ""),
                "Data MB": fv.get("data_exported_mb", ""),
                "Auth Fails": fv.get("failed_auth_attempts", ""),
                "IP Change": "⚠️" if fv.get("ip_change_flag") else "✅",
                "Role Esc.": "⚠️" if fv.get("role_escalation_flag") else "✅",
                "Timestamp": ts_str,
            })

        df = pd.DataFrame(behaviour_data)
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Score": st.column_config.ProgressColumn(
                    "Score", min_value=0, max_value=100, format="%.1f"
                ),
            },
        )

# ===== TAB 2: Model Visualization =====
with tab2:
    st.markdown("#### 📊 Anomaly Score Distribution")

    behaviours_all = mongo_client.find("behaviours", limit=500)

    if behaviours_all:
        scores = [b.get("isolation_score", 0) for b in behaviours_all]

        fig_hist = go.Figure()
        fig_hist.add_trace(go.Histogram(
            x=scores,
            nbinsx=30,
            marker=dict(
                color=[
                    '#00C896' if s <= 40 else '#FFB84D' if s <= 70 else '#FF4C4C'
                    for s in scores
                ],
                line=dict(color='#1E3055', width=1),
            ),
            opacity=0.85,
            hovertemplate="Score Range: %{x}<br>Count: %{y}<extra></extra>",
        ))

        # Add threshold lines
        fig_hist.add_vline(x=40, line_dash="dash", line_color="#00C896",
                           annotation_text="GREEN/AMBER", annotation_font_color="#00C896")
        fig_hist.add_vline(x=70, line_dash="dash", line_color="#FF4C4C",
                           annotation_text="AMBER/RED", annotation_font_color="#FF4C4C")

        fig_hist.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            height=350,
            margin=dict(t=40, b=40, l=40, r=20),
            xaxis=dict(title="Anomaly Score", gridcolor='#E2E8F0',
                       tickfont=dict(color='#64748B', family='JetBrains Mono'),
                       title_font=dict(color='#64748B', family='Inter')),
            yaxis=dict(title="Count", gridcolor='#E2E8F0',
                       tickfont=dict(color='#64748B', family='JetBrains Mono'),
                       title_font=dict(color='#64748B', family='Inter')),
            showlegend=False,
        )
        st.plotly_chart(fig_hist, use_container_width=True)

    # Feature importance scatter
    st.markdown("#### 🎯 Feature Space Visualization")

    if behaviours_all:
        feature_data = []
        for b in behaviours_all:
            fv = b.get("feature_vector", {})
            feature_data.append({
                "hour_of_login": fv.get("hour_of_login", 12),
                "data_exported_mb": fv.get("data_exported_mb", 0),
                "commands_per_min": fv.get("commands_per_min", 0),
                "anomaly_score": b.get("isolation_score", 0),
                "user": b.get("user_id", ""),
            })

        fdf = pd.DataFrame(feature_data)

        fig_scatter = px.scatter(
            fdf,
            x="hour_of_login",
            y="data_exported_mb",
            size="commands_per_min",
            color="anomaly_score",
            color_continuous_scale=["#10B981", "#F59E0B", "#EF4444"],
            range_color=[0, 100],
            hover_data=["user", "commands_per_min", "anomaly_score"],
            labels={
                "hour_of_login": "Login Hour",
                "data_exported_mb": "Data Exported (MB)",
                "anomaly_score": "Anomaly Score",
            },
        )

        fig_scatter.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            height=400,
            margin=dict(t=20, b=40, l=40, r=20),
            xaxis=dict(gridcolor='#E2E8F0',
                       tickfont=dict(color='#64748B', family='JetBrains Mono'),
                       title_font=dict(color='#64748B', family='Inter')),
            yaxis=dict(gridcolor='#E2E8F0',
                       tickfont=dict(color='#64748B', family='JetBrains Mono'),
                       title_font=dict(color='#64748B', family='Inter')),
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

# ===== TAB 3: AI Threat Briefs =====
with tab3:
    st.markdown("#### 🧠 AI-Generated Threat Narratives")

    alerts = mongo_client.find("alerts", sort=[("timestamp", -1)], limit=20)

    if alerts:
        for i, alert in enumerate(alerts[:10]):
            score = alert.get("risk_score", 0)
            if score <= 40:
                badge_class = "risk-badge-green"
                border_color = "#00C896"
            elif score <= 70:
                badge_class = "risk-badge-amber"
                border_color = "#FFB84D"
            else:
                badge_class = "risk-badge-red"
                border_color = "#FF4C4C"

            ts = alert.get("timestamp", "")
            if isinstance(ts, datetime.datetime):
                ts_str = ts.strftime("%Y-%m-%d %H:%M")
            else:
                ts_str = str(ts)

            narrative = alert.get("groq_narrative", "No narrative available.")

            st.markdown(f"""
                <div style="background: linear-gradient(135deg, #F0F7FF 0%, #F1F5F9 100%);
                            border: 1px solid #BEE3F8; border-left: 4px solid {border_color};
                            border-radius: 12px; padding: 20px; margin: 12px 0;
                            box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
                    <div style="display: flex; justify-content: space-between;
                                align-items: center; margin-bottom: 12px;">
                        <div>
                            <span style="font-weight: 700; color: #1E293B; font-size: 1rem;">
                                🚨 {alert.get('alert_type', 'Unknown').replace('_', ' ').title()}
                            </span>
                            <span style="margin-left: 12px;" class="{badge_class}">
                                Score: {score:.1f}
                            </span>
                        </div>
                        <span style="color: #64748B; font-size: 0.8rem;
                                    font-family: 'JetBrains Mono', monospace;">
                            {ts_str}
                        </span>
                    </div>
                    <div style="color: #64748B; font-size: 0.85rem; margin-bottom: 8px;">
                        👤 <strong>{alert.get('user_id', 'Unknown')}</strong> |
                        Resolved: {'✅' if alert.get('resolved') else '❌ Pending'}
                    </div>
                    <div style="color: #334155; font-size: 0.9rem; line-height: 1.7;
                                background: rgba(255,255,255,0.7); border-radius: 8px; padding: 12px;
                                border: 1px solid #E2E8F0;">
                        🤖 <strong>AI Threat Brief:</strong><br>{narrative}
                    </div>
                </div>
            """, unsafe_allow_html=True)

        # Generate new AI brief
        st.markdown("---")
        st.markdown("##### 🧠 Generate Fresh AI Analysis")
        selected_alert = st.selectbox(
            "Select an alert for AI analysis",
            options=range(len(alerts[:10])),
            format_func=lambda i: f"{alerts[i].get('user_id', '')} — "
                                  f"{alerts[i].get('alert_type', '')} "
                                  f"(Score: {alerts[i].get('risk_score', 0):.1f})",
        )

        if st.button("🤖 Generate AI Threat Brief", key="gen_brief"):
            alert = alerts[selected_alert]
            user_info = mongo_client.find_one("users", {"username": alert.get("user_id")})
            role = user_info.get("role", "UNKNOWN") if user_info else "UNKNOWN"

            behaviour = {
                "alert_type": alert.get("alert_type"),
                "risk_score": alert.get("risk_score"),
                "timestamp": str(alert.get("timestamp")),
                "resolved": alert.get("resolved"),
            }

            with st.spinner("🤖 Generating AI threat narrative..."):
                narrative = groq_client.generate_threat_narrative(
                    alert.get("user_id", "Unknown"), role,
                    alert.get("risk_score", 0), behaviour
                )

            st.markdown(f"""
                <div class="ai-insight-card">
                    <div style="font-weight: 700; color: #0066CC; margin-bottom: 12px;">
                        🤖 Fresh AI Threat Brief
                    </div>
                    <div style="color: #334155; line-height: 1.7;">{narrative}</div>
                </div>
            """, unsafe_allow_html=True)

# ===== TAB 4: Performance Metrics =====
with tab4:
    st.markdown("#### 📈 Model Performance Metrics")

    behaviours_perf = mongo_client.find("behaviours", limit=500)

    if behaviours_perf:
        scores = [b.get("isolation_score", 0) for b in behaviours_perf]

        n_green = len([s for s in scores if s <= 40])
        n_amber = len([s for s in scores if 40 < s <= 70])
        n_red = len([s for s in scores if s > 70])
        total = len(scores)

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("🟢 Normal (GREEN)", f"{n_green} ({round(n_green/max(1,total)*100,1)}%)")
        with col2:
            st.metric("🟡 Suspicious (AMBER)", f"{n_amber} ({round(n_amber/max(1,total)*100,1)}%)")
        with col3:
            st.metric("🔴 Critical (RED)", f"{n_red} ({round(n_red/max(1,total)*100,1)}%)")
        with col4:
            st.metric("📊 Total Scored", total)

        # Risk distribution pie chart
        fig_pie = go.Figure(data=[go.Pie(
            labels=["GREEN (Normal)", "AMBER (Suspicious)", "RED (Critical)"],
            values=[n_green, n_amber, n_red],
            marker=dict(colors=["#00C896", "#FFB84D", "#FF4C4C"]),
            hole=0.5,
            textinfo="percent+label",
            textfont=dict(color='#1E293B', family='Inter', size=12),
            hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
        )])

        fig_pie.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            height=350,
            margin=dict(t=20, b=20, l=20, r=20),
            showlegend=False,
            annotations=[dict(
                text=f"<b>{total}</b><br>Sessions",
                x=0.5, y=0.5, font_size=16,
                font=dict(color='#00D4FF', family='Inter'),
                showarrow=False,
            )],
        )
        st.plotly_chart(fig_pie, use_container_width=True)

        # Model info table
        st.markdown("##### ⚙️ Model Configuration")
        model_info = {
            "Parameter": [
                "Batch Model", "Estimators", "Contamination",
                "Online Model", "Trees", "Window Size",
                "Features",
            ],
            "Value": [
                "Isolation Forest (scikit-learn)", "150", "15%",
                "HalfSpaceTrees (River)", "15", "100",
                ", ".join(anomaly_engine.get_feature_names()),
            ],
        }
        st.dataframe(pd.DataFrame(model_info), use_container_width=True, hide_index=True)
