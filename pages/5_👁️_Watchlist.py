"""
SentinelIQ — Page 5: Insider Threat Scoring Leaderboard
========================================================
- Rank privileged users by cumulative risk over 30 days
- Watchlist: top 5 highest-risk users with AI summaries
- Trend sparklines per user
- Export watchlist as PDF-ready HTML table
"""

import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import datetime
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utils import mongo_client, groq_client, data_simulator

st.set_page_config(page_title="SentinelIQ — Watchlist", page_icon="👁️", layout="wide")

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
        <span style="font-size: 2rem;">👁️</span>
        <div>
            <div style="font-weight: 800; font-size: 1.6rem; color: #1E293B;">
                Insider Threat Scoring Leaderboard
            </div>
            <div style="color: #64748B; font-size: 0.85rem;">
                Rolling 30-day cumulative risk ranking for all privileged users
            </div>
        </div>
    </div>
""", unsafe_allow_html=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# Get Risk Data
# ---------------------------------------------------------------------------
risk_scores = mongo_client.get_rolling_risk_scores(days=30)
users = mongo_client.find("users")
user_map = {u.get("username"): u for u in users}

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab1, tab2, tab3 = st.tabs(["🏆 Risk Leaderboard", "👁️ Watchlist (Top 5)", "📤 Export"])

# ===== TAB 1: Risk Leaderboard =====
with tab1:
    st.markdown("#### 🏆 30-Day Cumulative Risk Ranking")

    if risk_scores:
        leaderboard_data = []
        for i, rs in enumerate(risk_scores):
            username = rs.get("_id", "unknown")
            user = user_map.get(username, {})
            total = rs.get("total_risk", 0)
            avg = rs.get("avg_risk", 0)
            max_r = rs.get("max_risk", 0)
            count = rs.get("session_count", 0)

            # Risk tier
            if avg > 70:
                tier = "🔴 CRITICAL"
                tier_color = "#FF4C4C"
            elif avg > 40:
                tier = "🟡 ELEVATED"
                tier_color = "#FFB84D"
            else:
                tier = "🟢 NORMAL"
                tier_color = "#00C896"

            percentile = mongo_client.get_user_risk_percentile(username)

            leaderboard_data.append({
                "Rank": i + 1,
                "User": username,
                "Role": user.get("role", "UNKNOWN"),
                "Department": user.get("department", ""),
                "Total Risk": round(total, 1),
                "Avg Risk": round(avg, 1),
                "Peak Risk": round(max_r, 1),
                "Sessions": count,
                "Risk Tier": tier,
                "Percentile": f"Top {percentile:.0f}%",
            })

        df = pd.DataFrame(leaderboard_data)
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Avg Risk": st.column_config.ProgressColumn(
                    "Avg Risk", min_value=0, max_value=100, format="%.1f"
                ),
                "Peak Risk": st.column_config.ProgressColumn(
                    "Peak Risk", min_value=0, max_value=100, format="%.1f"
                ),
            },
        )

        # Leaderboard bar chart
        st.markdown("##### 📊 Risk Score Comparison")
        fig_bar = go.Figure()

        usernames = [d["User"] for d in leaderboard_data]
        avg_risks = [d["Avg Risk"] for d in leaderboard_data]
        colors = ['#FF4C4C' if r > 70 else '#FFB84D' if r > 40 else '#00C896' for r in avg_risks]

        fig_bar.add_trace(go.Bar(
            x=usernames,
            y=avg_risks,
            marker=dict(color=colors, line=dict(color='#E2E8F0', width=1)),
            text=[f"{r:.1f}" for r in avg_risks],
            textposition='outside',
            textfont=dict(color='#1E293B', family='JetBrains Mono', size=11),
            hovertemplate="<b>%{x}</b><br>Avg Risk: %{y:.1f}<extra></extra>",
        ))

        fig_bar.add_hline(y=70, line_dash="dash", line_color="#FF4C4C",
                          annotation_text="Critical Threshold")
        fig_bar.add_hline(y=40, line_dash="dash", line_color="#FFB84D",
                          annotation_text="Elevated Threshold")

        fig_bar.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            height=350,
            margin=dict(t=40, b=40, l=40, r=20),
            xaxis=dict(gridcolor='#E2E8F0', tickangle=-45,
                       tickfont=dict(color='#64748B', family='Inter', size=10),
                       title_font=dict(color='#64748B', family='Inter')),
            yaxis=dict(title="Average Risk Score", gridcolor='#E2E8F0',
                       tickfont=dict(color='#64748B', family='JetBrains Mono'),
                       title_font=dict(color='#64748B', family='Inter')),
            showlegend=False,
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    else:
        st.info("📊 No risk data available yet.")

# ===== TAB 2: Watchlist (Top 5) =====
with tab2:
    st.markdown("#### 👁️ High-Risk Watchlist — Top 5 Users")

    if risk_scores:
        top_5 = risk_scores[:5]

        for i, rs in enumerate(top_5):
            username = rs.get("_id", "unknown")
            user = user_map.get(username, {})
            avg = rs.get("avg_risk", 0)
            total = rs.get("total_risk", 0)
            max_r = rs.get("max_risk", 0)

            if avg > 70:
                border_color = "#FF4C4C"
                badge_class = "risk-badge-red"
            elif avg > 40:
                border_color = "#FFB84D"
                badge_class = "risk-badge-amber"
            else:
                border_color = "#00C896"
                badge_class = "risk-badge-green"

            # Get user's recent scores for sparkline
            user_behaviours = mongo_client.find(
                "behaviours",
                {"user_id": username},
                sort=[("timestamp", -1)],
                limit=30,
            )
            sparkline_scores = [b.get("isolation_score", 0) for b in reversed(user_behaviours)]

            col1, col2 = st.columns([2, 1])
            with col1:
                st.markdown(f"""
                    <div style="background: linear-gradient(135deg, #F0F7FF, #F1F5F9);
                                border: 1px solid #BEE3F8; border-left: 4px solid {border_color};
                                border-radius: 12px; padding: 20px; margin: 8px 0;
                                box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
                        <div style="display: flex; justify-content: space-between;
                                    align-items: center; margin-bottom: 12px;">
                            <div>
                                <span style="font-weight: 700; color: #1E293B; font-size: 1.1rem;">
                                    #{i+1} — {username}
                                </span>
                                <span style="margin-left: 12px; background: {border_color};
                                            color: #FFFFFF;
                                            padding: 2px 10px; border-radius: 12px;
                                            font-size: 0.75rem; font-weight: 700;
                                            font-family: 'JetBrains Mono', monospace;">
                                    {user.get('role', 'UNKNOWN')}
                                </span>
                            </div>
                        </div>
                        <div style="color: #64748B; font-size: 0.85rem; line-height: 1.8;">
                            📊 Avg Risk: <strong style="color: {border_color};">{avg:.1f}</strong> |
                            🔺 Peak: <strong>{max_r:.1f}</strong> |
                            Σ Total: <strong>{total:.0f}</strong> |
                            📍 {user.get('department', 'N/A')}
                        </div>
                    </div>
                """, unsafe_allow_html=True)

            with col2:
                # Sparkline chart
                if sparkline_scores:
                    fig_spark = go.Figure()
                    fig_spark.add_trace(go.Scatter(
                        y=sparkline_scores,
                        mode='lines',
                        line=dict(color=border_color, width=2),
                        fill='tozeroy',
                        fillcolor=f"rgba({int(border_color[1:3],16)},{int(border_color[3:5],16)},{int(border_color[5:7],16)},0.1)",
                        hovertemplate="Score: %{y:.1f}<extra></extra>",
                    ))
                    fig_spark.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        height=80,
                        margin=dict(t=5, b=5, l=5, r=5),
                        xaxis=dict(visible=False),
                        yaxis=dict(visible=False, range=[0, 100]),
                        showlegend=False,
                    )
                    st.plotly_chart(fig_spark, use_container_width=True,
                                   key=f"spark_{username}")

            # AI Risk Summary
            with st.expander(f"🤖 AI Risk Summary for {username}", expanded=False):
                if st.button(f"Generate AI Summary", key=f"ai_summary_{username}"):
                    risk_data = {
                        "avg_risk": round(avg, 1),
                        "max_risk": round(max_r, 1),
                        "total_risk": round(total, 1),
                        "sessions": rs.get("session_count", 0),
                        "department": user.get("department", ""),
                    }
                    with st.spinner("🤖 Generating risk summary..."):
                        summary = groq_client.generate_risk_summary(
                            username, user.get("role", "UNKNOWN"), risk_data
                        )
                    st.markdown(f"""
                        <div class="ai-insight-card">
                            <div style="color: #334155; line-height: 1.7;">{summary}</div>
                        </div>
                    """, unsafe_allow_html=True)

# ===== TAB 3: Export =====
with tab3:
    st.markdown("#### 📤 Export Watchlist")

    if risk_scores:
        # Generate HTML table
        html_rows = ""
        for i, rs in enumerate(risk_scores):
            username = rs.get("_id", "unknown")
            user = user_map.get(username, {})
            avg = rs.get("avg_risk", 0)

            if avg > 70:
                row_color = "#FFCCCC"
            elif avg > 40:
                row_color = "#FFF3CD"
            else:
                row_color = "#D4EDDA"

            html_rows += f"""
                <tr style="background: {row_color};">
                    <td style="padding: 8px; border: 1px solid #ddd;">{i+1}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{username}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{user.get('role', '')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{user.get('department', '')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{avg:.1f}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{rs.get('max_risk', 0):.1f}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{rs.get('total_risk', 0):.0f}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{rs.get('session_count', 0)}</td>
                </tr>
            """

        html_table = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Inter', Arial, sans-serif; padding: 20px; }}
                h1 {{ color: #0A1628; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th {{ background: #0A1628; color: white; padding: 10px; border: 1px solid #ddd;
                      text-align: left; }}
            </style>
        </head>
        <body>
            <h1>🛡️ SentinelIQ — Insider Threat Watchlist Report</h1>
            <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Bank of Maharashtra — Privileged Access Monitoring</p>
            <table>
                <thead>
                    <tr>
                        <th>Rank</th><th>User</th><th>Role</th><th>Department</th>
                        <th>Avg Risk</th><th>Peak Risk</th><th>Total Risk</th><th>Sessions</th>
                    </tr>
                </thead>
                <tbody>{html_rows}</tbody>
            </table>
            <p style="color: #666; margin-top: 20px; font-size: 0.8rem;">
                Report generated by SentinelIQ v1.0 | Finspark Hackathon 2026
            </p>
        </body>
        </html>
        """

        st.download_button(
            "📄 Download Watchlist (HTML)",
            data=html_table,
            file_name=f"sentineliq_watchlist_{datetime.datetime.now().strftime('%Y%m%d')}.html",
            mime="text/html",
            use_container_width=True,
        )

        st.markdown("##### 📋 Preview")
        st.components.v1.html(html_table, height=400, scrolling=True)
