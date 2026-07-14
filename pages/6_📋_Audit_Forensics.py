"""
SentinelIQ — Page 6: Audit Trail & Forensics Timeline
=======================================================
- Full audit trail viewer with chronological timeline
- User selector with full event history
- "Explain This Event" button → Groq forensic narrative
- Filters: date range, risk level, action type, user role
- CSV download
"""

import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import datetime
import io
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utils import mongo_client, groq_client, data_simulator

def px_colors_from_count(n: int) -> list:
    """Generate a list of colors for plotly pie chart."""
    palette = [
        "#0066CC", "#FF4C4C", "#10B981", "#F59E0B", "#9B59B6",
        "#FF8C42", "#3498DB", "#E74C3C", "#2ECC71", "#F39C12",
        "#1ABC9C", "#E67E22", "#8E44AD", "#16A085", "#D35400",
    ]
    return [palette[i % len(palette)] for i in range(n)]

st.set_page_config(page_title="SentinelIQ — Audit Forensics", page_icon="📋", layout="wide")

if not st.session_state.get("authenticated"):
    st.warning("🔒 Please login from the main page.")
    st.stop()

from utils import rbac_engine

if not rbac_engine.check_page_permission(st.session_state.get("role"), "Audit_Forensics"):
    st.error("❌ Access Denied: You do not have permission to view the Audit Forensics logs.")
    st.stop()

if "initialized" not in st.session_state:
    data_simulator.seed_database()
    st.session_state["initialized"] = True

# ---------------------------------------------------------------------------
# Page Header
# ---------------------------------------------------------------------------
st.markdown("""
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
        <span style="font-size: 2rem;">📋</span>
        <div>
            <div style="font-weight: 800; font-size: 1.6rem; color: #1E293B;">
                Audit Trail & Forensics Timeline
            </div>
            <div style="color: #64748B; font-size: 0.85rem;">
                Complete chronological audit trail with AI-powered forensic narratives
            </div>
        </div>
    </div>
""", unsafe_allow_html=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------
st.markdown("### 🔍 Filters")

col1, col2, col3, col4 = st.columns(4)

users = mongo_client.find("users")
user_options = ["All"] + [u.get("username", "") for u in users]

with col1:
    filter_user = st.selectbox("👤 User", user_options, key="audit_user")
with col2:
    filter_action = st.selectbox("📌 Action Type",
                                 ["All", "LOGIN", "LOGOUT", "QUERY_EXECUTE", "DATA_EXPORT",
                                  "ROLE_CHANGE", "PASSWORD_RESET", "PERMISSION_GRANT",
                                  "SYSTEM_CONFIG_CHANGE", "ALERT_ACKNOWLEDGED",
                                  "SESSION_TIMEOUT", "STEP_UP_AUTH", "CREDENTIAL_ROTATION",
                                  "USER_SUSPEND", "USER_REINSTATE", "AUTO_SUSPEND",
                                  "STEP_UP_AUTH_SUCCESS"],
                                 key="audit_action")
with col3:
    filter_event_type = st.selectbox("🏷️ Event Type",
                                     ["All", "rbac_decision", "system", "security",
                                      "audit", "rbac_action"],
                                     key="audit_event_type")
with col4:
    filter_decision = st.selectbox("⚖️ Decision",
                                   ["All", "ALLOW", "DENY", "STEP_UP_REQUIRED", "SUSPEND"],
                                   key="audit_decision")

st.markdown("---")

# ---------------------------------------------------------------------------
# Query Audit Logs
# ---------------------------------------------------------------------------
query = {}
if filter_user != "All":
    query["actor"] = filter_user
if filter_action != "All":
    query["action"] = filter_action
if filter_event_type != "All":
    query["event_type"] = filter_event_type

audit_logs = mongo_client.find("audit_logs", query, sort=[("timestamp", -1)], limit=500)

if filter_decision != "All":
    audit_logs = [a for a in audit_logs if a.get("rbac_decision") == filter_decision]

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab1, tab2, tab3 = st.tabs(["📋 Audit Trail", "📈 Timeline Visualization",
                              "🤖 Forensic Analysis"])

# ===== TAB 1: Audit Trail =====
with tab1:
    st.markdown(f"#### 📋 Audit Trail ({len(audit_logs)} events)")

    if audit_logs:
        log_data = []
        for log in audit_logs:
            ts = log.get("timestamp", "")
            if isinstance(ts, datetime.datetime):
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
            else:
                ts_str = str(ts)

            dec = log.get("rbac_decision", "")
            dec_icon = {"ALLOW": "✅", "DENY": "❌", "STEP_UP_REQUIRED": "🔐",
                        "SUSPEND": "🚫"}.get(dec, "ℹ️")

            action = log.get("action", "")
            action_icon = {
                "LOGIN": "🔑", "LOGOUT": "🚪", "QUERY_EXECUTE": "💾",
                "DATA_EXPORT": "📤", "ROLE_CHANGE": "👤", "PASSWORD_RESET": "🔒",
                "PERMISSION_GRANT": "✅", "SYSTEM_CONFIG_CHANGE": "⚙️",
                "ALERT_ACKNOWLEDGED": "📢", "SESSION_TIMEOUT": "⏰",
                "STEP_UP_AUTH": "🔐", "AUTO_SUSPEND": "🚫",
                "CREDENTIAL_ROTATION": "🔄", "USER_SUSPEND": "⛔",
                "USER_REINSTATE": "♻️", "STEP_UP_AUTH_SUCCESS": "✅",
            }.get(action, "📌")

            log_data.append({
                "Timestamp": ts_str,
                "Actor": log.get("actor", ""),
                "Action": f"{action_icon} {action}",
                "Target": log.get("target", ""),
                "Decision": f"{dec_icon} {dec}" if dec else "—",
                "Event Type": log.get("event_type", ""),
                "Rationale": (log.get("rationale", "")[:100] + "...")
                             if len(log.get("rationale", "")) > 100
                             else log.get("rationale", ""),
            })

        df = pd.DataFrame(log_data)
        st.dataframe(df, use_container_width=True, hide_index=True, height=500)

        # CSV Download
        st.markdown("---")
        csv_data = df.to_csv(index=False)
        st.download_button(
            "📥 Download Audit Trail (CSV)",
            data=csv_data,
            file_name=f"sentineliq_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv",
            use_container_width=True,
        )
    else:
        st.info("📋 No audit events match the current filters.")

# ===== TAB 2: Timeline Visualization =====
with tab2:
    st.markdown("#### 📈 Event Timeline")

    if audit_logs:
        # Group events by date
        date_counts = {}
        action_counts = {}
        for log in audit_logs:
            ts = log.get("timestamp")
            if isinstance(ts, datetime.datetime):
                date_key = ts.strftime("%Y-%m-%d")
                date_counts[date_key] = date_counts.get(date_key, 0) + 1
                action = log.get("action", "OTHER")
                action_counts[action] = action_counts.get(action, 0) + 1

        # Timeline bar chart
        if date_counts:
            dates = sorted(date_counts.keys())
            counts = [date_counts[d] for d in dates]

            fig_timeline = go.Figure()
            fig_timeline.add_trace(go.Bar(
                x=dates,
                y=counts,
                marker=dict(
                    color='#0066CC',
                    line=dict(color='#E2E8F0', width=1),
                ),
                text=counts,
                textposition='outside',
                textfont=dict(color='#1E293B', family='JetBrains Mono'),
                hovertemplate="<b>%{x}</b><br>Events: %{y}<extra></extra>",
            ))

            fig_timeline.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                height=300,
                margin=dict(t=30, b=40, l=40, r=20),
                xaxis=dict(title="Date", gridcolor='#E2E8F0',
                           tickfont=dict(color='#64748B', family='JetBrains Mono'),
                           title_font=dict(color='#64748B', family='Inter')),
                yaxis=dict(title="Events", gridcolor='#E2E8F0',
                           tickfont=dict(color='#64748B', family='JetBrains Mono'),
                           title_font=dict(color='#64748B', family='Inter')),
            )
            st.plotly_chart(fig_timeline, use_container_width=True)

        # Action type distribution
        if action_counts:
            st.markdown("##### 📊 Event Type Distribution")
            sorted_actions = sorted(action_counts.items(), key=lambda x: x[1], reverse=True)
            labels = [a[0] for a in sorted_actions]
            values = [a[1] for a in sorted_actions]

            fig_pie = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                hole=0.4,
                marker=dict(colors=px_colors_from_count(len(labels))),
                textinfo="percent+label",
                textfont=dict(color='#1E293B', family='Inter', size=10),
                hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
            )])
            fig_pie.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                height=400,
                margin=dict(t=20, b=20, l=20, r=20),
                showlegend=True,
                legend=dict(font=dict(color='#8B9DC3', family='Inter', size=10)),
            )
            st.plotly_chart(fig_pie, use_container_width=True)

# ===== TAB 3: Forensic Analysis =====
with tab3:
    st.markdown("#### 🤖 AI Forensic Event Analysis")
    st.markdown("Select an audit event and generate an AI-powered forensic narrative.")

    if audit_logs:
        event_options = []
        for i, log in enumerate(audit_logs[:30]):
            ts = log.get("timestamp", "")
            if isinstance(ts, datetime.datetime):
                ts_str = ts.strftime("%m-%d %H:%M")
            else:
                ts_str = str(ts)[:16]
            event_options.append(
                f"[{ts_str}] {log.get('actor', '')} → {log.get('action', '')} → "
                f"{log.get('target', '')}"
            )

        selected_idx = st.selectbox("Select Event", range(len(event_options)),
                                    format_func=lambda i: event_options[i],
                                    key="forensic_event")

        selected_event = audit_logs[selected_idx]

        # Show event details
        ts = selected_event.get("timestamp", "")
        if isinstance(ts, datetime.datetime):
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
        else:
            ts_str = str(ts)

        st.markdown(f"""
            <div style="background: #162040; border: 1px solid #1E3055;
                        border-radius: 12px; padding: 20px; margin: 12px 0;">
                <div style="font-weight: 700; color: #00D4FF; margin-bottom: 12px;">
                    📌 Event Details
                </div>
                <div style="color: #8B9DC3; font-size: 0.9rem; line-height: 2;
                            font-family: 'JetBrains Mono', monospace;">
                    Timestamp: {ts_str}<br>
                    Actor: {selected_event.get('actor', '')}<br>
                    Action: {selected_event.get('action', '')}<br>
                    Target: {selected_event.get('target', '')}<br>
                    Decision: {selected_event.get('rbac_decision', 'N/A')}<br>
                    Event Type: {selected_event.get('event_type', '')}<br>
                    Rationale: {selected_event.get('rationale', 'N/A')}
                </div>
            </div>
        """, unsafe_allow_html=True)

        if st.button("🧠 Explain This Event", key="explain_event", use_container_width=True):
            event_data = {
                "timestamp": ts_str,
                "actor": selected_event.get("actor", ""),
                "action": selected_event.get("action", ""),
                "target": selected_event.get("target", ""),
                "rbac_decision": selected_event.get("rbac_decision", ""),
                "event_type": selected_event.get("event_type", ""),
                "rationale": selected_event.get("rationale", ""),
            }

            with st.spinner("🤖 Generating forensic narrative..."):
                narrative = groq_client.generate_forensic_narrative(event_data)

            st.markdown(f"""
                <div class="ai-insight-card">
                    <div style="font-weight: 700; color: #00D4FF; margin-bottom: 12px;">
                        🤖 AI Forensic Narrative
                    </div>
                    <div style="color: #C0CBDF; line-height: 1.7; font-size: 0.95rem;">
                        {narrative}
                    </div>
                    <div style="color: #4A5E80; font-size: 0.75rem; margin-top: 12px;
                                font-family: 'JetBrains Mono', monospace;">
                        Model: llama-3.3-70b-versatile |
                        Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                    </div>
                </div>
            """, unsafe_allow_html=True)
