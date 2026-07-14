"""
SentinelIQ — Page 4: Risk-Based Access Control (RBAC+) Engine
==============================================================
- Dynamic privilege scoring with step-up auth
- Role hierarchy visualization
- Step-Up Auth OTP simulation
- Access decision log with AI rationale
"""

import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import datetime
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utils import mongo_client, groq_client, rbac_engine, data_simulator

st.set_page_config(page_title="SentinelIQ — Access Control", page_icon="🛡️", layout="wide")

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
        <span style="font-size: 2rem;">🛡️</span>
        <div>
            <div style="font-weight: 800; font-size: 1.6rem; color: #1E293B;">
                Risk-Based Access Control (RBAC+)
            </div>
            <div style="color: #64748B; font-size: 0.85rem;">
                Dynamic privilege scoring with step-up authentication and auto-suspension
            </div>
        </div>
    </div>
""", unsafe_allow_html=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# Threshold Indicators
# ---------------------------------------------------------------------------
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("🟢 Normal Access", "Score ≤ 40")
with col2:
    st.metric("🟡 Enhanced Monitoring", "Score 41-70")
with col3:
    st.metric("🟠 Step-Up Auth", f"Score > {rbac_engine.STEP_UP_THRESHOLD}")
with col4:
    st.metric("🔴 Auto-Suspend", f"Score > {rbac_engine.SUSPEND_THRESHOLD}")

st.markdown("---")

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs(["🛡️ Access Simulator", "👥 Role Hierarchy",
                                    "📋 Decision Log", "🤖 AI Insight"])

# ===== TAB 1: Access Simulator =====
with tab1:
    st.markdown("#### 🛡️ Simulate Access Request")

    users = mongo_client.find("users")
    user_options = {u.get("username"): u for u in users}

    col1, col2 = st.columns(2)
    with col1:
        selected_user = st.selectbox("Select User", list(user_options.keys()), key="rbac_user")
        user_info = user_options.get(selected_user, {})
        role = user_info.get("role", "UNKNOWN")
        st.markdown(f"""
            <div style="background: #F1F5F9; border: 1px solid #E2E8F0;
                        border-radius: 8px; padding: 12px; margin: 8px 0;">
                <span style="color: #64748B;">Role:</span>
                <span style="color: {rbac_engine.get_role_color(role)};
                            font-weight: 700;">{role}</span>
                <br>
                <span style="color: #64748B;">Department:</span>
                <span style="color: #1E293B;">{user_info.get('department', '')}</span>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        permissions = rbac_engine.get_role_permissions(role)
        all_perms = list(set(p for perms in rbac_engine.ROLE_PERMISSIONS.values() for p in perms))
        selected_action = st.selectbox("Requested Action", sorted(all_perms), key="rbac_action")

        risk_score = st.slider("Simulated Risk Score", 0, 100,
                               int(user_info.get("risk_score", 30)), key="rbac_risk")

    if st.button("🔒 Evaluate Access Request", key="eval_access", use_container_width=True):
        with st.spinner("⚡ Evaluating access..."):
            decision = rbac_engine.evaluate_access(selected_user, role, risk_score, selected_action)

        # Display decision
        if decision["decision"] == "ALLOW":
            st.success(f"✅ **ACCESS GRANTED** — {selected_user} can perform `{selected_action}`")
        elif decision["decision"] == "STEP_UP_REQUIRED":
            st.warning(f"🔐 **STEP-UP AUTHENTICATION REQUIRED** — OTP Challenge issued!")

            # Store OTP in session state
            st.session_state["pending_otp"] = decision["otp_code"]
            st.session_state["pending_decision"] = decision

            st.markdown(f"""
                <div style="background: linear-gradient(135deg, #FFF9E6, #FFFDF5);
                            border: 2px solid #FFB84D; border-radius: 16px;
                            padding: 24px; margin: 16px 0; text-align: center;
                            box-shadow: 0 4px 12px rgba(245,158,11,0.1);">
                    <div style="font-size: 2rem; margin-bottom: 8px;">🔐</div>
                    <div style="font-weight: 700; color: #F59E0B; font-size: 1.2rem;">
                        Step-Up Authentication Challenge
                    </div>
                    <div style="color: #1E293B; margin: 12px 0;">
                        Your OTP code is: <span style="font-family: 'JetBrains Mono';
                        font-size: 2rem; color: #0066CC; letter-spacing: 8px;
                        font-weight: 700;">{decision['otp_code']}</span>
                    </div>
                    <div style="color: #64748B; font-size: 0.85rem;">
                        Enter this code below to verify your identity
                    </div>
                </div>
            """, unsafe_allow_html=True)

        elif decision["decision"] == "DENY":
            if decision["session_suspended"]:
                st.error(f"🚫 **SESSION SUSPENDED** — {selected_user}'s session has been "
                         f"auto-suspended due to critical risk score ({risk_score})")
            else:
                st.error(f"❌ **ACCESS DENIED** — {selected_user} lacks permission for "
                         f"`{selected_action}`")

        # Show rationale
        st.markdown(f"""
            <div class="ai-insight-card">
                <div style="font-weight: 700; color: #0066CC; margin-bottom: 8px;">
                    🤖 AI Decision Rationale
                </div>
                <div style="color: #334155; line-height: 1.7;">
                    {decision.get('ai_rationale', decision.get('rationale', ''))}
                </div>
            </div>
        """, unsafe_allow_html=True)

    # OTP Verification
    if "pending_otp" in st.session_state:
        st.markdown("---")
        st.markdown("##### 🔑 OTP Verification")
        otp_input = st.text_input("Enter OTP Code", max_chars=6, key="otp_input")
        if st.button("✅ Verify OTP", key="verify_otp"):
            if rbac_engine.verify_step_up(otp_input, st.session_state["pending_otp"]):
                st.success("✅ **OTP Verified!** Access granted after step-up authentication.")
                mongo_client.log_audit_event(
                    actor=selected_user,
                    action="STEP_UP_AUTH_SUCCESS",
                    target="system_resource",
                    rbac_decision="ALLOW",
                    rationale="Step-up authentication completed successfully via OTP verification.",
                    event_type="rbac_decision",
                )
                del st.session_state["pending_otp"]
                del st.session_state["pending_decision"]
            else:
                st.error("❌ Invalid OTP. Access remains restricted.")

# ===== TAB 2: Role Hierarchy =====
with tab2:
    st.markdown("#### 👥 Role Hierarchy & Permissions")

    # Role hierarchy visualization
    roles = rbac_engine.get_all_roles()

    fig_hierarchy = go.Figure()

    for i, role in enumerate(roles):
        level = rbac_engine.get_role_level(role)
        color = rbac_engine.get_role_color(role)
        perms = rbac_engine.get_role_permissions(role)

        fig_hierarchy.add_trace(go.Bar(
            x=[level],
            y=[role],
            orientation='h',
            marker=dict(
                color=color,
                line=dict(color='#E2E8F0', width=1),
            ),
            text=f"{role} (Level {level}) — {len(perms)} permissions",
            textposition='inside',
            textfont=dict(color='#FFFFFF', family='Inter', size=13, weight=700),
            hovertemplate=f"<b>{role}</b><br>Level: {level}<br>"
                          f"Permissions: {len(perms)}<extra></extra>",
            showlegend=False,
        ))

    fig_hierarchy.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=300,
        margin=dict(t=20, b=20, l=120, r=20),
        xaxis=dict(title="Privilege Level", gridcolor='#E2E8F0',
                   tickfont=dict(color='#64748B', family='JetBrains Mono'),
                   title_font=dict(color='#64748B', family='Inter')),
        yaxis=dict(tickfont=dict(color='#1E293B', family='Inter', size=12)),
        barmode='stack',
    )
    st.plotly_chart(fig_hierarchy, use_container_width=True)

    # Permissions matrix
    st.markdown("##### 🔒 Permission Matrix")
    all_perms = sorted(set(p for perms in rbac_engine.ROLE_PERMISSIONS.values() for p in perms))

    matrix_data = []
    for perm in all_perms:
        row = {"Permission": perm}
        for role in roles:
            row[role] = "✅" if rbac_engine.can_role_access(role, perm) else "❌"
        matrix_data.append(row)

    st.dataframe(pd.DataFrame(matrix_data), use_container_width=True, hide_index=True)

# ===== TAB 3: Decision Log =====
with tab3:
    st.markdown("#### 📋 Access Decision Log")

    # Filters
    col1, col2 = st.columns(2)
    with col1:
        filter_decision = st.selectbox("Filter by Decision",
                                       ["All", "ALLOW", "DENY", "STEP_UP_REQUIRED", "SUSPEND"],
                                       key="log_filter_dec")
    with col2:
        filter_user = st.selectbox("Filter by User",
                                   ["All"] + [u.get("username") for u in mongo_client.find("users")],
                                   key="log_filter_user")

    decisions = rbac_engine.get_access_decision_log(limit=200)

    if filter_decision != "All":
        decisions = [d for d in decisions if d.get("rbac_decision") == filter_decision]
    if filter_user != "All":
        decisions = [d for d in decisions if d.get("actor") == filter_user]

    if decisions:
        log_data = []
        for d in decisions[:50]:
            ts = d.get("timestamp", "")
            if isinstance(ts, datetime.datetime):
                ts_str = ts.strftime("%Y-%m-%d %H:%M")
            else:
                ts_str = str(ts)

            dec = d.get("rbac_decision", "")
            dec_icon = {"ALLOW": "✅", "DENY": "❌", "STEP_UP_REQUIRED": "🔐",
                        "SUSPEND": "🚫"}.get(dec, "❔")

            log_data.append({
                "Time": ts_str,
                "Actor": d.get("actor", ""),
                "Action": d.get("action", ""),
                "Target": d.get("target", ""),
                "Decision": f"{dec_icon} {dec}",
                "Rationale": d.get("rationale", "")[:80] + "...",
            })

        st.dataframe(pd.DataFrame(log_data), use_container_width=True, hide_index=True)
    else:
        st.info("📋 No access decisions recorded yet. Use the Access Simulator to generate some.")

# ===== TAB 4: AI Insight =====
with tab4:
    st.markdown("#### 🤖 AI Access Control Insight")

    with st.expander("📡 Generate AI Analysis of RBAC+ Activity", expanded=True):
        if st.button("🧠 Generate RBAC+ Insight", key="rbac_insight"):
            decisions = rbac_engine.get_access_decision_log(limit=50)
            allow_count = len([d for d in decisions if d.get("rbac_decision") == "ALLOW"])
            deny_count = len([d for d in decisions if d.get("rbac_decision") == "DENY"])
            step_up_count = len([d for d in decisions if d.get("rbac_decision") == "STEP_UP_REQUIRED"])

            stats = {
                "total_decisions": len(decisions),
                "allowed": allow_count,
                "denied": deny_count,
                "step_up_required": step_up_count,
                "unique_users": len(set(d.get("actor", "") for d in decisions)),
            }

            with st.spinner("🤖 Analyzing RBAC+ patterns..."):
                insight = groq_client.call_groq(
                    f"You are a banking security compliance officer. Analyze these RBAC+ "
                    f"access control statistics: {stats}. Provide a 3-sentence assessment "
                    f"of the access control health, any concerning patterns, and one "
                    f"recommendation for improving access security."
                )

            st.markdown(f"""
                <div class="ai-insight-card">
                    <div style="font-weight: 700; color: #0066CC; margin-bottom: 12px;">
                        🤖 AI RBAC+ Analysis
                    </div>
                    <div style="color: #334155; line-height: 1.7;">{insight}</div>
                </div>
            """, unsafe_allow_html=True)
