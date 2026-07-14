"""
SentinelIQ — Page 7: Quantum Risk Monitor
============================================
- HNDL (Harvest-Now-Decrypt-Later) threat detection
- Simulated detection of large data exfiltration events
- Groq AI explains each HNDL indicator
- PQC migration readiness checklist
"""

import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import datetime
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utils import mongo_client, groq_client, pqc_vault, data_simulator

st.set_page_config(page_title="SentinelIQ — Quantum Monitor", page_icon="⚛️", layout="wide")

if not st.session_state.get("authenticated"):
    st.warning("🔒 Please login from the main page.")
    st.stop()

from utils import rbac_engine

if not rbac_engine.check_page_permission(st.session_state.get("role"), "Quantum_Monitor"):
    st.error("❌ Access Denied: You do not have permission to view the Quantum Monitor.")
    st.stop()

if "initialized" not in st.session_state:
    data_simulator.seed_database()
    st.session_state["initialized"] = True

# ---------------------------------------------------------------------------
# Page Header
# ---------------------------------------------------------------------------
st.markdown("""
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
        <span style="font-size: 2rem;">⚛️</span>
        <div>
            <div style="font-weight: 800; font-size: 1.6rem; color: #1E293B;">
                Quantum Risk Monitor
            </div>
            <div style="color: #64748B; font-size: 0.85rem;">
                Harvest-Now-Decrypt-Later threat detection & PQC migration readiness
            </div>
        </div>
    </div>
""", unsafe_allow_html=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# Quantum Threat Overview
# ---------------------------------------------------------------------------
st.markdown("""
    <div class="ai-insight-card">
        <div style="font-weight: 700; color: #0066CC; margin-bottom: 8px; font-size: 1.05rem;">
            ⚛️ What is Harvest-Now-Decrypt-Later (HNDL)?
        </div>
        <div style="color: #334155; font-size: 0.9rem; line-height: 1.7;">
            HNDL is a quantum computing threat where adversaries <strong>exfiltrate encrypted
            data today</strong>, intending to decrypt it once quantum computers become powerful
            enough. For banks, this means customer financial data, credentials, and transaction
            histories could be at risk even if current encryption appears secure. SentinelIQ
            monitors for data exfiltration patterns consistent with HNDL attack signatures.
        </div>
    </div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab1, tab2, tab3 = st.tabs(["🚨 HNDL Threat Detector", "✅ PQC Migration Checklist",
                              "📊 Quantum Dashboard"])

# ===== TAB 1: HNDL Threat Detector =====
with tab1:
    st.markdown("#### 🚨 Harvest-Now-Decrypt-Later (HNDL) Threat Indicators")

    # Generate HNDL events on button click or show stored ones
    if "hndl_events" not in st.session_state:
        st.session_state["hndl_events"] = [data_simulator.generate_hndl_event() for _ in range(5)]

    col_refresh, col_sim = st.columns([3, 1])
    with col_sim:
        if st.button("🔄 Detect New HNDL Event"):
            new_event = data_simulator.generate_hndl_event()
            st.session_state["hndl_events"].insert(0, new_event)
            st.toast(f"⚠️ New HNDL indicator detected: {new_event['user_id']}")
            st.rerun()

    # Display HNDL events
    for i, event in enumerate(st.session_state["hndl_events"][:10]):
        threat_level = event.get("threat_level", "HIGH")
        border_color = "#FF4C4C" if threat_level == "CRITICAL" else "#FFB84D"

        ts = event.get("timestamp", datetime.datetime.now(datetime.timezone.utc))
        if isinstance(ts, datetime.datetime):
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
        else:
            ts_str = str(ts)

        indicators = event.get("hndl_indicators", {})

        st.markdown(f"""
            <div style="background: linear-gradient(135deg, {'#FFF5F5' if threat_level == 'CRITICAL' else '#FFFDF5'}, #FFFFFF);
                        border: 1px solid {border_color}; border-left: 4px solid {border_color};
                        border-radius: 12px; padding: 20px; margin: 12px 0;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
                <div style="display: flex; justify-content: space-between;
                            align-items: center; margin-bottom: 12px;">
                    <div>
                        <span style="font-weight: 700; color: #1E293B; font-size: 1.05rem;">
                            {'🔴' if threat_level == 'CRITICAL' else '🟠'} HNDL Indicator #{i+1}
                        </span>
                        <span style="background: {border_color};
                                    color: {'#FFF' if threat_level == 'CRITICAL' else '#0A1628'};
                                    padding: 2px 10px; border-radius: 12px;
                                    font-size: 0.75rem; font-weight: 700;
                                    margin-left: 10px; font-family: 'JetBrains Mono', monospace;">
                            {threat_level}
                        </span>
                    </div>
                    <span style="color: #64748B; font-size: 0.8rem;
                                font-family: 'JetBrains Mono', monospace;">
                        {ts_str}
                    </span>
                </div>
                <div style="color: #475569; font-size: 0.85rem; line-height: 1.9;">
                    👤 <strong>User:</strong> {event.get('user_id', '')}
                    ({event.get('role', '')}) |
                    📦 <strong>Volume:</strong> {event.get('data_volume_gb', 0)} GB |
                    🌐 <strong>Dest IP:</strong> {event.get('destination_ip', '')} |
                    📍 <strong>Dest Geo:</strong> {event.get('destination_geo', '')}
                    <br>
                    🔒 <strong>Encrypted:</strong> {'Yes ✅' if event.get('encryption_detected') else 'No'} |
                    📁 <strong>Format:</strong> {event.get('blob_format', '')} |
                    📡 <strong>Protocol:</strong> {event.get('protocol', '')} |
                    ⏱️ <strong>Duration:</strong> {event.get('duration_minutes', 0)} min
                    <br>
                    <strong>HNDL Indicators:</strong>
                    Large Transfer: {'✅' if indicators.get('large_encrypted_transfer') else '❌'} |
                    Unknown Dest: {'✅' if indicators.get('unknown_destination') else '❌'} |
                    Off-Hours: {'✅' if indicators.get('off_hours') else '❌'} |
                    Bulk DB: {'✅' if indicators.get('bulk_database_access') else '❌'} |
                    Pattern Match: {indicators.get('pattern_match_score', 0):.0%}
                </div>
            </div>
        """, unsafe_allow_html=True)

        # AI Analysis expander
        with st.expander(f"🤖 AI Analysis — HNDL Event #{i+1}", expanded=False):
            if st.button(f"Analyze with AI", key=f"hndl_ai_{i}"):
                with st.spinner("🤖 Analyzing HNDL threat..."):
                    analysis = groq_client.generate_hndl_analysis(event)

                st.markdown(f"""
                    <div class="ai-insight-card">
                        <div style="font-weight: 700; color: #0066CC; margin-bottom: 8px;">
                            🤖 AI HNDL Threat Analysis
                        </div>
                        <div style="color: #334155; line-height: 1.7;">{analysis}</div>
                    </div>
                """, unsafe_allow_html=True)

# ===== TAB 2: PQC Migration Checklist =====
with tab2:
    st.markdown("#### ✅ Post-Quantum Cryptography Migration Readiness Checklist")

    st.markdown("""
        <div class="ai-insight-card">
            <div style="font-weight: 700; color: #0066CC; margin-bottom: 8px;">
                📋 About This Checklist
            </div>
            <div style="color: #334155; font-size: 0.9rem; line-height: 1.7;">
                Track your branch's readiness for post-quantum cryptography migration.
                Items checked here are stored in the database for compliance tracking.
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Checklist categories
    checklist_items = {
        "🔐 Cryptographic Inventory": [
            "Identify all RSA and ECC key usage in production systems",
            "Catalog TLS certificate chains and expiry dates",
            "Map all data-at-rest encryption to specific algorithms",
            "Document key management infrastructure and HSM usage",
            "Audit VPN and secure communication channel encryption",
        ],
        "📊 Risk Assessment": [
            "Classify data sensitivity (public, confidential, top-secret)",
            "Estimate cryptographic shelf-life for each data category",
            "Identify long-lived encrypted data vulnerable to HNDL",
            "Assess third-party vendor quantum readiness",
            "Evaluate regulatory requirements for PQC compliance",
        ],
        "🔧 Technical Readiness": [
            "Test CRYSTALS-Kyber key generation performance",
            "Evaluate hybrid (classical + PQC) TLS configurations",
            "Benchmark PQC algorithm performance on production hardware",
            "Test PQC-compatible certificate authorities",
            "Validate backward compatibility with legacy systems",
        ],
        "👥 Organizational Readiness": [
            "Train IT security team on post-quantum cryptography",
            "Establish PQC migration governance committee",
            "Create PQC migration timeline and milestones",
            "Allocate budget for PQC infrastructure upgrades",
            "Develop incident response plan for quantum threats",
        ],
        "✅ Compliance & Audit": [
            "Align PQC migration with RBI cybersecurity guidelines",
            "Document PQC migration decisions for audit trail",
            "Schedule quarterly PQC readiness assessments",
            "Establish metrics for tracking migration progress",
            "Plan external security audit for PQC implementation",
        ],
    }

    # Load saved checklist state
    saved_checklist = mongo_client.find_one("pqc_checklist",
                                            {"branch": st.session_state.get("department", "default")})
    checked_items = set()
    if saved_checklist:
        checked_items = set(saved_checklist.get("checked_items", []))

    # Display checklist
    all_items = []
    current_checked = []

    for category, items in checklist_items.items():
        st.markdown(f"##### {category}")
        for item in items:
            item_key = f"{category}::{item}"
            checked = st.checkbox(item, value=(item_key in checked_items),
                                  key=f"pqc_check_{hash(item_key)}")
            all_items.append(item_key)
            if checked:
                current_checked.append(item_key)

    # Progress
    total = len(all_items)
    done = len(current_checked)
    progress = done / max(1, total)

    st.markdown("---")
    st.progress(progress, text=f"Migration Readiness: {done}/{total} items ({progress:.0%})")

    # Save button
    if st.button("💾 Save Checklist Progress", use_container_width=True):
        checklist_doc = {
            "branch": st.session_state.get("department", "default"),
            "checked_items": current_checked,
            "total_items": total,
            "progress": round(progress * 100, 1),
            "updated_at": datetime.datetime.now(datetime.timezone.utc),
            "updated_by": st.session_state.get("username", "system"),
        }
        # Upsert
        existing = mongo_client.find_one("pqc_checklist",
                                         {"branch": st.session_state.get("department", "default")})
        if existing:
            mongo_client.update_one(
                "pqc_checklist",
                {"branch": st.session_state.get("department", "default")},
                {"$set": checklist_doc}
            )
        else:
            mongo_client.insert_one("pqc_checklist", checklist_doc)

        mongo_client.log_audit_event(
            actor=st.session_state.get("username", "system"),
            action="PQC_CHECKLIST_UPDATE",
            target=st.session_state.get("department", "default"),
            rationale=f"PQC migration checklist updated: {done}/{total} items completed ({progress:.0%})",
            event_type="security",
        )
        st.success(f"✅ Checklist saved! Progress: {done}/{total} ({progress:.0%})")

# ===== TAB 3: Quantum Dashboard =====
with tab3:
    st.markdown("#### 📊 Quantum Threat Dashboard")

    # PQC Vault Status overview
    users = mongo_client.find("users")
    total_users = len(users)
    pqc_protected = len([u for u in users if u.get("pqc_vault")])
    needs_rotation = 0

    for u in users:
        vault = u.get("pqc_vault", {})
        if vault:
            rotation = pqc_vault.check_rotation_status(vault)
            if rotation["needs_rotation"]:
                needs_rotation += 1

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🛡️ PQC Protected", f"{pqc_protected}/{total_users}")
    with col2:
        st.metric("🔄 Needs Rotation", needs_rotation)
    with col3:
        hndl_count = len(st.session_state.get("hndl_events", []))
        st.metric("🚨 HNDL Indicators", hndl_count)
    with col4:
        pqc_meta = pqc_vault.get_pqc_metadata()
        st.metric("🔒 Algorithm", "Kyber-768")

    st.markdown("---")

    # Quantum threat gauge
    st.markdown("##### ⚛️ Quantum Threat Level")

    # Calculate overall quantum threat based on various factors
    threat_factors = {
        "unprotected_users": (total_users - pqc_protected) * 10,
        "rotation_overdue": needs_rotation * 15,
        "hndl_events": hndl_count * 5,
    }
    quantum_threat = min(100, sum(threat_factors.values()))

    fig_quantum = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=quantum_threat,
        number={'suffix': '%', 'font': {'size': 40, 'color': '#1E293B',
                'family': 'JetBrains Mono'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': '#E2E8F0'},
            'bar': {'color': '#FF4C4C' if quantum_threat > 60 else '#FFB84D' if quantum_threat > 30 else '#00C896'},
            'bgcolor': '#F8FAFC',
            'borderwidth': 2,
            'bordercolor': '#E2E8F0',
            'steps': [
                {'range': [0, 30], 'color': 'rgba(0,200,150,0.05)'},
                {'range': [30, 60], 'color': 'rgba(255,184,77,0.05)'},
                {'range': [60, 100], 'color': 'rgba(255,76,76,0.05)'},
            ],
        },
        title={
            'text': "Overall Quantum Threat Exposure",
            'font': {'size': 16, 'color': '#64748B', 'family': 'Inter'},
        },
    ))

    fig_quantum.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=300,
        margin=dict(t=80, b=20, l=40, r=40),
    )
    st.plotly_chart(fig_quantum, use_container_width=True)

    # Threat factors breakdown
    st.markdown("##### 📊 Threat Factor Breakdown")
    factor_data = pd.DataFrame([
        {"Factor": "Unprotected Users", "Score": threat_factors["unprotected_users"],
         "Details": f"{total_users - pqc_protected} user(s) without PQC protection"},
        {"Factor": "Credential Rotation Overdue", "Score": threat_factors["rotation_overdue"],
         "Details": f"{needs_rotation} credential(s) past 30-day rotation window"},
        {"Factor": "HNDL Indicators Detected", "Score": threat_factors["hndl_events"],
         "Details": f"{hndl_count} potential harvest-now-decrypt-later event(s)"},
    ])
    st.dataframe(factor_data, use_container_width=True, hide_index=True)

    # AI Insight
    st.markdown("---")
    with st.expander("🤖 AI Quantum Threat Assessment", expanded=False):
        if st.button("🧠 Generate Quantum Threat Assessment", key="quantum_insight"):
            quantum_data = {
                "pqc_protected_users": pqc_protected,
                "total_users": total_users,
                "credentials_needing_rotation": needs_rotation,
                "hndl_events_detected": hndl_count,
                "quantum_threat_score": quantum_threat,
                "pqc_algorithm": "CRYSTALS-Kyber-768",
            }
            with st.spinner("🤖 Analyzing quantum threat landscape..."):
                insight = groq_client.call_groq(
                    f"You are a quantum-aware banking CISO. Assess this bank's quantum "
                    f"threat posture: {quantum_data}. Provide a 3-sentence assessment "
                    f"covering: current quantum readiness, biggest vulnerability, and "
                    f"one critical next step for quantum migration."
                )

            st.markdown(f"""
                <div class="ai-insight-card">
                    <div style="font-weight: 700; color: #0066CC; margin-bottom: 12px;">
                        🤖 AI Quantum Threat Assessment
                    </div>
                    <div style="color: #334155; line-height: 1.7;">{insight}</div>
                </div>
            """, unsafe_allow_html=True)
