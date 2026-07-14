"""
SentinelIQ — Main Application Entry Point
===========================================
AI-Powered Insider Threat & Privileged Access Monitoring Platform
Bank of Maharashtra | Finspark Hackathon 2026

Multi-page Streamlit app with authentication, role-aware navigation,
and custom dark navy theme.
"""

import streamlit as st
import datetime
import hashlib
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import data_simulator, mongo_client, anomaly_engine


# ---------------------------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SentinelIQ — Insider Threat Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# Custom CSS — Dark Navy Theme
# ---------------------------------------------------------------------------
def inject_custom_css():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

        /* Root variables */
        :root {
            --bg-primary: #FFFFFF;
            --bg-secondary: #F8FAFC;
            --bg-card: #F1F5F9;
            --accent-blue: #0066CC;
            --accent-green: #10B981;
            --accent-red: #EF4444;
            --accent-amber: #F59E0B;
            --text-primary: #1E293B;
            --text-secondary: #64748B;
            --border-color: #E2E8F0;
            --glow-blue: 0 2px 12px rgba(0, 102, 204, 0.08);
        }

        /* Main app styling */
        .stApp {
            font-family: 'Inter', sans-serif !important;
            background-color: var(--bg-primary) !important;
            color: var(--text-primary) !important;
        }

        /* Sidebar styling */
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #F8FAFC 0%, #E2E8F0 100%) !important;
            border-right: 1px solid var(--border-color) !important;
        }

        [data-testid="stSidebar"] .stMarkdown {
            font-family: 'Inter', sans-serif !important;
        }

        /* Headers */
        h1, h2, h3, h4, h5, h6 {
            font-family: 'Inter', sans-serif !important;
            font-weight: 700 !important;
            color: var(--text-primary) !important;
        }

        /* Metric cards */
        [data-testid="stMetric"] {
            background: linear-gradient(135deg, #F1F5F9 0%, #E2E8F0 100%) !important;
            border: 1px solid var(--border-color) !important;
            border-radius: 12px;
            padding: 16px 20px;
            box-shadow: var(--glow-blue);
        }

        [data-testid="stMetricLabel"] {
            font-family: 'Inter', sans-serif !important;
            font-weight: 500 !important;
            color: var(--text-secondary) !important;
            font-size: 0.85rem !important;
        }

        [data-testid="stMetricValue"] {
            font-family: 'JetBrains Mono', monospace !important;
            font-weight: 700 !important;
            color: var(--accent-blue) !important;
        }

        /* Dataframe styling */
        [data-testid="stDataFrame"] {
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }

        /* Button styling */
        .stButton > button {
            background: linear-gradient(135deg, #0088CC 0%, #006699 100%) !important;
            color: #FFFFFF !important;
            font-family: 'Inter', sans-serif !important;
            font-weight: 600 !important;
            border: none !important;
            border-radius: 8px !important;
            padding: 8px 24px !important;
            transition: all 0.3s ease !important;
            box-shadow: 0 2px 8px rgba(0, 102, 204, 0.15) !important;
        }

        .stButton > button:hover {
            background: linear-gradient(135deg, #0099DD 0%, #0077AA 100%) !important;
            box-shadow: 0 4px 16px rgba(0, 102, 204, 0.25) !important;
            transform: translateY(-1px) !important;
        }

        /* Expander styling */
        .streamlit-expanderHeader {
            background: var(--bg-card) !important;
            border: 1px solid var(--border-color) !important;
            border-radius: 8px !important;
            font-family: 'Inter', sans-serif !important;
            font-weight: 600 !important;
            color: var(--text-primary) !important;
        }

        /* Tab styling */
        .stTabs [data-baseweb="tab-list"] {
            gap: 8px;
        }

        .stTabs [data-baseweb="tab"] {
            background: var(--bg-card) !important;
            border: 1px solid var(--border-color) !important;
            border-radius: 8px 8px 0 0 !important;
            font-family: 'Inter', sans-serif !important;
            font-weight: 500 !important;
            color: var(--text-secondary) !important;
        }

        .stTabs [aria-selected="true"] {
            background: linear-gradient(135deg, #F1F5F9 0%, #E2E8F0 100%) !important;
            border-bottom: 2px solid var(--accent-blue) !important;
            color: var(--accent-blue) !important;
        }

        /* Alert card styling */
        .ai-insight-card {
            background: linear-gradient(135deg, #F0F7FF 0%, #F1F5F9 100%);
            border: 1px solid #BEE3F8;
            border-left: 4px solid var(--accent-blue);
            border-radius: 12px;
            padding: 20px;
            margin: 16px 0;
            font-family: 'Inter', sans-serif;
            box-shadow: 0 4px 12px rgba(0, 102, 204, 0.05);
        }

        .risk-badge-green {
            background: linear-gradient(135deg, #00C896 0%, #00A87A 100%);
            color: #0A1628;
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.8rem;
            font-family: 'JetBrains Mono', monospace;
        }

        .risk-badge-amber {
            background: linear-gradient(135deg, #FFB84D 0%, #FF9F1C 100%);
            color: #0A1628;
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.8rem;
            font-family: 'JetBrains Mono', monospace;
        }

        .risk-badge-red {
            background: linear-gradient(135deg, #FF4C4C 0%, #CC3333 100%);
            color: #FFFFFF;
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.8rem;
            font-family: 'JetBrains Mono', monospace;
        }

        .quantum-shield-active {
            background: linear-gradient(135deg, #00C896 0%, #00A87A 100%);
            color: #0A1628;
            padding: 6px 16px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 0.85rem;
            display: inline-block;
            font-family: 'JetBrains Mono', monospace;
            box-shadow: 0 0 12px rgba(0, 200, 150, 0.3);
        }

        .quantum-shield-degraded {
            background: linear-gradient(135deg, #FFB84D 0%, #FF9F1C 100%);
            color: #0A1628;
            padding: 6px 16px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 0.85rem;
            display: inline-block;
            font-family: 'JetBrains Mono', monospace;
        }

        /* Scrollbar styling */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg-primary);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--border-color);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--accent-blue);
        }

        /* Logo title */
        .sentinel-title {
            font-family: 'Inter', sans-serif;
            font-weight: 900;
            font-size: 1.8rem;
            background: linear-gradient(135deg, #00D4FF 0%, #00C896 50%, #00D4FF 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.5px;
            margin-bottom: 0;
        }

        .sentinel-subtitle {
            font-family: 'Inter', sans-serif;
            font-size: 0.75rem;
            color: var(--text-secondary);
            letter-spacing: 2px;
            text-transform: uppercase;
            margin-top: -8px;
        }

        /* Code/log text */
        code, .stCode, pre {
            font-family: 'JetBrains Mono', monospace !important;
        }

        /* Selectbox styling */
        [data-testid="stSelectbox"] {
            font-family: 'Inter', sans-serif !important;
        }

        /* Divider */
        hr {
            border-color: var(--border-color) !important;
        }

        /* Toast/success messages */
        .stSuccess {
            background: rgba(0, 200, 150, 0.1) !important;
            border: 1px solid var(--accent-green) !important;
            border-radius: 8px !important;
        }

        .stWarning {
            background: rgba(255, 184, 77, 0.1) !important;
            border: 1px solid var(--accent-amber) !important;
            border-radius: 8px !important;
        }

        .stError {
            background: rgba(255, 76, 76, 0.1) !important;
            border: 1px solid var(--accent-red) !important;
            border-radius: 8px !important;
        }
    </style>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Authentication System
# ---------------------------------------------------------------------------

# Demo credentials (pre-hashed)
DEMO_USERS = {
    "admin": {
        "name": "Rajesh Kumar",
        "password": "admin123",
        "role": "SUPERADMIN",
        "department": "IT Security",
    },
    "analyst": {
        "name": "Priya Sharma",
        "password": "analyst123",
        "role": "DBA",
        "department": "Database Operations",
    },
    "manager": {
        "name": "Anita Joshi",
        "password": "manager123",
        "role": "BRANCH_MANAGER",
        "department": "Pune Main Branch",
    },
    "teller": {
        "name": "Kavita Nair",
        "password": "teller123",
        "role": "TELLER",
        "department": "Pune Main Branch",
    },
}


def authenticate_user(username: str, password: str) -> bool:
    """Authenticate user against demo credentials."""
    user = DEMO_USERS.get(username)
    if user and user["password"] == password:
        st.session_state["authenticated"] = True
        st.session_state["username"] = username
        st.session_state["name"] = user["name"]
        st.session_state["role"] = user["role"]
        st.session_state["department"] = user["department"]
        return True
    return False


def show_login_page():
    """Display the login page."""
    st.markdown("""
        <div style="text-align: center; padding: 40px 0 20px 0;">
            <div class="sentinel-title">🛡️ SentinelIQ</div>
            <div class="sentinel-subtitle">AI-Powered Insider Threat Monitor</div>
            <p style="color: #8B9DC3; margin-top: 12px; font-size: 0.95rem;">
                Bank of Maharashtra — Privileged Access Monitoring Platform
            </p>
        </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        st.markdown("""
            <div style="background: linear-gradient(135deg, #F8FAFC 0%, #E2E8F0 100%);
                        border: 1px solid #E2E8F0; border-radius: 16px; padding: 32px;
                        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.05);">
            </div>
        """, unsafe_allow_html=True)

        st.markdown("#### 🔐 Secure Login")

        username = st.text_input("Username", placeholder="Enter your username", key="login_user")
        password = st.text_input("Password", type="password", placeholder="Enter your password", key="login_pass")

        if st.button("🔓 Sign In", use_container_width=True):
            if authenticate_user(username, password):
                st.success(f"✅ Welcome, {st.session_state['name']}!")
                st.rerun()
            else:
                st.error("❌ Invalid credentials. Please try again.")

        st.markdown("---")
        st.markdown("""
            <div style="text-align: center; color: #8B9DC3; font-size: 0.8rem;">
                <strong>Demo Credentials:</strong><br>
                <code>admin / admin123</code> (SuperAdmin)<br>
                <code>analyst / analyst123</code> (DBA)<br>
                <code>manager / manager123</code> (Branch Manager)<br>
                <code>teller / teller123</code> (Teller)
            </div>
        """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def show_sidebar():
    """Display the role-aware sidebar."""
    with st.sidebar:
        st.markdown("""
            <div class="sentinel-title" style="font-size: 1.4rem;">🛡️ SentinelIQ</div>
            <div class="sentinel-subtitle" style="font-size: 0.65rem;">Insider Threat Monitor</div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        # User info
        role = st.session_state.get("role", "UNKNOWN")
        role_colors = {
            "SUPERADMIN": "#FF4C4C",
            "DBA": "#FF8C42",
            "NETWORK_ADMIN": "#FFB84D",
            "BRANCH_MANAGER": "#00D4FF",
            "TELLER": "#00C896",
        }
        role_color = role_colors.get(role, "#FFFFFF")

        st.markdown(f"""
            <div style="background: linear-gradient(135deg, #F1F5F9, #E2E8F0);
                        border: 1px solid #E2E8F0; border-radius: 12px;
                        padding: 16px; margin-bottom: 16px;">
                <div style="font-weight: 700; font-size: 1rem; color: #1E293B;">
                    👤 {st.session_state.get('name', 'User')}
                </div>
                <div style="margin-top: 6px;">
                    <span style="background: {role_color}; color: #FFFFFF;
                                padding: 2px 10px; border-radius: 12px;
                                font-size: 0.7rem; font-weight: 700;
                                font-family: 'JetBrains Mono', monospace;">
                        {role}
                    </span>
                </div>
                <div style="color: #64748B; font-size: 0.8rem; margin-top: 8px;">
                    📍 {st.session_state.get('department', '')}
                </div>
            </div>
        """, unsafe_allow_html=True)

        # System status
        mongo_status = "🟢 Online" if mongo_client.is_mongo_available() else "🟡 In-Memory"
        from utils import groq_client
        groq_status = "🟢 Connected" if groq_client.is_groq_available() else "🟡 Offline Mode"

        st.markdown(f"""
            <div style="background: #F8FAFC; border: 1px solid #E2E8F0;
                        border-radius: 8px; padding: 12px; margin-bottom: 16px;
                        font-size: 0.8rem;">
                <div style="color: #64748B; font-weight: 600; margin-bottom: 8px;">
                    ⚙️ System Status
                </div>
                <div style="color: #1E293B;">
                    Database: {mongo_status}<br>
                    Groq AI: {groq_status}
                </div>
            </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        # Logout
        if st.button("🚪 Logout", use_container_width=True):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

        st.markdown("""
            <div style="position: fixed; bottom: 16px; color: #4A5E80;
                        font-size: 0.7rem; font-family: 'JetBrains Mono', monospace;">
                SentinelIQ v1.0 | Finspark 2026
            </div>
        """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Main App Home Page
# ---------------------------------------------------------------------------

def show_home():
    """Display the home page with overview."""
    st.markdown("""
        <div style="text-align: center; padding: 20px 0;">
            <div class="sentinel-title" style="font-size: 2.5rem;">🛡️ SentinelIQ</div>
            <div class="sentinel-subtitle" style="font-size: 0.85rem; letter-spacing: 3px;">
                AI-POWERED INSIDER THREAT & PRIVILEGED ACCESS MONITORING
            </div>
            <p style="color: #8B9DC3; margin-top: 8px;">
                Bank of Maharashtra | Finspark Hackathon 2026
            </p>
        </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # Quick Stats
    col1, col2, col3, col4, col5 = st.columns(5)

    n_users = mongo_client.count_documents("users")
    n_sessions = mongo_client.count_documents("sessions")
    n_alerts = mongo_client.count_documents("alerts")
    n_audit = mongo_client.count_documents("audit_logs")
    n_flagged = mongo_client.count_documents("sessions", {"flagged": True})

    with col1:
        st.metric("👥 Monitored Users", n_users)
    with col2:
        st.metric("📊 Total Sessions", n_sessions)
    with col3:
        st.metric("🚨 Active Alerts", n_alerts)
    with col4:
        st.metric("📋 Audit Events", n_audit)
    with col5:
        st.metric("⚠️ Flagged Sessions", n_flagged)

    st.markdown("---")

    # Feature Cards
    st.markdown("### 🚀 Platform Modules")

    features = [
        ("🏠", "Real-Time Dashboard", "Live risk monitoring with Plotly gauges and heatmaps", "#00D4FF"),
        ("🔍", "AI Anomaly Engine", "Isolation Forest + River online learning with Groq AI briefs", "#FF8C42"),
        ("🔐", "Quantum-Proof Vault", "CRYSTALS-Kyber PQC credential encryption simulation", "#00C896"),
        ("🛡️", "RBAC+ Engine", "Dynamic risk-based access control with step-up auth", "#FFB84D"),
        ("👁️", "Threat Watchlist", "Insider threat scoring leaderboard with AI summaries", "#FF4C4C"),
        ("📋", "Audit Forensics", "Full timeline with AI-powered forensic narratives", "#9B59B6"),
        ("⚛️", "Quantum Monitor", "HNDL attack detection and PQC readiness tracking", "#3498DB"),
    ]

    for i in range(0, len(features), 3):
        cols = st.columns(3)
        for j, col in enumerate(cols):
            if i + j < len(features):
                icon, title, desc, color = features[i + j]
                with col:
                    st.markdown(f"""
                        <div style="background: linear-gradient(135deg, #162040 0%, #1A2850 100%);
                                    border: 1px solid #1E3055; border-radius: 16px;
                                    padding: 24px; margin: 8px 0; min-height: 160px;
                                    border-top: 3px solid {color};
                                    box-shadow: 0 4px 16px rgba(0,0,0,0.2);
                                    transition: all 0.3s ease;">
                            <div style="font-size: 2rem; margin-bottom: 8px;">{icon}</div>
                            <div style="font-weight: 700; color: {color};
                                        font-size: 1.05rem; margin-bottom: 8px;">
                                {title}
                            </div>
                            <div style="color: #8B9DC3; font-size: 0.85rem; line-height: 1.5;">
                                {desc}
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

    st.markdown("---")

    # Novel Features Highlight
    st.markdown("### ⭐ Novel Features")
    cols = st.columns(2)
    novel_features = [
        ("🤖 Groq-Powered Threat Narration",
         "Every anomaly gets a plain-English AI brief — not just a score. Evaluators can read exactly WHY something is a threat."),
        ("🛡️ Quantum-Proof Credential Vault",
         "Simulated CRYSTALS-Kyber PQC encryption for credentials — addresses the quantum risk dimension."),
        ("📈 Online Learning Model",
         "River library means the anomaly model LEARNS from new sessions in real-time without retraining."),
        ("⚛️ Harvest-Now-Decrypt-Later Detector",
         "Proactively flags data exfiltration patterns matching quantum harvest attack signatures."),
    ]
    for i, (title, desc) in enumerate(novel_features):
        with cols[i % 2]:
            st.markdown(f"""
                <div class="ai-insight-card">
                    <div style="font-weight: 700; color: #00D4FF; margin-bottom: 8px;">
                        {title}
                    </div>
                    <div style="color: #C0CBDF; font-size: 0.9rem; line-height: 1.6;">
                        {desc}
                    </div>
                </div>
            """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Initialization & Routing
# ---------------------------------------------------------------------------

def initialize_app():
    """Initialize app state and seed database on first run."""
    if "initialized" not in st.session_state:
        with st.spinner("🚀 Initializing SentinelIQ — seeding synthetic data..."):
            stats = data_simulator.seed_database()
            st.session_state["initialized"] = True
            st.session_state["seed_stats"] = stats


def main():
    """Main application entry point."""
    inject_custom_css()
    initialize_app()

    if not st.session_state.get("authenticated"):
        show_login_page()
    else:
        show_sidebar()
        show_home()


if __name__ == "__main__":
    main()
