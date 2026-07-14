# 🛡️ SentinelIQ

**SentinelIQ** is an AI-powered Insider Threat & Privileged Access Monitoring Platform built for **Bank of Maharashtra** for the **Finspark Hackathon 2026**. 

The platform monitors privileged users (DBAs, managers, superadmins) in real-time using a hybrid Machine Learning anomaly detection engine, secures critical keys using a simulated post-quantum cryptography (PQC) vault, enforces risk-based adaptive access controls, and explains threats in plain English using LLM narration.

---

## 🚀 Key Modules & Features

### 1. 🏠 Real-Time Behavioural Dashboard
- **Live Performance**: Displays overall threat exposure metrics, active alert counters, and session parameters.
- **Visual Analytics**: Interactive Plotly gauges showing current session risks for individual users and a 7-day login density heatmap.

### 2. 🔍 AI Anomaly Detection Engine
- **Hybrid ML Model**: 
  - **Batch Learning**: Scikit-Learn's *Isolation Forest* detects baseline deviations.
  - **Online Learning**: River's *HalfSpaceTrees (HST)* adapts dynamically to live transaction streams.
- **AI Threat Briefs**: Utilizes the Groq API (Llama 3.3 70B model) to generate instant security context reports explaining suspicious patterns.

### 3. 🔐 Quantum-Proof Credential Vault
- **Lattice-based Simulation**: Simulated implementation of **CRYSTALS-Kyber-768** parameter key encapsulation mechanism (KEM) to protect admin passwords.
- **Hybrid Encryption**: Combines Kyber-768 public key encapsulation with AES-256-GCM symmetric encryption for credential storage.
- **Age Tracker & Rotation**: Monitored rotation window enforcing credential rotation every 30 days.

### 4. 🛡️ Risk-Based Access Control (RBAC+)
- **Adaptive Evaluation**: Intercepts queries, exports, and config changes dynamically based on the actor's current risk score.
- **Step-Up Authentication**: Triggers a simulated Multi-Factor OTP challenge if the user's risk score exceeds `70`.
- **Auto-Suspension**: Instantly suspends accounts if their risk score spikes above `85`.

### 5. 👁️ Insider Threat Watchlist Leaderboard
- **30-Day Cumulative Risk**: Ranks users based on rolling cumulative anomalies.
- **AI Risk Summaries**: Generates high-risk profiles summarizing user vulnerability factors.
- **Compliance Export**: Downloads a clean, print-ready HTML/PDF report of the watchlist.

### 6. 📋 Audit Forensics Timeline
- **Chronological Ledger**: Tracks logs of all access decisions, logins, step-up challenges, and rotations.
- **AI Forensic Narrator**: Explains any selected event log in plain English.
- **CSV Exporter**: Exports audit logs for external compliance reviews.

### 7. ⚛️ Quantum Risk Monitor
- **HNDL Threat Detector**: Identifies Harvest-Now-Decrypt-Later (HNDL) data exfiltration patterns.
- **Checklist Compliance**: 25-step Post-Quantum Cryptography Migration Readiness checklist tracked at the branch level.

---

## 🛠️ Technology Stack

- **Frontend**: Streamlit (Multi-page App)
- **Database**: MongoDB Atlas (Fallbacks to local memory state if offline)
- **Large Language Model**: Groq API (`llama-3.3-70b-versatile`)
- **Machine Learning**: `scikit-learn` (Isolation Forest) & `river` (Online Learning)
- **Post-Quantum Crypto**: `cryptography` library (AES-256-GCM, HKDF, PBKDF2)
- **Task Scheduler**: `apscheduler` (handles real-time streaming simulation)
- **Authentication**: `streamlit-authenticator` (Bcrypt password hashing)

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.9+
- MongoDB (local instance or MongoDB Atlas connection string)
- Groq API Key

### Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Yash151005/SentinelIQ.git
   cd SentinelIQ
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**
   Create a `.env` file inside the `config/` directory:
   ```properties
   # Groq API Key
   GROQ_API_KEY=your_groq_api_key_here

   # MongoDB Connection
   MONGO_URI=mongodb://localhost:27017
   MONGO_DB_NAME=sentineliq

   # Session secret
   APP_SECRET_KEY=sentineliq-secret-key-change-in-production
   ```

4. **Run the Application**
   ```bash
   streamlit run app.py
   ```
   Open `http://localhost:8501` in your browser.

---

## 🔐 Demo Credentials
Use these demo accounts to log into the SentinelIQ platform:

| Username | Password | Role | Department |
| :--- | :--- | :--- | :--- |
| `admin` | `admin123` | SUPERADMIN | IT Security |
| `analyst` | `analyst123` | DBA | Database Operations |
| `manager` | `manager123` | BRANCH_MANAGER | Mumbai Central Branch |
| `teller` | `teller123` | TELLER | Pune Main Branch |

---

## ⚖️ Role-Based Access Control (RBAC) Compliance Matrix

SentinelIQ strictly adheres to the **Principle of Least Privilege (PoLP)** and **Segregation of Duties (SoD)** in compliance with RBI Cybersecurity guidelines for scheduled commercial banks.

### 📊 Page Access Rights

| Page / Module | SUPERADMIN | DBA | NETWORK_ADMIN | BRANCH_MANAGER | TELLER |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **🏠 Dashboard** | **Allowed** ✅ | **Allowed** ✅ | **Allowed** ✅ | **Allowed** ✅ | **Allowed** (Own Only) 👤 |
| **🔍 Anomaly Engine** | **Allowed** ✅ | **Allowed** ✅ | **Allowed** ✅ | **Restricted** ❌ | **Restricted** ❌ |
| **🔐 Credential Vault** | **Allowed** ✅ | **Allowed** ✅ | **Restricted** ❌ | **Restricted** ❌ | **Restricted** ❌ |
| **🛡️ Access Control** | **Allowed** ✅ | **Restricted** ❌ | **Restricted** ❌ | **Restricted** ❌ | **Restricted** ❌ |
| **👁️ Watchlist** | **Allowed** ✅ | **Allowed** ✅ | **Allowed** ✅ | **Restricted** ❌ | **Restricted** ❌ |
| **📋 Audit Forensics** | **Allowed** ✅ | **Allowed** ✅ | **Allowed** ✅ | **Allowed** (Branch Only) 📌 | **Restricted** ❌ |
| **⚛️ Quantum Monitor** | **Allowed** ✅ | **Allowed** ✅ | **Allowed** ✅ | **Restricted** ❌ | **Restricted** ❌ |

### 🛠️ Feature Access Control & Segregation of Duties

1. **SUPERADMIN**:
   - **Access**: Global configuration override, policy changes, user role elevation, simulated PQC vault overrides.
   - **Restriction**: Excluded from direct transaction processing to prevent administrative tampering with ledgers.
2. **DBA**:
   - **Access**: Database log analysis, query monitors, database health checks, PQC credential auditing.
   - **Restriction**: Forbidden from changing network policies or modifying RBAC user hierarchies.
3. **NETWORK_ADMIN**:
   - **Access**: Traffic exfiltration audits, connection timelines, HNDL exfiltration detection.
   - **Restriction**: Strictly prohibited from running database queries or decrypting database/pqc-vault payloads.
4. **BRANCH_MANAGER**:
   - **Access**: Local branch performance logs, compliance forensics for their specific branch, audit timelines.
   - **Restriction**: Blocked from ML model configurations, network details, or key rotation control.
5. **TELLER**:
   - **Access**: View own login metrics and own audit logs.
   - **Restriction**: Strictly sandboxed. Blocked from viewing system logs, alerts, database queries, and credentials of any other system entity.

---

*SentinelIQ Platform — Finspark Hackathon 2026*
