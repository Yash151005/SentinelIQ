"""
SentinelIQ — Data Simulator
=============================
Generates synthetic banking session data for demo purposes.

On first run, seeds MongoDB with:
- 10 synthetic privileged users across 5 roles
- 500 sessions (80% normal, 15% suspicious, 5% critical)
- 50 pre-scored anomaly alerts
- 200 audit log entries

Also provides continuous streaming simulation via APScheduler.
"""

import random
import datetime
import secrets
import uuid
from typing import Dict, List, Optional

from utils import mongo_client, anomaly_engine, pqc_vault

# ---------------------------------------------------------------------------
# Synthetic User Profiles
# ---------------------------------------------------------------------------

SYNTHETIC_USERS = [
    {"username": "rajesh.kumar", "role": "SUPERADMIN", "department": "IT Security"},
    {"username": "priya.sharma", "role": "DBA", "department": "Database Operations"},
    {"username": "amit.patel", "role": "DBA", "department": "Database Operations"},
    {"username": "sneha.desai", "role": "NETWORK_ADMIN", "department": "Network Infra"},
    {"username": "vikram.singh", "role": "NETWORK_ADMIN", "department": "Network Infra"},
    {"username": "anita.joshi", "role": "BRANCH_MANAGER", "department": "Pune Main Branch"},
    {"username": "suresh.reddy", "role": "BRANCH_MANAGER", "department": "Mumbai Central Branch"},
    {"username": "kavita.nair", "role": "TELLER", "department": "Pune Main Branch"},
    {"username": "deepak.verma", "role": "TELLER", "department": "Mumbai Central Branch"},
    {"username": "meena.gupta", "role": "TELLER", "department": "Nagpur Branch"},
]

# Known IPs and Geos
KNOWN_IPS = [
    "10.0.1.101", "10.0.1.102", "10.0.1.103", "10.0.1.104",
    "10.0.2.201", "10.0.2.202", "10.0.3.301", "10.0.3.302",
    "192.168.1.50", "192.168.1.51",
]
UNKNOWN_IPS = [
    "185.220.101.42", "91.219.237.128", "45.154.255.147",
    "194.26.29.113", "23.129.64.210", "198.98.56.78",
]
KNOWN_GEOS = [
    "Pune, India", "Mumbai, India", "Nagpur, India",
    "Hyderabad, India", "Delhi, India",
]
ANOMALOUS_GEOS = [
    "Moscow, Russia", "Lagos, Nigeria", "Unknown VPN",
    "Pyongyang, North Korea", "Tor Exit Node",
]

# Command sets by behaviour type
NORMAL_COMMANDS = [
    "SELECT * FROM accounts", "SELECT balance FROM customers",
    "UPDATE transaction_log SET status='processed'",
    "SELECT COUNT(*) FROM daily_transactions",
    "SHOW DATABASES", "SELECT user, host FROM mysql.user",
    "DESCRIBE customers", "SHOW TABLE STATUS",
]
SUSPICIOUS_COMMANDS = [
    "SELECT * FROM customers WHERE balance > 1000000",
    "EXPORT TABLE customer_details TO CSV",
    "ALTER USER admin IDENTIFIED BY 'newpass'",
    "SELECT * FROM audit_trail ORDER BY timestamp DESC",
    "GRANT ALL PRIVILEGES ON *.* TO 'temp_user'",
]
CRITICAL_COMMANDS = [
    "DROP TABLE audit_logs", "TRUNCATE TABLE access_logs",
    "mysqldump --all-databases > /tmp/full_backup.sql",
    "SELECT * FROM credit_card_numbers",
    "ALTER TABLE customers ADD COLUMN backdoor VARCHAR(255)",
    "GRANT SUPERADMIN TO 'external_user'",
    "DELETE FROM security_alerts WHERE resolved=0",
]

# Alert types
ALERT_TYPES = [
    "unusual_login_time", "excessive_data_export", "privilege_escalation",
    "geo_anomaly", "rapid_command_execution", "failed_auth_spike",
    "bulk_data_access", "off_hours_access", "ip_change_detected",
    "role_escalation_attempt",
]

# Audit event types
AUDIT_ACTIONS = [
    "LOGIN", "LOGOUT", "QUERY_EXECUTE", "DATA_EXPORT", "ROLE_CHANGE",
    "PASSWORD_RESET", "PERMISSION_GRANT", "SYSTEM_CONFIG_CHANGE",
    "ALERT_ACKNOWLEDGED", "SESSION_TIMEOUT", "STEP_UP_AUTH",
    "CREDENTIAL_ROTATION", "USER_SUSPEND", "USER_REINSTATE",
]


# ---------------------------------------------------------------------------
# Session Generation
# ---------------------------------------------------------------------------

def _generate_normal_session(user: Dict, base_time: datetime.datetime) -> Dict:
    """Generate a normal (benign) session."""
    hour = random.randint(9, 17)
    start = base_time.replace(hour=hour, minute=random.randint(0, 59))
    duration = random.randint(15, 180)  # 15 min to 3 hours
    end = start + datetime.timedelta(minutes=duration)

    num_commands = random.randint(5, 30)
    commands = random.choices(NORMAL_COMMANDS, k=num_commands)

    return {
        "user_id": user["username"],
        "start_time": start,
        "end_time": end,
        "commands": commands,
        "data_mb": round(random.uniform(0.1, 5.0), 2),
        "ip": random.choice(KNOWN_IPS),
        "geo": random.choice(KNOWN_GEOS),
        "anomaly_score": round(random.uniform(5, 35), 1),
        "flagged": False,
        "failed_auth_attempts": random.randint(0, 1),
        "ip_change_flag": False,
        "role_escalation_flag": False,
        "session_type": "normal",
    }


def _generate_suspicious_session(user: Dict, base_time: datetime.datetime) -> Dict:
    """Generate a suspicious session (elevated risk)."""
    # Off-hours or unusual time
    hour = random.choice([1, 2, 3, 4, 5, 22, 23, 0])
    start = base_time.replace(hour=hour, minute=random.randint(0, 59))
    duration = random.randint(30, 240)
    end = start + datetime.timedelta(minutes=duration)

    num_commands = random.randint(20, 80)
    commands = (random.choices(NORMAL_COMMANDS, k=num_commands // 2) +
                random.choices(SUSPICIOUS_COMMANDS, k=num_commands // 2))
    random.shuffle(commands)

    return {
        "user_id": user["username"],
        "start_time": start,
        "end_time": end,
        "commands": commands,
        "data_mb": round(random.uniform(10, 100), 2),
        "ip": random.choice(UNKNOWN_IPS) if random.random() > 0.5 else random.choice(KNOWN_IPS),
        "geo": random.choice(ANOMALOUS_GEOS) if random.random() > 0.6 else random.choice(KNOWN_GEOS),
        "anomaly_score": round(random.uniform(45, 72), 1),
        "flagged": True,
        "failed_auth_attempts": random.randint(2, 5),
        "ip_change_flag": random.random() > 0.4,
        "role_escalation_flag": False,
        "session_type": "suspicious",
    }


def _generate_critical_session(user: Dict, base_time: datetime.datetime) -> Dict:
    """Generate a critical session (high threat)."""
    hour = random.choice([0, 1, 2, 3, 4, 23])
    start = base_time.replace(hour=hour, minute=random.randint(0, 59))
    duration = random.randint(5, 60)
    end = start + datetime.timedelta(minutes=duration)

    num_commands = random.randint(50, 200)
    commands = (random.choices(SUSPICIOUS_COMMANDS, k=num_commands // 3) +
                random.choices(CRITICAL_COMMANDS, k=num_commands // 3) +
                random.choices(NORMAL_COMMANDS, k=num_commands // 3))
    random.shuffle(commands)

    return {
        "user_id": user["username"],
        "start_time": start,
        "end_time": end,
        "commands": commands,
        "data_mb": round(random.uniform(100, 2000), 2),
        "ip": random.choice(UNKNOWN_IPS),
        "geo": random.choice(ANOMALOUS_GEOS),
        "anomaly_score": round(random.uniform(75, 98), 1),
        "flagged": True,
        "failed_auth_attempts": random.randint(5, 15),
        "ip_change_flag": True,
        "role_escalation_flag": True,
        "session_type": "critical",
    }


# ---------------------------------------------------------------------------
# Alert Generation
# ---------------------------------------------------------------------------

def _generate_alert(session: Dict, user: Dict) -> Dict:
    """Generate an alert for a flagged session."""
    alert_type = random.choice(ALERT_TYPES)

    # Pre-generate a narrative (will be overwritten by Groq if available)
    narratives = {
        "unusual_login_time": f"User {session['user_id']} logged in at {session['start_time'].strftime('%H:%M')} which deviates significantly from their normal pattern of 9 AM-6 PM access. This off-hours activity combined with elevated data access warrants investigation. Recommend immediate session review and supervisor notification.",
        "excessive_data_export": f"User {session['user_id']} exported {session['data_mb']} MB of data in a single session, exceeding the 95th percentile for their role ({user['role']}). This bulk data transfer pattern is consistent with insider data theft. Recommend blocking further exports and initiating DLP review.",
        "privilege_escalation": f"User {session['user_id']} attempted role escalation during their session, a behaviour flagged by our anomaly model with score {session['anomaly_score']}. Combined with their access from {session['geo']}, this suggests potential credential compromise. Recommend immediate privilege revocation and credential reset.",
        "geo_anomaly": f"User {session['user_id']} connected from {session['geo']}, which is outside their normal geographic profile. This location anomaly, combined with off-hours access, elevates the threat to amber status. Recommend geo-blocking and multi-factor re-authentication.",
        "rapid_command_execution": f"User {session['user_id']} executed {len(session['commands'])} commands in their session, indicating automated or scripted behaviour. The command mix includes sensitive database operations. Recommend session isolation and command-level audit review.",
    }

    narrative = narratives.get(alert_type,
        f"User {session['user_id']} triggered a {alert_type} alert with anomaly score "
        f"{session['anomaly_score']}. The session from {session['geo']} showed {len(session['commands'])} "
        f"commands and {session['data_mb']} MB data access. Recommend enhanced monitoring and supervisor review."
    )

    return {
        "user_id": session["user_id"],
        "session_id": str(uuid.uuid4()),
        "alert_type": alert_type,
        "risk_score": session["anomaly_score"],
        "groq_narrative": narrative,
        "timestamp": session["start_time"],
        "resolved": random.random() > 0.7,
    }


# ---------------------------------------------------------------------------
# Audit Log Generation
# ---------------------------------------------------------------------------

def _generate_audit_entry(users: List[Dict], base_time: datetime.datetime) -> Dict:
    """Generate a synthetic audit log entry."""
    user = random.choice(users)
    action = random.choice(AUDIT_ACTIONS)

    targets = {
        "LOGIN": "auth_system",
        "LOGOUT": "auth_system",
        "QUERY_EXECUTE": random.choice(["customers_db", "transactions_db", "accounts_db"]),
        "DATA_EXPORT": random.choice(["customer_report", "transaction_dump", "audit_data"]),
        "ROLE_CHANGE": random.choice([u["username"] for u in users]),
        "PASSWORD_RESET": user["username"],
        "PERMISSION_GRANT": random.choice([u["username"] for u in users]),
        "SYSTEM_CONFIG_CHANGE": random.choice(["firewall_rules", "db_config", "network_policy"]),
        "ALERT_ACKNOWLEDGED": f"alert_{uuid.uuid4().hex[:8]}",
        "SESSION_TIMEOUT": user["username"],
        "STEP_UP_AUTH": user["username"],
        "CREDENTIAL_ROTATION": user["username"],
        "USER_SUSPEND": random.choice([u["username"] for u in users]),
        "USER_REINSTATE": random.choice([u["username"] for u in users]),
    }

    decisions = ["ALLOW", "ALLOW", "ALLOW", "DENY", "STEP_UP_REQUIRED"]
    decision = random.choice(decisions)

    hour_offset = random.randint(0, 23)
    minute_offset = random.randint(0, 59)
    timestamp = base_time.replace(hour=hour_offset, minute=minute_offset)

    return {
        "actor": user["username"],
        "action": action,
        "target": targets.get(action, "system"),
        "rbac_decision": decision,
        "rationale": f"{'Access granted' if decision == 'ALLOW' else 'Access restricted'} for {action} by {user['username']} (role: {user['role']}). Risk assessment: {'normal' if decision == 'ALLOW' else 'elevated'}.",
        "timestamp": timestamp,
        "event_type": random.choice(["rbac_decision", "system", "security", "audit"]),
    }


# ---------------------------------------------------------------------------
# Behaviour Record Generation
# ---------------------------------------------------------------------------

def _generate_behaviour(session: Dict) -> Dict:
    """Generate a behaviour record from a session."""
    features = anomaly_engine.extract_features(session)
    return {
        "user_id": session["user_id"],
        "feature_vector": features,
        "isolation_score": session["anomaly_score"],
        "timestamp": session["start_time"],
        "model_version": "v1.0-isolation-forest",
    }


# ---------------------------------------------------------------------------
# Main Seeder
# ---------------------------------------------------------------------------

def seed_database(force: bool = False):
    """
    Seed the database with synthetic data.
    Only seeds if database is empty (unless force=True).
    Returns seeding stats.
    """
    # Check if already seeded
    if not force and mongo_client.count_documents("users") > 0:
        # Train ML model on existing sessions so they are loaded in memory after restarts
        existing_sessions = mongo_client.find("sessions")
        if existing_sessions:
            training_data = [anomaly_engine.extract_features(s) for s in existing_sessions]
            anomaly_engine.train_isolation_forest(training_data)
            anomaly_engine.init_online_model()
            for fv in training_data[:100]:
                anomaly_engine.update_online_model(fv)
        else:
            anomaly_engine.init_online_model()
            
        return {
            "status": "already_seeded",
            "users": mongo_client.count_documents("users"),
            "sessions": len(existing_sessions),
            "alerts": mongo_client.count_documents("alerts"),
            "audit_logs": mongo_client.count_documents("audit_logs"),
            "behaviours": mongo_client.count_documents("behaviours"),
        }

    if force:
        for collection in ["users", "sessions", "alerts", "audit_logs", "behaviours"]:
            mongo_client.clear_collection(collection)

    random.seed(42)  # Reproducible data

    # --- 1. Create Users ---
    users = []
    for u in SYNTHETIC_USERS:
        vault_entry = pqc_vault.create_vault_entry(
            user_id=u["username"],
            username=u["username"],
            role=u["role"],
        )
        user_doc = {
            "username": u["username"],
            "role": u["role"],
            "department": u["department"],
            "pqc_key": vault_entry["pqc_public_key"],
            "pqc_fingerprint": vault_entry["pqc_fingerprint"],
            "pqc_vault": vault_entry,
            "risk_score": round(random.uniform(10, 60), 1),
            "created_at": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=random.randint(30, 365)),
            "last_login": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=random.randint(1, 72)),
            "is_suspended": False,
        }
        users.append(user_doc)

    mongo_client.insert_many("users", users)

    # --- 2. Generate Sessions ---
    sessions = []
    now = datetime.datetime.now(datetime.timezone.utc)

    for i in range(500):
        user = random.choice(SYNTHETIC_USERS)
        day_offset = random.randint(0, 6)
        base_time = now - datetime.timedelta(days=day_offset)

        rand = random.random()
        if rand < 0.80:
            session = _generate_normal_session(user, base_time)
        elif rand < 0.95:
            session = _generate_suspicious_session(user, base_time)
        else:
            session = _generate_critical_session(user, base_time)

        sessions.append(session)

    mongo_client.insert_many("sessions", sessions)

    # --- 3. Train ML model on session data ---
    training_data = [anomaly_engine.extract_features(s) for s in sessions]
    anomaly_engine.train_isolation_forest(training_data)
    anomaly_engine.init_online_model()

    # Feed some data through online model
    for features in training_data[:100]:
        anomaly_engine.update_online_model(features)

    # --- 4. Generate Alerts (50) ---
    flagged_sessions = [s for s in sessions if s.get("flagged")]
    alerts = []
    alert_sessions = random.sample(flagged_sessions, min(50, len(flagged_sessions)))
    for session in alert_sessions:
        user = next((u for u in SYNTHETIC_USERS if u["username"] == session["user_id"]), SYNTHETIC_USERS[0])
        alert = _generate_alert(session, user)
        alerts.append(alert)

    mongo_client.insert_many("alerts", alerts)

    # --- 5. Generate Audit Logs (200) ---
    audit_logs = []
    for i in range(200):
        day_offset = random.randint(0, 29)
        base_time = now - datetime.timedelta(days=day_offset)
        entry = _generate_audit_entry(SYNTHETIC_USERS, base_time)
        audit_logs.append(entry)

    mongo_client.insert_many("audit_logs", audit_logs)

    # --- 6. Generate Behaviour Records ---
    behaviours = []
    for session in sessions:
        behaviour = _generate_behaviour(session)
        behaviours.append(behaviour)

    mongo_client.insert_many("behaviours", behaviours)

    return {
        "status": "seeded",
        "users": len(users),
        "sessions": len(sessions),
        "alerts": len(alerts),
        "audit_logs": len(audit_logs),
        "behaviours": len(behaviours),
    }


def generate_live_session() -> Dict:
    """Generate a single new live session for streaming simulation."""
    user = random.choice(SYNTHETIC_USERS)
    now = datetime.datetime.now(datetime.timezone.utc)

    rand = random.random()
    if rand < 0.75:
        session = _generate_normal_session(user, now)
    elif rand < 0.92:
        session = _generate_suspicious_session(user, now)
    else:
        session = _generate_critical_session(user, now)

    # Score with ML models
    features = anomaly_engine.extract_features(session)
    combined_score, risk_level = anomaly_engine.get_combined_score(features)
    session["anomaly_score"] = combined_score
    session["risk_level"] = risk_level

    # Store
    mongo_client.insert_one("sessions", session)

    # Generate behaviour record
    behaviour = _generate_behaviour(session)
    behaviour["isolation_score"] = combined_score
    mongo_client.insert_one("behaviours", behaviour)

    # Generate alert if flagged
    alert = None
    if session.get("flagged") or combined_score > 60:
        alert = _generate_alert(session, user)
        alert["risk_score"] = combined_score
        mongo_client.insert_one("alerts", alert)

    return {
        "session": session,
        "alert": alert,
        "risk_level": risk_level,
        "score": combined_score,
    }


def generate_hndl_event() -> Dict:
    """Generate a simulated Harvest-Now-Decrypt-Later exfiltration event."""
    user = random.choice([u for u in SYNTHETIC_USERS if u["role"] in ["DBA", "NETWORK_ADMIN", "SUPERADMIN"]])
    now = datetime.datetime.now(datetime.timezone.utc)

    event = {
        "user_id": user["username"],
        "role": user["role"],
        "timestamp": now,
        "event_type": "HNDL_INDICATOR",
        "data_volume_gb": round(random.uniform(5, 500), 1),
        "destination_ip": random.choice(UNKNOWN_IPS),
        "destination_geo": random.choice(ANOMALOUS_GEOS),
        "encryption_detected": True,
        "blob_format": random.choice(["encrypted_archive", "binary_blob", "encrypted_dump"]),
        "protocol": random.choice(["SFTP", "HTTPS", "SCP", "FTP"]),
        "duration_minutes": random.randint(5, 120),
        "hndl_indicators": {
            "large_encrypted_transfer": True,
            "unknown_destination": True,
            "off_hours": random.random() > 0.3,
            "bulk_database_access": random.random() > 0.4,
            "pattern_match_score": round(random.uniform(0.7, 0.99), 2),
        },
        "threat_level": random.choice(["HIGH", "CRITICAL"]),
    }

    return event
