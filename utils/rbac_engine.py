"""
SentinelIQ — Risk-Based Access Control (RBAC+) Engine
======================================================
Dynamic privilege scoring with step-up authentication
and auto-suspension capabilities.

Role Hierarchy: SUPERADMIN > DBA > NETWORK_ADMIN > BRANCH_MANAGER > TELLER
"""

import datetime
import secrets
from typing import Dict, Tuple, Optional, List

from utils import groq_client, mongo_client

# ---------------------------------------------------------------------------
# Role Hierarchy
# ---------------------------------------------------------------------------

ROLE_HIERARCHY = {
    "SUPERADMIN": 5,
    "DBA": 4,
    "NETWORK_ADMIN": 3,
    "BRANCH_MANAGER": 2,
    "TELLER": 1,
}

ROLE_COLORS = {
    "SUPERADMIN": "#FF4C4C",
    "DBA": "#FF8C42",
    "NETWORK_ADMIN": "#FFB84D",
    "BRANCH_MANAGER": "#00D4FF",
    "TELLER": "#00C896",
}

ROLE_PERMISSIONS = {
    "SUPERADMIN": [
        "view_all_dashboards", "manage_users", "manage_roles",
        "view_audit_logs", "export_data", "configure_system",
        "manage_pqc_vault", "override_rbac", "view_watchlist",
    ],
    "DBA": [
        "view_all_dashboards", "view_audit_logs", "export_data",
        "manage_database", "view_watchlist", "view_pqc_vault",
    ],
    "NETWORK_ADMIN": [
        "view_all_dashboards", "view_audit_logs",
        "manage_network", "view_watchlist",
    ],
    "BRANCH_MANAGER": [
        "view_branch_dashboard", "view_audit_logs",
        "view_branch_reports",
    ],
    "TELLER": [
        "view_own_dashboard", "view_own_audit_log",
    ],
}

# ---------------------------------------------------------------------------
# Step-Up Auth Thresholds
# ---------------------------------------------------------------------------

STEP_UP_THRESHOLD = 70    # risk_score > 70 → Step-Up Auth
SUSPEND_THRESHOLD = 85    # risk_score > 85 → Auto-Suspend

# ---------------------------------------------------------------------------
# Access Decision Engine
# ---------------------------------------------------------------------------


def evaluate_access(username: str, role: str, risk_score: float,
                    requested_action: str) -> Dict:
    """
    Evaluate an access request based on dynamic risk scoring.
    Returns access decision with rationale.
    """
    decision = {
        "username": username,
        "role": role,
        "risk_score": risk_score,
        "requested_action": requested_action,
        "timestamp": datetime.datetime.now(datetime.timezone.utc),
        "decision": "ALLOW",
        "requires_step_up": False,
        "session_suspended": False,
        "rationale": "",
        "otp_code": None,
    }

    # Check role permissions first
    role_perms = ROLE_PERMISSIONS.get(role, [])
    if requested_action not in role_perms and "override_rbac" not in role_perms:
        decision["decision"] = "DENY"
        decision["rationale"] = (
            f"Role '{role}' does not have permission for '{requested_action}'. "
            f"Required: role with '{requested_action}' permission."
        )
        _log_rbac_decision(decision)
        return decision

    # Risk-based evaluation
    if risk_score > SUSPEND_THRESHOLD:
        decision["decision"] = "DENY"
        decision["session_suspended"] = True
        decision["rationale"] = (
            f"CRITICAL: Risk score {risk_score:.1f} exceeds suspension threshold "
            f"({SUSPEND_THRESHOLD}). Session auto-suspended. All access revoked "
            f"pending security review."
        )
        # Auto-suspend user
        _suspend_user(username, risk_score)

    elif risk_score > STEP_UP_THRESHOLD:
        decision["decision"] = "STEP_UP_REQUIRED"
        decision["requires_step_up"] = True
        decision["otp_code"] = _generate_otp()
        decision["rationale"] = (
            f"ELEVATED RISK: Risk score {risk_score:.1f} exceeds step-up threshold "
            f"({STEP_UP_THRESHOLD}). Step-up authentication required. "
            f"OTP challenge issued."
        )
    else:
        decision["decision"] = "ALLOW"
        decision["rationale"] = (
            f"Access granted. Risk score {risk_score:.1f} is within acceptable "
            f"range for role '{role}'."
        )

    # Generate AI rationale if Groq is available
    try:
        ai_rationale = groq_client.generate_rbac_rationale(
            username, role, risk_score, requested_action, decision["decision"]
        )
        decision["ai_rationale"] = ai_rationale
    except Exception:
        decision["ai_rationale"] = decision["rationale"]

    _log_rbac_decision(decision)
    return decision


def verify_step_up(provided_otp: str, expected_otp: str) -> bool:
    """Verify step-up authentication OTP."""
    return provided_otp == expected_otp


def _generate_otp() -> str:
    """Generate a 6-digit OTP for step-up authentication."""
    return f"{secrets.randbelow(900000) + 100000}"


def _suspend_user(username: str, risk_score: float):
    """Auto-suspend a user session and log to audit."""
    try:
        mongo_client.update_one(
            "users",
            {"username": username},
            {"$set": {"is_suspended": True}}
        )
        mongo_client.log_audit_event(
            actor="SYSTEM",
            action="AUTO_SUSPEND",
            target=username,
            rbac_decision="SUSPEND",
            rationale=f"Auto-suspended due to risk score {risk_score:.1f} > {SUSPEND_THRESHOLD}",
            event_type="rbac_action",
        )
    except Exception:
        pass


def _log_rbac_decision(decision: Dict):
    """Log RBAC decision to audit trail."""
    try:
        mongo_client.log_audit_event(
            actor=decision["username"],
            action=decision["requested_action"],
            target="system_resource",
            rbac_decision=decision["decision"],
            rationale=decision.get("ai_rationale", decision["rationale"]),
            event_type="rbac_decision",
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Role Management Helpers
# ---------------------------------------------------------------------------

def get_role_level(role: str) -> int:
    """Get numeric level for a role."""
    return ROLE_HIERARCHY.get(role, 0)


def get_role_color(role: str) -> str:
    """Get display color for a role."""
    return ROLE_COLORS.get(role, "#FFFFFF")


def get_role_permissions(role: str) -> List[str]:
    """Get list of permissions for a role."""
    return ROLE_PERMISSIONS.get(role, [])


def can_role_access(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    return permission in ROLE_PERMISSIONS.get(role, [])


def get_all_roles() -> List[str]:
    """Get all roles in hierarchy order."""
    return sorted(ROLE_HIERARCHY.keys(), key=lambda r: ROLE_HIERARCHY[r], reverse=True)


def get_risk_action(risk_score: float) -> str:
    """Get recommended action based on risk score."""
    if risk_score > SUSPEND_THRESHOLD:
        return "AUTO_SUSPEND"
    elif risk_score > STEP_UP_THRESHOLD:
        return "STEP_UP_AUTH"
    elif risk_score > 40:
        return "ENHANCED_MONITORING"
    else:
        return "NORMAL_ACCESS"


def get_access_decision_log(limit: int = 100) -> List[Dict]:
    """Get recent RBAC access decisions from audit trail."""
    return mongo_client.find(
        "audit_logs",
        {"event_type": "rbac_decision"},
        sort=[("timestamp", -1)],
        limit=limit,
    )
