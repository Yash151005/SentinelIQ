"""
SentinelIQ — Anomaly Detection Engine
=======================================
Dual-model architecture:
  1. Isolation Forest (scikit-learn) — batch-trained on synthetic data
  2. HalfSpaceTrees (River) — online learning, updates per-session

Features:
  - hour_of_login, commands_per_min, data_exported_mb,
    failed_auth_attempts, ip_change_flag, role_escalation_flag
"""

import numpy as np
import datetime
from typing import Dict, List, Tuple, Optional

# ---------------------------------------------------------------------------
# Isolation Forest (Batch Model)
# ---------------------------------------------------------------------------

_isolation_forest = None
_scaler = None
_feature_names = [
    "hour_of_login",
    "commands_per_min",
    "data_exported_mb",
    "failed_auth_attempts",
    "ip_change_flag",
    "role_escalation_flag",
]


def get_feature_names() -> List[str]:
    """Return the feature names used by the anomaly model."""
    return _feature_names.copy()


def train_isolation_forest(data: List[Dict]) -> dict:
    """
    Train Isolation Forest on synthetic/historical data.
    Returns training metrics.
    """
    global _isolation_forest, _scaler
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    if not data:
        return {"status": "error", "message": "No training data provided"}

    X = np.array([[d.get(f, 0) for f in _feature_names] for d in data])

    _scaler = StandardScaler()
    X_scaled = _scaler.fit_transform(X)

    _isolation_forest = IsolationForest(
        n_estimators=150,
        contamination=0.15,
        random_state=42,
        max_samples='auto',
        n_jobs=-1,
    )
    _isolation_forest.fit(X_scaled)

    # Get anomaly scores for training data
    raw_scores = _isolation_forest.decision_function(X_scaled)
    predictions = _isolation_forest.predict(X_scaled)

    n_anomalies = int(np.sum(predictions == -1))
    n_normal = int(np.sum(predictions == 1))

    return {
        "status": "trained",
        "samples": len(data),
        "features": len(_feature_names),
        "anomalies_detected": n_anomalies,
        "normal_detected": n_normal,
        "contamination_rate": round(n_anomalies / len(data) * 100, 1),
        "model_type": "IsolationForest",
        "n_estimators": 150,
    }


def predict_isolation_forest(features: Dict) -> Tuple[float, str]:
    """
    Predict anomaly score for a single session.
    Returns (score_0_to_100, risk_level).
    """
    global _isolation_forest, _scaler

    if _isolation_forest is None or _scaler is None:
        # Return a default mid-range score if model not trained
        return 50.0, "AMBER"

    X = np.array([[features.get(f, 0) for f in _feature_names]])
    X_scaled = _scaler.transform(X)

    # decision_function: lower = more anomalous (negative = outlier)
    raw_score = _isolation_forest.decision_function(X_scaled)[0]

    # Normalize to 0-100 scale (invert: lower raw = higher risk)
    # Typical range: [-0.5, 0.5] → map to [0, 100]
    normalized = max(0, min(100, 50 - raw_score * 100))

    risk_level = _classify_risk(normalized)
    return round(normalized, 1), risk_level


def _classify_risk(score: float) -> str:
    """Classify risk score into GREEN/AMBER/RED."""
    if score <= 40:
        return "GREEN"
    elif score <= 70:
        return "AMBER"
    else:
        return "RED"


def get_risk_color(level: str) -> str:
    """Get hex color for risk level."""
    return {
        "GREEN": "#00C896",
        "AMBER": "#FFB84D",
        "RED": "#FF4C4C",
    }.get(level, "#FFFFFF")


# ---------------------------------------------------------------------------
# River Online Learning Model (HalfSpaceTrees)
# ---------------------------------------------------------------------------

_online_model = None
_online_samples_processed = 0
_online_anomalies_detected = 0


def init_online_model():
    """Initialize the River online anomaly detection model."""
    global _online_model, _online_samples_processed, _online_anomalies_detected
    try:
        from river import anomaly
        _online_model = anomaly.HalfSpaceTrees(
            n_trees=15,
            height=6,
            window_size=100,
            seed=42,
        )
        _online_samples_processed = 0
        _online_anomalies_detected = 0
        return True
    except ImportError:
        _online_model = None
        return False


def update_online_model(features: Dict) -> Tuple[float, str]:
    """
    Score and learn from a new session (online learning).
    Returns (score_0_to_100, risk_level).
    """
    global _online_model, _online_samples_processed, _online_anomalies_detected

    if _online_model is None:
        if not init_online_model():
            return predict_isolation_forest(features)

    # Prepare features for River (uses dict input)
    x = {f: float(features.get(f, 0)) for f in _feature_names}

    # Score then learn
    raw_score = _online_model.score_one(x)
    _online_model.learn_one(x)

    _online_samples_processed += 1

    # River HalfSpaceTrees score: higher = more anomalous (0-1 range)
    normalized = round(min(100, raw_score * 100), 1)

    risk_level = _classify_risk(normalized)
    if risk_level == "RED":
        _online_anomalies_detected += 1

    return normalized, risk_level


def get_combined_score(features: Dict) -> Tuple[float, str]:
    """
    Get combined anomaly score from both models.
    Weighted: 60% Isolation Forest + 40% Online Model.
    """
    if_score, _ = predict_isolation_forest(features)
    ol_score, _ = update_online_model(features)

    combined = 0.6 * if_score + 0.4 * ol_score
    combined = round(combined, 1)
    risk_level = _classify_risk(combined)

    return combined, risk_level


def get_online_model_stats() -> Dict:
    """Get online model statistics."""
    return {
        "model_type": "HalfSpaceTrees (River)",
        "samples_processed": _online_samples_processed,
        "anomalies_detected": _online_anomalies_detected,
        "status": "active" if _online_model is not None else "not_initialized",
        "n_trees": 15,
        "window_size": 100,
    }


def get_model_status() -> Dict:
    """Get combined model status."""
    return {
        "isolation_forest": {
            "trained": _isolation_forest is not None,
            "type": "IsolationForest (scikit-learn)",
            "n_estimators": 150 if _isolation_forest else 0,
        },
        "online_model": get_online_model_stats(),
        "feature_names": _feature_names,
        "risk_thresholds": {
            "GREEN": "0-40",
            "AMBER": "41-70",
            "RED": "71-100",
        },
    }


# ---------------------------------------------------------------------------
# Feature extraction from session data
# ---------------------------------------------------------------------------

def extract_features(session: Dict) -> Dict:
    """Extract ML features from a raw session document."""
    start_time = session.get("start_time", datetime.datetime.now(datetime.timezone.utc))
    if isinstance(start_time, datetime.datetime):
        hour = start_time.hour
    else:
        hour = 12  # default

    commands = session.get("commands", [])
    duration_min = 30  # default duration
    end_time = session.get("end_time")
    if isinstance(start_time, datetime.datetime) and isinstance(end_time, datetime.datetime):
        diff = (end_time - start_time).total_seconds() / 60
        if diff > 0:
            duration_min = diff

    return {
        "hour_of_login": hour,
        "commands_per_min": round(len(commands) / max(1, duration_min), 2),
        "data_exported_mb": session.get("data_mb", 0),
        "failed_auth_attempts": session.get("failed_auth_attempts", 0),
        "ip_change_flag": 1 if session.get("ip_change_flag", False) else 0,
        "role_escalation_flag": 1 if session.get("role_escalation_flag", False) else 0,
    }
