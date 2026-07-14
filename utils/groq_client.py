"""
SentinelIQ — Groq API Client
==============================
Wrapper for Groq LLM calls with retry logic, prompt templates,
and graceful fallback when API key is unavailable.

Model: llama-3.3-70b-versatile
"""

import os
import time
import json
from typing import Optional, Dict
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '..', 'config', '.env'))

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
MODEL_ID = "llama-3.3-70b-versatile"
MAX_RETRIES = 3
RETRY_DELAY = 1.0  # seconds

_client = None


def _get_client():
    """Get Groq client singleton."""
    global _client
    if _client is not None:
        return _client
    
    # Reload environment variables dynamically
    load_dotenv(os.path.join(os.path.dirname(__file__), '..', 'config', '.env'), override=True)
    api_key = os.getenv("GROQ_API_KEY", "")
    
    if not api_key or api_key == "your_groq_api_key_here":
        return None
    try:
        from groq import Groq
        _client = Groq(api_key=api_key)
        return _client
    except Exception:
        return None


def is_groq_available() -> bool:
    """Check if Groq API is configured and reachable."""
    return _get_client() is not None


def call_groq(prompt: str, system_prompt: str = "You are a banking security analyst.",
              max_tokens: int = 500, temperature: float = 0.7) -> str:
    """
    Call Groq LLM with retry logic.
    Returns the response text or a fallback message.
    """
    client = _get_client()
    if client is None:
        return _get_fallback_response(prompt)

    for attempt in range(MAX_RETRIES):
        try:
            response = client.chat.completions.create(
                model=MODEL_ID,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return response.choices[0].message.content
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
            else:
                return f"[AI Analysis Unavailable — API Error: {str(e)[:100]}]\n\n{_get_fallback_response(prompt)}"

    return _get_fallback_response(prompt)


# ---------------------------------------------------------------------------
# Prompt Templates
# ---------------------------------------------------------------------------

def generate_threat_narrative(username: str, role: str, score: float,
                               behaviour: Dict) -> str:
    """Generate AI threat brief for an anomaly detection."""
    prompt = (
        f"You are a banking security analyst. A privileged user '{username}' "
        f"with role '{role}' triggered anomaly score {score:.1f}/100. "
        f"Behaviour: {json.dumps(behaviour)}. "
        f"Generate a 3-sentence threat narrative and recommend immediate action. "
        f"Be specific, concise, professional."
    )
    return call_groq(prompt)


def generate_rbac_rationale(username: str, role: str, risk_score: float,
                             action: str, decision: str) -> str:
    """Generate AI rationale for an RBAC+ access decision."""
    prompt = (
        f"You are a banking security analyst reviewing access control decisions. "
        f"User '{username}' (role: {role}) with current risk score {risk_score:.1f}/100 "
        f"attempted action: '{action}'. Decision: {decision}. "
        f"Generate a 2-sentence professional rationale explaining this access decision "
        f"and any recommended follow-up."
    )
    return call_groq(prompt, max_tokens=300)


def generate_forensic_narrative(event: Dict) -> str:
    """Generate plain-English forensic explanation of an audit event."""
    prompt = (
        f"You are a banking forensic analyst. Explain this audit event in plain English "
        f"for a compliance officer. Event details: {json.dumps(event, default=str)}. "
        f"Provide a 3-sentence explanation covering: what happened, why it matters, "
        f"and what should be investigated further."
    )
    return call_groq(prompt, max_tokens=400)


def generate_hndl_analysis(exfil_event: Dict) -> str:
    """Generate AI analysis of a potential Harvest-Now-Decrypt-Later attack."""
    prompt = (
        f"You are a quantum-aware cybersecurity analyst at a bank. "
        f"Analyze this potential Harvest-Now-Decrypt-Later (HNDL) data exfiltration event: "
        f"{json.dumps(exfil_event, default=str)}. "
        f"Explain in 3 sentences: why this looks like a quantum harvest attempt, "
        f"what the risk is to encrypted banking data, and what immediate countermeasures "
        f"should be taken."
    )
    return call_groq(prompt, max_tokens=400)


def generate_risk_summary(username: str, role: str, risk_data: Dict) -> str:
    """Generate AI summary for watchlist risk profile."""
    prompt = (
        f"You are a banking insider threat analyst. Summarize the risk profile of "
        f"privileged user '{username}' (role: {role}). "
        f"Risk data: {json.dumps(risk_data, default=str)}. "
        f"Provide a 3-sentence risk assessment covering: overall threat level, "
        f"key behavioural indicators, and recommended monitoring actions."
    )
    return call_groq(prompt, max_tokens=350)


def generate_dashboard_insight(stats: Dict) -> str:
    """Generate AI insight for the main dashboard."""
    prompt = (
        f"You are a banking CISO's AI assistant. Based on today's security metrics: "
        f"{json.dumps(stats, default=str)}, "
        f"provide a 3-sentence executive summary of the current insider threat landscape. "
        f"Highlight the most critical concern and recommend one priority action."
    )
    return call_groq(prompt, max_tokens=350)


# ---------------------------------------------------------------------------
# Fallback Responses (when Groq API is unavailable)
# ---------------------------------------------------------------------------

_FALLBACK_RESPONSES = {
    "threat": (
        "⚠️ **AI Analysis (Offline Mode)**: This user's behaviour deviates significantly "
        "from their established baseline. The combination of unusual access timing and "
        "elevated data transfer volumes suggests potential insider threat activity. "
        "**Recommendation**: Initiate enhanced monitoring and verify activity with the "
        "user's direct supervisor within 24 hours."
    ),
    "rbac": (
        "⚠️ **AI Rationale (Offline Mode)**: Access decision based on dynamic risk scoring. "
        "The user's current risk profile warrants the applied access control measure. "
        "Continue monitoring for further anomalous activity."
    ),
    "forensic": (
        "⚠️ **AI Forensics (Offline Mode)**: This event represents a security-relevant "
        "action in the privileged access monitoring system. The activity has been logged "
        "for compliance review. Further investigation may be warranted based on the "
        "event context and the actor's risk profile."
    ),
    "hndl": (
        "⚠️ **AI HNDL Analysis (Offline Mode)**: This data exfiltration pattern is "
        "consistent with Harvest-Now-Decrypt-Later attack signatures. Large encrypted "
        "data transfers to external endpoints should be treated as potential quantum "
        "harvest attempts. **Recommendation**: Block the destination IP and initiate "
        "a full forensic review of the data accessed."
    ),
    "risk": (
        "⚠️ **AI Risk Summary (Offline Mode)**: This user shows elevated risk indicators "
        "based on recent behavioral anomalies. Cumulative risk scoring suggests increased "
        "monitoring is warranted. Review access patterns and consider temporary privilege "
        "reduction pending investigation."
    ),
    "dashboard": (
        "⚠️ **AI Insight (Offline Mode)**: Current threat landscape shows normal activity "
        "levels with isolated anomalies requiring attention. Privileged access patterns "
        "are within expected parameters for most users. **Priority**: Review flagged "
        "high-risk sessions in the Anomaly Engine for detailed analysis."
    ),
}


def _get_fallback_response(prompt: str) -> str:
    """Return an appropriate fallback response based on prompt content."""
    prompt_lower = prompt.lower()
    if "threat narrative" in prompt_lower or "anomaly score" in prompt_lower:
        return _FALLBACK_RESPONSES["threat"]
    elif "access decision" in prompt_lower or "rbac" in prompt_lower:
        return _FALLBACK_RESPONSES["rbac"]
    elif "forensic" in prompt_lower or "audit event" in prompt_lower:
        return _FALLBACK_RESPONSES["forensic"]
    elif "hndl" in prompt_lower or "harvest-now" in prompt_lower or "quantum harvest" in prompt_lower:
        return _FALLBACK_RESPONSES["hndl"]
    elif "risk profile" in prompt_lower or "risk assessment" in prompt_lower:
        return _FALLBACK_RESPONSES["risk"]
    elif "executive summary" in prompt_lower or "ciso" in prompt_lower:
        return _FALLBACK_RESPONSES["dashboard"]
    else:
        return _FALLBACK_RESPONSES["threat"]
