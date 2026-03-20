"""
TrustCore Sentinel X — Response Engine
Generates automated defensive playbook actions based on threat level.
In production, these would trigger real SOAR integrations.
"""

from models.schemas import ThreatLevel, AutomatedResponse
from typing import List, Dict


# ── Response Playbooks ────────────────────────────────────────────────────────

PLAYBOOKS: Dict[ThreatLevel, List[str]] = {
    ThreatLevel.SAFE: [
        "LOG: Event recorded in audit trail",
        "MONITOR: Continue passive monitoring",
    ],
    ThreatLevel.LOW: [
        "LOG: Event recorded with LOW severity tag",
        "ALERT: Created analyst review ticket (P4)",
        "MONITOR: Enhanced logging enabled for source entity",
    ],
    ThreatLevel.MEDIUM: [
        "LOG: Event recorded with MEDIUM severity tag",
        "ALERT: Created analyst review ticket (P3)",
        "THROTTLE: Rate-limit applied to source (10% bandwidth cap)",
        "NOTIFY: Security team Slack channel notified",
        "WATCHLIST: Source added to 24-hour watchlist",
    ],
    ThreatLevel.HIGH: [
        "LOG: Event recorded with HIGH severity tag",
        "ALERT: Pager duty triggered (P2 — 15-min response SLA)",
        "BLOCK: Firewall rule deployed to block source IP",
        "QUARANTINE: Associated emails moved to quarantine",
        "NOTIFY: CISO dashboard updated",
        "TRACE: Initiated forensic packet capture",
    ],
    ThreatLevel.CRITICAL: [
        "LOG: Event recorded with CRITICAL severity tag — immutable audit log",
        "ALERT: Pager duty triggered (P1 — 5-min response SLA)",
        "ISOLATE: Network segment isolation initiated",
        "BLOCK: Firewall rules deployed across all perimeters",
        "QUARANTINE: All associated communications quarantined",
        "NOTIFY: Exec team, CISO, and SOC on-call alerted via SMS + call",
        "TRACE: Full memory dump and packet capture initiated",
        "REPORT: Automated incident report created (INC-XXXXXXX)",
        "ESCALATE: Ready for law enforcement escalation if confirmed",
    ],
}


def get_playbook_actions(threat_level: ThreatLevel, automated_response: AutomatedResponse) -> List[str]:
    """Returns the list of automated actions for a given threat level."""
    return PLAYBOOKS.get(threat_level, ["LOG: Event recorded"])


def format_response_summary(
    risk_score: float,
    threat_level: ThreatLevel,
    automated_response: AutomatedResponse,
    summary_text: str,
) -> str:
    """Generates a human-readable incident summary string."""
    bar_filled = int(risk_score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    return (
        f"[{threat_level.value}] Risk Score: {risk_score:.1f}/100  |{bar}|\n"
        f"Action: {automated_response.value}\n"
        f"Assessment: {summary_text}"
    )
