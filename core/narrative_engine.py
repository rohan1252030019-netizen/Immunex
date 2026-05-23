"""
IMMUNEX Narrative Engine
========================
Generates human-readable attack narratives from CorrelatedAttack objects.

Output for each correlated attack:
1. Chronological attack story (paragraph)
2. Impacted assets table
3. Attacker progression summary (bullet timeline)
4. Threat severity explanation
5. Recommended countermeasures

The engine is fully offline and requires no external LLM —
it uses deterministic template-driven text generation with
contextual data injected from the CorrelatedAttack.
"""

from __future__ import annotations

import textwrap
from datetime import datetime
from typing import Optional

from core.markov_predictor import STAGES, STAGE_INDEX
from utils.constants import SEVERITY_ORDER
from utils.logger import log

# ─── Severity Thresholds ──────────────────────────────────────────────────────

SEVERITY_RISK_MAP: list[tuple[float, str]] = [
    (0.80, "CRITICAL"),
    (0.60, "HIGH"),
    (0.40, "MEDIUM"),
    (0.20, "LOW"),
    (0.00, "INFO"),
]


def _risk_to_severity(risk: float) -> str:
    for threshold, sev in SEVERITY_RISK_MAP:
        if risk >= threshold:
            return sev
    return "INFO"


# ─── Stage Descriptions ───────────────────────────────────────────────────────

STAGE_DESCRIPTIONS: dict[str, str] = {
    "Reconnaissance": (
        "conducted reconnaissance to map the network topology, "
        "identify live hosts, and enumerate exposed services"
    ),
    "Credential_Access": (
        "attempted to obtain valid credentials through brute-force "
        "or password-spray attacks against authentication systems"
    ),
    "Lateral_Movement": (
        "moved laterally through the network, pivoting across internal "
        "hosts to extend their foothold and reach sensitive assets"
    ),
    "Execution": (
        "executed malicious payloads including PowerShell scripts "
        "and suspicious process chains to establish control"
    ),
    "Persistence": (
        "established persistence mechanisms such as registry modifications "
        "and scheduled tasks to maintain access across reboots"
    ),
    "Privilege_Escalation": (
        "escalated privileges to gain elevated system access, "
        "enabling deeper compromise of critical assets"
    ),
    "Exfiltration": (
        "began exfiltrating data from compromised systems, "
        "using covert channels to transfer sensitive information externally"
    ),
}

STAGE_COUNTERMEASURES: dict[str, list[str]] = {
    "Reconnaissance": [
        "Enable network-level port-scan detection and alerting",
        "Implement honeypots on unused IP ranges",
        "Review firewall rules to minimise exposed attack surface",
    ],
    "Credential_Access": [
        "Enforce multi-factor authentication on all user accounts",
        "Implement account lockout policies after failed login attempts",
        "Deploy credential-stuffing monitoring on authentication endpoints",
    ],
    "Lateral_Movement": [
        "Enforce network segmentation and micro-segmentation policies",
        "Restrict lateral protocols (RDP, SMB) between workstations",
        "Deploy deception assets to detect internal pivoting",
    ],
    "Execution": [
        "Enable application whitelisting to block unsigned executables",
        "Restrict PowerShell and scripting engines with Constrained Language Mode",
        "Deploy endpoint behavioural monitoring with process lineage tracking",
    ],
    "Persistence": [
        "Monitor registry run keys, scheduled tasks, and startup paths",
        "Implement file integrity monitoring on system directories",
        "Audit auto-start locations regularly",
    ],
    "Privilege_Escalation": [
        "Apply least-privilege principles to all service and user accounts",
        "Audit SUID/SGID binaries and privileged process list",
        "Enable Windows Credential Guard or Linux PAM hardening",
    ],
    "Exfiltration": [
        "Deploy DLP controls on outbound network traffic",
        "Monitor DNS traffic for tunnelling patterns",
        "Restrict egress to approved endpoints via firewall policy",
    ],
}

NEXT_STAGE_WARNINGS: dict[str, str] = {
    "Reconnaissance":       "The attacker may soon attempt credential-based intrusion.",
    "Credential_Access":    "Lateral movement is likely imminent — monitor internal traffic.",
    "Lateral_Movement":     "Expect malicious code execution on compromised hosts.",
    "Execution":            "Persistence mechanisms may be planted on affected systems.",
    "Persistence":          "Privilege escalation is the probable next step.",
    "Privilege_Escalation": "Data exfiltration may begin — activate DLP controls immediately.",
    "Exfiltration":         "Active exfiltration detected — contain and isolate immediately.",
}


# ─── Narrative Engine ─────────────────────────────────────────────────────────

class NarrativeEngine:
    """
    Converts a CorrelatedAttack into structured human-readable intelligence.

    All methods are pure functions of their inputs — the engine is stateless
    and can be called concurrently without locking.
    """

    def __init__(self) -> None:
        log.info("NarrativeEngine initialised")

    # ── Primary Entry Point ───────────────────────────────────────────────────

    def generate(self, correlated_attack: object) -> dict:
        """
        Generate a full attack narrative for a CorrelatedAttack.

        Args:
            correlated_attack: A CorrelatedAttack instance from CorrelationEngine.

        Returns:
            {
                campaign_id        : str
                severity           : str
                executive_summary  : str
                attack_story       : str
                timeline           : list[dict]
                impacted_assets    : list[str]
                countermeasures    : list[str]
                prediction_warning : str
                raw_stats          : dict
            }
        """
        ca = correlated_attack

        severity = _risk_to_severity(ca.risk_score)
        story    = self._build_story(ca)
        timeline = self._build_timeline(ca)
        assets   = self._build_asset_list(ca)
        measures = self._build_countermeasures(ca)
        warning  = self._build_prediction_warning(ca)
        summary  = self._build_executive_summary(ca, severity)

        narrative = {
            "campaign_id":        ca.campaign_id,
            "severity":           severity,
            "executive_summary":  summary,
            "attack_story":       story,
            "timeline":           timeline,
            "impacted_assets":    assets,
            "countermeasures":    measures,
            "prediction_warning": warning,
            "raw_stats": {
                "attacker_ip":           ca.attacker_ip,
                "target_count":          len(ca.target_ips),
                "stages_observed":       ca.stages_observed,
                "predicted_next_stage":  ca.predicted_next_stage,
                "prediction_confidence": round(ca.prediction_confidence, 4),
                "risk_score":            round(ca.risk_score, 4),
                "event_count":           len(ca.decisions),
            },
        }

        log.info(
            "NarrativeEngine: narrative generated",
            campaign_id=ca.campaign_id,
            severity=severity,
            stages=ca.stages_observed,
        )

        return narrative

    def format_text(self, narrative: dict) -> str:
        """
        Render a narrative dict as a formatted terminal-friendly text report.
        """
        sep   = "═" * 80
        thin  = "─" * 80
        lines = [
            sep,
            f"  IMMUNEX THREAT INTELLIGENCE REPORT",
            f"  Campaign: {narrative['campaign_id']}  │  Severity: {narrative['severity']}",
            sep,
            "",
            "[ EXECUTIVE SUMMARY ]",
            textwrap.fill(narrative["executive_summary"], width=78),
            "",
            "[ ATTACK STORY ]",
            textwrap.fill(narrative["attack_story"], width=78),
            "",
            "[ ATTACK TIMELINE ]",
        ]

        for entry in narrative["timeline"]:
            ts = entry.get("timestamp", "")
            if hasattr(ts, "strftime"):
                ts = ts.strftime("%H:%M:%S")
            lines.append(f"  {ts:12}  [{entry['stage']:25}]  {entry['description']}")

        lines += [
            "",
            "[ IMPACTED ASSETS ]",
        ]
        for asset in narrative["impacted_assets"]:
            lines.append(f"  • {asset}")

        lines += [
            "",
            "[ RECOMMENDED COUNTERMEASURES ]",
        ]
        for cm in narrative["countermeasures"]:
            lines.append(f"  ✓ {cm}")

        lines += [
            "",
            "[ THREAT PREDICTION ]",
            f"  ⚠  {narrative['prediction_warning']}",
            f"     Next predicted stage : {narrative['raw_stats']['predicted_next_stage']}",
            f"     Prediction confidence: {narrative['raw_stats']['prediction_confidence']:.1%}",
            "",
            thin,
        ]

        return "\n".join(lines)

    # ── Private Builders ──────────────────────────────────────────────────────

    def _build_executive_summary(self, ca: object, severity: str) -> str:
        n_stages  = len(set(ca.stages_observed))
        n_targets = len(ca.target_ips)
        latest    = ca.stages_observed[-1] if ca.stages_observed else "unknown"
        duration  = ca.graph_chain.get("end_time")
        start_t   = ca.graph_chain.get("start_time")

        duration_str = ""
        if duration and start_t:
            secs = (duration - start_t).total_seconds()
            if secs < 60:
                duration_str = f" over {int(secs)} seconds"
            else:
                duration_str = f" over {int(secs/60)} minutes"

        return (
            f"A {severity}-severity multi-stage intrusion campaign (ID: {ca.campaign_id}) "
            f"has been detected originating from {ca.attacker_ip}{duration_str}. "
            f"The attacker has progressed through {n_stages} distinct kill-chain stage(s) "
            f"and targeted {n_targets} internal asset(s). "
            f"The most recent observed activity is {latest.replace('_', ' ')}. "
            f"Immediate investigation and containment are recommended."
        )

    def _build_story(self, ca: object) -> str:
        if not ca.stages_observed:
            return f"Attacker {ca.attacker_ip} triggered anomaly detections with no clear kill-chain progression."

        parts: list[str] = []
        parts.append(
            f"Beginning at {ca.graph_chain.get('start_time', datetime.utcnow()).strftime('%H:%M:%S UTC')}, "
            f"threat actor operating from {ca.attacker_ip} "
        )

        for i, stage in enumerate(ca.stages_observed):
            desc = STAGE_DESCRIPTIONS.get(stage, f"performed {stage.replace('_', ' ').lower()}")
            if i == 0:
                parts.append(desc)
            elif i == len(ca.stages_observed) - 1:
                parts.append(f"Finally, the attacker {desc}")
            else:
                connectors = ["Subsequently, they", "The attacker then", "Moving further, the actor"]
                connector = connectors[i % len(connectors)]
                parts.append(f"{connector} {desc}")

        target_str = (
            f"Affected targets include: {', '.join(list(ca.target_ips)[:5])}."
            if ca.target_ips else ""
        )

        return " ".join(parts) + ". " + target_str

    def _build_timeline(self, ca: object) -> list[dict]:
        timeline: list[dict] = []

        for stage in ca.stages_observed:
            ts = ca.stage_timestamps.get(stage, datetime.utcnow())
            # Find a representative event for this stage
            stage_events = [
                d for d in ca.decisions
                if hasattr(d, "event_type")
            ]
            event_type = stage_events[0].event_type if stage_events else stage

            timeline.append({
                "stage":       stage,
                "timestamp":   ts,
                "description": STAGE_DESCRIPTIONS.get(stage, stage.replace("_", " ")),
                "event_type":  event_type,
            })

        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])
        return timeline

    def _build_asset_list(self, ca: object) -> list[str]:
        assets: list[str] = []
        for ip in ca.target_ips:
            assets.append(f"Host {ip}")

        # Also pull from graph_chain
        for asset_node in ca.graph_chain.get("target_assets", []):
            if asset_node not in assets:
                assets.append(asset_node)

        return assets[:20]  # cap display

    def _build_countermeasures(self, ca: object) -> list[str]:
        measures: list[str] = []
        seen: set[str] = set()

        for stage in ca.stages_observed:
            for cm in STAGE_COUNTERMEASURES.get(stage, []):
                if cm not in seen:
                    seen.add(cm)
                    measures.append(cm)

        # Always include a containment measure
        containment = f"Immediately isolate host {ca.attacker_ip} pending investigation"
        if containment not in seen:
            measures.insert(0, containment)

        return measures

    def _build_prediction_warning(self, ca: object) -> str:
        warning = NEXT_STAGE_WARNINGS.get(
            ca.predicted_next_stage,
            f"Predicted next stage: {ca.predicted_next_stage.replace('_', ' ')}",
        )
        conf_pct = ca.prediction_confidence * 100
        return f"{warning} (confidence: {conf_pct:.0f}%)"
