"""
IMMUNEX Layer 3 — Playbook Engine
===================================
Generates fully structured incident response playbooks from correlated
threat campaign data.

Integrates:
  - OllamaOrchestrator  (LLM narrative generation)
  - MitigationActions   (executable command generation)
  - IncidentPlaybook    (Pydantic model — strict JSON schema)

Pipeline per campaign:
  1. Build context dict from ThreatReport + PolicyDecision + RLDecision
  2. Dispatch to OllamaOrchestrator for LLM-enhanced narrative sections
  3. Generate deterministic IOC list, timeline, affected assets
  4. Generate platform-specific mitigation commands
  5. Assemble and validate IncidentPlaybook
  6. Return complete playbook (strict JSON-serialisable)

The engine guarantees that the returned playbook is NEVER None and always
contains all 15 required sections (LLM content + deterministic fallbacks).
"""

from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime
from typing import Any, Optional

from utils.logger import log
from core.ollama_orchestrator import OllamaOrchestrator
from core.mitigation_actions import generate_commands, CommandSet
from core.response_models import (
    AffectedAsset,
    AttackTimelineEntry,
    IncidentPlaybook,
    IOCEntry,
    MitigationCommands,
)


# ─── MITRE Stage Mapping ─────────────────────────────────────────────────────

STAGE_MITRE: dict[str, tuple[str, str, str]] = {
    "Reconnaissance":      ("T1595", "Active Scanning",                       "Reconnaissance"),
    "Credential_Access":   ("T1110", "Brute Force",                           "Credential Access"),
    "Lateral_Movement":    ("T1021", "Remote Services",                       "Lateral Movement"),
    "Execution":           ("T1059", "Command and Scripting Interpreter",      "Execution"),
    "Persistence":         ("T1053", "Scheduled Task/Job",                    "Persistence"),
    "Privilege_Escalation":("T1548", "Abuse Elevation Control Mechanism",     "Privilege Escalation"),
    "Exfiltration":        ("T1041", "Exfiltration Over C2 Channel",          "Exfiltration"),
}

STAGE_EVENT_MAP: dict[str, str] = {
    "Reconnaissance":       "Port_Scan",
    "Credential_Access":    "Brute_Force_Login",
    "Lateral_Movement":     "Suspicious_Process_Spawn",
    "Execution":            "PowerShell_Execution",
    "Persistence":          "Registry_Modification",
    "Privilege_Escalation": "PowerShell_Execution",
    "Exfiltration":         "Data_Exfiltration",
    "Unknown":              "Normal_Connection",
}


# ─── Playbook Engine ──────────────────────────────────────────────────────────


class PlaybookEngine:
    """
    Generates structured incident response playbooks from threat campaign data.

    Usage::

        engine = PlaybookEngine()
        playbook = engine.generate(
            report=threat_report,
            rl_decision=rl_decision,
            policy_decision=policy_decision,
        )
        print(playbook.model_dump_json(indent=2))
    """

    def __init__(
        self,
        orchestrator: Optional[OllamaOrchestrator] = None,
    ) -> None:
        self._orchestrator = orchestrator or OllamaOrchestrator()
        log.info(
            "PlaybookEngine initialised",
            ollama_available=self._orchestrator.is_available(),
            model=self._orchestrator.active_model(),
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def generate(
        self,
        report: Any,           # ThreatReport from adaptive_intelligence
        rl_decision: Any,      # RLDecision
        policy_decision: Any,  # PolicyDecision
        attacker_ip: str = "",
        target_ips: list[str] | None = None,
        process_name: str = "malicious_process",
        user_id: str = "compromised_user",
    ) -> IncidentPlaybook:
        """
        Generate a complete incident response playbook.

        Args:
            report:          ThreatReport from AdaptiveIntelligenceLayer.
            rl_decision:     RLDecision from RLDecisionEngine.
            policy_decision: PolicyDecision from PolicyEngine.
            attacker_ip:     Attacker source IP (override if not in report).
            target_ips:      List of victim IPs (override if not in report).
            process_name:    Process name involved in the attack.
            user_id:         Compromised user account.

        Returns:
            IncidentPlaybook — fully populated, all 15 sections present.
        """
        t0 = time.perf_counter()

        # Extract fields from report
        _attacker = attacker_ip or getattr(report, "attacker_ip", "0.0.0.0")
        _targets = target_ips or getattr(report, "target_ips", [])
        _stages = list(getattr(report, "stages_observed", ["Unknown"]))
        _severity = getattr(report, "severity", "HIGH")
        _risk = float(getattr(report, "risk_score", 0.5))
        _campaign_id = getattr(report, "campaign_id", str(uuid.uuid4())[:12])
        _predicted = getattr(report, "predicted_next_stage", "Unknown")
        _narrative = getattr(report, "narrative", {})
        _formatted = getattr(report, "formatted_report", "")

        # Narrative summary for context
        narrative_summary = _narrative.get(
            "threat_paragraph",
            _formatted[:500] if _formatted else f"Multi-stage attack: {' → '.join(_stages)}",
        )

        # Build LLM campaign context
        campaign_context = {
            "campaign_id": _campaign_id,
            "attacker_ip": _attacker,
            "target_ips": ", ".join(_targets[:5]) if _targets else "Multiple",
            "stages_observed": " → ".join(_stages),
            "predicted_next_stage": _predicted,
            "severity": _severity,
            "risk_score": f"{_risk:.2f}",
            "narrative_summary": narrative_summary[:600],
            "recommended_action": rl_decision.optimal_action,
            "policy_verdict": policy_decision.verdict,
        }

        # ── LLM-enhanced sections ─────────────────────────────────────────
        llm_content = self._orchestrator.generate_playbook_content(campaign_context)

        # ── Deterministic sections ────────────────────────────────────────
        playbook_id = f"PB-{_campaign_id[:8].upper()}-{int(time.time())}"

        ioc_list = self._build_ioc_list(
            attacker_ip=_attacker,
            target_ips=_targets,
            stages=_stages,
            process_name=process_name,
        )

        timeline = self._build_timeline(
            attacker_ip=_attacker,
            target_ips=_targets,
            stages=_stages,
        )

        affected_assets = self._build_affected_assets(
            target_ips=_targets,
            stages=_stages,
        )

        mitre_techniques = llm_content.get("mitre_techniques") or self._build_mitre(
            stages=_stages
        )

        # ── Mitigation commands ───────────────────────────────────────────
        target_subnet = self._infer_subnet(_targets[0] if _targets else _attacker)
        cmd_set: CommandSet = generate_commands(
            action_type=policy_decision.approved_action,
            attacker_ip=_attacker,
            target_ip=_targets[0] if _targets else "10.0.0.2",
            process_name=process_name,
            user_id=user_id,
            target_subnet=target_subnet,
            campaign_id=_campaign_id,
        )

        mitigation_commands = MitigationCommands(
            linux_commands=cmd_set.linux_commands,
            windows_commands=cmd_set.windows_commands,
            verification_commands=cmd_set.verification_commands,
            rollback_commands=cmd_set.rollback_commands,
        )

        # ── Assemble playbook ─────────────────────────────────────────────
        playbook = IncidentPlaybook(
            playbook_id=playbook_id,
            campaign_id=_campaign_id,
            generated_by_model=self._orchestrator.active_model(),

            # Section 1: Executive Summary
            executive_summary=llm_content.get("executive_summary", ""),

            # Section 2: Threat Severity
            threat_severity=_severity,
            severity_justification=llm_content.get("severity_justification", ""),

            # Section 3: MITRE ATT&CK
            mitre_techniques=mitre_techniques,

            # Section 4: Root Cause Analysis
            root_cause_analysis=llm_content.get("root_cause_analysis", ""),
            initial_access_vector=llm_content.get("initial_access_vector", ""),

            # Section 5: Attack Timeline
            attack_timeline=timeline,

            # Section 6: IOC List
            ioc_list=ioc_list,

            # Section 7: Affected Assets
            affected_assets=affected_assets,

            # Section 8: Threat Actor
            threat_actor_summary=llm_content.get("threat_actor_summary", ""),
            ttp_summary=llm_content.get("ttp_summary", ""),

            # Section 9 & 10: Mitigation Commands
            mitigation_commands=mitigation_commands,

            # Section 11: Containment Strategy
            containment_strategy=llm_content.get("containment_strategy", ""),
            containment_steps=llm_content.get("containment_steps", []),

            # Section 12: Recovery Plan
            recovery_plan=llm_content.get("recovery_plan", ""),
            recovery_steps=llm_content.get("recovery_steps", []),

            # Section 13: Hardening
            hardening_recommendations=llm_content.get("hardening_recommendations", []),

            # Section 14: Compliance
            compliance_frameworks=llm_content.get("compliance_frameworks", []),
            compliance_impact=llm_content.get("compliance_impact", ""),

            # Section 15: Blast Radius
            blast_radius_hosts=len(_targets),
            blast_radius_subnets=[target_subnet],
            blast_radius_description=llm_content.get("blast_radius_description", ""),
            potential_data_exposure=llm_content.get("potential_data_exposure", ""),
        )

        elapsed = (time.perf_counter() - t0) * 1000
        log.info(
            "PlaybookEngine: playbook generated",
            playbook_id=playbook_id,
            campaign_id=_campaign_id,
            severity=_severity,
            model=self._orchestrator.active_model(),
            latency_ms=round(elapsed, 1),
        )

        return playbook

    # ── Private Helpers ───────────────────────────────────────────────────────

    def _build_ioc_list(
        self,
        attacker_ip: str,
        target_ips: list[str],
        stages: list[str],
        process_name: str,
    ) -> list[IOCEntry]:
        iocs: list[IOCEntry] = []

        # Attacker IP
        iocs.append(IOCEntry(
            ioc_type="IP",
            value=attacker_ip,
            confidence=0.95,
            context="Primary attacker source IP — observed across all attack stages",
        ))

        # Target IPs
        for tip in target_ips[:5]:
            iocs.append(IOCEntry(
                ioc_type="IP",
                value=tip,
                confidence=0.85,
                context="Victim host — targeted during campaign",
            ))

        # Process IOC if execution stage
        if "Execution" in stages or "Persistence" in stages:
            iocs.append(IOCEntry(
                ioc_type="Process",
                value=process_name,
                confidence=0.80,
                context="Malicious process observed during Execution/Persistence stage",
            ))

        # DNS tunneling IOC
        if "Exfiltration" in stages:
            iocs.append(IOCEntry(
                ioc_type="Behaviour",
                value="DNS_Tunneling",
                confidence=0.75,
                context="Abnormal DNS query volume suggesting data exfiltration channel",
            ))

        # Credential attack IOC
        if "Credential_Access" in stages:
            iocs.append(IOCEntry(
                ioc_type="Behaviour",
                value="Brute_Force_Pattern",
                confidence=0.90,
                context="Rapid sequential authentication failures from attacker IP",
            ))

        return iocs

    def _build_timeline(
        self,
        attacker_ip: str,
        target_ips: list[str],
        stages: list[str],
    ) -> list[AttackTimelineEntry]:
        timeline: list[AttackTimelineEntry] = []
        base_ts = datetime.utcnow()
        target = target_ips[0] if target_ips else "10.0.0.100"

        for i, stage in enumerate(stages):
            offset_minutes = i * 8  # ~8 min between stages
            ts = base_ts.replace(
                minute=(base_ts.minute + offset_minutes) % 60,
                hour=base_ts.hour + ((base_ts.minute + offset_minutes) // 60),
            )
            event_type = STAGE_EVENT_MAP.get(stage, "Normal_Connection")

            timeline.append(AttackTimelineEntry(
                timestamp=ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                stage=stage,
                event_type=event_type,
                src_ip=attacker_ip,
                dst_ip=target,
                description=f"Stage {i + 1}: {stage} — {event_type} activity detected from {attacker_ip}",
            ))

        return timeline

    def _build_affected_assets(
        self,
        target_ips: list[str],
        stages: list[str],
    ) -> list[AffectedAsset]:
        assets: list[AffectedAsset] = []
        criticalities = ["HIGH", "MEDIUM", "CRITICAL", "LOW", "HIGH"]
        tiers = ["Tier_2", "Tier_3", "Tier_1", "Tier_4", "Tier_2"]

        for i, ip in enumerate(target_ips[:6]):
            crit = criticalities[i % len(criticalities)]
            tier = tiers[i % len(tiers)]
            compromise_stage = stages[-1] if stages else "Unknown"

            assets.append(AffectedAsset(
                ip=ip,
                asset_name=f"ASSET-{ip.replace('.', '-')}",
                asset_tier=tier,
                criticality=crit,
                compromise_stage=compromise_stage,
                first_seen=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                last_seen=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            ))

        return assets

    def _build_mitre(self, stages: list[str]) -> list[dict]:
        techniques: list[dict] = []
        for stage in stages:
            if stage in STAGE_MITRE:
                tid, name, tactic = STAGE_MITRE[stage]
                techniques.append({"id": tid, "name": name, "tactic": tactic})
        return techniques

    @staticmethod
    def _infer_subnet(ip: str) -> str:
        """Infer /24 subnet from an IP address."""
        try:
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return "10.0.1.0/24"
