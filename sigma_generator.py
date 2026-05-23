"""
IMMUNEX Sigma Rule Generator
==============================
Phase 5 — Automated Sigma detection rule synthesis from DetectionDecision events.

Generates valid YAML Sigma rules with MITRE ATT&CK technique tagging.
Air-gapped & CPU-only compatible. Zero external dependencies.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

import yaml

from utils.logger import log


# ─── MITRE Tactic → ATT&CK Tag Mapping ──────────────────────────────────────
_MITRE_TAG_MAP = {
    "reconnaissance":       "attack.reconnaissance",
    "resource_development":  "attack.resource_development",
    "initial_access":        "attack.initial_access",
    "execution":             "attack.execution",
    "persistence":           "attack.persistence",
    "privilege_escalation":  "attack.privilege_escalation",
    "defense_evasion":       "attack.defense_evasion",
    "credential_access":     "attack.credential_access",
    "discovery":             "attack.discovery",
    "lateral_movement":      "attack.lateral_movement",
    "collection":            "attack.collection",
    "command_and_control":   "attack.command_and_control",
    "exfiltration":          "attack.exfiltration",
    "impact":                "attack.impact",
}

# ─── Event type → Logsource mapping ──────────────────────────────────────────
_LOGSOURCE_MAP = {
    "process_creation":    {"category": "process_creation",   "product": "windows"},
    "network_connection":  {"category": "network_connection", "product": "windows"},
    "dns_query":           {"category": "dns_query",          "product": "windows"},
    "file_event":          {"category": "file_event",         "product": "windows"},
    "registry_event":      {"category": "registry_event",     "product": "windows"},
    "login_attempt":       {"category": "authentication",     "product": "windows", "service": "security"},
    "powershell":          {"category": "ps_script",          "product": "windows"},
    "c2_beacon":           {"category": "network_connection", "product": "windows"},
    "data_exfiltration":   {"category": "network_connection", "product": "windows"},
    "privilege_escalation":{"category": "process_creation",   "product": "windows"},
    "lateral_movement":    {"category": "network_connection", "product": "windows"},
    "ransomware":          {"category": "file_event",         "product": "windows"},
}

# ─── Severity → Sigma level ──────────────────────────────────────────────────
_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "INFO":     "informational",
}

# ─── LOLBins / suspicious processes ──────────────────────────────────────────
_LOLBINS = {
    "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "wmic.exe", "cscript.exe", "wscript.exe", "msiexec.exe",
    "bitsadmin.exe", "powershell.exe", "cmd.exe", "schtasks.exe",
    "psexec.exe", "net.exe", "nltest.exe", "vssadmin.exe",
}


class SigmaRuleGenerator:
    """
    Generates valid YAML Sigma detection rules from SecurityEvent + DetectionDecision.
    """

    def __init__(self):
        self._rule_counter = 0
        log.info("SigmaRuleGenerator initialized")

    def generate(self, event, decision) -> str:
        """
        Generate a Sigma detection rule from a SecurityEvent + DetectionDecision.

        Returns valid YAML Sigma rule string.
        """
        self._rule_counter += 1
        rule_id = f"immunex-auto-{self._rule_counter:06d}"

        # Determine logsource
        event_type = getattr(event, "event_type", "network_connection")
        logsource = _LOGSOURCE_MAP.get(event_type, {"category": "process_creation", "product": "windows"})

        # Build detection selection
        selection = {}
        process_name = getattr(event, "process_name", "")
        if process_name:
            selection["Image|endswith"] = f"\\{process_name}"
        src_ip = getattr(event, "src_ip", "")
        if src_ip and src_ip != "0.0.0.0":
            selection["SourceIp"] = src_ip
        dst_port = getattr(event, "dst_port", 0)
        if dst_port and dst_port not in (0, 80, 443):
            selection["DestinationPort"] = dst_port
        protocol = getattr(event, "protocol", "")
        if protocol:
            selection["Protocol"] = protocol

        # LOLBin enrichment
        if process_name.lower() in _LOLBINS:
            selection["ParentImage|endswith"] = "\\cmd.exe"

        # If selection is empty, add generic match
        if not selection:
            selection["EventType"] = event_type

        # Detection block
        detection = {"selection": selection, "condition": "selection"}

        # Determine severity level
        severity = getattr(decision, "severity", "MEDIUM")
        level = _SEVERITY_MAP.get(severity, "medium")

        # Build ATT&CK tags
        tags = []
        mitre_tactic = getattr(decision, "mitre_tactic", None)
        if mitre_tactic:
            tactic_key = mitre_tactic.lower().replace(" ", "_")
            if tactic_key in _MITRE_TAG_MAP:
                tags.append(_MITRE_TAG_MAP[tactic_key])
            else:
                tags.append(f"attack.{tactic_key}")

        # Add process-based tags
        if process_name.lower() in ("powershell.exe", "pwsh.exe"):
            tags.append("attack.execution")
            tags.append("attack.t1059.001")
        elif process_name.lower() in ("cmd.exe",):
            tags.append("attack.execution")
            tags.append("attack.t1059.003")

        if not tags:
            tags.append("attack.execution")

        # Build Sigma rule
        rule = {
            "title": f"IMMUNEX Auto-Detection: {event_type} from {src_ip}",
            "id": rule_id,
            "status": "experimental",
            "description": (
                f"Auto-generated Sigma rule by IMMUNEX SOC Copilot. "
                f"Detection reason: {getattr(decision, 'detection_reason', 'anomaly')}. "
                f"Anomaly score: {getattr(decision, 'anomaly_score', 0):.4f}."
            ),
            "author": "IMMUNEX Autonomous SOC",
            "date": datetime.utcnow().strftime("%Y/%m/%d"),
            "references": ["https://immunex.soc/auto-generated"],
            "logsource": logsource,
            "detection": detection,
            "level": level,
            "tags": tags,
            "falsepositives": ["Legitimate administrative activity"],
        }

        rule_yaml = yaml.dump(rule, default_flow_style=False, sort_keys=False)
        log.debug("SIGMA_RULE_GENERATED", rule_id=rule_id, event_type=event_type)
        return rule_yaml

    def generate_from_campaign(self, events: list, decisions: list) -> str:
        """Generate a compound Sigma rule from a campaign (multiple events)."""
        if not events or not decisions:
            return self._empty_rule("No events provided for campaign rule generation")

        # Aggregate selections from all events
        selections = {}
        all_tags = set()
        max_severity = "INFO"
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

        for i, (event, decision) in enumerate(zip(events, decisions)):
            sel_name = f"selection_{i + 1}"
            sel = {}
            process_name = getattr(event, "process_name", "")
            if process_name:
                sel["Image|endswith"] = f"\\{process_name}"
            src_ip = getattr(event, "src_ip", "")
            if src_ip:
                sel["SourceIp"] = src_ip
            if not sel:
                sel["EventType"] = getattr(event, "event_type", "unknown")
            selections[sel_name] = sel

            sev = getattr(decision, "severity", "INFO")
            if severity_order.index(sev) > severity_order.index(max_severity):
                max_severity = sev

            mitre = getattr(decision, "mitre_tactic", None)
            if mitre:
                tactic_key = mitre.lower().replace(" ", "_")
                all_tags.add(_MITRE_TAG_MAP.get(tactic_key, f"attack.{tactic_key}"))

        # Build compound detection
        condition_parts = " or ".join(selections.keys())
        detection = {**selections, "condition": condition_parts}

        rule = {
            "title": f"IMMUNEX Campaign Detection — {len(events)} correlated events",
            "id": f"immunex-campaign-{int(datetime.utcnow().timestamp())}",
            "status": "experimental",
            "description": f"Compound Sigma rule from {len(events)} correlated attack-chain events.",
            "author": "IMMUNEX Autonomous SOC",
            "date": datetime.utcnow().strftime("%Y/%m/%d"),
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": detection,
            "level": _SEVERITY_MAP.get(max_severity, "medium"),
            "tags": list(all_tags) or ["attack.execution"],
        }

        return yaml.dump(rule, default_flow_style=False, sort_keys=False)

    def validate_rule(self, rule_yaml: str) -> bool:
        """Basic YAML structure validation for Sigma rules."""
        try:
            parsed = yaml.safe_load(rule_yaml)
            if not isinstance(parsed, dict):
                return False
            required = ["title", "logsource", "detection", "level"]
            return all(k in parsed for k in required)
        except Exception:
            return False

    def _empty_rule(self, reason: str) -> str:
        return yaml.dump({
            "title": "IMMUNEX — Empty Rule",
            "status": "experimental",
            "description": reason,
            "author": "IMMUNEX",
            "date": datetime.utcnow().strftime("%Y/%m/%d"),
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {"selection": {"EventType": "*"}, "condition": "selection"},
            "level": "informational",
            "tags": [],
        }, default_flow_style=False, sort_keys=False)
