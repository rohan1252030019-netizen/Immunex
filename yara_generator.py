"""
IMMUNEX YARA Rule Generator
==============================
Phase 5 — Automated YARA malware signature synthesis from DetectionDecision events.

Generates compile-ready YARA rules with process patterns, hash indicators,
and behavioral signatures. Air-gapped & CPU-only compatible.
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any

from utils.logger import log


# ─── Suspicious patterns for behavioral rules ────────────────────────────────
_SUSPICIOUS_PATTERNS = {
    "encoded_payload":    ["-enc", "-EncodedCommand", "base64", "frombase64string"],
    "shadow_deletion":    ["vssadmin", "delete shadows", "wmic shadowcopy delete"],
    "credential_dump":    ["mimikatz", "sekurlsa", "lsadump", "procdump", "lsass"],
    "persistence":        ["schtasks", "reg add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
    "lateral_movement":   ["psexec", "wmiexec", "smbclient", "net use", "winrm"],
    "defense_evasion":    ["del /f", "wevtutil cl", "Clear-EventLog", "Set-MpPreference"],
    "ransomware":         ["encrypt", ".locked", ".crypt", "ransom", "bitcoin", "YOUR FILES"],
    "lolbin_abuse":       ["certutil -urlcache", "mshta javascript:", "regsvr32 /s /n /u /i:"],
}


class YaraRuleGenerator:
    """
    Generates compile-ready YARA rules from SecurityEvent + DetectionDecision.
    """

    def __init__(self):
        self._rule_counter = 0
        log.info("YaraRuleGenerator initialized")

    def generate(self, event, decision) -> str:
        """
        Generate a YARA rule from a SecurityEvent + DetectionDecision.

        Returns compile-ready YARA rule text.
        """
        self._rule_counter += 1
        rule_name = self._sanitize_name(
            f"IMMUNEX_Auto_{getattr(event, 'event_type', 'generic')}_{self._rule_counter}"
        )

        process_name = getattr(event, "process_name", "unknown")
        process_hash = getattr(event, "process_hash", "0" * 64)
        severity = getattr(decision, "severity", "MEDIUM")
        anomaly_score = getattr(decision, "anomaly_score", 0.0)
        detection_reason = getattr(decision, "detection_reason", "anomaly detected")
        event_type = getattr(event, "event_type", "unknown")
        src_ip = getattr(event, "src_ip", "0.0.0.0")

        # Meta section
        meta = {
            "author":        "IMMUNEX Autonomous SOC",
            "description":   f"Auto-generated YARA rule — {detection_reason}",
            "date":          datetime.utcnow().strftime("%Y-%m-%d"),
            "severity":      severity,
            "threat_level":  self._severity_to_threat(severity),
            "anomaly_score": f"{anomaly_score:.4f}",
            "reference":     "https://immunex.soc/auto-yara",
        }

        # Strings section
        strings = {}
        str_counter = 0

        # Primary process pattern
        if process_name and process_name != "unknown":
            str_counter += 1
            strings[f"$proc_{str_counter}"] = {"value": process_name, "type": "text"}

        # Process hash as hex
        if process_hash and process_hash != "0" * 64 and len(process_hash) == 64:
            str_counter += 1
            hex_str = " ".join(process_hash[i:i+2] for i in range(0, min(32, len(process_hash)), 2))
            strings[f"$hash_{str_counter}"] = {"value": hex_str, "type": "hex"}

        # Behavioral patterns based on event type
        detected_patterns = self._detect_patterns(event, decision)
        for pat_name, pat_strings in detected_patterns.items():
            for ps in pat_strings[:3]:  # Limit per category
                str_counter += 1
                strings[f"${pat_name}_{str_counter}"] = {"value": ps, "type": "text"}

        # Source IP as string
        if src_ip and src_ip != "0.0.0.0":
            str_counter += 1
            strings[f"$src_ip_{str_counter}"] = {"value": src_ip, "type": "text"}

        # Build YARA rule text
        rule_lines = [f"rule {rule_name}"]
        rule_lines.append("{")

        # Meta
        rule_lines.append("    meta:")
        for k, v in meta.items():
            rule_lines.append(f'        {k} = "{v}"')

        # Strings
        if strings:
            rule_lines.append("")
            rule_lines.append("    strings:")
            for name, info in strings.items():
                if info["type"] == "hex":
                    rule_lines.append(f"        {name} = {{ {info['value']} }}")
                else:
                    escaped = info["value"].replace("\\", "\\\\").replace('"', '\\"')
                    rule_lines.append(f'        {name} = "{escaped}" ascii wide nocase')

        # Condition
        rule_lines.append("")
        rule_lines.append("    condition:")
        if strings:
            str_names = list(strings.keys())
            if len(str_names) == 1:
                rule_lines.append(f"        {str_names[0]}")
            else:
                rule_lines.append(f"        any of them")
        else:
            rule_lines.append("        true")

        rule_lines.append("}")
        rule_text = "\n".join(rule_lines)

        log.debug("YARA_RULE_GENERATED", rule_name=rule_name, strings_count=len(strings))
        return rule_text

    def generate_from_indicators(self, indicators: dict) -> str:
        """
        Generate YARA rule from manual IOC indicators.

        Args:
            indicators: Dict with keys like 'hashes', 'ips', 'domains', 'strings', 'name'
        """
        rule_name = self._sanitize_name(
            indicators.get("name", f"IMMUNEX_IOC_{int(time.time())}")
        )

        meta = {
            "author": "IMMUNEX Autonomous SOC",
            "description": indicators.get("description", "IOC-based YARA rule"),
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "severity": indicators.get("severity", "HIGH"),
        }

        strings = {}
        counter = 0

        for h in indicators.get("hashes", []):
            counter += 1
            if len(h) == 64:
                hex_part = " ".join(h[i:i+2] for i in range(0, 32, 2))
                strings[f"$hash_{counter}"] = {"value": hex_part, "type": "hex"}

        for ip in indicators.get("ips", []):
            counter += 1
            strings[f"$ip_{counter}"] = {"value": ip, "type": "text"}

        for domain in indicators.get("domains", []):
            counter += 1
            strings[f"$domain_{counter}"] = {"value": domain, "type": "text"}

        for s in indicators.get("strings", []):
            counter += 1
            strings[f"$str_{counter}"] = {"value": s, "type": "text"}

        # Build rule
        lines = [f"rule {rule_name}", "{", "    meta:"]
        for k, v in meta.items():
            lines.append(f'        {k} = "{v}"')

        if strings:
            lines.extend(["", "    strings:"])
            for name, info in strings.items():
                if info["type"] == "hex":
                    lines.append(f"        {name} = {{ {info['value']} }}")
                else:
                    escaped = info["value"].replace('"', '\\"')
                    lines.append(f'        {name} = "{escaped}" ascii wide nocase')

        lines.extend(["", "    condition:"])
        lines.append("        any of them" if strings else "        true")
        lines.append("}")

        return "\n".join(lines)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _detect_patterns(self, event, decision) -> dict[str, list[str]]:
        """Detect suspicious behavioral patterns from event attributes."""
        detected = {}
        text_to_scan = " ".join([
            getattr(event, "process_name", ""),
            getattr(event, "event_type", ""),
            getattr(decision, "detection_reason", ""),
            getattr(decision, "mitre_tactic", "") or "",
        ]).lower()

        for category, patterns in _SUSPICIOUS_PATTERNS.items():
            matches = [p for p in patterns if p.lower() in text_to_scan]
            if matches:
                detected[category] = matches
        return detected

    def _severity_to_threat(self, severity: str) -> str:
        mapping = {
            "CRITICAL": "5/5 — Critical Threat",
            "HIGH":     "4/5 — High Threat",
            "MEDIUM":   "3/5 — Medium Threat",
            "LOW":      "2/5 — Low Threat",
            "INFO":     "1/5 — Informational",
        }
        return mapping.get(severity, "3/5 — Medium Threat")

    def _sanitize_name(self, name: str) -> str:
        """Sanitize rule name to be YARA-compatible."""
        sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", name)
        if sanitized and sanitized[0].isdigit():
            sanitized = f"rule_{sanitized}"
        return sanitized
