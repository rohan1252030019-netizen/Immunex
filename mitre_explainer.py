"""
IMMUNEX MITRE ATT&CK Explainer
================================
Phase 5 — Full offline ATT&CK taxonomy with human-readable narrative generation.

Contains the complete 14-tactic Enterprise matrix with technique mappings.
Air-gapped & CPU-only compatible. Zero external dependencies.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from utils.logger import log


# ─── Complete MITRE ATT&CK Enterprise Taxonomy ──────────────────────────────

MITRE_TACTICS = {
    "TA0043": {
        "id": "TA0043", "name": "Reconnaissance",
        "description": "Gathering information to plan future adversary operations.",
        "techniques": {
            "T1595": {"name": "Active Scanning", "desc": "Scanning infrastructure to identify targets."},
            "T1592": {"name": "Gather Victim Host Info", "desc": "Collecting host configuration details."},
            "T1589": {"name": "Gather Victim Identity Info", "desc": "Collecting credentials, email addresses."},
            "T1590": {"name": "Gather Victim Network Info", "desc": "Collecting network configuration details."},
            "T1591": {"name": "Gather Victim Org Info", "desc": "Collecting organizational structure info."},
            "T1598": {"name": "Phishing for Information", "desc": "Sending messages to gather information."},
            "T1597": {"name": "Search Closed Sources", "desc": "Searching threat intel feeds and dark web."},
            "T1596": {"name": "Search Open Technical Databases", "desc": "Searching WHOIS, DNS, certificate data."},
            "T1593": {"name": "Search Open Websites/Domains", "desc": "Searching social media and websites."},
            "T1594": {"name": "Search Victim-Owned Websites", "desc": "Scanning victim websites for info."},
        }
    },
    "TA0042": {
        "id": "TA0042", "name": "Resource Development",
        "description": "Establishing resources to support operations.",
        "techniques": {
            "T1583": {"name": "Acquire Infrastructure", "desc": "Buying or renting infrastructure."},
            "T1586": {"name": "Compromise Accounts", "desc": "Compromising existing accounts."},
            "T1584": {"name": "Compromise Infrastructure", "desc": "Compromising third-party infrastructure."},
            "T1587": {"name": "Develop Capabilities", "desc": "Building malware and exploit tools."},
            "T1585": {"name": "Establish Accounts", "desc": "Creating new accounts for operations."},
            "T1588": {"name": "Obtain Capabilities", "desc": "Acquiring tools, exploits, certificates."},
            "T1608": {"name": "Stage Capabilities", "desc": "Staging tools on infrastructure."},
            "T1650": {"name": "Acquire Access", "desc": "Purchasing access to target environments."},
            "T1651": {"name": "Cloud Administration Command", "desc": "Abusing cloud admin interfaces."},
            "T1612": {"name": "Build Image on Host", "desc": "Building container images on target."},
        }
    },
    "TA0001": {
        "id": "TA0001", "name": "Initial Access",
        "description": "Techniques that use various entry vectors to gain initial foothold.",
        "techniques": {
            "T1189": {"name": "Drive-by Compromise", "desc": "Exploiting web browser vulnerabilities."},
            "T1190": {"name": "Exploit Public-Facing Application", "desc": "Exploiting internet-facing services."},
            "T1133": {"name": "External Remote Services", "desc": "Leveraging VPN, RDP, SSH access."},
            "T1200": {"name": "Hardware Additions", "desc": "Introducing rogue hardware devices."},
            "T1566": {"name": "Phishing", "desc": "Sending spearphishing attachments or links."},
            "T1091": {"name": "Replication Through Removable Media", "desc": "Spreading via USB drives."},
            "T1195": {"name": "Supply Chain Compromise", "desc": "Compromising supply chain vendors."},
            "T1199": {"name": "Trusted Relationship", "desc": "Abusing trusted third-party relationships."},
            "T1078": {"name": "Valid Accounts", "desc": "Using compromised legitimate credentials."},
            "T1659": {"name": "Content Injection", "desc": "Injecting malicious content into traffic."},
        }
    },
    "TA0002": {
        "id": "TA0002", "name": "Execution",
        "description": "Techniques that result in adversary-controlled code running.",
        "techniques": {
            "T1059": {"name": "Command and Scripting Interpreter", "desc": "Using PowerShell, cmd, bash, Python."},
            "T1203": {"name": "Exploitation for Client Execution", "desc": "Exploiting software vulnerabilities."},
            "T1559": {"name": "Inter-Process Communication", "desc": "Using IPC mechanisms to execute code."},
            "T1106": {"name": "Native API", "desc": "Using OS native API calls."},
            "T1053": {"name": "Scheduled Task/Job", "desc": "Using task schedulers to execute code."},
            "T1129": {"name": "Shared Modules", "desc": "Executing payloads via shared libraries."},
            "T1072": {"name": "Software Deployment Tools", "desc": "Using IT management tools."},
            "T1569": {"name": "System Services", "desc": "Using system services to execute commands."},
            "T1204": {"name": "User Execution", "desc": "Relying on users to execute malware."},
            "T1047": {"name": "WMI", "desc": "Using Windows Management Instrumentation."},
        }
    },
    "TA0003": {
        "id": "TA0003", "name": "Persistence",
        "description": "Techniques that adversaries use to keep access to systems.",
        "techniques": {
            "T1098": {"name": "Account Manipulation", "desc": "Modifying accounts to maintain access."},
            "T1197": {"name": "BITS Jobs", "desc": "Using BITS for persistent execution."},
            "T1547": {"name": "Boot or Logon Autostart", "desc": "Using autostart mechanisms."},
            "T1037": {"name": "Boot or Logon Init Scripts", "desc": "Using login scripts."},
            "T1136": {"name": "Create Account", "desc": "Creating new user accounts."},
            "T1543": {"name": "Create or Modify System Process", "desc": "Creating services or daemons."},
            "T1546": {"name": "Event Triggered Execution", "desc": "Using event triggers."},
            "T1133": {"name": "External Remote Services", "desc": "Using VPN for persistent access."},
            "T1574": {"name": "Hijack Execution Flow", "desc": "DLL hijacking and search order abuse."},
            "T1053": {"name": "Scheduled Task/Job", "desc": "Creating scheduled tasks for persistence."},
        }
    },
    "TA0004": {
        "id": "TA0004", "name": "Privilege Escalation",
        "description": "Techniques to gain higher-level permissions.",
        "techniques": {
            "T1548": {"name": "Abuse Elevation Control", "desc": "Bypassing UAC and sudo."},
            "T1134": {"name": "Access Token Manipulation", "desc": "Manipulating access tokens."},
            "T1547": {"name": "Boot or Logon Autostart", "desc": "Autostart for privilege persistence."},
            "T1037": {"name": "Boot or Logon Init Scripts", "desc": "Init scripts with elevated rights."},
            "T1543": {"name": "Create or Modify System Process", "desc": "Service creation for escalation."},
            "T1484": {"name": "Domain Policy Modification", "desc": "Modifying AD group policies."},
            "T1611": {"name": "Escape to Host", "desc": "Escaping containers to host OS."},
            "T1546": {"name": "Event Triggered Execution", "desc": "Event triggers for escalation."},
            "T1068": {"name": "Exploitation for Privilege Escalation", "desc": "Exploiting kernel vulns."},
            "T1078": {"name": "Valid Accounts", "desc": "Using accounts with elevated rights."},
        }
    },
    "TA0005": {
        "id": "TA0005", "name": "Defense Evasion",
        "description": "Techniques to avoid being detected.",
        "techniques": {
            "T1548": {"name": "Abuse Elevation Control", "desc": "Bypassing security controls."},
            "T1134": {"name": "Access Token Manipulation", "desc": "Impersonating other users."},
            "T1197": {"name": "BITS Jobs", "desc": "Using BITS to evade detection."},
            "T1140": {"name": "Deobfuscate/Decode", "desc": "Decoding encoded payloads."},
            "T1006": {"name": "Direct Volume Access", "desc": "Reading disk directly to bypass OS."},
            "T1562": {"name": "Impair Defenses", "desc": "Disabling security tools."},
            "T1070": {"name": "Indicator Removal", "desc": "Clearing logs and artifacts."},
            "T1036": {"name": "Masquerading", "desc": "Disguising malicious files as legitimate."},
            "T1027": {"name": "Obfuscated Files or Info", "desc": "Obfuscating payloads."},
            "T1218": {"name": "System Binary Proxy Execution", "desc": "Using trusted binaries."},
        }
    },
    "TA0006": {
        "id": "TA0006", "name": "Credential Access",
        "description": "Techniques for stealing credentials.",
        "techniques": {
            "T1110": {"name": "Brute Force", "desc": "Password guessing and spraying."},
            "T1555": {"name": "Credentials from Password Stores", "desc": "Extracting stored passwords."},
            "T1212": {"name": "Exploitation for Credential Access", "desc": "Exploiting vulns for creds."},
            "T1187": {"name": "Forced Authentication", "desc": "Forcing auth to capture hashes."},
            "T1606": {"name": "Forge Web Credentials", "desc": "Forging SAML tokens, cookies."},
            "T1056": {"name": "Input Capture", "desc": "Keylogging and input recording."},
            "T1557": {"name": "Adversary-in-the-Middle", "desc": "LLMNR/NBT-NS poisoning, ARP spoofing."},
            "T1003": {"name": "OS Credential Dumping", "desc": "Dumping LSASS, SAM, NTDS."},
            "T1528": {"name": "Steal Application Access Token", "desc": "Stealing OAuth tokens."},
            "T1558": {"name": "Steal or Forge Kerberos Tickets", "desc": "Kerberoasting, Golden Ticket."},
        }
    },
    "TA0007": {
        "id": "TA0007", "name": "Discovery",
        "description": "Techniques to gain knowledge about the system and network.",
        "techniques": {
            "T1087": {"name": "Account Discovery", "desc": "Listing user accounts."},
            "T1010": {"name": "Application Window Discovery", "desc": "Listing open application windows."},
            "T1217": {"name": "Browser Information Discovery", "desc": "Enumerating browser data."},
            "T1580": {"name": "Cloud Infrastructure Discovery", "desc": "Enumerating cloud resources."},
            "T1482": {"name": "Domain Trust Discovery", "desc": "Discovering Active Directory trusts."},
            "T1083": {"name": "File and Directory Discovery", "desc": "Listing files and directories."},
            "T1046": {"name": "Network Service Discovery", "desc": "Port scanning internal services."},
            "T1057": {"name": "Process Discovery", "desc": "Listing running processes."},
            "T1018": {"name": "Remote System Discovery", "desc": "Discovering other networked hosts."},
            "T1082": {"name": "System Information Discovery", "desc": "Querying OS and hardware info."},
        }
    },
    "TA0008": {
        "id": "TA0008", "name": "Lateral Movement",
        "description": "Techniques to move through the environment.",
        "techniques": {
            "T1210": {"name": "Exploitation of Remote Services", "desc": "Exploiting remote service vulns."},
            "T1534": {"name": "Internal Spearphishing", "desc": "Phishing within the organization."},
            "T1570": {"name": "Lateral Tool Transfer", "desc": "Moving tools between systems."},
            "T1563": {"name": "Remote Service Session Hijacking", "desc": "Hijacking RDP/SSH sessions."},
            "T1021": {"name": "Remote Services", "desc": "Using RDP, SMB, SSH, WinRM."},
            "T1091": {"name": "Replication Through Removable Media", "desc": "Spreading via USB."},
            "T1072": {"name": "Software Deployment Tools", "desc": "Using SCCM, WSUS for spreading."},
            "T1080": {"name": "Taint Shared Content", "desc": "Modifying shared network content."},
            "T1550": {"name": "Use Alternate Authentication Material", "desc": "Pass the Hash/Ticket."},
            "T1048": {"name": "Exfiltration Over Alternative Protocol", "desc": "Using DNS, ICMP tunneling."},
        }
    },
    "TA0009": {
        "id": "TA0009", "name": "Collection",
        "description": "Techniques to gather data of interest.",
        "techniques": {
            "T1560": {"name": "Archive Collected Data", "desc": "Compressing collected data."},
            "T1123": {"name": "Audio Capture", "desc": "Recording audio via microphone."},
            "T1119": {"name": "Automated Collection", "desc": "Using scripts to collect data."},
            "T1185": {"name": "Browser Session Hijacking", "desc": "Hijacking browser sessions."},
            "T1115": {"name": "Clipboard Data", "desc": "Collecting clipboard contents."},
            "T1530": {"name": "Data from Cloud Storage", "desc": "Collecting from S3, Azure Blob."},
            "T1213": {"name": "Data from Info Repositories", "desc": "Collecting from SharePoint, wikis."},
            "T1005": {"name": "Data from Local System", "desc": "Collecting local files and data."},
            "T1039": {"name": "Data from Network Shared Drive", "desc": "Collecting from network shares."},
            "T1114": {"name": "Email Collection", "desc": "Collecting email messages."},
        }
    },
    "TA0011": {
        "id": "TA0011", "name": "Command and Control",
        "description": "Techniques for communicating with compromised systems.",
        "techniques": {
            "T1071": {"name": "Application Layer Protocol", "desc": "Using HTTP, HTTPS, DNS for C2."},
            "T1132": {"name": "Data Encoding", "desc": "Encoding C2 communications."},
            "T1001": {"name": "Data Obfuscation", "desc": "Obfuscating C2 traffic."},
            "T1568": {"name": "Dynamic Resolution", "desc": "Using DGA, DNS calc for C2 domains."},
            "T1573": {"name": "Encrypted Channel", "desc": "Using encryption for C2."},
            "T1008": {"name": "Fallback Channels", "desc": "Using backup C2 channels."},
            "T1105": {"name": "Ingress Tool Transfer", "desc": "Downloading tools from C2."},
            "T1104": {"name": "Multi-Stage Channels", "desc": "Using staged C2 infrastructure."},
            "T1095": {"name": "Non-Application Layer Protocol", "desc": "Using raw TCP/UDP/ICMP."},
            "T1571": {"name": "Non-Standard Port", "desc": "Using unusual ports for C2."},
        }
    },
    "TA0010": {
        "id": "TA0010", "name": "Exfiltration",
        "description": "Techniques to steal data from the network.",
        "techniques": {
            "T1020": {"name": "Automated Exfiltration", "desc": "Using scripts for data theft."},
            "T1030": {"name": "Data Transfer Size Limits", "desc": "Breaking data into small chunks."},
            "T1048": {"name": "Exfiltration Over Alternative Protocol", "desc": "DNS, ICMP tunneling."},
            "T1041": {"name": "Exfiltration Over C2 Channel", "desc": "Sending data over C2."},
            "T1011": {"name": "Exfiltration Over Other Network Medium", "desc": "Using bluetooth, RF."},
            "T1052": {"name": "Exfiltration Over Physical Medium", "desc": "Using USB drives."},
            "T1567": {"name": "Exfiltration Over Web Service", "desc": "Using cloud storage services."},
            "T1029": {"name": "Scheduled Transfer", "desc": "Exfiltrating on a schedule."},
            "T1537": {"name": "Transfer Data to Cloud Account", "desc": "Moving to attacker cloud."},
            "T1002": {"name": "Data Compressed", "desc": "Compressing data before exfil."},
        }
    },
    "TA0040": {
        "id": "TA0040", "name": "Impact",
        "description": "Techniques to manipulate, interrupt, or destroy systems and data.",
        "techniques": {
            "T1531": {"name": "Account Access Removal", "desc": "Locking out legitimate users."},
            "T1485": {"name": "Data Destruction", "desc": "Deleting data and backups."},
            "T1486": {"name": "Data Encrypted for Impact", "desc": "Ransomware encryption."},
            "T1565": {"name": "Data Manipulation", "desc": "Modifying data for impact."},
            "T1491": {"name": "Defacement", "desc": "Modifying visual content."},
            "T1561": {"name": "Disk Wipe", "desc": "Wiping disk structures."},
            "T1499": {"name": "Endpoint Denial of Service", "desc": "Crashing endpoints."},
            "T1495": {"name": "Firmware Corruption", "desc": "Corrupting firmware."},
            "T1489": {"name": "Service Stop", "desc": "Stopping critical services."},
            "T1529": {"name": "System Shutdown/Reboot", "desc": "Forcing system shutdown."},
        }
    },
}

# ─── Event type → Tactic mapping heuristic ───────────────────────────────────
_EVENT_TACTIC_MAP = {
    "process_creation":     ["TA0002"],
    "network_connection":   ["TA0011"],
    "dns_query":            ["TA0011", "TA0043"],
    "login_attempt":        ["TA0006", "TA0001"],
    "file_event":           ["TA0009", "TA0003"],
    "registry_event":       ["TA0003"],
    "powershell":           ["TA0002"],
    "c2_beacon":            ["TA0011"],
    "data_exfiltration":    ["TA0010"],
    "privilege_escalation": ["TA0004"],
    "lateral_movement":     ["TA0008"],
    "ransomware":           ["TA0040"],
    "credential_access":    ["TA0006"],
    "discovery":            ["TA0007"],
    "persistence":          ["TA0003"],
    "defense_evasion":      ["TA0005"],
}


class MITREExplainer:
    """Full offline MITRE ATT&CK Enterprise taxonomy and explainer engine."""

    def __init__(self):
        self._tactics = MITRE_TACTICS
        log.info("MITREExplainer initialized", tactics=len(self._tactics))

    def explain_tactic(self, tactic_id: str) -> dict:
        """Returns tactic details for a given ID (e.g., 'TA0001')."""
        tactic_id = tactic_id.upper()
        if tactic_id in self._tactics:
            t = self._tactics[tactic_id]
            return {
                "id": t["id"],
                "name": t["name"],
                "description": t["description"],
                "technique_count": len(t["techniques"]),
                "techniques": list(t["techniques"].keys()),
            }
        # Try matching by name
        for tid, t in self._tactics.items():
            if t["name"].lower() == tactic_id.lower():
                return {"id": tid, "name": t["name"], "description": t["description"],
                        "technique_count": len(t["techniques"]), "techniques": list(t["techniques"].keys())}
        return {"error": f"Tactic {tactic_id} not found"}

    def explain_technique(self, technique_id: str) -> dict:
        """Returns technique details for a given ID (e.g., 'T1059')."""
        technique_id = technique_id.upper()
        for tid, tactic in self._tactics.items():
            if technique_id in tactic["techniques"]:
                tech = tactic["techniques"][technique_id]
                return {
                    "id": technique_id,
                    "name": tech["name"],
                    "description": tech["desc"],
                    "tactic_id": tid,
                    "tactic_name": tactic["name"],
                }
        return {"error": f"Technique {technique_id} not found"}

    def map_event_to_techniques(self, event) -> list[dict]:
        """Maps event characteristics to likely MITRE techniques."""
        event_type = getattr(event, "event_type", "unknown")
        tactic_ids = _EVENT_TACTIC_MAP.get(event_type, ["TA0002"])

        results = []
        for tid in tactic_ids:
            tactic = self._tactics.get(tid)
            if not tactic:
                continue
            for tech_id, tech in list(tactic["techniques"].items())[:5]:
                results.append({
                    "technique_id": tech_id,
                    "technique_name": tech["name"],
                    "tactic_id": tid,
                    "tactic_name": tactic["name"],
                    "confidence": 0.7,
                })
        return results

    def get_tactic_chain(self, decisions: list) -> list[dict]:
        """Builds ordered tactic progression from a list of DetectionDecisions."""
        tactic_order = [
            "TA0043", "TA0042", "TA0001", "TA0002", "TA0003",
            "TA0004", "TA0005", "TA0006", "TA0007", "TA0008",
            "TA0009", "TA0011", "TA0010", "TA0040",
        ]
        seen_tactics = {}
        for d in decisions:
            mitre = getattr(d, "mitre_tactic", None)
            event_type = getattr(d, "event_type", "")
            if mitre:
                for tid, tactic in self._tactics.items():
                    if tactic["name"].lower().replace(" ", "_") == mitre.lower().replace(" ", "_"):
                        seen_tactics[tid] = {"tactic": tactic["name"], "event_type": event_type,
                                             "timestamp": str(getattr(d, "timestamp", ""))}
            # Also map from event type
            for tid in _EVENT_TACTIC_MAP.get(event_type, []):
                if tid not in seen_tactics:
                    seen_tactics[tid] = {"tactic": self._tactics.get(tid, {}).get("name", tid),
                                         "event_type": event_type,
                                         "timestamp": str(getattr(d, "timestamp", ""))}

        chain = []
        for tid in tactic_order:
            if tid in seen_tactics:
                chain.append({"tactic_id": tid, **seen_tactics[tid], "order": tactic_order.index(tid)})
        return chain

    def get_full_matrix(self) -> dict:
        """Returns the full ATT&CK matrix for heatmap rendering."""
        matrix = {}
        for tid, tactic in self._tactics.items():
            matrix[tid] = {
                "id": tid,
                "name": tactic["name"],
                "description": tactic["description"],
                "techniques": {
                    tech_id: {"name": tech["name"], "description": tech["desc"], "count": 0}
                    for tech_id, tech in tactic["techniques"].items()
                },
            }
        return matrix


class AttackNarrativeBuilder:
    """Generates human-readable attack narratives from detection decisions."""

    def __init__(self):
        self._explainer = MITREExplainer()

    def build_narrative(self, decision) -> str:
        """Build a human-readable attack story for a single detection."""
        severity = getattr(decision, "severity", "MEDIUM")
        src_ip = getattr(decision, "src_ip", "unknown")
        dst_ip = getattr(decision, "dst_ip", "unknown")
        event_type = getattr(decision, "event_type", "unknown")
        anomaly = getattr(decision, "anomaly_score", 0)
        reason = getattr(decision, "detection_reason", "anomaly detected")
        mitre = getattr(decision, "mitre_tactic", None)

        narrative = (
            f"🔴 **{severity} Severity Alert Detected**\n\n"
            f"At {getattr(decision, 'timestamp', 'unknown time')}, IMMUNEX detected "
            f"a **{event_type}** event originating from `{src_ip}` targeting `{dst_ip}`. "
            f"The anomaly engine scored this event at **{anomaly:.4f}** "
            f"(threshold breach: {getattr(decision, 'is_high_confidence_anomaly', False)}).\n\n"
            f"**Detection Reason:** {reason}\n"
        )

        if mitre:
            narrative += f"\n**MITRE ATT&CK Mapping:** {mitre}\n"

        if getattr(decision, "recommended_mitigation", None):
            narrative += f"\n**Recommended Action:** {decision.recommended_mitigation}\n"

        if getattr(decision, "attack_path", None):
            narrative += f"\n**Attack Path:** {' → '.join(decision.attack_path)}\n"

        return narrative

    def build_campaign_narrative(self, decisions: list) -> str:
        """Build a multi-stage campaign narrative."""
        if not decisions:
            return "No events available for campaign analysis."

        chain = self._explainer.get_tactic_chain(decisions)
        narrative = "# 🎯 Attack Campaign Analysis\n\n"
        narrative += f"**Total Events:** {len(decisions)}\n"
        narrative += f"**Attack Stages Identified:** {len(chain)}\n\n"

        for i, stage in enumerate(chain, 1):
            narrative += f"## Stage {i}: {stage['tactic']} ({stage['tactic_id']})\n"
            narrative += f"- Event Type: {stage['event_type']}\n"
            narrative += f"- Timestamp: {stage['timestamp']}\n\n"

        severity_counts = {}
        for d in decisions:
            sev = getattr(d, "severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        narrative += f"**Severity Distribution:** {severity_counts}\n"
        return narrative

    def build_executive_summary(self, decisions: list) -> str:
        """Build a CISO-level executive summary."""
        if not decisions:
            return "No security events detected in the analysis period."

        critical = sum(1 for d in decisions if getattr(d, "severity", "") == "CRITICAL")
        high = sum(1 for d in decisions if getattr(d, "severity", "") == "HIGH")
        unique_sources = len(set(getattr(d, "src_ip", "") for d in decisions))
        avg_score = sum(getattr(d, "anomaly_score", 0) for d in decisions) / len(decisions)

        summary = (
            f"# Executive Threat Intelligence Summary\n\n"
            f"**Reporting Period:** {getattr(decisions[0], 'timestamp', 'N/A')} — "
            f"{getattr(decisions[-1], 'timestamp', 'N/A')}\n\n"
            f"## Key Metrics\n"
            f"- **Total Events Analyzed:** {len(decisions)}\n"
            f"- **Critical Alerts:** {critical}\n"
            f"- **High Alerts:** {high}\n"
            f"- **Unique Threat Sources:** {unique_sources}\n"
            f"- **Average Anomaly Score:** {avg_score:.4f}\n\n"
            f"## Risk Assessment\n"
        )
        if critical > 0:
            summary += "⚠️ **ELEVATED RISK** — Critical-severity threats detected. Immediate response recommended.\n"
        elif high > 0:
            summary += "🟡 **MODERATE RISK** — High-severity threats detected. Investigation recommended.\n"
        else:
            summary += "🟢 **LOW RISK** — No critical threats detected in this period.\n"

        return summary
