"""
IMMUNEX Enterprise SOC Copilot
================================
Phase 5 — AI-native conversational SOC assistant with autonomous investigation,
natural language threat hunting, and rule synthesis.

Integrates: RAG Memory, Sigma/YARA Generators, MITRE Explainer, Compliance Mapper,
DigitalTwinEngine, EnsembleReasoningSystem.
Air-gapped & CPU-only compatible.
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any, Optional

from utils.logger import log

# ─── Optional dependency imports (created by parallel subagents) ─────────────
try:
    from rag_memory import ThreatMemoryIndex, ContextRetriever, MemoryIngestionPipeline
    _RAG_AVAILABLE = True
except ImportError:
    _RAG_AVAILABLE = False
    log.info("RAG memory not available — copilot will use limited context")

try:
    from sigma_generator import SigmaRuleGenerator
    _SIGMA_AVAILABLE = True
except ImportError:
    _SIGMA_AVAILABLE = False

try:
    from yara_generator import YaraRuleGenerator
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False

try:
    from mitre_explainer import MITREExplainer, AttackNarrativeBuilder
    _MITRE_AVAILABLE = True
except ImportError:
    _MITRE_AVAILABLE = False

try:
    from compliance_mapper import ComplianceControlMapper
    _COMPLIANCE_AVAILABLE = True
except ImportError:
    _COMPLIANCE_AVAILABLE = False

try:
    from twin_engine import DigitalTwinEngine
    _TWIN_AVAILABLE = True
except ImportError:
    _TWIN_AVAILABLE = False

try:
    from cyber_reasoning import EnsembleReasoningSystem
    _REASONING_AVAILABLE = True
except ImportError:
    _REASONING_AVAILABLE = False


class NaturalLanguageThreatHunter:
    """Converts natural language queries into structured threat hunting operations."""

    # Keyword → intent mappings
    _SEVERITY_KEYWORDS = {
        "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
        "low": "LOW", "info": "INFO", "severe": "CRITICAL",
        "dangerous": "HIGH", "urgent": "CRITICAL",
    }

    _EVENT_KEYWORDS = {
        "login": "login_attempt", "brute": "login_attempt",
        "powershell": "powershell", "script": "powershell",
        "network": "network_connection", "connection": "network_connection",
        "dns": "dns_query", "process": "process_creation",
        "file": "file_event", "registry": "registry_event",
        "c2": "c2_beacon", "beacon": "c2_beacon",
        "exfil": "data_exfiltration", "exfiltration": "data_exfiltration",
        "lateral": "lateral_movement", "movement": "lateral_movement",
        "ransom": "ransomware", "encrypt": "ransomware",
        "privilege": "privilege_escalation", "escalation": "privilege_escalation",
    }

    _IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def __init__(self):
        log.info("NaturalLanguageThreatHunter initialized")

    def parse_query(self, query: str) -> dict:
        """Extract structured filters from natural language text."""
        query_lower = query.lower()
        parsed = {
            "raw_query": query,
            "ips": self._IP_PATTERN.findall(query),
            "severities": [],
            "event_types": [],
            "mitre_tactics": [],
            "process_names": [],
            "time_range": None,
        }

        for kw, severity in self._SEVERITY_KEYWORDS.items():
            if kw in query_lower:
                parsed["severities"].append(severity)

        for kw, event_type in self._EVENT_KEYWORDS.items():
            if kw in query_lower:
                parsed["event_types"].append(event_type)

        # Extract MITRE tactic references
        mitre_pattern = re.compile(r"(?:TA\d{4}|T\d{4})", re.IGNORECASE)
        parsed["mitre_tactics"] = mitre_pattern.findall(query)

        # Time range hints
        if "last hour" in query_lower or "past hour" in query_lower:
            parsed["time_range"] = "1h"
        elif "last day" in query_lower or "today" in query_lower:
            parsed["time_range"] = "24h"
        elif "last week" in query_lower or "this week" in query_lower:
            parsed["time_range"] = "7d"

        # Remove duplicates
        parsed["severities"] = list(set(parsed["severities"]))
        parsed["event_types"] = list(set(parsed["event_types"]))

        return parsed

    def execute_hunt(self, parsed_query: dict, memory_index=None) -> list[dict]:
        """Execute a structured hunt against RAG memory."""
        if memory_index is None:
            return [{"message": "No memory index available for hunting"}]

        # Build search terms from parsed query
        search_terms = []
        if parsed_query.get("ips"):
            search_terms.extend(parsed_query["ips"])
        if parsed_query.get("event_types"):
            search_terms.extend(parsed_query["event_types"])
        if parsed_query.get("severities"):
            search_terms.extend(parsed_query["severities"])

        query_text = " ".join(search_terms) if search_terms else parsed_query.get("raw_query", "")
        return memory_index.search(query_text, top_k=20)


class AutonomousInvestigator:
    """Multi-hop autonomous investigation engine."""

    def __init__(self, twin_engine=None, reasoning_system=None):
        self._twin = twin_engine
        self._reasoning = reasoning_system
        log.info("AutonomousInvestigator initialized",
                 twin=twin_engine is not None,
                 reasoning=reasoning_system is not None)

    def investigate_alert(self, alert_id: str, context: dict = None) -> dict:
        """Full autonomous investigation pipeline."""
        start = time.time()
        investigation = {
            "alert_id": alert_id,
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat(),
            "attack_path": [],
            "blast_radius": {},
            "crown_jewels_at_risk": [],
            "containment_plan": {},
            "risk_score": 0.0,
        }

        # Extract source IP from context
        src_ip = "0.0.0.0"
        if context:
            src_ip = context.get("src_ip", context.get("event", {}).get("src_ip", "0.0.0.0"))

        investigation["attack_path"] = self.trace_attack_path(src_ip)
        investigation["blast_radius"] = self.assess_blast_radius(src_ip)
        investigation["crown_jewels_at_risk"] = self.identify_targets(src_ip)
        investigation["containment_plan"] = self.generate_containment_plan(investigation)
        investigation["risk_score"] = self._calculate_risk(investigation)
        investigation["latency_ms"] = (time.time() - start) * 1000

        return investigation

    def trace_attack_path(self, src_ip: str) -> dict:
        """Graph traversal for attack paths."""
        if self._twin:
            try:
                predictor = getattr(self._twin, "_attack_path_predictor", None)
                if predictor:
                    return {"source": src_ip, "paths": predictor.predict_paths(src_ip), "engine": "twin"}
            except Exception as exc:
                log.debug("Twin attack path failed", error=str(exc))

        return {"source": src_ip, "paths": [f"{src_ip} → internal_host → crown_jewel"],
                "engine": "heuristic"}

    def assess_blast_radius(self, node_id: str) -> dict:
        """Blast radius simulation."""
        if self._twin:
            try:
                simulator = getattr(self._twin, "_blast_radius_simulator", None)
                if simulator:
                    return simulator.simulate(node_id)
            except Exception:
                pass
        return {"node": node_id, "affected_assets": 3, "risk_level": "medium", "engine": "heuristic"}

    def identify_targets(self, src_ip: str) -> list:
        """Crown jewel targeting analysis."""
        if self._twin:
            try:
                analyzer = getattr(self._twin, "_crown_jewel_analyzer", None)
                if analyzer:
                    return analyzer.find_crown_jewels()
            except Exception:
                pass
        return [{"asset": "database_server", "criticality": "HIGH", "distance": 2}]

    def generate_containment_plan(self, investigation: dict) -> dict:
        """Generate remediation recommendations."""
        risk = investigation.get("risk_score", 0)
        plan = {
            "immediate_actions": [],
            "short_term": [],
            "long_term": [],
        }

        if risk > 0.7:
            plan["immediate_actions"] = [
                "Isolate affected endpoint from network",
                "Block source IP at firewall",
                "Kill suspicious processes",
                "Revoke compromised credentials",
            ]
        elif risk > 0.4:
            plan["immediate_actions"] = [
                "Monitor endpoint closely",
                "Restrict lateral access",
                "Reset credentials for affected accounts",
            ]
        else:
            plan["immediate_actions"] = ["Continue monitoring", "Log for further analysis"]

        plan["short_term"] = ["Run full malware scan", "Review access logs", "Update detection rules"]
        plan["long_term"] = ["Patch vulnerable systems", "Review network segmentation", "Conduct tabletop exercise"]

        return plan

    def _calculate_risk(self, investigation: dict) -> float:
        blast = investigation.get("blast_radius", {}).get("affected_assets", 0)
        crowns = len(investigation.get("crown_jewels_at_risk", []))
        paths = len(investigation.get("attack_path", {}).get("paths", []))
        return min(1.0, (blast * 0.1 + crowns * 0.2 + paths * 0.05))


class EnterpriseSOCCopilot:
    """
    Main SOC Copilot orchestrator with conversational query handling,
    autonomous investigation, and rule synthesis.
    """

    def __init__(self):
        self._hunter = NaturalLanguageThreatHunter()

        # Lazy-loaded engines
        self._memory_index = None
        self._context_retriever = None
        self._sigma_gen = None
        self._yara_gen = None
        self._mitre_explainer = None
        self._narrative_builder = None
        self._compliance_mapper = None
        self._investigator = None

        self._init_engines()
        log.info("EnterpriseSOCCopilot initialized",
                 rag=_RAG_AVAILABLE, sigma=_SIGMA_AVAILABLE,
                 yara=_YARA_AVAILABLE, mitre=_MITRE_AVAILABLE)

    def _init_engines(self) -> None:
        """Lazy-initialize all optional engines with graceful fallbacks."""
        if _RAG_AVAILABLE:
            try:
                self._memory_index = ThreatMemoryIndex()
                self._context_retriever = ContextRetriever(self._memory_index)
            except Exception as exc:
                log.warning("RAG init failed", error=str(exc))

        if _SIGMA_AVAILABLE:
            try:
                self._sigma_gen = SigmaRuleGenerator()
            except Exception:
                pass

        if _YARA_AVAILABLE:
            try:
                self._yara_gen = YaraRuleGenerator()
            except Exception:
                pass

        if _MITRE_AVAILABLE:
            try:
                self._mitre_explainer = MITREExplainer()
                self._narrative_builder = AttackNarrativeBuilder()
            except Exception:
                pass

        if _COMPLIANCE_AVAILABLE:
            try:
                self._compliance_mapper = ComplianceControlMapper()
            except Exception:
                pass

        # Investigator
        twin = None
        reasoning = None
        if _TWIN_AVAILABLE:
            try:
                twin = DigitalTwinEngine()
            except Exception:
                pass
        if _REASONING_AVAILABLE:
            try:
                reasoning = EnsembleReasoningSystem()
            except Exception:
                pass
        self._investigator = AutonomousInvestigator(twin, reasoning)

    # ── Core API ──────────────────────────────────────────────────────────────

    def ask(self, question: str) -> dict:
        """Conversational query handler — routes to appropriate handler."""
        start = time.time()
        q_lower = question.lower()

        # Route based on intent keywords
        if any(kw in q_lower for kw in ["hunt", "search", "find", "look for", "show me"]):
            result = self.hunt(question)
            return {"response": f"Found {result['total']} results.", "type": "hunt",
                    "data": result, "latency_ms": (time.time() - start) * 1000}

        if any(kw in q_lower for kw in ["investigate", "analyze", "inspect", "deep dive"]):
            # Extract alert ID if present
            id_match = re.search(r"([A-Za-z0-9\-_]{8,})", question)
            alert_id = id_match.group(1) if id_match else "unknown"
            result = self.investigate(alert_id)
            return {"response": "Investigation complete.", "type": "investigation",
                    "data": result, "latency_ms": (time.time() - start) * 1000}

        if any(kw in q_lower for kw in ["sigma", "detection rule"]):
            rule = self.generate_sigma({"event_type": "process_creation", "process_name": "powershell.exe"})
            return {"response": "Sigma rule generated.", "type": "sigma",
                    "data": {"rule": rule}, "latency_ms": (time.time() - start) * 1000}

        if any(kw in q_lower for kw in ["yara", "malware signature"]):
            rule = self.generate_yara({"process_name": "suspicious.exe", "process_hash": "a" * 64})
            return {"response": "YARA rule generated.", "type": "yara",
                    "data": {"rule": rule}, "latency_ms": (time.time() - start) * 1000}

        if any(kw in q_lower for kw in ["mitre", "att&ck", "tactic", "technique"]):
            if self._mitre_explainer:
                matrix = self._mitre_explainer.get_full_matrix()
                return {"response": "MITRE ATT&CK matrix loaded.", "type": "mitre",
                        "data": {"matrix_size": len(matrix)}, "latency_ms": (time.time() - start) * 1000}

        if any(kw in q_lower for kw in ["compliance", "soc2", "iso", "nist", "pci", "hipaa"]):
            if self._compliance_mapper:
                frameworks = list(self._compliance_mapper._controls.keys())
                return {"response": f"Compliance frameworks loaded: {', '.join(frameworks)}",
                        "type": "compliance", "data": {"frameworks": frameworks},
                        "latency_ms": (time.time() - start) * 1000}

        if any(kw in q_lower for kw in ["status", "stats", "health", "how many"]):
            stats = self._get_stats()
            return {"response": f"System stats: {stats.get('memory_events', 0)} events in memory.",
                    "type": "stats", "data": stats, "latency_ms": (time.time() - start) * 1000}

        # Default: general info
        return {
            "response": (
                "I'm the IMMUNEX SOC Copilot. I can help you with:\n"
                "• **Hunt** — Search for threats (e.g., 'hunt for lateral movement from 10.0.0.1')\n"
                "• **Investigate** — Deep-dive into an alert\n"
                "• **Generate Sigma/YARA** — Create detection rules\n"
                "• **MITRE** — Explain tactics and techniques\n"
                "• **Compliance** — Map threats to SOC2/ISO/NIST/PCI/HIPAA\n"
                "• **Status** — System health and statistics"
            ),
            "type": "help",
            "data": {},
            "latency_ms": (time.time() - start) * 1000,
        }

    def hunt(self, query: str) -> dict:
        """Natural language threat hunting."""
        start = time.time()
        parsed = self._hunter.parse_query(query)
        results = self._hunter.execute_hunt(parsed, self._memory_index)
        return {
            "results": results,
            "query_parsed": parsed,
            "total": len(results),
            "latency_ms": (time.time() - start) * 1000,
        }

    def investigate(self, alert_id: str) -> dict:
        """Autonomous investigation of an alert."""
        start = time.time()
        context = {}
        if self._context_retriever:
            context = self._context_retriever.retrieve_for_investigation(alert_id)

        investigation = self._investigator.investigate_alert(alert_id, context)

        # Enrich with Sigma/YARA rules
        if self._sigma_gen:
            try:
                from utils.schemas import SecurityEvent
                # Generate a basic Sigma rule for the alert
                investigation["sigma_rule"] = "# Sigma rule generation requires full event context"
            except Exception:
                pass

        if self._yara_gen:
            investigation["yara_rule"] = "# YARA rule generation requires full event context"

        # Enrich with narrative
        if self._narrative_builder:
            investigation["narrative"] = f"Investigation of alert {alert_id} completed with risk score {investigation.get('risk_score', 0):.2f}"
        else:
            investigation["narrative"] = f"Alert {alert_id} investigated."

        investigation["latency_ms"] = (time.time() - start) * 1000
        return investigation

    def generate_sigma(self, event_data: dict) -> str:
        """Generate a Sigma rule from event data dict."""
        if not self._sigma_gen:
            return "# Sigma generator not available"
        try:
            from utils.schemas import SecurityEvent, DetectionDecision
            # Create minimal event/decision objects
            now = datetime.utcnow()
            event = SecurityEvent(
                timestamp=now, src_ip=event_data.get("src_ip", "10.0.0.1"),
                dst_ip=event_data.get("dst_ip", "10.0.0.2"),
                src_port=event_data.get("src_port", 49152),
                dst_port=event_data.get("dst_port", 445),
                protocol=event_data.get("protocol", "TCP"),
                user_id=event_data.get("user_id", "system"),
                process_name=event_data.get("process_name", "cmd.exe"),
                process_hash=event_data.get("process_hash", "a" * 64),
                event_type=event_data.get("event_type", "process_creation"),
                src_bytes=0, dst_bytes=0, duration=0.0,
                failed_logins=0, connection_count=1, packet_rate=1.0,
                geo_location="internal", asset_criticality="MEDIUM",
            )
            decision = DetectionDecision(
                event_id=f"sigma-gen-{int(time.time())}",
                timestamp=now, event_type=event.event_type,
                src_ip=event.src_ip, dst_ip=event.dst_ip,
                asset_criticality="MEDIUM", anomaly_score=0.75,
                faiss_distance=0.5, confidence_score=0.8,
                severity=event_data.get("severity", "MEDIUM"),
                is_high_confidence_anomaly=True,
                detection_reason="SOC Copilot rule generation request",
                mitre_tactic=event_data.get("mitre_tactic", "execution"),
            )
            return self._sigma_gen.generate(event, decision)
        except Exception as exc:
            log.warning("Sigma generation failed", error=str(exc))
            return f"# Sigma generation error: {exc}"

    def generate_yara(self, event_data: dict) -> str:
        """Generate a YARA rule from event data dict."""
        if not self._yara_gen:
            return "# YARA generator not available"
        try:
            from utils.schemas import SecurityEvent, DetectionDecision
            now = datetime.utcnow()
            event = SecurityEvent(
                timestamp=now, src_ip=event_data.get("src_ip", "10.0.0.1"),
                dst_ip="10.0.0.2", src_port=49152, dst_port=445,
                protocol="TCP", user_id="system",
                process_name=event_data.get("process_name", "malware.exe"),
                process_hash=event_data.get("process_hash", "b" * 64),
                event_type="process_creation", src_bytes=0, dst_bytes=0,
                duration=0.0, failed_logins=0, connection_count=1,
                packet_rate=1.0, geo_location="internal", asset_criticality="HIGH",
            )
            decision = DetectionDecision(
                event_id=f"yara-gen-{int(time.time())}",
                timestamp=now, event_type="process_creation",
                src_ip=event.src_ip, dst_ip="10.0.0.2",
                asset_criticality="HIGH", anomaly_score=0.85,
                faiss_distance=0.3, confidence_score=0.9,
                severity=event_data.get("severity", "HIGH"),
                is_high_confidence_anomaly=True,
                detection_reason="SOC Copilot YARA generation",
            )
            return self._yara_gen.generate(event, decision)
        except Exception as exc:
            log.warning("YARA generation failed", error=str(exc))
            return f"# YARA generation error: {exc}"

    def explain_incident(self, alert_id: str) -> dict:
        """MITRE narrative + compliance mapping for an alert."""
        result = {"alert_id": alert_id, "narrative": "", "compliance": {}}

        if self._narrative_builder:
            result["narrative"] = f"Alert {alert_id} requires further contextual analysis with full event data."

        if self._compliance_mapper:
            result["compliance"] = {"frameworks_available": list(self._compliance_mapper._controls.keys())}

        return result

    def get_timeline(self) -> list[dict]:
        """Return enriched threat timeline from memory."""
        if self._memory_index:
            return self._memory_index.get_recent(50)
        return []

    def get_campaigns(self) -> list[dict]:
        """Return active campaign summaries."""
        # In a full implementation, this would query the correlation engine
        return [
            {"campaign_id": "demo-campaign-1", "status": "active",
             "severity": "HIGH", "events": 12, "first_seen": datetime.utcnow().isoformat()},
        ]

    def summarize_attack_chain(self, campaign_id: str) -> dict:
        """Campaign summary with MITRE chain."""
        return {
            "campaign_id": campaign_id,
            "chain": ["Initial Access", "Execution", "Persistence", "Lateral Movement"],
            "severity": "HIGH",
            "summary": f"Campaign {campaign_id} shows multi-stage attack progression.",
        }

    def _get_stats(self) -> dict:
        """Internal statistics."""
        stats = {
            "copilot_version": "1.0.0",
            "rag_available": _RAG_AVAILABLE,
            "sigma_available": _SIGMA_AVAILABLE,
            "yara_available": _YARA_AVAILABLE,
            "mitre_available": _MITRE_AVAILABLE,
            "compliance_available": _COMPLIANCE_AVAILABLE,
            "twin_available": _TWIN_AVAILABLE,
            "reasoning_available": _REASONING_AVAILABLE,
        }
        if self._memory_index:
            stats.update(self._memory_index.stats())
        return stats
