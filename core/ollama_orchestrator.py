"""
IMMUNEX Layer 3 — Ollama Orchestrator
=======================================
Local LLM orchestration layer using Ollama for fully offline inference.

This module provides:
  OllamaOrchestrator — manages connectivity, prompt dispatch, and response
                       parsing for all Ollama model interactions.

Design principles:
  • CPU-only optimised — no GPU requirement
  • Fully offline — no external API calls
  • Timeout + retry with exponential back-off
  • Strict JSON output parsing with malformed-response recovery
  • Token-efficient prompting (structured prompt templates)
  • Multiple model support with automatic fallback

Supported models (in preference order):
  1. mistral:7b-instruct-q4_K_M
  2. llama3:8b-instruct-q4_K_M
  3. phi3:mini
  4. deepseek-coder:6.7b-instruct-q4_K_M

If no Ollama server is reachable the orchestrator returns a structured
fallback response generated deterministically from the input data, allowing
the rest of the pipeline to continue uninterrupted.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Optional

from utils.logger import log


# ─── Configuration ────────────────────────────────────────────────────────────

OLLAMA_BASE_URL: str = "http://localhost:11434"
OLLAMA_API_GENERATE: str = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_API_TAGS: str = f"{OLLAMA_BASE_URL}/api/tags"

DEFAULT_MODELS: list[str] = [
    "mistral:7b-instruct-q4_K_M",
    "mistral",
    "llama3:8b-instruct-q4_K_M",
    "llama3",
    "phi3:mini",
    "phi3",
    "deepseek-coder:6.7b-instruct-q4_K_M",
    "deepseek-coder",
]

REQUEST_TIMEOUT_SECONDS: int = 120
MAX_RETRIES: int = 3
RETRY_BACKOFF_BASE: float = 2.0


# ─── Prompt Templates ─────────────────────────────────────────────────────────

PLAYBOOK_SYSTEM_PROMPT = """You are IMMUNEX, an autonomous SOC AI. You generate structured incident 
response playbooks in strict JSON format. Output ONLY valid JSON — no markdown, no code fences, 
no preamble, no explanation. Your JSON must match the requested schema exactly."""

PLAYBOOK_USER_TEMPLATE = """Generate a structured incident response playbook for the following 
security campaign. Return ONLY a JSON object with the exact keys specified below.

CAMPAIGN DATA:
- Campaign ID: {campaign_id}
- Attacker IP: {attacker_ip}
- Target IPs: {target_ips}
- Attack Stages: {stages_observed}
- Predicted Next Stage: {predicted_next_stage}
- Threat Severity: {severity}
- Risk Score: {risk_score}
- Attack Narrative: {narrative_summary}
- Recommended Action: {recommended_action}
- Policy Verdict: {policy_verdict}

Required JSON structure (ALL fields required):
{{
  "executive_summary": "2-3 sentence executive summary of the incident",
  "threat_severity": "{severity}",
  "severity_justification": "why this severity was assigned",
  "mitre_techniques": [
    {{"id": "T1234", "name": "Technique Name", "tactic": "Tactic Name"}}
  ],
  "root_cause_analysis": "root cause analysis paragraph",
  "initial_access_vector": "how the attacker gained initial access",
  "threat_actor_summary": "threat actor behaviour summary",
  "ttp_summary": "TTPs observed during the campaign",
  "containment_strategy": "primary containment strategy description",
  "containment_steps": ["step 1", "step 2", "step 3"],
  "recovery_plan": "recovery plan description",
  "recovery_steps": ["step 1", "step 2", "step 3"],
  "hardening_recommendations": ["rec 1", "rec 2", "rec 3"],
  "compliance_frameworks": ["PCI-DSS", "SOC2"],
  "compliance_impact": "compliance implications of this incident",
  "blast_radius_description": "estimated blast radius description",
  "potential_data_exposure": "description of potential data exposure"
}}"""

NARRATIVE_SYSTEM_PROMPT = """You are IMMUNEX, a cybersecurity AI analyst. You produce concise, 
structured security incident summaries. Output ONLY valid JSON — no markdown, no extra text."""

NARRATIVE_USER_TEMPLATE = """Summarise this security campaign in JSON format:

CAMPAIGN: {campaign_id}
ATTACKER: {attacker_ip}
STAGES: {stages}
SEVERITY: {severity}

Return JSON:
{{
  "one_line_summary": "one sentence summary",
  "attack_description": "2 sentence attack description",
  "immediate_risk": "immediate risk to the organisation",
  "actor_motivation": "likely threat actor motivation"
}}"""


# ─── Ollama Orchestrator ──────────────────────────────────────────────────────


class OllamaOrchestrator:
    """
    Manages all interactions with the local Ollama inference server.

    Usage::

        orch = OllamaOrchestrator()
        available = orch.check_availability()
        if available:
            result = orch.generate_playbook_content(campaign_data)
        else:
            result = orch.fallback_playbook_content(campaign_data)
    """

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        timeout: int = REQUEST_TIMEOUT_SECONDS,
        max_retries: int = MAX_RETRIES,
        preferred_models: list[str] | None = None,
        enable: bool = True,
    ) -> None:
        self._base_url = base_url
        self._timeout = timeout
        self._max_retries = max_retries
        self._models = preferred_models or DEFAULT_MODELS
        self._active_model: Optional[str] = None
        self._available: bool = False

        import sys
        if enable and "pytest" not in sys.modules:
            self._probe()
        else:
            log.info("OllamaOrchestrator: explicitly disabled by configuration or pytest")

    # ── Public API ────────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Return True if Ollama is reachable and at least one model is loaded."""
        return self._available and self._active_model is not None

    def active_model(self) -> str:
        """Return the name of the currently active model."""
        return self._active_model or "offline-fallback"

    def generate_playbook_content(self, campaign_data: dict) -> dict:
        """
        Generate playbook narrative content via the Ollama LLM.

        Falls back to deterministic generation if Ollama is unavailable.

        Args:
            campaign_data: Dict with campaign context fields.

        Returns:
            Dict with playbook narrative fields.
        """
        if not self.is_available():
            log.warning("OllamaOrchestrator: offline — using deterministic fallback")
            return self._deterministic_playbook_content(campaign_data)

        prompt = PLAYBOOK_USER_TEMPLATE.format(**campaign_data)
        raw = self._generate(
            system=PLAYBOOK_SYSTEM_PROMPT,
            prompt=prompt,
        )

        parsed = self._parse_json_response(raw)
        if parsed is None:
            log.warning("OllamaOrchestrator: JSON parse failed — using fallback")
            return self._deterministic_playbook_content(campaign_data)

        return parsed

    def generate_narrative_summary(self, campaign_data: dict) -> dict:
        """
        Generate a concise narrative summary for the campaign.

        Args:
            campaign_data: Campaign context (campaign_id, attacker_ip, stages, severity).

        Returns:
            Dict with summary fields.
        """
        if not self.is_available():
            return self._deterministic_narrative_summary(campaign_data)

        prompt = NARRATIVE_USER_TEMPLATE.format(**campaign_data)
        raw = self._generate(
            system=NARRATIVE_SYSTEM_PROMPT,
            prompt=prompt,
        )

        parsed = self._parse_json_response(raw)
        if parsed is None:
            return self._deterministic_narrative_summary(campaign_data)
        return parsed

    # ── Private: Ollama HTTP ──────────────────────────────────────────────────

    def _probe(self) -> None:
        """Check Ollama server reachability and discover an available model."""
        try:
            import urllib.request
            import urllib.error

            req = urllib.request.Request(
                OLLAMA_API_TAGS,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())

            loaded_models: list[str] = [m["name"] for m in data.get("models", [])]
            log.info("OllamaOrchestrator: server reachable", models=loaded_models)

            # Pick first preferred model that is available
            for preferred in self._models:
                for loaded in loaded_models:
                    if preferred.split(":")[0] in loaded:
                        self._active_model = loaded
                        self._available = True
                        log.info(
                            "OllamaOrchestrator: selected model",
                            model=self._active_model,
                        )
                        return

            if loaded_models:
                self._active_model = loaded_models[0]
                self._available = True
                log.warning(
                    "OllamaOrchestrator: no preferred model found — using first available",
                    model=self._active_model,
                )
            else:
                log.warning("OllamaOrchestrator: server reachable but no models loaded")

        except Exception as exc:
            log.warning(
                "OllamaOrchestrator: Ollama server not reachable — fallback mode",
                error=str(exc),
            )
            self._available = False

    def _generate(self, system: str, prompt: str) -> str:
        """
        Send a generation request to Ollama with retry and timeout handling.

        Returns:
            Raw string response from the model.
        """
        import urllib.request
        import urllib.error

        payload = json.dumps({
            "model": self._active_model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 2048,
            },
        }).encode()

        for attempt in range(1, self._max_retries + 1):
            try:
                t0 = time.perf_counter()
                req = urllib.request.Request(
                    OLLAMA_API_GENERATE,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    data = json.loads(resp.read().decode())
                    elapsed = (time.perf_counter() - t0) * 1000

                    response_text = data.get("response", "")
                    log.info(
                        "OllamaOrchestrator: generation complete",
                        model=self._active_model,
                        latency_ms=round(elapsed, 1),
                        tokens=data.get("eval_count", 0),
                    )
                    return response_text

            except Exception as exc:
                wait = RETRY_BACKOFF_BASE ** attempt
                log.warning(
                    "OllamaOrchestrator: generation attempt failed",
                    attempt=attempt,
                    max_retries=self._max_retries,
                    error=str(exc),
                    retry_in_s=wait,
                )
                if attempt < self._max_retries:
                    time.sleep(wait)

        log.error("OllamaOrchestrator: all retries exhausted")
        return ""

    # ── Private: JSON Parsing ─────────────────────────────────────────────────

    def _parse_json_response(self, raw: str) -> Optional[dict]:
        """
        Robustly extract JSON from an LLM response.

        Handles:
          • Clean JSON (ideal case)
          • JSON wrapped in markdown code fences (```json … ```)
          • JSON embedded in surrounding prose
        """
        if not raw:
            return None

        # Attempt 1: Direct parse
        try:
            return json.loads(raw.strip())
        except json.JSONDecodeError:
            pass

        # Attempt 2: Strip markdown fences
        fence_match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", raw)
        if fence_match:
            try:
                return json.loads(fence_match.group(1))
            except json.JSONDecodeError:
                pass

        # Attempt 3: Extract first JSON object from prose
        obj_match = re.search(r"\{[\s\S]+\}", raw)
        if obj_match:
            try:
                return json.loads(obj_match.group())
            except json.JSONDecodeError:
                pass

        log.warning(
            "OllamaOrchestrator: could not extract JSON from response",
            raw_preview=raw[:200],
        )
        return None

    # ── Deterministic Fallbacks ───────────────────────────────────────────────

    def _deterministic_playbook_content(self, data: dict) -> dict:
        """
        Generate structured playbook content deterministically when Ollama is
        unavailable.  Uses campaign data to produce meaningful, context-aware
        output without any LLM inference.
        """
        stages = data.get("stages_observed", ["Unknown"])
        severity = data.get("severity", "HIGH")
        attacker = data.get("attacker_ip", "Unknown")
        campaign_id = data.get("campaign_id", "UNKNOWN")
        action = data.get("recommended_action", "Log_Event")
        next_stage = data.get("predicted_next_stage", "Unknown")

        stage_mitre = {
            "Reconnaissance": ("T1595", "Active Scanning", "Reconnaissance"),
            "Credential_Access": ("T1110", "Brute Force", "Credential Access"),
            "Lateral_Movement": ("T1021", "Remote Services", "Lateral Movement"),
            "Execution": ("T1059", "Command and Scripting Interpreter", "Execution"),
            "Persistence": ("T1053", "Scheduled Task/Job", "Persistence"),
            "Privilege_Escalation": ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
            "Exfiltration": ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
        }

        mitre_techniques = []
        for stage in stages:
            if stage in stage_mitre:
                tid, name, tactic = stage_mitre[stage]
                mitre_techniques.append({"id": tid, "name": name, "tactic": tactic})

        stage_list_str = " → ".join(stages)

        return {
            "executive_summary": (
                f"A {severity}-severity multi-stage attack campaign (ID: {campaign_id[:12]}) "
                f"was detected originating from {attacker}. "
                f"The attacker progressed through {len(stages)} kill-chain stages "
                f"({stage_list_str}), with the next predicted stage being '{next_stage}'. "
                f"Immediate containment action '{action}' has been recommended."
            ),
            "threat_severity": severity,
            "severity_justification": (
                f"Severity rated {severity} based on multi-stage attack progression "
                f"({len(stages)} stages detected), target asset criticality, "
                "and predicted campaign escalation trajectory."
            ),
            "mitre_techniques": mitre_techniques,
            "root_cause_analysis": (
                f"The attack originated from IP {attacker} and exploited weaknesses "
                "in network perimeter controls and authentication mechanisms. "
                f"The campaign followed a structured kill-chain: {stage_list_str}."
            ),
            "initial_access_vector": (
                f"Initial access via {stages[0] if stages else 'Unknown'} "
                "techniques detected at network boundary."
            ),
            "threat_actor_summary": (
                f"Threat actor at {attacker} demonstrated structured, multi-stage TTPs "
                "consistent with a sophisticated persistent threat. "
                "Behaviour patterns suggest automated tooling combined with manual operator guidance."
            ),
            "ttp_summary": (
                f"Observed TTPs span {len(stages)} MITRE ATT&CK tactics. "
                f"Stages: {stage_list_str}. "
                "Actor used network scanning, credential attacks, and attempted lateral spread."
            ),
            "containment_strategy": (
                f"Primary containment via '{action}' to disrupt active campaign. "
                "Network-layer controls applied at ingress and internal chokepoints. "
                "Affected segments isolated pending forensic review."
            ),
            "containment_steps": [
                f"Execute approved mitigation: {action}",
                f"Block all inbound/outbound traffic from {attacker}",
                "Enable enhanced logging on all affected segments",
                "Deploy honeypot decoys to monitor attacker persistence attempts",
                f"Isolate affected hosts from {', '.join(data.get('target_ips', ['unknown'])[:3])}",
            ],
            "recovery_plan": (
                "Systematic recovery following confirmed containment. "
                "Restore services from verified clean backups. "
                "Re-issue compromised credentials and rotate all secrets."
            ),
            "recovery_steps": [
                "Confirm attacker eviction via network monitoring",
                "Restore affected services from last-known-good snapshots",
                "Rotate all credentials and API keys on affected systems",
                "Re-enable services incrementally with enhanced monitoring",
                "Conduct post-incident review within 48 hours",
            ],
            "hardening_recommendations": [
                "Implement zero-trust network architecture with micro-segmentation",
                "Deploy MFA on all privileged accounts and critical systems",
                "Enable EDR with real-time process monitoring on all endpoints",
                "Implement network traffic baselining and anomaly detection",
                "Conduct quarterly red team exercises targeting identified attack vectors",
                "Deploy deception technologies (honeypots) across critical segments",
            ],
            "compliance_frameworks": ["PCI-DSS", "SOC 2 Type II", "ISO 27001", "NIST CSF"],
            "compliance_impact": (
                f"This {severity} incident may trigger mandatory breach notification "
                "requirements under applicable data protection regulations. "
                "PCI-DSS Requirement 10 (logging) and Requirement 11 (testing) are implicated. "
                "Incident must be logged in the risk register within 24 hours."
            ),
            "blast_radius_description": (
                f"Estimated {len(data.get('target_ips', ['unknown']))} directly affected hosts. "
                "Potential spread to adjacent network segments if lateral movement succeeded. "
                "Payment systems and core banking assets assessed for secondary exposure."
            ),
            "potential_data_exposure": (
                "Customer PII, financial transaction records, and authentication credentials "
                "may have been accessed or exfiltrated during the Exfiltration stage. "
                "Full forensic analysis required to determine scope."
            ),
        }

    def _deterministic_narrative_summary(self, data: dict) -> dict:
        """Generate a deterministic narrative summary without LLM."""
        stages = data.get("stages", ["Unknown"])
        severity = data.get("severity", "HIGH")
        attacker = data.get("attacker_ip", "Unknown")
        campaign_id = data.get("campaign_id", "UNKNOWN")

        return {
            "one_line_summary": (
                f"{severity}-severity multi-stage attack campaign from {attacker} "
                f"spanning {len(stages)} kill-chain stages"
            ),
            "attack_description": (
                f"Attacker at {attacker} executed a structured campaign progressing through "
                f"{' → '.join(stages)}. "
                "The campaign demonstrates deliberate, goal-oriented attacker behaviour "
                "consistent with a targeted intrusion."
            ),
            "immediate_risk": (
                "Immediate risk of data exfiltration, lateral movement to adjacent systems, "
                "and persistence establishment if not contained."
            ),
            "actor_motivation": (
                "Financial gain or espionage — consistent with structured kill-chain "
                "progression targeting banking and payment infrastructure."
            ),
        }
