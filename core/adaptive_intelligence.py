"""
IMMUNEX Adaptive Intelligence Layer
=====================================
Layer 2 of the IMMUNEX detection stack.

Orchestrates:
  GraphEngine       → temporal attack graph
  CorrelationEngine → multi-stage attack detection
  MarkovPredictor   → attacker next-stage forecasting
  NarrativeEngine   → human-readable threat reports

Integration point: AdaptiveIntelligenceLayer.process(decision) receives a
DetectionDecision from the Layer 1 InnateImmunityLayer and returns either
None (single event, no campaign yet) or a fully populated ThreatReport.

The caller (main.py) simply calls process() on each decision; the layer
handles all internal state and logging transparently.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from core.correlation_engine import CorrelatedAttack, CorrelationEngine
from core.graph_engine import GraphEngine
from core.markov_predictor import MarkovPredictor
from core.narrative_engine import NarrativeEngine
from utils.logger import log
from utils.schemas import DetectionDecision


# ─── Threat Report ────────────────────────────────────────────────────────────

@dataclass
class ThreatReport:
    """
    Complete Layer 2 threat intelligence output for a correlated campaign.

    Consumed by:
    - main.py dashboard (display)
    - narrative_engine (formatting)
    - downstream SOAR / SIEM integrations (JSON export)
    """
    campaign_id:            str
    attacker_ip:            str
    target_ips:             list[str]
    stages_observed:        list[str]
    predicted_next_stage:   str
    prediction_confidence:  float
    risk_score:             float
    severity:               str
    narrative:              dict          # full narrative dict
    formatted_report:       str           # terminal-ready text
    correlated_at:          datetime      = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "campaign_id":           self.campaign_id,
            "attacker_ip":           self.attacker_ip,
            "target_ips":            self.target_ips,
            "stages_observed":       self.stages_observed,
            "predicted_next_stage":  self.predicted_next_stage,
            "prediction_confidence": round(self.prediction_confidence, 4),
            "risk_score":            round(self.risk_score, 4),
            "severity":              self.severity,
            "correlated_at":         self.correlated_at.isoformat(),
        }


# ─── Adaptive Intelligence Layer ─────────────────────────────────────────────

class AdaptiveIntelligenceLayer:
    """
    Layer 2: Adaptive Intelligence.

    Sits downstream of InnateImmunityLayer and consumes its DetectionDecisions.

    Lifecycle:
    1. Instantiate once at startup.
    2. Call process(decision) for every DetectionDecision from Layer 1.
    3. When a multi-stage campaign is detected, process() returns a ThreatReport.
    4. Call stats() at any time for telemetry.

    Example::

        layer2 = AdaptiveIntelligenceLayer()
        # in the main loop:
        report = layer2.process(decision)
        if report:
            print(report.formatted_report)
    """

    def __init__(
        self,
        max_graph_nodes: int = 5_000,
        max_graph_edges: int = 20_000,
        correlation_window_seconds: float = 300.0,
        markov_smoothing: float = 1.0,
        markov_prior_weight: float = 5.0,
    ) -> None:
        self._graph     = GraphEngine(max_nodes=max_graph_nodes, max_edges=max_graph_edges)
        self._markov    = MarkovPredictor(
            smoothing=markov_smoothing,
            prior_weight=markov_prior_weight,
        )
        self._correlator = CorrelationEngine(
            graph_engine=self._graph,
            markov_predictor=self._markov,
            correlation_window=correlation_window_seconds,
        )
        self._narrative = NarrativeEngine()

        self._events_processed:  int = 0
        self._reports_generated: int = 0
        self._start_time: float = time.time()

        log.info(
            "AdaptiveIntelligenceLayer initialised",
            max_graph_nodes=max_graph_nodes,
            correlation_window_s=correlation_window_seconds,
        )

    # ── Primary Processing ────────────────────────────────────────────────────

    def process(self, decision: DetectionDecision) -> Optional[ThreatReport]:
        """
        Process a single DetectionDecision through the full Layer 2 pipeline.

        Pipeline:
          DetectionDecision
            → GraphEngine.ingest()
            → CorrelationEngine.ingest()
            → (if multi-stage) NarrativeEngine.generate()
            → ThreatReport

        Args:
            decision: Output of InnateImmunityLayer.process().

        Returns:
            ThreatReport if a multi-stage campaign is detected, else None.
        """
        self._events_processed += 1

        try:
            # The correlation engine feeds the graph internally
            correlated: Optional[CorrelatedAttack] = self._correlator.ingest(decision)
        except Exception as exc:
            log.error(
                "AdaptiveIntelligenceLayer: correlation error",
                exc_info=exc,
                event_id=decision.event_id,
            )
            return None

        if correlated is None:
            return None

        try:
            report = self._build_report(correlated)
            self._reports_generated += 1
            return report
        except Exception as exc:
            log.error(
                "AdaptiveIntelligenceLayer: report generation error",
                exc_info=exc,
                campaign_id=correlated.campaign_id,
            )
            return None

    def process_batch(
        self, decisions: list[DetectionDecision]
    ) -> list[ThreatReport]:
        """Process a list of decisions, returning all generated reports."""
        reports: list[ThreatReport] = []
        for d in decisions:
            r = self.process(d)
            if r is not None:
                reports.append(r)
        return reports

    # ── Query / Inspection ────────────────────────────────────────────────────

    def get_graph_stats(self) -> dict:
        return self._graph.stats()

    def get_active_campaigns(self) -> dict:
        return self._correlator.get_active_profiles()

    def get_markov_stats(self) -> dict:
        return self._markov.stats()

    def predict_next_stage(self, current_stage: str) -> dict:
        """Direct Markov prediction query (useful for testing / SOAR)."""
        return self._markov.predict(current_stage)

    def stats(self) -> dict:
        uptime = time.time() - self._start_time
        return {
            "events_processed":  self._events_processed,
            "reports_generated": self._reports_generated,
            "uptime_seconds":    round(uptime, 1),
            "correlation":       self._correlator.stats(),
        }

    # ── Private ───────────────────────────────────────────────────────────────

    def _build_report(self, ca: CorrelatedAttack) -> ThreatReport:
        """Convert a CorrelatedAttack into a ThreatReport."""
        narrative     = self._narrative.generate(ca)
        formatted     = self._narrative.format_text(narrative)
        severity      = narrative["severity"]

        log.warning(
            "THREAT_REPORT generated",
            campaign_id=ca.campaign_id,
            severity=severity,
            attacker=ca.attacker_ip,
            stages=ca.stages_observed,
            predicted=ca.predicted_next_stage,
        )

        return ThreatReport(
            campaign_id=ca.campaign_id,
            attacker_ip=ca.attacker_ip,
            target_ips=list(ca.target_ips),
            stages_observed=list(ca.stages_observed),
            predicted_next_stage=ca.predicted_next_stage,
            prediction_confidence=ca.prediction_confidence,
            risk_score=ca.risk_score,
            severity=severity,
            narrative=narrative,
            formatted_report=formatted,
        )
