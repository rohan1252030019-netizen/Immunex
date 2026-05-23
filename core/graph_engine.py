"""
IMMUNEX Graph Engine
====================
Builds and manages temporal attack graphs from Layer 1 anomaly alerts.

Each node represents a security entity (IP, user, process, asset, hash)
with threat metadata, timestamps and risk scores.

Each edge represents a temporal relationship between entities derived
from a DetectionDecision, annotated with attack-stage mapping.

The graph is maintained in-process as a directed, time-ordered networkx
DiGraph. Connected components are analysed to reconstruct multi-stage
attack chains.
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Optional

import networkx as nx

from utils.constants import (
    ASSET_CRITICALITY_SCORE,
    EVENT_TYPE_MAP,
    MALICIOUS_EVENT_TYPES,
    SEVERITY_ORDER,
)
from utils.logger import log
from utils.schemas import DetectionDecision, SecurityEvent

# ─── Attack Stage Mapping ─────────────────────────────────────────────────────

EVENT_TO_STAGE: dict[str, str] = {
    # Reconnaissance
    "Port_Scan":                "Reconnaissance",
    "Network_Sweep":            "Reconnaissance",
    # Credential Access
    "Brute_Force_Login":        "Credential_Access",
    "Password_Spray":           "Credential_Access",
    # Lateral Movement (inferred from high connection count anomalies)
    "Normal_Connection":        "Lateral_Movement",
    # Execution
    "PowerShell_Execution":     "Execution",
    "Suspicious_Process_Spawn": "Execution",
    # Persistence
    "Registry_Modification":    "Persistence",
    "Scheduled_Task":           "Persistence",
    # Privilege Escalation (mapped from process anomalies)
    "File_Access":              "Privilege_Escalation",
    # Exfiltration
    "Data_Exfiltration":        "Exfiltration",
    "DNS_Tunneling":            "Exfiltration",
    # Generic
    "Process_Start":            "Execution",
    "Authentication_Success":   "Credential_Access",
    "DNS_Query":                "Reconnaissance",
    "HTTP_Request":             "Lateral_Movement",
}

STAGE_SEVERITY_WEIGHT: dict[str, float] = {
    "Reconnaissance":       0.20,
    "Credential_Access":    0.40,
    "Lateral_Movement":     0.55,
    "Execution":            0.65,
    "Persistence":          0.75,
    "Privilege_Escalation": 0.85,
    "Exfiltration":         1.00,
}

# ─── Entity Types ─────────────────────────────────────────────────────────────

ENTITY_IP      = "ip_address"
ENTITY_USER    = "user"
ENTITY_PROCESS = "process"
ENTITY_ASSET   = "asset"
ENTITY_HASH    = "hash"


def _node_id(entity_type: str, value: str) -> str:
    """Stable, deterministic node identifier."""
    return f"{entity_type}::{value}"


def _edge_id(src: str, dst: str, ts: datetime) -> str:
    raw = f"{src}|{dst}|{ts.isoformat()}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


# ─── Graph Engine ─────────────────────────────────────────────────────────────

class GraphEngine:
    """
    Temporal attack graph built from DetectionDecision objects.

    Nodes – keyed by (entity_type, value):
        timestamp_first  : datetime  – first seen
        timestamp_last   : datetime  – most recent observation
        risk_score       : float     – max anomaly score observed
        entity_type      : str       – one of ENTITY_* constants
        threat_metadata  : dict      – event types, stages, criticality
        observation_count: int       – how many times this node was hit

    Edges – directed src → dst:
        event_relationship : str  – e.g. "IP initiated brute-force by USER"
        temporal_sequence  : int  – monotonically increasing counter
        attack_stage       : str  – mapped attack kill-chain stage
        anomaly_score      : float
        faiss_distance     : float
        timestamp          : datetime
        edge_id            : str  – short hash identifier
    """

    def __init__(self, max_nodes: int = 5_000, max_edges: int = 20_000) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()
        self._max_nodes = max_nodes
        self._max_edges = max_edges
        self._edge_counter: int = 0
        self._alerts_ingested: int = 0
        # Cache: ip → list of event timestamps for temporal correlation
        self._ip_timeline: dict[str, list[datetime]] = defaultdict(list)
        log.info("GraphEngine initialised", max_nodes=max_nodes, max_edges=max_edges)

    # ── Public Interface ──────────────────────────────────────────────────────

    def ingest(self, decision: DetectionDecision) -> list[str]:
        """
        Ingest a DetectionDecision and update the attack graph.

        Only high-confidence anomalies contribute to the graph.
        Returns the list of node IDs that were added or updated.
        """
        if not decision.is_high_confidence_anomaly:
            return []

        self._alerts_ingested += 1
        event: Optional[SecurityEvent] = decision.raw_event

        stage = EVENT_TO_STAGE.get(decision.event_type, "Reconnaissance")
        risk  = decision.anomaly_score

        # ── Build node set ────────────────────────────────────────────────────
        nodes_updated: list[str] = []

        src_ip_node = self._upsert_node(
            entity_type=ENTITY_IP,
            value=decision.src_ip,
            timestamp=decision.timestamp,
            risk=risk,
            metadata={
                "event_types": [decision.event_type],
                "stages": [stage],
                "asset_criticality": decision.asset_criticality,
                "severity": decision.severity,
            },
        )
        nodes_updated.append(src_ip_node)

        dst_ip_node = self._upsert_node(
            entity_type=ENTITY_IP,
            value=decision.dst_ip,
            timestamp=decision.timestamp,
            risk=risk * 0.5,  # destination has lower attributed risk
            metadata={
                "event_types": [decision.event_type],
                "stages": [stage],
                "asset_criticality": decision.asset_criticality,
                "severity": "INFO",
            },
        )
        nodes_updated.append(dst_ip_node)

        # Add user / process / hash nodes only when raw event is available
        if event is not None:
            user_node = self._upsert_node(
                entity_type=ENTITY_USER,
                value=event.user_id,
                timestamp=decision.timestamp,
                risk=risk,
                metadata={"stages": [stage], "severity": decision.severity},
            )
            nodes_updated.append(user_node)

            proc_node = self._upsert_node(
                entity_type=ENTITY_PROCESS,
                value=event.process_name,
                timestamp=decision.timestamp,
                risk=risk,
                metadata={"stages": [stage]},
            )
            nodes_updated.append(proc_node)

            hash_node = self._upsert_node(
                entity_type=ENTITY_HASH,
                value=event.process_hash[:16],  # abbreviated
                timestamp=decision.timestamp,
                risk=risk,
                metadata={"full_hash": event.process_hash},
            )
            nodes_updated.append(hash_node)

            asset_node = self._upsert_node(
                entity_type=ENTITY_ASSET,
                value=f"{decision.dst_ip}:{event.dst_port}",
                timestamp=decision.timestamp,
                risk=ASSET_CRITICALITY_SCORE.get(decision.asset_criticality, 1) / 4.0,
                metadata={"criticality": decision.asset_criticality},
            )
            nodes_updated.append(asset_node)

        # ── Build edges ───────────────────────────────────────────────────────
        self._add_edge(
            src=src_ip_node,
            dst=dst_ip_node,
            stage=stage,
            decision=decision,
            relationship=f"{decision.src_ip} → {decision.event_type} → {decision.dst_ip}",
        )

        if event is not None:
            self._add_edge(
                src=src_ip_node,
                dst=user_node,
                stage=stage,
                decision=decision,
                relationship=f"IP operated as user {event.user_id}",
            )
            self._add_edge(
                src=user_node,
                dst=proc_node,
                stage=stage,
                decision=decision,
                relationship=f"user {event.user_id} spawned {event.process_name}",
            )
            self._add_edge(
                src=proc_node,
                dst=hash_node,
                stage=stage,
                decision=decision,
                relationship=f"process image hash observed",
            )
            if event is not None:
                self._add_edge(
                    src=proc_node,
                    dst=asset_node,
                    stage=stage,
                    decision=decision,
                    relationship=f"{event.process_name} accessed asset",
                )

        # ── Prune if graph grows too large ────────────────────────────────────
        self._prune_if_needed()

        log.debug(
            "GraphEngine: ingested alert",
            src_ip=decision.src_ip,
            stage=stage,
            nodes_updated=len(nodes_updated),
            total_nodes=self._graph.number_of_nodes(),
            total_edges=self._graph.number_of_edges(),
        )
        return nodes_updated

    def get_attack_chains(self) -> list[list[str]]:
        """
        Return all weakly connected components as potential attack chains.
        Components with only one node are excluded (no lateral movement).
        """
        components = list(nx.weakly_connected_components(self._graph))
        return [list(c) for c in components if len(c) > 1]

    def get_subgraph_for_ip(self, ip: str) -> nx.DiGraph:
        """Return the ego-graph centred on an IP node (radius 2)."""
        node_id = _node_id(ENTITY_IP, ip)
        if node_id not in self._graph:
            return nx.DiGraph()
        return nx.ego_graph(self._graph, node_id, radius=2)

    def get_node_data(self, node_id: str) -> dict:
        return dict(self._graph.nodes.get(node_id, {}))

    def get_edge_data(self, src: str, dst: str) -> dict:
        return dict(self._graph.edges.get((src, dst), {}))

    def reconstruct_chain(self, component_nodes: list[str]) -> dict:
        """
        Walk a connected component and reconstruct an ordered attack chain.

        Returns a dict with:
          - ordered_stages : list of (stage, node_id, timestamp) triples
          - start_time     : datetime of earliest event
          - end_time       : datetime of latest event
          - attacker_ips   : list of IP nodes in component
          - target_assets  : list of ASSET nodes in component
          - risk_score     : aggregate risk for the chain
        """
        subgraph = self._graph.subgraph(component_nodes)
        nodes_data = [
            (n, self._graph.nodes[n])
            for n in component_nodes
            if n in self._graph.nodes
        ]

        # Sort by first-seen timestamp
        nodes_data.sort(key=lambda x: x[1].get("timestamp_first", datetime.min))

        attacker_ips: list[str] = []
        target_assets: list[str] = []
        ordered_stages: list[tuple[str, str, datetime]] = []
        seen_stages: set[str] = set()
        risk_scores: list[float] = []

        for node_id, data in nodes_data:
            etype = data.get("entity_type", "")
            ts    = data.get("timestamp_last", datetime.utcnow())
            risk  = data.get("risk_score", 0.0)
            risk_scores.append(risk)

            if etype == ENTITY_IP:
                stages = data.get("threat_metadata", {}).get("stages", [])
                for stage in stages:
                    if stage not in seen_stages:
                        seen_stages.add(stage)
                        ordered_stages.append((stage, node_id, ts))
                if data.get("risk_score", 0) > 0.3:
                    attacker_ips.append(node_id)

            elif etype == ENTITY_ASSET:
                target_assets.append(node_id)

        # Sort ordered_stages by their timestamp
        ordered_stages.sort(key=lambda x: x[2])

        timestamps = [
            d.get("timestamp_first")
            for _, d in nodes_data
            if d.get("timestamp_first")
        ]

        return {
            "ordered_stages": ordered_stages,
            "start_time": min(timestamps) if timestamps else datetime.utcnow(),
            "end_time":   max(
                d.get("timestamp_last", datetime.utcnow())
                for _, d in nodes_data
            ),
            "attacker_ips":   attacker_ips,
            "target_assets":  target_assets,
            "risk_score":     max(risk_scores) if risk_scores else 0.0,
            "component_size": len(component_nodes),
        }

    def stats(self) -> dict:
        return {
            "nodes":           self._graph.number_of_nodes(),
            "edges":           self._graph.number_of_edges(),
            "alerts_ingested": self._alerts_ingested,
            "attack_chains":   len(self.get_attack_chains()),
        }

    # ── Private Helpers ───────────────────────────────────────────────────────

    def _upsert_node(
        self,
        entity_type: str,
        value: str,
        timestamp: datetime,
        risk: float,
        metadata: dict,
    ) -> str:
        node_id = _node_id(entity_type, value)

        if node_id in self._graph:
            existing = self._graph.nodes[node_id]
            # Update risk (keep max)
            existing["risk_score"] = max(existing.get("risk_score", 0.0), risk)
            # Update last-seen timestamp
            existing["timestamp_last"] = timestamp
            existing["observation_count"] = existing.get("observation_count", 1) + 1
            # Merge threat_metadata lists
            for k, v in metadata.items():
                if isinstance(v, list):
                    cur = existing.get("threat_metadata", {}).get(k, [])
                    existing.setdefault("threat_metadata", {})[k] = list(set(cur + v))
                else:
                    existing.setdefault("threat_metadata", {})[k] = v
        else:
            self._graph.add_node(
                node_id,
                entity_type=entity_type,
                value=value,
                timestamp_first=timestamp,
                timestamp_last=timestamp,
                risk_score=risk,
                threat_metadata=metadata,
                observation_count=1,
            )
        return node_id

    def _add_edge(
        self,
        src: str,
        dst: str,
        stage: str,
        decision: DetectionDecision,
        relationship: str,
    ) -> None:
        self._edge_counter += 1
        # If edge already exists, update it rather than duplicate
        if self._graph.has_edge(src, dst):
            ed = self._graph.edges[src, dst]
            ed["temporal_sequence"] = self._edge_counter
            ed["timestamp"] = decision.timestamp
            ed["anomaly_score"] = max(ed.get("anomaly_score", 0), decision.anomaly_score)
        else:
            self._graph.add_edge(
                src,
                dst,
                event_relationship=relationship,
                temporal_sequence=self._edge_counter,
                attack_stage=stage,
                anomaly_score=decision.anomaly_score,
                faiss_distance=decision.faiss_distance,
                timestamp=decision.timestamp,
                edge_id=_edge_id(src, dst, decision.timestamp),
            )

    def _prune_if_needed(self) -> None:
        """Remove oldest (lowest observation count) nodes when limits are exceeded."""
        if self._graph.number_of_nodes() > self._max_nodes:
            # Remove nodes sorted by observation_count ascending, then by timestamp
            candidates = sorted(
                self._graph.nodes(data=True),
                key=lambda x: (
                    x[1].get("observation_count", 0),
                    x[1].get("timestamp_first", datetime.min),
                ),
            )
            to_remove = [n for n, _ in candidates[: self._graph.number_of_nodes() - self._max_nodes]]
            self._graph.remove_nodes_from(to_remove)
            log.debug("GraphEngine: pruned old nodes", removed=len(to_remove))
