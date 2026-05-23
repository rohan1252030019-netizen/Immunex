"""
IMMUNEX Digital Twin Engine
===========================
Provides real-time environment modeling and attack path forecasting.
Maintains stateful representations of hosts, users, services, privileges,
and subnets, exposing simulators for ransomware spread, blast radius analysis,
crown jewel mapping, lateral movement prediction, and privilege escalation.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any, Optional
import networkx as nx

from utils.logger import log
from utils.schemas import SecurityEvent


# ─── Graph Node/Edge Type Constants ──────────────────────────────────────────

NODE_HOST = "HOST"
NODE_USER = "USER"
NODE_PROCESS = "PROCESS"
NODE_SERVICE = "SERVICE"
NODE_IP = "IP"
NODE_DOMAIN = "DOMAIN"
NODE_FILE = "FILE"
NODE_CONTAINER = "CONTAINER"
NODE_POD = "POD"
NODE_CLOUD_ACCOUNT = "CLOUD_ACCOUNT"
NODE_SESSION = "SESSION"

EDGE_LOGGED_INTO = "LOGGED_INTO"
EDGE_CONNECTED_TO = "CONNECTED_TO"
EDGE_EXECUTED = "EXECUTED"
EDGE_SPAWNED = "SPAWNED"
EDGE_AUTHENTICATED_TO = "AUTHENTICATED_TO"
EDGE_ACCESSED = "ACCESSED"
EDGE_COMMUNICATED_WITH = "COMMUNICATED_WITH"
EDGE_PRIV_ESC_TO = "PRIV_ESC_TO"
EDGE_MEMBER_OF = "MEMBER_OF"
EDGE_ASSUMED_ROLE = "ASSUMED_ROLE"


class DigitalTwinEngine:
    """
    Maintains a real-time relational model of the enterprise environment.
    Combines Asset, Identity, Privilege, Network, and Service graphs into a
    unified NetworkX directed graph representation.
    """

    def __init__(self) -> None:
        # A single multi-layered directed graph representing the enterprise twin
        self.graph: nx.DiGraph = nx.DiGraph()
        
        # Sub-components initialized with a reference to this engine
        self.blast_radius_simulator = BlastRadiusSimulator(self)
        self.crown_jewel_analyzer = CrownJewelAnalyzer(self)
        self.lateral_movement_predictor = LateralMovementPredictor(self)
        self.privilege_escalation_tracker = PrivilegeEscalationTracker(self)
        self.attack_path_predictor = AttackPathPredictor(self)
        
        # Bootstrap default nodes to ensure rich environment simulation out of the box
        self._bootstrap_environment()
        log.info("DigitalTwinEngine initialized with default environment twin")

    def _bootstrap_environment(self) -> None:
        """Seed the environment with a standard enterprise structure."""
        # Nodes
        hosts = [
            ("HOST-01", NODE_HOST, {"criticality": "LOW", "os": "Windows 11"}),
            ("HOST-02", NODE_HOST, {"criticality": "MEDIUM", "os": "Windows 10"}),
            ("WORKSTATION-22", NODE_HOST, {"criticality": "LOW", "os": "Windows 11"}),
            ("FILESERVER-01", NODE_HOST, {"criticality": "HIGH", "os": "Linux Ubuntu"}),
            ("DB-01", NODE_HOST, {"criticality": "CRITICAL", "os": "RedHat Enterprise"}),
            ("DC-01", NODE_HOST, {"criticality": "CRITICAL", "os": "Windows Server 2022"}),
        ]
        users = [
            ("admin_user", NODE_USER, {"privilege_level": "SYSTEM"}),
            ("john_doe", NODE_USER, {"privilege_level": "USER"}),
            ("jane_doe", NODE_USER, {"privilege_level": "USER"}),
            ("domain_admin", NODE_USER, {"privilege_level": "ADMIN"}),
        ]
        ips = [
            ("192.168.1.10", NODE_IP, {}),
            ("192.168.1.22", NODE_IP, {}),
            ("10.0.0.5", NODE_IP, {}),
            ("10.0.0.10", NODE_IP, {}),
        ]
        services = [
            ("Active Directory", NODE_SERVICE, {}),
            ("SQLDatabase", NODE_SERVICE, {}),
            ("SMBShare", NODE_SERVICE, {}),
        ]

        for nid, ntype, attrs in hosts + users + ips + services:
            self.graph.add_node(nid, type=ntype, **attrs)

        # Connect IPs to Hosts
        self.graph.add_edge("192.168.1.10", "HOST-01", type=EDGE_CONNECTED_TO)
        self.graph.add_edge("192.168.1.22", "WORKSTATION-22", type=EDGE_CONNECTED_TO)
        self.graph.add_edge("10.0.0.5", "DB-01", type=EDGE_CONNECTED_TO)
        self.graph.add_edge("10.0.0.10", "DC-01", type=EDGE_CONNECTED_TO)

        # Connect Users / Groups / Roles
        self.graph.add_edge("john_doe", "HOST-01", type=EDGE_LOGGED_INTO)
        self.graph.add_edge("jane_doe", "HOST-02", type=EDGE_LOGGED_INTO)
        self.graph.add_edge("domain_admin", "DC-01", type=EDGE_LOGGED_INTO)
        self.graph.add_edge("admin_user", "FILESERVER-01", type=EDGE_LOGGED_INTO)

        # Network Paths
        self.graph.add_edge("HOST-01", "FILESERVER-01", type=EDGE_COMMUNICATED_WITH, protocol="SMB")
        self.graph.add_edge("WORKSTATION-22", "FILESERVER-01", type=EDGE_COMMUNICATED_WITH, protocol="SMB")
        self.graph.add_edge("FILESERVER-01", "DB-01", type=EDGE_COMMUNICATED_WITH, protocol="TCP")
        self.graph.add_edge("FILESERVER-01", "DC-01", type=EDGE_COMMUNICATED_WITH, protocol="Kerberos")
        self.graph.add_edge("HOST-02", "DC-01", type=EDGE_COMMUNICATED_WITH, protocol="RDP")

        # Privilege & Sudo transitions
        self.graph.add_edge("john_doe", "admin_user", type=EDGE_PRIV_ESC_TO)
        self.graph.add_edge("admin_user", "domain_admin", type=EDGE_PRIV_ESC_TO)

    # ── Telemetry Ingestion ───────────────────────────────────────────────────

    def ingest_event(self, event: SecurityEvent) -> None:
        """Dynamically updates the Digital Twin with incoming telemetry."""
        # Sanitize event inputs
        src_ip = str(event.src_ip).strip()
        dst_ip = str(event.dst_ip).strip()
        user_id = str(event.user_id).strip()
        proc_name = str(event.process_name).strip()

        # 1. Update/Add IP nodes
        if src_ip not in self.graph:
            self.graph.add_node(src_ip, type=NODE_IP, criticality=event.asset_criticality)
        if dst_ip not in self.graph:
            self.graph.add_node(dst_ip, type=NODE_IP, criticality=event.asset_criticality)

        # 2. Update/Add User node
        if user_id not in self.graph:
            self.graph.add_node(user_id, type=NODE_USER, privilege_level="USER")

        # 3. Add Edge user logged into src IP
        self.graph.add_edge(user_id, src_ip, type=EDGE_LOGGED_INTO, timestamp=event.timestamp)

        # 4. Add communication path between IPs
        self.graph.add_edge(src_ip, dst_ip, type=EDGE_COMMUNICATED_WITH, protocol=event.protocol, timestamp=event.timestamp)

        # 5. Handle Process Executions
        proc_id = f"proc::{proc_name}@{src_ip}"
        if proc_id not in self.graph:
            self.graph.add_node(proc_id, type=NODE_PROCESS, name=proc_name)
        self.graph.add_edge(src_ip, proc_id, type=EDGE_EXECUTED, timestamp=event.timestamp)

        # 6. Analyze privilege and lateral patterns
        if event.failed_logins > 3:
            # Mark risk transition
            self.graph.edges[user_id, src_ip]["brute_force_detected"] = True

        log.debug("DigitalTwin updated from event", event_type=event.event_type, src=src_ip, dst=dst_ip)


# ─── Sub-Component Simulators ────────────────────────────────────────────────

class BlastRadiusSimulator:
    """Estimates spread impact and ransomware propagation metrics."""

    def __init__(self, engine: DigitalTwinEngine) -> None:
        self.engine = engine

    def simulate_ransomware_spread(self, start_node_id: str, network_infection_prob: float = 0.45) -> dict:
        """Simulates lateral ransomware spreading from a starting point."""
        if start_node_id not in self.engine.graph:
            return {"blast_radius_score": 0.0, "estimated_hosts_impacted": 0, "critical_assets_at_risk": 0}

        visited = {start_node_id}
        queue = [(start_node_id, 1.0)]  # (node, infection probability)
        hosts_impacted = 0
        critical_assets_at_risk = 0

        while queue:
            curr, prob = queue.pop(0)
            if prob < 0.1:
                continue

            node_data = self.engine.graph.nodes[curr]
            if node_data.get("type") == NODE_HOST or node_data.get("type") == NODE_IP:
                hosts_impacted += 1
                if node_data.get("criticality") in ("HIGH", "CRITICAL"):
                    critical_assets_at_risk += 1

            for neighbor in self.engine.graph.neighbors(curr):
                if neighbor not in visited:
                    visited.add(neighbor)
                    # Infection spreads through active network/communicated connections
                    edge_data = self.engine.graph.edges[curr, neighbor]
                    trans_prob = network_infection_prob
                    if edge_data.get("type") == EDGE_PRIV_ESC_TO:
                        trans_prob = 0.8  # high transition probability on privilege links
                    queue.append((neighbor, prob * trans_prob))

        total_hosts = max(1, sum(1 for n, d in self.engine.graph.nodes(data=True) if d.get("type") in (NODE_HOST, NODE_IP)))
        blast_score = min(1.0, hosts_impacted / total_hosts)

        return {
            "blast_radius_score": round(blast_score, 4),
            "estimated_hosts_impacted": hosts_impacted,
            "critical_assets_at_risk": critical_assets_at_risk,
        }

    def calculate_blast_radius(self, node_id: str) -> dict:
        """Calculates default blast metrics, including reachable hosts and privilege vectors."""
        return self.simulate_ransomware_spread(node_id, network_infection_prob=0.5)

    def estimate_propagation_speed(self, node_id: str) -> float:
        """Estimates spread speed coefficient [0.0, 10.0] based on node degree and centrality."""
        if node_id not in self.engine.graph:
            return 0.0
        degree = self.engine.graph.degree(node_id)
        # Higher density = faster spread speed
        speed = min(10.0, float(degree) * 1.5)
        return round(speed, 2)


class CrownJewelAnalyzer:
    """Discovers and ranks high-value enterprise assets."""

    def __init__(self, engine: DigitalTwinEngine) -> None:
        self.engine = engine

    def identify_crown_jewels(self) -> list[str]:
        """Scans nodes to pinpoint Domain Controllers, DBs, and target systems."""
        jewels = []
        for nid, data in self.engine.graph.nodes(data=True):
            ntype = data.get("type")
            name = str(nid).lower()
            criticality = data.get("criticality", "")
            
            # Match crown-jewel features
            if criticality == "CRITICAL":
                jewels.append(nid)
            elif ntype == NODE_HOST and ("dc-" in name or "db-" in name or "ad-" in name or "ldap" in name):
                jewels.append(nid)
            elif ntype == NODE_SERVICE and ("active directory" in name or "database" in name):
                jewels.append(nid)

        return list(set(jewels))

    def calculate_asset_criticality(self, node_id: str) -> float:
        """Calculates asset criticality score between 0.0 and 1.0."""
        if node_id not in self.engine.graph:
            return 0.0
        data = self.engine.graph.nodes[node_id]
        crit_map = {"LOW": 0.25, "MEDIUM": 0.50, "HIGH": 0.75, "CRITICAL": 1.00}
        return crit_map.get(data.get("criticality", ""), 0.3)

    def rank_assets(self) -> list[dict]:
        """Returns sorted list of assets ordered by criticality."""
        ranked = []
        for nid, d in self.engine.graph.nodes(data=True):
            if d.get("type") in (NODE_HOST, NODE_IP, NODE_SERVICE):
                ranked.append({"asset": nid, "criticality_score": self.calculate_asset_criticality(nid)})
        ranked.sort(key=lambda x: x["criticality_score"], reverse=True)
        return ranked


class LateralMovementPredictor:
    """Predicts next-hop attacker lateral steps."""

    def __init__(self, engine: DigitalTwinEngine) -> None:
        self.engine = engine

    def predict_next_hop(self, source_node_id: str) -> dict:
        """Selects the most likely neighbor destination and movement path type."""
        if source_node_id not in self.engine.graph:
            return {"source": source_node_id, "target": None, "probability": 0.0}

        best_target = None
        best_prob = 0.0
        
        for neighbor in self.engine.graph.neighbors(source_node_id):
            prob = self.calculate_lateral_probability(source_node_id, neighbor)
            if prob > best_prob:
                best_prob = prob
                best_target = neighbor

        return {
            "source": source_node_id,
            "target": best_target,
            "probability": round(best_prob, 4),
        }

    def calculate_lateral_probability(self, source_id: str, target_id: str) -> float:
        """Estimates connection feasibility using trust links, protocols, and active sessions."""
        if not self.engine.graph.has_edge(source_id, target_id):
            return 0.0
        
        edge_data = self.engine.graph.edges[source_id, target_id]
        etype = edge_data.get("type")
        protocol = edge_data.get("protocol", "")
        
        # Calculate base probability based on protocol and relation types
        prob = 0.2
        if etype == EDGE_COMMUNICATED_WITH:
            prob = 0.4
            if protocol in ("RDP", "SSH", "SMB"):
                prob = 0.75
        elif etype == EDGE_PRIV_ESC_TO:
            prob = 0.85
        elif etype == EDGE_LOGGED_INTO:
            prob = 0.65
            
        return prob

    def enumerate_attack_paths(self, source_id: str, target_id: str) -> list[list[str]]:
        """Returns all simple paths between nodes of maximum length 4."""
        if source_id not in self.engine.graph or target_id not in self.engine.graph:
            return []
        try:
            return list(nx.all_simple_paths(self.engine.graph, source_id, target_id, cutoff=4))
        except nx.NetworkXNoPath:
            return []


class PrivilegeEscalationTracker:
    """Tracks identity and role delegation privilege inheritances."""

    def __init__(self, engine: DigitalTwinEngine) -> None:
        self.engine = engine

    def trace_privilege_chain(self, start_node_id: str) -> list[str]:
        """Traces ascending privilege dependencies (who can transition to who)."""
        if start_node_id not in self.engine.graph:
            return []
        
        chain = [start_node_id]
        curr = start_node_id
        visited = {curr}
        
        while True:
            escalated = False
            # Find neighboring edges representing privilege escalations
            for neighbor in self.engine.graph.neighbors(curr):
                edge_data = self.engine.graph.edges[curr, neighbor]
                if edge_data.get("type") == EDGE_PRIV_ESC_TO and neighbor not in visited:
                    curr = neighbor
                    chain.append(curr)
                    visited.add(curr)
                    escalated = True
                    break
            if not escalated:
                break
        return chain

    def detect_escalation_paths(self, node_id: str) -> list[list[str]]:
        """Finds all privilege loops or linear paths starting from this node."""
        if node_id not in self.engine.graph:
            return []
        paths = []
        for node in self.engine.graph.nodes():
            if node != node_id and self.engine.graph.nodes[node].get("type") == NODE_USER:
                p = self.trace_privilege_chain(node_id)
                if len(p) > 1:
                    paths.append(p)
        return paths

    def score_privilege_risk(self, node_id: str) -> float:
        """Determines the privilege amplification index [0.0, 1.0]."""
        chain = self.trace_privilege_chain(node_id)
        # Longer chain of privilege transitions implies higher inherent path risk
        risk = min(1.0, len(chain) * 0.25)
        return round(risk, 4)


class AttackPathPredictor:
    """Finds traversal routes to crown-jewel nodes."""

    def __init__(self, engine: DigitalTwinEngine) -> None:
        self.engine = engine

    def find_path_to_crown_jewel(self, source_id: str) -> dict:
        """Finds shortest route to any identified crown jewel."""
        if source_id not in self.engine.graph:
            return {"path": [], "risk_score": 0.0}

        crown_jewels = self.engine.crown_jewel_analyzer.identify_crown_jewels()
        best_path = []
        best_risk = 0.0

        for jewel in crown_jewels:
            if jewel == source_id:
                continue
            try:
                path = nx.shortest_path(self.engine.graph, source_id, jewel)
                if not best_path or len(path) < len(best_path):
                    best_path = path
                    best_risk = self.calculate_path_risk(path)
            except nx.NetworkXNoPath:
                continue
            except nx.NodeNotFound:
                continue

        return {"path": best_path, "risk_score": round(best_risk, 4)}

    def calculate_path_risk(self, path: list[str]) -> float:
        """Aggregates step risks along an exploitation path."""
        if not path or len(path) < 2:
            return 0.0
        
        total_risk = 1.0
        for i in range(len(path) - 1):
            src, dst = path[i], path[i+1]
            step_prob = self.engine.lateral_movement_predictor.calculate_lateral_probability(src, dst)
            if step_prob == 0.0:
                step_prob = 0.1  # base connection risk
            total_risk *= step_prob
            
        # Exploitability risk scales inversely with hops and directly with probabilities
        path_risk = min(1.0, (1.0 - total_risk) + (0.1 * len(path)))
        return round(path_risk, 4)

    def enumerate_compromise_routes(self, source_id: str) -> list[dict]:
        """Lists compromise paths mapped to distinct crown jewels."""
        routes = []
        crown_jewels = self.engine.crown_jewel_analyzer.identify_crown_jewels()
        for j in crown_jewels:
            try:
                path = nx.shortest_path(self.engine.graph, source_id, j)
                routes.append({"target": j, "path": path, "risk_score": self.calculate_path_risk(path)})
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
        return routes
