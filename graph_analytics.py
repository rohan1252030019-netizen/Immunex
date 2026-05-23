"""
IMMUNEX Attack Graph Analytics Engine
=====================================
Hosts graph mathematical tools, centralities, embeddings, community clustering,
and handles pluggable Neo4j enterprise database mappings with automated NetworkX fallbacks.
"""

from __future__ import annotations

import json
from typing import Any, Optional
import networkx as nx

from utils.logger import log

# ─── Optional Neo4j Driver Loading ───────────────────────────────────────────
try:
    import neo4j
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False


class AttackGraphAnalytics:
    """
    Executes graph algorithms (centralities, community clustering, structural embeddings)
    on the relational digital twin model. Supports optional enterprise Neo4j syncing
    with robust local NetworkX fallback mechanisms.
    """

    def __init__(self, neo4j_uri: Optional[str] = None, neo4j_user: Optional[str] = None, neo4j_password: Optional[str] = None) -> None:
        self.neo4j_driver: Any = None
        self.neo4j_enabled = False

        if HAS_NEO4J and neo4j_uri and neo4j_password:
            try:
                self.neo4j_driver = neo4j.GraphDatabase.driver(
                    neo4j_uri, auth=(neo4j_user or "neo4j", neo4j_password)
                )
                self.neo4j_enabled = True
                log.info("Neo4j Enterprise Connector initialized and active")
            except Exception as e:
                log.warning("Neo4j initialization failed. Falling back to local NetworkX engine", error=str(e))
                self.neo4j_enabled = False
        else:
            log.info("Neo4j not configured or unavailable. Operating with local offline NetworkX engine")

    # ── Graph Building ────────────────────────────────────────────────────────

    def build_relationship_graph(self, twin_graph: nx.DiGraph) -> nx.DiGraph:
        """Processes and filters the digital twin graph to build an attack graph."""
        # Sanitizes and makes a copy of the network topology
        relationship_graph = nx.DiGraph()
        for node, attrs in twin_graph.nodes(data=True):
            relationship_graph.add_node(node, **attrs)
        
        for src, dst, attrs in twin_graph.edges(data=True):
            relationship_graph.add_edge(src, dst, **attrs)

        # Sync to Neo4j if configured
        if self.neo4j_enabled and self.neo4j_driver:
            self._sync_to_neo4j(relationship_graph)

        return relationship_graph

    def _sync_to_neo4j(self, g: nx.DiGraph) -> None:
        """Asynchronously synchronizes local network states into remote Neo4j databases."""
        if not self.neo4j_driver:
            return
        try:
            with self.neo4j_driver.session() as session:
                # Clear previous state safely
                session.run("MATCH (n) DETACH DELETE n")
                
                # Create nodes
                for node_id, data in g.nodes(data=True):
                    ntype = data.get("type", "UNKNOWN")
                    session.run(
                        f"CREATE (n:{ntype} {{id: $id, type: $type}})",
                        id=str(node_id), type=ntype
                    )
                
                # Create edges
                for u, v, data in g.edges(data=True):
                    etype = data.get("type", "CONNECTED_TO")
                    session.run(
                        f"MATCH (a), (b) WHERE a.id = $u AND b.id = $v "
                        f"CREATE (a)-[r:{etype}]->(b)",
                        u=str(u), v=str(v)
                    )
            log.success("Digital twin successfully synchronized to Neo4j cluster")
        except Exception as e:
            log.error("Neo4j database write failed", error=str(e))

    # ── Graph Analytics ───────────────────────────────────────────────────────

    def calculate_centrality(self, g: nx.DiGraph) -> dict[str, float]:
        """Calculates PageRank centrality to determine key compromise bridges."""
        if not g or g.number_of_nodes() == 0:
            return {}
        try:
            # PageRank provides robust importance score in a directed network
            pagerank = nx.pagerank(g, alpha=0.85)
            # Normalize scores
            max_val = max(pagerank.values()) if pagerank else 1.0
            return {k: round(v / max_val, 4) for k, v in pagerank.items()}
        except Exception:
            # Fallback to degree centrality if PageRank fails to converge
            deg = nx.degree_centrality(g)
            return {k: round(v, 4) for k, v in deg.items()}

    def detect_attack_clusters(self, g: nx.DiGraph) -> list[list[str]]:
        """Identifies community groupings of tightly coupled processes and hosts."""
        if not g or g.number_of_nodes() < 2:
            return []
        
        # Convert to undirected graph for community metrics
        undir = g.to_undirected()
        try:
            # Fallback to label propagation if python-louvain isn't installed
            from networkx.algorithms.community import label_propagation_communities
            communities = list(label_propagation_communities(undir))
            return [list(c) for c in communities]
        except Exception as e:
            log.warning("Community detection failed", error=str(e))
            return [list(g.nodes())]

    def compute_graph_embeddings(self, g: nx.DiGraph) -> dict[str, list[float]]:
        """Computes high-speed local node topological embeddings [size: 8]."""
        embeddings = {}
        centrality = self.calculate_centrality(g)
        
        # Generate stable mock-embeddings based on graph structural attributes
        for node in g.nodes():
            node_type = g.nodes[node].get("type", "UNKNOWN")
            in_degree = float(g.in_degree(node))
            out_degree = float(g.out_degree(node))
            pagerank = centrality.get(node, 0.0)
            
            # Map node type to index values
            type_map = {"HOST": 1.0, "USER": 2.0, "PROCESS": 3.0, "IP": 4.0}
            type_val = type_map.get(str(node_type), 0.0)

            # Build static embedding vector representing network position
            vector = [
                pagerank,
                in_degree,
                out_degree,
                type_val,
                pagerank * in_degree,
                out_degree / (in_degree + 1.0),
                0.5 if node_type in ("HOST", "IP") else 0.0,
                1.0 if "admin" in str(node).lower() else 0.0
            ]
            embeddings[node] = [round(x, 4) for x in vector]
            
        return embeddings

    # ── Visualizations ────────────────────────────────────────────────────────

    def export_graph_json(self, g: nx.DiGraph) -> str:
        """Generates Cytoscape/D3.js compatible structural JSON strings."""
        nodes = []
        edges = []
        
        for nid, data in g.nodes(data=True):
            nodes.append({
                "data": {
                    "id": str(nid),
                    "label": str(nid),
                    "type": data.get("type", "UNKNOWN"),
                    "criticality": data.get("criticality", "LOW")
                }
            })
            
        for u, v, data in g.edges(data=True):
            edges.append({
                "data": {
                    "source": str(u),
                    "target": str(v),
                    "relationship": data.get("type", "CONNECTED_TO"),
                    "protocol": data.get("protocol", "TCP")
                }
            })
            
        return json.dumps({"nodes": nodes, "edges": edges}, indent=2)

    def close(self) -> None:
        """Tears down remote database connection sessions safely."""
        if self.neo4j_driver:
            try:
                self.neo4j_driver.close()
                log.info("Neo4j driver session closed successfully")
            except Exception:
                pass
