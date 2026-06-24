"""
scaled_tkg_detector.py
----------------------
Scaled Enterprise Architecture for Temporal Knowledge Graph Zero-Day Detection.
Procedurally generates a 35+ node active topology, learns multi-node baselines,
and isolates lateral movement chains using PyVis interactive graph visualization.
"""

import collections
import dataclasses
import logging
import math
import os
import random
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple
from pyvis.network import Network
import networkx as nx

# Configure production forensic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [SCALE_TKG_ENGINE] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


@dataclasses.dataclass(frozen=True)
class TKGQuadruplet:
    """Represents a fundamental atomic fact within the Temporal Knowledge Graph."""
    subject: str
    relation: str
    obj: str
    timestamp: datetime


class TemporalKnowledgeGraph:
    """Manages the in-memory state of the time-evolving network graph infrastructure."""
    def __init__(self, retention_window_hours: int = 4):
        self.retention_window = timedelta(hours=retention_window_hours)
        self.ledger: List[TKGQuadruplet] = []
        self.forward_adjacency: Dict[str, Dict[str, List[Tuple[str, datetime]]]] = collections.defaultdict(
            lambda: collections.defaultdict(list)
        )

    def add_fact(self, subject: str, relation: str, obj: str, timestamp: datetime):
        """Ingests a time-stamped interaction into the graph schema bounds."""
        quad = TKGQuadruplet(subject, relation, obj, timestamp)
        self.ledger.append(quad)
        self.forward_adjacency[subject][relation].append((obj, timestamp))
        self._prune_expired_history(timestamp)

    def _prune_expired_history(self, current_time: datetime):
        """Slides the temporal window forward to optimize memory boundaries."""
        boundary = current_time - self.retention_window
        initial_count = len(self.ledger)
        self.ledger = [q for q in self.ledger if q.timestamp >= boundary]

        if len(self.ledger) < initial_count:
            self.forward_adjacency.clear()
            for q in self.ledger:
                self.forward_adjacency[q.subject][q.relation].append((q.obj, q.timestamp))

    def get_historical_sequence(self, subject: str, relation: str, windows: int = 5) -> List[int]:
        """Extracts interaction sequence rates over partitioned historical intervals."""
        if subject not in self.forward_adjacency or relation not in self.forward_adjacency[subject]:
            return [0] * windows

        end_time = self.ledger[-1].timestamp if self.ledger else datetime.now(timezone.utc)
        start_time = end_time - self.retention_window
        interval = self.retention_window / windows

        counts = [0] * windows
        for obj, t in self.forward_adjacency[subject][relation]:
            for i in range(windows):
                window_start = start_time + (i * interval)
                window_end = window_start + interval
                if window_start <= t < window_end:
                    counts[i] += 1
                    break
        return counts


class TemporalEmbeddingEngine:
    """Quantifies dynamic node representation shifts by calculating structural velocity."""
    @staticmethod
    def compute_temporal_velocity(sequence: List[int]) -> float:
        if len(sequence) < 2:
            return 0.0
        diffs = [sequence[i+1] - sequence[i] for i in range(len(sequence)-1)]
        weights = [math.exp(i / len(diffs)) for i in range(len(diffs))]
        weighted_velocity = sum(d * w for d, w in zip(diffs, weights)) / sum(weights)
        return round(weighted_velocity, 4)


class ZeroDayThreatDetector:
    """Analyzes temporal state transitions to isolate low-and-slow exploit paths."""
    def __init__(self, anomaly_threshold: float = 2.0):
        self.anomaly_threshold = anomaly_threshold
        self.baseline_velocities: Dict[str, List[float]] = collections.defaultdict(list)
        self.is_training_locked = False

    def lock_baseline(self):
        self.is_training_locked = True
        logging.info("TKG Threat Engine baseline locked. Transitioning to active zero-day monitoring.")

    def evaluate_activity(self, subject: str, relation: str, sequence: List[int]) -> Tuple[bool, float]:
        velocity = TemporalEmbeddingEngine.compute_temporal_velocity(sequence)
        key = f"{subject}::{relation}"

        history = self.baseline_velocities[key]

        if len(history) == 0 and self.is_training_locked:
            return True, 99.9  # Unseen interaction profile during runtime = immediate anomaly

        if len(history) < 5 and not self.is_training_locked:
            self.baseline_velocities[key].append(velocity)
            return False, 0.0

        mean_v = sum(history) / len(history) if history else 0.0
        variance = sum((x - mean_v) ** 2 for x in history) / len(history) if history else 0.01
        std_dev = math.sqrt(variance) if variance > 0 else 0.01

        z_score = abs(velocity - mean_v) / std_dev

        if not self.is_training_locked:
            self.baseline_velocities[key].append(velocity)

        if z_score > self.anomaly_threshold:
            return True, round(z_score, 2)
        return False, round(z_score, 2)


def generate_large_scale_visualization(tkg: TemporalKnowledgeGraph, alert_edges: List[Tuple[str, str]], filename="enterprise_temporal_map.html"):
    """Compiles the complete multi-node ledger state into an interactive HTML visualization."""
    logging.info("Rendering expanded network topology map (30+ Nodes)...")
    net = Network(height="850px", width="100%", bgcolor="#090b0e", font_color="#ffffff", select_menu=True)
    nx_graph = nx.DiGraph()

    # Track distinct node groups for color maps
    for quad in tkg.ledger:
        sub, obj, rel = quad.subject, quad.obj, quad.relation

        # Determine logical layer categorizations
        for node_id in [sub, obj]:
            if "Subnet" in node_id:
                group = "subnet"
            elif "Switch" in node_id or "Gateway" in node_id:
                group = "hardware"
            elif "Server" in node_id or "DB" in node_id:
                group = "server"
            elif "External" in node_id:
                group = "threat"
            else:
                group = "endpoint"
            nx_graph.add_node(node_id, label=node_id, group=group)

        # Color specific vectors bright crimson if flagged by the anomaly engine
        is_alert = (sub, obj) in alert_edges
        edge_color = "#ff2a55" if is_alert else "#3a4b5c"
        edge_width = 4.5 if is_alert else 1.2

        nx_graph.add_edge(
            sub, obj,
            title=f"Relation: {rel}\nLast Observed: {quad.timestamp.strftime('%H:%M:%S')}",
            color=edge_color, width=edge_width, arrows="to"
        )

    net.from_nx(nx_graph)

    # Map physical design attributes per group layer
    for node in net.nodes:
        ngroup = node["group"]
        if ngroup == "subnet":
            node["color"], node["shape"], node["size"] = "#4dadff", "hexagon", 26
        elif ngroup == "hardware":
            node["color"], node["shape"], node["size"] = "#ffd166", "square", 22
        elif ngroup == "server":
            node["color"], node["shape"], node["size"] = "#06d6a0", "database", 24
        elif ngroup == "threat":
            node["color"], node["shape"], node["size"] = "#ff4a4a", "triangle", 30
        else:
            node["color"], node["shape"], node["size"] = "#83c5be", "dot", 14

    net.set_options("""
    var options = {
      "physics": {
        "barnesHut": { "gravitationalConstant": -6000, "centralGravity": 0.1, "springLength": 120, "springConstant": 0.04 },
        "solver": "barnesHut"
      }
    }
    """)
    net.write_html(filename)
    logging.info(f"[SUCCESS] Enterprise security dashboard exported to: {os.path.abspath(filename)}")


# ==========================================
# Orchestration Execution Context
# ==========================================
if __name__ == "__main__":
    print("=" * 80)
    print("   TEMPORAL KNOWLEDGE GRAPH - ENTERPRISE TOPOLOGY THREAT DETECTOR")
    print("=" * 80)

    tkg = TemporalKnowledgeGraph(retention_window_hours=4)
    detector = ZeroDayThreatDetector(anomaly_threshold=2.2)
    base_time = datetime.now(timezone.utc)

    # 1. Procedural Inventory Layout Definition
    subnets = [f"Subnet_{i:02d}" for i in range(1, 6)]                         # 5 Subnets
    switches = ["Switch_Core", "Switch_Alpha", "Switch_Beta", "Gateway_DMZ"]  # 4 Infrastructure Nodes
    servers = ["Web_Server_01", "Web_Server_02", "App_Server_Auth", "App_Server_Logic", "DB_Active", "DB_Replica"]

    # Generate 20 unique internal workstation endpoint hosts
    endpoints = [f"Host_10_0_1_{i}" for i in range(10, 20)] + [f"Host_172_16_2_{i}" for i in range(50, 60)]

    print(f"[INFO] Initializing environment state mapping with {len(subnets)+len(switches)+len(servers)+len(endpoints)} unique nodes.")

    # 2. Phase 1: Ingest continuous background administrative activity
    logging.info("Phase 1: Generating baseline traffic profiles across topology...")

    # Establish structural graph backbones
    for minutes_offset in range(0, 180, 10):  # 3-Hour window step simulation
        timestamp = base_time + timedelta(minutes=minutes_offset)

        # Route subnets to infrastructure switches
        for i, subnet in enumerate(subnets):
            target_switch = switches[1] if i < 3 else switches[2]
            tkg.add_fact(subnet, "ROUTES_TRAFFIC_TO", target_switch, timestamp)
            tkg.add_fact(target_switch, "UPLINKS_TO", "Switch_Core", timestamp)

        # Switches polling connected endpoint pools
        for host in endpoints:
            associated_switch = switches[1] if "10_0" in host else switches[2]
            tkg.add_fact(associated_switch, "POLLS_STATUS", host, timestamp)

        # Core DMZ communication tracking
        tkg.add_fact("Switch_Core", "ROUTES_TRAFFIC_TO", "Gateway_DMZ", timestamp)
        tkg.add_fact("Gateway_DMZ", "FORWARDS_TRAFFIC_TO", "Web_Server_01", timestamp)
        tkg.add_fact("Gateway_DMZ", "FORWARDS_TRAFFIC_TO", "Web_Server_02", timestamp)
        tkg.add_fact("Web_Server_01", "QUERIES_DATA_FROM", "App_Server_Logic", timestamp)
        tkg.add_fact("App_Server_Logic", "COMMITS_TO", "DB_Active", timestamp)
        tkg.add_fact("DB_Active", "REPLICATES_TO", "DB_Replica", timestamp)

        # Keep evaluating historical velocities during setup to train thresholds
        for quad in tkg.ledger[-5:]:
            seq = tkg.get_historical_sequence(quad.subject, quad.relation)
            detector.evaluate_activity(quad.subject, quad.relation, seq)

    # Transition out of baseline training mode
    detector.lock_baseline()

    # 3. Phase 2: Live monitoring stream with an intrusive zero-day vector
    logging.info("Phase 2: Monitoring active. Injecting multi-stage structural exploit corridor...")

    # Weave the zero-day threat through specific structural nodes in our inventory
    attack_timeline = [
        (190, "External_Unmapped_IP", "EXPLOITS_PORT_80", "Web_Server_01"),
        (195, "Web_Server_01", "PIVOTS_RECONNAISSANCE", "Switch_Core"),
        (200, "Switch_Core", "FORCES_MALICIOUS_FIRMWARE", "DB_Active"),
        (205, "DB_Active", "EXFILTRATES_DUMP", "External_Command_Control")
    ]

    flagged_exploit_corridor = []

    for offset, sub, rel, obj in attack_timeline:
        event_time = base_time + timedelta(minutes=offset)
        tkg.add_fact(sub, rel, obj, event_time)

        sequence = tkg.get_historical_sequence(sub, rel)
        is_anomaly, metric_score = detector.evaluate_activity(sub, rel, sequence)

        if is_anomaly:
            logging.critical(
                f"🚨 ZERO-DAY ALERT: Isolated Temporal Mutation Footprint! "
                f"Vector: [{sub}] -[:{rel}]-> [{obj}] | Temporal Score: {metric_score}"
            )
            flagged_exploit_corridor.append((sub, obj))
        else:
            logging.info(f"Event verified safe: [{sub}] -[:{rel}]-> [{obj}]")

    # 4. Compile map output
    generate_large_scale_visualization(tkg, flagged_exploit_corridor, filename="enterprise_temporal_map.html")
    print("=" * 80)
