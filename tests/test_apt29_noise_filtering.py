"""
Unit & Integration Tests for Noise Filtering and Subgraph Pruning on APT29 Simulation Trace
"""

import json
from pathlib import Path
import pytest
from aira.core.normalizer import EventNormalizer
from aira.core.graph_builder import AttackGraphBuilder
from aira.core.mitre_mapper import MitreMapper
from aira.core.reasoning_agent import AIRAReasoningAgent


@pytest.fixture
def apt29_dataset():
    p = Path(__file__).resolve().parent.parent / "aira" / "data" / "samples" / "mordor_apt29_noisy.json"
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def test_apt29_investigation_and_noise_filtering(apt29_dataset):
    normalizer = EventNormalizer()
    events = normalizer.normalize_batch(apt29_dataset)
    assert len(events) == len(apt29_dataset)

    builder = AttackGraphBuilder()
    full_graph = builder.build_graph(events)
    total_raw_nodes = full_graph.number_of_nodes()
    assert total_raw_nodes >= 25

    mapper = MitreMapper()
    agent = AIRAReasoningAgent(builder, mapper)
    investigation = agent.investigate(events)

    # Verify APT29 techniques detected
    tech_ids = {t.id for h in investigation["hypotheses"] for t in h.mitre_techniques}
    assert "T1105" in tech_ids  # Ingress Tool Transfer (certutil)
    assert "T1218.011" in tech_ids  # Rundll32 Proxy Execution
    assert "T1069.002" in tech_ids  # Domain Admins group discovery
    assert "T1071.001" in tech_ids  # C2 HTTPS Beaconing
    assert "T1047" in tech_ids  # WMI Execution
    assert "T1560" in tech_ids  # Archive Collected Data

    # Test Causal Subgraph Noise Pruning
    subgraph, noise_metrics = builder.filter_noise(investigation["suspicious_nodes"])
    assert noise_metrics["noise_reduction_pct"] > 35.0
    assert noise_metrics["noise_nodes_filtered"] > 10

    # Verify attack nodes are retained
    attack_node_names = " ".join(noise_metrics["attack_subgraph_nodes"])
    assert "rundll32.exe" in attack_node_names
    assert "certutil.exe" in attack_node_names
    assert "WMIC.exe" in attack_node_names

    # Verify unlinked benign background processes are pruned out of the attack subgraph!
    assert "Spotify.exe" not in attack_node_names
    assert "OneDrive.exe" not in attack_node_names
