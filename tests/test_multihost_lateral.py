"""
Tests for AIRA Enterprise Multi-Host Lateral Movement Chaining
Validates cross-host graph edge creation, backward provenance walking across machines,
multi-host hypothesis generation, NTDS AD extraction detection, and action synthesis.
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from aira.core.normalizer import EventNormalizer
from aira.core.graph_builder import AttackGraphBuilder
from aira.core.mitre_mapper import MitreMapper
from aira.core.reasoning_agent import AIRAReasoningAgent
from aira.core.copilot import AIRACoPilot
from aira.ui.app import app

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "aira" / "data" / "samples"
MULTIHOST_FILE = SAMPLE_DIR / "enterprise_multihost_attack.json"


@pytest.fixture
def multihost_events():
    assert MULTIHOST_FILE.exists(), f"Sample file not found: {MULTIHOST_FILE}"
    with open(MULTIHOST_FILE, "r", encoding="utf-8") as f:
        raw = json.load(f)
    normalizer = EventNormalizer()
    return normalizer.normalize_batch(raw)


def test_multihost_normalization(multihost_events):
    assert len(multihost_events) == 16
    hosts = {e.host for e in multihost_events}
    assert hosts == {"CORP-WKS-042", "CORP-DC-001"}
    
    # Workstation events and DC events
    wks_events = [e for e in multihost_events if e.host == "CORP-WKS-042"]
    dc_events = [e for e in multihost_events if e.host == "CORP-DC-001"]
    assert len(wks_events) == 10
    assert len(dc_events) == 6


def test_multihost_graph_construction_and_lateral_edge(multihost_events):
    builder = AttackGraphBuilder()
    graph = builder.build_graph(multihost_events)
    
    assert graph.number_of_nodes() >= 15
    assert graph.number_of_edges() >= 15

    # Find the cross-host LATERAL_MOVEMENT edge
    lateral_edges = [
        (u, v, d) for u, v, d in graph.edges(data=True)
        if d.get("relation") == "LATERAL_MOVEMENT"
    ]
    assert len(lateral_edges) == 1
    u, v, data = lateral_edges[0]
    
    assert data["protocol"] == "SMB"
    assert data["port"] == 445
    assert data["source_host"] == "CORP-WKS-042"
    assert data["target_host"] == "CORP-DC-001"
    assert "net:10.0.0.50:445" in u
    assert "CORP-DC-001" in v


def test_cross_host_causal_provenance_walk(multihost_events):
    builder = AttackGraphBuilder()
    builder.build_graph(multihost_events)
    
    # Locate NTDS.dit file node on the domain controller
    ntds_nodes = [n for n in builder.graph.nodes if "ntds.dit" in n.lower()]
    assert len(ntds_nodes) == 1
    ntds_node = ntds_nodes[0]
    
    # Backward provenance traversal from Domain Controller must trace back to Workstation initial access!
    root_causes = builder.find_root_causes(ntds_node)
    assert len(root_causes) >= 1
    
    # At least one root cause must be on CORP-WKS-042 (explorer.exe or WINWORD.EXE)
    wks_roots = [r for r in root_causes if "CORP-WKS-042" in r]
    assert len(wks_roots) >= 1
    assert any("explorer.exe" in r or "WINWORD.EXE" in r for r in wks_roots)


def test_multihost_reasoning_and_actions(multihost_events):
    builder = AttackGraphBuilder()
    builder.build_graph(multihost_events)
    mapper = MitreMapper()
    agent = AIRAReasoningAgent(builder, mapper)
    
    inv = agent.investigate(multihost_events)
    
    # 1. Hypotheses
    hypotheses = inv["hypotheses"]
    assert len(hypotheses) == 1
    hyp = hypotheses[0]
    assert "Enterprise Multi-Host Intrusion" in hyp.title
    assert "CORP-WKS-042" in hyp.title
    assert "CORP-DC-001" in hyp.title
    assert hyp.confidence >= 0.95
    assert hyp.verdict == "MALICIOUS"

    # 2. MITRE Techniques
    tech_ids = {t.id for t in hyp.mitre_techniques}
    assert "T1021.002" in tech_ids  # SMB Lateral Movement
    assert "T1003.001" in tech_ids  # LSASS Memory Dump
    assert "T1003.003" in tech_ids  # NTDS Credential Dump
    assert "T1047" in tech_ids      # WMI Execution
    assert "T1543.003" in tech_ids  # Windows Service Persistence

    # 3. Actions
    actions = inv["recommended_actions"]
    act_types = {a.action_type for a in actions}
    
    # Both hosts must be isolated
    isolate_targets = {a.target for a in actions if a.action_type == "ISOLATE_HOST"}
    assert "CORP-WKS-042" in isolate_targets
    assert "CORP-DC-001" in isolate_targets
    
    # AD KRBTGT key reset must be recommended
    assert "RESET_KRBTGT_KEY" in act_types
    
    # Process kills on both hosts
    kill_targets = [a.target for a in actions if a.action_type == "KILL_PROCESS"]
    assert any("5104" in k for k in kill_targets)  # PowerShell on Workstation
    assert any("3920" in k for k in kill_targets)  # PowerShell on DC

    # Action deduplication check: no duplicate (action_type, target)
    seen = set()
    for a in actions:
        key = (a.action_type, a.target)
        assert key not in seen, f"Duplicate action found: {key}"
        seen.add(key)


def test_multihost_ui_and_vis_endpoints():
    client = TestClient(app)
    try:
        # 1. Load multi-host preset
        load_res = client.post("/api/load-trace?preset=multihost")
        assert load_res.status_code == 200
        data = load_res.json()
        assert data["status"] == "SUCCESS"
        assert data["incident_id"] == "INC-MULTIHOST-DC-01"
        
        # 2. Check incident endpoint
        inc_res = client.get("/api/incident")
        assert inc_res.status_code == 200
        inc_data = inc_res.json()
        assert set(inc_data["affected_hosts"]) == {"CORP-WKS-042", "CORP-DC-001"}
        
        # 3. Vis graph endpoint
        vis_res = client.get("/api/graph/vis")
        assert vis_res.status_code == 200
        vis_data = vis_res.json()
        
        nodes = vis_data["nodes"]
        edges = vis_data["edges"]
        assert len(nodes) >= 15
        assert len(edges) >= 15
        
        # Check that process nodes have host tags
        proc_nodes = [n for n in nodes if n["group"] == "process"]
        assert any("[CORP-WKS-042]" in n["label"] for n in proc_nodes)
        assert any("[CORP-DC-001]" in n["label"] for n in proc_nodes)
        
        # Check lateral movement edge styling
        lat_edges = [e for e in edges if "LATERAL PIVOT" in e["label"]]
        assert len(lat_edges) == 1
        lat_e = lat_edges[0]
        assert lat_e["color"]["color"] == "#f59e0b"
        assert lat_e["width"] == 3
        assert lat_e["dashes"] == [8, 4]
    finally:
        client.post("/api/reset-sample")


def test_copilot_lateral_movement_query(multihost_events):
    builder = AttackGraphBuilder()
    builder.build_graph(multihost_events)
    mapper = MitreMapper()
    agent = AIRAReasoningAgent(builder, mapper)
    inv = agent.investigate(multihost_events)
    
    dossier_dict = {
        "incident_id": "INC-MULTIHOST-DC-01",
        "affected_hosts": ["CORP-WKS-042", "CORP-DC-001"],
        "affected_users": ["CORP\\JohnDoe"],
        "severity": "CRITICAL",
        "hypotheses": [h.model_dump() for h in inv["hypotheses"]],
        "timeline": [t.model_dump() for t in inv["timeline"]],
        "recommended_actions": [a.model_dump() for a in inv["recommended_actions"]],
    }
    
    copilot = AIRACoPilot(dossier_dict, builder)
    resp = copilot.ask("Did the attacker move laterally to the domain controller?")
    
    assert "answer" in resp
    answer = resp["answer"]
    assert "CORP-WKS-042" in answer
    assert "CORP-DC-001" in answer
    assert "SMB" in answer
    assert "ntds" in answer.lower()
    assert "krbtgt" in answer.lower()
