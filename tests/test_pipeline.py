"""
AIRA Core Pipeline Unit & Integration Tests
Validates Event Normalization, Graph Causality, MITRE ATT&CK Mapping, and Reasoning Engine.
"""

import json
from pathlib import Path
import pytest
from aira.core.normalizer import EventNormalizer
from aira.core.graph_builder import AttackGraphBuilder
from aira.core.mitre_mapper import MitreMapper
from aira.core.reasoning_agent import AIRAReasoningAgent
from aira.core.report_generator import IncidentReportGenerator
from aira.core.models import EventType


@pytest.fixture
def sample_raw_events():
    sample_file = Path(__file__).resolve().parent.parent / "aira" / "data" / "samples" / "sample_attack_chain.json"
    with open(sample_file, "r") as f:
        return json.load(f)


def test_normalization(sample_raw_events):
    normalizer = EventNormalizer()
    events = normalizer.normalize_batch(sample_raw_events)

    assert len(events) == len(sample_raw_events)
    assert events[0].event_type == EventType.PROCESS_CREATE
    assert events[0].process.image.endswith("WINWORD.EXE")
    assert any(e.event_type == EventType.NETWORK_CONNECT for e in events)
    assert any(e.event_type == EventType.FILE_CREATE for e in events)
    assert any(e.event_type == EventType.REGISTRY_SET for e in events)


def test_graph_builder(sample_raw_events):
    normalizer = EventNormalizer()
    events = normalizer.normalize_batch(sample_raw_events)

    builder = AttackGraphBuilder()
    builder.build_graph(events)
    summary = builder.get_summary()

    assert summary["total_nodes"] > 5
    assert summary["total_edges"] > 4
    assert "process" in summary["node_distribution"]
    assert "network" in summary["node_distribution"]
    assert "file" in summary["node_distribution"]
    assert "registry" in summary["node_distribution"]

    # Verify root cause of powershell PID 5104
    ps_node = builder.process_lookup.get(("CORP-WKS-042", 5104))
    assert ps_node is not None
    roots = builder.find_root_causes(ps_node)
    assert any("explorer.exe" in r or "WINWORD.EXE" in r for r in roots)


def test_mitre_mapper(sample_raw_events):
    normalizer = EventNormalizer()
    events = normalizer.normalize_batch(sample_raw_events)

    mapper = MitreMapper()
    flagged = []
    for ev in events:
        techs = mapper.map_event(ev)
        if techs:
            flagged.append((ev, techs))

    assert len(flagged) >= 4
    technique_ids = {t.id for _, techs in flagged for t in techs}
    assert "T1059.001" in technique_ids  # PowerShell
    assert "T1071.001" in technique_ids  # C2 Web
    assert "T1547.001" in technique_ids  # Registry Run Key
    assert "T1003.001" in technique_ids  # LSASS Memory Credential Access


def test_end_to_end_investigation(sample_raw_events):
    normalizer = EventNormalizer()
    events = normalizer.normalize_batch(sample_raw_events)

    builder = AttackGraphBuilder()
    builder.build_graph(events)

    mapper = MitreMapper()
    agent = AIRAReasoningAgent(builder, mapper)
    res = agent.investigate(events)

    assert len(res["hypotheses"]) > 0
    top_hyp = res["hypotheses"][0]
    assert top_hyp.verdict in ["MALICIOUS", "SUSPICIOUS"]
    assert top_hyp.confidence > 0.8
    assert len(res["timeline"]) == len(events)
    assert len(res["recommended_actions"]) > 0

    generator = IncidentReportGenerator(builder)
    dossier = generator.generate_dossier("INC-TEST-001", events, res)
    assert dossier.severity in ["HIGH", "CRITICAL"]

    md_report = generator.export_markdown(dossier)
    assert "# AIRA Incident Investigation Dossier" in md_report
    assert "Prescribed Remediation & Response Actions" in md_report
