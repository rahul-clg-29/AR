"""
Unit tests for AIRA SOC Co-Pilot ("Ask AIRA") Graph-RAG Engine
"""

import pytest
from aira.core.copilot import AIRACoPilot
from aira.core.normalizer import EventNormalizer
from aira.core.graph_builder import AttackGraphBuilder
from aira.core.mitre_mapper import MitreMapper
from aira.core.reasoning_agent import AIRAReasoningAgent
from aira.core.report_generator import IncidentReportGenerator
import json
from pathlib import Path

@pytest.fixture
def copilot_fixture():
    sample_file = Path(__file__).resolve().parent.parent / "aira" / "data" / "samples" / "sample_attack_chain.json"
    with open(sample_file, "r", encoding="utf-8") as f:
        raw = json.load(f)
        
    events = EventNormalizer().normalize_batch(raw)
    builder = AttackGraphBuilder()
    builder.build_graph(events)
    agent = AIRAReasoningAgent(builder, MitreMapper())
    inv = agent.investigate(events)
    generator = IncidentReportGenerator(builder)
    dossier = generator.generate_dossier("INC-TEST-01", events, inv)
    
    return AIRACoPilot(dossier.model_dump(), builder)

def test_copilot_system_context(copilot_fixture):
    context = copilot_fixture.build_system_context()
    assert "INCIDENT CONTEXT:" in context
    assert "DETECTED MITRE ATT&CK TECHNIQUES:" in context
    assert "FORENSIC EVIDENCE TIMELINE:" in context

def test_copilot_root_cause_query(copilot_fixture):
    res = copilot_fixture.ask("What is the root cause and initial access?")
    assert res["status"] == "SUCCESS"
    assert "Root Cause" in res["answer"]
    assert "Patient-Zero" in res["answer"]
    assert res["engine"] == "aira-graph-rag-local"

def test_copilot_firewall_query(copilot_fixture):
    res = copilot_fixture.ask("Which IP addresses should I block on the firewall?")
    assert res["status"] == "SUCCESS"
    assert "Firewall" in res["answer"]
    assert "New-NetFirewallRule" in res["answer"]

def test_copilot_sigma_rule_generation(copilot_fixture):
    res = copilot_fixture.ask("Generate a Sigma detection rule for this attack")
    assert res["status"] == "SUCCESS"
    assert "title:" in res["answer"]
    assert "logsource:" in res["answer"]
    assert "detection:" in res["answer"]

def test_copilot_ciso_briefing(copilot_fixture):
    res = copilot_fixture.ask("Generate an Executive CISO Briefing")
    assert res["status"] == "SUCCESS"
    assert "Executive Incident Briefing" in res["answer"]
    assert "Business Impact" in res["answer"]

def test_copilot_compromised_assets(copilot_fixture):
    res = copilot_fixture.ask("what all things r compromised")
    assert res["status"] == "SUCCESS"
    assert "Compromised Asset Inventory" in res["answer"]
    assert "Blast Radius" in res["answer"]
    assert "Malicious Processes" in res["answer"]


def test_copilot_bayesian_query(copilot_fixture):
    # Test system context contains Bayesian section
    context = copilot_fixture.build_system_context()
    assert "BAYESIAN PROBABILISTIC ASSESSMENT:" in context

    # Test offline query for Bayesian mathematical proof
    res = copilot_fixture.ask("Explain the Bayesian probability and mathematical proof for this attack.")
    assert res["status"] == "SUCCESS"
    assert "Bayesian Mathematical Proof" in res["answer"]
    assert "Bayes' Theorem" in res["answer"]
    assert "Bayes Factor" in res["answer"]
    assert "Belief Update Trajectory" in res["answer"]

