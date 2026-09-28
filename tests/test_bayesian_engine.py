"""
Tests for AIRA Probabilistic Bayesian Reasoning & Belief Updating Engine
Validates odds-form Bayesian updates, likelihood ratios (Bayes factors),
noise dampening, posterior probability bounds, and hybrid heuristic integration.
"""

import json
from pathlib import Path
import pytest

from aira.core.normalizer import EventNormalizer
from aira.core.graph_builder import AttackGraphBuilder
from aira.core.mitre_mapper import MitreMapper
from aira.core.reasoning_agent import AIRAReasoningAgent
from aira.core.bayesian_engine import BayesianInferenceEngine

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "aira" / "data" / "samples"


@pytest.fixture
def clean_attack_events():
    path = SAMPLE_DIR / "sample_attack_chain.json"
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return EventNormalizer().normalize_batch(raw)


@pytest.fixture
def multihost_events():
    path = SAMPLE_DIR / "enterprise_multihost_attack.json"
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return EventNormalizer().normalize_batch(raw)


def test_bayesian_engine_initialization():
    engine = BayesianInferenceEngine(prior=0.001)
    assert engine.prior == 0.001
    assert 0.00100 < engine.prior_odds < 0.00101


def test_bayesian_clean_attack_progression(clean_attack_events):
    builder = AttackGraphBuilder()
    builder.build_graph(clean_attack_events)
    mapper = MitreMapper()
    flagged = [(e, mapper.map_event(e)) for e in clean_attack_events if mapper.map_event(e)]
    
    engine = BayesianInferenceEngine()
    assessment = engine.evaluate_incident(clean_attack_events, flagged)
    
    assert assessment.prior_probability == 0.001
    assert assessment.final_posterior >= 0.95
    assert assessment.total_bayes_factor > 100.0
    assert assessment.bayesian_verdict == "CONFIRMED_MALICIOUS"
    
    # Verify trajectory exists and probability monotonically increases on attack steps
    assert len(assessment.trajectory) >= 4
    first_step = assessment.trajectory[0]
    last_step = assessment.trajectory[-1]
    assert first_step.posterior_probability < last_step.posterior_probability
    assert last_step.posterior_probability >= 0.95


def test_bayesian_multihost_lateral_progression(multihost_events):
    builder = AttackGraphBuilder()
    builder.build_graph(multihost_events)
    mapper = MitreMapper()
    flagged = [(e, mapper.map_event(e)) for e in multihost_events if mapper.map_event(e)]
    
    engine = BayesianInferenceEngine()
    assessment = engine.evaluate_incident(multihost_events, flagged)
    
    # Active Directory NTDS extraction + LSASS dumping produces near 100% certainty
    assert assessment.final_posterior >= 0.98
    assert assessment.total_bayes_factor > 1000.0
    assert assessment.bayesian_verdict == "CONFIRMED_MALICIOUS"
    
    # Check that NTDS and LSASS appear in top contributing evidence
    top_features = [e["feature"] for e in assessment.top_contributing_evidence]
    assert any("T1003" in f for f in top_features)


def test_bayesian_noise_dampening():
    # Test that benign applications (Chrome, Spotify) produce Bayes factor < 1.0
    path = SAMPLE_DIR / "mordor_apt29_noisy.json"
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    noisy_events = EventNormalizer().normalize_batch(raw)
    
    mapper = MitreMapper()
    flagged = [(e, mapper.map_event(e)) for e in noisy_events if mapper.map_event(e)]
    
    engine = BayesianInferenceEngine()
    assessment = engine.evaluate_incident(noisy_events, flagged)
    
    # Despite 48 benign noise events, attack evidence successfully pushes final posterior up
    assert assessment.final_posterior >= 0.90
    assert assessment.bayesian_verdict in ["CONFIRMED_MALICIOUS", "PROBABLE_INTRUSION"]
    
    # Verify that benign noise was recognized in trajectory steps
    noise_steps = [s for s in assessment.trajectory if "Benign" in s.feature_name]
    assert len(noise_steps) >= 1
    assert noise_steps[0].likelihood_ratio < 1.0


def test_hybrid_reasoning_agent_integration(multihost_events):
    builder = AttackGraphBuilder()
    builder.build_graph(multihost_events)
    mapper = MitreMapper()
    agent = AIRAReasoningAgent(builder, mapper)
    
    inv = agent.investigate(multihost_events)
    hypotheses = inv["hypotheses"]
    assert len(hypotheses) == 1
    hyp = hypotheses[0]
    
    # Verify both heuristic qualitative outputs and Bayesian quantitative proofs are present
    assert "Enterprise Multi-Host Intrusion" in hyp.title
    assert hyp.confidence >= 0.95
    assert hyp.bayesian_posterior is not None
    assert hyp.bayesian_posterior >= 0.98
    assert hyp.bayesian_likelihood_ratio > 1000.0
    assert hyp.bayesian_verdict == "CONFIRMED_MALICIOUS"
    assert len(hyp.bayesian_trajectory) >= 4
