"""
Tests for AIRA Academic Evaluation & Benchmarking Suite
"""

import pytest
from aira.evaluation.benchmark import AIRABenchmarkRunner, BENCHMARK_DATASETS

def test_benchmark_runner_all_datasets():
    runner = AIRABenchmarkRunner()
    results = runner.run_all()
    
    assert len(results) == len(BENCHMARK_DATASETS)
    
    for r in results:
        assert r.t_total_ms > 0
        assert r.speedup_factor > 1000  # Sub-second vs 15-minute triage
        assert r.attack_path_recall == 100.0  # Zero dropped attack IOCs
        assert r.root_cause_correct is True  # Identified correct root cause

def test_benchmark_noise_reduction_apt29():
    runner = AIRABenchmarkRunner()
    results = runner.run_all()
    
    apt29_res = next(r for r in results if r.dataset_key == "apt29_mordor_noisy")
    assert apt29_res.noise_reduction_pct >= 70.0
    assert apt29_res.f1_score >= 0.90

def test_benchmark_export_artifacts(tmp_path):
    runner = AIRABenchmarkRunner()
    exported = runner.export_all(output_dir=tmp_path)
    
    assert exported["json"].exists()
    assert exported["markdown"].exists()
    assert exported["latex"].exists()
    
    latex_content = exported["latex"].read_text(encoding="utf-8")
    assert "\\begin{table}" in latex_content
    assert "Speedup vs SOC" in latex_content
