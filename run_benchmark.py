"""
AIRA Academic Evaluation & Benchmark Runner
Executes comprehensive DFIR benchmarks across synthetic and binary EVTX traces.
Outputs formal LaTeX tables, Markdown summary reports, and JSON datasets.

Usage:
    python run_benchmark.py
"""

import sys
import io
from pathlib import Path

# Ensure UTF-8 output on Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from aira.evaluation.benchmark import AIRABenchmarkRunner


def main():
    print("=" * 80)
    print("[*] AIRA CAPSTONE-I EMPIRICAL EVALUATION & BENCHMARK SUITE")
    print("=" * 80)
    print("Evaluating causal provenance graphs, noise pruning rates, MITRE accuracy,")
    print("and computational latency across test datasets...\n")

    runner = AIRABenchmarkRunner()
    results = runner.run_all()

    # Terminal ASCII Summary Table
    print("\n" + "=" * 80)
    print("[+] EMPIRICAL BENCHMARK SUMMARY TABLE")
    print("=" * 80)
    header = f"{'Dataset':<32} {'Format':<6} {'Events':<7} {'Total(ms)':<10} {'Pruning%':<10} {'F1-Score':<10} {'Speedup':<12}"
    print(header)
    print("-" * 87)

    for r in results:
        short_name = r.dataset_name[:30]
        speedup_str = f"{r.speedup_factor:,.0f}x"
        line = f"{short_name:<32} {r.file_type:<6} {r.event_count:<7} {r.t_total_ms:<10.2f} {r.noise_reduction_pct:<10.1f} {r.f1_score:<10.3f} {speedup_str:<12}"
        print(line)

    print("-" * 87)
    
    # Export artifacts
    out_dir = Path(__file__).resolve().parent / "benchmarks"
    exported = runner.export_all(out_dir)

    print(f"\n[+] All Benchmark Artifacts Exported Successfully:")
    print(f"   [LaTeX Tables]       : {exported['latex']}")
    print(f"   [Markdown Summary]   : {exported['markdown']}")
    print(f"   [JSON Raw Data]      : {exported['json']}\n")
    print("=" * 80)
    print("[*] Evaluation Complete! You can now include these tables in your project report.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
