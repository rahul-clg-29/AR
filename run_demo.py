"""
AIRA End-to-End Autonomous Investigation Demo
Executes ingestion, graph causality reconstruction, agentic reasoning,
and incident dossier generation on simulated attack telemetry.
"""

import json
import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from aira.core.normalizer import EventNormalizer
from aira.core.graph_builder import AttackGraphBuilder
from aira.core.mitre_mapper import MitreMapper
from aira.core.reasoning_agent import AIRAReasoningAgent
from aira.core.report_generator import IncidentReportGenerator

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False


def run_pipeline():
    print("=" * 70)
    print("  AIRA: Autonomous Incident Reasoning Agent - End-to-End Pipeline  ")
    print("=" * 70)

    # 1. Load Sample Telemetry
    sample_file = root_dir / "aira" / "data" / "samples" / "sample_attack_chain.json"
    with open(sample_file, "r") as f:
        raw_events = json.load(f)
    print(f"\n[+] Loaded {len(raw_events)} raw telemetry events from {sample_file.name}")

    # 2. Ingest and Normalize
    normalizer = EventNormalizer()
    canonical_events = normalizer.normalize_batch(raw_events)
    print(f"[+] Successfully normalized {len(canonical_events)} events into Canonical Event Schema.")

    # 3. Construct Causal Attack Graph
    builder = AttackGraphBuilder()
    graph = builder.build_graph(canonical_events)
    summary = builder.get_summary()
    print(f"[+] Attack Graph constructed:")
    print(f"    - Nodes: {summary['total_nodes']} ({summary['node_distribution']})")
    print(f"    - Causal Edges: {summary['total_edges']} ({summary['relation_distribution']})")

    # 4. Agentic Reasoning & Investigation
    mapper = MitreMapper()
    agent = AIRAReasoningAgent(builder, mapper)
    investigation = agent.investigate(canonical_events)

    print("\n[+] Autonomous Investigation Completed:")
    print(f"    - Root Causes Identified: {investigation['root_causes']}")
    print(f"    - Suspicious Nodes: {investigation['suspicious_nodes']}")
    print(f"    - Blast Radius Count: {len(investigation['blast_radius'])} entities")

    # 5. Incident Dossier & Markdown Report
    generator = IncidentReportGenerator(builder)
    dossier = generator.generate_dossier("INC-2026-0926-01", canonical_events, investigation)
    report_md = generator.export_markdown(dossier)

    report_path = root_dir / "incident_report_INC-001.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_md)
    print(f"[+] Incident Dossier exported to: {report_path.name}")

    # 6. Pretty Print Dashboard
    if RICH_AVAILABLE:
        # MITRE & Hypotheses Panel
        hyp = dossier.hypotheses[0] if dossier.hypotheses else None
        if hyp:
            console.print(Panel(
                f"[bold red]VERDICT: {hyp.verdict}[/bold red] (Confidence: [bold green]{int(hyp.confidence*100)}%[/bold green])\n"
                f"[bold]Hypothesis:[/bold] {hyp.title}\n"
                f"{hyp.description}",
                title=f"[bold cyan]AIRA Hypothesis Assessment - {hyp.hypothesis_id}[/bold cyan]"
            ))

        # Timeline Table
        table = Table(title="[bold yellow]Reconstructed Chronological Attack Timeline[/bold yellow]")
        table.add_column("Time", style="cyan", no_wrap=True)
        table.add_column("Tactic", style="magenta")
        table.add_column("Actor", style="green")
        table.add_column("Action", style="white")
        table.add_column("Target / Command", style="yellow")
        table.add_column("MITRE ID", style="red")

        for entry in dossier.timeline:
            table.add_row(
                entry.timestamp.strftime("%H:%M:%S"),
                entry.stage,
                entry.actor,
                entry.action,
                (entry.target[:40] + "...") if len(entry.target) > 40 else entry.target,
                entry.mitre_id or "-"
            )
        console.print(table)

        # Actions Table
        action_table = Table(title="[bold red]Prescribed Remediation Actions (Human-in-the-Loop Gate)[/bold red]")
        action_table.add_column("Action Type", style="bold red")
        action_table.add_column("Priority", style="yellow")
        action_table.add_column("Target Entity", style="white")
        action_table.add_column("Rationale", style="italic")

        for act in dossier.recommended_actions:
            action_table.add_row(act.action_type, act.priority, act.target, act.rationale)
        console.print(action_table)
    else:
        print("\n=== INVESTIGATION SUMMARY ===")
        print(f"Incident: {dossier.title} ({dossier.severity})")
        print(f"Executive Summary: {dossier.executive_summary}")
        print("\nTimeline Entries:")
        for t in dossier.timeline:
            print(f"  [{t.timestamp.strftime('%H:%M:%S')}] {t.stage} | {t.actor} -> {t.action} ({t.target}) [MITRE: {t.mitre_id}]")
        print("\nPrescribed Actions:")
        for a in dossier.recommended_actions:
            print(f"  [{a.priority}] {a.action_type}: {a.target} - {a.rationale}")

    print("\n" + "=" * 70)
    print("  [SUCCESS] Demo completed successfully!  ")
    print("=" * 70)


if __name__ == "__main__":
    run_pipeline()
