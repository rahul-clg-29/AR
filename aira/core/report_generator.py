"""
AIRA Incident Report Generator
Compiles graph analytics, reasoning hypotheses, chronological attack timeline,
and recommended remediation into an executive and technical Incident Dossier.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List
from aira.core.models import (
    IncidentDossier,
    CanonicalEvent,
)
from aira.core.graph_builder import AttackGraphBuilder


class IncidentReportGenerator:
    """
    Builds the formal Incident Dossier and exports analyst-grade Markdown reports.
    """

    def __init__(self, graph_builder: AttackGraphBuilder):
        self.graph_builder = graph_builder

    def generate_dossier(
        self,
        incident_id: str,
        events: List[CanonicalEvent],
        investigation_result: Dict[str, Any]
    ) -> IncidentDossier:
        affected_hosts = list({e.host for e in events})
        affected_users = list({e.user for e in events if e.user})

        hypotheses = investigation_result.get("hypotheses", [])
        timeline = investigation_result.get("timeline", [])
        actions = investigation_result.get("recommended_actions", [])
        graph_summary = self.graph_builder.get_summary()

        # Compute severity
        max_conf = max([h.confidence for h in hypotheses], default=0.0)
        severity = "CRITICAL" if max_conf >= 0.90 else "HIGH" if max_conf >= 0.70 else "MEDIUM"

        summary = (
            f"AIRA Autonomous Incident Investigation flagged a confirmed {severity} security incident "
            f"across host(s): {', '.join(affected_hosts)}. The attack graph correlates {graph_summary.get('total_nodes', 0)} "
            f"entities across {graph_summary.get('total_edges', 0)} causal provenance links. "
            f"Adversary activity was reconstructed from Initial Access through Execution, C2 beaconing, and Persistence."
        )

        dossier = IncidentDossier(
            incident_id=incident_id,
            title="Adversary Attack Chain Execution & Persistence Detection",
            severity=severity,
            created_at=datetime.now(timezone.utc),
            affected_hosts=affected_hosts,
            affected_users=affected_users,
            executive_summary=summary,
            hypotheses=hypotheses,
            timeline=timeline,
            attack_graph_summary=graph_summary,
            recommended_actions=actions,
            analyst_decision="PENDING_HUMAN_APPROVAL"
        )
        return dossier

    def export_markdown(self, dossier: IncidentDossier) -> str:
        """
        Produce a clean, publication-ready Markdown report.
        """
        md = []
        md.append(f"# AIRA Incident Investigation Dossier: `{dossier.incident_id}`")
        md.append(f"**Date Generated:** {dossier.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        md.append(f"**Incident Severity:** `{dossier.severity}` | **Analyst Status:** `{dossier.analyst_decision}`\n")
        md.append("---")

        md.append("## 1. Executive Summary")
        md.append(f"{dossier.executive_summary}\n")
        md.append(f"- **Impacted Hosts:** {', '.join(dossier.affected_hosts)}")
        md.append(f"- **Impacted Accounts:** {', '.join(dossier.affected_users)}")
        md.append(f"- **Total Entities in Causal Graph:** {dossier.attack_graph_summary.get('total_nodes')}")
        md.append(f"- **Causal Provenance Edges:** {dossier.attack_graph_summary.get('total_edges')}\n")

        md.append("## 2. Evidence-Based Hypotheses & MITRE ATT&CK Mapping")
        for hyp in dossier.hypotheses:
            md.append(f"### Hypothesis: {hyp.title} (Confidence: {int(hyp.confidence * 100)}%)")
            md.append(f"{hyp.description}\n")
            md.append("**Associated MITRE ATT&CK Techniques:**")
            for t in hyp.mitre_techniques:
                md.append(f"- **`{t.id}` ({t.tactic}) - {t.name}**: {t.description}")
            md.append("")

            if hyp.missing_evidence:
                md.append("**Identified Missing Evidence / Telemetry Blind Spots:**")
                for me in hyp.missing_evidence:
                    md.append(f"- :warning: {me}")
                md.append("")

        md.append("## 3. Reconstructed Chronological Attack Timeline")
        md.append("| Timestamp (UTC) | Tactic / Stage | Actor / Parent | Action Observed | Target / Command | Record ID | Severity |")
        md.append("|---|---|---|---|---|---|---|")
        for t in dossier.timeline:
            ts_str = t.timestamp.strftime("%H:%M:%S")
            target_clean = (t.target[:45] + "...") if len(t.target) > 45 else t.target
            target_clean = target_clean.replace("|", "/")
            action_clean = t.action.replace("|", "/")
            md.append(f"| {ts_str} | `{t.stage}` | `{t.actor}` | {action_clean} | `{target_clean}` | `{t.evidence_record_id}` | `{t.severity}` |")
        md.append("")

        md.append("## 4. Prescribed Remediation & Response Actions")
        md.append("> **Note to SOC Analyst:** AIRA recommends the following immediate actions. Approval is required before orchestration.\n")
        for i, act in enumerate(dossier.recommended_actions, 1):
            md.append(f"#### {i}. `{act.action_type}` on `{act.target}` [Priority: {act.priority}]")
            md.append(f"- **Rationale:** {act.rationale}")
            md.append(f"- **Approval Required:** {'Yes (Human-in-the-Loop)' if act.requires_approval else 'Autonomous'}\n")

        return "\n".join(md)
