"""
AIRA Agentic Reasoning Engine
Implements the autonomous cognitive loop: anomaly detection, backward provenance tracing,
forward blast-radius analysis, hypothesis generation, missing evidence detection, and action synthesis.
"""

from typing import List, Dict, Any, Set, Tuple, Optional
from aira.core.models import (
    CanonicalEvent,
    EventType,
    Hypothesis,
    MitreTechnique,
    RecommendedAction,
    TimelineEntry,
)
from aira.core.graph_builder import AttackGraphBuilder
from aira.core.mitre_mapper import MitreMapper
from aira.core.bayesian_engine import BayesianInferenceEngine


class AIRAReasoningAgent:
    """
    Autonomous cybersecurity reasoning agent. Correlates graph provenance,
    maps behaviors to MITRE ATT&CK, evaluates evidence hypotheses, and formulates response plans.
    """

    def __init__(self, graph_builder: AttackGraphBuilder, mitre_mapper: MitreMapper, bayesian_engine: Optional[BayesianInferenceEngine] = None):
        self.graph_builder = graph_builder
        self.mitre_mapper = mitre_mapper
        self.bayesian_engine = bayesian_engine or BayesianInferenceEngine()

    def investigate(self, events: List[CanonicalEvent]) -> Dict[str, Any]:
        """
        Main investigation entry point:
        1. Scan events for anomalies / MITRE techniques.
        2. Trace causal graph backwards for root cause and forward for impact.
        3. Formulate hypotheses and identify missing evidence.
        4. Synthesize chronological timeline and response actions.
        """
        event_map = {e.record_id: e for e in events}
        flagged_events: List[Tuple[CanonicalEvent, List[MitreTechnique]]] = []

        # Step 1: Scan events with MITRE engine
        for ev in events:
            techs = self.mitre_mapper.map_event(ev)
            if techs:
                flagged_events.append((ev, techs))

        # Step 2: Identify suspicious graph nodes
        suspicious_node_ids: Set[str] = set()
        for ev, techs in flagged_events:
            if ev.process:
                node_id = self.graph_builder.process_lookup.get((ev.host, ev.process.pid))
                if node_id:
                    suspicious_node_ids.add(node_id)

        # Step 3: Backward & Forward Graph Analysis
        root_causes: Set[str] = set()
        blast_radius: Set[str] = set()

        for node in suspicious_node_ids:
            roots = self.graph_builder.find_root_causes(node)
            root_causes.update(roots)
            descendants = self.graph_builder.find_blast_radius(node)
            blast_radius.update(descendants)

        # Step 4: Hypothesis Formulation
        hypotheses = self._formulate_hypotheses(flagged_events, events)

        # Step 5: Timeline Reconstruction
        timeline = self._reconstruct_timeline(events, flagged_events)

        # Step 6: Response Recommendations
        recommendations = self._synthesize_actions(events, flagged_events)

        return {
            "flagged_events_count": len(flagged_events),
            "suspicious_nodes": list(suspicious_node_ids),
            "root_causes": list(root_causes),
            "blast_radius": list(blast_radius),
            "hypotheses": hypotheses,
            "timeline": timeline,
            "recommended_actions": recommendations,
        }

    def _formulate_hypotheses(
        self,
        flagged_events: List[Tuple[CanonicalEvent, List[MitreTechnique]]],
        all_events: List[CanonicalEvent]
    ) -> List[Hypothesis]:
        hypotheses: List[Hypothesis] = []
        if not flagged_events:
            return hypotheses

        # Extract all techniques
        all_techs: List[MitreTechnique] = []
        supporting_records: List[str] = []
        for ev, techs in flagged_events:
            all_techs.extend(techs)
            supporting_records.append(ev.record_id)

        tactics_present = {t.tactic for t in all_techs}

        # Check for cross-host lateral movement
        lateral_edges = [
            (u, v, data) for u, v, data in self.graph_builder.graph.edges(data=True)
            if data.get("relation") == "LATERAL_MOVEMENT"
        ]
        has_lateral = len(lateral_edges) > 0

        # Check for multi-stage attack pattern
        is_multi_stage = len(tactics_present) >= 2

        # Missing evidence detection logic
        missing_evidence: List[str] = []
        has_network = any(e.event_type == EventType.NETWORK_CONNECT for e in all_events)
        has_file_drop = any(e.event_type == EventType.FILE_CREATE for e in all_events)
        has_dns = any(e.network and e.network.dns_query for e in all_events)

        if has_network and not has_dns:
            missing_evidence.append("Outbound network activity observed without corresponding DNS resolution event (possible DNS log bypass or direct IP connection).")

        if has_file_drop:
            # Check if file execution was logged
            dropped_paths = [e.file.path.lower() for e in all_events if e.file]
            executed_images = [e.process.image.lower() for e in all_events if e.process]
            for dp in dropped_paths:
                if not any(dp.endswith(img.split("\\")[-1]) for img in executed_images):
                    missing_evidence.append(f"Dropped executable '{dp}' has no recorded execution log in current telemetry window.")

        if has_lateral:
            lat_data = lateral_edges[0][2]
            src_h = lat_data.get("source_host", "Workstation")
            tgt_h = lat_data.get("target_host", "Internal Host")
            proto = lat_data.get("protocol", "SMB")
            port = lat_data.get("port", 445)
            tactics_present.add("Lateral Movement")

            title = f"Enterprise Multi-Host Intrusion: Lateral Movement from {src_h} to {tgt_h} via {proto}"
            desc = (
                f"AIRA identified an enterprise-scale multi-host intrusion pivoting from {src_h} to {tgt_h}. "
                f"Initial access occurred on {src_h}, followed by credential access and lateral pivot via {proto} (port {port}) "
                f"to compromise {tgt_h}, spanning {len(tactics_present)} MITRE ATT&CK tactics ({', '.join(sorted(tactics_present))})."
            )
            confidence = 0.96

            # Ensure Lateral Movement technique is recorded
            lat_tech_id = "T1021.002" if proto == "SMB" else "T1047"
            if not any(t.id == lat_tech_id for t in all_techs):
                all_techs.append(
                    MitreTechnique(
                        id=lat_tech_id,
                        name="SMB/Windows Admin Shares" if lat_tech_id == "T1021.002" else "Windows Management Instrumentation",
                        tactic="Lateral Movement",
                        description=f"Adversary used administrative {proto} connection to pivot across enterprise hosts.",
                        confidence=0.95
                    )
                )
        elif is_multi_stage:
            title = "Multi-Stage Attack Chain: Phishing to Execution and Persistence"
            desc = (
                f"AIRA identified a coherent attack sequence spanning {len(tactics_present)} MITRE ATT&CK tactics "
                f"({', '.join(sorted(tactics_present))}). The attack initiates from an anomalous parent process, "
                f"executes scripted download cradles, establishes external C2 communications, and attempts system persistence."
            )
            confidence = 0.92
        else:
            title = "Suspicious Script Execution Detected"
            desc = (
                f"AIRA identified suspicious execution activity spanning {len(tactics_present)} MITRE ATT&CK tactics "
                f"({', '.join(sorted(tactics_present))}). Immediate triage recommended."
            )
            confidence = 0.70

        # Mathematical Bayesian Inference calibration
        bayesian_assessment = self.bayesian_engine.evaluate_incident(all_events, flagged_events)
        
        # Combined confidence: max between heuristic baseline and Bayesian posterior
        calibrated_confidence = max(confidence, bayesian_assessment.final_posterior)

        hypotheses.append(
            Hypothesis(
                hypothesis_id="HYP-001",
                title=title,
                description=desc,
                mitre_techniques=all_techs,
                confidence=round(calibrated_confidence, 2),
                supporting_events=supporting_records,
                contradicting_events=[],
                missing_evidence=missing_evidence,
                verdict="MALICIOUS" if calibrated_confidence >= 0.85 else "SUSPICIOUS",
                bayesian_posterior=bayesian_assessment.final_posterior,
                bayesian_likelihood_ratio=bayesian_assessment.total_bayes_factor,
                bayesian_trajectory=[t.model_dump() for t in bayesian_assessment.trajectory],
                bayesian_verdict=bayesian_assessment.bayesian_verdict
            )
        )

        return hypotheses

    def _reconstruct_timeline(
        self,
        all_events: List[CanonicalEvent],
        flagged_events: List[Tuple[CanonicalEvent, List[MitreTechnique]]]
    ) -> List[TimelineEntry]:
        flagged_dict = {ev.record_id: techs for ev, techs in flagged_events}
        timeline: List[TimelineEntry] = []

        for ev in all_events:
            techs = flagged_dict.get(ev.record_id, [])
            mitre_id = techs[0].id if techs else None
            severity = "HIGH" if techs else "INFO"

            actor = "SYSTEM"
            action = "Activity"
            target = "Target"

            if ev.event_type == EventType.PROCESS_CREATE and ev.process:
                actor = ev.process.parent_image.split("\\")[-1] if ev.process.parent_image else "Unknown"
                action = f"Executed {ev.process.image.split('\\')[-1]}"
                target = ev.process.command_line or ev.process.image
            elif ev.event_type == EventType.NETWORK_CONNECT and ev.network:
                actor = ev.process.image.split("\\")[-1] if ev.process else "Process"
                action = f"Outbound Connection ({ev.network.protocol.upper()})"
                target = f"{ev.network.dst_ip}:{ev.network.dst_port}"
            elif ev.event_type == EventType.FILE_CREATE and ev.file:
                actor = ev.process.image.split("\\")[-1] if ev.process else "Process"
                action = "Created File"
                target = ev.file.path
            elif ev.event_type == EventType.REGISTRY_SET and ev.registry:
                actor = ev.process.image.split("\\")[-1] if ev.process else "Process"
                action = "Modified Registry Run Key"
                target = ev.registry.key_path
            elif ev.event_type == EventType.PROCESS_ACCESS and ev.process:
                actor = ev.process.image.split("\\")[-1] if ev.process else "Process"
                action = "Accessed Process Memory"
                target = ev.process.command_line or "target process"

            timeline.append(
                TimelineEntry(
                    timestamp=ev.timestamp,
                    stage=techs[0].tactic if techs else "Execution Baseline",
                    actor=actor,
                    action=action,
                    target=target,
                    evidence_record_id=ev.record_id,
                    mitre_id=mitre_id,
                    severity=severity
                )
            )

        return timeline

    def _synthesize_actions(
        self,
        all_events: List[CanonicalEvent],
        flagged_events: List[Tuple[CanonicalEvent, List[MitreTechnique]]]
    ) -> List[RecommendedAction]:
        actions: List[RecommendedAction] = []
        hosts = {e.host for e in all_events}

        for h in hosts:
            actions.append(
                RecommendedAction(
                    action_type="ISOLATE_HOST",
                    priority="IMMEDIATE",
                    target=h,
                    rationale=f"Prevent lateral movement and further C2 exfiltration from affected endpoint {h}.",
                    requires_approval=True
                )
            )

        # Kill suspicious processes
        for ev, techs in flagged_events:
            if ev.process and ev.event_type == EventType.PROCESS_CREATE:
                if any(t.id in ["T1059.001", "T1003.001"] for t in techs):
                    actions.append(
                        RecommendedAction(
                            action_type="KILL_PROCESS",
                            priority="IMMEDIATE",
                            target=f"PID {ev.process.pid} ({ev.process.image})",
                            rationale=f"Terminate malicious active process mapped to {techs[0].name}.",
                            requires_approval=True
                        )
                    )

        # Block external C2 IPs
        for ev in all_events:
            if ev.event_type == EventType.NETWORK_CONNECT and ev.network:
                dst = ev.network.dst_ip
                if not (dst.startswith("10.") or dst.startswith("192.168.") or dst.startswith("127.")):
                    actions.append(
                        RecommendedAction(
                            action_type="BLOCK_IP",
                            priority="HIGH",
                            target=f"{dst}:{ev.network.dst_port}",
                            rationale=f"Sever adversary command and control channel to external IP {dst}.",
                            requires_approval=True
                        )
                    )

        # Remove persistence keys
        for ev in all_events:
            if ev.event_type == EventType.REGISTRY_SET and ev.registry:
                actions.append(
                    RecommendedAction(
                        action_type="DELETE_REGISTRY_KEY",
                        priority="HIGH",
                        target=ev.registry.key_path,
                        rationale="Eradicate persistence mechanism added to startup registry.",
                        requires_approval=True
                    )
                )

        # Revoke credentials if credential dumping (e.g., T1003.001 LSASS dump or T1003.003 NTDS dump) detected
        has_cred_dump = any(
            any(t.id in ["T1003.001", "T1003.003"] for t in techs)
            for _, techs in flagged_events
        )
        if has_cred_dump:
            users = {e.user for e in all_events if e.user and not e.user.upper().endswith("$")}
            target_user = ", ".join(sorted(users)) if users else "Compromised User Accounts"
            actions.append(
                RecommendedAction(
                    action_type="RESET_CREDENTIALS",
                    priority="HIGH",
                    target=f"{target_user} (Kerberos TGT & Password)",
                    rationale=f"Force immediate password reset and invalidate active Kerberos TGT tickets for {target_user} due to observed credential dumping.",
                    requires_approval=True
                )
            )

        # Active Directory domain credential dumping (NTDS)
        has_ntds = any(
            any(t.id == "T1003.003" for t in techs)
            for _, techs in flagged_events
        )
        if has_ntds:
            actions.append(
                RecommendedAction(
                    action_type="RESET_KRBTGT_KEY",
                    priority="IMMEDIATE",
                    target="Active Directory Domain KRBTGT Account",
                    rationale="Execute double reset of Active Directory KRBTGT domain account key to invalidate forged Kerberos Golden/Silver tickets after NTDS database extraction.",
                    requires_approval=True
                )
            )

        # Deduplicate actions by action_type and target
        unique_actions: List[RecommendedAction] = []
        seen = set()
        for a in actions:
            key = (a.action_type, a.target)
            if key not in seen:
                seen.add(key)
                unique_actions.append(a)

        return unique_actions
