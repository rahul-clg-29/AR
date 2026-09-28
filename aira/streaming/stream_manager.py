"""
AIRA Real-Time Telemetry Streaming & Event Manager
Provides live streaming ingestion, incremental graph growth, dynamic Bayesian belief updates,
and Server-Sent Events (SSE) broadcasting to the SOC Workbench.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

from aira.core.models import CanonicalEvent, IncidentDossier
from aira.core.normalizer import EventNormalizer
from aira.core.graph_builder import AttackGraphBuilder
from aira.core.mitre_mapper import MitreMapper
from aira.core.reasoning_agent import AIRAReasoningAgent
from aira.core.report_generator import IncidentReportGenerator
from aira.core.bayesian_engine import BayesianInferenceEngine

logger = logging.getLogger("aira.streaming")


class LiveStreamManager:
    """
    Manages live event ingestion, incremental graph updates, Bayesian belief shifts,
    and SSE subscriber broadcasting.
    """

    def __init__(self, state_ref: Optional[Dict[str, Any]] = None):
        self.state = state_ref if state_ref is not None else {}
        self.subscribers: Set[asyncio.Queue] = set()
        
        self.normalizer = EventNormalizer()
        self.mitre_mapper = MitreMapper()
        self.bayesian_engine = BayesianInferenceEngine()

        self.is_simulating = False
        self.is_paused = False
        self.sim_speed = 1.5  # seconds per event
        self.sim_index = 0
        self.sim_events: List[Dict[str, Any]] = []
        self._sim_task: Optional[asyncio.Task] = None

    def subscribe(self) -> asyncio.Queue:
        """
        Registers a new SSE client subscriber queue.
        """
        q = asyncio.Queue()
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        """
        Removes an SSE client subscriber queue.
        """
        self.subscribers.discard(q)

    async def broadcast(self, data: Dict[str, Any]):
        """
        Dispatches an SSE message payload to all active client queues.
        """
        if not self.subscribers:
            return
        msg = f"data: {json.dumps(data)}\n\n"
        dead = []
        for q in list(self.subscribers):
            try:
                q.put_nowait(msg)
            except Exception:
                dead.append(q)
        for d in dead:
            self.subscribers.discard(d)

    def ingest_single_event(self, raw_ev: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synchronously ingests a single raw event:
        1. Normalizes to ECS CanonicalEvent.
        2. Incrementally updates the AttackGraphBuilder.
        3. Updates hypotheses, timeline, Bayesian posterior, and actions.
        4. Computes graph delta (new nodes & edges).
        """
        # Ensure state containers exist
        if "raw_events" not in self.state:
            self.state["raw_events"] = []
        if "canonical_events" not in self.state:
            self.state["canonical_events"] = []
        if "graph_builder" not in self.state or self.state["graph_builder"] is None:
            self.state["graph_builder"] = AttackGraphBuilder()

        builder: AttackGraphBuilder = self.state["graph_builder"]

        # Track existing nodes and edges before adding
        old_nodes = set(builder.graph.nodes) if hasattr(builder, "graph") else set()
        old_edges = set(builder.graph.edges) if hasattr(builder, "graph") else set()

        # 1. Normalize
        canon_ev = self.normalizer.normalize_event(raw_ev)
        if not canon_ev:
            return {"status": "SKIPPED", "detail": "Unrecognized or empty event"}

        self.state["raw_events"].append(raw_ev)
        self.state["canonical_events"].append(canon_ev)

        # 2. Add to graph
        builder.add_event(canon_ev)

        # Check for lateral movement if multiple hosts or network event
        if len(self.state["canonical_events"]) > 1:
            builder._correlate_lateral_movement(self.state["canonical_events"])

        # Compute delta
        new_nodes_set = set(builder.graph.nodes) - old_nodes
        new_edges_set = set(builder.graph.edges) - old_edges

        # Format new vis.js nodes and edges
        delta_vis_nodes = []
        delta_vis_edges = []

        type_colors = {
            "process": "#a855f7",
            "file": "#f59e0b",
            "network": "#06b6d4",
            "registry": "#10b981",
        }

        for n in new_nodes_set:
            ndata = builder.graph.nodes[n]
            ntype = ndata.get("node_type", "unknown")
            label = n.split(":")[-1] if ":" in n else n
            delta_vis_nodes.append({
                "id": n,
                "label": label,
                "node_type": ntype,
                "color": type_colors.get(ntype, "#64748b"),
                "shape": "diamond" if ndata.get("is_root") else ("dot" if ntype == "network" else "box"),
                "font": {"color": "#f8fafc", "face": "JetBrains Mono", "size": 11}
            })

        for u, v in new_edges_set:
            edata = builder.graph.edges[u, v]
            rel = edata.get("relation", "CONNECTED_TO")
            is_lat = rel == "LATERAL_MOVEMENT"
            delta_vis_edges.append({
                "from": u,
                "to": v,
                "label": f"⚡ LATERAL PIVOT ({edata.get('protocol', 'SMB')} {edata.get('port', 445)})" if is_lat else rel,
                "arrows": "to",
                "color": {"color": "#fbbf24" if is_lat else "#38bdf8"},
                "width": 3 if is_lat else 1,
                "font": {"color": "#fbbf24" if is_lat else "#94a3b8", "size": 10}
            })

        # 3. Update Reasoning & Bayesian Probability
        agent = AIRAReasoningAgent(builder, self.mitre_mapper)
        inv = agent.investigate(self.state["canonical_events"])
        self.state["investigation"] = inv

        report_gen = IncidentReportGenerator(builder)
        inc_id = self.state.get("dossier").incident_id if self.state.get("dossier") else "INC-STREAM-01"
        dossier = report_gen.generate_dossier(inc_id, self.state["canonical_events"], inv)
        self.state["dossier"] = dossier

        hyp = dossier.hypotheses[0] if dossier.hypotheses else None

        # Build stream update payload
        payload = {
            "type": "STREAM_EVENT",
            "timestamp": canon_ev.timestamp.isoformat(),
            "event_number": len(self.state["canonical_events"]),
            "record_id": canon_ev.record_id,
            "host": canon_ev.host,
            "event_type": canon_ev.event_type.value,
            "delta_nodes": delta_vis_nodes,
            "delta_edges": delta_vis_edges,
            "total_nodes": builder.graph.number_of_nodes(),
            "total_edges": builder.graph.number_of_edges(),
            "bayesian_posterior": hyp.bayesian_posterior if hyp else 0.05,
            "bayesian_likelihood_ratio": hyp.bayesian_likelihood_ratio if hyp else 1.0,
            "bayesian_verdict": hyp.bayesian_verdict if hyp else "ANALYZING",
            "latest_trajectory_step": hyp.bayesian_trajectory[-1] if (hyp and hyp.bayesian_trajectory) else None,
            "confidence_pct": round(hyp.confidence * 100) if hyp else 5,
            "pending_actions_count": len([a for a in dossier.recommended_actions if a.requires_approval]),
            "timeline_entry": {
                "timestamp": canon_ev.timestamp.isoformat(),
                "actor": canon_ev.process.image.split("\\")[-1] if canon_ev.process else "SYSTEM",
                "action": f"{canon_ev.event_type.value}",
                "target": (canon_ev.process.command_line if canon_ev.process else (canon_ev.network.dst_ip if canon_ev.network else "Host")) or "Target",
                "stage": dossier.timeline[-1].stage if dossier.timeline else "Execution",
                "mitre_id": dossier.timeline[-1].mitre_id if dossier.timeline else None,
                "evidence_record_id": canon_ev.record_id
            }
        }

        return payload

    async def ingest_and_broadcast(self, raw_ev: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingests an event and immediately pushes the update to all connected web clients via SSE.
        """
        payload = self.ingest_single_event(raw_ev)
        await self.broadcast(payload)
        return payload

    def load_simulation_preset(self, preset: str = "multihost"):
        """
        Loads an attack sequence into memory for live step-by-step playback.
        """
        base_dir = Path(__file__).resolve().parent.parent / "data" / "samples"
        if preset == "multihost":
            trace_path = base_dir / "enterprise_multihost_attack.json"
        elif preset == "apt29":
            trace_path = base_dir / "mordor_apt29_execution_subset.json"
        else:
            trace_path = base_dir / "sample_attack_chain.json"

        with open(trace_path, "r", encoding="utf-8") as f:
            self.sim_events = json.load(f)

        self.sim_index = 0
        self.is_simulating = False
        self.is_paused = False

    def reset_stream(self):
        """
        Clears live stream state back to ground zero.
        """
        if self._sim_task and not self._sim_task.done():
            self._sim_task.cancel()
        self.is_simulating = False
        self.is_paused = False
        self.sim_index = 0

        self.state["raw_events"] = []
        self.state["canonical_events"] = []
        self.state["graph_builder"] = AttackGraphBuilder()
        self.state["investigation"] = {}
        self.state["dossier"] = IncidentDossier(
            incident_id="INC-STREAM-01",
            title="Real-Time Streaming Incident Assessment",
            severity="LOW",
            affected_hosts=[],
            affected_users=[],
            executive_summary="Monitoring live telemetry stream.",
            hypotheses=[],
            timeline=[],
            attack_graph_summary={},
            recommended_actions=[]
        )

    async def _run_simulation_loop(self):
        """
        Internal loop that pushes events sequentially with the configured delay.
        """
        try:
            self.is_simulating = True
            self.is_paused = False

            while self.sim_index < len(self.sim_events):
                if self.is_paused:
                    await asyncio.sleep(0.5)
                    continue

                raw_ev = self.sim_events[self.sim_index]
                self.sim_index += 1

                # Ingest & broadcast to all web clients
                await self.ingest_and_broadcast(raw_ev)

                # Wait between events
                await asyncio.sleep(self.sim_speed)

            # Mark simulation complete
            self.is_simulating = False
            await self.broadcast({
                "type": "STREAM_COMPLETE",
                "message": f"Live trace replay finished ({len(self.sim_events)} events ingested)."
            })
        except asyncio.CancelledError:
            self.is_simulating = False
        except Exception as e:
            logger.error(f"Error in simulation loop: {e}", exc_info=True)
            self.is_simulating = False

    def start_simulation(self, speed: Optional[float] = None) -> Dict[str, Any]:
        """
        Launches the background simulation playback task.
        """
        if speed is not None:
            self.sim_speed = max(0.2, speed)

        if not self.sim_events:
            self.load_simulation_preset("multihost")

        if self.is_paused:
            self.is_paused = False
            self.is_simulating = True
            return {"status": "RESUMED", "index": self.sim_index, "total": len(self.sim_events)}

        if self._sim_task and not self._sim_task.done():
            self._sim_task.cancel()

        self.is_simulating = True
        self.is_paused = False
        self._sim_task = asyncio.create_task(self._run_simulation_loop())
        return {
            "status": "STARTED",
            "total_events": len(self.sim_events),
            "interval_seconds": self.sim_speed
        }

    def pause_simulation(self) -> Dict[str, Any]:
        """
        Pauses the live stream playback.
        """
        self.is_paused = True
        return {"status": "PAUSED", "index": self.sim_index}

    def stop_simulation(self) -> Dict[str, Any]:
        """
        Stops the live stream playback.
        """
        if self._sim_task and not self._sim_task.done():
            self._sim_task.cancel()
        self.is_simulating = False
        self.is_paused = False
        return {"status": "STOPPED", "index": self.sim_index}

    def get_status(self) -> Dict[str, Any]:
        """
        Returns real-time status of the stream engine.
        """
        return {
            "is_simulating": self.is_simulating,
            "is_paused": self.is_paused,
            "current_index": self.sim_index,
            "total_preset_events": len(self.sim_events),
            "sim_speed": self.sim_speed,
            "active_subscribers": len(self.subscribers),
            "ingested_events_count": len(self.state.get("canonical_events", []))
        }
