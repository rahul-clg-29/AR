"""
AIRA FastAPI Backend & SOC Analyst Workbench Server
Serves the REST API for graph telemetry, incident hypotheses, timeline, and the interactive UI.
"""

import os
import json
import asyncio
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, PlainTextResponse, Response, FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from aira.core.normalizer import EventNormalizer
from aira.core.graph_builder import AttackGraphBuilder
from aira.core.mitre_mapper import MitreMapper
from aira.core.reasoning_agent import AIRAReasoningAgent
from aira.core.report_generator import IncidentReportGenerator
from aira.core.evtx_parser import EVTXParser
from aira.core.models import CanonicalEvent, IncidentDossier
from aira.core.copilot import AIRACoPilot
from aira.core.sandbox_simulator import RemediationSandbox
from aira.core.playbook_generator import PlaybookGenerator

app = FastAPI(title="AIRA: Autonomous Incident Reasoning Agent", version="1.0.0")

sandbox = RemediationSandbox()
playbook_gen = PlaybookGenerator()

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory state
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
SAMPLE_FILE = ROOT_DIR / "aira" / "data" / "samples" / "sample_attack_chain.json"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

state = {
    "raw_events": [],
    "canonical_events": [],
    "graph_builder": None,
    "investigation": None,
    "dossier": None,
    "copilot": None,
    "approved_actions": set(),
    "rejected_actions": set(),
    "source_name": "sample_attack_chain.json (Default Preset)",
    "source_type": "JSON",
}

from aira.streaming.stream_manager import LiveStreamManager
from aira.streaming.file_watcher import ZeroETLFileWatcher

stream_manager = LiveStreamManager(state)
file_watcher = ZeroETLFileWatcher(str(ROOT_DIR / "aira" / "data" / "live_stream"), stream_manager)


@app.on_event("startup")
async def startup_event():
    try:
        loop = asyncio.get_event_loop()
        file_watcher.start(loop)
    except Exception as e:
        print(f"[Warning] Failed to start file watcher: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    try:
        file_watcher.stop()
    except Exception as e:
        pass



def run_investigation_pipeline(
    raw_events_data: List[Dict[str, Any]],
    incident_id: str = "INC-2026-0926-01",
    source_name: str = "sample_attack_chain.json (Default Preset)",
    source_type: str = "JSON"
):
    """
    Executes the full pipeline and updates the global state.
    """
    normalizer = EventNormalizer()
    canonical = normalizer.normalize_batch(raw_events_data)

    builder = AttackGraphBuilder()
    builder.build_graph(canonical)

    mapper = MitreMapper()
    agent = AIRAReasoningAgent(builder, mapper)
    investigation = agent.investigate(canonical)

    generator = IncidentReportGenerator(builder)
    dossier = generator.generate_dossier(incident_id, canonical, investigation)

    state["raw_events"] = raw_events_data
    state["canonical_events"] = canonical
    state["graph_builder"] = builder
    state["investigation"] = investigation
    state["dossier"] = dossier
    state["source_name"] = source_name
    state["source_type"] = source_type
    state["approved_actions"].clear()
    state["rejected_actions"].clear()

    if state.get("copilot") is not None:
        state["copilot"].update_context(dossier.model_dump(), builder)
    else:
        state["copilot"] = AIRACoPilot(dossier.model_dump(), builder)


# Initialize state with sample dataset on startup
try:
    if SAMPLE_FILE.exists():
        with open(SAMPLE_FILE, "r", encoding="utf-8") as f:
            initial_raw = json.load(f)
        run_investigation_pipeline(initial_raw)
except Exception as e:
    print(f"[Warning] Failed to initialize default sample: {e}")


@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """
    Serves the modern SOC Analyst Workbench single-page application.
    """
    index_file = TEMPLATES_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h2>index.html not found in templates directory</h2>", status_code=404)
    with open(index_file, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content)


@app.get("/api/incident")
async def get_incident():
    """
    Returns the complete incident dossier, hypotheses, timeline, and actions.
    """
    dossier = state.get("dossier")
    if not dossier:
        raise HTTPException(status_code=404, detail="No active incident loaded")

    # Serialize with action statuses and source metadata
    data = dossier.model_dump()
    data["source_name"] = state.get("source_name", "sample_attack_chain.json")
    data["source_type"] = state.get("source_type", "JSON")
    data["events_count"] = len(state.get("raw_events", []))

    for idx, act in enumerate(data.get("recommended_actions", [])):
        if idx in state["approved_actions"]:
            act["status"] = "APPROVED"
        elif idx in state["rejected_actions"]:
            act["status"] = "REJECTED"
        else:
            act["status"] = "PENDING"
    return data


@app.get("/api/graph/vis")
async def get_vis_graph(filter_noise: bool = True):
    """
    Returns graph nodes and edges optimized for Vis.js Network rendering.
    Optionally applies Causal Subgraph Pruning to filter out benign enterprise background noise.
    """
    builder: Optional[AttackGraphBuilder] = state.get("graph_builder")
    investigation = state.get("investigation")
    if not builder:
        return {"nodes": [], "edges": [], "noise_metrics": {}}

    suspicious_nodes = list(investigation.get("suspicious_nodes", [])) if investigation else []
    root_causes = set(investigation.get("root_causes", [])) if investigation else set()

    subgraph, noise_metrics = builder.filter_noise(suspicious_nodes) if suspicious_nodes else (builder.graph, {})
    g = subgraph if (filter_noise and len(subgraph) > 0) else builder.graph

    all_hosts = {d.get("host") for _, d in g.nodes(data=True) if d.get("host")}
    is_multihost = len(all_hosts) > 1

    vis_nodes = []
    for node_id, data in g.nodes(data=True):
        node_type = data.get("node_type", "generic")
        is_suspicious = node_id in suspicious_nodes
        is_root = node_id in root_causes
        host = data.get("host", "")
        host_tag = f"[{host}] " if (is_multihost and host) else ""

        # Visual styling by node type and malice (enlarged for instant visibility)
        if is_root:
            color = {"background": "#e11d48", "border": "#ffe4e6", "highlight": {"background": "#f43f5e", "border": "#fff"}}
            shape = "diamond"
            size = 40
            badge = " [ROOT CAUSE]"
        elif is_suspicious:
            color = {"background": "#ef4444", "border": "#fca5a5", "highlight": {"background": "#dc2626", "border": "#fff"}}
            shape = "dot"
            size = 35
            badge = " [SUSPICIOUS]"
        elif node_type == "process":
            color = {"background": "#8b5cf6", "border": "#ddd6fe", "highlight": {"background": "#7c3aed", "border": "#fff"}}
            shape = "dot"
            size = 28
            badge = ""
        elif node_type == "network":
            color = {"background": "#06b6d4", "border": "#cffafe", "highlight": {"background": "#0891b2", "border": "#fff"}}
            shape = "triangle"
            size = 28
            badge = ""
        elif node_type == "file":
            color = {"background": "#f59e0b", "border": "#fef3c7", "highlight": {"background": "#d97706", "border": "#fff"}}
            shape = "box"
            size = 26
            badge = ""
        elif node_type == "registry":
            color = {"background": "#10b981", "border": "#d1fae5", "highlight": {"background": "#059669", "border": "#fff"}}
            shape = "hexagon"
            size = 26
            badge = ""
        else:
            color = {"background": "#64748b", "border": "#cbd5e1"}
            shape = "dot"
            size = 22
            badge = ""

        # Human-friendly label
        if node_type == "process":
            img_name = data.get("image", "").split("\\")[-1] or node_id.split(":")[-1]
            pid_val = data.get("pid", "")
            base_label = f"{img_name} ({pid_val})" if pid_val else img_name
            clean_label = f"{host_tag}{base_label}"
            if is_root:
                clean_label = f"⬦ {clean_label} [ROOT CAUSE]"
            elif is_suspicious:
                clean_label = f"⚠️ {clean_label}"
        elif node_type == "network":
            clean_label = f"🌐 {data.get('dst_ip', '')}:{data.get('dst_port', '')}"
        elif node_type == "file":
            fname = data.get("path", "").split("\\")[-1] or "dropped_file"
            clean_label = f"{host_tag}📄 {fname}"
        elif node_type == "registry":
            rname = data.get("key_path", "").split("\\")[-1] or "RunKey"
            clean_label = f"{host_tag}🔑 {rname}"
        else:
            clean_label = f"{host_tag}{node_id.split(':')[-1]}"

        tooltip = f"<b>{node_id}</b>{badge}<br>Type: {node_type}<br>"
        for k, v in data.items():
            if k not in ["node_type"] and v:
                tooltip += f"• {k}: {str(v)[:120]}<br>"

        font_size = 14 if (is_root or is_suspicious) else 12

        vis_nodes.append({
            "id": node_id,
            "label": clean_label,
            "title": tooltip,
            "group": node_type,
            "shape": shape,
            "size": size,
            "color": color,
            "font": {
                "color": "#ffffff",
                "size": font_size,
                "face": "JetBrains Mono, monospace",
                "background": "rgba(8, 13, 26, 0.8)",
                "strokeWidth": 0
            },
            "is_suspicious": is_suspicious,
            "is_root": is_root,
            "raw_data": data,
        })

    vis_edges = []
    for u, v, data in g.edges(data=True):
        rel = data.get("relation", "CONNECTED")
        if rel == "LATERAL_MOVEMENT":
            proto = data.get("protocol", "SMB")
            port = data.get("port", 445)
            edge_color = "#f59e0b"  # Glowing Amber
            edge_width = 3
            dashes = [8, 4]
            edge_label = f"⚡ LATERAL PIVOT ({proto} {port})"
        elif rel in ["INJECTED_INTO", "MODIFIED_REGISTRY"]:
            edge_color = "#f43f5e"
            edge_width = 2
            dashes = False
            edge_label = rel
        else:
            edge_color = "#38bdf8"
            edge_width = 1
            dashes = False
            edge_label = rel

        vis_edges.append({
            "from": u,
            "to": v,
            "label": edge_label,
            "arrows": "to",
            "width": edge_width,
            "dashes": dashes,
            "color": {"color": edge_color, "highlight": "#ffffff"},
            "font": {
                "color": "#fbbf24" if rel == "LATERAL_MOVEMENT" else "#94a3b8",
                "size": 11 if rel == "LATERAL_MOVEMENT" else 10,
                "align": "middle",
                "background": "#0f172a"
            },
            "smooth": {"type": "cubicBezier", "roundness": 0.2},
            "title": f"Relation: {rel}<br>Timestamp: {data.get('timestamp')}<br>Record ID: {data.get('record_id')}<br>{data.get('details', '')}",
        })

    return {"nodes": vis_nodes, "edges": vis_edges, "noise_metrics": noise_metrics}


@app.post("/api/action/{action_idx}/approve")
async def approve_action(action_idx: int):
    """
    SOC Analyst human approval gate for an action.
    """
    dossier = state.get("dossier")
    if not dossier or action_idx < 0 or action_idx >= len(dossier.recommended_actions):
        raise HTTPException(status_code=400, detail="Invalid action index")
    state["approved_actions"].add(action_idx)
    state["rejected_actions"].discard(action_idx)
    return {"status": "SUCCESS", "action_index": action_idx, "decision": "APPROVED"}


@app.post("/api/action/{action_idx}/reject")
async def reject_action(action_idx: int):
    """
    SOC Analyst human rejection gate for an action.
    """
    dossier = state.get("dossier")
    if not dossier or action_idx < 0 or action_idx >= len(dossier.recommended_actions):
        raise HTTPException(status_code=400, detail="Invalid action index")
    state["rejected_actions"].add(action_idx)
    state["approved_actions"].discard(action_idx)
    return {"status": "SUCCESS", "action_index": action_idx, "decision": "REJECTED"}


@app.post("/api/action/{action_idx}/simulate")
async def simulate_action(action_idx: int):
    """
    Runs pre-flight containment sandbox simulation for an individual action.
    """
    dossier = state.get("dossier")
    if not dossier or action_idx < 0 or action_idx >= len(dossier.recommended_actions):
        raise HTTPException(status_code=400, detail="Invalid action index")
    act = dossier.recommended_actions[action_idx]
    result = sandbox.simulate_action(act, all_actions=dossier.recommended_actions)
    return result.model_dump()


@app.post("/api/action/simulate-all")
async def simulate_all_actions():
    """
    Runs pre-flight containment sandbox simulation across all actions in the incident dossier.
    """
    dossier = state.get("dossier")
    if not dossier:
        raise HTTPException(status_code=404, detail="No active incident loaded")
    summary = sandbox.simulate_all(dossier.recommended_actions)
    return summary


@app.get("/api/playbook/preview")
async def get_playbook_preview():
    """
    Returns previews of generated containment playbooks (PowerShell, Linux Bash, SOAR JSON, Manifest).
    """
    dossier = state.get("dossier")
    if not dossier:
        raise HTTPException(status_code=404, detail="No active incident loaded")
    dossier_data = dossier.model_dump()
    actions = dossier.recommended_actions
    return {
        "powershell": playbook_gen.generate_powershell_script(dossier_data, actions),
        "bash": playbook_gen.generate_linux_bash_script(dossier_data, actions),
        "soar_json": playbook_gen.generate_soar_playbook(dossier_data, actions),
        "manifest_md": playbook_gen.generate_manifest_markdown(dossier_data, actions),
    }


@app.get("/api/playbook/download")
async def download_playbook():
    """
    Exports a ready-to-deploy zip bundle of all containment scripts and SOAR manifests.
    """
    dossier = state.get("dossier")
    if not dossier:
        raise HTTPException(status_code=404, detail="No active incident loaded")
    dossier_data = dossier.model_dump()
    actions = dossier.recommended_actions
    zip_bytes = playbook_gen.create_playbook_zip(dossier_data, actions)
    inc_id = dossier.incident_id or "INC-001"

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=AIRA_Containment_Playbook_{inc_id}.zip"}
    )


@app.post("/api/reset-sample")
async def reset_sample():
    """
    Reloads the default sample attack chain.
    """
    with open(SAMPLE_FILE, "r", encoding="utf-8") as f:
        raw = json.load(f)
    run_investigation_pipeline(raw)
    return {"status": "SUCCESS", "message": "Loaded sample attack chain telemetry"}


@app.post("/api/load-trace")
async def load_trace(preset: str = "sample"):
    """
    Loads specific attack presets: 'sample' (10 clean events), 'apt29' (Mordor APT29 trace with 65 noisy events),
    or 'multihost' (Enterprise Multi-Host Lateral Movement pivot from Workstation to Domain Controller).
    """
    if preset == "multihost":
        target = ROOT_DIR / "aira" / "data" / "samples" / "enterprise_multihost_attack.json"
        inc_id = "INC-MULTIHOST-DC-01"
        src_name = "enterprise_multihost_attack.json (Multi-Host Lateral Movement)"
        src_type = "JSON Preset"
    elif preset == "apt29":
        target = ROOT_DIR / "aira" / "data" / "samples" / "mordor_apt29_noisy.json"
        inc_id = "INC-APT29-MORD-02"
        src_name = "mordor_apt29_noisy.json (APT29 Simulation)"
        src_type = "JSON Preset"
    else:
        target = SAMPLE_FILE
        inc_id = "INC-2026-0926-01"
        src_name = "sample_attack_chain.json (Kill Chain Sample)"
        src_type = "JSON Preset"

    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Preset file not found: {target.name}")

    with open(target, "r", encoding="utf-8") as f:
        raw = json.load(f)

    run_investigation_pipeline(raw, incident_id=inc_id, source_name=src_name, source_type=src_type)
    return {
        "status": "SUCCESS",
        "preset": preset,
        "incident_id": inc_id,
        "events_count": len(raw),
        "source_name": src_name,
        "source_type": src_type
    }


@app.post("/api/upload")
async def upload_telemetry(file: UploadFile = File(...)):
    """
    Ingests user-uploaded telemetry file (.json or native binary .evtx) and triggers real-time investigation.
    """
    try:
        orig_filename = file.filename or "telemetry.json"
        filename_lower = orig_filename.lower()
        content = await file.read()

        if filename_lower.endswith(".evtx"):
            source_type = "EVTX Binary"
            with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name

            try:
                parser = EVTXParser()
                raw_events = parser.parse_evtx_file(tmp_path)
            finally:
                Path(tmp_path).unlink(missing_ok=True)
        else:
            source_type = "JSON Telemetry"
            raw_events = json.loads(content.decode("utf-8"))
            if not isinstance(raw_events, list):
                raise ValueError("Uploaded JSON must be an array of event objects")

        incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
        run_investigation_pipeline(raw_events, incident_id=incident_id, source_name=orig_filename, source_type=source_type)
        return {
            "status": "SUCCESS",
            "incident_id": incident_id,
            "events_count": len(raw_events),
            "source_name": orig_filename,
            "source_type": source_type
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to process telemetry: {str(e)}")


@app.get("/api/report/markdown", response_class=PlainTextResponse)
async def get_markdown_report():
    """
    Exports the generated investigation dossier as markdown.
    """
    dossier = state.get("dossier")
    builder = state.get("graph_builder")
    if not dossier or not builder:
        raise HTTPException(status_code=404, detail="No incident available")
    generator = IncidentReportGenerator(builder)
    return PlainTextResponse(generator.export_markdown(dossier))


@app.get("/api/benchmark/results")
async def get_benchmark_results():
    """
    Runs or returns the latest benchmark suite metrics across all test datasets.
    """
    from aira.evaluation.benchmark import AIRABenchmarkRunner
    runner = AIRABenchmarkRunner()
    results = runner.run_all()
    return [r.model_dump() for r in results]


@app.get("/api/benchmark/latex", response_class=PlainTextResponse)
async def get_benchmark_latex():
    """
    Exports publication-grade LaTeX tables for the Capstone-I thesis.
    """
    from aira.evaluation.benchmark import AIRABenchmarkRunner
    runner = AIRABenchmarkRunner()
    results = runner.run_all()
    return PlainTextResponse(runner.generate_latex_tables(results))


@app.get("/api/benchmark/markdown", response_class=PlainTextResponse)
async def get_benchmark_markdown():
    """
    Exports the comprehensive benchmark markdown report.
    """
    from aira.evaluation.benchmark import AIRABenchmarkRunner
    runner = AIRABenchmarkRunner()
    results = runner.run_all()
    return PlainTextResponse(runner.generate_markdown_report(results))


class CopilotQuery(BaseModel):
    query: str
    api_key: Optional[str] = None
    provider: Optional[str] = "auto"


@app.post("/api/copilot/ask")
async def ask_copilot(payload: CopilotQuery):
    """
    Submits an analyst question to the AIRA SOC Co-Pilot.
    """
    copilot: Optional[AIRACoPilot] = state.get("copilot")
    dossier = state.get("dossier")
    builder = state.get("graph_builder")
    if not dossier or not builder:
        raise HTTPException(status_code=404, detail="No active incident loaded")

    if copilot is None:
        copilot = AIRACoPilot(dossier.model_dump(), builder)
        state["copilot"] = copilot
    else:
        copilot.update_context(dossier.model_dump(), builder)

    result = copilot.ask(payload.query, api_key=payload.api_key, provider=payload.provider or "auto")
    return result


@app.get("/api/copilot/status")
async def get_copilot_status():
    """
    Returns the operational status and active LLM configuration of AIRA Co-Pilot.
    """
    has_gemini = bool(os.environ.get("GEMINI_API_KEY"))
    has_openai = bool(os.environ.get("OPENAI_API_KEY"))
    return {
        "engine": "google-gemini" if has_gemini else ("openai" if has_openai else "aira-graph-rag-local"),
        "has_external_key": has_gemini or has_openai,
        "mode": "Live Online LLM" if (has_gemini or has_openai) else "Deterministic Graph-RAG (Offline Active)"
    }


@app.get("/api/paper/download")
async def download_ieee_paper():
    """
    Downloads the official publication-grade IEEE Capstone Research Paper PDF.
    """
    pdf_path = ROOT_DIR / "aira" / "docs" / "AIRA_IEEE_Capstone_Research_Paper.pdf"
    if not pdf_path.exists():
        from aira.core.pdf_paper_generator import build_ieee_research_paper_pdf
        build_ieee_research_paper_pdf(str(pdf_path))
    return FileResponse(
        str(pdf_path),
        media_type="application/pdf",
        filename="AIRA_IEEE_Capstone_Research_Paper.pdf"
    )


@app.get("/api/detections")
async def get_detections():
    """
    Returns all 5 multi-format detection rules generated from the active incident.
    """
    dossier = state.get("dossier")
    builder = state.get("graph_builder")
    if not dossier or not builder:
        raise HTTPException(status_code=404, detail="No active incident loaded")

    from aira.core.detection_hub import DetectionEngineeringHub
    hub = DetectionEngineeringHub(dossier.model_dump(), builder)
    return hub.generate_all_rules()


@app.get("/api/detections/download")
async def download_detections_zip():
    """
    Downloads an in-memory ZIP package containing all 5 detection rules and deployment README.
    """
    dossier = state.get("dossier")
    builder = state.get("graph_builder")
    if not dossier or not builder:
        raise HTTPException(status_code=404, detail="No active incident loaded")

    from aira.core.detection_hub import DetectionEngineeringHub
    hub = DetectionEngineeringHub(dossier.model_dump(), builder)
    zip_bytes = hub.generate_rules_zip()
    inc_id = dossier.incident_id

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=detection_rules_{inc_id}.zip"}
    )


@app.get("/api/stream/events")
async def stream_events():
    """
    Server-Sent Events (SSE) live feed delivering real-time telemetry events,
    graph additions, and Bayesian belief updates to connected web dashboards.
    """
    queue = stream_manager.subscribe()

    async def event_generator():
        try:
            yield f"data: {json.dumps({'type': 'CONNECTED', 'message': 'Live Telemetry Stream Active'})}\n\n"
            while True:
                msg = await queue.get()
                yield msg
        except asyncio.CancelledError:
            stream_manager.unsubscribe(queue)
            raise
        finally:
            stream_manager.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


class IngestPayload(BaseModel):
    event: Optional[Dict[str, Any]] = None
    events: Optional[List[Dict[str, Any]]] = None


@app.post("/api/stream/ingest")
async def stream_ingest(payload: IngestPayload):
    """
    Ingests live event(s) pushed via REST API, immediately broadcasting graph & Bayesian updates.
    """
    results = []
    if payload.event:
        res = await stream_manager.ingest_and_broadcast(payload.event)
        results.append(res)
    if payload.events:
        for ev in payload.events:
            res = await stream_manager.ingest_and_broadcast(ev)
            results.append(res)
    return {"status": "SUCCESS", "ingested_count": len(results), "updates": results}


@app.post("/api/stream/sim/start")
async def start_stream_simulation(speed: float = 1.5, preset: str = "multihost"):
    """
    Starts an automated live trace simulation replay pushing events sequentially.
    """
    stream_manager.load_simulation_preset(preset)
    return stream_manager.start_simulation(speed=speed)


@app.post("/api/stream/sim/pause")
async def pause_stream_simulation():
    """
    Pauses the running simulation replay.
    """
    return stream_manager.pause_simulation()


@app.post("/api/stream/sim/stop")
async def stop_stream_simulation():
    """
    Stops the simulation replay.
    """
    return stream_manager.stop_simulation()


@app.post("/api/stream/reset")
async def reset_stream():
    """
    Resets the active incident stream back to ground zero.
    """
    stream_manager.reset_stream()
    return {"status": "RESET", "message": "Telemetry stream reset to baseline"}


@app.get("/api/stream/status")
async def get_stream_status():
    """
    Returns live streaming engine status and metrics.
    """
    status = stream_manager.get_status()
    status["watcher_active"] = file_watcher.is_running
    status["watch_directory"] = str(file_watcher.watch_dir)
    return status



