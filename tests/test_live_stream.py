"""
Unit & Integration Tests for AIRA Real-Time Telemetry Streaming & Zero-ETL Watcher
"""

import pytest
import asyncio
from pathlib import Path
from fastapi.testclient import TestClient

from aira.ui.app import app, stream_manager, state
from aira.streaming.stream_manager import LiveStreamManager

client = TestClient(app)


def test_stream_status_endpoint():
    res = client.get("/api/stream/status")
    assert res.status_code == 200
    data = res.json()
    assert "is_simulating" in data
    assert "watcher_active" in data
    assert "watch_directory" in data


def test_stream_ingest_single_event():
    raw_ev = {
        "event_type": "PROCESS_CREATE",
        "timestamp": "2026-09-28T10:00:00Z",
        "host": "TEST-HOST-01",
        "record_id": "REC-STREAM-999",
        "user": "TEST\\User",
        "process": {
            "name": "powershell.exe",
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "pid": 9999,
            "command_line": "powershell.exe -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
            "parent_pid": 1111,
            "parent_image": "C:\\Windows\\explorer.exe"
        }
    }

    res = client.post("/api/stream/ingest", json={"event": raw_ev})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["ingested_count"] == 1
    update = data["updates"][0]
    assert update["type"] == "STREAM_EVENT"
    assert update["event_type"] == "PROCESS_CREATE"
    assert "bayesian_posterior" in update
    assert update["total_nodes"] >= 2


def test_stream_simulation_lifecycle():
    with TestClient(app) as tc:
        # 1. Start simulation
        res_start = tc.post("/api/stream/sim/start?speed=2.0&preset=sample")
        assert res_start.status_code == 200
        assert res_start.json()["status"] == "STARTED"

        # 2. Check status
        res_status = tc.get("/api/stream/status")
        assert res_status.status_code == 200
        assert res_status.json()["is_simulating"] is True

        # 3. Pause
        res_pause = tc.post("/api/stream/sim/pause")
        assert res_pause.status_code == 200
        assert res_pause.json()["status"] == "PAUSED"

        # 4. Stop
        res_stop = tc.post("/api/stream/sim/stop")
        assert res_stop.status_code == 200
        assert res_stop.json()["status"] == "STOPPED"

        # 5. Reset
        res_reset = tc.post("/api/stream/reset")
        assert res_reset.status_code == 200
        assert res_reset.json()["status"] == "RESET"


@pytest.mark.anyio
async def test_live_stream_manager_broadcast():
    mgr = LiveStreamManager()
    queue = mgr.subscribe()

    test_payload = {"type": "TEST_ALERT", "score": 0.99}
    await mgr.broadcast(test_payload)

    msg = await queue.get()
    assert "TEST_ALERT" in msg
    assert "0.99" in msg

    mgr.unsubscribe(queue)
    assert len(mgr.subscribers) == 0
