"""
Unit & Integration Tests for AIRA Web API & Dashboard Endpoints
"""

from fastapi.testclient import TestClient
from aira.ui.app import app

client = TestClient(app)


def test_dashboard_html():
    response = client.get("/")
    assert response.status_code == 200
    assert "AIRA" in response.text
    assert "vis-network" in response.text
    assert "Reconstructed Chronological" in response.text


def test_api_incident_endpoint():
    client.post("/api/reset-sample")
    response = client.get("/api/incident")
    assert response.status_code == 200
    data = response.json()
    assert "incident_id" in data
    assert data["severity"] in ["CRITICAL", "HIGH"]
    assert len(data["hypotheses"]) > 0
    assert len(data["timeline"]) > 0
    assert len(data["recommended_actions"]) == 5
    action_types = [a["action_type"] for a in data["recommended_actions"]]
    assert "ISOLATE_HOST" in action_types
    assert "KILL_PROCESS" in action_types
    assert "BLOCK_IP" in action_types
    assert "DELETE_REGISTRY_KEY" in action_types
    assert "RESET_CREDENTIALS" in action_types


def test_api_graph_vis_endpoint():
    response = client.get("/api/graph/vis")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) >= 6
    assert len(data["edges"]) >= 5

    # Check that root cause node has distinct attributes
    root_nodes = [n for n in data["nodes"] if "[ROOT CAUSE]" in n["label"]]
    assert len(root_nodes) >= 1
    assert root_nodes[0]["shape"] == "diamond"


def test_action_approval_lifecycle():
    # Approve action 0
    res_app = client.post("/api/action/0/approve")
    assert res_app.status_code == 200
    assert res_app.json()["decision"] == "APPROVED"

    # Verify state reflects approval
    inc_res = client.get("/api/incident")
    actions = inc_res.json()["recommended_actions"]
    assert actions[0]["status"] == "APPROVED"

    # Reject action 0
    res_rej = client.post("/api/action/0/reject")
    assert res_rej.status_code == 200
    assert res_rej.json()["decision"] == "REJECTED"

    inc_res2 = client.get("/api/incident")
    actions2 = inc_res2.json()["recommended_actions"]
    assert actions2[0]["status"] == "REJECTED"


def test_markdown_report_export():
    response = client.get("/api/report/markdown")
    assert response.status_code == 200
    text = response.text
    assert "# AIRA Incident Investigation Dossier" in text
    assert "MITRE ATT&CK" in text
    assert "Chronological Attack Timeline" in text


def test_bayesian_ui_integration():
    client.post("/api/reset-sample")
    
    # 1. Verify API serialization of Bayesian attributes
    inc_res = client.get("/api/incident")
    assert inc_res.status_code == 200
    data = inc_res.json()
    hyp = data["hypotheses"][0]
    assert "bayesian_posterior" in hyp
    assert hyp["bayesian_posterior"] is not None
    assert hyp["bayesian_posterior"] > 0.95
    assert "bayesian_likelihood_ratio" in hyp
    assert hyp["bayesian_likelihood_ratio"] > 100.0
    assert "bayesian_trajectory" in hyp
    assert len(hyp["bayesian_trajectory"]) > 0
    assert hyp["bayesian_verdict"] == "CONFIRMED_MALICIOUS"

    # 2. Verify HTML dashboard contains Bayesian UI elements
    dash_res = client.get("/")
    assert dash_res.status_code == 200
    html = dash_res.text
    assert "bayesian-proof-card" in html
    assert "bayesian-posterior-val" in html
    assert "bayesian-trajectory-list" in html
    assert "HYBRID ENGINE" in html


def test_detections_and_paper_api():
    client.post("/api/reset-sample")

    # 1. Test /api/detections JSON endpoint
    det_res = client.get("/api/detections")
    assert det_res.status_code == 200
    data = det_res.json()
    assert "rules" in data
    assert "sigma" in data["rules"]
    assert "yara" in data["rules"]
    assert "splunk" in data["rules"]
    assert "elastic" in data["rules"]
    assert "sentinel" in data["rules"]

    # 2. Test /api/detections/download ZIP endpoint
    zip_res = client.get("/api/detections/download")
    assert zip_res.status_code == 200
    assert zip_res.headers["content-type"] == "application/zip"
    assert len(zip_res.content) > 500

    # 3. Test /api/paper/download IEEE PDF endpoint
    paper_res = client.get("/api/paper/download")
    assert paper_res.status_code == 200
    assert "application/pdf" in paper_res.headers["content-type"]
    assert len(paper_res.content) > 1000

    # 4. Verify HTML contains Detection Hub tab and IEEE paper download link
    dash_res = client.get("/")
    assert dash_res.status_code == 200
    html = dash_res.text
    assert "tab-btn-detections" in html
    assert "section-detections" in html
    assert "/api/paper/download" in html
    assert "IEEE Paper (PDF)" in html


