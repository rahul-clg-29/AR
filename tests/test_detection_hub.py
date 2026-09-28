"""
Unit Tests for AIRA Multi-Format Detection Engineering Hub
"""

import io
import zipfile
import pytest
from pathlib import Path
import json

from aira.core.normalizer import EventNormalizer
from aira.core.graph_builder import AttackGraphBuilder
from aira.core.mitre_mapper import MitreMapper
from aira.core.reasoning_agent import AIRAReasoningAgent
from aira.core.report_generator import IncidentReportGenerator
from aira.core.detection_hub import DetectionEngineeringHub


@pytest.fixture
def detection_fixture():
    sample_file = Path(__file__).resolve().parent.parent / "aira" / "data" / "samples" / "sample_attack_chain.json"
    with open(sample_file, "r", encoding="utf-8") as f:
        raw = json.load(f)

    events = EventNormalizer().normalize_batch(raw)
    builder = AttackGraphBuilder()
    builder.build_graph(events)
    agent = AIRAReasoningAgent(builder, MitreMapper())
    inv = agent.investigate(events)
    generator = IncidentReportGenerator(builder)
    dossier = generator.generate_dossier("INC-DET-01", events, inv)

    hub = DetectionEngineeringHub(dossier.model_dump(), builder)
    return hub, dossier


def test_sigma_rule_generation(detection_fixture):
    hub, _ = detection_fixture
    sigma = hub.generate_sigma_rule()
    assert "title:" in sigma
    assert "logsource:" in sigma
    assert "category: process_creation" in sigma
    assert "ParentImage|endswith:" in sigma
    assert "powershell.exe" in sigma
    assert "attack." in sigma


def test_yara_rule_generation(detection_fixture):
    hub, _ = detection_fixture
    yara = hub.generate_yara_rule()
    assert "rule AIRA_Attack_Artifacts" in yara
    assert "strings:" in yara
    assert "$s1 = \"DownloadString\"" in yara
    assert "$r1 = \"Software\\\\" in yara
    assert "condition:" in yara
    assert "uint16(0) == 0x5A4D" in yara


def test_splunk_spl_generation(detection_fixture):
    hub, _ = detection_fixture
    spl = hub.generate_splunk_spl()
    assert "index=sysmon EventCode=1" in spl
    assert "EventCode=3" in spl
    assert "DestinationIp=" in spl
    assert "| stats" in spl
    assert "by host, User" in spl


def test_elastic_eql_generation(detection_fixture):
    hub, _ = detection_fixture
    eql = hub.generate_elastic_eql()
    assert "sequence by host.name with maxspan=5m" in eql
    assert "process where event.type == \"start\"" in eql
    assert "network where event.type == \"connection\"" in eql
    assert "registry where event.type == \"change\"" in eql


def test_sentinel_kql_generation(detection_fixture):
    hub, _ = detection_fixture
    kql = hub.generate_sentinel_kql()
    assert "let TimeWindow = 6h;" in kql
    assert "DeviceProcessEvents" in kql
    assert "DeviceNetworkEvents" in kql
    assert "join kind=inner" in kql
    assert "ProcessCommandLine" in kql


def test_generate_all_rules_structure(detection_fixture):
    hub, _ = detection_fixture
    all_rules = hub.generate_all_rules()
    assert all_rules["incident_id"] == "INC-DET-01"
    assert "sigma" in all_rules["rules"]
    assert "yara" in all_rules["rules"]
    assert "splunk" in all_rules["rules"]
    assert "elastic" in all_rules["rules"]
    assert "sentinel" in all_rules["rules"]
    for r_key, r_val in all_rules["rules"].items():
        assert len(r_val["content"]) > 50
        assert r_val["extension"] in ["yml", "yar", "spl", "eql", "kql"]


def test_detection_rules_zip_bundle(detection_fixture):
    hub, _ = detection_fixture
    zip_bytes = hub.generate_rules_zip()
    assert len(zip_bytes) > 500

    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    names = zf.namelist()
    assert any("sigma/sigma_incident_" in n and n.endswith(".yml") for n in names)
    assert any("yara/yara_incident_" in n and n.endswith(".yar") for n in names)
    assert any("splunk/splunk_incident_" in n and n.endswith(".spl") for n in names)
    assert any("elastic/elastic_incident_" in n and n.endswith(".eql") for n in names)
    assert any("sentinel/sentinel_incident_" in n and n.endswith(".kql") for n in names)
    assert "README_DETECTION_DEPLOYMENT.md" in names
