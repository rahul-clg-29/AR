"""
Tests for AIRA Safe Containment Sandbox & Multi-Platform Playbook Generator
Validates pre-flight risk rating, dry-run commands, rollback commands,
and generation of PowerShell, Bash, SOAR JSON, and ZIP bundle artifacts.
"""

import io
import json
import zipfile
import pytest
from fastapi.testclient import TestClient

from aira.core.models import RecommendedAction
from aira.core.sandbox_simulator import RemediationSandbox
from aira.core.playbook_generator import PlaybookGenerator
from aira.ui.app import app


@pytest.fixture
def sample_actions():
    return [
        RecommendedAction(
            action_type="ISOLATE_HOST",
            priority="IMMEDIATE",
            target="CORP-DC-001",
            rationale="Isolate affected domain controller.",
            requires_approval=True
        ),
        RecommendedAction(
            action_type="KILL_PROCESS",
            priority="IMMEDIATE",
            target="PID 5104 (powershell.exe)",
            rationale="Terminate malicious PowerShell download cradle.",
            requires_approval=True
        ),
        RecommendedAction(
            action_type="BLOCK_IP",
            priority="HIGH",
            target="198.51.100.45:443",
            rationale="Block adversary C2 IP address.",
            requires_approval=True
        ),
        RecommendedAction(
            action_type="DELETE_REGISTRY_KEY",
            priority="HIGH",
            target="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateAgent",
            rationale="Remove startup persistence key.",
            requires_approval=True
        ),
        RecommendedAction(
            action_type="RESET_KRBTGT_KEY",
            priority="IMMEDIATE",
            target="Active Directory Domain KRBTGT Account",
            rationale="Invalidate forged Golden Tickets.",
            requires_approval=True
        ),
    ]


@pytest.fixture
def sample_dossier():
    return {
        "incident_id": "INC-TEST-001",
        "affected_hosts": ["CORP-WKS-042", "CORP-DC-001"],
        "affected_users": ["CORP\\JohnDoe"],
        "severity": "CRITICAL"
    }


def test_sandbox_simulator_safety_ratings(sample_actions):
    sandbox = RemediationSandbox()
    
    # 1. DC isolation should trigger CRITICAL_CAUTION
    dc_sim = sandbox.simulate_action(sample_actions[0])
    assert dc_sim.risk_level == "CRITICAL_CAUTION"
    assert "Domain Controller" in dc_sim.operational_impact
    assert len(dc_sim.safety_warnings) >= 1
    assert "Disable-NetAdapter" in dc_sim.simulated_command
    assert "Enable-NetAdapter" in dc_sim.rollback_command

    # 2. PowerShell kill should be LOW risk
    kill_sim = sandbox.simulate_action(sample_actions[1])
    assert kill_sim.risk_level == "LOW"
    assert "5104" in kill_sim.simulated_command

    # 3. External IP block should be LOW risk
    ip_sim = sandbox.simulate_action(sample_actions[2])
    assert ip_sim.risk_level == "LOW"
    assert "198.51.100.45" in ip_sim.simulated_command
    assert "Remove-NetFirewallRule" in ip_sim.rollback_command

    # 4. KRBTGT reset should trigger CRITICAL_CAUTION
    krbtgt_sim = sandbox.simulate_action(sample_actions[4])
    assert krbtgt_sim.risk_level == "CRITICAL_CAUTION"
    assert "Golden" in krbtgt_sim.operational_impact


def test_sandbox_simulate_all(sample_actions):
    sandbox = RemediationSandbox()
    summary = sandbox.simulate_all(sample_actions)
    
    assert summary["total_actions"] == 5
    assert summary["overall_safety_level"] == "CRITICAL_CAUTION"
    assert summary["caution_flags"] >= 2
    assert len(summary["simulations"]) == 5
    assert summary["ready_for_containment"] is True


def test_playbook_generator_powershell(sample_dossier, sample_actions):
    gen = PlaybookGenerator()
    ps1 = gen.generate_powershell_script(sample_dossier, sample_actions)
    
    assert "#Requires -RunAsAdministrator" in ps1
    assert "INC-TEST-001" in ps1
    assert "Disable-NetAdapter" in ps1
    assert "Stop-Process" in ps1
    assert "New-NetFirewallRule" in ps1
    assert "Remove-Item" in ps1
    assert "krbtgt" in ps1.lower()


def test_playbook_generator_bash(sample_dossier, sample_actions):
    gen = PlaybookGenerator()
    sh = gen.generate_linux_bash_script(sample_dossier, sample_actions)
    
    assert "#!/usr/bin/env bash" in sh
    assert "iptables -A OUTPUT" in sh
    assert "198.51.100.45" in sh


def test_playbook_generator_soar_json(sample_dossier, sample_actions):
    gen = PlaybookGenerator()
    soar = gen.generate_soar_playbook(sample_dossier, sample_actions)
    
    assert soar["schema_version"] == "1.2.0"
    assert soar["incident_id"] == "INC-TEST-001"
    assert soar["total_steps"] == 5
    assert len(soar["execution_steps"]) == 5
    for step in soar["execution_steps"]:
        assert "action_type" in step
        assert "safety_risk_level" in step
        assert "cli_command" in step
        assert "rollback_command" in step


def test_playbook_generator_zip_bundle(sample_dossier, sample_actions):
    gen = PlaybookGenerator()
    zip_bytes = gen.create_playbook_zip(sample_dossier, sample_actions)
    
    assert len(zip_bytes) > 500
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    filenames = zf.namelist()
    assert "containment_windows.ps1" in filenames
    assert "containment_linux.sh" in filenames
    assert "soar_playbook.json" in filenames
    assert "remediation_manifest.md" in filenames


def test_api_simulation_and_playbook_endpoints():
    client = TestClient(app)
    try:
        # 1. Simulate single action
        sim_res = client.post("/api/action/0/simulate")
        assert sim_res.status_code == 200
        sim_data = sim_res.json()
        assert "action_type" in sim_data
        assert "risk_level" in sim_data
        assert "simulated_command" in sim_data
        assert "rollback_command" in sim_data

        # 2. Simulate all actions
        sim_all_res = client.post("/api/action/simulate-all")
        assert sim_all_res.status_code == 200
        sim_all_data = sim_all_res.json()
        assert "overall_safety_level" in sim_all_data
        assert len(sim_all_data["simulations"]) > 0

        # 3. Preview playbook
        prev_res = client.get("/api/playbook/preview")
        assert prev_res.status_code == 200
        prev_data = prev_res.json()
        assert "powershell" in prev_data
        assert "bash" in prev_data
        assert "soar_json" in prev_data
        assert "manifest_md" in prev_data

        # 4. Download playbook zip
        dl_res = client.get("/api/playbook/download")
        assert dl_res.status_code == 200
        assert dl_res.headers["content-type"] == "application/zip"
        zf = zipfile.ZipFile(io.BytesIO(dl_res.content))
        assert "containment_windows.ps1" in zf.namelist()
    finally:
        client.post("/api/reset-sample")
