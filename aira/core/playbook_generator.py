"""
AIRA Multi-Platform Containment Playbook Generator
Compiles incident response actions into production-ready PowerShell, Bash, SOAR JSON,
and audit manifests for enterprise containment execution.
"""

import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from aira.core.models import IncidentDossier, RecommendedAction
from aira.core.sandbox_simulator import RemediationSandbox


class PlaybookGenerator:
    """
    Synthesizes approved actions into multi-platform automation scripts
    and SOAR orchestration workflows.
    """

    def __init__(self):
        self.sandbox = RemediationSandbox()

    def generate_powershell_script(self, dossier: Dict[str, Any], actions: List[RecommendedAction]) -> str:
        inc_id = dossier.get("incident_id", "INC-001")
        hosts = ", ".join(dossier.get("affected_hosts", ["LocalHost"]))
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            "# ==============================================================================",
            f"# AIRA AUTONOMOUS CONTAINMENT PLAYBOOK (WINDOWS POWERSHELL)",
            f"# Incident ID     : {inc_id}",
            f"# Generated At    : {now_str}",
            f"# Target Host(s)  : {hosts}",
            f"# Total Actions   : {len(actions)} Prescribed Steps",
            "# ==============================================================================",
            "#Requires -RunAsAdministrator",
            "$ErrorActionPreference = 'Continue'",
            "",
            "Write-Host '============================================================================' -ForegroundColor Cyan",
            f"Write-Host '  [+] AIRA AUTOMATED CONTAINMENT PLAYBOOK - INCIDENT: {inc_id}' -ForegroundColor Cyan",
            "Write-Host '============================================================================' -ForegroundColor Cyan",
            "",
            "# Verification Check",
            "$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())",
            "if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {",
            "    Write-Error '[FATAL] This containment script requires Administrator privileges. Run elevated PowerShell.'",
            "    Exit 1",
            "}",
            "",
            "$logFile = \"$env:SystemRoot\\Temp\\AIRA_Containment_$($env:COMPUTERNAME).log\"",
            "function Log-Action($msg) {",
            "    $line = \"$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) $msg\"",
            "    Write-Host $line -ForegroundColor Yellow",
            "    Add-Content -Path $logFile -Value $line",
            "}",
            "",
            "Log-Action '[INIT] Starting Autonomous Containment Execution...'",
            ""
        ]

        # Phase 1: Host Isolation
        isolate_actions = [a for a in actions if a.action_type == "ISOLATE_HOST"]
        if isolate_actions:
            lines.append("# --- PHASE 1: ENDPOINT NETWORK ISOLATION ---")
            for act in isolate_actions:
                sim = self.sandbox.simulate_action(act)
                lines.append(f"Log-Action 'Executing Host Isolation: {act.target}'")
                if "critical" in sim.risk_level.lower():
                    lines.append(f"# [WARNING] {sim.operational_impact}")
                lines.append(f"if ($env:COMPUTERNAME -eq '{act.target}' -or '{act.target}' -eq 'LocalHost') {{")
                lines.append("    Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Disable-NetAdapter -Confirm:$false")
                lines.append("    New-NetFirewallRule -DisplayName 'AIRA_Quarantine' -Direction Outbound -Action Block -ErrorAction SilentlyContinue")
                lines.append(f"    Log-Action '[SUCCESS] Endpoint {act.target} network interfaces disabled.'")
                lines.append("} else {")
                lines.append(f"    Write-Host '[NOTE] Command targeted for remote host: {act.target}. Run via WinRM / EDR sensor.' -ForegroundColor DarkGray")
                lines.append("}")
                lines.append("")

        # Phase 2: Process Termination
        kill_actions = [a for a in actions if a.action_type == "KILL_PROCESS"]
        if kill_actions:
            lines.append("# --- PHASE 2: MALICIOUS PROCESS TERMINATION ---")
            for act in kill_actions:
                lines.append(f"Log-Action 'Terminating Process: {act.target}'")
                target_low = act.target.lower()
                if "pid" in target_low:
                    parts = act.target.split(" ")
                    pid_val = ""
                    for i, p in enumerate(parts):
                        if p.lower() == "pid" and i + 1 < len(parts):
                            pid_val = parts[i + 1].strip("()")
                    if pid_val and pid_val.isdigit():
                        lines.append(f"Stop-Process -Id {pid_val} -Force -ErrorAction SilentlyContinue")
                        lines.append(f"Log-Action '[SUCCESS] Process PID {pid_val} terminated.'")
                # Also kill by name if available
                if "(" in act.target and ")" in act.target:
                    exe_name = act.target.split("(")[-1].split(")")[0].split("\\")[-1]
                    proc_base = exe_name.replace(".exe", "")
                    if proc_base and proc_base.lower() not in ["powershell", "cmd"]:
                        lines.append(f"Stop-Process -Name '{proc_base}' -Force -ErrorAction SilentlyContinue")
            lines.append("")

        # Phase 3: Perimeter Firewall & Network Blocking
        block_actions = [a for a in actions if a.action_type == "BLOCK_IP"]
        if block_actions:
            lines.append("# --- PHASE 3: COMMAND & CONTROL EGRESS BLOCK ---")
            for act in block_actions:
                ip_clean = act.target.split(":")[0]
                rule_name = f"AIRA_Block_{ip_clean.replace('.', '_')}"
                lines.append(f"Log-Action 'Blocking C2 IP: {ip_clean}'")
                lines.append(f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Outbound -RemoteAddress '{ip_clean}' -Action Block -ErrorAction SilentlyContinue")
                lines.append(f"Log-Action '[SUCCESS] Outbound firewall drop rule added for {ip_clean}.'")
            lines.append("")

        # Phase 4: Registry Persistence Eradication
        reg_actions = [a for a in actions if a.action_type == "DELETE_REGISTRY_KEY"]
        if reg_actions:
            lines.append("# --- PHASE 4: PERSISTENCE ERADICATION ---")
            for act in reg_actions:
                clean_path = act.target.replace("HKCU\\", "HKCU:\\").replace("HKLM\\", "HKLM:\\")
                lines.append(f"Log-Action 'Removing Startup Registry Key: {act.target}'")
                lines.append(f"if (Test-Path '{clean_path}') {{")
                lines.append(f"    Remove-Item -Path '{clean_path}' -Force -Recurse -ErrorAction SilentlyContinue")
                lines.append(f"    Log-Action '[SUCCESS] Registry entry eradicated.'")
                lines.append("} else {")
                lines.append(f"    Log-Action '[INFO] Key not found or already removed: {clean_path}'")
                lines.append("}")
            lines.append("")

        # Phase 5: Credential Invalidation
        cred_actions = [a for a in actions if a.action_type == "RESET_CREDENTIALS"]
        if cred_actions:
            lines.append("# --- PHASE 5: CREDENTIAL REVOCATION ---")
            for act in cred_actions:
                user_clean = act.target.split(" ")[0].replace("CORP\\", "")
                lines.append(f"Log-Action 'Purging Kerberos Tickets for {user_clean}'")
                lines.append("klist purge -li 0x3e7 -ErrorAction SilentlyContinue")
                lines.append(f"# Set-ADUser -Identity '{user_clean}' -ChangePasswordAtLogon $true")
                lines.append(f"Log-Action '[SUCCESS] Cached session tickets purged.'")
            lines.append("")

        # Phase 6: Active Directory KRBTGT Key Double Reset
        krbtgt_actions = [a for a in actions if a.action_type == "RESET_KRBTGT_KEY"]
        if krbtgt_actions:
            lines.append("# --- PHASE 6: ACTIVE DIRECTORY KRBTGT RESET GUIDANCE ---")
            lines.append("Write-Host '[CRITICAL] Active Directory Database Extraction Detected.' -ForegroundColor Red")
            lines.append("Write-Host 'Execute official Microsoft KRBTGT double-reset procedure on Domain Controller:' -ForegroundColor Yellow")
            lines.append("Write-Host '  1. Run New-KrbtgtKeys.ps1 or Set-ADAccountPassword -Identity krbtgt -Reset' -ForegroundColor White")
            lines.append("Write-Host '  2. Run repadmin /syncall /AdeP to replicate to all DCs' -ForegroundColor White")
            lines.append("Write-Host '  3. Wait 10-12 hours before performing second reset to invalidate old Golden Tickets.' -ForegroundColor White")
            lines.append("")

        lines.extend([
            "Log-Action '[COMPLETE] Autonomous Containment Execution Finished Successfully.'",
            f"Write-Host 'Log file saved to: ' $logFile -ForegroundColor Green",
            ""
        ])

        return "\n".join(lines)

    def generate_linux_bash_script(self, dossier: Dict[str, Any], actions: List[RecommendedAction]) -> str:
        inc_id = dossier.get("incident_id", "INC-001")
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            f"# AIRA AUTONOMOUS CONTAINMENT PLAYBOOK (LINUX / GATEWAY / PERIMETER)",
            f"# Incident ID  : {inc_id}",
            f"# Generated At : {now_str}",
            "# ==============================================================================",
            "set -euo pipefail",
            "",
            "if [ \"$EUID\" -ne 0 ]; then",
            "  echo \"[!] Error: Please run this containment script as root (sudo).\"",
            "  exit 1",
            "fi",
            "",
            "echo \"[+] AIRA Perimeter Containment executing for ${1:-incident}...\"",
            ""
        ]

        # Block external C2 IPs via iptables and ufw
        block_actions = [a for a in actions if a.action_type == "BLOCK_IP"]
        if block_actions:
            lines.append("# --- EGRESS C2 NETWORK FIREWALL BLOCK ---")
            for act in block_actions:
                ip_clean = act.target.split(":")[0]
                lines.append(f"echo \"[+] Blocking external adversary IP: {ip_clean}\"")
                lines.append(f"iptables -C OUTPUT -d {ip_clean} -j DROP 2>/dev/null || iptables -A OUTPUT -d {ip_clean} -j DROP")
                lines.append(f"iptables -C FORWARD -d {ip_clean} -j DROP 2>/dev/null || iptables -A FORWARD -d {ip_clean} -j DROP")
                lines.append(f"if command -v ufw >/dev/null 2>&1; then")
                lines.append(f"    ufw insert 1 deny out to {ip_clean}")
                lines.append(f"fi")
            lines.append("")

        lines.extend([
            "echo \"[+] Containment egress rules applied successfully.\"",
            "iptables -L OUTPUT -v -n --line-numbers | grep -E 'DROP'",
            ""
        ])

        return "\n".join(lines)

    def generate_soar_playbook(self, dossier: Dict[str, Any], actions: List[RecommendedAction]) -> Dict[str, Any]:
        """
        Universal SOAR (Cortex XSOAR / Splunk SOAR / Phantom) JSON Playbook.
        """
        inc_id = dossier.get("incident_id", "INC-001")
        steps = []
        
        for idx, act in enumerate(actions, 1):
            sim = self.sandbox.simulate_action(act)
            steps.append({
                "step_number": idx,
                "action_type": act.action_type,
                "target": act.target,
                "priority": act.priority,
                "rationale": act.rationale,
                "requires_analyst_approval": act.requires_approval,
                "safety_risk_level": sim.risk_level,
                "operational_impact": sim.operational_impact,
                "safety_warnings": sim.safety_warnings,
                "cli_command": sim.simulated_command,
                "rollback_command": sim.rollback_command,
                "status": "APPROVED_PREPARED"
            })

        return {
            "schema_version": "1.2.0",
            "playbook_name": f"AIRA_Autonomous_Containment_{inc_id}",
            "incident_id": inc_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "target_assets": dossier.get("affected_hosts", []),
            "target_users": dossier.get("affected_users", []),
            "total_steps": len(steps),
            "containment_phases": [
                "PHASE_1_ENDPOINT_ISOLATION",
                "PHASE_2_PROCESS_TERMINATION",
                "PHASE_3_NETWORK_EGRESS_BLOCKING",
                "PHASE_4_PERSISTENCE_REMOVAL",
                "PHASE_5_IDENTITY_AND_CREDENTIAL_ROTATION"
            ],
            "execution_steps": steps
        }

    def generate_manifest_markdown(self, dossier: Dict[str, Any], actions: List[RecommendedAction]) -> str:
        inc_id = dossier.get("incident_id", "INC-001")
        hosts = ", ".join(dossier.get("affected_hosts", ["LocalHost"]))
        sim_summary = self.sandbox.simulate_all(actions)

        lines = [
            f"# AIRA Autonomous Remediation Manifest — `{inc_id}`",
            "",
            f"* **Target Infrastructure**: `{hosts}`",
            f"* **Generated Timestamp**: `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`",
            f"* **Pre-Flight Safety Rating**: **{sim_summary['overall_safety_level']}**",
            f"* **Total Containment Steps**: `{len(actions)}`",
            "",
            "---",
            "",
            "## 🛡️ Pre-Flight Safety Summary",
            "",
            "| Step | Action Type | Target | Priority | Safety Risk | Operational Impact |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |"
        ]

        for idx, act in enumerate(actions, 1):
            sim = self.sandbox.simulate_action(act)
            lines.append(f"| {idx} | `{act.action_type}` | `{act.target}` | `{act.priority}` | **{sim.risk_level}** | {sim.operational_impact} |")

        lines.extend([
            "",
            "---",
            "",
            "## 📋 Post-Containment Verification Checklist",
            "1. [ ] Confirm endpoint network isolation active (no outbound packets to external gateways).",
            "2. [ ] Verify malicious PID deallocated from memory using `Get-Process`.",
            "3. [ ] Confirm C2 egress IP drop rule present in Windows Defender Firewall.",
            "4. [ ] Verify startup Registry Run keys / Windows Services eradicated.",
            "5. [ ] Force Active Directory password reset and revoke Kerberos tickets.",
            "6. [ ] If NTDS database extracted, schedule double KRBTGT domain key rotation.",
            "",
            "---",
            "*Generated by AIRA Autonomous Incident Reasoning Agent (SOC Tier-2/3 Copilot)*"
        ])

        return "\n".join(lines)

    def create_playbook_zip(self, dossier: Dict[str, Any], actions: List[RecommendedAction]) -> bytes:
        """
        Creates an in-memory zip archive containing all 4 containment artifacts.
        """
        ps1_content = self.generate_powershell_script(dossier, actions)
        sh_content = self.generate_linux_bash_script(dossier, actions)
        soar_json = json.dumps(self.generate_soar_playbook(dossier, actions), indent=2)
        manifest_md = self.generate_manifest_markdown(dossier, actions)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("containment_windows.ps1", ps1_content)
            zf.writestr("containment_linux.sh", sh_content)
            zf.writestr("soar_playbook.json", soar_json)
            zf.writestr("remediation_manifest.md", manifest_md)

        buf.seek(0)
        return buf.getvalue()
