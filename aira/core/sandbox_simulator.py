"""
AIRA Safe Containment Sandbox Simulation Engine
Provides pre-flight safety analysis, dry-run simulation, operational blast-radius estimation,
and rollback generation for prescribed incident response actions.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from aira.core.models import RecommendedAction


class SimulationResult(BaseModel):
    action_type: str
    target: str
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL_CAUTION
    operational_impact: str
    simulated_command: str
    predicted_host_state: str
    rollback_command: str
    safety_warnings: List[str] = Field(default_factory=list)
    simulation_status: str = "SUCCESS_PREVIEW"


class RemediationSandbox:
    """
    Evaluates containment actions against enterprise infrastructure constraints
    (e.g., Domain Controllers, critical file servers, kernel/OS dependencies)
    to prevent accidental denial of service during incident containment.
    """

    CRITICAL_HOST_KEYWORDS = ["dc", "domain", "ctrl", "primary", "ad-", "dns"]
    PROTECTED_SYSTEM_PROCESSES = ["lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "services.exe", "svchost.exe"]

    def simulate_action(self, action: RecommendedAction, all_actions: Optional[List[RecommendedAction]] = None) -> SimulationResult:
        """
        Runs a pre-flight safety simulation for a single recommended action.
        """
        act_type = action.action_type
        target = action.target
        target_lower = target.lower()

        warnings: List[str] = []
        risk_level = "LOW"
        operational_impact = "Minimal impact on standard business processes."
        cmd = ""
        predicted_state = ""
        rollback = ""

        if act_type == "ISOLATE_HOST":
            is_dc = any(k in target_lower for k in self.CRITICAL_HOST_KEYWORDS) or "dc" in target_lower
            if is_dc:
                risk_level = "CRITICAL_CAUTION"
                operational_impact = (
                    f"Target '{target}' appears to be a Domain Controller or Identity Service. "
                    "Isolating will disrupt Active Directory authentication, Kerberos ticket granting, "
                    "and LDAP queries for dependent enterprise domain workstations."
                )
                warnings.append("Ensure secondary Domain Controller (DC2/Failover) is reachable prior to isolating.")
                warnings.append("Coordinate with Identity & Directory Operations team before network cut.")
            else:
                risk_level = "MEDIUM"
                operational_impact = f"Endpoint '{target}' user session and network connectivity will be terminated."

            cmd = (
                f"# Windows Host Network Quarantine ({target})\n"
                f"Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' }} | Disable-NetAdapter -Confirm:$false\n"
                f"# Configure quarantine loopback exception if local logging agent required\n"
                f"New-NetFirewallRule -DisplayName 'AIRA_Quarantine_Isolation' -Direction Outbound -Action Block"
            )
            predicted_state = f"All physical and virtual network interfaces disabled on {target}. Attacker C2 severed."
            rollback = (
                f"# Rollback: Restore Network Connectivity on {target}\n"
                f"Get-NetAdapter | Enable-NetAdapter -Confirm:$false\n"
                f"Remove-NetFirewallRule -DisplayName 'AIRA_Quarantine_Isolation' -ErrorAction SilentlyContinue"
            )

        elif act_type == "KILL_PROCESS":
            is_protected = any(p in target_lower for p in self.PROTECTED_SYSTEM_PROCESSES)
            if is_protected:
                risk_level = "CRITICAL_CAUTION"
                operational_impact = "CRITICAL: Target is an essential Windows OS subsystem process. Terminating directly may cause an instant Blue Screen of Death (BSOD) system crash!"
                warnings.append("Never terminate core subsystem processes directly. Isolate host instead.")
            elif any(s in target_lower for s in ["powershell", "cmd.exe", "update_agent", "mshta", "rundll32"]):
                risk_level = "LOW"
                operational_impact = "Malicious or scripting process will be forcefully terminated in memory. Zero impact to legitimate business applications."
            else:
                risk_level = "LOW"
                operational_impact = "Active process handle closed and memory deallocated."

            # Extract PID if present
            pid_str = ""
            if "pid" in target_lower:
                parts = target.split(" ")
                for i, p in enumerate(parts):
                    if p.lower() == "pid" and i + 1 < len(parts):
                        pid_str = parts[i + 1].strip("()")

            cmd = (
                f"# Process Termination ({target})\n"
                f"Stop-Process -Id {pid_str if pid_str else 'TARGET_PID'} -Force -ErrorAction SilentlyContinue"
            )
            predicted_state = f"Process {target} terminated immediately. In-memory stager thread purged."
            rollback = "# Process termination cannot be undone in memory. Re-launch valid software manually if required."

        elif act_type == "BLOCK_IP":
            ip_val = target.split(":")[0] if ":" in target else target
            is_internal = ip_val.startswith("10.") or ip_val.startswith("192.168.") or ip_val.startswith("127.") or ip_val.startswith("172.")
            if is_internal:
                risk_level = "HIGH"
                operational_impact = f"IP '{ip_val}' is an internal subnet address. Blocking may sever internal LAN services."
                warnings.append("Internal IP blocking should be applied selectively to avoid LAN disruption.")
            else:
                risk_level = "LOW"
                operational_impact = f"External adversary IP '{ip_val}' blocked at perimeter and host firewall. Zero internal impact."

            cmd = (
                f"# Perimeter Firewall Egress Drop ({ip_val})\n"
                f"New-NetFirewallRule -DisplayName 'AIRA_Block_{ip_val}' -Direction Outbound -RemoteAddress '{ip_val}' -Action Block"
            )
            predicted_state = f"Outbound TCP/UDP traffic to {ip_val} dropped by Windows Filtering Platform (WFP)."
            rollback = f"Remove-NetFirewallRule -DisplayName 'AIRA_Block_{ip_val}' -ErrorAction SilentlyContinue"

        elif act_type == "DELETE_REGISTRY_KEY":
            is_run_key = "currentversion\\run" in target_lower or "services" in target_lower
            risk_level = "LOW"
            operational_impact = f"Adversary startup persistence key removed. Prevents malware survivability across reboots."
            
            # Format PowerShell registry command
            key_path = target
            hive = "HKCU" if "hkcu" in target_lower else "HKLM"
            clean_path = key_path.replace("HKCU\\", "HKCU:\\").replace("HKLM\\", "HKLM:\\")
            
            cmd = (
                f"# Registry Persistence Eradication\n"
                f"if (Test-Path '{clean_path}') {{\n"
                f"    Remove-Item -Path '{clean_path}' -Force -Recurse\n"
                f"}}"
            )
            predicted_state = f"Registry key '{target}' eradicated from hive {hive}."
            rollback = f"# To restore: re-create registry value under '{clean_path}' if legit item was flagged."

        elif act_type == "RESET_CREDENTIALS":
            risk_level = "MEDIUM"
            operational_impact = "Forces immediate user password rotation and revokes existing Kerberos TGT and active logon tokens."
            warnings.append("User will be logged out of active Outlook, OneDrive, and VPN sessions.")
            
            user_clean = target.split(" ")[0].replace("CORP\\", "")
            cmd = (
                f"# Active Directory Password & Kerberos Token Invalidation ({user_clean})\n"
                f"Set-ADUser -Identity '{user_clean}' -ChangePasswordAtLogon $true\n"
                f"# Revoke active Kerberos TGT tickets\n"
                f"klist purge -li 0x3e7"
            )
            predicted_state = f"Active session credentials revoked for {target}. Re-authentication required with MFA."
            rollback = "# User accounts can be re-enabled via Active Directory Administrative Center."

        elif act_type == "RESET_KRBTGT_KEY":
            risk_level = "CRITICAL_CAUTION"
            operational_impact = (
                "Double reset of the Active Directory KRBTGT domain account key. "
                "This invalidates all forged Kerberos Golden & Silver tickets domain-wide."
            )
            warnings.append("CRITICAL: Perform the two resets with a minimum 10-hour or replication-cycle interval.")
            warnings.append("Ensure all Domain Controllers have replicated the first reset before executing the second.")
            warnings.append("Service accounts and Kerberos tickets will require renewal.")

            cmd = (
                f"# Active Directory KRBTGT Key Double-Reset Procedure\n"
                f"# Step 1: Run Microsoft official New-KrbtgtKeys.ps1 or set password via AD Module\n"
                f"Set-ADAccountPassword -Identity 'krbtgt' -Reset\n"
                f"# Step 2: Force replication across all Domain Controllers\n"
                f"repadmin /syncall /AdeP\n"
                f"# Step 3: Wait replication cycle before executing second reset to avoid authentication outages."
            )
            predicted_state = "Domain KRBTGT key updated. Adversary golden ticket persistence invalidated."
            rollback = "# KRBTGT keys cannot be rolled back to prior compromised state for security reasons."

        else:
            risk_level = "LOW"
            operational_impact = f"Standard remediation for action {act_type}."
            cmd = f"# Execute remediation: {act_type} on {target}"
            predicted_state = f"Action {act_type} completed on {target}."
            rollback = f"# Manual rollback for {act_type}"

        return SimulationResult(
            action_type=act_type,
            target=target,
            risk_level=risk_level,
            operational_impact=operational_impact,
            simulated_command=cmd,
            predicted_host_state=predicted_state,
            rollback_command=rollback,
            safety_warnings=warnings,
            simulation_status="SUCCESS_PREVIEW"
        )

    def simulate_all(self, actions: List[RecommendedAction]) -> Dict[str, Any]:
        """
        Runs comprehensive pre-flight simulation across all prescribed actions.
        """
        results: List[SimulationResult] = []
        overall_risk = "LOW"
        high_risk_count = 0
        caution_count = 0

        for act in actions:
            sim = self.simulate_action(act, all_actions=actions)
            results.append(sim)
            if sim.risk_level == "CRITICAL_CAUTION":
                caution_count += 1
                overall_risk = "CRITICAL_CAUTION"
            elif sim.risk_level == "HIGH" and overall_risk != "CRITICAL_CAUTION":
                high_risk_count += 1
                overall_risk = "HIGH"
            elif sim.risk_level == "MEDIUM" and overall_risk == "LOW":
                overall_risk = "MEDIUM"

        return {
            "total_actions": len(actions),
            "overall_safety_level": overall_risk,
            "caution_flags": caution_count,
            "high_risk_flags": high_risk_count,
            "simulations": [r.model_dump() for r in results],
            "ready_for_containment": True
        }
