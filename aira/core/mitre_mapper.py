"""
AIRA MITRE ATT&CK Knowledge Engine & Heuristic Mapper
Maps observed endpoint and network behaviors to standardized MITRE ATT&CK techniques.
"""

import re
from typing import List, Optional
from aira.core.models import CanonicalEvent, EventType, MitreTechnique


class MitreMapper:
    """
    Evaluates individual events and process execution patterns against
    MITRE ATT&CK Enterprise tactics and techniques.
    """

    KNOWN_TECHNIQUES = {
        "T1204.002": {
            "name": "User Execution: Malicious File",
            "tactic": "Execution",
            "description": "An adversary relies on the user executing an Office or archive file which initiates an execution chain."
        },
        "T1059.001": {
            "name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "description": "Adversaries abuse PowerShell commands and scripts for code execution and download cradles."
        },
        "T1059.003": {
            "name": "Command and Scripting Interpreter: Windows Command Shell",
            "tactic": "Execution",
            "description": "Adversaries abuse cmd.exe to execute commands or batch files."
        },
        "T1059.005": {
            "name": "Command and Scripting Interpreter: Visual Basic",
            "tactic": "Execution",
            "description": "Adversaries abuse Visual Basic script interpreters (cscript.exe, wscript.exe) to execute malicious scripts."
        },
        "T1082": {
            "name": "System Information Discovery",
            "tactic": "Discovery",
            "description": "Adversaries attempt to get detailed information about the operating system and environment (whoami, ipconfig, systeminfo)."
        },
        "T1071.001": {
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "description": "Adversaries communicate using application layer protocols (HTTP/HTTPS) to avoid detection."
        },
        "T1547.001": {
            "name": "Boot or Logon Autostart Execution: Registry Run Keys",
            "tactic": "Persistence",
            "description": "Adversaries modify Windows Registry Run keys to achieve persistence across reboots."
        },
        "T1003.001": {
            "name": "OS Credential Dumping: LSASS Memory",
            "tactic": "Credential Access",
            "description": "Adversaries attempt to access or dump the memory of the Local Security Authority Subsystem Service (LSASS)."
        },
        "T1003.003": {
            "name": "OS Credential Dumping: NTDS",
            "tactic": "Credential Access",
            "description": "Adversaries attempt to access or create a copy of the Active Directory domain database (ntds.dit) using tools like ntdsutil."
        },
        "T1543.003": {
            "name": "Create or Modify System Process: Windows Service",
            "tactic": "Persistence",
            "description": "Adversaries create or modify Windows services to execute binaries persistently across reboots."
        },
        "T1021.002": {
            "name": "Remote Services: SMB/Windows Admin Shares",
            "tactic": "Lateral Movement",
            "description": "Adversaries leverage SMB to access admin shares and move laterally within the network."
        },
        "T1070.001": {
            "name": "Indicator Removal: Clear Windows Event Logs",
            "tactic": "Defense Evasion",
            "description": "Adversaries clear event logs to hide their tracks (e.g. wevtutil cl)."
        },
        "T1105": {
            "name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "description": "Adversaries transfer tools or other files from an external system into a compromised network (e.g. certutil, bitsadmin)."
        },
        "T1218.011": {
            "name": "System Binary Proxy Execution: Rundll32",
            "tactic": "Defense Evasion",
            "description": "Adversaries abuse rundll32.exe to proxy execution of malicious code and bypass application allowlisting."
        },
        "T1069.002": {
            "name": "Permission Groups Discovery: Domain Groups",
            "tactic": "Discovery",
            "description": "Adversaries attempt to find domain-level groups and permission settings (e.g. net group 'Domain Admins')."
        },
        "T1047": {
            "name": "Windows Management Instrumentation",
            "tactic": "Execution",
            "description": "Adversaries abuse WMI to execute malicious commands and move laterally between hosts."
        },
        "T1560": {
            "name": "Archive Collected Data",
            "tactic": "Collection",
            "description": "Adversaries compress or encrypt sensitive data prior to exfiltration (e.g. 7z, rar, zip)."
        },
        "T1218.005": {
            "name": "System Binary Proxy Execution: Mshta",
            "tactic": "Defense Evasion",
            "description": "Adversaries abuse mshta.exe to proxy execution of malicious .hta scripts and bypass application controls."
        }
    }

    def map_event(self, event: CanonicalEvent) -> List[MitreTechnique]:
        """
        Analyze a single event and return detected MITRE ATT&CK techniques.
        """
        matches: List[MitreTechnique] = []

        if event.event_type == EventType.PROCESS_CREATE and event.process:
            cmd = (event.process.command_line or "").lower()
            img = (event.process.image or "").lower()
            p_img = (event.process.parent_image or "").lower()

            # T1204.002: Office launching shell
            if any(office_app in p_img for office_app in ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]):
                if any(shell in img for shell in ["cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe", "mshta.exe"]):
                    matches.append(self._create_technique("T1204.002", confidence=0.95))

            # T1059.001: PowerShell suspicious usage
            if "powershell.exe" in img or "pwsh.exe" in img:
                conf = 0.6
                if any(x in cmd for x in ["-enc", "-encodedcommand", "downloadstring", "invoke-expression", "iex", "bypass"]):
                    conf = 0.95
                matches.append(self._create_technique("T1059.001", confidence=conf))

            # T1059.003: cmd.exe
            elif "cmd.exe" in img:
                matches.append(self._create_technique("T1059.003", confidence=0.5))

            # T1059.005: Visual Basic Scripting (wscript/cscript)
            elif any(s in img for s in ["wscript.exe", "cscript.exe"]):
                matches.append(self._create_technique("T1059.005", confidence=0.90))
                if "powershell" in cmd or "iex" in cmd:
                    matches.append(self._create_technique("T1059.001", confidence=0.95))

            # T1082 & T1069.002: Discovery commands
            if "net" in img and any(x in cmd for x in ["group", "user", "localgroup"]) and "domain" in cmd:
                matches.append(self._create_technique("T1069.002", confidence=0.90))
            elif any(disco in img for disco in ["whoami.exe", "ipconfig.exe", "systeminfo.exe", "net.exe"]):
                matches.append(self._create_technique("T1082", confidence=0.85))

            # T1105: Ingress Tool Transfer (certutil / bitsadmin)
            if "certutil" in img and any(x in cmd for x in ["-urlcache", "-split", "http://", "https://"]):
                matches.append(self._create_technique("T1105", confidence=0.95))

            # T1218.011: Rundll32 proxy execution
            if "rundll32.exe" in img and any(x in cmd for x in [".dll", "start", "entry"]):
                matches.append(self._create_technique("T1218.011", confidence=0.88))

            # T1218.005: Mshta proxy execution
            if "mshta.exe" in img and any(x in cmd for x in [".hta", "http://", "https://", "vbscript", "javascript"]):
                matches.append(self._create_technique("T1218.005", confidence=0.92))

            # T1047: WMI lateral execution
            if ("wmic" in img and "process call create" in cmd) or ("wmiprvse.exe" in p_img and any(sh in img for sh in ["cmd.exe", "powershell.exe"])):
                matches.append(self._create_technique("T1047", confidence=0.94))

            # T1003.003: NTDS Active Directory credential dumping
            if "ntdsutil" in cmd or "ntds.dit" in cmd:
                matches.append(self._create_technique("T1003.003", confidence=0.96))

            # T1560: Archive Collected Data
            if any(arch in img for arch in ["7z.exe", "winrar.exe", "rar.exe"]) and any(x in cmd for x in [" a ", " -p"]):
                matches.append(self._create_technique("T1560", confidence=0.85))

            # T1070.001: Log clearing
            if "wevtutil" in img and any(x in cmd for x in ["cl", "clear-log"]):
                matches.append(self._create_technique("T1070.001", confidence=0.99))

        elif event.event_type == EventType.FILE_CREATE and event.file:
            path_lower = event.file.path.lower()
            if "ntds.dit" in path_lower:
                matches.append(self._create_technique("T1003.003", confidence=0.96))

        elif event.event_type == EventType.NETWORK_CONNECT and event.network:
            dst_ip = event.network.dst_ip
            dst_port = event.network.dst_port
            proc_img = (event.process.image.lower() if event.process and event.process.image else "")
            is_benign_app = any(b in proc_img for b in ["chrome.exe", "msedge.exe", "firefox.exe", "spotify.exe", "onedrive.exe", "teams.exe", "slack.exe"])
            is_lolbas_script = any(s in proc_img for s in ["powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "certutil.exe", "cscript.exe", "wscript.exe", "cmd.exe"])

            # C2 outbound communication (T1071.001) from LOLBAS/scripting processes or suspicious external hosts
            if is_lolbas_script and dst_port in [80, 443, 4443, 4444, 8080, 8443, 9001]:
                matches.append(self._create_technique("T1071.001", confidence=0.92))
            elif not is_benign_app and not (dst_ip.startswith("10.") or dst_ip.startswith("192.168.") or dst_ip.startswith("127.") or dst_ip.startswith("172.16.")):
                if dst_port in [80, 443, 8080, 8443]:
                    matches.append(self._create_technique("T1071.001", confidence=0.85))

            # T1021.002: SMB port 445 lateral traffic
            if dst_port == 445:
                matches.append(self._create_technique("T1021.002", confidence=0.80))

        elif event.event_type == EventType.REGISTRY_SET and event.registry:
            key = event.registry.key_path.lower()
            if "currentversion\\run" in key or "runonce" in key:
                matches.append(self._create_technique("T1547.001", confidence=0.92))
            elif "\\services\\" in key:
                matches.append(self._create_technique("T1543.003", confidence=0.92))

        elif event.event_type == EventType.PROCESS_ACCESS and event.process:
            cmd = (event.process.command_line or "").lower()
            if "lsass.exe" in cmd:
                matches.append(self._create_technique("T1003.001", confidence=0.95))

        return matches

    def _create_technique(self, tech_id: str, confidence: float) -> MitreTechnique:
        info = self.KNOWN_TECHNIQUES.get(tech_id, {
            "name": "Unknown Technique",
            "tactic": "Unknown",
            "description": "Unclassified security event technique."
        })
        return MitreTechnique(
            id=tech_id,
            name=info["name"],
            tactic=info["tactic"],
            description=info["description"],
            confidence=confidence
        )
