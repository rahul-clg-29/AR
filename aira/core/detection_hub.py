"""
AIRA Multi-Format Detection Engineering Hub
Converts reconstructed causal attack paths and MITRE techniques into deployable,
production-ready detection rules across 5 major industry SIEM & EDR formats:
1. Sigma Rules (Vendor-agnostic YAML)
2. YARA Forensics Rules (Memory & Disk scanning)
3. Splunk SPL (Search Processing Language)
4. Elasticsearch KQL & EQL (Event Query Language sequences)
5. Microsoft Sentinel KQL (Kusto Query Language for Azure Defender)
"""

import io
import zipfile
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class DetectionEngineeringHub:
    """
    Transforms active incident artifacts into multi-format detection rules.
    """

    def __init__(self, incident_data: Optional[Dict[str, Any]] = None, graph_builder: Optional[Any] = None):
        self.incident_data = incident_data or {}
        self.graph_builder = graph_builder

    def update_context(self, incident_data: Dict[str, Any], graph_builder: Optional[Any] = None):
        self.incident_data = incident_data
        if graph_builder is not None:
            self.graph_builder = graph_builder

    def _extract_indicators(self) -> Dict[str, Any]:
        """
        Extracts key forensic indicators from timeline, hypotheses, and graph nodes.
        """
        data = self.incident_data
        timeline = data.get("timeline", [])
        hypotheses = data.get("hypotheses", [])
        hyp = hypotheses[0] if hypotheses else {}
        techs = hyp.get("mitre_techniques", [])

        parent_procs = set()
        child_procs = set()
        c2_ips = set()
        reg_keys = set()
        file_paths = set()
        mitre_ids = [t.get("id") for t in techs if t.get("id")]

        # Extract from timeline
        for ev in timeline:
            actor = ev.get("actor", "")
            action = ev.get("action", "")
            target = ev.get("target", "")

            if ".exe" in actor.lower():
                parent_procs.add(actor)
            if ".exe" in target.lower():
                child_procs.add(target.split("\\")[-1])

            if "net:" in target:
                clean_ip = target.replace("net:", "").split(":")[0]
                c2_ips.add(clean_ip)
            elif ":" in target and any(c.isdigit() for c in target.split(":")[0]):
                ip_cand = target.split(":")[0]
                if not (ip_cand.startswith("10.") or ip_cand.startswith("192.168.") or ip_cand.startswith("127.")):
                    c2_ips.add(ip_cand)

            if any(k in target.lower() for k in ["hklm", "hkcu", "currentversion"]):
                reg_keys.add(target)

            if any(ext in target.lower() for ext in [".exe", ".dll", ".ps1", ".vbs", ".bat", ".dit", ".docx"]):
                if "\\" in target or "/" in target:
                    file_paths.add(target)

        # Graph node extraction fallback/supplement
        if self.graph_builder and hasattr(self.graph_builder, "graph"):
            for n, ndata in self.graph_builder.graph.nodes(data=True):
                ntype = ndata.get("node_type", "")
                if ntype == "process":
                    img = ndata.get("image", "")
                    if img:
                        child_procs.add(img.split("\\")[-1])
                elif ntype == "network":
                    dst = ndata.get("dst_ip", "")
                    if dst and not (dst.startswith("10.") or dst.startswith("192.168.") or dst.startswith("127.")):
                        c2_ips.add(dst)
                elif ntype == "registry":
                    kp = ndata.get("key_path", "")
                    if kp:
                        reg_keys.add(kp)

        # Defaults if empty
        if not parent_procs:
            parent_procs.add("WINWORD.EXE")
        if not child_procs:
            child_procs.update(["powershell.exe", "cmd.exe", "update_agent.exe"])
        if not c2_ips:
            c2_ips.add("198.51.100.45")

        return {
            "incident_id": data.get("incident_id", "INC-001"),
            "title": data.get("title", hyp.get("title", "Adversary Attack Chain")),
            "severity": data.get("severity", "CRITICAL"),
            "hosts": data.get("affected_hosts", ["CORP-WKS-042"]),
            "parent_procs": sorted(list(parent_procs)),
            "child_procs": sorted(list(child_procs)),
            "c2_ips": sorted(list(c2_ips)),
            "reg_keys": sorted(list(reg_keys)),
            "file_paths": sorted(list(file_paths)),
            "mitre_ids": mitre_ids
        }

    def generate_sigma_rule(self) -> str:
        """
        Generates a valid Sigma (YAML) process creation detection rule.
        """
        i = self._extract_indicators()
        inc_id = i["incident_id"]
        today = datetime.now(timezone.utc).strftime("%Y/%m/%d")

        parent_list = "\n".join([f"            - '\\{p}'" for p in i["parent_procs"][:4]])
        child_list = "\n".join([f"            - '\\{c}'" for c in i["child_procs"][:5]])
        tags_list = "\n".join([f"    - attack.{m.lower().replace('.', '_')}" for m in i["mitre_ids"][:6]]) or "    - attack.execution"

        return f"""title: Causal Process Spawn Anomaly - {i['title']}
id: 7b31b26a-8b1e-4c3d-9d41-{abs(hash(inc_id)) % 1000000000000:012d}
status: production
description: |
    Detects abnormal process spawning patterns observed during incident {inc_id}.
    Identifies parent desktop/system processes spawning hidden scripting shells and unauthorized binaries.
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://attack.mitre.org/techniques/T1204/002/
author: AIRA Autonomous Detection Engineering Hub
date: {today}
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
{parent_list}
    selection_child:
        Image|endswith:
{child_list}
    selection_flags:
        CommandLine|contains:
            - '-w hidden'
            - '-enc'
            - 'DownloadString'
            - 'IEX'
            - 'Bypass'
    condition: (selection_parent and selection_child) or (selection_child and selection_flags)
fields:
    - ComputerName
    - User
    - ParentImage
    - Image
    - CommandLine
    - CurrentDirectory
falsepositives:
    - Verified IT deployment automation scripts with valid cryptographic signatures.
level: {i['severity'].lower()}
tags:
{tags_list}
"""

    def generate_yara_rule(self) -> str:
        """
        Generates a YARA forensic rule for disk and process memory scanning.
        """
        i = self._extract_indicators()
        clean_id = i["incident_id"].replace("-", "_")
        c2_ip = i["c2_ips"][0] if i["c2_ips"] else "198.51.100.45"
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        return f"""/*
    YARA Rule generated by AIRA Autonomous Detection Engineering Hub
    Incident Reference: {i['incident_id']}
    Severity: {i['severity']}
*/

rule AIRA_Attack_Artifacts_{clean_id}
{{
    meta:
        description = "Detects in-memory and on-disk payload artifacts related to {i['incident_id']}"
        author = "AIRA Cognitive SOC Platform"
        date = "{today}"
        reference = "AIRA Causal Provenance Incident {i['incident_id']}"
        threat_level = "{i['severity']}"
        mitre_technique = "T1059.001, T1003.001, T1547.001"

    strings:
        // Script download cradles & execution stagers
        $s1 = "DownloadString" ascii wide nocase
        $s2 = "Invoke-Expression" ascii wide nocase
        $s3 = "IEX(" ascii wide nocase
        $s4 = "-ExecutionPolicy Bypass" ascii wide nocase
        $s5 = "-WindowStyle Hidden" ascii wide nocase

        // Registry Run persistence strings
        $r1 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii wide nocase
        $r2 = "update_agent" ascii wide nocase

        // Command and Control network IOCs
        $net1 = "{c2_ip}" ascii wide

        // Credential dumping signatures
        $cred1 = "lsass.exe" ascii wide nocase
        $cred2 = "ntds.dit" ascii wide nocase
        $cred3 = "ntdsutil" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and // PE Binary
        (
            2 of ($s*) or
            (1 of ($s*) and $net1) or
            ($r1 and $r2) or
            1 of ($cred*)
        )
}}
"""

    def generate_splunk_spl(self) -> str:
        """
        Generates production Splunk Search Processing Language (SPL) query.
        """
        i = self._extract_indicators()
        parent_filter = " OR ".join([f'ParentImage="*{p}"' for p in i["parent_procs"][:3]])
        child_filter = " OR ".join([f'Image="*{c}"' for c in i["child_procs"][:4]])
        c2_filter = " OR ".join([f'DestinationIp="{ip}"' for ip in i["c2_ips"]])

        return f"""```
=============================================================================
AIRA Autonomous Splunk SPL Detection Query
Incident: {i['incident_id']} - {i['title']}
Description: Correlates suspicious parent-child process lineage with external C2 egress.
=============================================================================
```

(index=sysmon EventCode=1 ({parent_filter}) ({child_filter}))
OR
(index=sysmon EventCode=3 ({c2_filter}))
OR
(index=sysmon EventCode=13 TargetObject="*CurrentVersion\\\\Run*")
| eval Stage=case(
    EventCode==1, "Suspicious Execution Lineage",
    EventCode==3, "External C2 Beaconing",
    EventCode==13, "Startup Persistence Established",
    1==1, "Incident Artifact"
)
| stats 
    count,
    min(_time) as EarliestSeen,
    max(_time) as LatestSeen,
    values(CommandLine) as Commands,
    values(DestinationIp) as C2_Endpoints,
    values(TargetObject) as RegistryModifications
    by host, User, ParentImage, Image, Stage
| eval EarliestSeen=strftime(EarliestSeen, "%Y-%m-%d %H:%M:%S")
| eval LatestSeen=strftime(LatestSeen, "%Y-%m-%d %H:%M:%S")
| sort - count
"""

    def generate_elastic_eql(self) -> str:
        """
        Generates an Elasticsearch Event Query Language (EQL) sequence query.
        """
        i = self._extract_indicators()
        c2_ip = i["c2_ips"][0] if i["c2_ips"] else "198.51.100.45"

        return f"""/*
  AIRA Autonomous Detection Engineering: Elasticsearch EQL Sequence
  Incident: {i['incident_id']}
  Target: Multi-stage attack progression within 5-minute correlation window
*/

sequence by host.name with maxspan=5m
  [process where event.type == "start" and 
   process.parent.name in ("winword.exe", "excel.exe", "explorer.exe") and
   process.name in ("powershell.exe", "cmd.exe", "mshta.exe")]
  [network where event.type == "connection" and
   destination.ip == "{c2_ip}"]
  [process where event.type == "start" and
   process.name == "update_agent.exe"]
  [registry where event.type == "change" and
   registry.path : "*\\\\CurrentVersion\\\\Run\\\\*"]
"""

    def generate_sentinel_kql(self) -> str:
        """
        Generates a Microsoft Sentinel / Azure Log Analytics Kusto Query Language (KQL) query.
        """
        i = self._extract_indicators()
        c2_ip = i["c2_ips"][0] if i["c2_ips"] else "198.51.100.45"

        return f"""// =========================================================================
// AIRA Microsoft Sentinel KQL Detection Rule
// Incident ID: {i['incident_id']} - {i['title']}
// TTPs: Phishing Macro ➔ Script Cradle ➔ C2 Egress ➔ Registry Persistence
// =========================================================================

let TimeWindow = 6h;
let C2Addresses = dynamic(["{c2_ip}"]);

let ProcessEvents = DeviceProcessEvents
| where TimeGenerated >= ago(TimeWindow)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "explorer.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "update_agent.exe")
| project ProcessTime = TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName;

let NetworkEvents = DeviceNetworkEvents
| where TimeGenerated >= ago(TimeWindow)
| where RemoteIP in (C2Addresses)
| project NetworkTime = TimeGenerated, DeviceName, RemoteIP, RemotePort;

ProcessEvents
| join kind=inner (
    NetworkEvents
) on DeviceName
| where abs(datetime_diff('minute', NetworkTime, ProcessTime)) <= 15
| project ProcessTime, NetworkTime, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, RemoteIP, RemotePort
| order by ProcessTime desc
"""

    def generate_all_rules(self) -> Dict[str, Any]:
        """
        Generates all 5 rule formats and metadata in a structured dictionary.
        """
        i = self._extract_indicators()
        sigma = self.generate_sigma_rule()
        yara = self.generate_yara_rule()
        splunk = self.generate_splunk_spl()
        elastic = self.generate_elastic_eql()
        sentinel = self.generate_sentinel_kql()

        return {
            "incident_id": i["incident_id"],
            "title": i["title"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "indicators": i,
            "rules": {
                "sigma": {
                    "format_name": "Sigma Rule (Vendor-Agnostic)",
                    "extension": "yml",
                    "content": sigma,
                    "target_platform": "Any SIEM (Splunk, Elastic, Sentinel via pySigma)"
                },
                "yara": {
                    "format_name": "YARA Forensics Rule",
                    "extension": "yar",
                    "content": yara,
                    "target_platform": "Memory & Disk Forensics (Thor, Loki, Velociraptor)"
                },
                "splunk": {
                    "format_name": "Splunk SPL Query",
                    "extension": "spl",
                    "content": splunk,
                    "target_platform": "Splunk Enterprise & Splunk Cloud"
                },
                "elastic": {
                    "format_name": "Elasticsearch EQL Sequence",
                    "extension": "eql",
                    "content": elastic,
                    "target_platform": "Elastic SIEM / Security App"
                },
                "sentinel": {
                    "format_name": "Microsoft Sentinel KQL",
                    "extension": "kql",
                    "content": sentinel,
                    "target_platform": "Azure Sentinel & Microsoft Defender XDR"
                }
            }
        }

    def generate_rules_zip(self) -> bytes:
        """
        Bundles all 5 detection rules and a deployment guide into an in-memory ZIP archive.
        """
        all_rules = self.generate_all_rules()
        inc_id = all_rules["incident_id"]

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # 1. Sigma
            zf.writestr(f"sigma/sigma_incident_{inc_id}.yml", all_rules["rules"]["sigma"]["content"])
            # 2. YARA
            zf.writestr(f"yara/yara_incident_{inc_id}.yar", all_rules["rules"]["yara"]["content"])
            # 3. Splunk
            zf.writestr(f"splunk/splunk_incident_{inc_id}.spl", all_rules["rules"]["splunk"]["content"])
            # 4. Elastic
            zf.writestr(f"elastic/elastic_incident_{inc_id}.eql", all_rules["rules"]["elastic"]["content"])
            # 5. Sentinel
            zf.writestr(f"sentinel/sentinel_incident_{inc_id}.kql", all_rules["rules"]["sentinel"]["content"])

            # 6. Readme
            readme = f"""# AIRA Multi-Format Detection Engineering Package
**Incident ID**: {inc_id}  
**Generated At**: {all_rules['generated_at']}  
**Platform**: Autonomous Incident Reasoning Agent (AIRA)

## Included Detection Rules
1. `sigma/sigma_incident_{inc_id}.yml`: Vendor-neutral process creation and hidden flags rule.
2. `yara/yara_incident_{inc_id}.yar`: Forensic binary and memory string matching rule.
3. `splunk/splunk_incident_{inc_id}.spl`: Production search processing query correlating parent-child and C2 egress.
4. `elastic/elastic_incident_{inc_id}.eql`: 4-stage behavioral sequence query for Elastic Security.
5. `sentinel/sentinel_incident_{inc_id}.kql`: Kusto query linking process creation and network events for Microsoft Sentinel.

## Deployment Instructions
* **Splunk**: Navigate to Search & Reporting, paste the query from `.spl`, and click *Save As > Alert*.
* **Elastic**: Go to Security > Rules > Create New Rule > Threshold / Sequence > Paste `.eql`.
* **Sentinel**: Go to Microsoft Sentinel > Analytics > Create > Scheduled query rule > Paste `.kql`.
* **Sigma**: Convert using `sigmac` or `pySigma` for any custom vendor target.
* **YARA**: Run `yara64 -r yara_incident_{inc_id}.yar C:\\Windows\\Temp\\` or deploy via Velociraptor hunt.
"""
            zf.writestr("README_DETECTION_DEPLOYMENT.md", readme)

        buf.seek(0)
        return buf.getvalue()
