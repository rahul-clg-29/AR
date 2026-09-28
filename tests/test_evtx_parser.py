"""
Unit & Integration Tests for Native Windows Event Log (.evtx) XML & Record Parsing
"""

from aira.core.evtx_parser import EVTXParser
from aira.core.normalizer import EventNormalizer
from aira.core.models import EventType

SAMPLE_SYSMON_E1_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-26T10:15:18.420000Z"/>
    <EventRecordID>98142</EventRecordID>
    <Execution ProcessID="2420" ThreadID="3100"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>CORP-WKS-042</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-09-26 10:15:18.420</Data>
    <Data Name="ProcessGuid">{B8A048C8-0000-0000-0000-000000000000}</Data>
    <Data Name="ProcessId">5104</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=</Data>
    <Data Name="CurrentDirectory">C:\\Users\\JohnDoe\\</Data>
    <Data Name="User">CORP\\JohnDoe</Data>
    <Data Name="ParentProcessId">3120</Data>
    <Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>
    <Data Name="ParentCommandLine">&quot;C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE&quot;</Data>
  </EventData>
</Event>"""

SAMPLE_SYSMON_E3_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
    <EventID>3</EventID>
    <TimeCreated SystemTime="2026-09-26T10:15:20.110000Z"/>
    <EventRecordID>98143</EventRecordID>
    <Computer>CORP-WKS-042</Computer>
  </System>
  <EventData>
    <Data Name="ProcessId">5104</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="User">CORP\\JohnDoe</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="SourceIp">10.0.1.42</Data>
    <Data Name="SourcePort">49812</Data>
    <Data Name="DestinationIp">198.51.100.45</Data>
    <Data Name="DestinationPort">443</Data>
  </EventData>
</Event>"""


def test_evtx_xml_record_parser():
    parser = EVTXParser()
    record = parser.parse_record_xml(SAMPLE_SYSMON_E1_XML)

    assert record is not None
    assert record["EventID"] == 1
    assert record["RecordId"] == "98142"
    assert record["Computer"] == "CORP-WKS-042"
    assert record["ProcessId"] == "5104"
    assert "powershell.exe" in record["Image"]
    assert "WINWORD.EXE" in record["ParentImage"]


def test_evtx_to_canonical_normalizer():
    parser = EVTXParser()
    normalizer = EventNormalizer()

    # Parse and normalize Process Create
    raw_proc = parser.parse_record_xml(SAMPLE_SYSMON_E1_XML)
    canon_proc = normalizer.normalize_sysmon_event(raw_proc)

    assert canon_proc is not None
    assert canon_proc.event_type == EventType.PROCESS_CREATE
    assert canon_proc.process.pid == 5104
    assert canon_proc.process.parent_pid == 3120

    # Parse and normalize Network Connect
    raw_net = parser.parse_record_xml(SAMPLE_SYSMON_E3_XML)
    canon_net = normalizer.normalize_sysmon_event(raw_net)

    assert canon_net is not None
    assert canon_net.event_type == EventType.NETWORK_CONNECT
    assert canon_net.network.dst_ip == "198.51.100.45"
    assert canon_net.network.dst_port == 443
