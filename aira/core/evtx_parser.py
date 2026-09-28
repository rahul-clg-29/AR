"""
AIRA Native Windows Event Log (.evtx) Binary Parser
Parses Windows Event Log files (.evtx) into structured dictionaries for canonical normalization.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional
import Evtx.Evtx as evtx


class EVTXParser:
    """
    Parses native binary Windows .evtx event logs into raw telemetry dictionaries.
    Strips XML namespaces and extracts standard System and EventData fields.
    """

    @staticmethod
    def _strip_tag(tag: str) -> str:
        """Removes XML namespace prefix if present."""
        if "}" in tag:
            return tag.split("}", 1)[1]
        return tag

    def parse_record_xml(self, xml_str: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single EVTX XML record into a dictionary.
        """
        try:
            root = ET.fromstring(xml_str)
            record: Dict[str, Any] = {}

            # Process <System> node
            system_elem = None
            event_data_elem = None

            for child in root:
                tag = self._strip_tag(child.tag)
                if tag == "System":
                    system_elem = child
                elif tag in ("EventData", "UserData"):
                    event_data_elem = child

            if system_elem is not None:
                for elem in system_elem:
                    t = self._strip_tag(elem.tag)
                    if t == "EventID":
                        try:
                            record["EventID"] = int(elem.text or "0")
                        except ValueError:
                            record["EventID"] = 0
                    elif t == "EventRecordID":
                        record["RecordId"] = elem.text or ""
                    elif t == "TimeCreated":
                        record["UtcTime"] = elem.attrib.get("SystemTime", "")
                    elif t == "Computer":
                        record["Computer"] = elem.text or ""
                    elif t == "Channel":
                        record["Channel"] = elem.text or ""

            # Process <EventData> node
            if event_data_elem is not None:
                for elem in event_data_elem:
                    # Sysmon uses <Data Name="ProcessId">value</Data>
                    name = elem.attrib.get("Name")
                    if name:
                        record[name] = elem.text or ""
                    else:
                        # Security events sometimes use unnamed <Data>value</Data>
                        t = self._strip_tag(elem.tag)
                        if elem.text:
                            record[t] = elem.text

            return record if record else None

        except Exception as err:
            return None

    def parse_evtx_file(self, file_path: str, max_events: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Reads a binary .evtx file and returns a list of parsed event dictionaries.
        """
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"EVTX file not found: {file_path}")

        records: List[Dict[str, Any]] = []
        with evtx.Evtx(str(p)) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    parsed = self.parse_record_xml(xml_str)
                    if parsed:
                        records.append(parsed)
                        if max_events and len(records) >= max_events:
                            break
                except Exception:
                    continue

        return records
