"""
AIRA Telemetry Normalizer
Converts raw Windows Event Logs / Sysmon events into CanonicalEvent objects.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from dateutil import parser as dt_parser
from aira.core.models import (
    CanonicalEvent,
    EventType,
    ProcessEntity,
    NetworkEntity,
    FileEntity,
    RegistryEntity,
)


class EventNormalizer:
    """
    Parses and normalizes heterogeneous telemetry into the canonical AIRA schema.
    Supports Sysmon Event IDs (1, 3, 7, 8, 11, 12, 13) and generic Windows logs.
    """

    @staticmethod
    def parse_timestamp(ts: Any) -> datetime:
        dt = None
        if isinstance(ts, datetime):
            dt = ts
        elif isinstance(ts, str):
            try:
                dt = dt_parser.parse(ts)
            except Exception:
                pass
        if dt is None:
            dt = datetime.utcnow()
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return dt

    def normalize_sysmon_event(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        try:
            event_id = int(raw.get("EventID") or raw.get("event_id") or 0)
            record_id = str(raw.get("RecordId") or raw.get("record_id") or raw.get("RecordNumber") or id(raw))
            timestamp = self.parse_timestamp(raw.get("UtcTime") or raw.get("timestamp") or raw.get("TimeCreated"))
            host = str(raw.get("Computer") or raw.get("host") or "WORKSTATION-01")
            user = str(raw.get("User") or raw.get("user") or "SYSTEM")

            event_type = EventType.GENERIC
            process_entity = None
            network_entity = None
            file_entity = None
            registry_entity = None

            # Sysmon Event ID 1: Process Creation
            if event_id == 1:
                event_type = EventType.PROCESS_CREATE
                pid = int(raw.get("ProcessId") or raw.get("pid") or 0)
                image = str(raw.get("Image") or raw.get("image") or "")
                cmd = str(raw.get("CommandLine") or raw.get("command_line") or "")
                parent_pid = int(raw.get("ParentProcessId") or raw.get("parent_pid") or 0)
                parent_image = str(raw.get("ParentImage") or raw.get("parent_image") or "")
                parent_cmd = str(raw.get("ParentCommandLine") or raw.get("parent_command_line") or "")
                guid = str(raw.get("ProcessGuid") or "")

                process_entity = ProcessEntity(
                    pid=pid,
                    image=image,
                    command_line=cmd,
                    parent_pid=parent_pid,
                    parent_image=parent_image,
                    parent_command_line=parent_cmd,
                    user=user,
                    guid=guid,
                    hashes={"sha256": str(raw.get("Hashes", ""))} if raw.get("Hashes") else {}
                )

            # Sysmon Event ID 3: Network Connection
            elif event_id == 3:
                event_type = EventType.NETWORK_CONNECT
                pid = int(raw.get("ProcessId") or raw.get("pid") or 0)
                image = str(raw.get("Image") or raw.get("image") or "")
                src_ip = str(raw.get("SourceIp") or "127.0.0.1")
                src_port = int(raw.get("SourcePort") or 0)
                dst_ip = str(raw.get("DestinationIp") or "0.0.0.0")
                dst_port = int(raw.get("DestinationPort") or 0)
                protocol = str(raw.get("Protocol") or "tcp").lower()

                process_entity = ProcessEntity(
                    pid=pid,
                    image=image,
                    user=user
                )
                network_entity = NetworkEntity(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol
                )

            # Sysmon Event ID 11: File Creation
            elif event_id == 11:
                event_type = EventType.FILE_CREATE
                pid = int(raw.get("ProcessId") or raw.get("pid") or 0)
                image = str(raw.get("Image") or raw.get("image") or "")
                target_filename = str(raw.get("TargetFilename") or raw.get("path") or "")

                process_entity = ProcessEntity(pid=pid, image=image, user=user)
                file_entity = FileEntity(
                    path=target_filename,
                    hashes={"sha256": str(raw.get("Hashes", ""))} if raw.get("Hashes") else {},
                    action="created"
                )

            # Sysmon Event ID 12 / 13: Registry Event
            elif event_id in (12, 13):
                event_type = EventType.REGISTRY_SET
                pid = int(raw.get("ProcessId") or raw.get("pid") or 0)
                image = str(raw.get("Image") or raw.get("image") or "")
                target_object = str(raw.get("TargetObject") or raw.get("key_path") or "")
                details = str(raw.get("Details") or raw.get("value_data") or "")

                process_entity = ProcessEntity(pid=pid, image=image, user=user)
                registry_entity = RegistryEntity(
                    key_path=target_object,
                    value_data=details
                )

            # Sysmon Event ID 10: Process Access (e.g. LSASS injection / credential dumping)
            elif event_id == 10:
                event_type = EventType.PROCESS_ACCESS
                src_pid = int(raw.get("SourceProcessId") or 0)
                src_img = str(raw.get("SourceImage") or "")
                target_pid = int(raw.get("TargetProcessId") or 0)
                target_img = str(raw.get("TargetImage") or "")
                granted_access = str(raw.get("GrantedAccess") or "")

                process_entity = ProcessEntity(
                    pid=src_pid,
                    image=src_img,
                    user=user,
                    command_line=f"Target: {target_img} (PID {target_pid}), Access: {granted_access}"
                )

            return CanonicalEvent(
                record_id=record_id,
                timestamp=timestamp,
                host=host,
                user=user,
                source_channel="Microsoft-Windows-Sysmon/Operational",
                event_id=event_id,
                event_type=event_type,
                process=process_entity,
                network=network_entity,
                file=file_entity,
                registry=registry_entity,
                raw_payload=raw
            )

        except Exception as err:
            print(f"[Normalizer Warning] Failed to parse event: {err}")
            return None

    def normalize_event(self, raw: Dict[str, Any]) -> Optional[CanonicalEvent]:
        """
        Normalizes a single event dict into a CanonicalEvent.
        Supports both raw Sysmon logs and pre-structured ECS dicts.
        """
        if isinstance(raw, CanonicalEvent):
            return raw

        if isinstance(raw, dict) and "event_type" in raw:
            try:
                ts = self.parse_timestamp(raw.get("timestamp"))
                ev_type_val = raw.get("event_type")
                if isinstance(ev_type_val, str):
                    ev_type = EventType(ev_type_val.upper())
                else:
                    ev_type = ev_type_val

                # Map EventType to default event_id if not present
                event_id_val = raw.get("event_id") or raw.get("EventID")
                if event_id_val is None:
                    if ev_type == EventType.PROCESS_CREATE:
                        event_id_val = 1
                    elif ev_type == EventType.NETWORK_CONNECT:
                        event_id_val = 3
                    elif ev_type == EventType.PROCESS_TERMINATE:
                        event_id_val = 5
                    elif ev_type == EventType.IMAGE_LOAD:
                        event_id_val = 7
                    elif ev_type == EventType.FILE_CREATE:
                        event_id_val = 11
                    elif ev_type == EventType.REGISTRY_SET:
                        event_id_val = 13
                    else:
                        event_id_val = 99
                
                proc = None
                if raw.get("process"):
                    p_data = {k: v for k, v in raw["process"].items() if k in ProcessEntity.model_fields}
                    if "image" not in p_data or not p_data["image"]:
                        p_data["image"] = str(raw["process"].get("name") or raw["process"].get("process_name") or "unknown.exe")
                    if "pid" not in p_data:
                        p_data["pid"] = int(raw["process"].get("pid") or 0)
                    proc = ProcessEntity(**p_data)

                net = None
                if raw.get("network"):
                    n_data = {k: v for k, v in raw["network"].items() if k in NetworkEntity.model_fields}
                    if "src_ip" not in n_data: n_data["src_ip"] = str(raw["network"].get("source_ip") or "127.0.0.1")
                    if "dst_ip" not in n_data: n_data["dst_ip"] = str(raw["network"].get("destination_ip") or "127.0.0.1")
                    if "src_port" not in n_data: n_data["src_port"] = int(raw["network"].get("source_port") or 0)
                    if "dst_port" not in n_data: n_data["dst_port"] = int(raw["network"].get("destination_port") or 0)
                    net = NetworkEntity(**n_data)

                f_ent = None
                if raw.get("file"):
                    f_data = {k: v for k, v in raw["file"].items() if k in FileEntity.model_fields}
                    if "path" not in f_data: f_data["path"] = str(raw["file"].get("file_path") or raw["file"].get("name") or "unknown")
                    f_ent = FileEntity(**f_data)

                r_ent = None
                if raw.get("registry"):
                    r_data = {k: v for k, v in raw["registry"].items() if k in RegistryEntity.model_fields}
                    if "key_path" not in r_data: r_data["key_path"] = str(raw["registry"].get("path") or "UNKNOWN_REG_KEY")
                    r_ent = RegistryEntity(**r_data)

                return CanonicalEvent(
                    record_id=str(raw.get("record_id") or id(raw)),
                    timestamp=ts,
                    host=str(raw.get("host") or "WORKSTATION-01"),
                    user=str(raw.get("user") or "SYSTEM"),
                    source_channel=str(raw.get("source_channel") or "LiveTelemetry"),
                    event_id=int(event_id_val),
                    event_type=ev_type,
                    process=proc,
                    network=net,
                    file=f_ent,
                    registry=r_ent,
                    raw_payload=raw
                )
            except Exception as e:
                pass

        return self.normalize_sysmon_event(raw)

    def normalize_batch(self, raw_events: List[Dict[str, Any]]) -> List[CanonicalEvent]:
        normalized = []
        for raw in raw_events:
            event = self.normalize_event(raw)
            if event:
                normalized.append(event)
        # Ensure chronological ordering
        normalized.sort(key=lambda x: x.timestamp)
        return normalized

