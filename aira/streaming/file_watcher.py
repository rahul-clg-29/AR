"""
AIRA Zero-ETL Directory Watcher Daemon
Monitors an incoming drop-zone folder (aira/data/live_stream/) for real-time telemetry drops.
Automatically ingests, normalizes, and updates the live attack graph without manual intervention.
"""

import os
import json
import time
import logging
import asyncio
from pathlib import Path
from typing import Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent

from aira.streaming.stream_manager import LiveStreamManager

logger = logging.getLogger("aira.file_watcher")


class TelemetryFileDropHandler(FileSystemEventHandler):
    """
    Handles filesystem events when a new telemetry file is dropped into the watch folder.
    """

    def __init__(self, stream_manager: LiveStreamManager, loop: asyncio.AbstractEventLoop):
        super().__init__()
        self.stream_manager = stream_manager
        self.loop = loop
        self.processed_files = set()

    def on_created(self, event):
        if event.is_directory:
            return
        self._process_file(event.src_path)

    def _process_file(self, file_path: str):
        path = Path(file_path)
        if path.name.startswith(".") or path.suffix.lower() not in [".json", ".ndjson", ".evtx"]:
            return

        # Debounce duplicate filesystem events
        if str(path) in self.processed_files:
            return
        self.processed_files.add(str(path))

        # Give small delay for file write to complete
        time.sleep(0.3)

        try:
            logger.info(f"[Zero-ETL Watcher] New telemetry drop detected: {path.name}")
            events = []

            if path.suffix.lower() == ".json":
                with open(path, "r", encoding="utf-8") as f:
                    content = json.load(f)
                    if isinstance(content, list):
                        events = content
                    elif isinstance(content, dict):
                        events = [content]
            elif path.suffix.lower() == ".ndjson":
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            events.append(json.loads(line.strip()))

            if events:
                logger.info(f"[Zero-ETL Watcher] Ingesting {len(events)} real-time events from {path.name}")
                for ev in events:
                    # Thread-safe dispatch to asyncio event loop
                    asyncio.run_coroutine_threadsafe(
                        self.stream_manager.ingest_and_broadcast(ev),
                        self.loop
                    )
        except Exception as e:
            logger.error(f"[Zero-ETL Watcher] Failed to process {path.name}: {e}", exc_info=True)


class ZeroETLFileWatcher:
    """
    Manages the background filesystem observer thread.
    """

    def __init__(self, watch_dir: str, stream_manager: LiveStreamManager):
        self.watch_dir = Path(watch_dir)
        self.stream_manager = stream_manager
        self.observer: Optional[Observer] = None
        self.is_running = False

    def start(self, loop: Optional[asyncio.AbstractEventLoop] = None):
        """
        Starts the watchdog observer in a dedicated background thread.
        """
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        active_loop = loop or asyncio.get_event_loop()

        handler = TelemetryFileDropHandler(self.stream_manager, active_loop)
        self.observer = Observer()
        self.observer.schedule(handler, str(self.watch_dir), recursive=False)
        self.observer.daemon = True
        self.observer.start()
        self.is_running = True
        logger.info(f"Zero-ETL Watcher active on directory: {self.watch_dir.resolve()}")

    def stop(self):
        """
        Stops the observer thread.
        """
        if self.observer and self.is_running:
            self.observer.stop()
            self.observer.join(timeout=2.0)
            self.is_running = False
            logger.info("Zero-ETL Watcher stopped.")
