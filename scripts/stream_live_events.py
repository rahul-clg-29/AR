#!/usr/bin/env python3
"""
AIRA Real-Time Telemetry Stream Generator
=========================================
Demonstrates real-time telemetry streaming into the AIRA SOC Analyst Workbench.
Can push live events directly via REST API or drop them into the Zero-ETL directory.

Usage:
    python scripts/stream_live_events.py                     # Streams sample attack chain via REST
    python scripts/stream_live_events.py --speed 0.5         # Streams fast (0.5s interval)
    python scripts/stream_live_events.py --preset multihost  # Streams multi-host lateral movement
    python scripts/stream_live_events.py --mode drop-file    # Demonstrates Zero-ETL File Watcher
"""

import sys
import time
import json
import argparse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = BASE_DIR / "aira" / "data" / "samples"
WATCH_DIR = BASE_DIR / "aira" / "data" / "live_stream"
API_URL = "http://127.0.0.1:8000/api/stream/ingest"
RESET_URL = "http://127.0.0.1:8000/api/stream/reset"


def load_events(preset: str):
    if preset == "multihost":
        target = SAMPLES_DIR / "enterprise_multihost_attack.json"
    elif preset == "apt29":
        target = SAMPLES_DIR / "mordor_apt29_execution_subset.json"
    else:
        target = SAMPLES_DIR / "sample_attack_chain.json"

    with open(target, "r", encoding="utf-8") as f:
        events = json.load(f)
    return events, target.name


def send_rest_event(event_dict):
    """Pushes a single telemetry event via REST API."""
    # Stamp with current real-time UTC timestamp
    event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()

    payload = json.dumps({"event": event_dict}).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data
    except urllib.error.URLError as e:
        print(f"\n[!] Connection error connecting to AIRA at {API_URL}: {e}")
        print("    Ensure the web server is running ('python run_ui.py')")
        sys.exit(1)


def stream_rest(events, preset_name, speed):
    print("=" * 72)
    print(f"  AIRA LIVE TELEMETRY STREAMER (REST API Mode)")
    print(f"  Target: {API_URL}")
    print(f"  Dataset: {preset_name} ({len(events)} events)")
    print(f"  Interval: {speed}s per event")
    print("=" * 72)
    print(">> Open your browser at http://127.0.0.1:8000 to watch the live graph!")
    print("-" * 72)

    for i, ev in enumerate(events, 1):
        ev_type = ev.get("event_type") or f"EventID-{ev.get('EventID', 1)}"
        host = ev.get("host") or ev.get("Computer") or "CORP-WKS-042"
        proc = ""
        if "process" in ev and isinstance(ev["process"], dict):
            proc = ev["process"].get("image") or ev["process"].get("name") or ""
        elif "Image" in ev:
            proc = ev["Image"]
        proc_short = proc.split("\\")[-1] if proc else "-"

        res = send_rest_event(ev)
        update = res["updates"][0] if res.get("updates") else {}
        nodes = update.get("total_nodes", "?")
        post = update.get("bayesian_posterior", 0.0)
        verdict = update.get("bayesian_verdict", "ANALYZING")

        print(
            f"[+] Event {i:02d}/{len(events):02d} | "
            f"{ev_type:<16} | "
            f"Host: {host:<12} | "
            f"Proc: {proc_short:<14} | "
            f"Graph Nodes: {nodes:<2} | "
            f"P(Bayes): {post*100:>5.1f}% [{verdict}]"
        )
        time.sleep(speed)

    print("-" * 72)
    print("[*] Stream complete! All events successfully ingested into causal graph.")
    print("=" * 72)


def stream_file_drop(events, preset_name):
    print("=" * 72)
    print(f"  AIRA ZERO-ETL WATCHER TEST (File Drop Mode)")
    print(f"  Target Directory: {WATCH_DIR}")
    print("=" * 72)
    WATCH_DIR.mkdir(parents=True, exist_ok=True)

    drop_filename = f"live_ingest_{int(time.time())}.json"
    drop_path = WATCH_DIR / drop_filename

    print(f"[+] Dropping telemetry payload: {drop_filename} ({len(events)} events)...")
    with open(drop_path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    print(f"[✓] File created! The Zero-ETL Watcher will automatically detect and ingest it.")
    print(f"[✓] Check your browser at http://127.0.0.1:8000 for the 'Zero-ETL Watcher Drop' toast.")
    print("=" * 72)


def main():
    parser = argparse.ArgumentParser(description="AIRA Real-Time Telemetry Stream Generator")
    parser.add_argument("--preset", choices=["sample", "multihost", "apt29"], default="multihost",
                        help="Attack preset to stream (default: multihost)")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="Delay in seconds between events in REST mode (default: 1.0)")
    parser.add_argument("--mode", choices=["rest", "drop-file"], default="rest",
                        help="Streaming delivery mode: 'rest' or 'drop-file' (default: rest)")
    parser.add_argument("--reset-first", action="store_true",
                        help="Reset live incident state back to baseline before streaming")

    args = parser.parse_args()

    if args.reset_first:
        try:
            req = urllib.request.Request(RESET_URL, method="POST")
            urllib.request.urlopen(req, timeout=3)
            print("[*] Successfully reset live telemetry state to baseline.")
        except Exception:
            pass

    events, name = load_events(args.preset)

    if args.mode == "drop-file":
        stream_file_drop(events, name)
    else:
        stream_rest(events, name, args.speed)


if __name__ == "__main__":
    main()
