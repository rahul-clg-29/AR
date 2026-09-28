"""
AIRA SOC Analyst Workbench Launcher
Starts the FastAPI web server on http://127.0.0.1:8000
"""

import sys
import webbrowser
from pathlib import Path
import uvicorn

root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))


def main():
    print("=" * 70)
    print("  AIRA: Autonomous Incident Reasoning Agent - SOC Analyst Workbench  ")
    print("=" * 70)
    print("[+] Launching web application on: http://127.0.0.1:8000")
    print("[+] Press Ctrl+C in terminal to stop the server.")
    print("=" * 70)

    # Optional: automatically open browser
    try:
        webbrowser.open("http://127.0.0.1:8000")
    except Exception:
        pass

    uvicorn.run("aira.ui.app:app", host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
