"""
NANDA Prototype — Demo Orchestrator
====================================
Starts all servers, waits for them to be healthy, runs the resolution client,
then shuts everything down.

Usage:
    python run_demo.py

What it starts:
    Port 7700 — NANDA Index (index_server.py)
    Port 7701 — weather-agent facts server (agent_server.py --name weather-agent)
    Port 7702 — calculator-agent facts server (agent_server.py --name calculator-agent)
    Port 7703 — code-review-agent facts server (agent_server.py --name code-review-agent)
"""

import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).parent
PYTHON = sys.executable
INDEX_URL = "http://127.0.0.1:7700"

SERVERS = [
    {
        "label": "NANDA Index",
        "cmd": [PYTHON, str(HERE / "index_server.py"), "--port", "7700"],
        "health_url": f"{INDEX_URL}/health",
    },
    {
        "label": "weather-agent",
        "cmd": [
            PYTHON, str(HERE / "agent_server.py"),
            "--name", "weather-agent",
            "--port", "7701",
            "--index-url", INDEX_URL,
        ],
        "health_url": "http://127.0.0.1:7701/health",
    },
    {
        "label": "calculator-agent",
        "cmd": [
            PYTHON, str(HERE / "agent_server.py"),
            "--name", "calculator-agent",
            "--port", "7702",
            "--index-url", INDEX_URL,
        ],
        "health_url": "http://127.0.0.1:7702/health",
    },
    {
        "label": "code-review-agent",
        "cmd": [
            PYTHON, str(HERE / "agent_server.py"),
            "--name", "code-review-agent",
            "--port", "7703",
            "--index-url", INDEX_URL,
        ],
        "health_url": "http://127.0.0.1:7703/health",
    },
]

# ── Helpers ──────────────────────────────────────────────────────────────────

CYAN  = "\033[96m"
GREEN = "\033[92m"
RED   = "\033[91m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
RESET = "\033[0m"


def log(msg: str, color: str = DIM) -> None:
    print(f"{color}[orchestrator] {msg}{RESET}", flush=True)


def wait_healthy(health_url: str, label: str, timeout: float = 15.0) -> bool:
    """Poll the health endpoint until it responds 200 or timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(health_url, timeout=1.0)
            if r.status_code == 200:
                log(f"{label} is healthy", GREEN)
                return True
        except Exception:
            pass
        time.sleep(0.2)
    log(f"Timeout waiting for {label} at {health_url}", RED)
    return False


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    procs: list[subprocess.Popen] = []

    def shutdown(signum=None, frame=None) -> None:
        log("Shutting down all servers…")
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
        log("All servers stopped.")

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    log("Starting NANDA prototype servers…", BOLD)

    # Start the index first, wait for it, then start agents (so they can register)
    for srv in SERVERS:
        log(f"Starting {srv['label']}…")
        proc = subprocess.Popen(
            srv["cmd"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append(proc)

        if not wait_healthy(srv["health_url"], srv["label"]):
            log(f"Failed to start {srv['label']} — aborting.", RED)
            shutdown()
            sys.exit(1)

        # Give agents a moment to complete self-registration after becoming healthy
        if srv["label"] != "NANDA Index":
            time.sleep(0.5)

    log("All servers healthy. Running client demo…", GREEN)
    print()

    # Run the client in the foreground (same process, direct import)
    import client as c
    c.main(INDEX_URL)

    shutdown()


if __name__ == "__main__":
    main()
