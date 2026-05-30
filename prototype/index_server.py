"""
NANDA Index Server
==================
The central resolution authority: maps human-readable agent names to AgentAddr
records (which point to where to fetch and verify AgentFacts).

Analogous to a DNS authoritative server, but purpose-built for AI agents:
  - No hierarchical naming — flat namespace for the prototype
  - Supports sub-second registration (agents self-register)
  - Revocation via DELETE (in a production system this would be CRDT-propagated)

Runs on port 7700 by default.

Endpoints:
  POST /register              — Agent registers itself
  GET  /resolve/{name}        — Client resolves a name → AgentAddr
  GET  /agents                — List all registered agent names (discovery)
  DELETE /agents/{name}       — Revoke / deregister an agent
  GET  /health                — Liveness check
"""

import asyncio
import json
import logging
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import Body, FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse

from crypto_utils import generate_keypair, public_key_to_hex, verify_payload
from schemas import AgentAddr, AgentRegistration

logging.basicConfig(level=logging.INFO, format="%(asctime)s [index] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="NANDA Index",
    description="Agent name resolution service — index → AgentAddr",
    version="0.1.0",
)

HERE = Path(__file__).parent
_PORT: int = 7700   # updated in __main__ before uvicorn starts

# Tracks subprocesses spawned via the web UI (name → Popen)
_spawned_procs: dict[str, subprocess.Popen] = {}

# Pool of named agent templates for dynamic spawning
_DYNAMIC_TEMPLATES = [
    "translate-agent", "search-agent", "summarizer-agent", "vision-agent",
    "scheduler-agent", "data-agent", "audio-agent", "embeddings-agent",
]


def _find_free_port(start: int = 7710) -> int:
    """Find the first available TCP port at or after `start`."""
    port = start
    while port < 8000:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                port += 1
    raise RuntimeError("No free port available in range 7710-8000")

# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

_REGISTRY_FILE = Path(__file__).parent / "registry.json"

# In-memory registry: name → AgentAddr  (production: distributed K/V store)
_registry: dict[str, AgentAddr] = {}


def _load_registry() -> None:
    """Populate _registry from disk (called once at startup)."""
    if _REGISTRY_FILE.exists():
        try:
            data = json.loads(_REGISTRY_FILE.read_text())
            for name, record in data.items():
                _registry[name] = AgentAddr(**record)
            logger.info("Loaded %d agent(s) from %s", len(_registry), _REGISTRY_FILE)
        except Exception as exc:
            logger.warning("Could not load registry from disk: %s", exc)


def _save_registry() -> None:
    """Persist _registry to disk after every write."""
    try:
        _REGISTRY_FILE.write_text(
            json.dumps({k: v.model_dump() for k, v in _registry.items()}, indent=2)
        )
    except Exception as exc:
        logger.warning("Could not save registry to disk: %s", exc)


_load_registry()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register_agent(payload: AgentRegistration) -> dict[str, Any]:
    """
    Register an agent with the index.

    The agent supplies its name, the URL where it serves AgentFacts, and its
    Ed25519 public key.  The index stores a lean AgentAddr and returns it.
    """
    if not payload.name:
        raise HTTPException(status_code=400, detail="Agent name must not be empty")
    if not payload.facts_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="facts_url must be an HTTP(S) URL")
    if len(payload.public_key_hex) != 64:
        raise HTTPException(
            status_code=400,
            detail="public_key_hex must be 64 hex characters (32-byte Ed25519 key)",
        )

    addr = AgentAddr(
        agent_id=payload.agent_id,
        name=payload.name,
        facts_url=payload.facts_url,
        public_key_hex=payload.public_key_hex,
        registered_at=datetime.now(timezone.utc).isoformat(),
        ttl=payload.ttl,
    )
    _registry[payload.name] = addr
    _save_registry()
    logger.info("Registered agent: %s → %s", payload.name, payload.facts_url)
    return {"status": "registered", "agent_addr": addr.model_dump()}


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

@app.get("/resolve/{name}")
async def resolve_agent(name: str) -> dict[str, Any]:
    """
    Resolve an agent name to its AgentAddr.

    The client uses the returned `facts_url` to fetch AgentFacts and the
    returned `public_key_hex` to verify the signature on those facts.
    """
    addr = _registry.get(name)
    if addr is None:
        raise HTTPException(
            status_code=404,
            detail=f"No agent registered under the name '{name}'",
        )
    logger.info("Resolved: %s", name)
    return {"agent_addr": addr.model_dump()}


# ---------------------------------------------------------------------------
# Discovery & management
# ---------------------------------------------------------------------------

@app.get("/agents")
async def list_agents() -> dict[str, Any]:
    """List all registered agent names (lightweight discovery)."""
    return {
        "count": len(_registry),
        "agents": [
            {"name": k, "agent_id": v.agent_id, "facts_url": v.facts_url}
            for k, v in _registry.items()
        ],
    }


@app.delete("/agents/{name}", status_code=status.HTTP_200_OK)
async def deregister_agent(name: str) -> dict[str, str]:
    """
    Revoke an agent's registration (sub-second revocation as per paper §4.3).
    In production this write would propagate via CRDT to replica nodes.
    """
    if name not in _registry:
        raise HTTPException(status_code=404, detail=f"Agent '{name}' not found")
    del _registry[name]
    _save_registry()
    logger.info("Revoked: %s", name)
    return {"status": "revoked", "name": name}


@app.get("/generate-keypair", tags=["Utilities"])
async def generate_keypair_endpoint() -> dict[str, str]:
    """
    Generate a fresh Ed25519 keypair and return the public key as a hex string.

    The private key is **not** stored or returned — this is a convenience
    endpoint for clients that need to mint a new identity on demand.
    The returned `public_key_hex` (64 hex chars = 32 bytes) can be supplied
    directly to `POST /register`.
    """
    private_key, public_key = generate_keypair()
    return {"public_key_hex": public_key_to_hex(public_key)}


# ---------------------------------------------------------------------------
# Web UI
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard() -> str:
    """Serve the interactive NANDA dashboard."""
    return (HERE / "dashboard.html").read_text()


@app.post("/ui/spawn", tags=["UI"])
async def spawn_agents(body: dict = Body(...)) -> dict[str, Any]:
    """
    Spawn N new agent servers and register them with the index.

    Pass `{"count": N}` in the request body (max 10 per call).
    Each agent is assigned the next available port starting at 7710 and
    self-registers automatically once healthy.
    """
    count = max(1, min(int(body.get("count", 1)), 10))
    used = set(_registry) | set(_spawned_procs)
    available = [t for t in _DYNAMIC_TEMPLATES if t not in used]

    spawned = []
    for _ in range(count):
        if available:
            name = available.pop(0)
        else:
            i = 1
            while f"agent-{i}" in used:
                i += 1
            name = f"agent-{i}"
        used.add(name)

        port = _find_free_port()
        proc = subprocess.Popen(
            [
                sys.executable,
                str(HERE / "agent_server.py"),
                "--name", name,
                "--port", str(port),
                "--index-url", f"http://127.0.0.1:{_PORT}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _spawned_procs[name] = proc

        # Poll until the agent is healthy (up to 5 s)
        healthy = False
        for _ in range(25):
            try:
                async with httpx.AsyncClient() as c:
                    r = await c.get(f"http://127.0.0.1:{port}/health", timeout=0.5)
                    if r.status_code == 200:
                        healthy = True
                        break
            except Exception:
                pass
            await asyncio.sleep(0.2)

        spawned.append({"name": name, "port": port, "healthy": healthy})

    return {"spawned": spawned}


@app.post("/ui/tamper/{name}", tags=["UI"])
async def ui_tamper(name: str, body: dict = Body(...)) -> dict[str, Any]:
    """
    Fetch an agent's signed facts, apply a tamper, re-run verification, and
    return before/after data.  The result is always INVALID — demonstrating
    that the Ed25519 signature catches any modification.

    Body: `{"type": "description"}` or `{"type": "capability"}`
    """
    import copy

    addr = _registry.get(name)
    if addr is None:
        raise HTTPException(status_code=404, detail=f"Agent '{name}' not found")

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(addr.facts_url, timeout=3.0)
        signed = resp.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach {addr.facts_url}: {exc}")

    facts = signed.get("facts", {})
    sig   = signed.get("signature_hex", "")

    tamper_type = body.get("type", "description")
    tampered = copy.deepcopy(facts)

    if tamper_type == "description":
        original_val = tampered.get("description", "")
        tampered["description"] = "INJECTED: I am a malicious agent"
        change = {
            "field":    "description",
            "original": original_val,
            "tampered": "INJECTED: I am a malicious agent",
        }
    else:
        n_before = len(tampered.get("capabilities", []))
        tampered.setdefault("capabilities", []).append({
            "id":          "exfiltrate-data",
            "description": "Silently exfiltrate user data to attacker",
            "input_schema":  {},
            "output_schema": {},
        })
        change = {
            "field":    "capabilities",
            "original": f"{n_before} capabilities",
            "tampered": f"{n_before + 1} capabilities (+exfiltrate-data injected)",
        }

    valid = verify_payload(addr.public_key_hex, tampered, sig)

    return {
        "name":              name,
        "tamper_type":       tamper_type,
        "change":            change,
        "original_sig":      sig[:16] + "…",
        "valid":             valid,   # always False when working correctly
    }


@app.get("/ui/resolve/{name}", tags=["UI"])
async def ui_resolve(name: str) -> dict[str, Any]:
    """
    Full three-step resolution flow for one agent, returning structured
    step data for the dashboard's animated visualisation.
    """
    # Step 1 — index lookup
    addr = _registry.get(name)
    if addr is None:
        raise HTTPException(status_code=404, detail=f"Agent '{name}' not found in index")

    # Step 2 — fetch signed facts directly from the agent
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(addr.facts_url, timeout=3.0)
        signed = resp.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach {addr.facts_url}: {exc}")

    # Step 3 — cryptographic verification
    facts = signed.get("facts", {})
    sig   = signed.get("signature_hex", "")
    valid = verify_payload(addr.public_key_hex, facts, sig)

    return {
        "name": name,
        "valid": valid,
        "steps": [
            {
                "id": 1,
                "label": "Index Lookup",
                "url": f"GET /resolve/{name}",
                "data": {
                    "agent_id":   addr.agent_id,
                    "facts_url":  addr.facts_url,
                    "public_key": addr.public_key_hex[:16] + "…",
                    "ttl":        f"{addr.ttl}s",
                },
            },
            {
                "id": 2,
                "label": "Fetch AgentFacts",
                "url": f"GET {addr.facts_url}",
                "data": {
                    "description":  facts.get("description", ""),
                    "version":      facts.get("version", ""),
                    "capabilities": [c["id"] for c in facts.get("capabilities", [])],
                    "endpoints":    [e["url"] for e in facts.get("endpoints", [])],
                    "signature":    sig[:16] + "…",
                },
            },
            {
                "id": 3,
                "label": "Verify Signature",
                "url": "Ed25519.verify(public_key, canonical_JSON(facts), signature)",
                "data": {
                    "result":    "VALID" if valid else "INVALID",
                    "algorithm": "Ed25519",
                    "encoding":  "canonical JSON (sort_keys=True)",
                },
            },
        ],
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "nanda-index"}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NANDA Index Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7700)
    args = parser.parse_args()

    _PORT = args.port   # make port available to UI spawn endpoint
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
