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

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse

from crypto_utils import generate_keypair, public_key_to_hex
from schemas import AgentAddr, AgentRegistration

logging.basicConfig(level=logging.INFO, format="%(asctime)s [index] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="NANDA Index",
    description="Agent name resolution service — index → AgentAddr",
    version="0.1.0",
)

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

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
