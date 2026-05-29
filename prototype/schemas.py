"""
NANDA protocol data schemas (Pydantic models).

Three-layer protocol objects that mirror the paper's architecture:

  AgentRegistration  →  what an agent POSTs to the index
  AgentAddr          →  what the index returns on name resolution
  AgentFacts         →  rich capability metadata served by the agent
  SignedAgentFacts    →  AgentFacts + Ed25519 signature
"""

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Any


# ---------------------------------------------------------------------------
# Capability & endpoint descriptors
# ---------------------------------------------------------------------------

class Capability(BaseModel):
    """A single capability assertion (what this agent can do)."""
    id: str = Field(..., description="Stable capability identifier")
    description: str = Field(..., description="Human-readable summary")
    input_schema: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON-Schema-like shape of expected inputs",
    )
    output_schema: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON-Schema-like shape of returned values",
    )


class Endpoint(BaseModel):
    """A reachable endpoint for this agent."""
    id: str = Field(..., description="Endpoint role, e.g. 'primary' or 'fallback'")
    url: str = Field(..., description="Full URL of the endpoint")
    protocol: str = Field(default="MCP/1.0", description="Wire protocol")
    region: str | None = Field(default=None, description="Deployment region hint")


# ---------------------------------------------------------------------------
# AgentFacts — the rich verifiable metadata document
# ---------------------------------------------------------------------------

class AgentFacts(BaseModel):
    """
    Verifiable metadata document produced and signed by the agent itself.

    This is what a resolver fetches after obtaining the AgentAddr from the
    NANDA Index.  The signature is computed over the canonical JSON of the
    `facts` field (everything *except* the signature itself), so any field
    change is detectable.
    """
    agent_id: str = Field(..., description="Globally unique agent DID / identifier")
    name: str = Field(..., description="Human-readable name, used for resolution")
    description: str = Field(..., description="What this agent does")
    version: str = Field(default="1.0.0")
    capabilities: list[Capability] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    issued_at: str = Field(..., description="ISO-8601 timestamp of signing")
    expires_at: str = Field(..., description="ISO-8601 expiry of these facts")


# ---------------------------------------------------------------------------
# AgentAddr — the lean pointer returned by the NANDA Index
# ---------------------------------------------------------------------------

class AgentAddr(BaseModel):
    """
    Lean address record analogous to a DNS A record.

    Contains just enough information to (a) locate the AgentFacts document
    and (b) verify its signature, without revealing full capability details.
    """
    agent_id: str
    name: str
    facts_url: str = Field(..., description="Where to fetch signed AgentFacts")
    public_key_hex: str = Field(
        ..., description="Ed25519 public key (hex) for fact verification"
    )
    registered_at: str
    ttl: int = Field(default=300, description="Cache TTL in seconds")


# ---------------------------------------------------------------------------
# Registration payload — what the agent POSTs to the index
# ---------------------------------------------------------------------------

class AgentRegistration(BaseModel):
    """Payload an agent sends to POST /register on the NANDA Index."""
    agent_id: str
    name: str
    facts_url: str
    public_key_hex: str
    ttl: int = 300


# ---------------------------------------------------------------------------
# SignedAgentFacts — wire format served by agent fact servers
# ---------------------------------------------------------------------------

class SignedAgentFacts(BaseModel):
    """
    The complete signed facts document returned by an agent's /facts endpoint.

    `facts` is the raw dict (so it round-trips identically through JSON for
    signature verification).  `signature_hex` is the Ed25519 signature over
    the canonical JSON of `facts`.
    """
    facts: dict[str, Any]
    signature_hex: str

    class Config:
        extra = "allow"
