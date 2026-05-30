"""
NANDA Agent Facts Server
========================
A generic server that any agent can run to:
  1. Generate a fresh Ed25519 keypair at startup
  2. Produce and sign an AgentFacts document
  3. Self-register with the NANDA Index
  4. Serve the signed facts at GET /facts

Configure via CLI flags (see __main__ block at the bottom).

Separate instances run for each agent (weather-agent on 7701,
calculator-agent on 7702, code-review-agent on 7703).

Endpoints:
  GET /facts      — Signed AgentFacts document (the heart of verification)
  GET /pubkey     — Public key in hex (convenience; also stored in index)
  GET /health     — Liveness check
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI

from crypto_utils import generate_keypair, public_key_to_hex, sign_payload
from schemas import (
    AgentFacts,
    AgentRegistration,
    Capability,
    Endpoint,
    SignedAgentFacts,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

# ---------------------------------------------------------------------------
# Agent capability catalogue
# Each entry describes a real-world agent archetype.
# ---------------------------------------------------------------------------

AGENT_CATALOGUE: dict[str, dict[str, Any]] = {
    "weather-agent": {
        "agent_id": "nanda:did:agent:weather-v1",
        "description": "Provides real-time weather data and multi-day forecasts",
        "version": "1.2.0",
        "capabilities": [
            Capability(
                id="get-current-weather",
                description="Return current conditions for a location",
                input_schema={"location": {"type": "string"}},
                output_schema={"temp_c": {"type": "number"}, "condition": {"type": "string"}},
            ),
            Capability(
                id="get-forecast",
                description="Return a N-day weather forecast",
                input_schema={
                    "location": {"type": "string"},
                    "days": {"type": "integer", "minimum": 1, "maximum": 14},
                },
                output_schema={"forecast": {"type": "array"}},
            ),
            Capability(
                id="get-alerts",
                description="Return active severe-weather alerts for a region",
                input_schema={"region": {"type": "string"}},
                output_schema={"alerts": {"type": "array"}},
            ),
        ],
        "endpoints": [
            Endpoint(id="primary", url="https://weather.example.com/mcp", region="us-east-1"),
            Endpoint(id="fallback", url="https://weather-eu.example.com/mcp", region="eu-west-1"),
        ],
        "tags": ["weather", "forecast", "environment", "real-time"],
    },
    "calculator-agent": {
        "agent_id": "nanda:did:agent:calculator-v2",
        "description": "Performs symbolic and numerical mathematics",
        "version": "2.0.1",
        "capabilities": [
            Capability(
                id="evaluate",
                description="Evaluate an arithmetic or symbolic expression",
                input_schema={"expression": {"type": "string"}},
                output_schema={"result": {"type": "string"}},
            ),
            Capability(
                id="solve",
                description="Solve algebraic equations for a given variable",
                input_schema={
                    "equation": {"type": "string"},
                    "variable": {"type": "string"},
                },
                output_schema={"solutions": {"type": "array"}},
            ),
            Capability(
                id="integrate",
                description="Compute definite or indefinite integrals",
                input_schema={
                    "expression": {"type": "string"},
                    "variable": {"type": "string"},
                    "lower": {"type": "number", "optional": True},
                    "upper": {"type": "number", "optional": True},
                },
                output_schema={"result": {"type": "string"}},
            ),
        ],
        "endpoints": [
            Endpoint(id="primary", url="https://calc.example.com/mcp", region="us-west-2"),
        ],
        "tags": ["math", "algebra", "calculus", "computation"],
    },
    "code-review-agent": {
        "agent_id": "nanda:did:agent:codereview-v1",
        "description": "Analyzes source code for bugs, security issues, and style",
        "version": "0.9.5",
        "capabilities": [
            Capability(
                id="review",
                description="Return a structured code review with issues ranked by severity",
                input_schema={
                    "code": {"type": "string"},
                    "language": {"type": "string"},
                },
                output_schema={"issues": {"type": "array"}, "score": {"type": "number"}},
            ),
            Capability(
                id="security-scan",
                description="Scan for OWASP Top 10 vulnerabilities",
                input_schema={
                    "code": {"type": "string"},
                    "language": {"type": "string"},
                },
                output_schema={"vulnerabilities": {"type": "array"}},
            ),
            Capability(
                id="suggest-refactor",
                description="Propose refactoring to improve readability and performance",
                input_schema={"code": {"type": "string"}, "language": {"type": "string"}},
                output_schema={"suggestion": {"type": "string"}},
            ),
        ],
        "endpoints": [
            Endpoint(id="primary", url="https://codereview.example.com/mcp", region="us-east-1"),
        ],
        "tags": ["code", "security", "review", "quality"],
    },
    "translate-agent": {
        "agent_id": "nanda:did:agent:translate-v1",
        "description": "Translates text between 100+ languages with cultural context awareness",
        "version": "3.1.0",
        "capabilities": [
            Capability(
                id="translate",
                description="Translate text from one language to another",
                input_schema={"text": {"type": "string"}, "from": {"type": "string"}, "to": {"type": "string"}},
                output_schema={"translated": {"type": "string"}, "confidence": {"type": "number"}},
            ),
            Capability(
                id="detect-language",
                description="Detect the language of a text snippet",
                input_schema={"text": {"type": "string"}},
                output_schema={"language": {"type": "string"}, "confidence": {"type": "number"}},
            ),
        ],
        "endpoints": [Endpoint(id="primary", url="https://translate.example.com/mcp", region="us-east-1")],
        "tags": ["translation", "nlp", "multilingual"],
    },
    "search-agent": {
        "agent_id": "nanda:did:agent:search-v1",
        "description": "Semantic search over documents, knowledge bases, and the web",
        "version": "2.5.0",
        "capabilities": [
            Capability(
                id="semantic-search",
                description="Vector-similarity search over a document corpus",
                input_schema={"query": {"type": "string"}, "top_k": {"type": "integer"}},
                output_schema={"results": {"type": "array"}},
            ),
            Capability(
                id="web-search",
                description="Real-time web search with ranked results",
                input_schema={"query": {"type": "string"}},
                output_schema={"results": {"type": "array"}},
            ),
        ],
        "endpoints": [Endpoint(id="primary", url="https://search.example.com/mcp", region="us-east-1")],
        "tags": ["search", "retrieval", "semantic"],
    },
    "summarizer-agent": {
        "agent_id": "nanda:did:agent:summarizer-v1",
        "description": "Summarizes documents, articles, and conversations into concise outputs",
        "version": "1.8.0",
        "capabilities": [
            Capability(
                id="summarize",
                description="Generate an abstractive summary of a long text",
                input_schema={"text": {"type": "string"}, "max_words": {"type": "integer"}},
                output_schema={"summary": {"type": "string"}},
            ),
            Capability(
                id="bullet-points",
                description="Extract key points as a bulleted list",
                input_schema={"text": {"type": "string"}},
                output_schema={"points": {"type": "array"}},
            ),
        ],
        "endpoints": [Endpoint(id="primary", url="https://summarizer.example.com/mcp", region="us-east-1")],
        "tags": ["summarization", "nlp", "compression"],
    },
    "vision-agent": {
        "agent_id": "nanda:did:agent:vision-v1",
        "description": "Analyzes images and extracts structured information using computer vision",
        "version": "4.0.0",
        "capabilities": [
            Capability(
                id="describe-image",
                description="Generate a natural language description of an image",
                input_schema={"image_url": {"type": "string"}},
                output_schema={"description": {"type": "string"}},
            ),
            Capability(
                id="detect-objects",
                description="Detect and classify objects in an image",
                input_schema={"image_url": {"type": "string"}},
                output_schema={"objects": {"type": "array"}},
            ),
            Capability(
                id="ocr",
                description="Extract text from images via optical character recognition",
                input_schema={"image_url": {"type": "string"}},
                output_schema={"text": {"type": "string"}},
            ),
        ],
        "endpoints": [
            Endpoint(id="primary", url="https://vision.example.com/mcp", region="us-west-2"),
            Endpoint(id="eu", url="https://vision-eu.example.com/mcp", region="eu-central-1"),
        ],
        "tags": ["vision", "cv", "ocr", "multimodal"],
    },
    "scheduler-agent": {
        "agent_id": "nanda:did:agent:scheduler-v1",
        "description": "Manages tasks, reminders, and calendar events across time zones",
        "version": "1.0.0",
        "capabilities": [
            Capability(
                id="create-event",
                description="Schedule a calendar event",
                input_schema={"title": {"type": "string"}, "start": {"type": "string"}, "duration_minutes": {"type": "integer"}},
                output_schema={"event_id": {"type": "string"}},
            ),
            Capability(
                id="set-reminder",
                description="Set a one-shot reminder at a specific time",
                input_schema={"message": {"type": "string"}, "at": {"type": "string"}},
                output_schema={"reminder_id": {"type": "string"}},
            ),
        ],
        "endpoints": [Endpoint(id="primary", url="https://scheduler.example.com/mcp", region="us-east-1")],
        "tags": ["scheduling", "calendar", "productivity"],
    },
    "data-agent": {
        "agent_id": "nanda:did:agent:data-v1",
        "description": "Queries, transforms, and analyzes structured data from databases and APIs",
        "version": "2.2.0",
        "capabilities": [
            Capability(
                id="query",
                description="Run a natural-language query over a dataset",
                input_schema={"question": {"type": "string"}, "dataset": {"type": "string"}},
                output_schema={"answer": {"type": "string"}, "data": {"type": "array"}},
            ),
            Capability(
                id="transform",
                description="Apply a transformation pipeline to structured data",
                input_schema={"data": {"type": "array"}, "pipeline": {"type": "array"}},
                output_schema={"result": {"type": "array"}},
            ),
        ],
        "endpoints": [Endpoint(id="primary", url="https://data.example.com/mcp", region="us-east-1")],
        "tags": ["data", "analytics", "query"],
    },
    "audio-agent": {
        "agent_id": "nanda:did:agent:audio-v1",
        "description": "Transcribes, synthesizes, and analyzes audio content",
        "version": "1.4.0",
        "capabilities": [
            Capability(
                id="transcribe",
                description="Convert speech audio to text (STT)",
                input_schema={"audio_url": {"type": "string"}, "language": {"type": "string"}},
                output_schema={"transcript": {"type": "string"}},
            ),
            Capability(
                id="synthesize",
                description="Convert text to natural-sounding speech (TTS)",
                input_schema={"text": {"type": "string"}, "voice": {"type": "string"}},
                output_schema={"audio_url": {"type": "string"}},
            ),
        ],
        "endpoints": [Endpoint(id="primary", url="https://audio.example.com/mcp", region="us-east-1")],
        "tags": ["audio", "tts", "stt", "speech"],
    },
    "embeddings-agent": {
        "agent_id": "nanda:did:agent:embeddings-v1",
        "description": "Generates dense vector embeddings for text, images, and multimodal inputs",
        "version": "3.0.0",
        "capabilities": [
            Capability(
                id="embed-text",
                description="Generate embeddings for a batch of text strings",
                input_schema={"texts": {"type": "array"}, "model": {"type": "string"}},
                output_schema={"embeddings": {"type": "array"}, "dimensions": {"type": "integer"}},
            ),
            Capability(
                id="embed-image",
                description="Generate CLIP-style embeddings for images",
                input_schema={"image_urls": {"type": "array"}},
                output_schema={"embeddings": {"type": "array"}},
            ),
        ],
        "endpoints": [
            Endpoint(id="primary", url="https://embeddings.example.com/mcp", region="us-east-1"),
            Endpoint(id="gpu", url="https://embeddings-gpu.example.com/mcp", region="us-west-2"),
        ],
        "tags": ["embeddings", "vectors", "semantic", "multimodal"],
    },
}


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------

def build_app(
    agent_name: str,
    own_port: int,
    index_url: str,
    registration_type: str = "native",
    gateway_url: str | None = None,
) -> FastAPI:
    """
    Build a FastAPI app for the given agent.
    Generates a keypair, creates signed AgentFacts, and self-registers.

    registration_type — one of: 'native', 'enterprise', 'did'
    gateway_url       — enterprise API gateway URL (enterprise type only)
    """
    logger = logging.getLogger(agent_name)

    if agent_name not in AGENT_CATALOGUE:
        # Generic fallback for dynamically-spawned agents
        cfg = {
            "agent_id": f"nanda:did:agent:{agent_name.replace('-', '_')}",
            "description": f"Dynamically spawned agent: {agent_name}",
            "version": "1.0.0",
            "capabilities": [
                Capability(
                    id="process",
                    description="Process a generic task input",
                    input_schema={"input": {"type": "string"}},
                    output_schema={"output": {"type": "string"}},
                ),
            ],
            "endpoints": [
                Endpoint(id="primary", url=f"https://{agent_name}.example.com/mcp", region="us-east-1"),
            ],
            "tags": ["generic", "dynamic"],
        }
    else:
        cfg = AGENT_CATALOGUE[agent_name]

    # --- Crypto setup ---
    private_key, public_key = generate_keypair()
    pub_hex = public_key_to_hex(public_key)
    logger.info("Generated Ed25519 keypair — public key: %s…", pub_hex[:16])

    # --- Build AgentFacts ---
    now = datetime.now(timezone.utc)
    facts = AgentFacts(
        agent_id=cfg["agent_id"],
        name=agent_name,
        description=cfg["description"],
        version=cfg["version"],
        capabilities=cfg["capabilities"],
        endpoints=cfg["endpoints"],
        tags=cfg["tags"],
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(hours=24)).isoformat(),
    )

    # Serialize to dict once; this exact dict is what gets signed
    facts_dict = facts.model_dump()

    # --- Sign the facts ---
    signature_hex = sign_payload(private_key, facts_dict)
    logger.info("AgentFacts signed (sig prefix: %s…)", signature_hex[:16])

    # The signed document served at /facts
    signed_facts = SignedAgentFacts(facts=facts_dict, signature_hex=signature_hex)

    # --- Build FastAPI app ---
    app = FastAPI(
        title=f"NANDA Agent — {agent_name}",
        description=cfg["description"],
        version=cfg["version"],
    )

    @app.get("/facts")
    async def get_facts() -> dict[str, Any]:
        """
        Return the signed AgentFacts for this agent.

        The client MUST:
          1. Fetch the agent's public key from the NANDA Index AgentAddr
          2. Compute canonical JSON of `facts`
          3. Verify `signature_hex` against that canonical JSON using Ed25519
        """
        return signed_facts.model_dump()

    @app.get("/pubkey")
    async def get_pubkey() -> dict[str, str]:
        """Convenience endpoint — public key is also stored in the Index."""
        return {"public_key_hex": pub_hex, "algorithm": "Ed25519"}

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "agent": agent_name}

    # --- Self-register with the NANDA Index at startup ---
    @app.on_event("startup")
    async def self_register() -> None:
        facts_url = f"http://127.0.0.1:{own_port}/facts"

        # DID registration: ensure agent_id is a proper DID; derive did_document_url
        reg_agent_id = cfg["agent_id"]
        did_document_url: str | None = None
        if registration_type == "did":
            if not reg_agent_id.startswith("did:"):
                reg_agent_id = f"did:nanda:{agent_name}"
            did_document_url = f"{index_url}/did/{agent_name}"

        registration = AgentRegistration(
            agent_id=reg_agent_id,
            name=agent_name,
            facts_url=facts_url,
            public_key_hex=pub_hex,
            ttl=300,
            registration_type=registration_type,
            gateway_url=gateway_url,
            did_document_url=did_document_url,
        )
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{index_url}/register",
                    json=registration.model_dump(),
                    timeout=5.0,
                )
                resp.raise_for_status()
            logger.info("Self-registered with NANDA Index at %s", index_url)
        except Exception as exc:
            logger.error("Failed to register with index: %s", exc)

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NANDA Agent Facts Server")
    parser.add_argument(
        "--name",
        required=True,
        help="Agent name — must match a key in AGENT_CATALOGUE, or any custom name for a generic agent",
    )
    parser.add_argument("--port", type=int, required=True, help="Port to listen on")
    parser.add_argument(
        "--index-url",
        default="http://127.0.0.1:7700",
        help="URL of the NANDA Index for self-registration",
    )
    parser.add_argument(
        "--registration-type",
        default="native",
        choices=["native", "enterprise", "did"],
        help="Registration type: native (direct), enterprise (gateway-routed), or did (DID-based identity)",
    )
    parser.add_argument(
        "--gateway-url",
        default=None,
        help="Enterprise API gateway URL (used only with --registration-type enterprise)",
    )
    args = parser.parse_args()

    app = build_app(
        args.name,
        args.port,
        args.index_url,
        registration_type=args.registration_type,
        gateway_url=args.gateway_url,
    )
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
