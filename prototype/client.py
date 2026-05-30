"""
NANDA Resolution Client
=======================
Demonstrates the full end-to-end resolution flow from the paper:

    Client
      │
      ├─ 1. GET /resolve/{name}           NANDA Index
      │       └─ returns AgentAddr        (facts_url, public_key_hex)
      │
      ├─ 2. GET {facts_url}               Agent Facts Server
      │       └─ returns SignedAgentFacts (facts dict + signature_hex)
      │
      └─ 3. verify_payload(public_key_hex, facts, signature_hex)
              └─ True  → agent is authentic, use its capabilities
              └─ False → TAMPERED — reject

Also demonstrates:
  - Discovery: listing all agents from the index
  - Tamper detection: modifying a field → verification fails
  - Negative lookup: resolving an unregistered name → 404
"""

import json
import sys
import textwrap
from typing import Any

import httpx

from crypto_utils import verify_payload

# ── Palette ─────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

OK   = f"{GREEN}✓{RESET}"
FAIL = f"{RED}✗{RESET}"
INFO = f"{CYAN}→{RESET}"


def banner(text: str) -> None:
    width = 72
    print()
    print(f"{BOLD}{'─' * width}{RESET}")
    print(f"{BOLD}  {text}{RESET}")
    print(f"{BOLD}{'─' * width}{RESET}")


def step(n: int, text: str) -> None:
    print(f"\n  {CYAN}Step {n}{RESET}  {text}")


def ok(text: str) -> None:
    print(f"  {OK}  {text}")


def fail(text: str) -> None:
    print(f"  {FAIL}  {RED}{text}{RESET}")


def info(text: str) -> None:
    print(f"  {INFO}  {DIM}{text}{RESET}")


def show_json(label: str, data: Any, indent: int = 6) -> None:
    prefix = " " * indent
    dumped = json.dumps(data, indent=2)
    indented = textwrap.indent(dumped, prefix)
    print(f"\n  {DIM}{label}:{RESET}")
    print(f"{DIM}{indented}{RESET}")


# ── Core resolution logic ────────────────────────────────────────────────────

def resolve_name(client: httpx.Client, index_url: str, name: str) -> dict[str, Any] | None:
    """Query the NANDA Index for `name`; return AgentAddr dict or None."""
    resp = client.get(f"{index_url}/resolve/{name}")
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()["agent_addr"]


def fetch_signed_facts(client: httpx.Client, facts_url: str) -> dict[str, Any]:
    """Fetch the SignedAgentFacts from the agent's /facts endpoint."""
    resp = client.get(facts_url)
    resp.raise_for_status()
    return resp.json()


def full_resolution(
    client: httpx.Client,
    index_url: str,
    name: str,
    *,
    agent_num: int,
) -> None:
    """
    Perform and narrate the complete resolution flow for one agent name.
    """
    banner(f"Agent {agent_num} — resolving '{name}'")

    # ── Step 1: Name → AgentAddr ──────────────────────────────────────────
    step(1, f"Querying NANDA Index  GET {index_url}/resolve/{name}")
    agent_addr = resolve_name(client, index_url, name)
    if agent_addr is None:
        fail(f"No record for '{name}' in the index")
        return

    ok(f"AgentAddr received:")
    info(f"agent_id    : {agent_addr['agent_id']}")
    info(f"facts_url   : {agent_addr['facts_url']}")
    info(f"public_key  : {agent_addr['public_key_hex'][:24]}…  (Ed25519, 32 bytes)")
    info(f"ttl         : {agent_addr['ttl']}s")

    # ── Step 2: AgentAddr → SignedAgentFacts ─────────────────────────────
    facts_url: str = agent_addr["facts_url"]
    step(2, f"Fetching AgentFacts   GET {facts_url}")
    signed = fetch_signed_facts(client, facts_url)

    facts     = signed["facts"]
    sig_hex   = signed["signature_hex"]
    pub_hex   = agent_addr["public_key_hex"]

    ok(f"SignedAgentFacts received ({len(json.dumps(facts))} bytes)")
    info(f"description : {facts['description']}")
    info(f"version     : {facts['version']}")
    info(f"capabilities: {[c['id'] for c in facts.get('capabilities', [])]}")
    info(f"endpoints   : {[e['url'] for e in facts.get('endpoints', [])]}")
    info(f"signature   : {sig_hex[:24]}…  ({len(sig_hex)//2} bytes, Ed25519)")

    # ── Step 3: Verify signature ──────────────────────────────────────────
    step(3, "Verifying Ed25519 signature")
    info("canonical_JSON(facts) → Ed25519.verify(public_key, signature)")

    valid = verify_payload(pub_hex, facts, sig_hex)
    if valid:
        ok(f"{GREEN}{BOLD}Signature VALID — agent is authentic{RESET}")
    else:
        fail(f"Signature INVALID — REJECT this agent")


def demo_tamper_detection(
    client: httpx.Client,
    index_url: str,
    name: str,
) -> None:
    """
    Show that modifying a single field in the facts breaks verification.
    """
    banner("Tamper Detection — what happens if facts are modified?")
    info(f"Using agent '{name}' for tamper test")

    agent_addr = resolve_name(client, index_url, name)
    if agent_addr is None:
        fail("Cannot run tamper test — agent not found")
        return

    signed = fetch_signed_facts(client, agent_addr["facts_url"])
    facts   = signed["facts"]
    sig_hex = signed["signature_hex"]
    pub_hex = agent_addr["public_key_hex"]

    # Verify authentic first
    step(1, "Verify original (authentic) facts")
    assert verify_payload(pub_hex, facts, sig_hex), "Should be valid"
    ok("Original facts are valid")

    # Tamper: change the description
    step(2, "Tamper: overwrite 'description' field")
    tampered = dict(facts)
    original_desc = tampered["description"]
    tampered["description"] = "What is the matrix...?"
    info(f"original  → \"{original_desc}\"")
    info(f"tampered  → \"{tampered['description']}\"")

    step(3, "Re-run verification on tampered facts (same signature)")
    result = verify_payload(pub_hex, tampered, sig_hex)
    if not result:
        ok(f"{GREEN}{BOLD}CORRECT — tampered facts REJECTED (signature mismatch){RESET}")
    else:
        fail("BUG: tampered facts passed verification — this should not happen")

    # Tamper: forge a capability
    step(4, "Tamper: inject a fake capability into the capabilities list")
    tampered2 = dict(facts)
    tampered2["capabilities"] = facts.get("capabilities", []) + [
        {"id": "exfiltrate-data", "description": "Secretly send data to attacker",
         "input_schema": {}, "output_schema": {}}
    ]
    info("Appended: {\"id\": \"exfiltrate-data\", ...}")

    result2 = verify_payload(pub_hex, tampered2, sig_hex)
    if not result2:
        ok(f"{GREEN}{BOLD}CORRECT — fake capability injection REJECTED{RESET}")
    else:
        fail("BUG: capability injection passed — this should not happen")


def demo_negative_lookup(client: httpx.Client, index_url: str) -> None:
    """Show that resolving an unknown name returns a clear 404."""
    banner("Negative Lookup — resolving an unregistered agent name")
    name = "nonexistent-agent"
    step(1, f"Querying index for '{name}'")
    result = resolve_name(client, index_url, name)
    if result is None:
        ok(f"Index correctly returned 404 for '{name}'")
    else:
        fail(f"Expected 404 but got an AgentAddr — index is wrong")


def demo_discovery(client: httpx.Client, index_url: str) -> None:
    """Show the full agent listing (lightweight discovery without fetching facts)."""
    banner("Discovery — listing all registered agents")
    step(1, f"GET {index_url}/agents")
    resp = client.get(f"{index_url}/agents")
    resp.raise_for_status()
    data = resp.json()
    ok(f"{data['count']} agent(s) registered in the index:")
    for a in data["agents"]:
        info(f"{a['name']:30s}  id={a['agent_id']}")
        info(f"{'':30s}  facts_url={a['facts_url']}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main(index_url: str = "http://127.0.0.1:7700") -> None:
    print(f"\n{BOLD}{'═' * 72}{RESET}")
    print(f"{BOLD}  NANDA Resolution Client{RESET}")
    print(f"{BOLD}  Flow: Index → AgentAddr → AgentFacts → Verify{RESET}")
    print(f"{BOLD}{'═' * 72}{RESET}")
    print(f"\n  {DIM}Index URL: {index_url}{RESET}")

    with httpx.Client(timeout=10.0) as client:
        # Discovery pass — find what's registered
        demo_discovery(client, index_url)

        # Full resolution for each of the two primary agents
        full_resolution(client, index_url, "weather-agent", agent_num=1)
        full_resolution(client, index_url, "calculator-agent", agent_num=2)

        # Third agent if present (code-review-agent)
        resp = client.get(f"{index_url}/agents")
        names = {a["name"] for a in resp.json().get("agents", [])}
        if "code-review-agent" in names:
            full_resolution(client, index_url, "code-review-agent", agent_num=3)

        # Tamper detection demo
        demo_tamper_detection(client, index_url, "weather-agent")

        # Negative lookup
        demo_negative_lookup(client, index_url)

    print(f"\n{BOLD}{'═' * 72}{RESET}")
    print(f"{BOLD}  Demo complete.{RESET}")
    print(f"{BOLD}{'═' * 72}{RESET}\n")


if __name__ == "__main__":
    idx = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:7700"
    main(idx)
