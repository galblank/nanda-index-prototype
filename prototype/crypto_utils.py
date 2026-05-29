"""
Cryptographic utilities for NANDA prototype.
Uses Ed25519 for signing AgentFacts (fast, compact, modern).

Signing approach: canonical JSON serialization → Ed25519 signature.
The client can detect any tampering because modifying a single byte of
the facts payload breaks the signature.
"""

import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_to_hex(public_key: Ed25519PublicKey) -> str:
    """Serialize a public key to a hex string (32 raw bytes → 64 hex chars)."""
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw.hex()


def hex_to_public_key(hex_str: str) -> Ed25519PublicKey:
    """Deserialize a public key from a hex string."""
    raw = bytes.fromhex(hex_str)
    return Ed25519PublicKey.from_public_bytes(raw)


def canonical_bytes(payload: dict) -> bytes:
    """
    Produce a deterministic byte representation of a dict.
    Uses sorted keys + no extra whitespace — ensures identical output
    regardless of key insertion order.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def sign_payload(private_key: Ed25519PrivateKey, payload: dict) -> str:
    """Sign a dict payload and return the signature as a hex string."""
    data = canonical_bytes(payload)
    sig_bytes = private_key.sign(data)
    return sig_bytes.hex()


def verify_payload(public_key_hex: str, payload: dict, signature_hex: str) -> bool:
    """
    Verify that `payload` was signed by the private key corresponding to
    `public_key_hex`.  Returns True on success, False on any failure
    (wrong key, tampered data, malformed signature).
    """
    try:
        public_key = hex_to_public_key(public_key_hex)
        data = canonical_bytes(payload)
        sig_bytes = bytes.fromhex(signature_hex)
        public_key.verify(sig_bytes, data)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False
