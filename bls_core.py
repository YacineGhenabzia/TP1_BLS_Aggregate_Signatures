"""Core helpers for the educational TP1 BLS aggregate-signature lab.

This is a teaching implementation built on py_ecc. It is not production code.
"""
from __future__ import annotations

import base64
import json
import os
from typing import Any

from py_ecc.bls import G2ProofOfPossession as bls


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    """Serialize a dictionary deterministically before signing/verifying."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def generate_keypair() -> tuple[int, bytes, bytes]:
    """Return (secret_key, public_key, proof_of_possession)."""
    # KeyGen needs high-entropy input; use the operating system CSPRNG.
    secret_key = bls.KeyGen(os.urandom(32))
    public_key = bls.SkToPk(secret_key)
    proof = bls.PopProve(secret_key)
    return secret_key, public_key, proof


def validate_registry_entry(public_key: bytes, proof: bytes) -> bool:
    """Validate proof of possession when registering a public key."""
    try:
        return bool(bls.PopVerify(public_key, proof))
    except (ValueError, AssertionError, TypeError):
        return False


def sign_message(secret_key: int, message: bytes) -> bytes:
    return bls.Sign(secret_key, message)


def verify_message(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        return bool(bls.Verify(public_key, message, signature))
    except (ValueError, AssertionError, TypeError):
        return False


def aggregate_signatures(signatures: list[bytes]) -> bytes:
    if not signatures:
        raise ValueError("At least one signature is required")
    return bls.Aggregate(signatures)


def verify_aggregate(public_keys: list[bytes], messages: list[bytes], aggregate_signature: bytes) -> bool:
    if not public_keys or len(public_keys) != len(messages):
        return False
    try:
        return bool(bls.AggregateVerify(public_keys, messages, aggregate_signature))
    except (ValueError, AssertionError, TypeError):
        return False


def make_sensor_reading(sensor_id: str, seq: int) -> dict[str, Any]:
    """Produce deterministic demonstration data for repeatable tests."""
    temperature = round(19.5 + ((seq * 7) % 90) / 10, 1)
    humidity = round(35.0 + ((seq * 11) % 500) / 10, 1)
    return {
        "device_id": sensor_id,
        "sequence": seq,
        "temperature_c": temperature,
        "humidity_pct": humidity,
        "unit": "demo",
    }
