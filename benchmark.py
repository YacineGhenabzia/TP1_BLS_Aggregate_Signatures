"""Compare BLS aggregation against ordinary Ed25519 signatures.

Times are local educational measurements, not portable performance claims.
"""
from __future__ import annotations

import csv
import os
import statistics
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from bls_core import (
    aggregate_signatures,
    canonical_json_bytes,
    generate_keypair,
    make_sensor_reading,
    sign_message,
    validate_registry_entry,
    verify_aggregate,
)

SIZES = (2, 8, 32, 128)
REPEATS = 3


def timed(fn, repeats: int = REPEATS):
    samples = []
    result = None
    for _ in range(repeats):
        start = time.perf_counter()
        result = fn()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples), result


def run_size(n: int) -> dict[str, float | int]:
    bls_rows = []
    ed_rows = []
    for i in range(n):
        sid = f"sensor-{i+1:03d}"
        msg = canonical_json_bytes(make_sensor_reading(sid, seq=1))

        sk, pk, pop = generate_keypair()
        if not validate_registry_entry(pk, pop):
            raise RuntimeError("BLS proof-of-possession validation failed")
        bls_rows.append((sk, pk, msg))

        ed_sk = Ed25519PrivateKey.generate()
        ed_pk = ed_sk.public_key()
        ed_rows.append((ed_sk, ed_pk, msg))

    bls_sign_ms, bls_sigs = timed(lambda: [sign_message(sk, msg) for sk, _, msg in bls_rows])
    bls_sign_per_sensor_ms = bls_sign_ms / n
    aggregate_ms, aggregate_sig = timed(lambda: aggregate_signatures(bls_sigs))
    bls_verify_ms, bls_ok = timed(lambda: verify_aggregate(
        [pk for _, pk, _ in bls_rows], [msg for _, _, msg in bls_rows], aggregate_sig
    ))
    if not bls_ok:
        raise RuntimeError(f"BLS aggregate verification failed for n={n}")

    ed_sign_ms, ed_sigs = timed(lambda: [sk.sign(msg) for sk, _, msg in ed_rows])
    ed_verify_ms, ed_ok = timed(lambda: all(
        _safe_ed_verify(pk, msg, sig) for (_, pk, msg), sig in zip(ed_rows, ed_sigs)
    ))
    if not ed_ok:
        raise RuntimeError(f"Ed25519 verification failed for n={n}")

    return {
        "sensor_count": n,
        "bls_sign_total_ms": round(bls_sign_ms, 4),
        "bls_sign_avg_per_sensor_ms": round(bls_sign_per_sensor_ms, 4),
        "bls_aggregate_ms": round(aggregate_ms, 4),
        "bls_aggregate_verify_ms": round(bls_verify_ms, 4),
        "bls_aggregate_signature_bytes": len(aggregate_sig),
        "ed25519_sign_total_ms": round(ed_sign_ms, 4),
        "ed25519_verify_all_ms": round(ed_verify_ms, 4),
        "ed25519_signature_bytes_total": sum(len(s) for s in ed_sigs),
        "ed25519_signature_bytes_each": len(ed_sigs[0]) if ed_sigs else 0,
    }


def _safe_ed_verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def main() -> None:
    rows = [run_size(n) for n in SIZES]
    output = Path("benchmark_results.csv")
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print("Median timings in milliseconds; machine/library-dependent values.")
    print(f"Results written to: {output.resolve()}\n")
    for row in rows:
        print(row)


if __name__ == "__main__":
    main()
