"""Run the core TP1 correctness demonstration without MQTT."""
from __future__ import annotations

from bls_core import (
    aggregate_signatures,
    canonical_json_bytes,
    generate_keypair,
    make_sensor_reading,
    sign_message,
    validate_registry_entry,
    verify_aggregate,
    verify_message,
)


def main() -> None:
    print("TP1 — BLS aggregate signatures: correctness demo")
    print("=" * 54)

    fleet = []
    messages = []
    signatures = []
    public_keys = []

    for index in range(1, 11):
        sensor_id = f"sensor-{index:02d}"
        secret_key, public_key, proof = generate_keypair()
        assert validate_registry_entry(public_key, proof), "PoP registration failed"

        reading = make_sensor_reading(sensor_id, seq=1)
        message = canonical_json_bytes(reading)
        signature = sign_message(secret_key, message)

        fleet.append((secret_key, public_key, proof, reading))
        messages.append(message)
        signatures.append(signature)
        public_keys.append(public_key)
        assert verify_message(public_key, message, signature)

    aggregate_signature = aggregate_signatures(signatures)
    good_result = verify_aggregate(public_keys, messages, aggregate_signature)

    tampered_messages = list(messages)
    tampered_messages[0] = canonical_json_bytes({
        "device_id": "sensor-01", "sequence": 1,
        "temperature_c": 99.9, "humidity_pct": 40.0, "unit": "demo"
    })
    tampered_result = verify_aggregate(public_keys, tampered_messages, aggregate_signature)

    wrong_keypair = generate_keypair()
    wrong_public_keys = list(public_keys)
    wrong_public_keys[0] = wrong_keypair[1]
    wrong_key_result = verify_aggregate(wrong_public_keys, messages, aggregate_signature)

    print(f"Sensors/signatures: {len(signatures)}")
    print(f"One individual BLS signature size: {len(signatures[0])} bytes")
    print(f"Aggregate BLS signature size:      {len(aggregate_signature)} bytes")
    print(f"Aggregate verification (valid data): {good_result} (expected True)")
    print(f"Aggregate verification (tampered message): {tampered_result} (expected False)")
    print(f"Aggregate verification (wrong public key): {wrong_key_result} (expected False)")

    assert good_result is True
    assert tampered_result is False
    assert wrong_key_result is False
    print("\nPASS: all correctness and tampering checks succeeded.")


if __name__ == "__main__":
    main()
