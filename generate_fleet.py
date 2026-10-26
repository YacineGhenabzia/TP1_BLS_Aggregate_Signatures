"""Generate demo keys for the MQTT lab. Files are for classroom use only."""
from __future__ import annotations

import json
from pathlib import Path

from bls_core import b64e, generate_keypair, validate_registry_entry

N_SENSORS = 10


def main() -> None:
    private_file = Path("sensor_private_keys.json")
    public_file = Path("public_registry.json")
    private_records = {}
    registry = {}
    for i in range(1, N_SENSORS + 1):
        sensor_id = f"sensor-{i:02d}"
        sk, pk, pop = generate_keypair()
        if not validate_registry_entry(pk, pop):
            raise RuntimeError(f"Invalid proof of possession for {sensor_id}")
        private_records[sensor_id] = {"secret_key_hex": format(sk, "x")}
        registry[sensor_id] = {"public_key_b64": b64e(pk), "pop_b64": b64e(pop)}
    private_file.write_text(json.dumps(private_records, indent=2), encoding="utf-8")
    public_file.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    print(f"Generated {N_SENSORS} demo sensors.")
    print(f"Private keys: {private_file.resolve()}  [KEEP LOCAL; never publish]")
    print(f"Public registry: {public_file.resolve()}")


if __name__ == "__main__":
    main()
