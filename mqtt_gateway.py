"""Collect sensor messages, aggregate BLS signatures and verify the batch."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import paho.mqtt.client as mqtt

from bls_core import (
    aggregate_signatures, b64d, canonical_json_bytes,
    validate_registry_entry, verify_aggregate,
)

BROKER = os.getenv("MQTT_HOST", "127.0.0.1")
PORT = int(os.getenv("MQTT_PORT", "1883"))
EXPECTED = int(os.getenv("SENSOR_COUNT", "10"))
REGISTRY_FILE = Path("public_registry.json")


def main() -> None:
    if not REGISTRY_FILE.exists():
        raise SystemExit("Missing public_registry.json. Run: python generate_fleet.py")
    registry = json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
    for sensor_id, entry in registry.items():
        if not validate_registry_entry(b64d(entry["public_key_b64"]), b64d(entry["pop_b64"])):
            raise SystemExit(f"Invalid registered key/proof for {sensor_id}")

    received: dict[str, tuple[bytes, bytes, dict]] = {}
    started = time.perf_counter()

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            client.subscribe("tp1/sensors/+", qos=1)
            print(f"Gateway listening on {BROKER}:{PORT}; waiting for {EXPECTED} sensors...")
        else:
            print(f"MQTT connection failed: {reason_code}")

    def on_message(client, userdata, msg):
        try:
            topic_sensor = msg.topic.rsplit("/", 1)[-1]
            envelope = json.loads(msg.payload.decode("utf-8"))
            reading = envelope["message"]
            signature = b64d(envelope["signature_b64"])
            claimed_sensor = reading["device_id"]
            if topic_sensor != claimed_sensor:
                print(f"Rejecting topic/identity mismatch: {msg.topic}")
                return
            if claimed_sensor not in registry:
                print(f"Rejecting unregistered sensor: {claimed_sensor}")
                return
            if claimed_sensor in received:
                print(f"Ignoring duplicate message from {claimed_sensor}")
                return
            public_key = b64d(registry[claimed_sensor]["public_key_b64"])
            message_bytes = canonical_json_bytes(reading)
            received[claimed_sensor] = (public_key, message_bytes, signature)
            print(f"Received {len(received)}/{EXPECTED}: {claimed_sensor}")

            if len(received) >= EXPECTED:
                # Keep deterministic ordering when pairing messages with public keys.
                sensor_ids = sorted(received)[:EXPECTED]
                pks = [received[sid][0] for sid in sensor_ids]
                messages = [received[sid][1] for sid in sensor_ids]
                signatures = [received[sid][2] for sid in sensor_ids]
                agg_sig = aggregate_signatures(signatures)
                valid = verify_aggregate(pks, messages, agg_sig)
                elapsed_ms = (time.perf_counter() - started) * 1000
                print("\n=== Aggregate verification result ===")
                print(f"Sensors in batch: {len(sensor_ids)}")
                print(f"Aggregate signature size: {len(agg_sig)} bytes")
                print(f"Equivalent separate BLS signatures: {sum(len(sig) for sig in signatures)} bytes")
                print(f"AggregateVerify: {valid}")
                print(f"Elapsed collection + verification: {elapsed_ms:.2f} ms (includes MQTT waiting time)")
                client.disconnect()
        except Exception as exc:
            print(f"Could not process message: {exc}")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="tp1-batch-gateway")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER, PORT, keepalive=30)
    client.loop_forever()


if __name__ == "__main__":
    main()
