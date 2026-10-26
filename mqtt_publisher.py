"""Publish signed sensor readings to an MQTT broker (classroom lab only)."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import paho.mqtt.client as mqtt

from bls_core import b64e, canonical_json_bytes, make_sensor_reading, sign_message

BROKER = os.getenv("MQTT_HOST", "127.0.0.1")
PORT = int(os.getenv("MQTT_PORT", "1883"))
COUNT = int(os.getenv("SENSOR_COUNT", "10"))
PRIVATE_FILE = Path("sensor_private_keys.json")


def main() -> None:
    if not PRIVATE_FILE.exists():
        raise SystemExit("Missing sensor_private_keys.json. Run: python generate_fleet.py")
    secrets = json.loads(PRIVATE_FILE.read_text(encoding="utf-8"))
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="tp1-sensor-publisher")
    client.connect(BROKER, PORT, keepalive=30)
    client.loop_start()
    try:
        for i in range(1, COUNT + 1):
            sensor_id = f"sensor-{i:02d}"
            secret_key = int(secrets[sensor_id]["secret_key_hex"], 16)
            message = make_sensor_reading(sensor_id, seq=1)
            signature = sign_message(secret_key, canonical_json_bytes(message))
            envelope = {"message": message, "signature_b64": b64e(signature)}
            info = client.publish(f"tp1/sensors/{sensor_id}", json.dumps(envelope), qos=1)
            info.wait_for_publish()
            print(f"Published signed reading from {sensor_id}: {message['temperature_c']} C")
            time.sleep(0.1)
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
