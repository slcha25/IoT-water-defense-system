"""
publisher_defended.py - Multi-Device MQTT Publisher with Replay Defenses

Publishes simulated Main Building, Pool & Spa, and Kitchen & Laundry sensor
data with three layers of replay protection:
  1. Timestamps (already present, now validated by subscriber)
  2. Sequence counter (incrementing message number per device)
  3. HMAC signature (proves message hasn't been tampered with)

Based on publisher_mtls.py from Project 5.

Usage:
    python publisher_defended.py
"""

import paho.mqtt.client as mqtt
import ssl
import json
import time
import random
import hmac
import hashlib
from datetime import datetime, timezone

# Handle paho-mqtt 2.0+ API change
try:
    MQTT_CLIENT_ARGS = {"callback_api_version": mqtt.CallbackAPIVersion.VERSION1}
except AttributeError:
    MQTT_CLIENT_ARGS = {}

# =============================================================================
# Configuration
# =============================================================================
BROKER_HOST = "localhost"
BROKER_PORT = 8883
CERT_DEVICE_ID = "001"

# Certificate files (same as Project 5)
CA_CERT = "certs/ca.pem"
CLIENT_CERT = f"certs/device-{CERT_DEVICE_ID}.pem"
CLIENT_KEY = f"certs/device-{CERT_DEVICE_ID}-key.pem"

# One mTLS client simulates the three Grand Marina sensor devices.
CLIENT_NAME = "GrandMarina-Defended-MultiSensor"
PUBLISH_INTERVAL_SECONDS = 5

# Device profiles are based on the original Main Building reading ranges.
# Each profile normally produces safe readings, with occasional anomalies so
# the custom high-pressure and low-flow dashboard alerts can be demonstrated.
DEVICES = [
    {
        "device_id": "HYDROLOGIC-Device-001",
        "zone": "main_building",
        "display_name": "Main Building",
        "topic": "hydroficient/grandmarina/sensors/main-building",
        "pressure_normal": (58, 64),
        "pressure_high": (66, 72),
        "pressure_anomaly_chance": 0.18,
        "pressure_drop": (3, 6),
        "flow_normal": (47, 55),
        "flow_low": (36, 44),
        "flow_anomaly_chance": 0.18,
        "gate_range": (42, 48),
    },
    {
        "device_id": "HYDROLOGIC-Device-002",
        "zone": "pool_spa",
        "display_name": "Pool & Spa",
        "topic": "hydroficient/grandmarina/sensors/pool-spa",
        "pressure_normal": (50, 61),
        "pressure_high": (66, 71),
        "pressure_anomaly_chance": 0.18,
        "pressure_drop": (3, 7),
        "flow_normal": (46, 53),
        "flow_low": (35, 44),
        "flow_anomaly_chance": 0.18,
        "gate_range": (48, 58),
    },
    {
        "device_id": "HYDROLOGIC-Device-003",
        "zone": "kitchen",
        "display_name": "Kitchen & Laundry",
        "topic": "hydroficient/grandmarina/sensors/kitchen-laundry",
        "pressure_normal": (55, 64),
        "pressure_high": (66, 74),
        "pressure_anomaly_chance": 0.18,
        "pressure_drop": (4, 8),
        "flow_normal": (47, 58),
        "flow_low": (34, 44),
        "flow_anomaly_chance": 0.18,
        "gate_range": (52, 64),
    },
]

# =============================================================================
# REPLAY DEFENSE: Shared Secret for HMAC
# =============================================================================
# In production, this would be securely provisioned to each device.
# For this exercise, both publisher and subscriber use the same secret.
SHARED_SECRET = "grandmarina-hydroficient-2024-secret-key"


# =============================================================================
# REPLAY DEFENSE: Sequence Counters
# =============================================================================
# Each logical device has its own independent, incrementing sequence counter.
sequence_counters = {device["device_id"]: 0 for device in DEVICES}
total_messages_published = 0


# =============================================================================
# HMAC Computation
# =============================================================================
def compute_hmac(message_dict):
    """
    Compute HMAC-SHA256 for a message.

    Process:
    1. Copy the message (don't modify the original)
    2. Remove the 'hmac' field if present
    3. Sort the keys for consistent ordering
    4. Convert to a JSON string
    5. Sign with the shared secret

    Returns the HMAC as a hex string.
    """
    # Make a copy and remove hmac field
    msg_copy = {k: v for k, v in message_dict.items() if k != "hmac"}

    # Create a consistent string representation
    msg_string = json.dumps(msg_copy, sort_keys=True)

    # Compute HMAC-SHA256
    signature = hmac.new(
        SHARED_SECRET.encode("utf-8"),
        msg_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return signature


# =============================================================================
# Callbacks
# =============================================================================
def on_connect(client, userdata, flags, rc):
    """Called when connection is established."""
    if rc == 0:
        print(f"[SUCCESS] Connected to broker as {CLIENT_NAME}")
        print(f"[INFO] Replay defenses ACTIVE: timestamp + sequence + HMAC")
    else:
        print(f"[ERROR] Connection failed with code {rc}")


def on_disconnect(client, userdata, rc):
    """Called when disconnected from broker."""
    if rc == 0:
        print("[INFO] Clean disconnect")
    else:
        print(f"[WARNING] Unexpected disconnect (rc={rc})")


def on_publish(client, userdata, mid):
    """Called when a message is published."""
    pass  # Quiet — we print our own output below


# =============================================================================
# Sensor Data Generation (with replay defenses)
# =============================================================================
def generate_defended_reading(device_config=None):
    """
    Generate sensor data WITH replay attack defenses.

    New fields compared to publisher_mtls.py:
    - sequence: Incrementing counter (unique per message)
    - hmac: HMAC-SHA256 signature (proves authenticity)

    If no device profile is supplied, Main Building is used for backward
    compatibility with the original single-device function.
    """
    if device_config is None:
        device_config = DEVICES[0]

    device_id = device_config["device_id"]
    sequence_counters[device_id] += 1
    sequence = sequence_counters[device_id]

    # Each device independently decides whether to generate an anomaly. There
    # is no fixed cycle, device order, or scheduled anomaly type.
    pressure_range = (
        device_config["pressure_high"]
        if random.random() < device_config["pressure_anomaly_chance"]
        else device_config["pressure_normal"]
    )
    flow_range = (
        device_config["flow_low"]
        if random.random() < device_config["flow_anomaly_chance"]
        else device_config["flow_normal"]
    )

    pressure_upstream = round(random.uniform(*pressure_range), 2)
    pressure_drop = random.uniform(*device_config["pressure_drop"])
    pressure_downstream = round(max(0, pressure_upstream - pressure_drop), 2)
    flow_rate = round(random.uniform(*flow_range), 2)
    gate_a_position = round(random.uniform(*device_config["gate_range"]), 1)
    gate_b_position = round(random.uniform(*device_config["gate_range"]), 1)

    # Build the message using the same fields as the original publisher.
    message = {
        "device_id": device_id,
        "zone": device_config["zone"],
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sequence": sequence,
        "readings": {
            "pressure_upstream": pressure_upstream,
            "pressure_downstream": pressure_downstream,
            "flow_rate": flow_rate,
            "gate_a_position": gate_a_position,
            "gate_b_position": gate_b_position
        },
        "status": "operational"
    }

    # Compute and attach HMAC signature
    message["hmac"] = compute_hmac(message)

    return message


# =============================================================================
# Main
# =============================================================================
def main():
    global total_messages_published

    print("=" * 60)
    print("HYDROLOGIC Sensor Publisher (Defended)")
    print("=" * 60)
    print(f"Logical devices: {len(DEVICES)}")
    for device in DEVICES:
        print(f"  - {device['display_name']}: {device['topic']}")
    print(f"Certificate: {CLIENT_CERT}")
    print(f"Defenses: timestamp + sequence counter + HMAC-SHA256")
    print("=" * 60)

    # Create MQTT client
    client = mqtt.Client(client_id=CLIENT_NAME, **MQTT_CLIENT_ARGS)

    # Set up callbacks
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish

    # Configure mTLS (same as Project 5)
    try:
        client.tls_set(
            ca_certs=CA_CERT,
            certfile=CLIENT_CERT,
            keyfile=CLIENT_KEY,
            cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS
        )
    except FileNotFoundError as e:
        print(f"[ERROR] Certificate not found: {e}")
        print("[ERROR] Make sure your Project 5 certs/ directory is set up")
        return
    except Exception as e:
        print(f"[ERROR] TLS configuration failed: {e}")
        return

    # Connect to broker
    print(f"\n[CONNECTING] {BROKER_HOST}:{BROKER_PORT}...")
    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return

    # Start network loop
    client.loop_start()
    time.sleep(1)

    # Publish sensor readings
    print("\n[PUBLISHING] Sending defended readings (Ctrl+C to stop)...\n")
    try:
        while True:
            for device in DEVICES:
                reading = generate_defended_reading(device)
                payload = json.dumps(reading, indent=2)
                result = client.publish(device["topic"], payload, qos=1)
                result.wait_for_publish()
                total_messages_published += 1

                sensor = reading["readings"]
                seq = reading["sequence"]
                hmac_short = reading["hmac"][:12] + "..."
                print(
                    f"[{device['display_name']}] "
                    f"Pressure: {sensor['pressure_upstream']} PSI | "
                    f"Flow: {sensor['flow_rate']} LPM | "
                    f"seq={seq} | hmac={hmac_short}"
                )

                random_anomalies = []
                if sensor["pressure_upstream"] > 65:
                    random_anomalies.append("HIGH PRESSURE")
                if sensor["flow_rate"] < 45:
                    random_anomalies.append("LOW FLOW")

                if random_anomalies:
                    print(
                        f"  [RANDOM ANOMALY] {device['display_name']}: "
                        f"{' + '.join(random_anomalies)}"
                    )

            print(f"[CYCLE] Published all {len(DEVICES)} device readings\n")
            time.sleep(PUBLISH_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print(f"\n\n[INFO] Stopping after {total_messages_published} messages...")

    client.loop_stop()
    client.disconnect()
    print("[INFO] Disconnected from broker")


if __name__ == "__main__":
    main()
