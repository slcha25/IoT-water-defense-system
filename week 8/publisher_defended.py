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
import os
import socket
import threading
from datetime import datetime, timezone

# Use the current callback API when paho-mqtt 2.x is installed.
try:
    MQTT_CLIENT_ARGS = {"callback_api_version": mqtt.CallbackAPIVersion.VERSION2}
except AttributeError:
    MQTT_CLIENT_ARGS = {}

# =============================================================================
# Configuration
# =============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BROKER_HOST = os.getenv("MQTT_HOST", "localhost")
# Windows has reserved port 8883 on this system, so Grand Marina mTLS uses
# 18884 by default. Set MQTT_PORT to override without editing this file.
BROKER_PORT = int(os.getenv("MQTT_PORT", "18884"))
CERT_DEVICE_ID = "001"

# Certificate files (same as Project 5)
CA_CERT = os.getenv("MQTT_CA_CERT", os.path.join(BASE_DIR, "certs", "ca.pem"))
CLIENT_CERT = os.getenv(
    "MQTT_CLIENT_CERT",
    os.path.join(BASE_DIR, "certs", f"device-{CERT_DEVICE_ID}.pem"),
)
CLIENT_KEY = os.getenv(
    "MQTT_CLIENT_KEY",
    os.path.join(BASE_DIR, "certs", f"device-{CERT_DEVICE_ID}-key.pem"),
)

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
# Start from the current UTC time in milliseconds. If the publisher restarts
# while the subscriber is still running, its new sequence remains greater than
# the previous run and is not incorrectly rejected as a replay.
sequence_start = int(time.time() * 1000)
sequence_counters = {
    device["device_id"]: sequence_start for device in DEVICES
}
total_messages_published = 0

# Connection state is set by the MQTT network callback.
connected_event = threading.Event()
connection_failed_event = threading.Event()


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
def on_connect(client, userdata, flags, reason_code, properties=None):
    """Called when connection is established."""
    if reason_code == 0:
        print(f"[SUCCESS] Connected to broker as {CLIENT_NAME}")
        print(f"[INFO] Replay defenses ACTIVE: timestamp + sequence + HMAC")
        connected_event.set()
    else:
        print(f"[ERROR] Broker rejected the MQTT connection: {reason_code}")
        connection_failed_event.set()


def on_disconnect(client, userdata, *args):
    """Called when disconnected from broker."""
    # VERSION1 provides rc; VERSION2 provides flags, reason_code, properties.
    reason_code = args[1] if len(args) >= 2 else (args[0] if args else 0)
    if reason_code == 0:
        print("[INFO] Clean disconnect")
    else:
        print(f"[WARNING] Unexpected disconnect ({reason_code})")


def on_publish(client, userdata, mid, *args):
    """Called when a message is published."""
    pass  # Quiet — we print our own output below


def create_tls_context():
    """Build a TLS 1.2+ context compatible with the legacy lab CA."""
    missing = [path for path in (CA_CERT, CLIENT_CERT, CLIENT_KEY) if not os.path.isfile(path)]
    if missing:
        raise FileNotFoundError("Missing certificate file(s): " + ", ".join(missing))

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)

    # Python/OpenSSL on newer Windows builds may enable strict RFC 5280
    # extension checking. The course certificates predate that requirement and
    # omit Authority Key Identifier, although their CA signatures remain valid.
    # Clear only the strict-extension flag; keep CERT_REQUIRED and hostname
    # verification enabled.
    strict_flag = getattr(ssl, "VERIFY_X509_STRICT", 0)
    if strict_flag and context.verify_flags & strict_flag:
        context.verify_flags &= ~strict_flag
        print(
            "[TLS COMPAT] Legacy certificate mode enabled "
            "(CA signature + hostname verification remain ON)"
        )
    return context


def verify_mtls_listener(context):
    """Confirm that the configured broker port serves TLS before MQTT connects."""
    try:
        with socket.create_connection((BROKER_HOST, BROKER_PORT), timeout=5) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=BROKER_HOST) as tls_socket:
                version = tls_socket.version()
                peer = tls_socket.getpeercert()
                subject = dict(item[0] for item in peer.get("subject", ()))
                print(
                    f"[mTLS PASS] Broker negotiated {version}; "
                    f"server={subject.get('commonName', 'certificate verified')}"
                )
                return True
    except ssl.SSLError as error:
        print(f"[mTLS ERROR] TLS handshake failed: {error}")
        if "WRONG_VERSION_NUMBER" in str(error).upper():
            print(
                f"[CAUSE] Port {BROKER_PORT} is open, but the process on that "
                "port is not using TLS/mTLS."
            )
            print("[FIX] Stop that process and start Mosquitto with mosquitto_mtls.conf.")
        else:
            print("[FIX] Check that server.pem matches localhost and all certificates use the same CA.")
        return False
    except ConnectionRefusedError:
        print(f"[mTLS ERROR] Nothing is listening on {BROKER_HOST}:{BROKER_PORT}.")
        print('[FIX] Start: mosquitto -c ".\\mosquitto_mtls.conf" -v')
        return False
    except (OSError, socket.timeout) as error:
        print(f"[mTLS ERROR] Cannot verify broker: {error}")
        return False


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
    print(f"Broker: {BROKER_HOST}:{BROKER_PORT} (mTLS required)")
    print(f"Certificate: {CLIENT_CERT}")
    print(f"Defenses: timestamp + sequence counter + HMAC-SHA256")
    print("=" * 60)

    # Create MQTT client
    client = mqtt.Client(client_id=CLIENT_NAME, **MQTT_CLIENT_ARGS)

    # Set up callbacks
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish

    # Configure mTLS and verify that the selected port is a TLS listener.
    try:
        tls_context = create_tls_context()
        if not verify_mtls_listener(tls_context):
            return
        client.tls_set_context(tls_context)
    except FileNotFoundError as e:
        print(f"[ERROR] Certificate not found: {e}")
        print(f"[ERROR] Expected certificate folder: {os.path.join(BASE_DIR, 'certs')}")
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

    # Start network loop, then wait for the MQTT CONNACK before publishing.
    client.loop_start()
    if not connected_event.wait(timeout=10):
        if not connection_failed_event.is_set():
            print("[ERROR] Timed out waiting for MQTT connection confirmation.")
        client.loop_stop()
        client.disconnect()
        return

    # Publish sensor readings
    print("\n[PUBLISHING] Sending defended readings (Ctrl+C to stop)...\n")
    try:
        while True:
            for device in DEVICES:
                reading = generate_defended_reading(device)
                payload = json.dumps(reading, indent=2)
                result = client.publish(device["topic"], payload, qos=1)
                if result.rc != mqtt.MQTT_ERR_SUCCESS:
                    raise RuntimeError(
                        f"Publish failed for {device['display_name']} (MQTT rc={result.rc})"
                    )
                result.wait_for_publish(timeout=10)
                if not result.is_published():
                    raise TimeoutError(
                        f"Broker did not acknowledge {device['display_name']} within 10 seconds"
                    )
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
    except (RuntimeError, TimeoutError) as error:
        print(f"\n[ERROR] {error}")

    client.loop_stop()
    client.disconnect()
    print("[INFO] Disconnected from broker")


if __name__ == "__main__":
    main()
