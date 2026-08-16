"""
anomaly_injector.py - Subtle Anomaly Publisher for AI Detection Testing

Publishes MQTT messages with VALID HMAC signatures, fresh timestamps,
and proper sequence numbers — but with subtly abnormal sensor readings
that should pass all rule-based checks and trigger the AI model.

Anomaly types:
  1. High pressure (obstruction downstream — 63-70 PSI)
  2. Low pressure (supply failure — 50-57 PSI)
  3. Flow surge (possible leak — 56-65 LPM)
  4. Flow drop (blockage — 33-44 LPM)

Each test message uses a dedicated AI-test device identity. This prevents the
high test sequence numbers from advancing the replay counter for the real
Main Building, Pool & Spa, or Kitchen & Laundry publishers.

Usage:
    python anomaly_injector.py
"""

import paho.mqtt.client as mqtt
import ssl
import json
import hmac
import hashlib
import time
import sys
import os
import random
import threading
from datetime import datetime, timezone

# Fix Windows console encoding
if sys.platform == "win32":
    os.system("")
    sys.stdout.reconfigure(encoding="utf-8")

# Use the current callback API when paho-mqtt 2.x is installed.
try:
    MQTT_CLIENT_ARGS = {"callback_api_version": mqtt.CallbackAPIVersion.VERSION2}
except AttributeError:
    MQTT_CLIENT_ARGS = {}


# =============================================================================
# ANSI Colors
# =============================================================================
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    ORANGE = "\033[38;5;208m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# =============================================================================
# Configuration
# =============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BROKER_HOST = os.getenv("MQTT_HOST", "localhost")
BROKER_PORT = int(os.getenv("MQTT_PORT", "18884"))

# mTLS certificates (this is an insider — has valid creds)
CA_CERT = os.getenv("MQTT_CA_CERT", os.path.join(BASE_DIR, "certs", "ca.pem"))
CLIENT_CERT = os.getenv("MQTT_CLIENT_CERT", os.path.join(BASE_DIR, "certs", "device-001.pem"))
CLIENT_KEY = os.getenv("MQTT_CLIENT_KEY", os.path.join(BASE_DIR, "certs", "device-001-key.pem"))

# Dedicated logical identities keep anomaly-test sequence counters separate
# from the production device counters in subscriber_dashboard_ai.py.
TARGETS = [
    {
        "name": "Main Building",
        "zone": "main_building",
        "topic": "hydroficient/grandmarina/sensors/main-building",
        "device_id": "AI-TEST-MainBuilding",
    },
    {
        "name": "Pool & Spa",
        "zone": "pool_spa",
        "topic": "hydroficient/grandmarina/sensors/pool-spa",
        "device_id": "AI-TEST-PoolSpa",
    },
    {
        "name": "Kitchen & Laundry",
        "zone": "kitchen",
        "topic": "hydroficient/grandmarina/sensors/kitchen-laundry",
        "device_id": "AI-TEST-KitchenLaundry",
    },
]

# Shared secret (same as publisher_defended.py — this is the point)
SHARED_SECRET = "grandmarina-hydroficient-2024-secret-key"

# Independent, restart-safe counters for the dedicated AI test identities.
sequence_start = int(time.time() * 1000)
sequence_counters = {
    target["device_id"]: sequence_start for target in TARGETS
}
connected_event = threading.Event()
connection_failed_event = threading.Event()


def create_tls_context():
    """Build mTLS context while supporting the legacy course CA chain."""
    missing = [path for path in (CA_CERT, CLIENT_CERT, CLIENT_KEY) if not os.path.isfile(path)]
    if missing:
        raise FileNotFoundError("Missing certificate file(s): " + ", ".join(missing))

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)

    strict_flag = getattr(ssl, "VERIFY_X509_STRICT", 0)
    if strict_flag and context.verify_flags & strict_flag:
        context.verify_flags &= ~strict_flag
        print(
            f"{C.YELLOW}[TLS COMPAT]{C.RESET} Legacy certificate mode enabled "
            "(CA signature + hostname verification remain ON)"
        )
    return context


def on_connect(client, userdata, connect_flags, reason_code, properties=None):
    """Confirm the broker accepted this MQTT connection."""
    if reason_code == 0:
        connected_event.set()
    else:
        print(f"{C.RED}[ERROR] Broker rejected connection: {reason_code}{C.RESET}")
        connection_failed_event.set()


# =============================================================================
# HMAC Signing (identical to publisher_defended.py)
# =============================================================================
def sign_message(message_dict):
    """Sign a message with HMAC-SHA256. Returns the message with HMAC added."""
    msg_string = json.dumps(message_dict, sort_keys=True)
    signature = hmac.new(
        SHARED_SECRET.encode("utf-8"),
        msg_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    message_dict["hmac"] = signature
    return message_dict


# =============================================================================
# Anomaly Generators
# =============================================================================
class AnomalyGenerator:
    """Generates different types of subtle anomalies matching the training data."""

    def __init__(self):
        self.anomaly_count = 0

    def high_pressure(self):
        """Obstruction downstream — pressure above normal range (63-70 PSI)."""
        return {
            "pressure_upstream": round(random.uniform(63.0, 70.0), 2),
            "pressure_downstream": round(random.uniform(58.0, 65.0), 2),
            "flow_rate": round(random.uniform(48.0, 55.0), 2),
            "gate_a_position": round(random.uniform(42.0, 48.0), 2),
            "gate_b_position": round(random.uniform(42.0, 48.0), 2),
        }

    def low_pressure(self):
        """Supply failure — pressure below normal range (50-57 PSI)."""
        return {
            "pressure_upstream": round(random.uniform(50.0, 57.0), 2),
            "pressure_downstream": round(random.uniform(45.0, 52.0), 2),
            "flow_rate": round(random.uniform(48.0, 55.0), 2),
            "gate_a_position": round(random.uniform(42.0, 48.0), 2),
            "gate_b_position": round(random.uniform(42.0, 48.0), 2),
        }

    def flow_surge(self):
        """Possible leak — flow above normal range (56-65 LPM)."""
        return {
            "pressure_upstream": round(random.uniform(58.0, 62.0), 2),
            "pressure_downstream": round(random.uniform(53.0, 57.0), 2),
            "flow_rate": round(random.uniform(56.0, 65.0), 2),
            "gate_a_position": round(random.uniform(42.0, 48.0), 2),
            "gate_b_position": round(random.uniform(42.0, 48.0), 2),
        }

    def flow_drop(self):
        """Blockage — flow below normal range (33-44 LPM)."""
        return {
            "pressure_upstream": round(random.uniform(58.0, 62.0), 2),
            "pressure_downstream": round(random.uniform(53.0, 57.0), 2),
            "flow_rate": round(random.uniform(33.0, 44.0), 2),
            "gate_a_position": round(random.uniform(42.0, 48.0), 2),
            "gate_b_position": round(random.uniform(42.0, 48.0), 2),
        }

    def next_anomaly(self):
        """Choose a random anomaly type so the demo is not predictable."""
        generators = [
            ("High Pressure", self.high_pressure),
            ("Low Pressure", self.low_pressure),
            ("Flow Surge", self.flow_surge),
            ("Flow Drop", self.flow_drop),
        ]
        self.anomaly_count += 1
        name, gen = random.choice(generators)
        return name, gen()


# =============================================================================
# Publisher
# =============================================================================
def publish_anomaly(client, target, anomaly_type, readings):
    """Build a properly signed message with anomalous readings."""
    device_id = target["device_id"]
    sequence_counters[device_id] += 1
    sequence = sequence_counters[device_id]

    message = {
        "device_id": device_id,
        "zone": target["zone"],
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sequence": sequence,
        "readings": readings,
        "status": "operational",
        "test_metadata": {
            "source": "anomaly_injector",
            "anomaly_type": anomaly_type,
            "target_zone": target["name"],
        },
    }

    # Sign with the REAL shared secret — this will pass HMAC verification
    message = sign_message(message)

    payload = json.dumps(message)
    result = client.publish(target["topic"], payload, qos=1)
    if result.rc != mqtt.MQTT_ERR_SUCCESS:
        raise RuntimeError(f"MQTT publish failed with result code {result.rc}")
    result.wait_for_publish(timeout=10)
    if not result.is_published():
        raise TimeoutError("Broker did not acknowledge anomaly message within 10 seconds")

    return message


# =============================================================================
# Banner
# =============================================================================
def print_banner():
    print(f"""
{C.ORANGE}{C.BOLD}
    +===========================================================+
    |                                                             |
    |     A N O M A L Y   I N J E C T O R                       |
    |                                                             |
    |     Target: Grand Marina Hotel                             |
    |     Mode:   Subtle anomalies with VALID signatures         |
    |     Goal:   Test AI anomaly detection                      |
    |                                                             |
    +===========================================================+
{C.RESET}""")


# =============================================================================
# Main
# =============================================================================
def main():
    print_banner()

    print(f"{C.ORANGE}[INFO]{C.RESET} Testing all three hotel zones with dedicated AI-test identities")
    print(f"{C.ORANGE}[INFO]{C.RESET} and subtly abnormal sensor readings.")
    print(f"{C.ORANGE}[INFO]{C.RESET} Rule-based checks will PASS. The AI model should flag them.")
    print(f"{C.ORANGE}[INFO]{C.RESET} Uses device-001 certs for mTLS (cert authenticates TLS, not payload)")
    print()

    # Connect with mTLS
    client = mqtt.Client(
        client_id=f"anomaly-injector-{os.getpid()}", **MQTT_CLIENT_ARGS
    )
    client.on_connect = on_connect

    try:
        client.tls_set_context(create_tls_context())
    except FileNotFoundError as e:
        print(f"{C.RED}[ERROR] Certificate not found: {e}{C.RESET}")
        print("[ERROR] Make sure your Project 5 certs/ directory is set up")
        return

    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        client.loop_start()
    except Exception as e:
        print(f"{C.RED}[ERROR] Connection failed: {e}{C.RESET}")
        return

    if not connected_event.wait(timeout=10):
        if not connection_failed_event.is_set():
            print(f"{C.RED}[ERROR] Timed out waiting for MQTT CONNACK{C.RESET}")
        client.loop_stop()
        client.disconnect()
        return

    print(f"{C.GREEN}[CONNECTED]{C.RESET} {BROKER_HOST}:{BROKER_PORT}")
    print(f"{C.GREEN}[TOPICS]{C.RESET}    hydroficient/grandmarina/sensors/#")
    print(f"{C.ORANGE}[SENDING]{C.RESET}   Anomalies every 3 seconds (Ctrl+C to stop)")
    print()

    generator = AnomalyGenerator()

    try:
        while True:
            target = random.choice(TARGETS)
            anomaly_type, readings = generator.next_anomaly()
            message = publish_anomaly(client, target, anomaly_type, readings)

            pressure = readings["pressure_upstream"]
            flow = readings["flow_rate"]
            gate = readings["gate_a_position"]
            seq = message["sequence"]

            print(f"{C.ORANGE}[ANOMALY]{C.RESET} {target['name']} · {anomaly_type}")
            print(f"  Seq: {seq} | Pressure: {pressure} PSI | Flow: {flow} LPM | Gate: {gate}%")
            print(f"  HMAC: {C.GREEN}VALID{C.RESET} | Timestamp: {C.GREEN}FRESH{C.RESET} | Sequence: {C.GREEN}NEW{C.RESET}")
            print(f"  {C.DIM}(All rule checks will pass — only AI should flag this){C.RESET}")
            print()

            time.sleep(3)

    except KeyboardInterrupt:
        print(f"\n{C.ORANGE}[INFO]{C.RESET} Stopping anomaly injector...")
        print(f"{C.ORANGE}[STATS]{C.RESET} Published {generator.anomaly_count} anomalous messages")
        print()
        print(f"{C.CYAN}Check the dashboard:{C.RESET}")
        print(f"  - {C.GREEN}Green{C.RESET} messages = normal publisher data (rules + AI passed)")
        print(f"  - {C.ORANGE}Orange{C.RESET} messages = anomaly injector data (rules passed, AI flagged)")
        print(f"  - {C.RED}Red{C.RESET} messages = attack simulator data (rules blocked)")
        print()
    except (RuntimeError, TimeoutError) as error:
        print(f"{C.RED}[ERROR] {error}{C.RESET}")

    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
