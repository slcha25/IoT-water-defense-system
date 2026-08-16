"""
subscriber_dashboard_ai.py - MQTT Subscriber with Replay Defenses + AI Anomaly Detection

Extends subscriber_dashboard.py (Project 7) with an Isolation Forest model
that scores every accepted message for anomalies. Messages that pass all
rule-based checks but trigger the AI model get an orange "FLAGGED" warning
on the dashboard instead of a red "BLOCKED" or green "ACCEPTED."

Architecture:
    Incoming Message → Rule Checks → FAIL → Red "BLOCKED"
                                   → PASS → AI Score → ANOMALY → Orange "FLAGGED"
                                                     → NORMAL  → Green "ACCEPTED"

Usage:
    python subscriber_dashboard_ai.py
"""

import paho.mqtt.client as mqtt
import ssl
import json
import hmac
import hashlib
import time
import threading
import numpy as np
import os
from pathlib import Path
import warnings
from datetime import datetime, timezone

try:
    import joblib
except ImportError:
    print("[ERROR] joblib not installed. Run: pip install joblib")
    exit(1)

# Import the dashboard server
from dashboard_server_ai import DashboardServer

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
# Windows has reserved 8883 on this system. Match mosquitto_mtls.conf, which
# now listens on 18884. MQTT_PORT can still override this default.
BROKER_PORT = int(os.getenv("MQTT_PORT", "18884"))
SUBSCRIBER_ID = "dashboard-ai"

# Certificate files (same as Project 5)
CA_CERT = os.getenv("MQTT_CA_CERT", os.path.join(BASE_DIR, "certs", "ca.pem"))
CLIENT_CERT = os.getenv("MQTT_CLIENT_CERT", os.path.join(BASE_DIR, "certs", "device-001.pem"))
CLIENT_KEY = os.getenv("MQTT_CLIENT_KEY", os.path.join(BASE_DIR, "certs", "device-001-key.pem"))

# Subscribe to all Grand Marina devices
TOPIC = "hydroficient/grandmarina/#"
CLIENT_NAME = "GrandMarina-Dashboard-AI"

# =============================================================================
# REPLAY DEFENSE: Shared Secret (must match publisher_defended.py)
# =============================================================================
SHARED_SECRET = "grandmarina-hydroficient-2024-secret-key"

# =============================================================================
# REPLAY DEFENSE: Configuration
# =============================================================================
MAX_AGE_SECONDS = 30  # Reject messages older than 30 seconds

# Track the last sequence number seen from each device
device_counters = {}

# Statistics
stats = {"accepted": 0, "rejected": 0, "ai_anomalies": 0}

# Dashboard server instance (initialized in main)
dashboard = None

# AI model (loaded in main)
ai_model = None
ai_model_status = "not_started"
ai_model_ready = threading.Event()

# =============================================================================
# AI Model: Feature Extraction
# =============================================================================
def resolve_ai_model_path():
    """Find the model in common project locations or use AI_MODEL_PATH."""
    configured_path = os.getenv("AI_MODEL_PATH")
    if configured_path:
        return Path(configured_path).expanduser().resolve()

    candidates = [
        Path(BASE_DIR) / "anomaly_model.joblib",
        Path(BASE_DIR) / "project-8-ai-anomaly-detection" / "anomaly_model.joblib",
        Path(BASE_DIR) / "project_8_ai_anomaly_detection" / "anomaly_model.joblib",
        Path(BASE_DIR).parent / "project-8-ai-anomaly-detection" / "anomaly_model.joblib",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return candidates[0].resolve()


AI_MODEL_PATH = resolve_ai_model_path()


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
            "[TLS COMPAT] Legacy certificate mode enabled "
            "(CA signature + hostname verification remain ON)"
        )
    return context


def load_ai_model_in_background():
    """Load and validate the model without blocking dashboard/MQTT startup."""
    global ai_model, ai_model_status

    if not AI_MODEL_PATH.is_file():
        ai_model_status = "not_found"
        print(f"AI Model:        {AI_MODEL_PATH} (NOT FOUND — AI scoring disabled)", flush=True)
        print("[WARNING] Put anomaly_model.joblib beside subscriber_dashboard_ai.py", flush=True)
        print("[WARNING] Or set: $env:AI_MODEL_PATH = 'C:\\full\\path\\anomaly_model.joblib'", flush=True)
        ai_model_ready.set()
        return

    ai_model_status = "loading"
    model_size_mb = AI_MODEL_PATH.stat().st_size / (1024 * 1024)
    print(
        f"AI Model:        Loading {AI_MODEL_PATH} ({model_size_mb:.1f} MB) in background...",
        flush=True,
    )
    started = time.monotonic()

    try:
        with warnings.catch_warnings(record=True) as caught_warnings:
            warnings.simplefilter("always")
            loaded_model = joblib.load(str(AI_MODEL_PATH))

        if not callable(getattr(loaded_model, "predict", None)):
            raise TypeError("Loaded object does not provide predict()")
        if not callable(getattr(loaded_model, "decision_function", None)):
            raise TypeError("Loaded object does not provide decision_function()")

        feature_count = getattr(loaded_model, "n_features_in_", len(FEATURE_NAMES))
        if feature_count != len(FEATURE_NAMES):
            raise ValueError(
                f"Model expects {feature_count} features, but subscriber provides "
                f"{len(FEATURE_NAMES)} ({', '.join(FEATURE_NAMES)})"
            )

        # Run a harmless sample through both APIs now, rather than discovering
        # a scikit-learn compatibility problem on the first live MQTT message.
        health_sample = np.array([[60.0, 50.0, 45.0]], dtype=float)
        loaded_model.predict(health_sample)
        loaded_model.decision_function(health_sample)

        ai_model = loaded_model
        ai_model_status = "ready"
        elapsed = time.monotonic() - started
        print(f"[AI READY] Model loaded and validated in {elapsed:.1f}s", flush=True)
        for warning_record in caught_warnings:
            if "version" in str(warning_record.message).lower():
                print(f"[AI WARNING] {warning_record.message}", flush=True)
                break
    except Exception as error:
        ai_model = None
        ai_model_status = "error"
        print(f"[AI ERROR] Model could not be loaded: {type(error).__name__}: {error}", flush=True)
        print("[AI FALLBACK] Dashboard will continue with HMAC, timestamp, and sequence checks.", flush=True)
    finally:
        ai_model_ready.set()


def report_slow_model_load():
    """Explain a slow load while allowing all other services to keep running."""
    if not ai_model_ready.wait(timeout=15):
        print(
            "[AI WARNING] Model is still loading after 15 seconds. MQTT and the "
            "dashboard remain active; readings use rule-based checks until it is ready.",
            flush=True,
        )

# Feature names must match the order used during training
FEATURE_NAMES = ["pressure_upstream", "flow_rate", "gate_a_position"]


def extract_features(readings):
    """
    Extract feature vector from sensor readings for AI scoring.
    Returns a numpy array shaped (1, n_features) ready for model.predict().

    We use three features because the Isolation Forest was trained on these same
    three values. The order must match: [pressure, flow, gate]. Using .get()
    with fallbacks handles both P5-style field names and P3-style field names.
    """
    features = [
        readings.get("pressure_upstream", readings.get("pressure_psi", 0)),
        readings.get("flow_rate", readings.get("flow_rate_lpm", 0)),
        readings.get("gate_a_position", readings.get("valve_position", 50)),
    ]
    return np.array([features])


def score_with_ai(readings):
    """
    Score sensor readings with the AI model.
    Returns (is_anomaly, score) where is_anomaly is True if flagged.
    """
    if ai_model is None:
        return False, 0.0

    features = extract_features(readings)
    prediction = ai_model.predict(features)       # 1 = normal, -1 = anomaly
    score = ai_model.decision_function(features)   # lower = more anomalous

    is_anomaly = prediction[0] == -1
    return is_anomaly, float(score[0])


# =============================================================================
# HMAC Verification (same as Project 6)
# =============================================================================
def verify_hmac(message_dict):
    """
    Verify the HMAC signature on a message.
    Returns (True, "") if valid, (False, reason) if invalid.
    """
    received_hmac = message_dict.get("hmac")
    if received_hmac is None:
        return False, "No HMAC field in message"

    msg_copy = {k: v for k, v in message_dict.items() if k != "hmac"}
    msg_string = json.dumps(msg_copy, sort_keys=True)

    expected_hmac = hmac.new(
        SHARED_SECRET.encode("utf-8"),
        msg_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    if hmac.compare_digest(received_hmac, expected_hmac):
        return True, ""
    else:
        return False, "HMAC mismatch"


# =============================================================================
# Timestamp Validation (same as Project 6)
# =============================================================================
def check_timestamp(message_dict):
    """
    Check if the message timestamp is within the acceptable window.
    Returns (True, age_seconds) if fresh, (False, age_seconds) if stale.
    """
    timestamp_str = message_dict.get("timestamp")
    if timestamp_str is None:
        return False, -1

    try:
        msg_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        age = (now - msg_time).total_seconds()

        if age <= MAX_AGE_SECONDS:
            return True, age
        else:
            return False, age
    except (ValueError, TypeError):
        return False, -1


# =============================================================================
# Sequence Counter Validation (same as Project 6)
# =============================================================================
def check_sequence(message_dict):
    """
    Check if the sequence number is higher than the last seen.
    Returns (True, "") if valid, (False, reason) if replay detected.
    """
    device_id = message_dict.get("device_id", "unknown")
    sequence = message_dict.get("sequence")

    if sequence is None:
        return False, "No sequence field in message"

    last_seen = device_counters.get(device_id, 0)

    if sequence > last_seen:
        device_counters[device_id] = sequence
        return True, ""
    else:
        return False, f"Sequence {sequence} <= last seen {last_seen}"


# =============================================================================
# Combined Validation (same as Project 6)
# =============================================================================
def validate_message(message_dict):
    """
    Run all three checks: HMAC -> Timestamp -> Sequence.
    Returns (True, results_dict) or (False, results_dict).
    """
    results = {
        "hmac": {"passed": False, "detail": ""},
        "timestamp": {"passed": False, "detail": ""},
        "sequence": {"passed": False, "detail": ""}
    }

    # Check 1: HMAC
    hmac_ok, hmac_reason = verify_hmac(message_dict)
    results["hmac"]["passed"] = hmac_ok
    results["hmac"]["detail"] = "Valid" if hmac_ok else hmac_reason
    if not hmac_ok:
        return False, results

    # Check 2: Timestamp freshness
    ts_ok, age = check_timestamp(message_dict)
    if age >= 0:
        results["timestamp"]["detail"] = f"Age: {age:.1f}s (max: {MAX_AGE_SECONDS}s)"
    else:
        results["timestamp"]["detail"] = "Missing or invalid timestamp"
    results["timestamp"]["passed"] = ts_ok
    if not ts_ok:
        return False, results

    # Check 3: Sequence counter
    seq_ok, seq_reason = check_sequence(message_dict)
    results["sequence"]["passed"] = seq_ok
    results["sequence"]["detail"] = "Valid (new sequence)" if seq_ok else seq_reason
    if not seq_ok:
        return False, results

    return True, results


# =============================================================================
# Callbacks
# =============================================================================
def on_connect(client, userdata, connect_flags, reason_code, properties=None):
    """Called when connection is established."""
    if reason_code == 0:
        print(f"[SUCCESS] Connected to broker as {CLIENT_NAME}")
        print(f"[INFO] Replay defenses ACTIVE")
        print(f"[INFO]   HMAC verification: ON")
        print(f"[INFO]   Timestamp window: {MAX_AGE_SECONDS} seconds")
        print(f"[INFO]   Sequence tracking: ON")
        print(
            f"[INFO]   AI anomaly detection: "
            f"{'ON' if ai_model_status == 'ready' else ai_model_status.upper()}"
        )
        print(f"[INFO]   Live dashboard: ON")
        print(f"[INFO] Subscribing to: {TOPIC}")
        client.subscribe(TOPIC, qos=1)
    else:
        print(f"[ERROR] Connection failed: {reason_code}")


def on_message(client, userdata, msg):
    """Called when a message is received. Validates, scores with AI, and pushes to dashboard."""
    try:
        data = json.loads(msg.payload.decode())

        # Run all rule-based validation checks
        accepted, results = validate_message(data)

        device = data.get("device_id", "Unknown")
        flow = data.get("readings", {}).get(
            "flow_rate", data.get("readings", {}).get("flow_rate_lpm", "N/A")
        )
        seq = data.get("sequence", "N/A")

        if accepted:
            # Rules first, then AI: rules block known-bad messages (red) before the AI
            # model ever sees them. AI only scores messages that passed all rule checks,
            # looking for subtle anomalies in the sensor values themselves (orange).
            sensor_data = data.get("readings", {})
            is_anomaly, ai_score = score_with_ai(sensor_data)

            if is_anomaly:
                stats["accepted"] += 1
                stats["ai_anomalies"] += 1

                # Print to terminal
                print(f"\n[AI ALERT] Device: {device} | Flow: {flow} LPM | Seq: {seq}")
                print(f"  HMAC: PASS | Timestamp: PASS | Sequence: PASS | AI: ANOMALY (score: {ai_score:.3f})")

                # Push AI anomaly to dashboard
                if dashboard:
                    dashboard.log_ai_anomaly(device, sensor_data, ai_score, msg.topic)
            else:
                stats["accepted"] += 1

                # Print to terminal
                print(f"\n[ACCEPTED] Device: {device} | Flow: {flow} LPM | Seq: {seq}")
                print(f"  HMAC: PASS | Timestamp: PASS | Sequence: PASS | AI: Normal (score: {ai_score:.3f})")

                # Push to dashboard
                if dashboard:
                    dashboard.log_valid_message(device, sensor_data, msg.topic)

        else:
            stats["rejected"] += 1

            # Find which check failed
            failed_check = "unknown"
            reason = "unknown"
            for check_name in ["hmac", "timestamp", "sequence"]:
                if not results[check_name]["passed"]:
                    failed_check = check_name.upper()
                    reason = results[check_name]["detail"]
                    break

            # Print to terminal
            print(f"\n[REJECTED] Device: {device} | Flow: {flow} LPM | Seq: {seq}")
            print(f"  Failed check: {failed_check}")
            print(f"  Reason: {reason}")

            # Push to dashboard
            if dashboard:
                attack_types = {
                    "HMAC": "Message Tampering",
                    "TIMESTAMP": "Stale Message",
                    "SEQUENCE": "Replay Attack"
                }
                attack_type = attack_types.get(failed_check, "Security Violation")
                dashboard.log_rejected_message(
                    reason, attack_type, device, msg.topic
                )

        # Show running stats
        total = stats["accepted"] + stats["rejected"]
        ai_str = f", {stats['ai_anomalies']} AI anomalies" if stats["ai_anomalies"] > 0 else ""
        print(f"  Stats: {stats['accepted']} accepted, {stats['rejected']} rejected{ai_str} ({total} total)")

    except json.JSONDecodeError:
        print(f"\n[REJECTED] Non-JSON message on {msg.topic}")
        stats["rejected"] += 1
        if dashboard:
            dashboard.log_rejected_message(
                "Invalid JSON", "Missing Fields", "unknown", msg.topic
            )


def on_subscribe(client, userdata, mid, reason_code_list, properties=None):
    """Called when subscription is confirmed."""
    print(f"[SUBSCRIBED] QoS granted: {reason_code_list}")


# =============================================================================
# Main
# =============================================================================
def main():
    global dashboard, ai_model

    print("=" * 60)
    print("Grand Marina Security Dashboard (AI-Enhanced)")
    print("=" * 60)

    print(f"Subscribing to:  {TOPIC}")
    print(f"Broker:          {BROKER_HOST}:{BROKER_PORT} (mTLS)")
    print(f"Certificate:     {CLIENT_CERT}")
    print(f"Max message age: {MAX_AGE_SECONDS} seconds")
    print(f"Dashboard:       http://localhost:8000")
    print("=" * 60)

    # ---- Start the dashboard server in a background thread ----
    dashboard = DashboardServer(html_file="dashboard.html")
    if not dashboard.check_port_available(dashboard.http_port):
        print("[ERROR] Port 8000 is already in use. Stop `python -m http.server 8000` or the old dashboard.")
        return
    if not dashboard.check_port_available(dashboard.ws_port):
        print("[ERROR] Port 8765 is already in use. Stop the old subscriber/dashboard process.")
        return

    def run_dashboard():
        try:
            dashboard.start(open_browser=True)
        except Exception as e:
            print(f"[ERROR] Dashboard server failed: {e}")

    dash_thread = threading.Thread(target=run_dashboard, daemon=True)
    dash_thread.start()
    time.sleep(2)  # give servers time to bind

    if not dash_thread.is_alive():
        print("[ERROR] Dashboard ports 8000/8765 are unavailable.")
        print("[ERROR] Stop the previous dashboard and `python -m http.server 8000`, then retry.")
        return

    # Load the model only after the dashboard is available. A slow or
    # incompatible joblib file must never prevent MQTT monitoring from starting.
    model_thread = threading.Thread(
        target=load_ai_model_in_background,
        name="ai-model-loader",
        daemon=True,
    )
    model_thread.start()
    threading.Thread(
        target=report_slow_model_load,
        name="ai-model-watchdog",
        daemon=True,
    ).start()

    # ---- Set up MQTT client ----
    client = mqtt.Client(client_id=CLIENT_NAME, **MQTT_CLIENT_ARGS)
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_subscribe = on_subscribe

    # Configure mTLS with legacy course-certificate compatibility.
    try:
        client.tls_set_context(create_tls_context())
    except FileNotFoundError as e:
        print(f"[ERROR] Certificate not found: {e}")
        print("[ERROR] Make sure your Project 5 certs/ directory is set up")
        return
    except Exception as e:
        print(f"[ERROR] TLS configuration failed: {e}")
        return

    print(f"\n[CONNECTING] {BROKER_HOST}:{BROKER_PORT}...")
    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return

    print("[LISTENING] Waiting for messages (Ctrl+C to stop)...\n")
    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print(f"\n\n[INFO] Shutting down...")
        print(f"[STATS] Accepted: {stats['accepted']} | Rejected: {stats['rejected']} | AI Anomalies: {stats['ai_anomalies']}")

    client.disconnect()
    print("[INFO] Disconnected from broker")


if __name__ == "__main__":
    main()
