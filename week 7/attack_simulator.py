"""
attack_simulator.py - Three-Phase Attack Demonstration

Runs a theatrical attack sequence against all three Grand Marina devices in
the defended MQTT pipeline. Every injection and replay should be BLOCKED by
the subscriber's validation checks (HMAC, timestamp, sequence counter).

Phases:
  1. Eavesdrop   - subscribe to the topic and display intercepted messages
  2. Inject      - publish a message with a fake HMAC signature
  3. Replay      - re-send a captured message (stale timestamp + old sequence)

The dashboard will show each blocked attack in real time with red alerts.

Usage:
    python attack_simulator.py
"""

import paho.mqtt.client as mqtt
import ssl
import json
import time
import hmac
import hashlib
import sys
import os
import copy
from datetime import datetime, timezone

# Fix Windows console encoding for Unicode / ANSI colors
if sys.platform == "win32":
    os.system("")  # enable ANSI escape codes on Windows
    sys.stdout.reconfigure(encoding="utf-8")

# Handle paho-mqtt 2.0+ API change
try:
    MQTT_CLIENT_ARGS = {"callback_api_version": mqtt.CallbackAPIVersion.VERSION1}
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
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# =============================================================================
# Configuration
# =============================================================================
BROKER_HOST = "localhost"
BROKER_PORT = 8883

# mTLS certificates (attacker has valid credentials — insider threat)
CA_CERT = "certs/ca.pem"
CLIENT_CERT = "certs/device-001.pem"
CLIENT_KEY = "certs/device-001-key.pem"

# The attacker targets all three logical hotel sensors through one valid mTLS
# credential, simulating an insider threat or a compromised trusted client.
TARGETS = [
    {
        "device_id": "HYDROLOGIC-Device-001",
        "zone": "main_building",
        "display_name": "Main Building",
        "topic": "hydroficient/grandmarina/sensors/main-building",
    },
    {
        "device_id": "HYDROLOGIC-Device-002",
        "zone": "pool_spa",
        "display_name": "Pool & Spa",
        "topic": "hydroficient/grandmarina/sensors/pool-spa",
    },
    {
        "device_id": "HYDROLOGIC-Device-003",
        "zone": "kitchen",
        "display_name": "Kitchen & Laundry",
        "topic": "hydroficient/grandmarina/sensors/kitchen-laundry",
    },
]

# Used only to build a validly signed stale fallback message for the replay
# demonstration. It must match publisher_defended.py and the subscriber.
SHARED_SECRET = "grandmarina-hydroficient-2024-secret-key"


# =============================================================================
# Helpers
# =============================================================================
def type_effect(text, delay=0.03, color=C.GREEN):
    """Print text with a typewriter effect."""
    for ch in text:
        sys.stdout.write(f"{color}{ch}{C.RESET}")
        sys.stdout.flush()
        time.sleep(delay)
    print()


def status(prefix, message, color=C.GREEN):
    """Print a bracketed status line."""
    print(f"{color}[{prefix}]{C.RESET} {message}")


def section_header(title):
    print(f"\n{C.CYAN}{'=' * 55}")
    print(f"        {title}")
    print(f"{'=' * 55}{C.RESET}\n")


def compute_hmac(message_dict):
    """Compute the same HMAC-SHA256 signature used by the defended publisher."""
    msg_copy = {k: v for k, v in message_dict.items() if k != "hmac"}
    msg_string = json.dumps(msg_copy, sort_keys=True)
    return hmac.new(
        SHARED_SECRET.encode("utf-8"),
        msg_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# =============================================================================
# Attack Simulator
# =============================================================================
class AttackSimulator:
    def __init__(self):
        self.client = None
        self.intercepted = []

    # --- connection ---
    def connect(self):
        self.client = mqtt.Client(
            client_id="attack-simulator", **MQTT_CLIENT_ARGS
        )
        self.client.on_message = self._on_message

        try:
            self.client.tls_set(
                ca_certs=CA_CERT,
                certfile=CLIENT_CERT,
                keyfile=CLIENT_KEY,
                cert_reqs=ssl.CERT_REQUIRED,
                tls_version=ssl.PROTOCOL_TLS,
            )
        except FileNotFoundError as e:
            print(f"{C.RED}[ERROR] Certificate not found: {e}{C.RESET}")
            print("[ERROR] Make sure your Project 5 certs/ directory is set up")
            return False

        status("*", "Scanning for MQTT broker...", C.YELLOW)
        time.sleep(1)

        try:
            self.client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
            self.client.loop_start()
        except Exception as e:
            status("-", f"Connection failed: {e}", C.RED)
            return False

        status("+", f"Connected to {BROKER_HOST}:{BROKER_PORT}", C.RED)
        return True

    def disconnect(self):
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()

    def _on_message(self, client, userdata, msg):
        try:
            data = json.loads(msg.payload.decode())
            self.intercepted.append({
                "topic": msg.topic,
                "payload": data,
                "raw": msg.payload.decode(),
                "time": datetime.now().strftime("%H:%M:%S"),
            })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # PHASE 1: Eavesdrop
    # ------------------------------------------------------------------
    def phase_eavesdrop(self, duration=8):
        section_header("PHASE 1: EAVESDROPPING")
        type_effect("Subscribing to hydroficient/grandmarina/#...", 0.02, C.YELLOW)

        self.client.subscribe("hydroficient/grandmarina/#")
        time.sleep(0.5)

        status("+", "Now intercepting ALL hotel water system messages...", C.RED)
        print()

        start = time.time()
        shown = 0

        while time.time() - start < duration:
            if len(self.intercepted) > shown:
                msg = self.intercepted[shown]
                self._display_intercepted(msg)
                shown += 1
            time.sleep(0.3)

        if shown == 0:
            status(
                "!",
                "No messages intercepted yet. Is publisher_defended.py running?",
                C.YELLOW,
            )

        print(f"\n{C.DIM}Captured {len(self.intercepted)} messages.{C.RESET}\n")

    def _display_intercepted(self, msg):
        readings = msg["payload"].get("readings", msg["payload"])
        device = msg["payload"].get("device_id", "Unknown")
        zone = msg["payload"].get("zone", "unknown")
        pressure = readings.get("pressure_upstream",
                   readings.get("pressure_psi", "N/A"))
        flow = readings.get("flow_rate",
               readings.get("flow_rate_gpm", "N/A"))

        print(f"{C.DIM}+------------- {C.RED}INTERCEPTED{C.DIM} --------------+{C.RESET}")
        print(f"{C.DIM}|{C.RESET}  Device:   {C.WHITE}{device}{C.RESET}")
        print(f"{C.DIM}|{C.RESET}  Zone:     {C.WHITE}{zone}{C.RESET}")
        print(f"{C.DIM}|{C.RESET}  Topic:    {C.CYAN}{msg['topic']}{C.RESET}")
        print(f"{C.DIM}|{C.RESET}  Pressure: {C.YELLOW}{pressure} PSI{C.RESET}")
        print(f"{C.DIM}|{C.RESET}  Flow:     {C.YELLOW}{flow} LPM{C.RESET}")
        print(f"{C.DIM}|{C.RESET}  Time:     {C.WHITE}{msg['time']}{C.RESET}")
        print(f"{C.DIM}+-------------------------------------------+{C.RESET}")
        print()

    # ------------------------------------------------------------------
    # PHASE 2: Inject fake data (wrong HMAC)
    # ------------------------------------------------------------------
    def phase_inject(self):
        section_header("PHASE 2: DATA INJECTION")
        type_effect("Crafting fake readings for all three zones...", 0.02, C.YELLOW)
        time.sleep(0.5)

        for index, target in enumerate(TARGETS, start=1):
            fake_message = {
                "device_id": target["device_id"],
                "zone": target["zone"],
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "sequence": 99000 + index,
                "readings": {
                    "pressure_upstream": 250.0,   # dangerously high
                    "pressure_downstream": 240.0,
                    "flow_rate": 0.0,             # no flow
                    "gate_a_position": 100.0,
                    "gate_b_position": 100.0,
                },
                "status": "operational",
                "hmac": "FAKE_HMAC_0000000000000000000000000000000000000000",
            }

            result = self.client.publish(
                target["topic"], json.dumps(fake_message), qos=1
            )
            result.wait_for_publish()
            status(
                "!",
                f"{target['display_name']}: sent pressure = 250 PSI with fake HMAC",
                C.RED,
            )
            time.sleep(0.4)

        status("!", "All three injections should be rejected: HMAC mismatch", C.YELLOW)
        print()
        time.sleep(2)

    # ------------------------------------------------------------------
    # PHASE 3: Replay captured message
    # ------------------------------------------------------------------
    def phase_replay(self):
        section_header("PHASE 3: REPLAY ATTACK")

        type_effect("Replaying one message against each hotel zone...", 0.02, C.YELLOW)
        time.sleep(0.5)

        captured_by_topic = {}
        target_topics = {target["topic"] for target in TARGETS}
        for captured in self.intercepted:
            if (
                captured["topic"] in target_topics
                and captured["topic"] not in captured_by_topic
                and captured["payload"].get("hmac")
                == compute_hmac(captured["payload"])
            ):
                captured_by_topic[captured["topic"]] = captured

        for target in TARGETS:
            captured = captured_by_topic.get(target["topic"])

            if captured:
                result = self.client.publish(
                    captured["topic"], captured["raw"], qos=1
                )
                result.wait_for_publish()
                status(
                    "!",
                    f"{target['display_name']}: replayed captured message",
                    C.RED,
                )
            else:
                # Build a stale but correctly signed message. HMAC therefore
                # passes and the timestamp defense is what rejects the replay.
                stale_message = {
                    "device_id": target["device_id"],
                    "zone": target["zone"],
                    "timestamp": "2024-01-01T00:00:00Z",
                    "sequence": 1,
                    "readings": {
                        "pressure_upstream": 60.0,
                        "pressure_downstream": 55.0,
                        "flow_rate": 50.0,
                        "gate_a_position": 45.0,
                        "gate_b_position": 45.0,
                    },
                    "status": "operational",
                }
                stale_message["hmac"] = compute_hmac(stale_message)
                result = self.client.publish(
                    target["topic"], json.dumps(stale_message), qos=1
                )
                result.wait_for_publish()
                status(
                    "!",
                    f"{target['display_name']}: sent correctly signed stale message",
                    C.RED,
                )

            time.sleep(0.4)

        status(
            "!",
            "All three replays should be rejected: stale timestamp or duplicate sequence",
            C.YELLOW,
        )

        print()
        time.sleep(2)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    def summary(self):
        print(f"\n{C.RED}{C.BOLD}")
        print("    +===================================================+")
        print("    |                                                     |")
        print("    |     ATTACK SEQUENCE COMPLETE                       |")
        print("    |                                                     |")
        print("    |     Check the dashboard — were attacks blocked?    |")
        print("    |                                                     |")
        print("    +===================================================+")
        print(f"{C.RESET}")

        print(f"{C.CYAN}Expected results:{C.RESET}")
        print(f"  Phase 1 (Eavesdrop):  Messages visible — TLS protects the")
        print(f"                        wire, but this attacker has mTLS certs.")
        print(f"  Phase 2 (Inject):     {C.GREEN}BLOCKED x3{C.RESET} — HMAC mismatch")
        print(f"  Phase 3 (Replay):     {C.GREEN}BLOCKED x3{C.RESET} — stale timestamp or duplicate sequence")
        print()
        print(f"{C.YELLOW}If the subscriber accepted any attacks, the defenses have a gap.{C.RESET}")
        print(f"{C.YELLOW}If ALL were blocked, your pipeline is secure.{C.RESET}\n")


# =============================================================================
# Banner
# =============================================================================
def print_banner():
    print(f"""
{C.RED}{C.BOLD}
    +===========================================================+
    |                                                             |
    |     A T T A C K   S I M U L A T O R                       |
    |                                                             |
    |     Target: Grand Marina Hotel                             |
    |     System: Water Monitoring Pipeline                      |
    |     Scope:  Main, Pool/Spa, Kitchen/Laundry               |
    |     Mode:   Three-Phase Attack Sequence                    |
    |                                                             |
    +===========================================================+
{C.RESET}""")
    time.sleep(1)


# =============================================================================
# Main
# =============================================================================
def main():
    print_banner()

    attacker = AttackSimulator()
    if not attacker.connect():
        print(f"{C.RED}Failed to connect. Is the mTLS broker running?{C.RESET}")
        return

    print()
    time.sleep(1)

    try:
        # Phase 1: Eavesdrop
        attacker.phase_eavesdrop(duration=8)

        # Phase 2: Inject fake data
        attacker.phase_inject()

        # Phase 3: Replay
        attacker.phase_replay()

        # Summary
        attacker.summary()

    finally:
        attacker.disconnect()


if __name__ == "__main__":
    main()
