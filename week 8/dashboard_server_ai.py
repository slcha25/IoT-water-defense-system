"""
dashboard_server_ai.py - WebSocket + HTTP Server for the AI-Enhanced Dashboard

Extends dashboard_server.py (Project 7) with AI anomaly event support.
Adds log_ai_anomaly() method that pushes orange warning events to the
browser dashboard.

Components:
    HTTP server  (port 8000) - serves the configured dashboard HTML
    WebSocket    (port 8765) - pushes events to the browser

Usage:
    # As a module (imported by subscriber_dashboard_ai.py)
    from dashboard_server_ai import DashboardServer
    dashboard = DashboardServer(html_file="dashboard.html")
"""

import asyncio
import websockets
import json
import threading
import time
from typing import Set
import logging
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
import webbrowser
import socket

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - DASHBOARD - %(message)s"
)
logger = logging.getLogger(__name__)


class DashboardServer:
    """WebSocket server that pushes MQTT events to the browser dashboard."""

    def __init__(self, ws_port=8765, http_port=8000, html_file="dashboard.html"):
        self.ws_port = ws_port
        self.http_port = http_port
        self.html_file = html_file
        self.connected_clients: Set = set()
        self._loop = None
        self.stats = {
            "total": 0,
            "valid": 0,
            "rejected": 0,
            "ai_anomalies": 0
        }

    # -----------------------------------------------------------------
    # WebSocket client management
    # -----------------------------------------------------------------
    async def register_client(self, websocket):
        """Register a new browser connection."""
        self.connected_clients.add(websocket)
        logger.info(
            f"Dashboard client connected. "
            f"Total clients: {len(self.connected_clients)}"
        )
        await self._send(websocket, {
            "type": "stats_update",
            "data": self.stats
        })

    async def unregister_client(self, websocket):
        self.connected_clients.discard(websocket)
        logger.info(
            f"Dashboard client disconnected. "
            f"Total clients: {len(self.connected_clients)}"
        )

    async def _send(self, websocket, message):
        try:
            await websocket.send(json.dumps(message))
        except websockets.exceptions.ConnectionClosed:
            await self.unregister_client(websocket)
        except Exception as e:
            logger.error(f"Error sending to client: {e}")

    async def broadcast(self, message):
        """Send a message to every connected browser."""
        if not self.connected_clients:
            return
        disconnected = set()
        for ws in self.connected_clients.copy():
            try:
                await ws.send(json.dumps(message))
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(ws)
            except Exception as e:
                logger.error(f"Broadcast error: {e}")
                disconnected.add(ws)
        for ws in disconnected:
            self.connected_clients.discard(ws)

    async def handle_client(self, websocket):
        """Handle a single browser WebSocket connection."""
        await self.register_client(websocket)
        try:
            async for raw in websocket:
                try:
                    data = json.loads(raw)
                    if data.get("type") == "ping":
                        await self._send(websocket, {"type": "pong"})
                except json.JSONDecodeError:
                    pass
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.unregister_client(websocket)

    # -----------------------------------------------------------------
    # Public API — called from the subscriber (sync context)
    # -----------------------------------------------------------------
    def log_valid_message(self, device_id, sensor_data, topic=""):
        """Called when a message passes all checks (rules + AI)."""
        self.stats["total"] += 1
        self.stats["valid"] += 1

        message = {
            "type": "valid_message",
            "data": {
                "device_id": device_id,
                "topic": topic,
                "timestamp": time.strftime("%H:%M:%S"),
                "pressure_psi": sensor_data.get("pressure_upstream",
                                sensor_data.get("pressure_psi", 0)),
                "flow_rate_lpm": sensor_data.get("flow_rate",
                                 sensor_data.get("flow_rate_lpm", 0)),
                "valve_position": sensor_data.get("gate_a_position",
                                  sensor_data.get("valve_position", 50)),
                "zone": self._zone_from_topic(topic)
            }
        }
        self._schedule_broadcast(message)
        logger.info(f"Valid message from {device_id}")

    def log_rejected_message(self, reason, attack_type, source, topic=""):
        """Called when a message fails rule-based validation."""
        self.stats["total"] += 1
        self.stats["rejected"] += 1

        message = {
            "type": "rejected_message",
            "data": {
                "attack_type": attack_type,
                "source": source,
                "topic": topic,
                "reasons": [reason],
                "timestamp": time.strftime("%H:%M:%S"),
                "description": self._describe_attack(attack_type)
            }
        }
        self._schedule_broadcast(message)
        logger.info(f"REJECTED: {attack_type} from {source}")

    def log_ai_anomaly(self, device_id, sensor_data, ai_score, topic=""):
        """Called when a message passes rules but is flagged by the AI model."""
        self.stats["total"] += 1
        self.stats["valid"] += 1  # it passed rules, so it counts as accepted
        self.stats["ai_anomalies"] += 1

        pressure = sensor_data.get("pressure_upstream",
                   sensor_data.get("pressure_psi", 0))
        flow = sensor_data.get("flow_rate",
               sensor_data.get("flow_rate_lpm", 0))
        gate = sensor_data.get("gate_a_position",
               sensor_data.get("valve_position", 50))

        # Describe the anomaly based on the readings
        anomaly_desc = self._describe_anomaly(pressure, flow, gate)

        message = {
            "type": "ai_anomaly",
            "data": {
                "device_id": device_id,
                "topic": topic,
                "timestamp": time.strftime("%H:%M:%S"),
                "pressure_psi": pressure,
                "flow_rate_lpm": flow,
                "valve_position": gate,
                "ai_score": round(ai_score, 3),
                "anomaly_description": anomaly_desc,
                "zone": self._zone_from_topic(topic)
            }
        }
        self._schedule_broadcast(message)
        logger.info(f"AI ANOMALY from {device_id} (score: {ai_score:.3f})")

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------
    def _schedule_broadcast(self, message):
        """Bridge from sync caller to async WebSocket broadcast."""
        if self._loop is None:
            return
        try:
            asyncio.run_coroutine_threadsafe(
                self.broadcast(message), self._loop
            )
        except Exception as e:
            logger.error(f"Failed to broadcast: {e}")

    @staticmethod
    def _zone_from_topic(topic):
        topic = (topic or "").lower()
        if "pool" in topic or "spa" in topic:
            return "pool_spa"
        if "kitchen" in topic or "laundry" in topic:
            return "kitchen"
        return "main_building"

    @staticmethod
    def _describe_attack(attack_type):
        descriptions = {
            "Message Tampering":
                "HMAC mismatch — message contents were altered",
            "Replay Attack":
                "Sequence number already seen — duplicate message blocked",
            "Stale Message":
                "Timestamp too old — message outside freshness window",
            "Missing Fields":
                "Required security fields absent from message",
        }
        return descriptions.get(attack_type, "Security violation detected")

    @staticmethod
    def _describe_anomaly(pressure, flow, gate):
        """Generate a human-readable description of why the AI flagged this."""
        reasons = []
        if pressure > 62:
            reasons.append(f"high pressure ({pressure:.1f} PSI)")
        elif pressure < 58:
            reasons.append(f"low pressure ({pressure:.1f} PSI)")
        if flow > 55:
            reasons.append(f"high flow ({flow:.1f} LPM)")
        elif flow < 45:
            reasons.append(f"low flow ({flow:.1f} LPM)")

        if reasons:
            return "Unusual pattern: " + ", ".join(reasons)
        return "Unusual sensor combination detected"

    # -----------------------------------------------------------------
    # Server startup
    # -----------------------------------------------------------------
    def _start_websocket_server(self):
        """Run the async WebSocket server (blocking — run in a thread)."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop

        async def serve():
            async with websockets.serve(
                self.handle_client, "localhost", self.ws_port
            ):
                logger.info(
                    f"WebSocket server running on ws://localhost:{self.ws_port}"
                )
                await asyncio.Future()  # run forever

        loop.run_until_complete(serve())

    def _start_http_server(self):
        """Serve the configured dashboard HTML on the HTTP port."""
        serve_dir = os.path.dirname(os.path.abspath(__file__))
        html_file = self.html_file

        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=serve_dir, **kwargs)

            def do_GET(self):
                if self.path in ("/", "/dashboard"):
                    self.path = "/" + html_file
                super().do_GET()

            def log_message(self, fmt, *args):
                pass

        server = HTTPServer(("localhost", self.http_port), Handler)
        logger.info(f"HTTP server running on http://localhost:{self.http_port}")
        server.serve_forever()

    def start(self, open_browser=True):
        """Start both HTTP and WebSocket servers."""
        logger.info("Starting AI-Enhanced Dashboard Server...")

        http_thread = threading.Thread(
            target=self._start_http_server, daemon=True
        )
        http_thread.start()

        if open_browser:
            time.sleep(0.5)
            webbrowser.open(f"http://localhost:{self.http_port}")

        # WebSocket server (blocking)
        self._start_websocket_server()

    @staticmethod
    def check_port_available(port):
        """Return False with a clear log message when a dashboard port is busy."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("localhost", port))
            except OSError:
                logger.error(
                    f"Port {port} is already in use. Stop the old dashboard "
                    "or standalone `python -m http.server` process first."
                )
                return False
        return True


if __name__ == "__main__":
    server = DashboardServer()
    if server.check_port_available(server.http_port) and server.check_port_available(server.ws_port):
        server.start(open_browser=True)
