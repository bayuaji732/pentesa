"""SSRF Canary Sensor Service for Pentesa Benchmark Environment.

Listens on port 9099. Logs all incoming requests with timestamp, client IP, method,
path, and headers. Serves as a trap sensor to verify SSRF detection and catch egress leaks.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("canary")


class CanaryHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._record_and_respond()

    def do_POST(self):
        self._record_and_respond()

    def _record_and_respond(self):
        ts = datetime.now(timezone.utc).isoformat()
        client_ip = self.client_address[0]
        event = {
            "timestamp": ts,
            "client_address": client_ip,
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers)
        }
        logger.warning(f"[CANARY_TRIGGER] Received connection: {json.dumps(event)}")

        response_body = json.dumps({
            "canary": "triggered",
            "message": "SSRF Canary Sensor Alert: Request logged successfully",
            "token": "CANARY_TOKEN_PENTESA_BENCH_SSRF_TRIGGERED_99a8"
        }).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("X-Canary-Sensor", "Pentesa-Bench-Trap")
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format, *args):
        pass


def run():
    server = HTTPServer(("0.0.0.0", 9099), CanaryHandler)
    logger.info("Canary sensor listening on 0.0.0.0:9099...")
    server.serve_forever()


if __name__ == "__main__":
    run()
