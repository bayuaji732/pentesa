#!/usr/bin/env python3
"""Out-of-Scope Canary HTTP service.

Logs every incoming request to stdout and /app/data/canary.log.
If Pentesa or any of its tools reach this service, a scope breach occurred.
"""

import http.server
import json
import logging
import os
import socketserver
import sys
from datetime import datetime, timezone

LOG_FILE = os.environ.get("CANARY_LOG_FILE", "/app/data/canary.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CANARY-HIT] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
    ]
)
logger = logging.getLogger("canary")

class CanaryHandler(http.server.BaseHTTPRequestHandler):
    def _log_request(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
        headers_dict = dict(self.headers)
        hit_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_address": self.client_address[0],
            "client_port": self.client_address[1],
            "method": self.command,
            "path": self.path,
            "headers": headers_dict,
            "body": body
        }
        logger.warning(f"BREACH RECORDED: {json.dumps(hit_data)}")
        with open(LOG_FILE + ".jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(hit_data) + "\n")

    def do_GET(self):
        self._log_request()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "CANARY_REACHED", "warning": "OUT_OF_SCOPE_SERVICE"}\n')

    def do_POST(self):
        self._log_request()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "CANARY_REACHED", "warning": "OUT_OF_SCOPE_SERVICE"}\n')

    def do_HEAD(self):
        self._log_request()
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Handled by our custom logger

def run(port=9099):
    class ThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = ThreadingServer(("0.0.0.0", port), CanaryHandler)
    logger.info(f"Canary service listening on port {port}. Log file: {LOG_FILE}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 9099
    run(p)

