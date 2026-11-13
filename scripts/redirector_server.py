#!/usr/bin/env python3
"""In-Scope Redirector HTTP service.

Answers HTTP 302 Found redirecting to the out-of-scope Canary service.
Used to test whether HTTP clients and tool subprocesses (nuclei/ffuf)
blindly follow redirects into out-of-scope targets.
"""

import http.server
import logging
import os
import socketserver
import sys

CANARY_URL = os.environ.get("CANARY_URL", "http://canary:9099/canary-trap")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [REDIRECTOR] %(message)s"
)
logger = logging.getLogger("redirector")

class RedirectorHandler(http.server.BaseHTTPRequestHandler):
    def _redirect(self):
        logger.info(f"Received {self.command} {self.path} from {self.client_address[0]}. Redirecting (302) to {CANARY_URL}")
        self.send_response(302)
        self.send_header("Location", CANARY_URL)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"Redirecting to {CANARY_URL}\n".encode("utf-8"))

    def do_GET(self):
        self._redirect()

    def do_POST(self):
        self._redirect()

    def do_HEAD(self):
        self._redirect()

    def log_message(self, format, *args):
        pass

def run(port=9098):
    class ThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = ThreadingServer(("0.0.0.0", port), RedirectorHandler)
    logger.info(f"Redirector service listening on port {port}. Destination: {CANARY_URL}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 9098
    run(p)

