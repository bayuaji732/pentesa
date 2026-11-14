"""Test nuclei redirect behavior with and without -dr flag."""

import http.server
import os
import subprocess
import threading
import time

canary_hits = 0
redirector_hits = 0

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global canary_hits, redirector_hits
        if self.path == '/redirect':
            redirector_hits += 1
            self.send_response(302)
            self.send_header('Location', f'http://127.0.0.1:{server.server_port}/canary')
            self.end_headers()
        elif self.path == '/canary':
            canary_hits += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'CANARY_TRIGGERED')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
port = server.server_port
t = threading.Thread(target=server.serve_forever, daemon=True)
t.start()

tpl_path = "/tmp/test_redirect_tpl.yaml"
tpl_content = """id: test-internal-redirect
info:
  name: Test Redirect
  author: audit
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/redirect"
    redirects: true
    matchers:
      - type: status
        status:
          - 200
"""
with open(tpl_path, "w") as f:
    f.write(tpl_content)

print(f"Redirect test server listening on 127.0.0.1:{port}")

# Test 1: Run nuclei WITHOUT -dr
canary_hits = 0
redirector_hits = 0
proc1 = subprocess.run(
    ["nuclei", "-target", f"http://127.0.0.1:{port}", "-t", tpl_path, "-silent", "-no-interactsh", "-duc", "-timeout", "3"],
    capture_output=True,
    text=True,
    timeout=15
)
print(f"Test 1 (WITHOUT -dr): redirector_hits={redirector_hits}, canary_hits={canary_hits}, stdout={proc1.stdout.strip()}")

# Test 2: Run nuclei WITH -dr
canary_hits = 0
redirector_hits = 0
proc2 = subprocess.run(
    ["nuclei", "-target", f"http://127.0.0.1:{port}", "-t", tpl_path, "-silent", "-no-interactsh", "-duc", "-timeout", "3", "-dr"],
    capture_output=True,
    text=True,
    timeout=15
)
print(f"Test 2 (WITH -dr): redirector_hits={redirector_hits}, canary_hits={canary_hits}, stdout={proc2.stdout.strip()}")

if os.path.exists(tpl_path):
    os.remove(tpl_path)
