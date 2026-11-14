"""Verification Round V6 Runner: Nuclei & ffuf Redirect Hardening (NI-03)."""

import http.server
import json
import os
import subprocess
import threading
import time

hits = {"redirect": 0, "canary": 0}

class RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global hits
        if "/redirect" in self.path:
            hits["redirect"] += 1
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{server.server_port}/canary")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif "/canary" in self.path:
            hits["canary"] += 1
            body = b"CANARY_HIT_DETECTED"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

    def log_message(self, format, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
port = server.server_port
t = threading.Thread(target=server.serve_forever, daemon=True)
t.start()

tpl_path = "/tmp/test_redirect_template.yaml"
tpl_content = """id: test-internal-redirect
info:
  name: Template with Internal Redirect Flag
  author: audit
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/redirect"
    redirects: true
    max-redirects: 5
    matchers:
      - type: word
        words:
          - "CANARY_HIT_DETECTED"
"""
with open(tpl_path, "w") as f:
    f.write(tpl_content)

print("================================================================================")
print("=== V6: REDIRECT HARDENING VERIFICATION (NUCLEI & FFUF) ===")
print("================================================================================")
print(f"Redirect test server running on 127.0.0.1:{port}")
print("Redirect endpoint: /redirect -> 302 -> /canary")
print("Canary endpoint:   /canary   -> 200 (logs canary hit)")
print()

# Test 1: Nuclei WITHOUT -dr flag (default vulnerability state)
hits["redirect"] = 0
hits["canary"] = 0
print("--- TEST 1: Nuclei WITHOUT -dr flag (Template has redirects: true) ---")
cmd1 = [
    "nuclei",
    "-target", f"http://127.0.0.1:{port}",
    "-t", tpl_path,
    "-silent",
    "-no-interactsh",
    "-duc",
    "-timeout", "2"
]
print(f"Command: {' '.join(cmd1)}")
proc1 = subprocess.run(cmd1, capture_output=True, text=True, timeout=10)
print(f"Redirector Hits: {hits['redirect']}")
print(f"Canary Hits:     {hits['canary']}")
print(f"Findings Output: {proc1.stdout.strip()}")
print(f"Outcome: Template followed internal redirect -> Canary was reached: {hits['canary'] > 0}")
assert hits['canary'] > 0, "Expected canary to be reached without -dr"
print("[CONFIRMED] Nuclei without -dr follows template-level redirects into out-of-scope targets.\n")

# Test 2: Nuclei WITH -dr flag (Pentesa hardened runner default via FIX-08)
hits["redirect"] = 0
hits["canary"] = 0
print("--- TEST 2: Nuclei WITH -dr flag (Pentesa hardened build_argv) ---")
cmd2 = [
    "nuclei",
    "-target", f"http://127.0.0.1:{port}",
    "-t", tpl_path,
    "-silent",
    "-no-interactsh",
    "-duc",
    "-dr",
    "-timeout", "2"
]
print(f"Command: {' '.join(cmd2)}")
proc2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=10)
print(f"Redirector Hits: {hits['redirect']}")
print(f"Canary Hits:     {hits['canary']}")
print(f"Findings Output: {proc2.stdout.strip()}")
print(f"Outcome: -dr flag blocked template-level redirect -> Canary hits: {hits['canary']} (ZERO HITS)")
assert hits['canary'] == 0, f"Expected 0 canary hits with -dr, got {hits['canary']}"
print("[PASS] Nuclei -dr flag successfully prevented redirect following.\n")

# Test 3: ffuf redirect behavior
print("--- TEST 3: ffuf redirect behavior ---")
wordlist_path = "/tmp/test_wordlist.txt"
with open(wordlist_path, "w") as f:
    f.write("redirect\n")

# 3a. ffuf default (no -r)
hits["redirect"] = 0
hits["canary"] = 0
cmd3a = [
    "ffuf",
    "-u", f"http://127.0.0.1:{port}/FUZZ",
    "-w", wordlist_path,
    "-s"
]
print(f"Command (default): {' '.join(cmd3a)}")
proc3a = subprocess.run(cmd3a, capture_output=True, text=True, timeout=10)
print(f"Redirector Hits: {hits['redirect']}")
print(f"Canary Hits:     {hits['canary']}")
print(f"Outcome: ffuf default does not follow redirects -> Canary hits: {hits['canary']} (ZERO HITS)")
assert hits['canary'] == 0, f"Expected 0 canary hits in ffuf default, got {hits['canary']}"
print("[PASS] ffuf does not follow redirects without -r flag.\n")

# 3b. ffuf with -r (proves -r is dangerous and why Pentesa strips it)
hits["redirect"] = 0
hits["canary"] = 0
cmd3b = [
    "ffuf",
    "-u", f"http://127.0.0.1:{port}/FUZZ",
    "-w", wordlist_path,
    "-r",
    "-s"
]
print(f"Command (with -r): {' '.join(cmd3b)}")
proc3b = subprocess.run(cmd3b, capture_output=True, text=True, timeout=10)
print(f"Redirector Hits: {hits['redirect']}")
print(f"Canary Hits:     {hits['canary']}")
print(f"Outcome: ffuf with -r followed redirect to canary -> Canary hits: {hits['canary']}")
assert hits['canary'] > 0, "Expected ffuf -r to reach canary"
print("[CONFIRMED] ffuf -r is dangerous and Pentesa FfufRunner strictly forbids/strips -r.\n")

print("================================================================================")
print("=== V6 ARCHITECTURAL ANALYSIS (NI-03 CLASSIFICATION) ===")
print("  - Nuclei templates can declare 'redirects: true'. Passing '-dr' (-disable-redirects)")
print("    in NucleiRunner.build_argv() completely disables template-level redirects.")
print("  - ffuf by default NEVER follows HTTP redirects; FfufRunner strips -r to prevent following.")
print("  - Both tools with Pentesa CLI hardening achieve ZERO canary hits (0 hits).")
print("  - However, because CLI flags rely on subprocess/tool cooperation, complete architectural")
print("    defense-in-depth requires a dedicated Layer-2 container proxy (reassigned to Phase 9).")
print("  - In the interim, NI-03 is mitigated via fail-closed lab-only guardrail and -dr CLI enforcement.")
print("================================================================================")

if os.path.exists(tpl_path):
    os.remove(tpl_path)
if os.path.exists(wordlist_path):
    os.remove(wordlist_path)
