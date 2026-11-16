import socketserver
import http.server
import subprocess
import threading

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    print(f"Server on {port}")
    cmd = ["nuclei", "-target", f"http://127.0.0.1:{port}", "-t", "/app/tests/fixtures/nuclei/ping.yaml", "-silent", "-no-interactsh", "-duc"]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    print(f"Exit code: {res.returncode}, stdout: {res.stdout.strip()}")
    server.shutdown()
