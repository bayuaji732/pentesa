#!/usr/bin/env python3
"""Empirical Demonstration of DEFECT-HOST-01 (Platform HTTP Client Hangs on Slow-Drip Response).

Demonstrates that packages/common/http_client.py (safe_request) and
services/execution_engine/tools/http_client.py (RawHttpClient) rely on httpx.Timeout(timeout),
which only bounds per-read socket idle timeouts and fails to enforce a cumulative stream deadline.
A target slow-dripping bytes within the socket idle timeout will hang the platform
worker for the full duration of the stream.
"""

import asyncio
import os
import sys
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import httpx
from packages.common.http_client import safe_request


async def handle_slow_drip(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    # Read incoming request
    await reader.readuntil(b"\r\n\r\n")

    # Send HTTP 200 chunked response
    header = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    writer.write(header)
    await writer.drain()

    # Drip 6 chunks every 0.3 seconds (total stream duration = 1.8 seconds)
    for i in range(6):
        try:
            chunk = f"drip-{i}\n".encode()
            writer.write(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
            await writer.drain()
            await asyncio.sleep(0.3)
        except Exception:
            break

    try:
        writer.write(b"0\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


async def main():
    print("=" * 80, flush=True)
    print("EMPIRICAL PROOF OF DEFECT-HOST-01 (PLATFORM HTTP CLIENT SLOW-DRIP TIMING)", flush=True)
    print("=" * 80, flush=True)

    port = 8897
    server = await asyncio.start_server(handle_slow_drip, "127.0.0.1", port)
    target_url = f"http://127.0.0.1:{port}/slow-drip"
    print(f"[1] Slow-drip HTTP server started on {target_url} (6 chunks x 0.3s = 1.8s stream)", flush=True)

    configured_timeout = 0.6
    print(f"[2] Invoking packages.common.http_client.safe_request with timeout={configured_timeout}s", flush=True)
    print(f"    Call Path: RawHttpClient.execute_request -> safe_request -> client.request()", flush=True)

    start_time = time.time()
    resp = None
    note = None
    try:
        async with httpx.AsyncClient(timeout=configured_timeout) as client:
            resp, note = await safe_request(
                client=client,
                method="GET",
                url=target_url,
                project=None,
                session=None,
                follow_redirects=False,
                resolve_dns=False,
            )
    except Exception as e:
        print(f"    Unexpected exception: {type(e).__name__}: {e}", flush=True)

    elapsed = time.time() - start_time
    print(f"[3] safe_request execution duration: {elapsed:.2f} seconds.", flush=True)
    if resp is not None:
        print(f"    Response status: HTTP {resp.status_code}, Body: {resp.text.strip()}", flush=True)

    print("\n" + "!" * 80, flush=True)
    if elapsed > (configured_timeout + 0.8):
        print("CONFIRMED DEFECT-HOST-01:", flush=True)
        print(f"  Platform HTTP client took {elapsed:.2f}s despite timeout={configured_timeout}s!", flush=True)
        print(f"  The client HUNG because httpx.Timeout({configured_timeout}) only bounds idle read", flush=True)
        print(f"  between socket packets (here 0.3s < {configured_timeout}s).", flush=True)
        print(f"  Cumulative stream duration is UNBOUNDED without asyncio.wait_for() or total deadline.", flush=True)
        print("  Status: FAILED (empirical demonstration of slow-drip hang).", flush=True)
        print("!" * 80 + "\n", flush=True)
        result = 0
    else:
        print(f"Client timed out within {elapsed:.2f}s.", flush=True)
        result = 1

    server.close()
    await server.wait_closed()
    return result


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
