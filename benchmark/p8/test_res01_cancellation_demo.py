#!/usr/bin/env python3
"""Empirical Demonstration of DEFECT-RES-01 (Process Orphan Leak on asyncio.CancelledError).

Verifies the exact behavior of BaseToolWrapper when an enclosing asyncio task is cancelled.
In Python 3.8+, asyncio.CancelledError inherits from BaseException.
BaseToolWrapper.execute() catches asyncio.TimeoutError and Exception, but lacks
a finally: block or except asyncio.CancelledError handler, resulting in orphan child
processes that outlive task cancellation.
"""

import asyncio
import os
import sys
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from services.execution_engine.tools.base import BaseToolWrapper


class HarmlessLongRunningTool(BaseToolWrapper):
    captured_proc = None

    def __init__(self):
        super().__init__(tool_name="harmless_sleep", binary_name=sys.executable)

    def get_binary_path(self) -> str:
        return sys.executable

    def build_argv(self, target_url: str, opts: dict) -> list:
        # Harmless child process sleeping for 15 seconds
        return [sys.executable, "-c", "import time; time.sleep(15)"]

    def parse_output(self, stdout: str, baseline: dict = None) -> list:
        return []

    async def validate_scope(self, session, project_id, target_url):
        return True


async def main():
    print("=" * 80, flush=True)
    print("EMPIRICAL PROOF OF DEFECT-RES-01 (CANCELLATION LEAK IN BASETOOLWRAPPER)", flush=True)
    print("=" * 80, flush=True)

    # Monkeypatch asyncio.create_subprocess_exec to capture the spawned subprocess
    orig_create_subprocess = asyncio.create_subprocess_exec

    async def tracking_create_subprocess(*args, **kwargs):
        proc = await orig_create_subprocess(*args, **kwargs)
        HarmlessLongRunningTool.captured_proc = proc
        return proc

    asyncio.create_subprocess_exec = tracking_create_subprocess

    tool = HarmlessLongRunningTool()

    print("[1] Spawning BaseToolWrapper.execute() inside an asyncio.Task...", flush=True)
    task = asyncio.create_task(
        tool.execute(
            session=None,
            project_id=None,
            target_url="http://127.0.0.1:8000",
            timeout_seconds=60,
        )
    )

    # Allow subprocess to spawn
    await asyncio.sleep(0.5)
    proc = HarmlessLongRunningTool.captured_proc
    if proc is None or proc.pid is None:
        print("ERROR: Child process was not spawned.", flush=True)
        return 1

    child_pid = proc.pid
    print(f"[2] Subprocess spawned: PID {child_pid}, proc.returncode={proc.returncode}", flush=True)

    print("[3] Enforcing task.cancel() on enclosing coroutine...", flush=True)
    task.cancel()

    try:
        await task
        print("UNEXPECTED: Task finished without exception!", flush=True)
    except asyncio.CancelledError:
        print("[4] Successfully caught asyncio.CancelledError at task caller boundary.", flush=True)

    # Allow a brief moment for any cleanup handlers to run
    await asyncio.sleep(0.3)

    return_code = proc.returncode
    print(f"[5] Post-cancellation check for PID {child_pid}: proc.returncode = {return_code}", flush=True)

    if return_code is None:
        print("\n" + "!" * 80, flush=True)
        print("CONFIRMED DEFECT-RES-01:")
        print(f"  Child PID {child_pid} is STILL RUNNING (proc.returncode is None) after task cancellation!")
        print("  Root Cause: BaseToolWrapper.execute() catches only asyncio.TimeoutError and Exception.")
        print("  In Python 3.8+, asyncio.CancelledError inherits from BaseException.")
        print("  The coroutine terminates immediately without executing proc.kill().")
        print("  Status: FAILED (empirical demonstration of orphan process leak).", flush=True)
        print("!" * 80 + "\n", flush=True)

        # Cleanup orphan cleanly
        try:
            proc.terminate()
            print(f"[6] Forensic cleanup: Sent terminate signal to orphan child PID {child_pid}.", flush=True)
        except Exception as e:
            print(f"Error terminating child: {e}", flush=True)
        return 0
    else:
        print("Child process terminated cleanly upon cancellation.", flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
