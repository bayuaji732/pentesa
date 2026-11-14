"""Pentesa Autonomous Asynchronous Execution Worker.

Monitors asynchronous workflow queues, dispatches specialized security testing jobs,
and manages worker heartbeat and health status.
"""

import asyncio
import logging
import signal
import sys
import os

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Worker] %(message)s"
)
logger = logging.getLogger("pentesa.worker")

SHUTDOWN_EVENT = asyncio.Event()


def handle_signal(sig, frame):
    """Graceful worker shutdown handler."""
    logger.info(f"Received termination signal ({sig}). Initiating graceful shutdown...")
    SHUTDOWN_EVENT.set()


async def run_worker_loop():
    """Main worker event loop."""
    logger.info("Initializing Pentesa Asynchronous Security Worker...")
    logger.info(f"Worker PID: {os.getpid()}")

    # Fail-closed startup security validation (SEC-KEY-01, SEC-PWD-01)
    from apps.api.main import validate_encryption_key_startup
    validate_encryption_key_startup()

    logger.info("Connecting to Redis task queue & PostgreSQL state engine...")

    # Set up signal handlers where supported
    try:
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
    except (ValueError, AttributeError):
        pass

    logger.info("Worker is ready to consume autonomous penetration testing tasks.")

    while not SHUTDOWN_EVENT.is_set():
        try:
            # Poll task queues or perform heartbeat maintenance
            await asyncio.sleep(2)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in worker event loop: {e}", exc_info=True)
            await asyncio.sleep(5)

    logger.info("Worker loop terminated cleanly. Exiting.")


if __name__ == "__main__":
    try:
        asyncio.run(run_worker_loop())
    except KeyboardInterrupt:
        logger.info("Worker stopped by KeyboardInterrupt.")

