#!/usr/bin/env python3
"""Minimal 1-token health check for the LiteLLM gateway with backoff retries (STEP 1)."""

import asyncio
import datetime
import os
import sys
import time
from typing import Dict, Optional, Tuple

import httpx

# Ensure workspace root is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def load_env_production() -> Dict[str, str]:
    """Parse .env.production safely without printing values."""
    env_vars = {}
    env_path = os.path.abspath(".env.production")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env_vars[k.strip()] = v.strip().strip('"').strip("'")
    return env_vars


async def check_gateway_once(
    base_url: str,
    api_key: str,
    model: str,
    timeout: float = 30.0
) -> Tuple[bool, int, int, int, str]:
    """Execute minimal 1-token completion to verify gateway availability."""
    chat_url = base_url.rstrip("/")
    if not chat_url.endswith("/chat/completions"):
        if chat_url.endswith("/v1"):
            chat_url = f"{chat_url}/chat/completions"
        else:
            chat_url = f"{chat_url}/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "1"}],
        "max_tokens": 1
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(chat_url, json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                usage = data.get("usage") or {}
                p_tokens = usage.get("prompt_tokens", 1)
                c_tokens = usage.get("completion_tokens", 1)
                t_tokens = usage.get("total_tokens", p_tokens + c_tokens)
                return True, p_tokens, c_tokens, t_tokens, "OK"
            else:
                return False, 0, 0, 0, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, 0, 0, 0, str(e)


def append_health_to_cost_log(
    p_tokens: int,
    c_tokens: int,
    t_tokens: int,
    status_str: str,
    evidence_dir: str = "docs/audit/evidence/phase3"
):
    """Log health check tokens and cost to cost-log.md."""
    cost_log_path = os.path.join(evidence_dir, "cost-log.md")
    if not os.path.exists(cost_log_path):
        return

    # Calculate token cost (assume blended ~$0.005 / 1k tokens)
    cost_usd = round((p_tokens * 0.000003) + (c_tokens * 0.000015), 6)
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    run_id = f"GATEWAY-HEALTH-{datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S')}"

    # Read current cumulative totals
    cum_tokens = 0
    cum_cost = 0.0
    with open(cost_log_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("|") and not line.startswith("| Run ID") and not line.startswith("|---"):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 12:
                    try:
                        cum_tokens = int(parts[10].replace(",", ""))
                        cum_cost = float(parts[11].replace("$", "").replace(",", ""))
                    except ValueError:
                        pass

    cum_tokens += t_tokens
    cum_cost += cost_usd
    budget_pct = round((cum_cost / 10.0) * 100.0, 1)

    row = (
        f"| {run_id} | gateway-health | 1-TOKEN | {now_utc} | {now_utc} | "
        f"{p_tokens:,} | {c_tokens:,} | {t_tokens:,} | ${cost_usd:.4f} | "
        f"{cum_tokens:,} | ${cum_cost:.4f} | {budget_pct}% | {status_str} |\n"
    )

    with open(cost_log_path, "a", encoding="utf-8", newline="\n") as f:
        f.write(row)
    print(f"[+] Health check recorded in cost-log.md: {t_tokens} tokens, ${cost_usd:.4f} (Cumulative: ${cum_cost:.4f})")


async def main():
    env_vars = load_env_production()
    base_url = env_vars.get("PENTESA_LITELLM_BASE_URL") or "http://localhost:4000"
    api_key = env_vars.get("PENTESA_LITELLM_API_KEY") or "sk-placeholder"
    model = env_vars.get("PENTESA_LITELLM_MODEL") or "gpt-4o"

    print(f"=== STEP 1: GATEWAY HEALTH CHECK ===")
    print(f"Target Gateway: {base_url}")
    print(f"Model: {model}")

    backoffs = [10, 60, 180]  # Retries over ~5 minutes
    max_attempts = 4

    for attempt in range(1, max_attempts + 1):
        print(f"\n[Attempt {attempt}/{max_attempts}] Probing gateway with 1-token prompt...")
        ok, p_tok, c_tok, t_tok, msg = await check_gateway_once(base_url, api_key, model)

        if ok:
            print(f"[+] GATEWAY HEALTHY: 200 OK received! (Prompt tokens: {p_tok}, Completion: {c_tok}, Total: {t_tok})")
            append_health_to_cost_log(p_tok, c_tok, t_tok, "PASS")
            sys.exit(0)

        print(f"[-] Gateway probe failed: {msg}")
        if attempt < max_attempts:
            delay = backoffs[attempt - 1]
            print(f"[*] Backing off for {delay} seconds before retry {attempt + 1}...")
            await asyncio.sleep(delay)

    print("\n[-] GATEWAY HEALTH CHECK FAILED AFTER ALL RETRIES. HALTING BENCHMARK.")
    append_health_to_cost_log(0, 0, 0, "FAIL_UNAVAILABLE")
    sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
