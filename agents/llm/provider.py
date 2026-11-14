"""LLM Provider abstraction layer supporting local Ollama, OpenAI-compatible APIs, and deterministic Mock providers."""

import abc
import json
import time
from typing import Any, Dict, List, Optional, Type, TypeVar
import httpx
from pydantic import BaseModel
from packages.common.exceptions import LLMGatewayError

T = TypeVar("T", bound=BaseModel)


class LLMResponse(BaseModel):
    """Normalized response envelope returned by all LLM providers."""
    content: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    model: str = "default"
    duration_ms: int = 0


class BaseLLMProvider(abc.ABC):
    """Abstract interface for LLM completions."""

    @abc.abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_mode: bool = False,
        temperature: Optional[float] = None
    ) -> LLMResponse:
        """Execute chat completion and return response envelope."""
        pass

    async def generate_structured(
        self,
        prompt: str,
        schema_class: Type[T],
        system_prompt: Optional[str] = None,
        max_retries: int = 2,
        temperature: Optional[float] = None
    ) -> tuple[T, LLMResponse]:
        """Generate and parse structured Pydantic object with automatic repair retry."""
        system_instruction = (system_prompt or "") + (
            f"\nYou must respond ONLY with a valid JSON object matching this schema:\n"
            f"{json.dumps(schema_class.model_json_schema())}"
        )

        last_error = None
        for attempt in range(max_retries + 1):
            retry_prompt = prompt
            if attempt > 0:
                retry_prompt += f"\nYour previous output produced this JSON parsing error: {last_error}. Please correct the JSON output."

            resp = await self.generate(
                prompt=retry_prompt,
                system_prompt=system_instruction,
                json_mode=True,
                temperature=temperature
            )

            # Strip markdown code blocks if model included them
            raw = resp.content.strip()
            if raw.startswith("```json"):
                raw = raw[7:]
            elif raw.startswith("```"):
                raw = raw[3:]
            if raw.endswith("```"):
                raw = raw[:-3]
            raw = raw.strip()

            try:
                data = json.loads(raw)
                parsed = schema_class.model_validate(data)
                return parsed, resp
            except Exception as e:
                last_error = str(e)

        raise ValueError(f"Failed to produce valid structured output for {schema_class.__name__} after {max_retries} retries: {last_error}")


class MockLLMProvider(BaseLLMProvider):
    """Deterministic, offline Mock LLM provider for unit testing and CI/CD."""

    def __init__(self, responses: Optional[Dict[str, str]] = None):
        self.responses = responses or {}
        self.default_responses: Dict[str, str] = {}

    def register_response(self, keyword: str, response_json_or_text: str):
        """Register canned response triggered by a keyword in the prompt."""
        self.responses[keyword] = response_json_or_text

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_mode: bool = False,
        temperature: Optional[float] = None
    ) -> LLMResponse:
        start_time = time.time()
        matched_content = None

        for keyword, resp_text in self.responses.items():
            if keyword.lower() in prompt.lower():
                matched_content = resp_text
                break

        if not matched_content:
            p_low = prompt.lower()
            s_low = (system_prompt or "").lower()
            combined = f"{s_low}\n{p_low}"

            if "agt-01" in s_low or "project planning" in s_low or "engagement test plan" in p_low:
                matched_content = json.dumps({
                    "strategy": "Scoped OWASP WSTG v4.2 assessment beginning with passive attack surface mapping followed by targeted checks.",
                    "recommended_phases": ["PLANNING", "RECON", "WSTG_PLANNING", "ACTIVE_ASSESSMENT", "VALIDATION", "REPORTING"],
                    "rate_limit_rps": 20,
                    "target_subdomains_priority": ["primary", "api", "auth"]
                })
            elif "agt-03" in s_low or "reconnaissance" in s_low or "seed urls" in p_low:
                matched_content = json.dumps({
                    "discovered_domains": ["target.local"],
                    "recommended_ports": [80, 443, 8000, 9000],
                    "seed_strategy": "Inspect discovered endpoints, robots.txt, sitemap.xml, and query schemas.",
                    "technologies": ["FastAPI", "Uvicorn", "SQLite"]
                })
            elif "agt-05" in s_low or "wstg assessment" in s_low or "wstg testing plan" in p_low:
                matched_content = json.dumps({
                    "selected_categories": ["WSTG-INFO", "WSTG-CONF", "WSTG-INPV", "WSTG-ATHZ"],
                    "priority_probes": ["Security headers audit", "Configuration exposure checks", "Input handling review"],
                    "execution_mode": "Deterministic scope-guarded probe dispatch"
                })
            elif "agt-09" in s_low or "vulnerability detection" in s_low or "nuclei" in p_low:
                matched_content = json.dumps({
                    "nuclei_tags": ["cve", "misconfig", "exposure"],
                    "rate_limit_rps": 20,
                    "hypotheses": ["Unauthenticated debug config exposure", "Unsanitized search query reflection", "SQL string concatenation"]
                })
            elif "agt-07" in s_low or "authz" in combined or "authorization" in combined or "idor" in combined:
                matched_content = json.dumps({
                    "has_anomaly": True,
                    "anomaly_type": "BOLA_IDOR",
                    "affected_resource": "/api/v1/users/1",
                    "severity": "High",
                    "description": "Cross-tenant object identifier accessible without caller ownership validation."
                })
            elif "agt-11" in s_low or "validation" in combined or "false positive" in combined:
                matched_content = json.dumps({
                    "is_valid": True,
                    "confidence": "Confirmed",
                    "reasoning": "Observed reproducible vulnerability signal matching verified empirical response criteria.",
                    "reproduction_curl": "curl -i -s 'http://127.0.0.1:9000/api/v1/users/1'"
                })
            elif "agt-15" in s_low or "reporting" in combined or "ptes" in combined:
                matched_content = json.dumps({
                    "executive_summary": "Pentesa completed an autonomous penetration test across all 7 DAG phases verifying confirmed security exposures.",
                    "overall_risk_score": 7.8,
                    "strategic_recommendations": [
                        "Enforce server-side object-level authorization checks on API endpoints.",
                        "Use parameterized SQL queries and contextual output encoding.",
                        "Deploy defensive HTTP security headers (CSP, HSTS, X-Content-Type-Options)."
                    ]
                })
            elif "plan" in p_low or "planner" in s_low:
                matched_content = json.dumps({
                    "strategy": "Comprehensive OWASP WSTG v4.2 assessment with passive recon first.",
                    "recommended_phases": ["PLANNING", "RECON", "WSTG_PLANNING", "ACTIVE_ASSESSMENT", "VALIDATION", "REPORTING"],
                    "rate_limit_rps": 20
                })
            else:
                matched_content = json.dumps({"status": "SUCCESS", "message": "Analysis completed successfully."}) if json_mode else "Analysis completed successfully."

        duration_ms = int((time.time() - start_time) * 1000)
        p_tokens = max(1, len(prompt.split()) + len((system_prompt or "").split()))
        c_tokens = max(1, len(matched_content.split()))

        return LLMResponse(
            content=matched_content,
            prompt_tokens=p_tokens,
            completion_tokens=c_tokens,
            total_tokens=p_tokens + c_tokens,
            model="mock-gpt",
            duration_ms=duration_ms
        )


class OllamaProvider(BaseLLMProvider):
    """Local-first Ollama LLM provider (zero cloud dependency)."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.1"):
        self.base_url = base_url.rstrip("/")
        self.model = model

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_mode: bool = False,
        temperature: Optional[float] = None
    ) -> LLMResponse:
        start_time = time.time()
        url = f"{self.base_url}/api/chat"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        if temperature is not None:
            payload["options"] = {"temperature": temperature}
        if json_mode:
            payload["format"] = "json"

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()

        duration_ms = int((time.time() - start_time) * 1000)
        msg_content = data.get("message", {}).get("content", "")
        p_tokens = data.get("prompt_eval_count", len(prompt.split()))
        c_tokens = data.get("eval_count", len(msg_content.split()))

        return LLMResponse(
            content=msg_content,
            prompt_tokens=p_tokens,
            completion_tokens=c_tokens,
            total_tokens=p_tokens + c_tokens,
            model=self.model,
            duration_ms=duration_ms
        )


class OpenAICompatibleProvider(BaseLLMProvider):
    """OpenAI-compatible LLM provider for local gateways (vLLM, LMStudio) or commercial APIs."""

    def __init__(
        self,
        base_url: str = "https://api.openai.com/v1",
        api_key: str = "sk-placeholder",
        model: str = "gpt-4o-mini",
        transport: Optional[httpx.AsyncBaseTransport] = None
    ):
        raw_url = base_url.rstrip("/")
        if raw_url.endswith("/chat/completions"):
            self.chat_url = raw_url
            self.base_url = raw_url[:-len("/chat/completions")].rstrip("/")
        else:
            self.chat_url = f"{raw_url}/chat/completions"
            self.base_url = raw_url

        self.api_key = api_key
        self.model = model
        self.transport = transport

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_mode: bool = False,
        temperature: Optional[float] = None
    ) -> LLMResponse:
        start_time = time.time()

        effective_system = system_prompt or ""
        if json_mode:
            combined_text = f"{effective_system}\n{prompt}".lower()
            if "json" not in combined_text:
                effective_system = (effective_system + "\nRespond strictly with a concise, valid JSON object.").strip()
            elif "json schema" not in combined_text and "concise" not in combined_text:
                effective_system = (effective_system + "\nKeep your JSON output concise (under 200 words).").strip()

        messages = []
        if effective_system:
            messages.append({"role": "system", "content": effective_system})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
        }
        # Azure GPT-5 series / reasoning models reject or return null for non-default temperatures
        is_reasoning_or_gpt5 = any(prefix in self.model.lower() for prefix in ["gpt-5", "o1", "o3", "o4"])
        if temperature is not None and not is_reasoning_or_gpt5:
            payload["temperature"] = temperature
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        try:
            async with httpx.AsyncClient(timeout=120.0, transport=self.transport) as client:
                resp = await client.post(self.chat_url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()

                choices = data.get("choices") or []
                msg_obj = (choices[0].get("message") or {}) if choices else {}
                msg_content = (msg_obj.get("content") or "").strip()

                # Fallback: if json_mode produced an empty choice on gateway, retry without response_format
                if not msg_content and not msg_obj.get("reasoning_content") and json_mode:
                    fallback_payload = dict(payload)
                    fallback_payload.pop("response_format", None)
                    resp_retry = await client.post(self.chat_url, json=fallback_payload, headers=headers)
                    resp_retry.raise_for_status()
                    data = resp_retry.json()
                    choices = data.get("choices") or []
                    msg_obj = (choices[0].get("message") or {}) if choices else {}
                    msg_content = (msg_obj.get("content") or "").strip()
        except httpx.HTTPStatusError as e:
            code = 502 if e.response.status_code >= 500 or e.response.status_code in (403, 401) else 503
            raise LLMGatewayError(
                f"Upstream AI gateway returned HTTP error {e.response.status_code} at {self.chat_url}: {e.response.text[:200]}",
                status_code=code,
                details={"status_code": e.response.status_code, "url": self.chat_url}
            ) from e
        except (httpx.RequestError, TimeoutError, ConnectionRefusedError) as e:
            raise LLMGatewayError(
                f"Failed to connect to upstream AI gateway at {self.chat_url}: {e}",
                status_code=503,
                details={"error": str(e), "url": self.chat_url}
            ) from e

        if not msg_content:
            msg_content = (msg_obj.get("reasoning_content") or msg_obj.get("refusal") or "").strip()

        duration_ms = int((time.time() - start_time) * 1000)
        usage = data.get("usage") or {}
        p_tokens = usage.get("prompt_tokens") or max(1, len(prompt.split()) + len(effective_system.split()))
        c_tokens = usage.get("completion_tokens") or max(1, len(msg_content.split()))
        t_tokens = usage.get("total_tokens") or (p_tokens + c_tokens)

        return LLMResponse(
            content=msg_content,
            prompt_tokens=p_tokens,
            completion_tokens=c_tokens,
            total_tokens=t_tokens,
            model=data.get("model", self.model),
            duration_ms=duration_ms
        )


class LiteLLMProvider(BaseLLMProvider):
    """LiteLLM proxy provider supporting model routing, virtual keys, and multi-LLM proxying."""

    def __init__(
        self,
        base_url: str = "http://localhost:4000",
        api_key: str = "sk-placeholder",
        model: str = "gpt-4o",
        timeout: float = 120.0,
        transport: Optional[httpx.AsyncBaseTransport] = None
    ):
        raw_url = base_url.rstrip("/")
        if raw_url.endswith("/chat/completions"):
            self.chat_url = raw_url
            self.base_url = raw_url[:-len("/chat/completions")].rstrip("/")
        elif raw_url.endswith("/v1"):
            self.chat_url = f"{raw_url}/chat/completions"
            self.base_url = raw_url
        else:
            self.chat_url = f"{raw_url}/chat/completions"
            self.base_url = raw_url

        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.transport = transport

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_mode: bool = False,
        temperature: Optional[float] = None
    ) -> LLMResponse:
        start_time = time.time()

        effective_system = system_prompt or ""
        if json_mode:
            combined_text = f"{effective_system}\n{prompt}".lower()
            if "json" not in combined_text:
                effective_system = (effective_system + "\nRespond strictly with a concise, valid JSON object.").strip()
            elif "json schema" not in combined_text and "concise" not in combined_text:
                effective_system = (effective_system + "\nKeep your JSON output concise (under 200 words).").strip()

        messages = []
        if effective_system:
            messages.append({"role": "system", "content": effective_system})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
        }
        # Azure GPT-5 series / reasoning models reject or return null for non-default temperatures
        is_reasoning_or_gpt5 = any(prefix in self.model.lower() for prefix in ["gpt-5", "o1", "o3", "o4"])
        if temperature is not None and not is_reasoning_or_gpt5:
            payload["temperature"] = temperature
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
                resp = await client.post(self.chat_url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()

                if isinstance(data, dict) and data.get("error"):
                    raise RuntimeError(f"LiteLLM gateway returned error payload: {data.get('error')}")

                choices = data.get("choices") or []
                msg_obj = (choices[0].get("message") or {}) if choices else {}
                msg_content = (msg_obj.get("content") or "").strip()

                # Retry once without response_format if gateway returned empty choice under json_mode
                if not msg_content and not msg_obj.get("reasoning_content") and json_mode:
                    fallback_payload = dict(payload)
                    fallback_payload.pop("response_format", None)
                    resp_retry = await client.post(self.chat_url, json=fallback_payload, headers=headers)
                    resp_retry.raise_for_status()
                    data_retry = resp_retry.json()
                    if isinstance(data_retry, dict) and not data_retry.get("error"):
                        data = data_retry
                        choices = data.get("choices") or []
                        msg_obj = (choices[0].get("message") or {}) if choices else {}
                        msg_content = (msg_obj.get("content") or "").strip()

        except httpx.HTTPStatusError as e:
            code = 502 if e.response.status_code >= 500 or e.response.status_code in (403, 401) else 503
            raise LLMGatewayError(
                f"Upstream AI gateway returned HTTP error {e.response.status_code} at {self.chat_url}: {e.response.text[:200]}",
                status_code=code,
                details={"status_code": e.response.status_code, "url": self.chat_url}
            ) from e
        except (httpx.RequestError, TimeoutError, ConnectionRefusedError) as e:
            raise LLMGatewayError(
                f"Failed to connect to upstream AI gateway at {self.chat_url}: {e}",
                status_code=503,
                details={"error": str(e), "url": self.chat_url}
            ) from e

        if not msg_content:
            msg_content = (msg_obj.get("reasoning_content") or msg_obj.get("refusal") or "").strip()

        duration_ms = int((time.time() - start_time) * 1000)
        usage = data.get("usage") or {}
        p_tokens = usage.get("prompt_tokens") or max(1, len(prompt.split()) + len(effective_system.split()))
        c_tokens = usage.get("completion_tokens") or max(1, len(msg_content.split()))
        t_tokens = usage.get("total_tokens") or (p_tokens + c_tokens)

        return LLMResponse(
            content=msg_content,
            prompt_tokens=p_tokens,
            completion_tokens=c_tokens,
            total_tokens=t_tokens,
            model=data.get("model", self.model),
            duration_ms=duration_ms
        )

    async def check_health(self) -> bool:
        """Probe LiteLLM proxy /health endpoint."""
        try:
            health_url = f"{self.base_url}/health"
            headers = {"Authorization": f"Bearer {self.api_key}"}
            async with httpx.AsyncClient(timeout=5.0, transport=self.transport) as client:
                resp = await client.get(health_url, headers=headers)
                return resp.status_code == 200
        except Exception:
            return False


def get_default_llm_provider() -> BaseLLMProvider:
    """Return configured LLM provider according to platform Settings.

    Supports:
    - 'litellm': LiteLLM proxy / gateway server
    - 'ollama': Local Ollama instance
    - 'openai': Direct OpenAI-compatible endpoint
    - 'mock': Deterministic mock provider (strictly restricted to PENTESA_ENV=test)
    """
    from packages.common.config import settings

    provider_name = (settings.llm_provider or "").lower().strip()
    env = (settings.env or "").lower().strip()

    if not provider_name:
        if env == "test":
            return MockLLMProvider()
        raise RuntimeError(
            f"PENTESA_LLM_PROVIDER is not configured. Explicit LLM provider configuration is required in environment '{settings.env}'."
        )

    if provider_name == "litellm":
        if (
            not settings.litellm_base_url
            or not settings.litellm_api_key
            or settings.litellm_api_key == "sk-placeholder"
        ):
            raise ValueError(
                "LiteLLM provider selected, but PENTESA_LITELLM_BASE_URL or "
                "PENTESA_LITELLM_API_KEY is missing or placeholder."
            )
        return LiteLLMProvider(
            base_url=settings.litellm_base_url,
            api_key=settings.litellm_api_key,
            model=settings.litellm_model,
            timeout=settings.litellm_timeout,
        )

    if provider_name == "ollama":
        return OllamaProvider(
            base_url=settings.ollama_base_url,
            model=settings.ollama_model,
        )

    if provider_name == "openai":
        if not settings.openai_api_key or settings.openai_api_key == "sk-placeholder":
            raise ValueError(
                "OpenAI provider selected, but PENTESA_OPENAI_API_KEY is missing or placeholder."
            )
        return OpenAICompatibleProvider(
            base_url=settings.openai_base_url,
            api_key=settings.openai_api_key,
            model=settings.openai_model,
        )

    if provider_name == "mock":
        if env != "test":
            raise RuntimeError(
                f"MockLLMProvider cannot be used in environment '{settings.env}'. "
                "PENTESA_LLM_PROVIDER=mock is strictly restricted to PENTESA_ENV=test."
            )
        return MockLLMProvider()

    raise ValueError(
        f"Unsupported PENTESA_LLM_PROVIDER='{provider_name}'. "
        "Supported providers: litellm, ollama, openai, mock."
    )
