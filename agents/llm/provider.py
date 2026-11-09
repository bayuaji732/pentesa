"""LLM Provider abstraction layer supporting local Ollama, OpenAI-compatible APIs, and deterministic Mock providers."""

import abc
import json
import time
from typing import Any, Dict, List, Optional, Type, TypeVar
import httpx
from pydantic import BaseModel

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
            # Fallback heuristic responses based on agent keywords
            if "plan" in prompt.lower() or "planner" in (system_prompt or "").lower():
                matched_content = json.dumps({
                    "strategy": "Comprehensive OWASP WSTG v4.2 assessment with passive recon first.",
                    "recommended_phases": ["RECON", "MAPPING", "WSTG_PLANNING", "ACTIVE_ASSESSMENT", "VALIDATION", "REPORTING"],
                    "rate_limit_rps": 20,
                    "target_subdomains_priority": ["api", "app", "auth"]
                })
            elif "recon" in prompt.lower() or "recon" in (system_prompt or "").lower():
                matched_content = json.dumps({
                    "discovered_domains": ["api.target.com", "auth.target.com", "app.target.com"],
                    "recommended_ports": [80, 443, 8443],
                    "technologies": ["Nginx", "Node.js", "Express"]
                })
            elif "validation" in prompt.lower() or "validation" in (system_prompt or "").lower():
                matched_content = json.dumps({
                    "is_valid": True,
                    "confidence": "Confirmed",
                    "reasoning": "Observed SQL syntax error in response body verifying injection vulnerability.",
                    "reproduction_curl": "curl -i -s 'https://target.com/api/search?q=%27%20OR%201=1--'"
                })
            elif "authz" in prompt.lower() or "authorization" in (system_prompt or "").lower():
                matched_content = json.dumps({
                    "has_anomaly": True,
                    "anomaly_type": "BOLA_IDOR",
                    "affected_resource": "/api/v1/users/1002/orders",
                    "severity": "High",
                    "description": "User A can access User B's order records without authorization checks."
                })
            elif "report" in prompt.lower() or "reporting" in (system_prompt or "").lower():
                matched_content = json.dumps({
                    "executive_summary": "Pentesa completed an autonomous penetration test identifying 3 high-severity issues.",
                    "overall_risk_score": 7.8,
                    "strategic_recommendations": [
                        "Implement centralized object-level authorization checks.",
                        "Enforce strict parameterized database queries across all input handlers.",
                        "Deploy comprehensive Content-Security-Policy headers."
                    ]
                })
            else:
                matched_content = json.dumps({"status": "SUCCESS", "message": "Analysis completed successfully."}) if json_mode else "Analysis completed successfully."

        duration_ms = int((time.time() - start_time) * 1000)
        p_tokens = len(prompt.split()) + len((system_prompt or "").split())
        c_tokens = len(matched_content.split())

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

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
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

        async with httpx.AsyncClient(timeout=120.0, transport=self.transport) as client:
            resp = await client.post(self.chat_url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        duration_ms = int((time.time() - start_time) * 1000)
        choices = data.get("choices", [{}])
        msg_content = ""
        if choices:
            msg_content = choices[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})

        return LLMResponse(
            content=msg_content,
            prompt_tokens=usage.get("prompt_tokens", len(prompt.split())),
            completion_tokens=usage.get("completion_tokens", len(msg_content.split())),
            total_tokens=usage.get("total_tokens", 0),
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

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
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
        except httpx.HTTPStatusError as e:
            raise RuntimeError(
                f"LiteLLM proxy returned HTTP error {e.response.status_code} at {self.chat_url}: {e.response.text}"
            ) from e
        except httpx.RequestError as e:
            raise RuntimeError(
                f"Failed to connect to LiteLLM proxy at {self.chat_url}: {e}"
            ) from e

        duration_ms = int((time.time() - start_time) * 1000)
        choices = data.get("choices", [])
        msg_content = ""
        if choices:
            msg_content = choices[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})

        return LLMResponse(
            content=msg_content,
            prompt_tokens=usage.get("prompt_tokens", len(prompt.split())),
            completion_tokens=usage.get("completion_tokens", len(msg_content.split())),
            total_tokens=usage.get("total_tokens", 0),
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
    - 'litellm': LiteLLM proxy server (configured via URL, API Key, Model)
    - 'ollama': Local Ollama instance
    - 'openai': Direct OpenAI-compatible endpoint
    - 'mock': Deterministic mock provider (default for testing and offline development)
    """
    try:
        from packages.common.config import settings
        provider_name = (settings.llm_provider or "mock").lower().strip()

        if provider_name == "litellm":
            return LiteLLMProvider(
                base_url=settings.litellm_base_url,
                api_key=settings.litellm_api_key,
                model=settings.litellm_model,
                timeout=settings.litellm_timeout
            )
        elif provider_name == "ollama":
            return OllamaProvider(
                base_url=settings.ollama_base_url,
                model=settings.ollama_model
            )
        elif provider_name == "openai":
            return OpenAICompatibleProvider(
                base_url=settings.openai_base_url,
                api_key=settings.openai_api_key,
                model=settings.openai_model
            )
    except Exception:
        pass

    return MockLLMProvider()
