"""Unit tests for LLM provider abstraction and structured output generation."""

import json
import httpx
import pytest
from pydantic import BaseModel, Field

from agents.llm.provider import (
    LiteLLMProvider,
    MockLLMProvider,
    get_default_llm_provider
)
from packages.common.config import settings


class SampleAssessmentPlan(BaseModel):
    strategy: str
    target_count: int = Field(ge=1)
    high_priority_tags: list[str]


@pytest.mark.asyncio
async def test_mock_llm_provider_generation():
    """Verify basic mock generation, token counting, and duration measurement."""
    provider = MockLLMProvider()
    resp = await provider.generate(
        prompt="Please analyze the attack surface for vulnerabilities.",
        system_prompt="You are a security analyst."
    )
    assert resp.content is not None
    assert resp.prompt_tokens > 0
    assert resp.completion_tokens > 0
    assert resp.model == "mock-gpt"


@pytest.mark.asyncio
async def test_mock_llm_provider_keyword_matching():
    """Verify custom canned responses triggered by keywords."""
    provider = MockLLMProvider()
    provider.register_response("special_secret_target", '{"custom_result": "found_exploit"}')

    resp = await provider.generate(
        prompt="Scan special_secret_target now",
        json_mode=True
    )
    assert 'found_exploit' in resp.content


@pytest.mark.asyncio
async def test_mock_llm_provider_structured_output():
    """Verify structured output parsing into strongly typed Pydantic models."""
    provider = MockLLMProvider()
    provider.register_response(
        "structured_plan_query",
        '{"strategy": "Deep crawl", "target_count": 5, "high_priority_tags": ["cve", "auth"]}'
    )

    plan, raw_resp = await provider.generate_structured(
        prompt="Run structured_plan_query",
        schema_class=SampleAssessmentPlan
    )

    assert isinstance(plan, SampleAssessmentPlan)
    assert plan.strategy == "Deep crawl"
    assert plan.target_count == 5
    assert "cve" in plan.high_priority_tags


def test_litellm_provider_url_normalization():
    """Verify LiteLLM endpoint normalization for various base URL inputs."""
    p1 = LiteLLMProvider(base_url="http://localhost:4000")
    assert p1.chat_url == "http://localhost:4000/chat/completions"
    assert p1.base_url == "http://localhost:4000"

    p2 = LiteLLMProvider(base_url="http://localhost:4000/v1")
    assert p2.chat_url == "http://localhost:4000/v1/chat/completions"

    p3 = LiteLLMProvider(base_url="http://localhost:4000/chat/completions/")
    assert p3.chat_url == "http://localhost:4000/chat/completions"
    assert p3.base_url == "http://localhost:4000"

    p4 = LiteLLMProvider(base_url="https://litellm.internal:8443/v1/chat/completions")
    assert p4.chat_url == "https://litellm.internal:8443/v1/chat/completions"


@pytest.mark.asyncio
async def test_litellm_provider_generate_mock_transport():
    """Verify LiteLLMProvider correctly serializes requests and parses OpenAI-compatible responses."""
    captured_requests = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        payload = json.loads(request.read().decode("utf-8"))
        assert payload["model"] == "claude-3-5-sonnet"
        assert len(payload["messages"]) == 2
        assert payload["messages"][0]["role"] == "system"
        assert payload["messages"][1]["role"] == "user"

        return httpx.Response(
            status_code=200,
            json={
                "id": "chatcmpl-litellm-12345",
                "object": "chat.completion",
                "model": "claude-3-5-sonnet",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "Reconnaissance complete: discovered 4 APIs."
                        },
                        "finish_reason": "stop"
                    }
                ],
                "usage": {
                    "prompt_tokens": 42,
                    "completion_tokens": 12,
                    "total_tokens": 54
                }
            }
        )

    transport = httpx.MockTransport(mock_handler)
    provider = LiteLLMProvider(
        base_url="http://localhost:4000",
        api_key="sk-litellm-secret-key-xyz",
        model="claude-3-5-sonnet",
        transport=transport
    )

    response = await provider.generate(
        prompt="Execute passive recon for target.com",
        system_prompt="You are a senior security auditor."
    )

    assert response.content == "Reconnaissance complete: discovered 4 APIs."
    assert response.prompt_tokens == 42
    assert response.completion_tokens == 12
    assert response.total_tokens == 54
    assert response.model == "claude-3-5-sonnet"
    assert len(captured_requests) == 1
    req = captured_requests[0]
    assert req.headers["Authorization"] == "Bearer sk-litellm-secret-key-xyz"
    assert req.headers["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_litellm_provider_json_mode_and_structured_output():
    """Verify LiteLLMProvider with json_mode passes response_format and structured output parses."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.read().decode("utf-8"))
        assert payload.get("response_format") == {"type": "json_object"}
        return httpx.Response(
            status_code=200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps({
                                "strategy": "Fast API assessment",
                                "target_count": 3,
                                "high_priority_tags": ["owasp-top-10", "sqli"]
                            })
                        }
                    }
                ],
                "usage": {"prompt_tokens": 20, "completion_tokens": 15, "total_tokens": 35}
            }
        )

    transport = httpx.MockTransport(mock_handler)
    provider = LiteLLMProvider(
        base_url="http://localhost:4000/v1",
        api_key="sk-test",
        model="gpt-4o",
        transport=transport
    )

    plan, _ = await provider.generate_structured(
        prompt="Generate assessment plan for microservice cluster",
        schema_class=SampleAssessmentPlan
    )

    assert plan.strategy == "Fast API assessment"
    assert plan.target_count == 3
    assert "sqli" in plan.high_priority_tags


@pytest.mark.asyncio
async def test_litellm_provider_error_handling():
    """Verify descriptive error wrapping when LiteLLM proxy responds with HTTP error or connection error."""
    def error_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=401,
            text='{"error": {"message": "Invalid LiteLLM virtual key", "type": "auth_error"}}'
        )

    transport = httpx.MockTransport(error_handler)
    provider = LiteLLMProvider(
        base_url="http://localhost:4000",
        api_key="invalid-key",
        transport=transport
    )

    with pytest.raises(RuntimeError) as exc_info:
        await provider.generate("Test prompt")

    assert "LiteLLM proxy returned HTTP error 401" in str(exc_info.value)
    assert "Invalid LiteLLM virtual key" in str(exc_info.value)


@pytest.mark.asyncio
async def test_litellm_health_check():
    """Verify health probe checks LiteLLM proxy /health endpoint."""
    def health_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(status_code=200, json={"status": "healthy"})
        return httpx.Response(status_code=404)

    transport = httpx.MockTransport(health_handler)
    provider = LiteLLMProvider(
        base_url="http://localhost:4000",
        api_key="sk-test",
        transport=transport
    )

    is_healthy = await provider.check_health()
    assert is_healthy is True


def test_get_default_llm_provider_factory(monkeypatch):
    """Verify provider factory instantiates LiteLLMProvider when configured in settings."""
    monkeypatch.setattr(settings, "llm_provider", "litellm")
    monkeypatch.setattr(settings, "litellm_base_url", "http://my-litellm-proxy:4000")
    monkeypatch.setattr(settings, "litellm_api_key", "sk-custom-master-key")
    monkeypatch.setattr(settings, "litellm_model", "deepseek-v3")

    provider = get_default_llm_provider()
    assert isinstance(provider, LiteLLMProvider)
    assert provider.chat_url == "http://my-litellm-proxy:4000/chat/completions"
    assert provider.api_key == "sk-custom-master-key"
    assert provider.model == "deepseek-v3"


@pytest.mark.asyncio
async def test_litellm_provider_json_prompt_injection_and_null_usage_fallback():
    """Verify LiteLLMProvider adds JSON instruction, tolerates null usage, and retries if empty choice."""
    calls = []

    def fallback_handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.read().decode("utf-8"))
        calls.append(payload)
        sys_msg = payload["messages"][0]["content"]
        assert "json" in sys_msg.lower()

        if len(calls) == 1:
            assert payload.get("response_format") == {"type": "json_object"}
            return httpx.Response(status_code=200, json={"choices": [{"message": {}}], "usage": None})

        assert "response_format" not in payload
        return httpx.Response(
            status_code=200,
            json={
                "choices": [{"message": {"content": '{"strategy": "Verified fallback json"}'}}],
                "usage": None
            }
        )

    transport = httpx.MockTransport(fallback_handler)
    provider = LiteLLMProvider(
        base_url="https://litellm.example.com/v1/",
        api_key="sk-test",
        model="azure/gpt-5.6-terra-dev-gtw",
        transport=transport
    )

    resp = await provider.generate(
        prompt="Summarize target recon posture",
        system_prompt="You are a security planner.",
        json_mode=True,
        temperature=0.2
    )
    assert len(calls) == 2
    assert "temperature" not in calls[0]
    assert "Verified fallback json" in resp.content
    assert resp.prompt_tokens > 0
    assert resp.completion_tokens > 0


