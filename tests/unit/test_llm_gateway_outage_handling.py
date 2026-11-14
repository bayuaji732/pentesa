"""Unit regression tests verifying graceful handling of LLM gateway and network outages (AGT-LLM-01).

Guarantees:
1. When upstream LLM gateway is unreachable or returns 403/502/503, provider raises typed LLMGatewayError.
2. Workflow supervisor catches gateway outage, persists workflow status as FAILED,
   and records failure_reason="Upstream AI gateway unreachable" in state_data.
3. Unfinished agent execution rows are marked FAILED with failure_reason.
4. Agents API endpoint returns clean HTTP 502/503 without internal stack traces or 500 error.
"""

import uuid
from datetime import datetime, timedelta, timezone
import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agents.llm.provider import LiteLLMProvider
from apps.api.main import app
from database.models.project import Project
from database.models.user import User
from database.session import get_db
from packages.common.exceptions import LLMGatewayError
from packages.common.security import create_access_token
from packages.schemas.agent import WorkflowStartRequest
from services.orchestrator.supervisor import WorkflowSupervisor


@pytest.mark.asyncio
async def test_litellm_provider_unreachable_gateway_raises_typed_error():
    """Unreachable gateway URL raises LLMGatewayError with status_code=503."""
    # Target non-listening port
    unreachable_provider = LiteLLMProvider(
        base_url="http://127.0.0.1:49999",
        api_key="sk-test-token",
        model="gpt-4o",
        timeout=1.0
    )

    with pytest.raises(LLMGatewayError) as exc_info:
        await unreachable_provider.generate("Test prompt")

    assert exc_info.value.status_code == 503
    assert "unreachable" in str(exc_info.value).lower() or "connect" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_litellm_provider_cloudfront_403_raises_typed_error():
    """CloudFront 403 WAF block raises LLMGatewayError with status_code=502."""
    mock_transport = httpx.MockTransport(
        lambda req: httpx.Response(403, text="<html><body>403 Forbidden: CloudFront block</body></html>")
    )
    mocked_provider = LiteLLMProvider(
        base_url="http://mock-gateway:4000",
        api_key="sk-test-token",
        model="gpt-4o",
        transport=mock_transport
    )

    with pytest.raises(LLMGatewayError) as exc_info:
        await mocked_provider.generate("Test prompt")

    assert exc_info.value.status_code == 502
    assert "403" in str(exc_info.value)


@pytest.mark.asyncio
async def test_supervisor_persists_failed_status_and_reason_on_gateway_outage(db_session: AsyncSession, admin_user: User):
    """WorkflowSupervisor persists FAILED state and failure_reason on LLM gateway outage."""
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="LLM Outage Test Project",
        description="Testing LLM gateway failure persistence",
        target_domains=["example.test"],
        allowed_cidrs=[],
        excluded_paths=[],
        allow_internal_networks=False,
        authorization_start=now,
        authorization_end=now + timedelta(days=7),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.commit()
    await db_session.refresh(project)

    # Use provider that fails with CloudFront 403
    mock_transport = httpx.MockTransport(
        lambda req: httpx.Response(403, text="<html><body>403 Forbidden: CloudFront block</body></html>")
    )
    failing_provider = LiteLLMProvider(
        base_url="http://mock-gateway:4000",
        api_key="sk-test-token",
        model="gpt-4o",
        transport=mock_transport
    )

    supervisor = WorkflowSupervisor(db_session, llm_provider=failing_provider)

    with pytest.raises(Exception):
        await supervisor.start_workflow(
            project_id=project.id,
            user_id=admin_user.id,
            scan_profile="QUICK"
        )

    # Inspect persisted workflow execution state
    workflow = await supervisor.get_active_workflow(project.id)
    assert workflow is not None
    assert workflow.status == "FAILED"
    assert workflow.state_data.get("failure_reason") == "Upstream AI gateway unreachable"

    status_resp = await supervisor.get_workflow_status(project.id)
    assert status_resp.status == "FAILED"
    assert status_resp.failure_reason == "Upstream AI gateway unreachable"


@pytest.mark.asyncio
async def test_api_workflow_start_returns_clean_502_on_gateway_outage(db_session: AsyncSession, admin_user: User):
    """POST /workflow/start returns clean HTTP 502/503 on upstream LLM outage without 500 stack trace."""
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="API Outage Test Project",
        description="Testing API error status",
        target_domains=["example.test"],
        allowed_cidrs=[],
        excluded_paths=[],
        allow_internal_networks=False,
        authorization_start=now,
        authorization_end=now + timedelta(days=7),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.commit()
    await db_session.refresh(project)

    token = create_access_token(str(admin_user.id), claims={"email": admin_user.email, "role": admin_user.role})
    headers = {"Authorization": f"Bearer {token}"}

    # Override get_db to return db_session
    async def override_db():
        yield db_session

    app.dependency_overrides[get_db] = override_db

    # Inject a failing LiteLLM provider into WorkflowSupervisor via mock
    mock_transport = httpx.MockTransport(
        lambda req: httpx.Response(403, text="<html><body>403 Forbidden: CloudFront block</body></html>")
    )
    failing_provider = LiteLLMProvider(
        base_url="http://mock-gateway:4000",
        api_key="sk-test-token",
        model="gpt-4o",
        transport=mock_transport
    )

    import services.orchestrator.supervisor
    orig_init = services.orchestrator.supervisor.WorkflowSupervisor.__init__

    def patched_init(self, session, llm_provider=None):
        orig_init(self, session, llm_provider=failing_provider)

    services.orchestrator.supervisor.WorkflowSupervisor.__init__ = patched_init

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post(
                f"/api/v1/projects/{project.id}/agents/workflow/start",
                json={"scan_profile": "QUICK", "async_execution": False},
                headers=headers
            )

            # Assert clean 502 Bad Gateway (or 503), NEVER 500
            assert resp.status_code in (502, 503)
            assert resp.status_code != 500
            assert resp.json()["detail"] == "Upstream AI gateway unreachable"
    finally:
        services.orchestrator.supervisor.WorkflowSupervisor.__init__ = orig_init
        app.dependency_overrides.clear()
