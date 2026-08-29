from __future__ import annotations

from pathlib import Path

import pytest

from integrations.analysis_supervisor import AnalysisSupervisor
from pentestgpt_agent.protocol import ErrorCategory, ExecutionStatus, TaskSpec
from pentestgpt_agent.protocol.mock_adapter import MockAdapter


@pytest.mark.asyncio
@pytest.mark.parametrize(("domain", "expected_agent"), [("reverse", "kong-route"), ("dfir", "trudi-route")])
async def test_routes_supported_domains(
    tmp_path: Path, domain: str, expected_agent: str
) -> None:
    kong = MockAdapter()
    kong.agent_id = "kong-route"
    trudi = MockAdapter()
    trudi.agent_id = "trudi-route"
    supervisor = AnalysisSupervisor(kong_adapter=kong, trudi_adapter=trudi, runs_root=tmp_path / "runs")
    task = TaskSpec(task_id=f"route-{domain}", domain=domain, target="fixture", goal="route")

    result = await supervisor.execute(task)

    assert result.status is ExecutionStatus.SUCCESS
    assert result.agent_id == expected_agent


@pytest.mark.asyncio
async def test_unsupported_domain_is_structured_failure(tmp_path: Path) -> None:
    supervisor = AnalysisSupervisor(
        kong_adapter=MockAdapter(), trudi_adapter=MockAdapter(), runs_root=tmp_path / "runs"
    )
    task = TaskSpec(task_id="unsupported-analysis", domain="pentest", target="fixture", goal="route")

    result = await supervisor.execute(task)

    assert result.status is ExecutionStatus.FAILED
    assert result.error is not None
    assert result.error.category is ErrorCategory.INVALID_TASK
    assert result.error.code == "ANALYSIS_DOMAIN_UNSUPPORTED"
