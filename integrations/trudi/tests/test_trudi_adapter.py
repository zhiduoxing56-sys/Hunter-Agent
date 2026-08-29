from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from integrations.trudi import TrudiAdapter
from integrations.trudi.parser import load_triage, triage_finding
from pentestgpt_agent.protocol import AdapterRunner, ExecutionStatus, RunLayout, TaskSpec


def test_parser_requires_successful_structured_hash_output(tmp_path: Path) -> None:
    output = tmp_path / "trudi_result.json"
    output.write_text(json.dumps({
        "success": True,
        "evidence_path": "/evidence/a.log",
        "tools": {
            "hash_file": {
                "success": True,
                "size_bytes": 12,
                "md5": "m",
                "sha1": "s1",
                "sha256": "s256",
            },
            "stat_file": {"success": True},
        },
    }), encoding="utf-8")

    value = load_triage(output)
    finding = triage_finding(value, ("trudi-output-evidence",))

    assert finding.type == "dfir_evidence_metadata"
    assert finding.evidence_refs == ("trudi-output-evidence",)
    assert finding.metadata["sha256"] == "s256"


def _live_target() -> Path:
    value = os.environ.get("HUNTER_TRUDI_SMOKE_EVIDENCE")
    if not value:
        pytest.skip("live TRUDI evidence is not configured")
    return Path(value)


@pytest.mark.asyncio
async def test_live_healthcheck_and_mcp_lifecycle_produce_valid_agent_result(
    tmp_path: Path,
) -> None:
    target = _live_target()
    adapter = TrudiAdapter()
    task = TaskSpec(
        task_id="trudi-live-triage",
        domain="dfir",
        target=str(target),
        goal="Run real TRUDI MCP file triage.",
    )

    health = await adapter.healthcheck(task)
    assert health.available is True
    assert int(health.details["tool_count"]) >= 200
    result = await AdapterRunner(adapter, runs_root=tmp_path / "runs").execute(task)

    assert result.status is ExecutionStatus.SUCCESS
    assert result.agent_id == "trudi"
    assert result.metrics["reasoning_backend_used"] is False
    layout = RunLayout.ensure(tmp_path / "runs", task)
    assert layout.read_result() == result
    layout.validate_result_references(result)
