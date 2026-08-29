from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from integrations.analysis_supervisor import AnalysisSupervisor
from integrations.kong import KongAdapter
from integrations.linking import trudi_to_kong
from integrations.trudi import TrudiAdapter
from pentestgpt_agent.protocol import ExecutionStatus, RunLayout, TaskSpec


def _required_path(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} is not configured for the real cross-adapter test")
    return Path(value)


@pytest.mark.asyncio
async def test_real_trudi_artifact_becomes_kong_child_input(tmp_path: Path) -> None:
    binary = _required_path("HUNTER_KONG_SMOKE_BINARY")
    kong = KongAdapter(
        java_home=_required_path("HUNTER_KONG_JAVA_HOME"),
        ghidra_dir=_required_path("HUNTER_KONG_GHIDRA_DIR"),
        kong_config_dir=Path(os.environ["HUNTER_KONG_CONFIG_DIR"]),
    )
    supervisor = AnalysisSupervisor(
        kong_adapter=kong,
        trudi_adapter=TrudiAdapter(),
        runs_root=tmp_path / "runs",
    )
    parent = TaskSpec(
        task_id="trudi-kong-parent",
        domain="dfir",
        target=str(binary),
        goal="Triage a benign ELF and export it for reverse analysis.",
        metadata={"export_evidence_artifact": True},
    )

    linked = await trudi_to_kong(supervisor, parent, child_task_id="trudi-kong-child")

    assert linked.dfir.status is ExecutionStatus.SUCCESS
    assert linked.reverse is not None
    assert linked.reverse.status is ExecutionStatus.SUCCESS
    assert linked.reverse.agent_id == "kong"
    parent_artifact = next(
        artifact for artifact in linked.dfir.artifacts
        if artifact.artifact_id == "trudi-exported-evidence"
    )
    child_task_path = tmp_path / "runs" / linked.reverse.task_id / "task.json"
    child_task = TaskSpec.from_dict(json.loads(child_task_path.read_text(encoding="utf-8")))
    child_layout = RunLayout.ensure(tmp_path / "runs", child_task)
    assert child_task.target == parent_artifact.path
    assert child_task.metadata["parent_task_id"] == parent.task_id
    assert child_task.metadata["parent_artifact_sha256"] == parent_artifact.sha256
    RunLayout.ensure(tmp_path / "runs", parent).validate_result_references(linked.dfir)
    child_layout.validate_result_references(linked.reverse)
