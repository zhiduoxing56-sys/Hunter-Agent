from __future__ import annotations

from pathlib import Path

import pytest

from autopenbench_adapter.protocol import AutoPenBenchProtocolAdapter
from pentestgpt_agent.protocol.adapter import AdapterExecutionError
from pentestgpt_agent.protocol.contracts import AuthorizationScope, ErrorCategory, TaskSpec
from pentestgpt_agent.protocol.layout import RunLayout


def _authorized_task(adapter: AutoPenBenchProtocolAdapter, runs: Path) -> TaskSpec:
    game = adapter.game()
    task_id = "autopenbench-contract-test"
    workspace = str((runs / task_id).resolve())
    target = str(game["target"])
    return TaskSpec(
        task_id,
        "pentest",
        target,
        str(game["task"]),
        workspace=workspace,
        scope={"allowed_targets": [target]},
        authorization=AuthorizationScope((target,), workspace=workspace),
    )


@pytest.mark.asyncio
async def test_autopenbench_protocol_prepare_preserves_task_and_isolates_backend(tmp_path: Path) -> None:
    adapter = AutoPenBenchProtocolAdapter()
    runs = tmp_path / "runs"
    task = _authorized_task(adapter, runs)
    layout = RunLayout.ensure(runs, task)

    prepared = await adapter.prepare(task, layout)

    assert prepared.task_spec == task
    assert prepared.run_layout == layout
    command = prepared.backend_input["command"]
    assert "--run-id" in command
    assert f"{task.task_id}-backend" in command
    assert str(layout.artifacts / "backend-runs") in command
    assert command[command.index("--benchmark-root") + 1] == str(adapter.benchmark_root)


@pytest.mark.asyncio
async def test_autopenbench_protocol_rejects_unrelated_target_before_execution(tmp_path: Path) -> None:
    adapter = AutoPenBenchProtocolAdapter()
    runs = tmp_path / "runs"
    task = _authorized_task(adapter, runs)
    unrelated = TaskSpec(
        task.task_id,
        task.domain,
        "unrelated-target",
        task.goal,
        workspace=task.workspace,
        scope={"allowed_targets": ["unrelated-target"]},
        authorization=AuthorizationScope(("unrelated-target",), workspace=task.workspace),
    )
    layout = RunLayout.ensure(runs, unrelated)

    with pytest.raises(AdapterExecutionError) as captured:
        await adapter.prepare(unrelated, layout)

    assert captured.value.detail.category is ErrorCategory.INVALID_TASK
    assert adapter.last_pid is None

