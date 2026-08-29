"""One-way Analysis artifact handoff; no planner or recursive loop."""

from __future__ import annotations

from dataclasses import dataclass

from pentestgpt_agent.protocol import AgentResult, ExecutionStatus, TaskSpec

from .analysis_supervisor import AnalysisSupervisor


@dataclass(frozen=True)
class LinkedAnalysisResults:
    dfir: AgentResult
    reverse: AgentResult | None


async def trudi_to_kong(
    supervisor: AnalysisSupervisor,
    dfir_task: TaskSpec,
    *,
    child_task_id: str,
) -> LinkedAnalysisResults:
    dfir_result = await supervisor.execute(dfir_task)
    if dfir_result.status is not ExecutionStatus.SUCCESS:
        return LinkedAnalysisResults(dfir_result, None)
    artifact = next(
        (item for item in dfir_result.artifacts if item.artifact_id == "trudi-exported-evidence"),
        None,
    )
    if artifact is None:
        return LinkedAnalysisResults(dfir_result, None)
    child = TaskSpec(
        task_id=child_task_id,
        domain="reverse",
        target=artifact.path,
        goal="Reverse engineer the binary artifact exported by the parent DFIR task.",
        metadata={
            "parent_task_id": dfir_task.task_id,
            "parent_agent": dfir_result.agent_id,
            "parent_artifact_id": artifact.artifact_id,
            "parent_artifact_sha256": artifact.sha256,
        },
    )
    return LinkedAnalysisResults(dfir_result, await supervisor.execute(child))
