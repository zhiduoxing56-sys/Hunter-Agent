"""Protocol v1 AgentAdapter for TRUDI's official FastMCP stdio server."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from pentestgpt_agent.protocol import (
    AgentAdapter,
    AgentManifest,
    AgentResult,
    Artifact,
    ErrorCategory,
    ErrorDetail,
    ExecutionHandle,
    ExecutionStatus,
    HealthcheckResult,
    PreparedTask,
    RunLayout,
    TaskSpec,
)
from pentestgpt_agent.protocol.contracts import utc_now

from .parser import artifact_evidence, load_triage, triage_finding


@dataclass
class _Process:
    process: asyncio.subprocess.Process
    stdout_stream: BinaryIO
    stderr_stream: BinaryIO
    stdout_path: Path
    stderr_path: Path
    started_at: str
    started_monotonic: float


class TrudiAdapter(AgentAdapter):
    agent_id = "trudi"

    def __init__(self, *, repo_root: Path | None = None) -> None:
        self.repo_root = (repo_root or Path(__file__).resolve().parents[2]).resolve()
        self.manifest = AgentManifest.load(Path(__file__).with_name("manifest.json"))
        self.executable = self.repo_root / self.manifest.start[0]
        self.runner = self.repo_root / self.manifest.start[1]
        self.server = self.repo_root / self.manifest.start[3]
        self._processes: dict[str, _Process] = {}

    async def healthcheck(self, task_spec: TaskSpec) -> HealthcheckResult:
        try:
            task_spec.validate()
            if task_spec.domain != "dfir":
                return _unavailable(ErrorCategory.INVALID_TASK, "TRUDI requires domain='dfir'", "TRUDI_DOMAIN")
            target = Path(task_spec.target).resolve()
            if not target.is_file():
                return _unavailable(ErrorCategory.INVALID_TASK, f"TRUDI lightweight target is not a file: {target}", "TRUDI_TARGET")
            missing = [str(path) for path in (self.executable, self.runner, self.server) if not path.is_file()]
            if missing:
                return _unavailable(ErrorCategory.DEPENDENCY_ERROR, f"TRUDI runtime files are unavailable: {', '.join(missing)}", "TRUDI_RUNTIME")
            probe = await asyncio.create_subprocess_exec(
                str(self.executable), "-c", "import asyncio, server; print(len(asyncio.run(server.mcp.list_tools())))",
                cwd=self.server.parent,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await probe.communicate()
            if probe.returncode != 0:
                return _unavailable(ErrorCategory.DEPENDENCY_ERROR, f"TRUDI server import failed: {stderr.decode(errors='replace')[-500:]}", "TRUDI_IMPORT")
            return HealthcheckResult(True, {
                "executable": str(self.executable),
                "server": str(self.server),
                "tool_count": stdout.decode().strip(),
                "manifest": self.manifest.to_dict(),
                "reasoning_backend_ready": _reasoning_backend_ready(),
                "scope": "lightweight_file_triage",
            })
        except Exception as exc:
            return _unavailable(ErrorCategory.INVALID_TASK, str(exc), "TRUDI_HEALTHCHECK")

    async def prepare(self, task_spec: TaskSpec, run_layout: RunLayout) -> PreparedTask:
        task_spec.validate()
        output = run_layout.artifacts / "trudi_result.json"
        case_dir = run_layout.artifacts / "trudi-case"
        command = [
            str(self.executable), str(self.runner),
            "--server", str(self.server),
            "--evidence", str(Path(task_spec.target).resolve()),
            "--case-dir", str(case_dir),
            "--output", str(output),
        ]
        if task_spec.metadata.get("export_evidence_artifact") is True:
            command.append("--export-evidence")
        return PreparedTask(
            task_spec,
            run_layout,
            backend_input={"command": command, "output": str(output)},
            metadata={"manifest": self.manifest.to_dict(), "scope": "lightweight_file_triage"},
        )

    async def run(self, prepared: PreparedTask) -> ExecutionHandle:
        stdout_path = prepared.run_layout.logs / "trudi.stdout.log"
        stderr_path = prepared.run_layout.logs / "trudi.stderr.log"
        stdout_stream = stdout_path.open("wb")
        stderr_stream = stderr_path.open("wb")
        try:
            process = await asyncio.create_subprocess_exec(
                *prepared.backend_input["command"],
                cwd=self.repo_root,
                env=os.environ.copy(),
                stdout=stdout_stream,
                stderr=stderr_stream,
                start_new_session=True,
            )
        except Exception:
            stdout_stream.close()
            stderr_stream.close()
            raise
        backend_id = f"trudi-{uuid.uuid4().hex}"
        started_at = utc_now()
        self._processes[backend_id] = _Process(process, stdout_stream, stderr_stream, stdout_path, stderr_path, started_at, time.monotonic())
        return ExecutionHandle(backend_id, started_at, {"pid": process.pid})

    async def collect(self, prepared: PreparedTask, handle: ExecutionHandle) -> AgentResult:
        context = self._processes.get(handle.backend_id)
        if context is None:
            raise RuntimeError("unknown TRUDI process handle")
        returncode = await context.process.wait()
        context.stdout_stream.close()
        context.stderr_stream.close()
        elapsed = time.monotonic() - context.started_monotonic
        self._processes.pop(handle.backend_id, None)
        output_path = Path(str(prepared.backend_input["output"]))
        if returncode != 0 or not output_path.is_file():
            error_text = context.stderr_path.read_text(encoding="utf-8", errors="replace")
            return _failed(prepared, context.started_at, elapsed, returncode, error_text)
        try:
            value = load_triage(output_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return _failed(prepared, context.started_at, elapsed, returncode, str(exc))
        artifacts = [Artifact.from_path("trudi-raw-result", "dfir_raw_result", output_path, producer=self.agent_id)]
        trace_path = Path(str(value["trace_path"]))
        if trace_path.is_file():
            artifacts.append(Artifact.from_path("trudi-trace", "dfir_execution_trace", trace_path, producer=self.agent_id))
        strings_path_value = value.get("strings_path")
        if strings_path_value and Path(str(strings_path_value)).is_file():
            artifacts.append(Artifact.from_path("trudi-strings", "extracted_strings", Path(str(strings_path_value)), producer=self.agent_id))
        exported_value = value.get("exported_evidence_path")
        if exported_value and Path(str(exported_value)).is_file():
            exported_path = Path(str(exported_value))
            with exported_path.open("rb") as stream:
                magic = stream.read(4)
            artifact_type = "suspect_binary" if magic == b"\x7fELF" else "exported_evidence"
            artifacts.append(Artifact.from_path("trudi-exported-evidence", artifact_type, exported_path, producer=self.agent_id))
        evidence = tuple(
            artifact_evidence(f"{artifact.artifact_id}-evidence", artifact.artifact_id, f"Original TRUDI output: {artifact.type}.")
            for artifact in artifacts
        )
        finding = triage_finding(value, tuple(item.evidence_id for item in evidence))
        return AgentResult(
            task_id=prepared.task_spec.task_id,
            agent_id=self.agent_id,
            domain=prepared.task_spec.domain,
            status=ExecutionStatus.SUCCESS,
            started_at=context.started_at,
            finished_at=utc_now(),
            summary="TRUDI completed real MCP-based hash, stat, and strings triage of the evidence file.",
            findings=(finding,),
            evidence=evidence,
            artifacts=tuple(artifacts),
            metrics={"wall_seconds": elapsed, "tool_calls": 4, "reasoning_backend_used": False},
            raw_output={"returncode": returncode, "stdout_log": str(context.stdout_path), "stderr_log": str(context.stderr_path), "trudi": value},
        )

    async def stop(self, prepared: PreparedTask | None, *, reason: str) -> None:
        for backend_id, context in list(self._processes.items()):
            if context.process.returncode is None:
                with suppress(ProcessLookupError):
                    os.killpg(context.process.pid, signal.SIGTERM)
                try:
                    await asyncio.wait_for(context.process.wait(), timeout=2)
                except TimeoutError:
                    with suppress(ProcessLookupError):
                        os.killpg(context.process.pid, signal.SIGKILL)
                    await context.process.wait()
            context.stdout_stream.close()
            context.stderr_stream.close()
            self._processes.pop(backend_id, None)


def _reasoning_backend_ready() -> bool:
    return bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or (os.environ.get("REASON_URL") and os.environ.get("DAIR_URL"))
    )


def _unavailable(category: ErrorCategory, message: str, code: str) -> HealthcheckResult:
    return HealthcheckResult(False, {"code": code}, ErrorDetail(category, message, code=code))


def _failed(prepared: PreparedTask, started_at: str, elapsed: float, returncode: int, detail: str) -> AgentResult:
    summary = f"TRUDI lightweight triage exited with status {returncode}."
    return AgentResult(
        task_id=prepared.task_spec.task_id,
        agent_id="trudi",
        domain=prepared.task_spec.domain,
        status=ExecutionStatus.FAILED,
        started_at=started_at,
        finished_at=utc_now(),
        summary=summary,
        metrics={"wall_seconds": elapsed},
        error=ErrorDetail(ErrorCategory.BACKEND_ERROR, summary, code="TRUDI_PROCESS_FAILED", metadata={"returncode": returncode, "detail": detail[-2000:]}),
        raw_output={"returncode": returncode, "detail": detail[-4000:]},
    )
