from __future__ import annotations

import json
import os
from hashlib import sha256
from pathlib import Path

import pytest

from integrations.trudi import TrudiAdapter
from integrations.trudi.adapter import _full_artifact_id
from integrations.trudi.full_runner import _classify_failure, _trace_summary
from integrations.trudi.full_server import MINIMAL_FULL_TOOLS, mcp as full_mcp
from integrations.trudi.parser import full_findings, load_full, load_triage, triage_finding
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


@pytest.mark.asyncio
async def test_full_server_exposes_only_qualified_official_tools() -> None:
    tools = await full_mcp.list_tools()
    names = {tool.name for tool in tools}

    assert names == MINIMAL_FULL_TOOLS
    assert "hash_hash_file" in names
    assert "reason_reason_plan" in names
    assert "dair_dair_assess" in names
    assert "vol_vol_pslist" not in names
    assert "misc_chainsaw_hunt" not in names


@pytest.mark.asyncio
async def test_full_mode_missing_reasoning_key_fails_without_lite_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence.log"
    evidence.write_text("benign fixture\n", encoding="utf-8")
    digest = sha256(evidence.read_bytes()).hexdigest()
    for name in ("HUNTER_TRUDI_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    adapter = TrudiAdapter(mode="full")
    task = TaskSpec(
        task_id="trudi-full-no-key",
        domain="dfir",
        target=str(evidence),
        goal="full",
        metadata={"file_type": {"sha256": digest}},
    )

    health = await adapter.healthcheck(task)

    assert health.available is False
    assert health.error is not None
    assert health.error.code == "TRUDI_REASONING_UNAVAILABLE"


@pytest.mark.asyncio
async def test_full_prepare_is_task_isolated_and_never_places_key_in_argv(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence.log"
    evidence.write_text("benign fixture\n", encoding="utf-8")
    digest = sha256(evidence.read_bytes()).hexdigest()
    adapter = TrudiAdapter(mode="full")
    tasks = [
        TaskSpec(
            task_id=f"trudi-full-isolation-{suffix}",
            domain="dfir",
            target=str(evidence),
            goal="full",
            metadata={"file_type": {"sha256": digest}},
        )
        for suffix in ("a", "b")
    ]
    prepared = []
    for task in tasks:
        layout = RunLayout.ensure(tmp_path / "runs", task)
        prepared.append(await adapter.prepare(task, layout))

    commands = [item.backend_input["command"] for item in prepared]
    assert all(item.metadata["mode"] == "full" for item in prepared)
    assert all(item.metadata["manifest"]["timeout"] == 1800 for item in prepared)
    assert commands[0] != commands[1]
    assert "trudi-full-isolation-a/runtime/trudi-home" in " ".join(commands[0])
    assert "trudi-full-isolation-b/runtime/trudi-home" in " ".join(commands[1])
    assert "secret" not in " ".join(sum(commands, []))
    assert all(
        not any(str(part).endswith("integrations/trudi/runner.py") for part in command)
        for command in commands
    )


def test_full_parser_and_trace_qualification_preserve_real_lineage(tmp_path: Path) -> None:
    trace_path = tmp_path / "trace.json"
    trace_path.write_text(json.dumps({
        "entries": [
            {"call_id": 1, "type": "call_initiated", "tool": "reason_plan", "backend": "openai-compat"},
            {"call_id": 2, "type": "reason_call", "tool": "reason_plan", "success": True},
            {"call_id": 3, "type": "call_initiated", "tool": "dair_assess", "backend": "openai-compat"},
            {"call_id": 4, "type": "dair_call"},
            {"call_id": 5, "type": "tool_call", "cmd": "<py>:hash_hash_file", "success": True},
            {
                "call_id": 6,
                "type": "finding",
                "description": "Verified benign fixture content.",
                "confidence": "CONFIRMED",
                "source": "hash.hash_file",
                "linked_call_id": 5,
                "claim": {"kind": "positive"},
            },
            {
                "call_id": 7,
                "type": "reason_call",
                "tool": "reason_pre_report_check",
                "success": True,
                "ready_to_report": True,
            },
        ]
    }), encoding="utf-8")
    summary = _trace_summary(trace_path)
    output = tmp_path / "full.json"
    output.write_text(json.dumps({"mode": "full", "trace": summary}), encoding="utf-8")

    value = load_full(output)
    findings = full_findings(value, ("trace-evidence",))

    assert summary["reason_backend_used"] is True
    assert summary["dair_backend_used"] is True
    assert summary["traceable_finding_count"] == 1
    assert summary["ready_to_report"] is True
    assert findings[0].metadata["linked_call_id"] == 5


@pytest.mark.parametrize(
    ("stderr", "primary", "timed_out", "code"),
    [
        ("HTTP 401 authentication failed", {}, False, "TRUDI_AUTHENTICATION"),
        ("HTTP 429 rate limit", {}, False, "TRUDI_RATE_LIMIT"),
        ("", None, False, "TRUDI_MALFORMED_STRUCTURED_RESPONSE"),
        ("", {}, True, "TRUDI_FULL_TIMEOUT"),
    ],
)
def test_full_backend_failures_keep_distinct_error_codes(
    stderr: str, primary: dict[str, object] | None, timed_out: bool, code: str,
) -> None:
    assert _classify_failure(stderr, primary, timed_out=timed_out)["code"] == code


def test_full_artifact_ids_leave_room_for_evidence_suffix() -> None:
    relative = Path("reports") / ("case-" + "x" * 180 + "_trace.json")

    artifact_id = _full_artifact_id(relative)

    assert len(artifact_id) <= 119
    assert len(f"{artifact_id}-evidence") <= 128
    assert artifact_id == _full_artifact_id(relative)


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
