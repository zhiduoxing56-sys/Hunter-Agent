from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from integrations.kong import KongAdapter
from integrations.kong.parser import findings_from_analysis, load_analysis, parse_info_output
from pentestgpt_agent.protocol import AdapterRunner, ExecutionStatus, RunLayout, TaskSpec


def test_relative_config_directory_is_resolved_before_backend_changes_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    adapter = KongAdapter(kong_config_dir=Path("runtime/kong-config"))

    assert adapter.kong_config_dir == (tmp_path / "runtime/kong-config").resolve()


def test_parser_preserves_structured_function_details(tmp_path: Path) -> None:
    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(
        json.dumps(
            {
                "binary": {"name": "benign"},
                "stats": {"analyzed": 1, "llm_calls": 1},
                "functions": [
                    {
                        "address": "0x00401000",
                        "original_name": "FUN_00401000",
                        "name": "add_values",
                        "signature": "int add_values(int, int)",
                        "confidence": 91,
                        "classification": "math",
                        "comments": "Adds two integer values.",
                        "reasoning": "Observed a single addition operation.",
                        "obfuscation_techniques": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    loaded = load_analysis(analysis_path)
    findings = findings_from_analysis(loaded, evidence_id="kong-analysis-evidence")

    assert findings[0].title == "add_values (0x00401000)"
    assert findings[0].evidence_refs == ("kong-analysis-evidence",)
    assert findings[0].metadata["confidence"] == 91


def test_info_parser_requires_real_kong_fields() -> None:
    parsed = parse_info_output(
        """Binary: benign\nArch: x86\nFormat: ELF\nWord Size: 64-bit\nFunctions: 18\n"""
    )
    assert parsed == {
        "binary": "benign",
        "arch": "x86",
        "format": "ELF",
        "word_size": 64,
        "functions": 18,
    }


def _live_adapter() -> tuple[KongAdapter, Path]:
    java_home = os.environ.get("HUNTER_KONG_JAVA_HOME")
    ghidra_dir = os.environ.get("HUNTER_KONG_GHIDRA_DIR")
    binary = os.environ.get("HUNTER_KONG_SMOKE_BINARY")
    if not java_home or not ghidra_dir or not binary:
        pytest.skip("live Kong paths are not configured")
    return (
        KongAdapter(java_home=Path(java_home), ghidra_dir=Path(ghidra_dir)),
        Path(binary),
    )


@pytest.mark.asyncio
async def test_live_healthcheck_and_info_lifecycle_produce_valid_agent_result(
    tmp_path: Path,
) -> None:
    adapter, binary = _live_adapter()
    task = TaskSpec(
        task_id="kong-live-info",
        domain="reverse",
        target=str(binary),
        goal="Collect real Ghidra-backed binary metadata through Kong.",
        metadata={"kong_mode": "info"},
    )

    health = await adapter.healthcheck(task)
    assert health.available is True
    result = await AdapterRunner(adapter, runs_root=tmp_path / "runs").execute(task)

    assert result.status is ExecutionStatus.SUCCESS
    assert result.agent_id == "kong"
    assert result.metrics["mode"] == "info"
    assert result.artifacts and result.evidence and result.findings
    layout = RunLayout.ensure(tmp_path / "runs", task)
    assert layout.read_result() == result
    layout.validate_result_references(result)


@pytest.mark.asyncio
async def test_analyze_healthcheck_reports_missing_real_inference_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, binary = _live_adapter()
    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "KONG_BASE_URL", "KONG_MODEL"):
        monkeypatch.delenv(name, raising=False)
    task = TaskSpec(
        task_id="kong-no-provider",
        domain="reverse",
        target=str(binary),
        goal="Run complete Kong reverse engineering.",
    )

    health = await adapter.healthcheck(task)

    assert health.available is False
    assert health.error is not None
    assert health.error.code == "KONG_LLM_UNAVAILABLE"
