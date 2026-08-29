"""Translate TRUDI MCP triage output into Protocol v1 components."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pentestgpt_agent.protocol import Evidence, Finding


def load_triage(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("TRUDI runner result must be a JSON object")
    if value.get("success") is not True:
        raise ValueError(str(value.get("error") or "TRUDI triage did not succeed"))
    tools = value.get("tools")
    if not isinstance(tools, dict) or not isinstance(tools.get("hash_file"), dict):
        raise ValueError("TRUDI triage result is missing hash_file output")
    return value


def triage_finding(value: dict[str, Any], evidence_refs: tuple[str, ...]) -> Finding:
    hashed = value["tools"]["hash_file"]
    stat = value["tools"].get("stat_file", {})
    path = str(value.get("evidence_path") or hashed.get("file") or "evidence")
    return Finding(
        finding_id="trudi-evidence-triage",
        type="dfir_evidence_metadata",
        title=f"TRUDI triage of {Path(path).name}",
        description=(
            f"TRUDI hashed and inspected the evidence file ({hashed.get('size_bytes')} bytes); "
            "the attached artifacts preserve its MCP output, execution trace, and extracted strings."
        ),
        evidence_refs=evidence_refs,
        metadata={
            "sha256": hashed.get("sha256"),
            "md5": hashed.get("md5"),
            "sha1": hashed.get("sha1"),
            "stat": stat,
        },
    )


def artifact_evidence(evidence_id: str, artifact_id: str, description: str) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        type="forensic_tool_output",
        source="trudi",
        description=description,
        artifact_ref=artifact_id,
    )
