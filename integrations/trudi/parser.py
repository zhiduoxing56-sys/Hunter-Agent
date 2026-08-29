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


def load_full(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("mode") != "full":
        raise ValueError("TRUDI Full result must be a full-mode JSON object")
    trace = value.get("trace")
    if not isinstance(trace, dict):
        raise ValueError("TRUDI Full result is missing its trace qualification")
    return value


def full_findings(value: dict[str, Any], evidence_refs: tuple[str, ...]) -> tuple[Finding, ...]:
    trace = value.get("trace", {})
    items = trace.get("findings", []) if isinstance(trace, dict) else []
    findings: list[Finding] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        call_id = item.get("call_id")
        confidence = str(item.get("confidence") or "UNSPECIFIED")
        description = str(item.get("description") or "TRUDI recorded a finding.")
        findings.append(
            Finding(
                finding_id=f"trudi-full-finding-{call_id or index}",
                type="dfir_investigation_finding",
                title=f"TRUDI {confidence} finding",
                description=description,
                evidence_refs=evidence_refs,
                metadata={
                    "trace_call_id": call_id,
                    "linked_call_id": item.get("linked_call_id"),
                    "confidence": confidence,
                    "source": item.get("source"),
                    "claim": item.get("claim", {}),
                    "tested_hypothesis_id": item.get("tested_hypothesis_id"),
                },
            )
        )
    return tuple(findings)
