"""Translate Kong's preserved outputs into Protocol v1 result components."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pentestgpt_agent.protocol import Evidence, Finding


def load_analysis(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Kong analysis.json must contain a JSON object")
    for key in ("binary", "stats", "functions"):
        if key not in value:
            raise ValueError(f"Kong analysis.json is missing {key!r}")
    if not isinstance(value["binary"], dict) or not isinstance(value["stats"], dict):
        raise ValueError("Kong binary and stats sections must be JSON objects")
    if not isinstance(value["functions"], list):
        raise ValueError("Kong functions section must be a JSON array")
    return value


def findings_from_analysis(value: dict[str, Any], *, evidence_id: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for index, item in enumerate(value["functions"]):
        if not isinstance(item, dict):
            raise ValueError("Kong function entries must be JSON objects")
        name = str(item.get("name") or item.get("original_name") or "unknown")
        address = str(item.get("address") or "unknown")
        comments = str(item.get("comments") or "")
        reasoning = str(item.get("reasoning") or "")
        description = comments or reasoning or f"Kong analyzed function {name} at {address}."
        findings.append(
            Finding(
                finding_id=f"kong-function-{index + 1}",
                type="reverse_engineered_function",
                title=f"{name} ({address})",
                description=description,
                evidence_refs=(evidence_id,),
                metadata={
                    "address": address,
                    "original_name": item.get("original_name"),
                    "signature": item.get("signature"),
                    "confidence": item.get("confidence"),
                    "classification": item.get("classification"),
                    "obfuscation_techniques": item.get("obfuscation_techniques", []),
                },
            )
        )
    return tuple(findings)


def parse_info_output(output: str) -> dict[str, str | int]:
    parsed: dict[str, str | int] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        normalized = key.lower().replace(" ", "_")
        if normalized in {"functions", "word_size"}:
            digits = "".join(character for character in value if character.isdigit())
            parsed[normalized] = int(digits) if digits else value
        elif normalized in {"binary", "path", "arch", "format", "endianness", "compiler"}:
            parsed[normalized] = value
    if "binary" not in parsed or "functions" not in parsed:
        raise ValueError("Kong info output is missing required binary metadata")
    return parsed


def analysis_evidence(artifact_id: str) -> Evidence:
    return Evidence(
        evidence_id="kong-analysis-evidence",
        type="backend_analysis",
        source="kong",
        description="Kong's original structured reverse-engineering output.",
        artifact_ref=artifact_id,
    )
