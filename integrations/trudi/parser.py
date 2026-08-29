"""Translate TRUDI MCP triage output into Protocol v1 components."""

from __future__ import annotations

import json
import re
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


def _call_id(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _claim_identity(item: dict[str, Any]) -> str:
    claim = item.get("claim") if isinstance(item.get("claim"), dict) else {}
    identity = {
        "hypothesis": item.get("tested_hypothesis_id"),
        "kind": claim.get("kind"),
        "category": claim.get("category"),
        "act": claim.get("act"),
        "entities": sorted(str(value) for value in claim.get("entities_norm", []) if value),
        "principal": claim.get("principal_norm"),
        "answers_case_question": claim.get("answers_case_question"),
    }
    if any(value not in (None, "", [], False) for value in identity.values()):
        return json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return json.dumps(
        {
            "description": " ".join(str(item.get("description") or "").lower().split()),
            "source": item.get("source"),
            "linked_call_id": item.get("linked_call_id"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_finding_items(value: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    """Return only final, non-superseded and non-duplicate trace findings."""
    trace = value.get("trace", {})
    raw_items = trace.get("findings", []) if isinstance(trace, dict) else []
    items = [item for item in raw_items if isinstance(item, dict)]
    superseded = {
        call_id
        for item in items
        if (call_id := _call_id(item.get("supersedes"))) is not None
    }
    candidates = [item for item in items if _call_id(item.get("call_id")) not in superseded]

    # Official Full investigations may record exploratory SUSPECTED findings
    # before Reason admits a reportable claim. Once evaluated/gated candidates
    # exist, the ungated entries remain audit trace only, not final findings.
    gated = [
        item
        for item in candidates
        if _call_id(item.get("gated_by_evaluate_call_id")) is not None
    ]
    if gated:
        candidates = gated

    # A final trace should use ``supersedes`` explicitly. Keep the latest entry as
    # a defensive fallback when a backend emits duplicate final claims without it.
    latest_by_claim: dict[str, dict[str, Any]] = {}
    for item in candidates:
        latest_by_claim[_claim_identity(item)] = item
    selected = {id(item) for item in latest_by_claim.values()}
    return tuple(item for item in candidates if id(item) in selected)


def expired_finding_techniques(value: dict[str, Any]) -> tuple[str, ...]:
    """Techniques present only in findings replaced by the canonical findings."""
    trace = value.get("trace", {})
    raw_items = trace.get("findings", []) if isinstance(trace, dict) else []
    items = [item for item in raw_items if isinstance(item, dict)]
    canonical = canonical_finding_items(value)

    def techniques(values: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> set[str]:
        result: set[str] = set()
        for item in values:
            claim = item.get("claim") if isinstance(item.get("claim"), dict) else {}
            result.update(str(value) for value in claim.get("techniques", []) if value)
        return result

    return tuple(sorted(techniques(items) - techniques(canonical)))


def normalize_final_text(text: str, expired_techniques: tuple[str, ...]) -> str:
    """Remove expired technique identifiers from final mapped text only."""
    normalized = text
    for technique in expired_techniques:
        normalized = normalized.replace(technique, "superseded technique")
    return normalized


def _assignment_values(text: str, field: str) -> list[str]:
    pattern = re.compile(rf"\b{re.escape(field)}=(?:\"([^\"]*)\"|([^\s;,]+))")
    values: list[str] = []
    for match in pattern.finditer(text):
        value = match.group(1) if match.group(1) is not None else match.group(2)
        # Reason sometimes embeds verbatim log rows as JSON-escaped quotations.
        # Decode exactly that one wrapper layer; do not interpret general escape
        # sequences or repeatedly collapse legitimate UNC path separators.
        if value and value.startswith(r'\"') and value.endswith(r'\"'):
            value = value[2:-2].replace("\\\\", "\\")
        if value and value not in values:
            values.append(value)
    return values


def _structured_iocs(item: dict[str, Any]) -> dict[str, list[Any]]:
    supporting = str(item.get("supporting_evidence") or "")
    ports: list[int] = []
    for value in _assignment_values(supporting, "destination_port"):
        if value.isdigit() and int(value) not in ports:
            ports.append(int(value))
    hashes = [
        value.lower()
        for value in _assignment_values(supporting, "sha256")
        if re.fullmatch(r"[0-9a-fA-F]{64}", value)
    ]
    def windows_values(field: str) -> list[str]:
        normalized: list[str] = []
        for value in _assignment_values(supporting, field):
            if field != "task_name" and value.startswith("\\\\"):
                value = "\\\\" + re.sub(r"\\+", r"\\", value[2:])
            else:
                value = re.sub(r"\\+", r"\\", value)
            normalized.append(value)
        return normalized

    return {
        "ip": _assignment_values(supporting, "destination_ip"),
        "port": ports,
        "domain": _assignment_values(supporting, "destination_domain"),
        "url": _assignment_values(supporting, "source_url"),
        "file_path": windows_values("path"),
        "sha256": list(dict.fromkeys(hashes)),
        "registry_key": windows_values("key"),
        "scheduled_task": windows_values("task_name"),
    }


def _persistence_evidence_scope(
    item: dict[str, Any], iocs: dict[str, list[Any]],
) -> dict[str, Any]:
    classes = item.get("artifact_classes") if isinstance(item.get("artifact_classes"), dict) else {}
    class_names = {str(name).lower() for name in classes}
    registry_verified = any("registry" in name or "hive" in name for name in class_names)
    task_verified = any("scheduled_task" in name or "task_scheduler" in name for name in class_names)
    return {
        "log_observed": {
            "registry_persistence": bool(iocs["registry_key"]),
            "scheduled_task_persistence": bool(iocs["scheduled_task"]),
        },
        "independently_verified": {
            "registry_artifact": registry_verified,
            "task_scheduler_artifact": task_verified,
        },
        "artifact_classes": sorted(class_names),
    }


def full_findings(value: dict[str, Any], evidence_refs: tuple[str, ...]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    expired = expired_finding_techniques(value)
    for index, item in enumerate(canonical_finding_items(value), start=1):
        call_id = item.get("call_id")
        confidence = str(item.get("confidence") or "UNSPECIFIED")
        description = normalize_final_text(
            str(item.get("description") or "TRUDI recorded a finding."), expired,
        )
        iocs = _structured_iocs(item)
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
                    "supersedes": item.get("supersedes"),
                    "canonical": True,
                    "iocs": iocs,
                    "persistence_evidence_scope": _persistence_evidence_scope(item, iocs),
                },
            )
        )
    return tuple(findings)
