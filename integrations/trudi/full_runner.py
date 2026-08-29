"""Run one isolated, official TRUDI investigation through Claude Code.

Hunter owns process setup and result qualification only.  Investigation
planning, Reason, DAIR, gates, tool execution, and report writing remain in the
pinned TRUDI checkout.
"""

from __future__ import annotations

import argparse
import fcntl
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TRUDI_ROOT = PROJECT_ROOT / "third_party" / "trudi"
FULL_SERVER = PROJECT_ROOT / "integrations" / "trudi" / "full_server.py"
DEEPSEEK_URL = "https://api.deepseek.com"
DEEPSEEK_ANTHROPIC_URL = f"{DEEPSEEK_URL}/anthropic"
DEEPSEEK_MODEL = "deepseek-v4-flash"

_child: subprocess.Popen[str] | None = None


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def _deepseek_key() -> str:
    for name in ("HUNTER_TRUDI_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY"):
        value = os.environ.get(name)
        if value:
            return value
    raise RuntimeError("TRUDI Full requires DEEPSEEK_API_KEY")


def _configure_case(
    case_dir: Path,
    runtime_home: Path,
    *,
    case_id: str,
    evidence: Path,
    expected_sha256: str,
) -> Path:
    for directory in (
        case_dir / "analysis",
        case_dir / "exports",
        case_dir / "reports",
        case_dir / ".claude",
        runtime_home / ".claude",
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    shutil.copyfile(TRUDI_ROOT / "claude" / "CLAUDE.md", runtime_home / ".claude" / "CLAUDE.md")
    shutil.copyfile(
        TRUDI_ROOT / "case-template" / ".claude" / "settings.json",
        case_dir / ".claude" / "settings.json",
    )

    register_path = TRUDI_ROOT / "claude" / "hooks" / "_register_hooks.py"
    spec = importlib.util.spec_from_file_location("trudi_register_hooks", register_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("TRUDI hook registrar is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.register(
        runtime_home / ".claude" / "settings.json",
        str(TRUDI_ROOT / "claude" / "hooks"),
    )

    trust = {
        "projects": {
            str(PROJECT_ROOT): {"hasTrustDialogAccepted": True},
        }
    }
    _write_json(runtime_home / ".claude" / ".claude.json", trust)

    case_prompt = f"""# Case: {case_id}

**Evidence integrity: never modify the evidence file. All output must be produced through TRUDI MCP under `./analysis/`, `./exports/`, or `./reports/`.**

## Case metadata

- Case ID: `{case_id}`
- Evidence file: `{evidence}`
- Expected SHA-256: `{expected_sha256}`
- Evidence type: an individual file accepted and made read-only by Hunter Layer 1
- Evidence custody: task-owned Hunter artifact; do not copy or alter it

## Case question

Does this individual evidence file establish malicious activity, and what facts can be supported by the available evidence?

## Deployment capability boundary

This is a deliberately minimal TRUDI deployment, not a SIFT workstation. The MCP tools visible to you are the complete set actually qualified for this case. Do not request or invoke tools that are not visible. Disk-image, memory, EVTX, PCAP, Volatility, Plaso, Chainsaw, Sleuth Kit, and EZ Tools evidence is not present and those tools are unavailable.

Follow the official TRUDI lifecycle completely:

1. Start the execution trace and verify the expected evidence hash.
2. Perform real static triage with the visible tools.
3. Run typed `reason.hypothesize`, `reason.plan`, and DAIR assessment.
4. Execute applicable visible work orders. If a directive names an unavailable or evidence-inapplicable tool, record a typed disposition and ask DAIR to reassess; never fabricate a result.
5. Review the case-answering finding with Reason, record it with real call IDs, synthesize, run the pre-report gate, and honestly resolve permitted blockers.
6. Export the trace and create the final report through official TRUDI MCP tools.

Distinguish “not established by this individual file” from “the wider host is proven clean.” State every evidence limitation. Do not ask the operator questions.
"""
    (case_dir / "CLAUDE.md").write_text(case_prompt, encoding="utf-8")

    mcp_config = {
        "mcpServers": {
            "trudi-sift": {
                "type": "stdio",
                "command": str(TRUDI_ROOT / ".venv" / "bin" / "python"),
                "args": [str(FULL_SERVER)],
            }
        }
    }
    mcp_path = runtime_home / "mcp.json"
    _write_json(mcp_path, mcp_config)
    return mcp_path


def _child_environment(runtime_home: Path, node_bin: Path, key: str) -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
        environment.pop(name, None)
    environment.update(
        {
            "HOME": str(runtime_home),
            "CLAUDE_CONFIG_DIR": str(runtime_home / ".claude"),
            "PATH": f"{node_bin}:{environment.get('PATH', '')}",
            "DISABLE_AUTOUPDATER": "1",
            "DISABLE_TELEMETRY": "1",
            "ANTHROPIC_BASE_URL": DEEPSEEK_ANTHROPIC_URL,
            "ANTHROPIC_AUTH_TOKEN": key,
            "ANTHROPIC_MODEL": DEEPSEEK_MODEL,
            "ANTHROPIC_DEFAULT_OPUS_MODEL": DEEPSEEK_MODEL,
            "ANTHROPIC_DEFAULT_SONNET_MODEL": DEEPSEEK_MODEL,
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": DEEPSEEK_MODEL,
            "CLAUDE_CODE_SUBAGENT_MODEL": DEEPSEEK_MODEL,
            "REASON_BACKEND": "openai-compat",
            "REASON_URL": DEEPSEEK_URL,
            "REASON_API_KEY": key,
            "REASON_MODEL": DEEPSEEK_MODEL,
            "DAIR_BACKEND": "openai-compat",
            "DAIR_URL": DEEPSEEK_URL,
            "DAIR_API_KEY": key,
            "DAIR_MODEL": DEEPSEEK_MODEL,
            "TRUDI_COMPAT_EXTRA_BODY": '{"thinking":{"type":"disabled"}}',
            "TRUDI_COMPAT_NO_THINK_TOOLS": (
                "dair_assess,reason_plan,reason_cite_check,"
                "reason_confidence_score,reason_audit_findings"
            ),
            "TRUDI_COMPAT_NO_THINK_MODE": "both",
            "TRUDI_REASON_TIMEOUT": os.environ.get("TRUDI_REASON_TIMEOUT", "300"),
            "TRUDI_DAIR_TIMEOUT": os.environ.get("TRUDI_DAIR_TIMEOUT", "300"),
            "TRUDI_DEFAULT_TIMEOUT": os.environ.get("TRUDI_DEFAULT_TIMEOUT", "300"),
        }
    )
    return environment


def _terminate_child(_signum: int, _frame: Any) -> None:
    if _child is not None and _child.poll() is None:
        try:
            os.killpg(_child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    raise SystemExit(143)


def _trace_summary(trace_path: Path) -> dict[str, Any]:
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    entries = trace.get("entries")
    if not isinstance(entries, list):
        raise ValueError("TRUDI trace has no entries array")
    reason = [item for item in entries if item.get("type") == "reason_call"]
    dair = [item for item in entries if item.get("type") == "dair_call"]
    tools = [item for item in entries if item.get("type") == "tool_call"]
    findings = [item for item in entries if item.get("type") == "finding"]
    pre_report = [
        item for item in reason if item.get("tool") == "reason_pre_report_check"
    ]
    successful_tool_ids = {
        item.get("call_id") for item in tools if item.get("success") is True
    }
    traceable_findings = [
        item for item in findings if item.get("linked_call_id") in successful_tool_ids
    ]
    return {
        "entry_count": len(entries),
        "reason_calls": len(reason),
        "dair_calls": len(dair),
        "mcp_tool_calls": len(tools),
        "mcp_tool_names": [str(item.get("cmd") or "") for item in tools],
        "successful_mcp_tool_calls": sum(item.get("success") is True for item in tools),
        "findings": findings,
        "finding_count": len(findings),
        "traceable_finding_count": len(traceable_findings),
        "reason_backend_used": any(
            item.get("type") == "call_initiated"
            and str(item.get("tool") or "").startswith("reason_")
            and item.get("backend") == "openai-compat"
            for item in entries
        ),
        "dair_backend_used": any(
            item.get("type") == "call_initiated"
            and item.get("tool") == "dair_assess"
            and item.get("backend") == "openai-compat"
            for item in entries
        ),
        "ready_to_report": bool(pre_report and pre_report[-1].get("ready_to_report") is True),
    }


def _classify_failure(stderr: str, primary: dict[str, Any] | None, *, timed_out: bool) -> dict[str, Any]:
    text = f"{stderr}\n{json.dumps(primary or {})}".lower()
    if timed_out:
        return {"code": "TRUDI_FULL_TIMEOUT", "category": "timeout", "retryable": True,
                "message": "TRUDI Full exceeded its configured runtime."}
    if "401" in text or "authentication" in text or "invalid api key" in text:
        return {"code": "TRUDI_AUTHENTICATION", "category": "environment_error", "retryable": False,
                "message": "DeepSeek authentication failed."}
    if "429" in text or "rate limit" in text:
        return {"code": "TRUDI_RATE_LIMIT", "category": "backend_error", "retryable": True,
                "message": "DeepSeek rate-limited the investigation."}
    if "model" in text and ("unavailable" in text or "not found" in text):
        return {"code": "TRUDI_MODEL_UNAVAILABLE", "category": "dependency_error", "retryable": True,
                "message": "The configured DeepSeek model is unavailable."}
    if any(value in text for value in ("network", "connection", "dns", "timed out")):
        return {"code": "TRUDI_NETWORK", "category": "environment_error", "retryable": True,
                "message": "TRUDI Full could not reach its configured backend."}
    if primary is None or any(
        value in text for value in ("malformed", "json decode", "structured response")
    ):
        return {"code": "TRUDI_MALFORMED_STRUCTURED_RESPONSE", "category": "backend_error",
                "retryable": True, "message": "A reasoning backend returned malformed structured output."}
    return {"code": "TRUDI_FULL_INCOMPLETE", "category": "backend_error", "retryable": False,
            "message": "TRUDI Full did not satisfy every autonomous-investigation success condition."}


def run(args: argparse.Namespace) -> dict[str, Any]:
    global _child
    evidence = args.evidence.resolve(strict=True)
    if not evidence.is_file():
        raise ValueError("TRUDI Full requires an individual evidence file")
    case_dir = args.case_dir.resolve()
    runtime_home = args.runtime_home.resolve()
    key = _deepseek_key()
    mcp_path = _configure_case(
        case_dir,
        runtime_home,
        case_id=args.case_id,
        evidence=evidence,
        expected_sha256=args.expected_sha256,
    )
    environment = _child_environment(runtime_home, args.node_bin.resolve(), key)
    command = [
        str(args.claude.resolve()),
        "-p",
        (
            "Investigate this case autonomously now. Follow the complete official "
            "TRUDI lifecycle and do not stop until the gated final report and "
            "exported trace exist, or an honest non-recoverable blocker is recorded."
        ),
        "--mcp-config",
        str(mcp_path),
        "--strict-mcp-config",
        "--tools",
        "",
        "--allowedTools",
        "mcp__trudi-sift__*",
        "--permission-mode",
        "dontAsk",
        "--setting-sources",
        "user,project,local",
        "--max-turns",
        str(args.max_turns),
        "--output-format",
        "json",
        "--model",
        DEEPSEEK_MODEL,
        "--effort",
        "low",
    ]
    started = time.monotonic()
    timed_out = False
    with args.lock.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        _child = subprocess.Popen(
            command,
            cwd=case_dir,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = _child.communicate(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(_child.pid, signal.SIGTERM)
            try:
                stdout, stderr = _child.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(_child.pid, signal.SIGKILL)
                stdout, stderr = _child.communicate()
        returncode = _child.returncode
        _child = None
    args.primary_stdout.write_text(stdout, encoding="utf-8")
    args.primary_stderr.write_text(stderr, encoding="utf-8")
    primary: dict[str, Any] | None = None
    try:
        value = json.loads(stdout)
        if isinstance(value, dict):
            primary = value
    except json.JSONDecodeError:
        pass

    live_trace = case_dir / "analysis" / f"{args.case_id}_trace.json"
    trace_summary: dict[str, Any] = {}
    if live_trace.is_file():
        trace_summary = _trace_summary(live_trace)
    reports = sorted((case_dir / "reports").glob("*.md"))
    report = next((path for path in reports if not path.name.endswith("_trace.md")), None)
    exported_json = case_dir / "reports" / f"{args.case_id}_trace.json"
    exported_md = case_dir / "reports" / f"{args.case_id}_trace.md"
    model_usage = (primary or {}).get("modelUsage", {})
    primary_model = next(iter(model_usage), "") if isinstance(model_usage, dict) else ""
    primary_ok = bool(
        returncode == 0
        and primary
        and primary.get("is_error") is False
        and primary_model == DEEPSEEK_MODEL
    )
    full_success = bool(
        primary_ok
        and trace_summary.get("reason_backend_used")
        and trace_summary.get("dair_backend_used")
        and trace_summary.get("reason_calls", 0) >= 1
        and trace_summary.get("dair_calls", 0) >= 1
        and trace_summary.get("successful_mcp_tool_calls", 0) >= 1
        and trace_summary.get("traceable_finding_count", 0) >= 1
        and trace_summary.get("ready_to_report")
        and report is not None
        and exported_json.is_file()
        and exported_md.is_file()
    )
    failure = None if full_success else _classify_failure(stderr, primary, timed_out=timed_out)
    safe_primary = {
        "is_error": (primary or {}).get("is_error"),
        "session_id": (primary or {}).get("session_id"),
        "num_turns": (primary or {}).get("num_turns", 0),
        "stop_reason": (primary or {}).get("stop_reason"),
        "terminal_reason": (primary or {}).get("terminal_reason"),
        "model": primary_model,
        "result": (primary or {}).get("result", ""),
    }
    return {
        "success": full_success,
        "mode": "full",
        "case_id": args.case_id,
        "evidence_path": str(evidence),
        "expected_sha256": args.expected_sha256,
        "primary_runtime_used": primary_ok,
        "primary_model": primary_model,
        "primary_model_calls": int((primary or {}).get("num_turns", 0) or 0),
        "reason_backend_used": bool(trace_summary.get("reason_backend_used")),
        "dair_backend_used": bool(trace_summary.get("dair_backend_used")),
        "duration_seconds": time.monotonic() - started,
        "returncode": returncode,
        "timed_out": timed_out,
        "trace": trace_summary,
        "paths": {
            "case_dir": str(case_dir),
            "live_trace": str(live_trace) if live_trace.is_file() else None,
            "exported_trace_json": str(exported_json) if exported_json.is_file() else None,
            "exported_trace_md": str(exported_md) if exported_md.is_file() else None,
            "report": str(report) if report else None,
        },
        "primary": safe_primary,
        "failure": failure,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--case-dir", type=Path, required=True)
    parser.add_argument("--runtime-home", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--primary-stdout", type=Path, required=True)
    parser.add_argument("--primary-stderr", type=Path, required=True)
    parser.add_argument("--claude", type=Path, required=True)
    parser.add_argument("--node-bin", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--max-turns", type=int, default=60)
    parser.add_argument("--timeout", type=float, default=1800.0)
    args = parser.parse_args()
    for path in (args.output, args.primary_stdout, args.primary_stderr, args.lock):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    signal.signal(signal.SIGTERM, _terminate_child)
    result: dict[str, Any]
    returncode = 0
    try:
        result = run(args)
        if not result["success"]:
            returncode = 2
    except Exception as exc:
        result = {
            "success": False,
            "mode": "full",
            "trace": {},
            "failure": {
                "code": "TRUDI_FULL_RUNNER_ERROR",
                "category": "backend_error",
                "retryable": False,
                "message": f"{type(exc).__name__}: {exc}",
            },
        }
        returncode = 1
    _write_json(args.output, result)
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
