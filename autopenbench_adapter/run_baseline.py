"""Run one real AutoPenBench task through the unmodified Hunter-Agent loop."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import time
import traceback
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPOSITORY_ROOT.parent
PENTEST_ROOT = Path(
    os.environ.get(
        "PENTESTGPT_AGENT_ROOT",
        REPOSITORY_ROOT / "pentestgpt-core",
    )
).resolve()
if not PENTEST_ROOT.is_dir():
    # Keep existing local checkouts working during the transition to the
    # self-contained Git submodule layout.
    PENTEST_ROOT = WORKSPACE_ROOT / "PentestGPT"
PENTEST_SRC = PENTEST_ROOT / "pentestgpt_agent/src"
if str(PENTEST_SRC) not in sys.path:
    sys.path.insert(0, str(PENTEST_SRC))
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from unified_agent import SandboxPolicy, UnifiedAgent  # noqa: E402

from autopenbench_adapter.environment import AutoPenBenchSession, SessionConfig  # noqa: E402
from autopenbench_adapter.recording_backend import RecordingOpenAICompatibleBackend  # noqa: E402
from pentestgpt_agent.agents import (  # noqa: E402
    EXECUTOR_INSTRUCTIONS,
    SUPERVISOR_INSTRUCTIONS,
    Executor,
    Supervisor,
)
from pentestgpt_agent.openai_compatible import (  # noqa: E402
    OpenAICompatibleBackend,
    OpenAICompatibleConfig,
)
from pentestgpt_agent.trace import EpisodeRunner, TraceStore  # noqa: E402
from pentestgpt_agent.trial import TrialConfig, _resolved_config, run_trial  # noqa: E402


def _game(root: Path, level: str, category: str, vm: int) -> dict[str, Any]:
    data = json.loads((root / "data/games.json").read_text(encoding="utf-8"))
    try:
        game = data[level][category][vm]
    except (KeyError, IndexError) as exc:
        raise ValueError(
            f"unknown AutoPenBench task {level}/{category}/vm{vm}"
        ) from exc
    if not isinstance(game, dict):
        raise ValueError("malformed AutoPenBench game metadata")
    return game


def _roles(
    config: TrialConfig, env: dict[str, str], run_dir: Path
) -> tuple[Supervisor, Executor]:
    role_root = config.workspace_root / config.run_id
    provider: str | OpenAICompatibleBackend
    if config.backend == "openai_compatible":
        provider = RecordingOpenAICompatibleBackend(
            OpenAICompatibleConfig.from_env(
                model=config.model, base_url=config.provider_base_url
            ),
            journal_path=run_dir / "model-requests.jsonl",
        )
    else:
        provider = config.backend
    traces = TraceStore(config.runs_root)
    common = {
        "model": config.model,
        "effort": config.effort,
        "sandbox": SandboxPolicy.FULL_ACCESS,
        "tools": "autopenbench_adapter.tools:REGISTRY",
        "extra_env": env,
    }
    return (
        Supervisor(
            EpisodeRunner(
                UnifiedAgent(
                    provider,
                    workspace=role_root / "supervisor",
                    instructions=SUPERVISOR_INSTRUCTIONS,
                    **common,
                ),
                traces,
            ),
            max_turns=config.supervisor_max_turns,
        ),
        Executor(
            EpisodeRunner(
                UnifiedAgent(
                    provider,
                    workspace=role_root / "executor",
                    instructions=EXECUTOR_INSTRUCTIONS,
                    **common,
                ),
                traces,
            ),
            max_turns=config.executor_max_turns,
        ),
    )


def _judge(run_dir: Path, expected_flag: str) -> dict[str, Any]:
    answers = run_dir / "submitted-answers.jsonl"
    submitted: list[str] = []
    if answers.exists():
        for line in answers.read_text(encoding="utf-8").splitlines():
            value = json.loads(line)
            if isinstance(value.get("flag"), str):
                submitted.append(value["flag"])
    tool_trace = run_dir / "adapter-tool-events.jsonl"
    actual_tool_invocations = 0
    if tool_trace.exists():
        actual_tool_invocations = sum(
            1
            for line in tool_trace.read_text(encoding="utf-8").splitlines()
            if '"kind": "kali_command"' in line
        )
    return {
        "oracle": "upstream_data_games_json_exact_flag",
        "submitted_answers": submitted,
        "success": expected_flag in submitted,
        "actual_kali_commands": actual_tool_invocations,
        "valid_execution": actual_tool_invocations > 0,
    }


async def _run(args: argparse.Namespace) -> int:
    bench = args.benchmark_root.resolve()
    game = _game(bench, args.level, args.category, args.vm)
    run_id = (
        args.run_id
        or f"autopenbench-{args.level}-{args.category}-vm{args.vm}-{int(time.time())}"
    )
    runs_root = args.runs_root.resolve()
    run_dir = runs_root / run_id
    staging_dir = runs_root / f".staging-{run_id}"
    staging_dir.mkdir(parents=True, exist_ok=False)
    task_input = {
        key: game[key] for key in ("task", "target", "vulnerability") if key in game
    }
    (staging_dir / "autopenbench-task.json").write_text(
        json.dumps(task_input, indent=2) + "\n", encoding="utf-8"
    )
    session_config = SessionConfig(
        bench, args.level, args.category, game["target"], staging_dir
    )
    session = AutoPenBenchSession(session_config)
    environment = {
        "AUTOPENBENCH_ROOT": str(bench),
        "AUTOPENBENCH_LEVEL": args.level,
        "AUTOPENBENCH_CATEGORY": args.category,
        "AUTOPENBENCH_TARGET": game["target"],
        "AUTOPENBENCH_RUN_DIR": str(run_dir),
    }
    config = _resolved_config(
        TrialConfig(
            run_id=run_id,
            goal=game["task"],
            targets=(game["target"],),
            backend=args.backend,
            model=args.model,
            provider_base_url=args.provider_base_url,
            runs_root=runs_root,
            workspace_root=args.workspace_root.resolve(),
            effort=args.effort,
            max_decisions=args.max_decisions,
            supervisor_max_turns=args.supervisor_max_turns,
            executor_max_turns=args.executor_max_turns,
        )
    )
    summary: dict[str, Any] | None = None
    run_error: str | None = None
    started = time.time()
    cleanup_error: str | None = None
    try:
        session.start()
        supervisor, executor = _roles(config, environment, run_dir)
        summary = await run_trial(config, supervisor=supervisor, executor=executor)
    except Exception as exc:  # preserve a machine-readable failed attempt
        run_error = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()
    finally:
        try:
            session.cleanup()
        except Exception as exc:
            cleanup_error = f"{type(exc).__name__}: {exc}"
        # The frozen core owns creation of its run directory. Environment setup
        # runs before it, so its receipts are staged then merged afterwards.
        run_dir.mkdir(parents=True, exist_ok=True)
        for source in staging_dir.iterdir():
            if source.name == "upstream-machines":
                shutil.rmtree(source)
                continue
            destination = run_dir / source.name
            if source.name == "adapter-tool-events.jsonl" and destination.exists():
                with destination.open("a", encoding="utf-8") as stream:
                    stream.write(source.read_text(encoding="utf-8"))
            else:
                shutil.move(str(source), destination)
        shutil.rmtree(staging_dir)
    judgment = _judge(run_dir, game["flag"])
    evaluation = {
        "schema_version": 1,
        "run_id": run_id,
        "task": task_input,
        "summary": summary,
        "judge": judgment,
        "run_error": run_error,
        "cleanup_error": cleanup_error,
        "wall_duration_s": time.time() - started,
        "result": "success"
        if summary
        and summary.get("status") == "completed"
        and judgment["success"]
        and judgment["valid_execution"]
        and cleanup_error is None
        else "failure",
    }
    (run_dir / "autopenbench-evaluation.json").write_text(
        json.dumps(evaluation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("AUTOPENBENCH_RESULT=" + json.dumps(evaluation, sort_keys=True))
    return 0 if evaluation["result"] == "success" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark-root",
        type=Path,
        default=Path(
            os.environ.get("AUTOPENBENCH_ROOT", REPOSITORY_ROOT / "AutoPenBench")
        ),
    )
    parser.add_argument("--level", default="in-vitro")
    parser.add_argument("--category", default="web_security")
    parser.add_argument("--vm", type=int, default=0)
    parser.add_argument(
        "--backend", default=os.environ.get("HUNTER_MODEL_BACKEND", "openai_compatible")
    )
    parser.add_argument("--model", default=os.environ.get("HUNTER_MODEL_NAME"))
    parser.add_argument(
        "--provider-base-url", default=os.environ.get("HUNTER_MODEL_BASE_URL")
    )
    parser.add_argument("--effort")
    parser.add_argument("--run-id")
    parser.add_argument(
        "--runs-root",
        type=Path,
        default=REPOSITORY_ROOT / "artifacts/autopenbench/runs",
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=REPOSITORY_ROOT / "artifacts/autopenbench/workspaces",
    )
    parser.add_argument("--max-decisions", type=int, default=12)
    parser.add_argument("--supervisor-max-turns", type=int, default=4)
    parser.add_argument("--executor-max-turns", type=int, default=10)
    args = parser.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
