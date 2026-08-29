#!/usr/bin/env python3
"""Run one real HTTP upload through Hunter Web and TRUDI Full mode.

The caller must provide DEEPSEEK_API_KEY in the environment.  The key is
never printed or persisted by this harness.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import httpx

from web.app import create_app
from web.runtime import HunterRuntime, WebConfig


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = b"""2026-08-29T01:00:00Z host=lab01 event=login user=analyst result=success
2026-08-29T01:01:00Z host=lab01 event=file_created path=/opt/lab/hunter-kong-benign sha256=unknown
2026-08-29T01:02:00Z host=lab01 event=process_start image=/opt/lab/hunter-kong-benign disposition=training-fixture
"""
TERMINAL = {"success", "failed", "partial", "unsupported_domain"}


async def main() -> int:
    if not os.environ.get("DEEPSEEK_API_KEY"):
        raise SystemExit("DEEPSEEK_API_KEY is required")
    os.environ["HUNTER_TRUDI_MODE"] = "full"
    runtime = HunterRuntime(
        WebConfig(
            project_root=PROJECT_ROOT,
            runs_root=PROJECT_ROOT / "runs",
            staging_root=PROJECT_ROOT / ".runtime" / "web-full-e2e-staging",
            worker_count=1,
        )
    )
    transport = httpx.ASGITransport(app=create_app(runtime))
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://hunter.local", timeout=30
        ) as client:
            response = await client.post(
                "/api/tasks",
                files={"file": ("benign-full-dfir.log", FIXTURE, "application/octet-stream")},
            )
            response.raise_for_status()
            task_id = response.json()["task_id"]
            print(f"task_id={task_id}", flush=True)
            previous = None
            while True:
                status_response = await client.get(f"/api/tasks/{task_id}")
                status_response.raise_for_status()
                payload = status_response.json()
                state = (payload.get("status"), payload.get("stage"))
                if state != previous:
                    print(f"status={state[0]} stage={state[1]}", flush=True)
                    previous = state
                if state[0] in TERMINAL:
                    break
                if time.monotonic() - started > 1900:
                    raise TimeoutError("Web E2E polling exceeded 1900 seconds")
                await asyncio.sleep(5)

            result_response = await client.get(f"/api/tasks/{task_id}/result")
            result_response.raise_for_status()
            task, layout = runtime.load_task(task_id)
            result = layout.read_result()
            result.validate()
            layout.validate_result_references(result)
            print(f"domain={task.domain}", flush=True)
            print(f"result_status={result.status.value}", flush=True)
            print(f"result_path={layout.result_json}", flush=True)
            print(f"artifact_count={len(result.artifacts)}", flush=True)
            print(f"evidence_count={len(result.evidence)}", flush=True)
            return 0 if result.status.value == "success" else 2
    finally:
        runtime.close(wait=True)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
