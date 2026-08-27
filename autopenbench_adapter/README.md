# Hunter-Agent × AutoPenBench baseline adapter

This directory is an external evaluation harness. It uses the pinned
`pentestgpt-core` Git submodule and does not modify its prompts, loop, provider
adapter, or core tools at runtime.

## Fresh-clone setup

Clone this repository with its core submodule, then clone the public benchmark
beside the adapter:

```bash
git clone --recurse-submodules https://github.com/zhiduoxing56-sys/Hunter-Agent.git
cd Hunter-Agent
git clone https://github.com/lucagioacchini/auto-pen-bench.git AutoPenBench
cd pentestgpt-core/pentestgpt_agent
uv sync
cd ../..
```

Configure an OpenAI-compatible model without putting its key in a repository:

```bash
export HUNTER_MODEL_NAME='deepseek-v4-flash'
export HUNTER_MODEL_BASE_URL='https://api.deepseek.com'
export HUNTER_MODEL_API_KEY='your-api-key'
export HUNTER_MODEL_RESPONSE_FORMAT='json_object'
export HUNTER_MODEL_TIMEOUT_S='180'
```

The runner needs Docker access to build and remove disposable Kali and target
containers. After setup, run a task from the repository root:

```bash
PYTHONPATH=.:pentestgpt-core/pentestgpt_agent/src \
  pentestgpt-core/pentestgpt_agent/.venv/bin/python \
  autopenbench_adapter/run_baseline.py --vm=0
```

The runner defaults to 14 Executor turns so a RECOVER task can complete a
focused exploit revalidation and submit a captured flag. Override it only when
you intentionally want a tighter per-task budget.

The first task is deliberately the smallest web path-traversal task:
`in-vitro/web_security/vm0`.  The runner gives the frozen agent only the public
AutoPenBench task text and target identifier.  It starts the upstream Kali and
target containers, exposes real Kali/SSH/file tools through the existing
UnifiedAgent MCP seam, records every tool result, and removes the containers in
`finally`.

Run from the Hunter-Agent repository root using the pinned submodule environment:

```bash
PYTHONPATH=.:pentestgpt-core/pentestgpt_agent/src \
  pentestgpt-core/pentestgpt_agent/.venv/bin/python \
  autopenbench_adapter/run_baseline.py --level in-vitro --category web_security --vm 0
```

Or use the short wrapper (recommended for a terminal where long pasted lines
may wrap): `bash /home/tenggn/projects/Hunter-Agent/autopenbench_adapter/run_vm0.sh`.

Each run is stored under `Hunter-Agent/artifacts/autopenbench/runs/<run-id>/`:

- `traces/*/{input.json,events.jsonl,output.json}`: original model prompts,
  structured plans, MCP calls, real tool output, errors, usage, and retries.
- `model-requests.jsonl`: every OpenAI-compatible request payload and response
  (the API key is never in the payload or journal).
- `adapter-tool-events.jsonl`: container lifecycle and Kali/SSH command receipts.
- `submitted-answers.jsonl`: final answers actually submitted by the model.
- `autopenbench-evaluation.json`: independent upstream-flag comparison,
  execution/cleanup proof, total duration, and final result.

The only success condition is all of: Hunter-Agent completed, a submitted flag
equals AutoPenBench's oracle, at least one real Kali command was recorded, and
cleanup succeeded.  No solution file or oracle is shown to the agent.

The upstream Kali Dockerfile attempts a rolling upgrade which is currently
incompatible with its own published base image.  The adapter materializes a
per-run copy that retains that upstream workstation and skips only the broken
upgrade; no upstream source is changed.
