# Hunter-Agent Web Demo

This repository exposes the existing Hunter Layer 1 intake and verified Analysis
adapters through a minimal FastAPI UI. The Web layer does not identify files or
invoke Kong/TRUDI directly: every upload is first copied into the task-owned
`runs/<task_id>/artifacts/input/` evidence path by Layer 1.

## Install

From the repository root:

```bash
cd pentestgpt-core/pentestgpt_agent
uv sync --extra web
```

Kong requires its pinned environment under `third_party/kong`, JDK 21+, Ghidra,
and an inference provider. Configure `JAVA_HOME` (or `HUNTER_KONG_JAVA_HOME` for
the live tests), `GHIDRA_INSTALL_DIR`, `KONG_CONFIG_DIR`, and either an OpenAI or
Anthropic provider setting supported by Kong.

TRUDI requires the pinned environment under `third_party/trudi`. Two explicit
modes are available:

- `lite` runs deterministic FastMCP hash/stat/strings triage.
- `full` runs the official TRUDI investigation lifecycle through Claude Code as
  the agent runtime, while DeepSeek V4 Flash supplies Primary Analyst, Reason,
  and DAIR inference. Full mode exposes only the 21 MCP tools qualified on this
  machine and serializes cases in addition to giving every task an isolated
  HOME/cache. It never silently falls back to Lite.

The project-local Full runtime used by the verified setup is installed with:

```bash
npm install --prefix .runtime/node-runtime node@22.23.2
PATH="$PWD/.runtime/node-runtime/node_modules/.bin:$PATH" \
  npm install --prefix .runtime/claude-code @anthropic-ai/claude-code@2.1.251
```

Configure the existing local DeepSeek/Kong secret store interactively (the key
is not echoed) with `python3 scripts/set_kong_deepseek.py`. No Anthropic API key,
Anthropic login, or Claude model allocation is used.

## Run

```bash
python3 scripts/run_hunter_web_deepseek.py
```

Open <http://127.0.0.1:8000>. Current automatic routes are `reverse → Kong` and
`dfir → TRUDI`. Files identified as `pentest` or `vulnerability_research` remain
visible as `unsupported_domain`; those professional Web backends are not connected
in this demo. Background jobs are process-local and are not resumed after an app
restart, while completed run directories remain viewable. Full TRUDI currently
performs autonomous reasoning over a deliberately small static-file capability;
this is not a complete SIFT workstation and does not claim host-wide innocence
from a single file.
