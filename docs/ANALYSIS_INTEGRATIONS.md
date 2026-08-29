# Analysis integrations

This subsystem reuses the frozen Hunter Protocol v1 contracts. It does not define
another `TaskSpec`, `AgentResult`, `AgentAdapter`, run layout, event model, error
taxonomy, verifier, or world-state boundary.

## Routes and scope

| Hunter domain | Adapter | Upstream entry point | Current scope |
|---|---|---|---|
| `reverse` | `KongAdapter` | Official `kong analyze` CLI subprocess | Full Ghidra-backed analysis with raw JSON/source output |
| `dfir` | `TrudiAdapter` | Official FastMCP stdio server | Real hash/stat/strings file triage and trace capture |

`AnalysisSupervisor` is a deterministic two-route dispatcher. Unsupported domains
produce an `invalid_task` result with code `ANALYSIS_DOMAIN_UNSUPPORTED`; it is not
an LLM planner or a global supervisor.

The TRUDI route intentionally does **not** claim to be a complete autonomous TRUDI
investigation. The current route calls the real upstream MCP server and preserves
its structured results and execution trace, but records
`reasoning_backend_used: false`. Full disk/memory tool coverage requires SANS SIFT;
the full gated investigation loop additionally requires a primary analyst client
plus configured DAIR and reviewer backends. Claude Code and Protocol SIFT are the
upstream reference client, not a requirement imposed on Hunter.

The current architecture decision is to keep Hunter as that primary decision
layer and TRUDI as the typed DFIR MCP/tool and guardrail boundary. The upstream
regression harness explicitly supports a custom agent client. Recreating TRUDI's
Claude orchestration inside this Adapter, or installing the reference Claude/SIFT
stack, is deferred until an acceptance case requires full gated findings/reporting.
See `docs/decisions/0001-trudi-mcp-boundary.md`.

## Upstream versions and manifests

- Kong: `third_party/kong`, upstream commit
  `8c4ee4bf52e0eb9efc3a0b22ad6da03387543fd2`, manifest
  `integrations/kong/manifest.json`.
- TRUDI: `third_party/trudi`, upstream commit
  `10559b13e01c06107165cc22db6ee17ec3c59f6c`, manifest
  `integrations/trudi/manifest.json`.

Both directories are clean submodules pinned to commits reachable from their
official `origin/main` branches. Three candidate Kong robustness changes were
discarded after the unmodified pinned commit completed the same benign full
analysis successfully (6 of 9 functions named, exit code 0, 52.1 seconds). The
earlier failure was an installation permission problem on Ghidra's native
decompiler, not a required Kong source fix.

Kong requires Python 3.11+, JDK 21+, Ghidra, and an inference provider. TRUDI's
lightweight route requires its Python environment and the FastMCP server. TRUDI
currently writes its upstream call trace under `~/.cache/trudi` as well as exporting
the selected trace into the Hunter run.

## Real verification (2026-08-29)

The benign Kong fixture is compiled from
`integrations/kong/tests/fixtures/benign.c`. The TRUDI fixture is
`integrations/trudi/tests/fixtures/benign_security.log`; neither fixture contains
malware.

Persisted real runs under the ignored `runs/` directory:

- `kong-analyze-smoke-20260829`: full Kong analysis, success.
- `trudi-smoke-20260829`: real TRUDI MCP file triage, success.
- `trudi-kong-parent-20260829-v2`: TRUDI exports a benign ELF artifact, success.
- `trudi-kong-child-20260829-v2`: Kong consumes that exact artifact, success.
- `analysis-unsupported-20260829`: structured unsupported-domain failure.

Each success `result.json` was read back as the existing `AgentResult` type and
passed `RunLayout.validate_result_references`. The parent artifact SHA-256 recorded
in the child `task.json` is
`58debb3bb473ddb5054d41c986f057599e8c4575ac7dfa6398036ad464ccb358`.

The earlier `trudi-kong-child-20260829` is deliberately retained as a failed-run
record: a relative Kong config directory was interpreted after changing the
subprocess working directory. The adapter now resolves that directory before launch,
and the `-v2` run verifies the fix.

Focused verification commands and results:

```text
python -m pytest integrations -q
11 passed in 59.73s

python -m pytest tests/test_protocol_adapter.py tests/test_protocol_contracts.py \
  tests/test_protocol_events.py tests/test_protocol_interfaces.py \
  tests/test_protocol_v1_acceptance.py tests/test_layer1_protocol_boundary.py -q
37 passed in 0.98s

cd third_party/kong && .venv/bin/python -m pytest -q
431 passed in 3.84s

cd third_party/trudi && .venv/bin/python -m pytest \
  tests/test_server.py tests/tools/test_hashing.py tests/tools/test_lifecycle.py -q
60 passed in 4.66s
```

Live tests require the paths and local inference settings represented by
`HUNTER_KONG_JAVA_HOME`, `HUNTER_KONG_GHIDRA_DIR`,
`HUNTER_KONG_CONFIG_DIR`, `HUNTER_KONG_SMOKE_BINARY`, `KONG_BASE_URL`,
`KONG_MODEL`, and `HUNTER_TRUDI_SMOKE_EVIDENCE`.
