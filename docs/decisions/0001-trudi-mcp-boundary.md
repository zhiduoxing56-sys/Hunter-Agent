# Decision 0001: Hunter owns DFIR decisions; TRUDI supplies the MCP boundary

Status: accepted for the current Analysis milestone, 2026-08-29.

## Decision

Do not install or reproduce TRUDI's complete Claude Code orchestration pipeline
inside Hunter now. Hunter remains the primary decision layer and invokes the
official TRUDI FastMCP server as the professional DFIR backend.

The current `TrudiAdapter` remains deliberately scoped to real lightweight file
triage. A later DFIR milestone may broaden the MCP tool sequence or invoke
TRUDI's `dair.*`, `reason.*`, `misc.record_finding`, and report-gate tools, but
that work must be driven by a concrete disk, memory, or investigation acceptance
case rather than by the mere availability of those components.

## Evidence from the pinned upstream

- `server.py` describes TRUDI as a SIFT forensic tool gateway and exposes its
  capabilities through one FastMCP stdio boundary.
- `docs/architecture.md` separates the primary analyst from the MCP server. The
  primary analyst selects actions; DAIR directs phases; `reason.*` challenges
  conclusions; server-side gates enforce evidence and finding constraints.
- `tests/regression/README.md` explicitly permits an end-to-end client to be
  Claude Code, a custom agent, or manual replay. Hunter is therefore a supported
  architectural replacement for the reference Claude client, provided it obeys
  the MCP and gate contracts it elects to use.
- DAIR and `reason.*` support OpenAI-compatible/local backends. Claude is the
  upstream reference configuration, not the only possible backend.

These facts are pinned by the TRUDI submodule at
`10559b13e01c06107165cc22db6ee17ec3c59f6c`.

## Why the full pipeline is deferred

Running the reference pipeline would add three distinct obligations that the
current milestone does not need:

1. SANS SIFT and its forensic binaries for broad disk/memory coverage.
2. A primary analyst orchestration session and its Claude Code hooks/playbooks.
3. Two reasoning surfaces, DAIR and reviewer, with model capacity, timeouts,
   trace lineage, finding gates, and report gates.

Adding only some of these would produce a degraded run while making the Adapter
look more complete than it is. The current implementation instead reports its
scope and `reasoning_backend_used: false` explicitly.

## Revisit criteria

Reopen this decision only when at least one of these is required:

- a real disk or memory fixture needs SIFT-only tooling;
- acceptance requires TRUDI's gated `record_finding` or final report output;
- Hunter must demonstrate DAIR phase transitions and adversarial review rather
  than raw DFIR evidence collection;
- measured precision/recall shows the Hunter decision layer is insufficient.

At that point, prefer making Hunter a complete custom MCP client that consumes
the existing DAIR/reviewer/gate tools. Do not duplicate those state machines in
Hunter and do not default to installing Claude Code unless the selected
acceptance path specifically requires the upstream reference client.
