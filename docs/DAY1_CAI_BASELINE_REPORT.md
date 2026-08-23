# Day 1 — CAI Baseline Validation Report

Date: 2026-08-24
Branch: `dev`
Verdict: **DAY1_PASS**

## A. Environment

- Runtime: WSL2 Ubuntu, Python 3.12.3, project virtual environment.
- Safety flags in every newly executed test: `CAI_TRACING=false`,
  `OPENAI_AGENTS_DISABLE_TRACING=true`, and `CAI_YOLO=false`.
- Provider: real `deepseek/deepseek-chat`, via DeepSeek's OpenAI-compatible
  endpoint. Credential values were neither printed nor written.
- All model invocations had `max_turns`; specialist and handoff tests also use
  a 90-second asyncio timeout and were launched with a 120-second process cap.

## B. Upstream CAI baseline

**PASS** — the authoritative baseline is `cai-framework` **0.5.10**, installed
editable from `third_party/cai_framework-0.5.10`. `UPSTREAM_BASELINE.md`
records the verified source archive SHA-256
`de82ac5560eb01548f2e6d74e00d7718d4b8bfa04ab3843dc3645f50efe1d293`.
Archive v1.1.5 was not used.

## C. Test 01 runtime import

**PASS** — `import cai` and `from cai.sdk.agents import Agent, Runner` succeeded;
installed distribution version was exactly `0.5.10`.

Evidence: `artifacts/smoke/test01_runtime_import.log`.

## D. Test 02 real DeepSeek LLM

**PASS** — a real `OpenAIChatCompletionsModel` request to
`deepseek/deepseek-chat` completed through `Runner.run`, producing the required
`HUNTER_LLM_PASS` output.

Evidence: `artifacts/smoke/test02_deepseek_agent.log`.

## E. Test 03 real function tool calling

**PASS** — DeepSeek requested the local `add` function with `(17, 25)`;
the function actually executed and returned `42`, after which the model produced
a final answer containing `42`.

Evidence: `artifacts/smoke/test03_tool_call.log`.

## F. CAI 0.5.10 specialist agent inventory

The following was reconfirmed from the actual 0.5.10 source, rather than assumed:

| Area | Module and exported Agent | Enumerated upstream tools |
| --- | --- | --- |
| Reverse | `cai.agents.reverse_engineering_agent.reverse_engineering_agent` | `generic_linux_command`, `run_ssh_command_with_credentials`, `execute_code` |
| Red/Pentest | `cai.agents.red_teamer.redteam_agent` | `generic_linux_command`, `execute_code` |
| DFIR | `cai.agents.dfir.dfir_agent` | `generic_linux_command`, `run_ssh_command_with_credentials`, `execute_code`, `think` |
| Vulnerability research | `cai.agents.bug_bounter.bug_bounter_agent` | `generic_linux_command`, `execute_code`, `shodan_search`, `shodan_host_info` |

Each test imported the module, verified the object is an SDK `Agent`, constructed
a new SDK `Agent` from its real prompt/model/tool configuration, loaded its
instructions, and enumerated its tools. For the actual model call, a no-tools
clone preserved that specialist's real upstream instructions and DeepSeek model.
This deliberate safety isolation prevented the model from invoking upstream
shell, SSH, search, or Shodan tools; it is not a mock or fake model.

## G. Reverse smoke

**PASS** — the real Reverse Engineering Specialist received the local/read-only
ELF triage task and returned a non-empty read-only analysis plan.

Evidence: `artifacts/day1/04_reverse_specialist.log`.

## H. Red/Pentest smoke

**PASS** — the real Red Team Agent completed the fictional `example.invalid`
planning task. No tools were available to its execution clone and no network
scan was performed.

Evidence: `artifacts/day1/05_red_specialist.log`.

## I. DFIR smoke

**PASS** — the real DFIR Agent analyzed only the supplied simulated log line and
returned an evidence-preserving first action.

Evidence: `artifacts/day1/06_dfir_specialist.log`.

## J. Vulnerability Research smoke

**PASS** — the real Bug Bounter Agent reviewed the local illustrative query code
and identified SQL injection and related review categories without executing tools.

Evidence: `artifacts/day1/07_vuln_specialist.log`.

## K. SDK handoff smoke

**PASS** — source inspection confirmed the CAI SDK pattern is `handoffs=[agent]`
or `handoff(agent=...)`; the 0.5.10 customer-service and agent-pattern examples
use that same mechanism. The real Router run generated one SDK
`HandoffCallItem` (`transfer_to_reverse_engineering_specialist`) and one
`HandoffOutputItem`; `result.last_agent` was `Reverse Engineering Specialist`.
The specialist then supplied the final non-empty output.

Evidence: `artifacts/day1/handoff.log` and
`tests_real/day1/08_sdk_handoff.py`.

## L. Failures and blocked dependencies

No acceptance item is **FAIL**, **BLOCKED**, or **NOT TESTED**.

The restricted command sandbox could not resolve `api.deepseek.com`; the real
provider tests were therefore run through the approved WSL network path. This
was an execution-sandbox DNS constraint, not a CAI or public upstream blocker.

## M. Evidence and test paths

- `tests_real/smoke/01_runtime_import.py`
- `tests_real/smoke/02_deepseek_agent.py`
- `tests_real/smoke/03_deepseek_tool_call.py`
- `tests_real/day1/04_reverse_specialist.py`
- `tests_real/day1/05_red_specialist.py`
- `tests_real/day1/06_dfir_specialist.py`
- `tests_real/day1/07_vuln_specialist.py`
- `tests_real/day1/08_sdk_handoff.py`
- `artifacts/smoke/test01_runtime_import.log`
- `artifacts/smoke/test02_deepseek_agent.log`
- `artifacts/smoke/test03_tool_call.log`
- `artifacts/day1/04_reverse_specialist.log`
- `artifacts/day1/05_red_specialist.log`
- `artifacts/day1/06_dfir_specialist.log`
- `artifacts/day1/07_vuln_specialist.log`
- `artifacts/day1/handoff.log`

## N. Day 1 exit criteria

| Required real validation | Status |
| --- | --- |
| CAI 0.5.10 runtime | **PASS** |
| Real DeepSeek LLM | **PASS** |
| Real function tool calling | **PASS** |
| Reverse specialist smoke | **PASS** |
| Red specialist smoke | **PASS** |
| DFIR specialist smoke | **PASS** |
| Vulnerability specialist smoke | **PASS** |
| Real SDK handoff | **PASS** |

All required Day 1 conditions are met. The project can proceed to Day 2.
