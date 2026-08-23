"""Shared real-provider smoke runner for CAI 0.5.10 specialist agents."""

import asyncio
import importlib
import os
import re
from typing import Any

from cai.sdk.agents import Agent, Runner

TIMEOUT_SECONDS = 90
MAX_TURNS = 3


def configure_safe_environment() -> None:
    """Set only the documented test-safety flags; never print credential values."""
    os.environ["CAI_TRACING"] = "false"
    os.environ["OPENAI_AGENTS_DISABLE_TRACING"] = "true"
    os.environ["CAI_YOLO"] = "false"
    if not os.environ.get("DEEPSEEK_API_KEY"):
        raise RuntimeError("DEEPSEEK_API_KEY is required for the real-provider smoke")
    os.environ["OPENAI_API_KEY"] = os.environ["DEEPSEEK_API_KEY"]
    os.environ["OPENAI_BASE_URL"] = "https://api.deepseek.com/v1"


def redact(value: Any) -> str:
    text = str(value)
    return re.sub(
        r"(?i)((?:api[_-]?key|token|authorization)\s*[=:]\s*)([^\s,]+)",
        r"\1[REDACTED]",
        text,
    )


def tool_name(tool: Any) -> str:
    return str(getattr(tool, "name", getattr(tool, "__name__", type(tool).__name__)))


async def run_specialist(
    module_name: str,
    agent_attribute: str,
    task: str,
    pass_marker: str,
) -> None:
    configure_safe_environment()
    print("CAI_TRACING =", os.environ["CAI_TRACING"])
    print("OPENAI_AGENTS_DISABLE_TRACING =", os.environ["OPENAI_AGENTS_DISABLE_TRACING"])
    print("CAI_YOLO =", os.environ["CAI_YOLO"])
    print("MODEL =", os.environ.get("CAI_MODEL", "<missing>"))
    print("PROVIDER_BASE_URL = https://api.deepseek.com/v1")
    if os.environ.get("CAI_MODEL") != "deepseek/deepseek-chat":
        raise RuntimeError("Expected CAI_MODEL=deepseek/deepseek-chat")

    module = importlib.import_module(module_name)
    source_agent = getattr(module, agent_attribute)
    if not isinstance(source_agent, Agent):
        raise TypeError(f"{module_name}.{agent_attribute} is not an Agent")

    # This reconstruction proves the source agent's public configuration can be
    # used to construct an SDK Agent. It retains the actual prompt/model/tools.
    constructed_agent = Agent(
        name=source_agent.name,
        instructions=source_agent.instructions,
        description=source_agent.description,
        handoff_description=source_agent.handoff_description,
        tools=list(source_agent.tools),
        model=source_agent.model,
    )
    instructions = await constructed_agent.get_system_prompt(None)  # type: ignore[arg-type]
    tools = [tool_name(tool) for tool in constructed_agent.tools]
    print("SOURCE_AGENT =", f"{module_name}.{agent_attribute}")
    print("AGENT_NAME =", constructed_agent.name)
    print("INSTRUCTIONS_LOADED =", bool(instructions and instructions.strip()))
    print("INSTRUCTIONS_LENGTH =", len(instructions or ""))
    print("TOOLS_ENUMERATED =", tools)
    print("TOOL_COUNT =", len(tools))

    # Do not expose any upstream command/search/SSH tools to an LLM during this
    # safety smoke. The clone preserves the upstream specialist prompt and real
    # DeepSeek model; only capabilities that could touch a target are removed.
    execution_agent = constructed_agent.clone(
        tools=[], input_guardrails=[], output_guardrails=[]
    )
    print("EXECUTION_AGENT =", execution_agent.name)
    print("EXECUTION_TOOLS = [] (safety isolation; source tools enumerated above)")
    result = await asyncio.wait_for(
        Runner.run(execution_agent, task, max_turns=MAX_TURNS), timeout=TIMEOUT_SECONDS
    )
    print("LAST_AGENT =", result.last_agent.name)
    print("FINAL_OUTPUT =", redact(result.final_output))
    if result.last_agent.name != constructed_agent.name:
        raise RuntimeError("Unexpected specialist change during single-agent smoke")
    if not str(result.final_output).strip():
        raise RuntimeError("Real provider returned empty final output")
    print(pass_marker)
