"""Real DeepSeek SDK handoff smoke, with source-specialist prompt and model."""

import asyncio
import importlib
import os
import re

from cai.sdk.agents import Agent, HandoffCallItem, HandoffOutputItem, Runner

TIMEOUT_SECONDS = 90


def redact(text: object) -> str:
    return re.sub(r"(?i)((?:api[_-]?key|token)\s*[=:]\s*)([^\s,]+)", r"\1[REDACTED]", str(text))


async def main() -> None:
    os.environ["CAI_TRACING"] = "false"
    os.environ["OPENAI_AGENTS_DISABLE_TRACING"] = "true"
    os.environ["CAI_YOLO"] = "false"
    if not os.environ.get("DEEPSEEK_API_KEY"):
        raise RuntimeError("DEEPSEEK_API_KEY is required for the real-provider smoke")
    os.environ["OPENAI_API_KEY"] = os.environ["DEEPSEEK_API_KEY"]
    os.environ["OPENAI_BASE_URL"] = "https://api.deepseek.com/v1"
    if os.environ.get("CAI_MODEL") != "deepseek/deepseek-chat":
        raise RuntimeError("Expected CAI_MODEL=deepseek/deepseek-chat")

    source = importlib.import_module("cai.agents.reverse_engineering_agent").reverse_engineering_agent
    # Preserve the actual upstream specialist's prompt/model; remove active
    # target-facing tools because this test only proves transfer semantics.
    reverse_specialist = source.clone(tools=[])
    router = Agent(
        name="Day1 ELF Router",
        instructions=(
            "You are a router. For every request about an ELF executable, you MUST call "
            "the handoff tool to transfer the task to the Reverse Engineering Specialist. "
            "Do not answer the request yourself."
        ),
        handoffs=[reverse_specialist],
        model=source.model,
    )
    print("INITIAL_AGENT =", router.name)
    print("PROVIDER_BASE_URL = https://api.deepseek.com/v1")
    print("TARGET_AGENT =", reverse_specialist.name)
    print("HANDOFF_TOOL =", router.handoffs[0].tool_name if hasattr(router.handoffs[0], "tool_name") else "generated from Agent")
    result = await asyncio.wait_for(
        Runner.run(
            router,
            "The task is to analyze an ELF executable. Select the appropriate specialist.",
            max_turns=3,
        ),
        timeout=TIMEOUT_SECONDS,
    )
    handoff_calls = [item for item in result.new_items if isinstance(item, HandoffCallItem)]
    handoff_outputs = [item for item in result.new_items if isinstance(item, HandoffOutputItem)]
    print("HANDOFF_CALL_COUNT =", len(handoff_calls))
    for item in handoff_calls:
        print("HANDOFF_CALL_EVENT =", item.type, "agent=", item.agent.name, "tool=", item.raw_item.name)
    print("HANDOFF_OUTPUT_COUNT =", len(handoff_outputs))
    for item in handoff_outputs:
        print("HANDOFF_OUTPUT_EVENT =", item.type, "source=", item.source_agent.name, "target=", item.target_agent.name)
    print("FINAL_AGENT =", result.last_agent.name)
    print("FINAL_OUTPUT =", redact(result.final_output))
    if not handoff_calls or not handoff_outputs:
        raise RuntimeError("No SDK HandoffCallItem/HandoffOutputItem recorded")
    if result.last_agent.name != reverse_specialist.name:
        raise RuntimeError("Final agent is not the Reverse Engineering Specialist")
    if not str(result.final_output).strip():
        raise RuntimeError("Handoff target returned empty output")
    print("TEST08_REAL_SDK_HANDOFF_PASS")


if __name__ == "__main__":
    asyncio.run(main())
