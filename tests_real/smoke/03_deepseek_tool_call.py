import asyncio
import os

from openai import AsyncOpenAI
from cai.sdk.agents import (
    Agent,
    Runner,
    OpenAIChatCompletionsModel,
    function_tool,
)


tool_state = {
    "calls": 0,
    "arguments": [],
}


@function_tool
def add(a: int, b: int) -> int:
    """Add two integers and return the result."""
    tool_state["calls"] += 1
    tool_state["arguments"].append((a, b))

    result = a + b

    print(f"TOOL_EXECUTED: add(a={a}, b={b}) -> {result}")

    return result


async def main():
    # DeepSeek exposes an OpenAI-compatible API. Keep credentials out of output.
    os.environ["OPENAI_API_KEY"] = os.environ["DEEPSEEK_API_KEY"]
    os.environ["OPENAI_BASE_URL"] = "https://api.deepseek.com/v1"
    model_name = os.environ["CAI_MODEL"]

    print("MODEL =", model_name)
    print("PROVIDER_BASE_URL = https://api.deepseek.com/v1")

    agent = Agent(
        name="Hunter Tool Baseline Agent",
        instructions=(
            "You are testing tool execution. "
            "When asked to add numbers, you MUST use the provided add tool. "
            "Do not calculate the result yourself."
        ),
        tools=[add],
        model=OpenAIChatCompletionsModel(
            model=model_name,
            openai_client=AsyncOpenAI(),
        ),
    )

    result = await Runner.run(
        agent,
        "Use the add tool to calculate 17 + 25. "
        "After receiving the tool result, return the final result.",
        max_turns=5,
    )

    print("FINAL_OUTPUT =", result.final_output)
    print("TOOL_CALL_COUNT =", tool_state["calls"])
    print("TOOL_ARGUMENTS =", tool_state["arguments"])

    if tool_state["calls"] < 1:
        raise RuntimeError("TEST FAIL: model never invoked the add tool")

    if (17, 25) not in tool_state["arguments"]:
        raise RuntimeError(
            f"TEST FAIL: expected arguments (17, 25), got {tool_state['arguments']}"
        )

    if "42" not in str(result.final_output):
        raise RuntimeError(
            f"TEST FAIL: expected final answer containing 42, got {result.final_output!r}"
        )

    print("TEST03_REAL_TOOL_CALL_PASS")


if __name__ == "__main__":
    asyncio.run(main())
