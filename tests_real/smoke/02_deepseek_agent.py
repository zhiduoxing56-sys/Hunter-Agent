import asyncio
import os

from cai.sdk.agents import Agent, Runner, OpenAIChatCompletionsModel
from openai import AsyncOpenAI


async def main():
    # DeepSeek exposes an OpenAI-compatible API. Do not rely on a developer's
    # optional OPENAI_BASE_URL setting when validating this real provider.
    os.environ["OPENAI_API_KEY"] = os.environ["DEEPSEEK_API_KEY"]
    os.environ["OPENAI_BASE_URL"] = "https://api.deepseek.com/v1"
    print("MODEL =", os.environ.get("CAI_MODEL"))
    print("PROVIDER_BASE_URL = https://api.deepseek.com/v1")

    agent = Agent(
        name="Hunter Baseline Agent",
        instructions=(
            "You are a minimal test agent. "
            "Reply with exactly: HUNTER_LLM_PASS"
        ),
        model=OpenAIChatCompletionsModel(
            model=os.environ["CAI_MODEL"],
            openai_client=AsyncOpenAI(),
        ),
    )

    result = await Runner.run(
        agent,
        "Return the required test response.",
        max_turns=3,
    )

    print("FINAL_OUTPUT =", result.final_output)
    if "HUNTER_LLM_PASS" not in str(result.final_output):
        raise RuntimeError(f"Unexpected real-model output: {result.final_output!r}")
    print("TEST02_REAL_DEEPSEEK_LLM_PASS")


if __name__ == "__main__":
    asyncio.run(main())
