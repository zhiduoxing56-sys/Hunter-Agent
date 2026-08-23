import asyncio
from _specialist_smoke import run_specialist


if __name__ == "__main__":
    asyncio.run(run_specialist(
        "cai.agents.reverse_engineering_agent", "reverse_engineering_agent",
        "For a local ELF executable that you must not execute or modify, list the first read-only analysis steps. Do not call tools.",
        "TEST04_REVERSE_SPECIALIST_PASS",
    ))
