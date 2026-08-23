import asyncio
from _specialist_smoke import run_specialist


if __name__ == "__main__":
    asyncio.run(run_specialist(
        "cai.agents.red_teamer", "redteam_agent",
        "For the fictional local lab host example.invalid, give a high-level, non-executing reconnaissance plan. Do not call tools or scan anything.",
        "TEST05_RED_SPECIALIST_PASS",
    ))
