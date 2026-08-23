import asyncio
from _specialist_smoke import run_specialist


if __name__ == "__main__":
    asyncio.run(run_specialist(
        "cai.agents.dfir", "dfir_agent",
        "Given this simulated local log only: '2026-08-24T10:00:00Z failed login user=alice source=192.0.2.10', state the first evidence-preserving investigation action. Do not call tools.",
        "TEST06_DFIR_SPECIALIST_PASS",
    ))
