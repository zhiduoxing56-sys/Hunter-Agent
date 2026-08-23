import asyncio
from _specialist_smoke import run_specialist


if __name__ == "__main__":
    asyncio.run(run_specialist(
        "cai.agents.bug_bounter", "bug_bounter_agent",
        "For this local illustrative code only, name vulnerability categories to review without exploiting it: query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\". Do not call tools.",
        "TEST07_VULN_SPECIALIST_PASS",
    ))
