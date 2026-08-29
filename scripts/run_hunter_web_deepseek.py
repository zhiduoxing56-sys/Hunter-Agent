#!/usr/bin/env python3
"""Start Hunter Web with this workspace's verified DeepSeek/Kong prerequisites."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECTS_ROOT = PROJECT_ROOT.parent
AGENT_ROOT = PROJECT_ROOT / "pentestgpt-core" / "pentestgpt_agent"
PYTHON = AGENT_ROOT / ".venv" / "bin" / "python"


def main() -> None:
    config_db = PROJECT_ROOT / ".runtime" / "kong" / "config" / "config.db"
    with sqlite3.connect(config_db) as database:
        row = database.execute(
            "SELECT value FROM config WHERE key = ?", ("custom_api_key",)
        ).fetchone()
    if not row or not isinstance(row[0], str) or not row[0].strip():
        raise SystemExit(
            "DeepSeek API Key is missing from the existing Kong secure configuration."
        )
    deepseek_api_key = row[0].strip()
    environment = os.environ.copy()
    environment.update(
        {
            "JAVA_HOME": str(PROJECTS_ROOT / ".tools" / "jdk21"),
            "GHIDRA_INSTALL_DIR": str(
                PROJECTS_ROOT / ".tools" / "ghidra-12.0.4" / "ghidra_12.0.4_PUBLIC"
            ),
            "KONG_CONFIG_DIR": str(PROJECT_ROOT / ".runtime" / "kong" / "config"),
            "KONG_PROVIDER": "custom",
            "KONG_BASE_URL": "https://api.deepseek.com",
            "KONG_MODEL": "deepseek-v4-flash",
            "DEEPSEEK_API_KEY": deepseek_api_key,
            "HUNTER_TRUDI_MODE": "full",
            "PYTHONPATH": str(AGENT_ROOT / "src"),
        }
    )
    os.chdir(PROJECT_ROOT)
    os.execve(PYTHON, [str(PYTHON), "-m", "web.app"], environment)


if __name__ == "__main__":
    main()
