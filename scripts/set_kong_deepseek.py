#!/usr/bin/env python3
"""Configure Kong's custom provider for DeepSeek without echoing the API key."""

from __future__ import annotations

import getpass
import os
import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = PROJECT_ROOT / ".runtime" / "kong" / "config"
CONFIG_DB = CONFIG_DIR / "config.db"


def main() -> None:
    if not CONFIG_DB.is_file():
        raise SystemExit(f"Kong config database does not exist: {CONFIG_DB}")

    api_key = getpass.getpass("请输入 DeepSeek API Key（输入不会显示）: ").strip()
    if not api_key:
        raise SystemExit("API Key 不能为空；配置未修改。")

    values = {
        "enabled_providers": '["custom"]',
        "default_provider": "custom",
        "setup_complete": "true",
        "custom_base_url": "https://api.deepseek.com",
        "custom_model": "deepseek-v4-flash",
        "custom_api_key": api_key,
    }
    with sqlite3.connect(CONFIG_DB) as database:
        for key, value in values.items():
            cursor = database.execute(
                "UPDATE config SET value = ? WHERE key = ?",
                (value, key),
            )
            if cursor.rowcount != 1:
                raise RuntimeError(f"Kong config row is missing: {key}")

    os.chmod(CONFIG_DIR, 0o700)
    os.chmod(CONFIG_DB, 0o600)

    with sqlite3.connect(f"file:{CONFIG_DB}?mode=ro", uri=True) as database:
        stored = database.execute(
            "SELECT length(value) FROM config WHERE key = ?",
            ("custom_api_key",),
        ).fetchone()
    if stored is None or not stored[0]:
        raise RuntimeError("Kong API Key verification failed")

    print("DeepSeek V4 Flash 已配置；API Key 已写入本地 Kong 配置。")
    print(f"配置文件权限：{oct(CONFIG_DB.stat().st_mode & 0o777)}")


if __name__ == "__main__":
    main()
