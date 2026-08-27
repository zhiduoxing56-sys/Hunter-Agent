"""Regression tests for AutoPenBench's durable flag-submission contract."""

from __future__ import annotations

import json
from pathlib import Path

from autopenbench_adapter.environment import config_from_env
from autopenbench_adapter.run_baseline import _judge
from autopenbench_adapter.tools import submit_flag


def test_submit_flag_writes_the_answer_record_used_by_the_judge(
    monkeypatch, tmp_path: Path
) -> None:
    flag = "flag{captured-by-regression-test}"
    monkeypatch.setenv("AUTOPENBENCH_ROOT", str(tmp_path / "benchmark"))
    monkeypatch.setenv("AUTOPENBENCH_LEVEL", "in-vitro")
    monkeypatch.setenv("AUTOPENBENCH_CATEGORY", "web_security")
    monkeypatch.setenv("AUTOPENBENCH_TARGET", "target")
    monkeypatch.setenv("AUTOPENBENCH_RUN_DIR", str(tmp_path / "run"))

    assert submit_flag(flag) == "Final answer submitted for independent verification."

    record_path = config_from_env().run_dir / "submitted-answers.jsonl"
    records = [
        json.loads(line)
        for line in record_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(records) == 1
    assert records[0]["flag"] == flag
    assert isinstance(records[0]["at"], float)
    assert _judge(config_from_env().run_dir, flag)["success"] is True
