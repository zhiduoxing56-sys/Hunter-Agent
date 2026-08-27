"""Adapter-side request journal for the frozen OpenAI-compatible backend."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from pentestgpt_agent.openai_compatible import OpenAICompatibleBackend


class RecordingOpenAICompatibleBackend(OpenAICompatibleBackend):
    """Append every provider request/response without recording the API key."""

    def __init__(self, *args: Any, journal_path: Path, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.journal_path = journal_path

    def _record(self, record: dict[str, object]) -> None:
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with self.journal_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")

    async def _post(self, payload: dict[str, Any], *, structured_output: bool) -> dict[str, Any]:
        opened = time.time()
        self._record({"at": opened, "type": "model_request", "payload": payload})
        try:
            response = await super()._post(payload, structured_output=structured_output)
        except Exception as exc:
            self._record(
                {
                    "at": time.time(),
                    "type": "model_error",
                    "error": f"{type(exc).__name__}: {exc}",
                    "duration_s": time.time() - opened,
                }
            )
            raise
        self._record(
            {
                "at": time.time(),
                "type": "model_response",
                "response": response,
                "duration_s": time.time() - opened,
            }
        )
        return response
