"""In-memory registry of active and recent test runs."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from controller.models.test_script import TestRunResult

if TYPE_CHECKING:
    from controller.services.test_runner.executor import TestRunExecutor


@dataclass
class ActiveTestRun:
    executor: TestRunExecutor
    task: asyncio.Task
    result: TestRunResult = field(init=False)

    def __post_init__(self) -> None:
        self.result = self.executor.result


class TestRunRegistry:
    def __init__(self) -> None:
        self._runs: dict[str, ActiveTestRun] = {}

    def get(self, run_id: str) -> ActiveTestRun | None:
        return self._runs.get(run_id)

    def list_ids(self) -> list[str]:
        return sorted(self._runs.keys(), reverse=True)

    def register(self, run: ActiveTestRun) -> None:
        self._runs[run.executor.result.run_id] = run

    def remove(self, run_id: str) -> ActiveTestRun | None:
        return self._runs.pop(run_id, None)
