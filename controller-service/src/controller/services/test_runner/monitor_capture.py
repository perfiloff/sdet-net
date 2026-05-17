"""Background log capture for monitor sessions (test runner)."""

from __future__ import annotations

import asyncio
import re

from controller.services.ssh.prompt_filter import VtyshMonitorLineFilter


class MonitorLogCapture:
    def __init__(self, stdout, *, use_prompt_filter: bool, max_chars: int = 2_000_000) -> None:
        self._stdout = stdout
        self._filter = VtyshMonitorLineFilter() if use_prompt_filter else None
        self._text = ""
        self._max_chars = max_chars
        self._task: asyncio.Task | None = None
        self._closed = False
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._read_loop(), name="monitor-log-capture")

    async def stop(self) -> None:
        self._closed = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _read_loop(self) -> None:
        try:
            while not self._closed:
                chunk = await self._stdout.read(65536)
                if not chunk:
                    break
                text = chunk if isinstance(chunk, str) else chunk.decode("utf-8", errors="replace")
                async with self._lock:
                    if self._filter:
                        filtered = self._filter.feed(text)
                        if filtered:
                            self._append(filtered)
                    else:
                        self._append(text)
        except asyncio.CancelledError:
            raise
        except Exception:
            self._closed = True

    def _append(self, text: str) -> None:
        self._text += text
        if len(self._text) > self._max_chars:
            self._text = self._text[-self._max_chars :]

    def snapshot(self) -> str:
        return self._text

    async def wait_for_pattern(
        self,
        pattern: re.Pattern[str],
        *,
        timeout: float,
        poll: float = 0.25,
    ) -> str:
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            async with self._lock:
                if self._filter:
                    tail = self._filter.flush()
                    if tail:
                        self._append(tail)
                match = pattern.search(self._text)
                if match:
                    return self._text
            await asyncio.sleep(poll)
        raise TimeoutError(f"pattern not seen within {timeout}s: {pattern.pattern}")
