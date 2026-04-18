"""Stream container stdout/stderr via Docker Engine API."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Literal

import docker
from docker.errors import DockerException, NotFound

from controller.core.settings import Settings

logger = logging.getLogger(__name__)

LogSource = Literal["frr", "tester", "all"]

_SENTINEL = object()


def _docker_client(settings: Settings) -> docker.DockerClient:
    base = settings.docker_socket
    if base.startswith("unix://"):
        return docker.DockerClient(base_url=base)
    return docker.DockerClient(base_url=base)


async def stream_container_logs(
    settings: Settings,
    container_name: str,
    tail: int | None = 0,
    *,
    follow: bool = True,
) -> AsyncIterator[bytes]:
    """Async byte stream of container logs (stdout + stderr, labeled)."""

    def open_streams():
        client = _docker_client(settings)
        container = client.containers.get(container_name)
        # docker-py APIClient.logs has no demux=; use separate stdout/stderr streams.
        stdout_it = container.logs(
            stream=True,
            follow=follow,
            tail=tail,
            timestamps=False,
            stdout=True,
            stderr=False,
        )
        stderr_it = container.logs(
            stream=True,
            follow=follow,
            tail=tail,
            timestamps=False,
            stdout=False,
            stderr=True,
        )
        return client, stdout_it, stderr_it

    loop = asyncio.get_running_loop()
    try:
        client, stdout_it, stderr_it = await loop.run_in_executor(None, open_streams)
    except NotFound:
        yield f"[{container_name}] container not found\n".encode()
        return
    except DockerException as exc:
        yield f"[{container_name}] docker error: {exc}\n".encode()
        return

    prefix = f"[{container_name}] ".encode()
    queue: asyncio.Queue[bytes | object] = asyncio.Queue(maxsize=512)

    def pump(it, label: bytes) -> None:
        try:
            for chunk in it:
                if chunk:
                    data = label + chunk
                    try:
                        loop.call_soon_threadsafe(queue.put_nowait, data)
                    except asyncio.QueueFull:
                        logger.warning("Log queue full; dropping chunk for %s", container_name)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Log pump failed for %s: %s", container_name, exc)
            err = label + f"[stream_error: {exc}]\n".encode()
            loop.call_soon_threadsafe(queue.put_nowait, err)
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, _SENTINEL)

    loop.run_in_executor(None, pump, stdout_it, prefix)
    loop.run_in_executor(None, pump, stderr_it, prefix + b"[err] ")

    try:
        finished = 0
        while finished < 2:
            item = await queue.get()
            if item is _SENTINEL:
                finished += 1
                continue
            if isinstance(item, bytes):
                yield item
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


async def snapshot_logs(
    settings: Settings,
    container_name: str,
    tail: int = 500,
) -> str:
    """Last N bytes of combined stdout+stderr as text."""

    def read_sync() -> str:
        client = _docker_client(settings)
        try:
            container = client.containers.get(container_name)
            stdout = container.logs(
                tail=tail,
                timestamps=False,
                stdout=True,
                stderr=False,
            )
            stderr = container.logs(
                tail=tail,
                timestamps=False,
                stdout=False,
                stderr=True,
            )
            parts = []
            if stdout:
                parts.append(stdout.decode("utf-8", errors="replace"))
            if stderr:
                parts.append(stderr.decode("utf-8", errors="replace"))
            return "".join(parts)
        except NotFound:
            return f"[{container_name}] container not found\n"
        except DockerException as exc:
            return f"[{container_name}] docker error: {exc}\n"
        finally:
            client.close()

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, read_sync)


def resolve_container_names(settings: Settings, source: LogSource) -> list[str]:
    if source == "frr":
        return [settings.container_frr]
    if source == "tester":
        return [settings.container_tester]
    return [settings.container_frr, settings.container_tester]


async def stream_merged_logs(
    settings: Settings,
    source: LogSource,
    tail: int | None = 0,
) -> AsyncIterator[bytes]:
    """Follow logs; when source=all, merge streams from all containers in parallel."""
    names = resolve_container_names(settings, source)
    if len(names) == 1:
        async for chunk in stream_container_logs(settings, names[0], tail=tail, follow=True):
            yield chunk
        return

    queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=512)

    async def pump(name: str) -> None:
        try:
            async for chunk in stream_container_logs(settings, name, tail=tail, follow=True):
                await queue.put(chunk)
        finally:
            await queue.put(None)

    tasks = [asyncio.create_task(pump(n)) for n in names]
    finished = 0
    try:
        while finished < len(names):
            item = await queue.get()
            if item is None:
                finished += 1
                continue
            yield item
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def lines_from_bytes(chunks: AsyncIterator[bytes]) -> AsyncIterator[str]:
    """Buffer chunks into newline-terminated strings."""
    buf = ""
    async for chunk in chunks:
        buf += chunk.decode("utf-8", errors="replace")
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            yield line + "\n"
    if buf:
        yield buf
