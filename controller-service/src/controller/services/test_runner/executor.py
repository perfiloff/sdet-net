"""Execute test scripts against DUT devices."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from controller.core.settings import Settings
from controller.models.schemas import MonitorConfig
from controller.models.ssh import SSHConfig
from controller.models.test_script import (
    ActionResult,
    ConfigurationFile,
    DeviceSpec,
    StepResult,
    TestRunResult,
    TestScript,
)
from controller.services.ssh.device_monitor import DeviceMonitorSession
from controller.services.ssh.frr import FrrVtyshSession
from controller.services.test_runner.config_catalog import (
    ConfigCatalog,
    load_catalog,
    validate_catalog_for_script,
    wait_until_pattern_to_regex,
)
from controller.services.test_runner.device_handle import DeviceHandle
from controller.services.test_runner.monitor_capture import MonitorLogCapture

logger = logging.getLogger(__name__)


def resolve_device_ssh(settings: Settings, spec: DeviceSpec) -> SSHConfig:
    if spec.host:
        if not spec.username:
            raise ValueError(f"device with host {spec.host!r} requires username")
        return SSHConfig(
            host=spec.host.strip(),
            port=spec.port,
            username=spec.username.strip(),
            password=spec.password,
            private_key=spec.private_key,
        )
    ref = (spec.ref or "").strip()
    for target in settings.dut_ssh_targets:
        if target.host == ref:
            return SSHConfig(
                host=target.host,
                port=spec.port if spec.port != 22 else target.port,
                username=target.username,
                password=spec.password if spec.password is not None else target.password,
                private_key=spec.private_key if spec.private_key is not None else target.private_key,
            )
    raise ValueError(f"device ref {ref!r} not found in dut_devices")


class TestRunExecutor:
    def __init__(
        self,
        settings: Settings,
        script: TestScript,
        catalog: ConfigCatalog,
        *,
        output_dir: Path,
        run_id: str | None = None,
    ) -> None:
        self._settings = settings
        self._script = script
        self._catalog = catalog
        self._run_id = run_id or str(uuid.uuid4())
        self._output_dir = output_dir / self._run_id
        self._handles: dict[str, DeviceHandle] = {}
        self._result = TestRunResult(
            run_id=self._run_id,
            script_name=script.name,
            status="pending",
            output_dir=str(self._output_dir),
        )
        self._cancelled = False

    @property
    def result(self) -> TestRunResult:
        return self._result

    def cancel(self) -> None:
        self._cancelled = True

    async def run(self) -> TestRunResult:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._persist_configs_snapshot()
        self._result.status = "running"
        self._result.started_at = datetime.now(timezone.utc)
        try:
            validate_catalog_for_script(self._catalog, self._script)
            for step_index, step_raw in enumerate(self._script.steps):
                if self._cancelled:
                    self._result.status = "cancelled"
                    break
                await self._run_step(step_index, step_raw)
            if self._result.status == "running":
                self._result.status = "passed"
        except Exception as exc:
            logger.exception("test run %s failed: %s", self._run_id, exc)
            self._result.status = "failed"
            self._result.error = str(exc)
        finally:
            self._result.finished_at = datetime.now(timezone.utc)
            self._result.current_step = None
            self._result.current_action = None
            await self._close_all_devices()
            self._write_results()
        return self._result

    def _persist_configs_snapshot(self) -> None:
        cfg_dir = self._output_dir / "configs"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        for name, data in self._catalog.snapshot().items():
            (cfg_dir / name).write_text(
                json.dumps(data, indent=2),
                encoding="utf-8",
            )

    def _write_results(self) -> None:
        path = self._output_dir / "results.json"
        path.write_text(
            self._result.model_dump(mode="json", indent=2),
            encoding="utf-8",
        )

    async def _run_step(self, step_index: int, step_raw: dict[str, Any]) -> None:
        if "reconnect" in step_raw and "parallel_connect" not in step_raw and "actions" not in step_raw:
            step_result = StepResult(name="reconnect")
            self._result.steps.append(step_result)
            self._result.current_step = step_result.name
            act = await self._run_reconnect(step_raw["reconnect"], step_result)
            step_result.actions.append(act)
            if act.status == "failed" and not self._script.continue_on_error:
                raise RuntimeError(act.error or "reconnect failed")
            return

        name = step_raw.get("name") or f"step_{step_index + 1}"
        step_result = StepResult(name=name)
        self._result.steps.append(step_result)
        self._result.current_step = name

        parallel = step_raw.get("parallel_connect") or []
        if not parallel:
            raise ValueError(f"step {name!r} requires parallel_connect")
        await self._parallel_connect(parallel)

        for act_raw in step_raw.get("actions") or []:
            if self._cancelled:
                break
            if not isinstance(act_raw, dict):
                continue
            act_result = await self._run_action(act_raw, step_result)
            step_result.actions.append(act_result)
            if act_result.status == "failed":
                step_result.status = "failed"
                step_result.error = act_result.error
                if not self._script.continue_on_error:
                    raise RuntimeError(act_result.error or "action failed")

        if step_result.status == "ok" and any(a.status == "failed" for a in step_result.actions):
            step_result.status = "failed"

    async def _parallel_connect(self, aliases: list[str]) -> None:
        await asyncio.gather(*(self._connect_device(a) for a in aliases))

    async def _connect_device(self, alias: str) -> None:
        if alias in self._handles:
            return
        spec = self._script.devices.get(alias)
        if spec is None:
            raise ValueError(f"unknown device alias: {alias}")
        ssh = resolve_device_ssh(self._settings, spec)
        handle = DeviceHandle(
            alias=alias,
            ssh=ssh,
            session_kind=spec.session,
            monitor_config=spec.monitor,
        )
        if spec.session == "control":
            handle.control = FrrVtyshSession(self._settings, ssh)
            await handle.control.login()
        else:
            assert spec.monitor is not None
            handle.monitor = DeviceMonitorSession(self._settings, ssh, spec.monitor)
            await handle.monitor.start()
            if not handle.monitor.try_acquire_runner():
                raise RuntimeError(f"monitor session busy (runner): {alias}")
            handle.capture = MonitorLogCapture(
                handle.monitor.stdout,
                use_prompt_filter=handle.monitor.mode == "terminal_monitor",
            )
            await handle.capture.start()
        self._handles[alias] = handle
        if spec.default_configure and not handle.default_configure_applied:
            await self._apply_configure_file(handle, spec.default_configure, StepResult(name="default"))

    async def _close_all_devices(self) -> None:
        for handle in list(self._handles.values()):
            await self._close_device(handle)
        self._handles.clear()

    async def _close_device(self, handle: DeviceHandle) -> None:
        if handle.capture is not None:
            await handle.capture.stop()
            handle.capture = None
        if handle.monitor is not None:
            handle.monitor.release_runner()
            await handle.monitor.logout()
            handle.monitor = None
        if handle.control is not None:
            await handle.control.logout()
            handle.control = None

    async def _run_action(self, act_raw: dict[str, Any], step_result: StepResult) -> ActionResult:
        if "sleep" in act_raw:
            sec = float(act_raw["sleep"])
            self._result.current_action = f"sleep {sec}s"
            t0 = time.monotonic()
            await asyncio.sleep(sec)
            return ActionResult(
                type="sleep",
                status="ok",
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

        if "wait_until" in act_raw:
            wu = act_raw["wait_until"]
            device = str(wu["device"])
            pattern = str(wu["pattern"])
            timeout = float(wu.get("timeout", 30))
            self._result.current_action = f"wait_until {device!r}"
            return await self._run_wait_until(device, pattern, timeout)

        if "reconnect" in act_raw:
            self._result.current_action = "reconnect"
            return await self._run_reconnect(act_raw["reconnect"], step_result)

        if "configure" in act_raw:
            device = str(act_raw["device"])
            cfg_name = str(act_raw["configure"])
            self._result.current_action = f"configure {cfg_name}"
            handle = await self._ensure_connected(device)
            return await self._apply_configure_file(handle, cfg_name, step_result)

        if "send" in act_raw:
            device = str(act_raw["device"])
            cfg_name = str(act_raw["send"])
            self._result.current_action = f"send {cfg_name}"
            handle = await self._ensure_connected(device)
            return await self._apply_send_file(handle, cfg_name, step_result)

        if "show" in act_raw:
            device = str(act_raw["device"])
            cmd = str(act_raw["show"])
            self._result.current_action = f"show {cmd!r}"
            handle = await self._ensure_connected(device)
            return await self._run_show(handle, cmd)

        raise ValueError(f"unknown action: {act_raw}")

    async def _ensure_connected(self, alias: str) -> DeviceHandle:
        if alias not in self._handles:
            await self._connect_device(alias)
        return self._handles[alias]

    async def _apply_configure_file(
        self,
        handle: DeviceHandle,
        cfg_name: str,
        step_result: StepResult,
    ) -> ActionResult:
        t0 = time.monotonic()
        try:
            cfg = self._catalog.get(cfg_name)
            if cfg.type != "configure":
                raise ValueError(f"{cfg_name} is type {cfg.type}, expected configure")
            if handle.control is None:
                raise RuntimeError(f"device {handle.alias} is not a control session")
            out = await handle.control.configure(cfg.commands)
            handle.default_configure_applied = True
            return ActionResult(
                type="configure",
                device=handle.alias,
                config_file=cfg_name,
                commands=list(cfg.commands),
                output=out,
                status="ok",
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
        except Exception as exc:
            return ActionResult(
                type="configure",
                device=handle.alias,
                config_file=cfg_name,
                status="failed",
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

    async def _apply_send_file(
        self,
        handle: DeviceHandle,
        cfg_name: str,
        step_result: StepResult,
    ) -> ActionResult:
        t0 = time.monotonic()
        try:
            cfg = self._catalog.get(cfg_name)
            if cfg.type != "send":
                raise ValueError(f"{cfg_name} is type {cfg.type}, expected send")
            out = await self._send_commands(handle, cfg)
            return ActionResult(
                type="send",
                device=handle.alias,
                config_file=cfg_name,
                commands=list(cfg.commands),
                output=out,
                status="ok",
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
        except Exception as exc:
            return ActionResult(
                type="send",
                device=handle.alias,
                config_file=cfg_name,
                status="failed",
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

    async def _send_commands(self, handle: DeviceHandle, cfg: ConfigurationFile) -> str:
        if handle.monitor is not None:
            await handle.monitor.send_lines(cfg.commands)
            if handle.capture is not None:
                await asyncio.sleep(0.5)
                return handle.capture.snapshot()[-8000:]
            return ""
        if handle.control is None:
            raise RuntimeError(f"device {handle.alias} has no session")
        parts: list[str] = []
        for line in cfg.commands:
            parts.append(await handle.control.show(line))
        return "".join(parts)

    async def _run_show(self, handle: DeviceHandle, command: str) -> ActionResult:
        t0 = time.monotonic()
        try:
            if handle.control is None:
                raise RuntimeError(f"device {handle.alias} is not a control session")
            out = await handle.control.show(command)
            return ActionResult(
                type="show",
                device=handle.alias,
                commands=[command],
                output=out,
                status="ok",
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
        except Exception as exc:
            return ActionResult(
                type="show",
                device=handle.alias,
                commands=[command],
                status="failed",
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

    async def _run_wait_until(self, alias: str, pattern: str, timeout: float) -> ActionResult:
        t0 = time.monotonic()
        try:
            handle = await self._ensure_connected(alias)
            if handle.capture is None:
                raise RuntimeError(f"device {alias} has no log capture (use monitor session)")
            regex = wait_until_pattern_to_regex(pattern)
            await handle.capture.wait_for_pattern(regex, timeout=timeout)
            return ActionResult(
                type="wait_until",
                device=alias,
                commands=[pattern],
                output=handle.capture.snapshot()[-4000:],
                status="ok",
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
        except Exception as exc:
            return ActionResult(
                type="wait_until",
                device=alias,
                commands=[pattern],
                status="failed",
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

    async def _run_reconnect(self, raw: dict[str, Any], step_result: StepResult) -> ActionResult:
        alias = str(raw["device"])
        timeout = float(raw.get("timeout", 60))
        force = bool(raw.get("force", False))
        t0 = time.monotonic()
        try:
            handle = self._handles.get(alias)
            if handle is None:
                await self._connect_device(alias)
                return ActionResult(
                    type="reconnect",
                    device=alias,
                    status="ok",
                    output="connected (was not connected)",
                    duration_ms=int((time.monotonic() - t0) * 1000),
                )

            alive = False
            if handle.monitor is not None:
                alive = handle.monitor.is_alive()
            elif handle.control is not None:
                alive = handle.control.is_alive()

            if not force and alive:
                return ActionResult(
                    type="reconnect",
                    device=alias,
                    status="ok",
                    output="skipped (session alive)",
                    duration_ms=int((time.monotonic() - t0) * 1000),
                )

            async def _do() -> None:
                await self._close_device(handle)
                self._handles.pop(alias, None)
                await self._connect_device(alias)

            await asyncio.wait_for(_do(), timeout=timeout)
            return ActionResult(
                type="reconnect",
                device=alias,
                status="ok",
                output="reconnected",
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
        except Exception as exc:
            return ActionResult(
                type="reconnect",
                device=alias,
                status="failed",
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
            )


def parse_test_script(data: dict[str, Any]) -> TestScript:
    return TestScript.model_validate(data)


def create_executor_from_yaml(
    settings: Settings,
    script_yaml: str,
    *,
    uploaded_configs: dict[str, bytes] | None = None,
    output_dir: Path | None = None,
) -> TestRunExecutor:
    import yaml

    raw = yaml.safe_load(script_yaml)
    if not isinstance(raw, dict):
        raise ValueError("test script must be a YAML mapping")
    script = parse_test_script(raw)
    base_out = output_dir or Path(settings.test_run_output_dir)
    catalog = load_catalog(
        script,
        settings_config_dir=Path(settings.test_config_dir),
        uploaded=uploaded_configs,
    )
    return TestRunExecutor(settings, script, catalog, output_dir=base_out)
