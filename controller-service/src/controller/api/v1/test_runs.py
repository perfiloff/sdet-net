"""Test script run API: upload script + configs, poll status, download results."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.requests import HTTPConnection

from controller.core.state import AppContainer
from controller.models.test_script import TestRunListItem, TestRunListResponse, TestRunResult
from controller.services.test_runner.executor import TestRunExecutor, create_executor_from_yaml
from controller.services.test_runner.run_registry import ActiveTestRun

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/test-runs", tags=["test-runs"])


def get_container(conn: HTTPConnection) -> AppContainer:
    return conn.app.state.container


ContainerDep = Annotated[AppContainer, Depends(get_container)]


async def _run_job(executor: TestRunExecutor) -> None:
    try:
        await executor.run()
    except Exception:
        logger.exception("test run %s crashed", executor.result.run_id)


@router.get("", response_model=TestRunListResponse)
async def list_test_runs(container: ContainerDep) -> TestRunListResponse:
    items: list[TestRunListItem] = []
    for run_id in container.test_run_registry.list_ids():
        active = container.test_run_registry.get(run_id)
        if active is None:
            continue
        r = active.executor.result
        items.append(
            TestRunListItem(
                run_id=r.run_id,
                script_name=r.script_name,
                status=r.status,
                started_at=r.started_at,
                finished_at=r.finished_at,
                current_step=r.current_step,
                current_action=r.current_action,
            )
        )
    return TestRunListResponse(runs=items)


@router.post("", response_model=TestRunResult, status_code=status.HTTP_202_ACCEPTED)
async def start_test_run(
    container: ContainerDep,
    script: UploadFile = File(..., description="Test script YAML"),
    configs: list[UploadFile] = File(default=[], description="Optional configuration YAML files"),
) -> TestRunResult:
    script_bytes = await script.read()
    if not script_bytes.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "script file is empty")
    uploaded: dict[str, bytes] = {}
    for cfg in configs:
        name = cfg.filename or "config.yaml"
        data = await cfg.read()
        if not data.strip():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"configuration file is empty: {name}")
        uploaded[name] = data

    try:
        executor = create_executor_from_yaml(
            container.settings,
            script_bytes.decode("utf-8"),
            uploaded_configs=uploaded or None,
        )
    except Exception as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    task = asyncio.create_task(_run_job(executor))
    container.test_run_registry.register(ActiveTestRun(executor=executor, task=task))
    return executor.result


@router.get("/{run_id}", response_model=TestRunResult)
async def get_test_run(run_id: str, container: ContainerDep) -> TestRunResult:
    active = container.test_run_registry.get(run_id)
    if active is not None:
        return active.executor.result
    path = Path(container.settings.test_run_output_dir) / run_id / "results.json"
    if path.is_file():
        return TestRunResult.model_validate(json.loads(path.read_text(encoding="utf-8")))
    raise HTTPException(status.HTTP_404_NOT_FOUND, "test run not found")


@router.get("/{run_id}/results")
async def get_test_run_results(run_id: str, container: ContainerDep) -> JSONResponse:
    active = container.test_run_registry.get(run_id)
    if active is not None:
        return JSONResponse(active.executor.result.model_dump(mode="json"))
    path = Path(container.settings.test_run_output_dir) / run_id / "results.json"
    if path.is_file():
        return JSONResponse(json.loads(path.read_text(encoding="utf-8")))
    raise HTTPException(status.HTTP_404_NOT_FOUND, "test run not found")


@router.get("/{run_id}/download")
async def download_test_run_results(run_id: str, container: ContainerDep) -> FileResponse:
    path = Path(container.settings.test_run_output_dir) / run_id / "results.json"
    if not path.is_file():
        active = container.test_run_registry.get(run_id)
        if active is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(active.executor.result.model_dump_json(indent=2), encoding="utf-8")
    if not path.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "results not found")
    return FileResponse(path, media_type="application/json", filename="results.json")


@router.delete("/{run_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def cancel_test_run(run_id: str, container: ContainerDep) -> Response:
    active = container.test_run_registry.get(run_id)
    if active is None:
        path = Path(container.settings.test_run_output_dir) / run_id
        if path.is_dir():
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        raise HTTPException(status.HTTP_404_NOT_FOUND, "test run not found")
    active.executor.cancel()
    if not active.task.done():
        active.task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await active.task
    container.test_run_registry.remove(run_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
