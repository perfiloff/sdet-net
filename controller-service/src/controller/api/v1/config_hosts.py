"""CRUD for ``dut_devices`` in the controller YAML config (passwords are write-only)."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status

from controller.core.config_persistence import (
    config_file_path,
    device_to_yaml_dict,
    get_dut_devices_raw,
    load_yaml_document,
    save_yaml_document,
    set_dut_devices,
    validate_device,
)
from controller.core.settings import Settings
from controller.core.state import AppContainer
from controller.models.schemas import (
    DutHostCreate,
    DutHostListResponse,
    DutHostRead,
    DutHostUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/config", tags=["config"])


def get_container(request: Request) -> AppContainer:
    return request.app.state.container


ContainerDep = Annotated[AppContainer, Depends(get_container)]


def _to_read(dev: dict, index: int) -> DutHostRead:
    return DutHostRead(
        index=index,
        host=str(dev["host"]),
        port=int(dev.get("port", 22)),
        username=str(dev["username"]),
        has_password=bool(dev.get("password")),
        has_private_key=bool(dev.get("private_key")),
    )


def _reload_settings(container: AppContainer) -> None:
    container.apply_settings(Settings())


def _apply_update(existing: dict, body: DutHostUpdate) -> dict:
    m = dict(existing)
    if body.host is not None:
        m["host"] = body.host.strip()
    if body.port is not None:
        m["port"] = body.port
    if body.username is not None:
        m["username"] = body.username.strip()
    if body.clear_password:
        m.pop("password", None)
    elif "password" in body.model_fields_set:
        if body.password:
            m["password"] = body.password
        else:
            m.pop("password", None)
    if body.clear_private_key:
        m.pop("private_key", None)
    elif "private_key" in body.model_fields_set:
        if body.private_key:
            m["private_key"] = body.private_key
        else:
            m.pop("private_key", None)
    return m


@router.get("/dut-hosts", response_model=DutHostListResponse)
async def list_dut_hosts() -> DutHostListResponse:
    """List devices under ``dut_devices`` in the YAML file. Passwords and keys are never returned."""
    doc = load_yaml_document()
    devices = get_dut_devices_raw(doc)
    return DutHostListResponse(
        hosts=[_to_read(d, i) for i, d in enumerate(devices)],
        config_path=str(config_file_path()),
    )


@router.get("/dut-hosts/{index}", response_model=DutHostRead)
async def get_dut_host(index: Annotated[int, Path(ge=0)]) -> DutHostRead:
    doc = load_yaml_document()
    devices = get_dut_devices_raw(doc)
    if index >= len(devices):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "host not found")
    return _to_read(devices[index], index)


@router.post("/dut-hosts", response_model=DutHostRead, status_code=status.HTTP_201_CREATED)
async def create_dut_host(
    body: DutHostCreate,
    container: ContainerDep,
) -> DutHostRead:
    """Append a DUT to ``dut_devices`` and save the config file."""
    doc = load_yaml_document()
    devices = get_dut_devices_raw(doc)
    new_dev = device_to_yaml_dict(
        body.host,
        body.port,
        body.username,
        password=body.password,
        private_key=body.private_key,
    )
    try:
        validate_device(new_dev)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    devices.append(new_dev)
    try:
        save_yaml_document(set_dut_devices(doc, devices))
    except OSError as exc:
        logger.exception("failed to save config")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    _reload_settings(container)
    return _to_read(new_dev, len(devices) - 1)


@router.put("/dut-hosts/{index}", response_model=DutHostRead)
async def update_dut_host(
    index: Annotated[int, Path(ge=0)],
    body: DutHostUpdate,
    container: ContainerDep,
) -> DutHostRead:
    """Update one ``dut_devices`` entry. Password / private_key stay unchanged unless set or cleared."""
    doc = load_yaml_document()
    devices = get_dut_devices_raw(doc)
    if index >= len(devices):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "host not found")
    merged = _apply_update(devices[index], body)
    try:
        validate_device(merged)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    devices[index] = merged
    try:
        save_yaml_document(set_dut_devices(doc, devices))
    except OSError as exc:
        logger.exception("failed to save config")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    _reload_settings(container)
    return _to_read(merged, index)


@router.delete("/dut-hosts/{index}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_dut_host(
    index: Annotated[int, Path(ge=0)],
    container: ContainerDep,
) -> Response:
    doc = load_yaml_document()
    devices = get_dut_devices_raw(doc)
    if index >= len(devices):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "host not found")
    devices.pop(index)
    try:
        save_yaml_document(set_dut_devices(doc, devices))
    except OSError as exc:
        logger.exception("failed to save config")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    _reload_settings(container)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
