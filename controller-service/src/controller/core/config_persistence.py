"""Read/write the controller YAML config file (``dut_devices`` and related keys)."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from controller.core.settings import config_yaml_path


def config_file_path() -> Path:
    return config_yaml_path()


def load_yaml_document() -> dict[str, Any]:
    path = config_file_path()
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}


def save_yaml_document(data: dict[str, Any]) -> None:
    path = config_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(
            data,
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )


def get_dut_devices_raw(doc: dict[str, Any]) -> list[dict[str, Any]]:
    raw = doc.get("dut_devices")
    if raw is None:
        return []
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            out.append(dict(item))
    return out


def validate_device(dev: dict[str, Any]) -> None:
    host = dev.get("host")
    if not host or not str(host).strip():
        raise ValueError("host is required")
    try:
        port = int(dev.get("port", 22))
    except (TypeError, ValueError) as exc:
        raise ValueError("port must be an integer between 1 and 65535") from exc
    if not (1 <= port <= 65535):
        raise ValueError("port must be an integer between 1 and 65535")
    user = dev.get("username")
    if not user or not str(user).strip():
        raise ValueError("username is required")


def set_dut_devices(doc: dict[str, Any], devices: list[dict[str, Any]]) -> dict[str, Any]:
    new_doc = deepcopy(doc)
    new_doc["dut_devices"] = devices
    return new_doc


def device_to_yaml_dict(
    host: str,
    port: int,
    username: str,
    *,
    password: str | None = None,
    private_key: str | None = None,
) -> dict[str, Any]:
    d: dict[str, Any] = {
        "host": host.strip(),
        "port": port,
        "username": username.strip(),
    }
    if password is not None and password != "":
        d["password"] = password
    if private_key is not None and private_key != "":
        d["private_key"] = private_key
    return d
