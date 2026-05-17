"""Load and resolve configuration files referenced by test scripts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from controller.models.test_script import ConfigurationFile, TestScript, _normalize_config_name


class ConfigCatalog:
    def __init__(self) -> None:
        self._files: dict[str, ConfigurationFile] = {}

    def add(self, name: str, cfg: ConfigurationFile) -> None:
        key = _normalize_config_name(name)
        self._files[key] = cfg

    def get(self, name: str) -> ConfigurationFile:
        key = _normalize_config_name(name)
        if key not in self._files:
            raise KeyError(f"configuration file not found: {key}")
        return self._files[key]

    def names(self) -> list[str]:
        return sorted(self._files.keys())

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return {k: v.model_dump() for k, v in self._files.items()}


def load_catalog_from_script(script: TestScript) -> ConfigCatalog:
    catalog = ConfigCatalog()
    for name, cfg in script.configurations.items():
        catalog.add(name, cfg)
    return catalog


def merge_config_dir(catalog: ConfigCatalog, config_dir: Path) -> None:
    if not config_dir.is_dir():
        return
    paths = sorted(config_dir.glob("*.yaml"), key=lambda p: p.name) + sorted(
        config_dir.glob("*.yml"),
        key=lambda p: p.name,
    )
    for path in paths:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not raw:
            continue
        catalog.add(path.name, ConfigurationFile.model_validate(raw))


def merge_uploaded_files(catalog: ConfigCatalog, uploads: dict[str, bytes]) -> None:
    for name, data in uploads.items():
        raw = yaml.safe_load(data.decode("utf-8"))
        if not raw:
            raise ValueError(f"empty configuration file: {name}")
        catalog.add(name, ConfigurationFile.model_validate(raw))


def load_catalog(
    script: TestScript,
    *,
    settings_config_dir: Path | None,
    uploaded: dict[str, bytes] | None = None,
) -> ConfigCatalog:
    """Inline ``configurations`` override files from disk when names collide."""
    catalog = load_catalog_from_script(script)
    dirs: list[Path] = []
    if script.config_dir:
        dirs.append(Path(script.config_dir).expanduser())
    if settings_config_dir:
        dirs.append(settings_config_dir)
    for d in dirs:
        merge_config_dir(catalog, d)
    if uploaded:
        merge_uploaded_files(catalog, uploaded)
    return catalog


def collect_config_references(script: TestScript) -> set[str]:
    refs: set[str] = set()
    for dev in script.devices.values():
        if dev.default_configure:
            refs.add(_normalize_config_name(dev.default_configure))
    for step_raw in script.steps:
        if "reconnect" in step_raw and len(step_raw) == 1:
            continue
        actions = step_raw.get("actions") or []
        for act in actions:
            if not isinstance(act, dict):
                continue
            if "configure" in act and isinstance(act["configure"], str):
                refs.add(_normalize_config_name(act["configure"]))
            if "send" in act and isinstance(act["send"], str):
                refs.add(_normalize_config_name(act["send"]))
    return refs


def validate_catalog_for_script(catalog: ConfigCatalog, script: TestScript) -> None:
    missing = [n for n in collect_config_references(script) if n not in catalog.names()]
    if missing:
        raise ValueError(f"unknown configuration file(s): {', '.join(missing)}")


def wait_until_pattern_to_regex(pattern: str) -> re.Pattern[str]:
    """Treat pattern as substring search unless it looks like a regex."""
    if pattern.startswith("^") or any(c in pattern for c in ".*+?[]()|"):
        return re.compile(pattern)
    return re.compile(re.escape(pattern))
