"""Application settings: YAML file, then ``.env``, with environment variables overriding both."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict
from pydantic_settings.sources import YamlConfigSettingsSource

from controller.models.schemas import TesterPortalEntry
from controller.models.ssh import SSHConfig

_PACKAGE_DIR = Path(__file__).resolve().parent
_DEFAULT_YAML = _PACKAGE_DIR / "config" / "config.yaml"


def _resolve_yaml_path() -> Path:
    override = os.environ.get("CONTROLLER_CONFIG_FILE")
    if override:
        return Path(override).expanduser().resolve()
    return _DEFAULT_YAML


def config_yaml_path() -> Path:
    """Path to the controller YAML file (``CONTROLLER_CONFIG_FILE`` or package default)."""
    return _resolve_yaml_path()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        yaml_file=_DEFAULT_YAML,
        yaml_file_encoding="utf-8",
    )

    project_name: str = Field(default="controller", alias="PROJECT_NAME")
    debug: bool = Field(default=False, alias="DEBUG")

    docker_socket: str = Field(default="unix:///var/run/docker.sock", alias="DOCKER_SOCKET")
    container_frr: str = Field(default="frr", alias="CONTAINER_FRR")
    container_tester: str = Field(default="tester", alias="CONTAINER_TESTER")

    dut_ssh_host: str = Field(default="frr", alias="DUT_SSH_HOST")
    dut_ssh_port: int = Field(default=22, alias="DUT_SSH_PORT")
    dut_ssh_username: str = Field(default="root", alias="DUT_SSH_USERNAME")
    dut_ssh_password: str | None = Field(default=None, alias="DUT_SSH_PASSWORD")
    dut_ssh_known_hosts: str | None = Field(default=None, alias="DUT_SSH_KNOWN_HOSTS")
    dut_command_timeout: float = Field(default=60.0, alias="DUT_COMMAND_TIMEOUT")

    #: Tester web UIs opened from the controller portal; each ``url`` must be reachable from the browser.
    tester_portals: list[TesterPortalEntry] = Field(
        default_factory=lambda: [TesterPortalEntry(name="Tester", url="http://localhost:8000")],
    )

    #: When non-empty, each entry is a DUT (bootstrap sessions created for all). When empty, legacy single-DUT fields apply.
    dut_devices: list[SSHConfig] = Field(default_factory=list)

    test_run_output_dir: str = Field(
        default="/var/lib/controller/test-runs",
        alias="TEST_RUN_OUTPUT_DIR",
    )
    test_config_dir: str = Field(
        default="/opt/test-configs",
        alias="TEST_CONFIG_DIR",
    )

    @property
    def dut_ssh_targets(self) -> list[SSHConfig]:
        if self.dut_devices:
            return list(self.dut_devices)
        return [
            SSHConfig(
                host=self.dut_ssh_host,
                port=self.dut_ssh_port,
                username=self.dut_ssh_username,
                password=self.dut_ssh_password,
            )
        ]

    @property
    def primary_dut_ssh(self) -> SSHConfig:
        """First configured DUT (health checks, single-target helpers)."""
        targets = self.dut_ssh_targets
        if not targets:
            return SSHConfig(
                host=self.dut_ssh_host,
                port=self.dut_ssh_port,
                username=self.dut_ssh_username,
                password=self.dut_ssh_password,
            )
        return targets[0]

    @model_validator(mode="after")
    def _ensure_at_least_one_dut(self) -> Settings:
        if not self.dut_devices:
            return self
        for d in self.dut_devices:
            if not d.host or not str(d.host).strip():
                raise ValueError("Each dut_devices entry must include a non-empty host")
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Priority (later tuple entries are weaker): init > env > .env > yaml > secrets; defaults last.
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSettingsSource(settings_cls, yaml_file=_resolve_yaml_path()),
            file_secret_settings,
        )


settings = Settings()
