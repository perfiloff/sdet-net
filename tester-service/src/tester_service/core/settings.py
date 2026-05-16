from pydantic import Field, ConfigDict, model_validator
from pydantic_settings import BaseSettings

from tester_service.models.bgp_capabilities import BGPCapabilityCode, BGPCapabilityModel


class Settings(BaseSettings):
    project_name: str = Field("movies", alias="PROJECT_NAME")
    debug: bool = Field(False, alias="DEBUG")
    cors_origins: str = Field(
        default="http://localhost:8001,http://127.0.0.1:8001",
        alias="CORS_ORIGINS",
        description="Comma-separated origins allowed to call the tester API from a browser (controller UI)",
    )


class BGPSettings(BaseSettings):
    model_config = ConfigDict(populate_by_name=True)

    as_number: int = Field(65001, alias="AS_NUMBER")
    router_id: str = Field("2.2.2.2", alias="ROUTER_ID")
    hold_time: int = Field(180, alias="HOLD_TIME")
    bgp_version: int = Field(4, alias="BGP_VERSION")
    remote_host: str = Field("frr", alias="REMOTE_HOST")
    remote_port: int = Field(179, alias="REMOTE_PORT")
    capabilities: list[BGPCapabilityModel] = Field(
        default_factory=lambda: [
            BGPCapabilityModel(
                code=BGPCapabilityCode.MP_BGP,
                value={"afi": 1, "reserved": 0, "safi": 1},
            ),
            BGPCapabilityModel(code=BGPCapabilityCode.ROUTE_REFRESH, value={}),
            BGPCapabilityModel(
                code=BGPCapabilityCode.ORF,
                value={"orf": [{"afi": 1, "reserved": 0, "safi": 1, "entries": []}]},
            ),
            BGPCapabilityModel(
                code=BGPCapabilityCode.GRACEFUL_RESTART,
                value={"restart_flags": 0, "restart_time": 120},
            ),
            BGPCapabilityModel(
                code=BGPCapabilityCode.FOUR_OCTET_AS,
                value={"asn": 65001},
            ),
        ],
        alias="CAPABILITIES",
    )

    @model_validator(mode="after")
    def ensure_four_octet_asn(self):
        """Keep Four-Octet-AS capability in sync with configured local AS."""
        for idx, capability in enumerate(self.capabilities):
            if capability.code != BGPCapabilityCode.FOUR_OCTET_AS:
                continue

            value = capability.value or {}
            if value.get("asn") == self.as_number:
                break

            self.capabilities[idx] = BGPCapabilityModel(
                code=capability.code,
                value={**value, "asn": self.as_number},
            )
            break
        else:
            self.capabilities.append(
                BGPCapabilityModel(
                    code=BGPCapabilityCode.FOUR_OCTET_AS,
                    value={"asn": self.as_number},
                )
            )

        return self

    def __str__(self):
        return (
            f"BGPSettings(as_number={self.as_number}, router_id={self.router_id}, hold_time={self.hold_time}, "
            f"bgp_version={self.bgp_version}, remote_host={self.remote_host}, remote_port={self.remote_port}, "
            f"capabilities={len(self.capabilities)})"
        )


def load_bgp_settings_with_fallback(config_path: str | None = None) -> BGPSettings:
    """
    Load BGP settings from YAML file with fallback to environment variables.

    First attempts to load from YAML configuration file. If YAML file is not found
    or loading fails, falls back to creating BGPSettings from environment variables
    and defaults.

    Args:
        config_path: Optional path to YAML configuration file. If not provided,
                    searches in default locations and BGP_CONFIG_FILE env var.

    Returns:
        BGPSettings instance, either from YAML or from environment/defaults.
    """
    try:
        from .config_loader import load_bgp_config_from_yaml
        return load_bgp_config_from_yaml(config_path)
    except (FileNotFoundError, Exception) as e:
        print(f"YAML config not found or failed to load: {e}. Falling back to env vars and defaults.")
        return BGPSettings()


settings = Settings()
bgp_settings = load_bgp_settings_with_fallback()
