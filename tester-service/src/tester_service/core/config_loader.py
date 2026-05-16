"""YAML configuration loader for BGP settings."""
import os
from pathlib import Path
from typing import Optional, TYPE_CHECKING

import yaml

from tester_service.models.bgp_capabilities import BGPCapabilityCode, BGPCapabilityModel

if TYPE_CHECKING:
    from .settings import BGPSettings

DEFAULT_BGP_CONFIG_PATH = Path("/opt/config/bgp_config.yaml")


def resolve_bgp_config_path(config_path: Optional[str] = None) -> Path:
    """Resolved path for the BGP YAML file (explicit, search, env, or default)."""
    if config_path:
        return Path(config_path).expanduser().resolve()
    found = _find_config_file()
    if found:
        return Path(found)
    env_path = os.getenv("BGP_CONFIG_FILE")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return DEFAULT_BGP_CONFIG_PATH


def validate_bgp_yaml_text(text: str) -> None:
    """Ensure uploaded YAML has a ``bgp`` section before writing to disk."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc
    if not data or "bgp" not in data:
        raise ValueError("YAML configuration must contain a top-level 'bgp' section")


def write_bgp_config_yaml(text: str, config_path: Optional[str] = None) -> Path:
    """Overwrite the BGP config file on disk (atomic replace)."""
    validate_bgp_yaml_text(text)
    path = resolve_bgp_config_path(config_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
    return path


def load_bgp_config_from_yaml(config_path: Optional[str] = None) -> "BGPSettings":
    """
    Load BGP configuration from a YAML file and return a BGPSettings instance.

    Args:
        config_path: Path to the YAML configuration file. If None, searches for
                    default locations: ./config/bgp_config.yaml,
                    ../config/bgp_config.yaml, or uses environment variables.

    Returns:
        BGPSettings instance populated from YAML configuration.

    Raises:
        FileNotFoundError: If the configuration file cannot be found.
        yaml.YAMLError: If the YAML file is malformed.
        ValueError: If required BGP configuration fields are missing.
    """
    # Import here to avoid circular imports
    from .settings import BGPSettings

    path = resolve_bgp_config_path(config_path)
    config_path = str(path)

    if not path.is_file():
        raise FileNotFoundError(
            f"BGP configuration file not found: {config_path}. "
            "Provide config_path or place bgp_config.yaml in ./config/ or ../config/"
        )

    with open(path, "r", encoding="utf-8") as f:
        config_data = yaml.safe_load(f)

    if not config_data or "bgp" not in config_data:
        raise ValueError("YAML configuration must contain a 'bgp' section")

    bgp_data = config_data["bgp"]

    # Parse capabilities from YAML format
    capabilities = []
    if "capabilities" in bgp_data:
        for cap in bgp_data["capabilities"]:
            code = int(cap.get("code"))
            value = cap.get("value", {})
            capabilities.append(
                BGPCapabilityModel(
                    code=BGPCapabilityCode(code),
                    value=value if value else None,
                )
            )

    # Build BGPSettings dict from YAML
    settings_dict = {
        "as_number": bgp_data.get("as_number", 65001),
        "router_id": bgp_data.get("router_id", "2.2.2.2"),
        "hold_time": bgp_data.get("hold_time", 180),
        "bgp_version": bgp_data.get("bgp_version", 4),
        "remote_host": bgp_data.get("remote_host", "frr"),
        "remote_port": bgp_data.get("remote_port", 179),
    }

    if capabilities:
        settings_dict["capabilities"] = capabilities

    return BGPSettings(**settings_dict)


def _find_config_file() -> Optional[str]:
    """
    Search for bgp_config.yaml in default locations.

    Searches in this order:
    1. Current working directory: ./config/bgp_config.yaml
    2. Parent directory: ../config/bgp_config.yaml
    3. BGP_CONFIG_FILE environment variable
    """
    # Try relative paths from current working directory
    candidate_paths = [
        "./config/bgp_config.yaml",
        "../config/bgp_config.yaml",
        "../../config/bgp_config.yaml",
        Path(__file__).parent.parent.parent / "config" / "bgp_config.yaml",
        "/opt/config/bgp_config.yaml",
    ]

    for path in candidate_paths:
        if isinstance(path, Path):
            path = str(path)
        if os.path.exists(path):
            return os.path.abspath(path)

    # Check environment variable
    env_path = os.getenv("BGP_CONFIG_FILE")
    if env_path and os.path.exists(env_path):
        return env_path

    return None
