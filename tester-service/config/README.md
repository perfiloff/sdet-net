# BGP Settings Configuration

This directory contains the YAML configuration file for BGP settings.

## Overview

BGP settings can be configured in two ways:

1. **YAML Configuration File** (Recommended for development and testing)
2. **Environment Variables** (Recommended for production/containers)

## YAML Configuration

### Configuration File Location

The loader searches for `bgp_config.yaml` in these locations (in order):
1. `./config/bgp_config.yaml` (relative to working directory)
2. `../config/bgp_config.yaml` 
3. `../../config/bgp_config.yaml`
4. `BGP_CONFIG_FILE` environment variable (if set)

### Configuration File Format

The YAML file should have the following structure:

```yaml
bgp:
  as_number: 65001
  router_id: "2.2.2.2"
  hold_time: 180
  bgp_version: 4
  remote_host: "frr"
  remote_port: 179
  capabilities:
    - code: 1  # MP_BGP
      value:
        afi: 1
        reserved: 0
        safi: 1
    - code: 2  # ROUTE_REFRESH
      value: {}
    - code: 3  # ORF
      value:
        orf:
          - afi: 1
            reserved: 0
            safi: 1
            entries: []
    - code: 64  # GRACEFUL_RESTART
      value:
        restart_flags: 0
        restart_time: 120
    - code: 65  # FOUR_OCTET_AS
      value:
        asn: 65001
```

### Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `as_number` | int | 65001 | Local BGP AS number |
| `router_id` | string | "2.2.2.2" | BGP router ID (IP address format) |
| `hold_time` | int | 180 | BGP hold time in seconds |
| `bgp_version` | int | 4 | BGP protocol version (usually 4) |
| `remote_host` | string | "frr" | Remote BGP peer hostname/IP |
| `remote_port` | int | 179 | Remote BGP peer port |
| `capabilities` | list | See defaults | BGP capabilities to advertise in OPEN message |

### Capability Codes

| Code | Name | Description |
|------|------|-------------|
| 1 | MP_BGP | Multiprotocol Extensions (RFC 4760) |
| 2 | ROUTE_REFRESH | Route Refresh Capability (RFC 2918) |
| 3 | ORF | Outbound Route Filtering (RFC 5291) |
| 64 | GRACEFUL_RESTART | Graceful Restart (RFC 4724) |
| 65 | FOUR_OCTET_AS | Four-octet AS number (RFC 6793) |

## Loading Configuration

### From Python Code

#### Using YAML

```python
from tester_service.core.config_loader import load_bgp_config_from_yaml

# Load from default location
config = load_bgp_config_from_yaml()

# Or specify a path
config = load_bgp_config_from_yaml('/path/to/config.yaml')
```

#### With Fallback

```python
from tester_service.core.settings import load_bgp_settings_with_fallback

# Tries YAML first, falls back to environment variables
config = load_bgp_settings_with_fallback()
```

### Environment Variables

If YAML file is not found, the loader falls back to environment variables:

| Variable | Type | Default |
|----------|------|---------|
| `AS_NUMBER` | int | 65001 |
| `ROUTER_ID` | string | "2.2.2.2" |
| `HOLD_TIME` | int | 180 |
| `BGP_VERSION` | int | 4 |
| `REMOTE_HOST` | string | "frr" |
| `REMOTE_PORT` | int | 179 |
| `CAPABILITIES` | string | (JSON array) |

### Docker Compose

Mount the YAML file or set environment variables:

```yaml
services:
  tester:
    environment:
      BGP_CONFIG_FILE: /app/config/bgp_config.yaml
    volumes:
      - ./config/bgp_config.yaml:/app/config/bgp_config.yaml
```

## Example Usage

### In main.py or startup

```python
from tester_service.core.settings import load_bgp_settings_with_fallback, bgp_settings

# The default bgp_settings is already loaded with YAML fallback
# But you can reload if needed:
bgp_settings = load_bgp_settings_with_fallback()

print(f"BGP ASN: {bgp_settings.as_number}")
print(f"Router ID: {bgp_settings.router_id}")
```

### In BGPManager initialization

```python
from tester_service.core.settings import bgp_settings
from tester_service.models.bgp_settings import BGPConfig

config = BGPConfig()  # Will use defaults from bgp_settings
# Use config...
```

## Modifying Configuration

### For Testing

Create a test-specific YAML file:

```bash
cp config/bgp_config.yaml config/bgp_config.test.yaml
# Edit bgp_config.test.yaml as needed
```

Then load it:

```python
config = load_bgp_config_from_yaml('config/bgp_config.test.yaml')
```

### Via Environment Variables

```bash
export AS_NUMBER=65002
export ROUTER_ID="3.3.3.3"
# Then loading without YAML will use these values
```

## Default Configuration

If no YAML file is found and no environment variables are set, the following defaults are used:

```python
as_number: 65001
router_id: "2.2.2.2"
hold_time: 180
bgp_version: 4
remote_host: "frr"
remote_port: 179
capabilities: [MP_BGP, ROUTE_REFRESH, ORF, GRACEFUL_RESTART, FOUR_OCTET_AS]
```

## Troubleshooting

### "BGP configuration file not found" error

- Ensure `bgp_config.yaml` exists in one of the search locations
- Or set the `BGP_CONFIG_FILE` environment variable
- Or use environment variables instead of YAML

### YAML parsing errors

- Check for proper indentation (YAML is whitespace-sensitive)
- Verify all required fields are present
- Use a YAML validator: `yamllint config/bgp_config.yaml`

### Validation errors

- Ensure all field types match the expected types (see Configuration Fields table)
- Check capability codes are valid integers
- Verify IP addresses are valid format for `router_id` and `remote_host`
