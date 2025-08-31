# Configuration Management Architecture

Centralized environment and runtime configuration for APTL.

## Goals

- Single source of truth for ports, paths, and secrets
- Consistent configuration loading across languages and services
- Simple overrides for local development or CI

## Structure

```
aptl/
├── .env                 # Environment variable definitions
├── aptl.config          # YAML configuration with defaults
└── ...                  # Code and documentation
```

## .env File

Defines environment variables for all services. Example:

```bash
APT_ENV=development
WAZUH_API_PORT=55000
KALI_SSH_PORT=2023
```

Values can be overridden per-developer or per-environment without modifying source files.

## aptl.config

YAML file containing structured settings that reference environment variables:

```yaml
version: 1
paths:
  data_dir: ${APT_DATA_DIR:-./data}
wazuh:
  api_port: ${WAZUH_API_PORT}
  dashboard_port: ${WAZUH_DASHBOARD_PORT:-443}
```

The config loader resolves `${VAR}` entries using the values loaded from `.env`.

## Loading Order

1. Load `.env` using language-specific dotenv libraries
2. Parse `aptl.config`
3. Resolve `${VAR}` placeholders from the environment
4. Expose resulting config object to application code

## Component Integration

- **Node.js**: use `dotenv` and `js-yaml` to load config in each MCP service
- **Python**: use `python-dotenv` and `pyyaml` for auxiliary scripts
- **Shell scripts**: source `.env` and use `yq` to read `aptl.config`

## Example Usage

```javascript
// Node.js loader example
import dotenv from 'dotenv';
import fs from 'fs';
import yaml from 'js-yaml';

dotenv.config();
const config = yaml.load(fs.readFileSync('aptl.config', 'utf8'));
```

Applications import the shared loader to ensure consistent configuration across the lab.

