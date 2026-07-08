"""Static checks for TheHive <-> Cortex lab integration."""

from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = PROJECT_ROOT / "docker-compose.yml"
CORTEX_CONF_PATH = PROJECT_ROOT / "config" / "cortex" / "application.conf"
THEHIVE_CORTEX_ENV_PATH = PROJECT_ROOT / "config" / "cortex" / "thehive-cortex.env"
CORTEX_INDEX_INIT_SCRIPT = PROJECT_ROOT / "scripts" / "cortex-index-init.sh"
CORTEX_APIKEY_SCRIPT = PROJECT_ROOT / "scripts" / "cortex-apikey.sh"
SEED_PRIME_SCRIPT = PROJECT_ROOT / "scripts" / "seed-prime.sh"


def _compose():
    with COMPOSE_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _fixture_key() -> str:
    lines = THEHIVE_CORTEX_ENV_PATH.read_text(encoding="utf-8").splitlines()
    values = [line.split("=", maxsplit=1)[1] for line in lines if line.startswith("TH_CORTEX_KEYS=")]
    assert len(values) == 1
    assert values[0]
    assert values[0].isalnum()
    assert values[0].islower()
    return values[0]


def test_cortex_uses_supported_elasticsearch_uri_setting():
    text = CORTEX_CONF_PATH.read_text(encoding="utf-8")

    assert "uri = \"http://thehive-es:9200\"" in text
    assert 'auth.provider = ["local", "key"]' in text
    assert "search.host" not in text
    assert "host = [\"http://thehive-es:9200\"]" not in text


def test_thehive_compose_enables_cortex_connector():
    services = _compose()["services"]
    thehive = services["thehive"]

    assert "./config/cortex/thehive-cortex.env" in thehive["env_file"]
    command = thehive["command"]
    assert "--no-config-cortex" not in command
    assert command[command.index("--cortex-proto") + 1] == "http"
    assert command[command.index("--cortex-hostnames") + 1] == "cortex"
    assert command[command.index("--cortex-port") + 1] == "9001"
    assert thehive["depends_on"]["cortex"]["condition"] == "service_healthy"


def test_cortex_compose_precreates_key_auth_index_mapping():
    services = _compose()["services"]
    index_init = services["cortex-index-init"]
    cortex = services["cortex"]

    assert index_init["image"] == services["thehive-es"]["image"]
    assert index_init["restart"] == "no"
    assert index_init["entrypoint"] == ["/bin/sh", "/usr/local/bin/cortex-index-init.sh"]
    assert "./scripts/cortex-index-init.sh:/usr/local/bin/cortex-index-init.sh:ro" in index_init["volumes"]
    assert index_init["depends_on"]["thehive-es"]["condition"] == "service_healthy"
    assert cortex["depends_on"]["cortex-index-init"]["condition"] == "service_completed_successfully"

    text = CORTEX_INDEX_INIT_SCRIPT.read_text(encoding="utf-8")
    assert 'INDEX="${CORTEX_INDEX:-cortex_6}"' in text
    assert '"relations":{"type":"keyword"}' in text
    assert '"status":{"type":"keyword"}' in text
    assert '"key":{"type":"keyword"}' in text
    assert '"count":' in text
    assert "lacks keyword key-auth mappings" in text


def test_cortex_seed_script_matches_thehive_fixture_key():
    fixture_key = _fixture_key()
    text = CORTEX_APIKEY_SCRIPT.read_text(encoding="utf-8")

    assert f'CORTEX_API_KEY="${{CORTEX_API_KEY:-{fixture_key}}}"' in text
    assert '"roles": ["read", "analyze", "orgadmin"]' in text
    assert 'CORTEX_INDEX="${CORTEX_INDEX:-cortex_6}"' in text
    assert 'sh -s < "$SCRIPT_DIR/cortex-index-init.sh"' in text
    assert "/api/organization" in text
    assert "/api/user" in text


def test_prime_seed_provisions_and_persists_cortex_key():
    text = SEED_PRIME_SCRIPT.read_text(encoding="utf-8")

    assert "aptl-cortex aptl-thehive aptl-misp aptl-shuffle-frontend" in text
    assert 'INDEXER_PORT="${APTL_HP_WAZUH_INDEXER_9200:-9200}"' in text
    assert 'INDEXER_URL="${INDEXER_URL:-https://localhost:${INDEXER_PORT}}"' in text
    assert 'CORTEX_API_KEY=$("$SCRIPT_DIR/cortex-apikey.sh"' in text
    assert 'update_env_var CORTEX_API_KEY "$CORTEX_API_KEY"' in text
    assert "sed -i" not in text
    assert 'mktemp "${ENV_FILE}.tmp.XXXXXX"' in text
    assert "Cortex API key: provisioned for TheHive connector" in text
