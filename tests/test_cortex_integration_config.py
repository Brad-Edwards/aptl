"""Static and executable checks for TheHive <-> Cortex lab integration."""

import json
from pathlib import Path
import subprocess

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = PROJECT_ROOT / "docker-compose.yml"
CORTEX_CONF_PATH = PROJECT_ROOT / "config" / "cortex" / "application.conf"
THEHIVE_CORTEX_ENV_PATH = PROJECT_ROOT / "config" / "cortex" / "thehive-cortex.env"
CORTEX_INDEX_INIT_SCRIPT = PROJECT_ROOT / "scripts" / "cortex-index-init.sh"
CORTEX_INDEX_MAPPING = PROJECT_ROOT / "config" / "cortex" / "index-mapping.json"
CORTEX_APIKEY_SCRIPT = PROJECT_ROOT / "scripts" / "cortex-apikey.sh"
SEED_PRIME_SCRIPT = PROJECT_ROOT / "scripts" / "seed-prime.sh"
CORTEX_ANALYZER_DIR = PROJECT_ROOT / "config" / "cortex" / "analyzers"
CORTEX_ANALYZER_DESCRIPTOR = (
    CORTEX_ANALYZER_DIR / "APTLObservable" / "APTL_Observable.json"
)
CORTEX_ANALYZER_SCRIPT = (
    CORTEX_ANALYZER_DIR / "APTLObservable" / "aptl_observable.py"
)


def _compose():
    with COMPOSE_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_cortex_uses_supported_elasticsearch_uri_setting():
    text = CORTEX_CONF_PATH.read_text(encoding="utf-8")

    assert "uri = \"http://thehive-es:9200\"" in text
    assert 'auth.provider = ["local", "key"]' in text
    assert "search.host" not in text
    assert "host = [\"http://thehive-es:9200\"]" not in text


def test_cortex_declares_the_bundled_analyzer_catalog():
    text = CORTEX_CONF_PATH.read_text(encoding="utf-8")

    assert 'analyzer.urls = ["/opt/aptl/cortex-analyzers"]' in text


def test_cortex_bundles_an_executable_offline_observable_analyzer(tmp_path):
    descriptor = json.loads(CORTEX_ANALYZER_DESCRIPTOR.read_text(encoding="utf-8"))

    assert descriptor["name"] == "APTL_Observable"
    assert descriptor["integration_type"] == "local"
    assert descriptor["registration_required"] is False
    assert descriptor["subscription_required"] is False
    assert "ip" in descriptor["dataTypeList"]
    assert descriptor["command"] == "APTLObservable/aptl_observable.py"
    assert CORTEX_ANALYZER_SCRIPT.stat().st_mode & 0o111

    job_dir = tmp_path / "job"
    (job_dir / "input").mkdir(parents=True)
    (job_dir / "output").mkdir()
    (job_dir / "input" / "input.json").write_text(
        json.dumps(
            {
                "dataType": "ip",
                "data": "192.0.2.10",
                "tlp": 2,
                "pap": 2,
                "message": "APTL analyzer contract test",
                "parameters": {},
                "config": {},
            }
        ),
        encoding="utf-8",
    )

    subprocess.run([CORTEX_ANALYZER_SCRIPT, job_dir], check=True)
    output = json.loads((job_dir / "output" / "output.json").read_text(encoding="utf-8"))

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        {
            "level": "info",
            "namespace": "APTL",
            "predicate": "Observable",
            "value": "ip",
        }
    ]
    assert output["full"] == {
        "data": "192.0.2.10",
        "dataType": "ip",
        "message": "APTL analyzer contract test",
    }
    assert output["artifacts"] == []
    assert output["operations"] == []


def test_cortex_key_seeding_uses_the_released_runtime_api():
    key_script = CORTEX_APIKEY_SCRIPT.read_text(encoding="utf-8")

    assert "TechVaultScenarioContext_1_0" in key_script
    assert "/api/analyzer" in key_script


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
    assert (
        "./config/cortex/index-mapping.json:/usr/local/share/aptl/cortex-index-mapping.json:ro"
        in index_init["volumes"]
    )
    assert index_init["depends_on"]["thehive-es"]["condition"] == "service_healthy"
    assert cortex["depends_on"]["cortex-index-init"]["condition"] == "service_completed_successfully"

    text = CORTEX_INDEX_INIT_SCRIPT.read_text(encoding="utf-8")
    mapping = json.loads(CORTEX_INDEX_MAPPING.read_text(encoding="utf-8"))
    assert 'INDEX="${CORTEX_INDEX:-cortex_6}"' in text
    assert 'CORTEX_MAPPING_FILE:-/usr/local/share/aptl/cortex-index-mapping.json' in text
    assert mapping["mappings"]["properties"]["relations"]["type"] == "join"
    assert mapping["mappings"]["properties"]["status"] == {"type": "keyword"}
    assert mapping["mappings"]["properties"]["key"] == {"type": "keyword"}
    assert mapping["mappings"]["properties"]["organization"] == {
        "type": "keyword"
    }
    assert '"count":' in text
    assert "lacks the required Cortex mapping" in text


def test_cortex_seed_script_uses_the_realized_thehive_connector_key():
    text = CORTEX_APIKEY_SCRIPT.read_text(encoding="utf-8")

    assert "cortex-service-credentials/cortex/initializer-api-key" in text
    assert "cortex-service-credentials/cortex/connector-api-key" in text
    assert 'IFS= read -r CORTEX_ADMIN_KEY < "$CORTEX_INITIALIZER_KEY_FILE"' in text
    assert 'IFS= read -r CORTEX_API_KEY < "$CORTEX_CONNECTOR_KEY_FILE"' in text
    assert '"roles": ["read", "analyze"]' in text
    assert '"roles": ["read", "analyze", "orgadmin"]' in text
    # The env-pack host-publishes no Cortex port, so the seed reaches the API
    # through the container rather than a host localhost:9001 binding.
    assert 'docker exec "$CORTEX_CONTAINER" curl' in text
    # The released pack leaves Cortex's native schema under Cortex ownership.
    # Initialization must use Cortex's API rather than mutate Elasticsearch.
    assert "cortex-index-init.sh" not in text
    assert "/api/maintenance/migrate" in text
    assert "Cortex owns its native index mapping" in text
    assert "curl -X PUT" not in text
    assert "curl -X DELETE" not in text
    assert "/api/organization" in text
    assert "/api/user" in text
    assert "/api/analyzerdefinition/scan" in text
    assert "/api/analyzerdefinition" in text
    assert "/api/organization/analyzer/${ANALYZER_DEFINITION_ID}" in text
    assert 'ANALYZER_NAME="TechVaultScenarioContext"' in text


def test_prime_seed_provisions_and_persists_cortex_key():
    text = SEED_PRIME_SCRIPT.read_text(encoding="utf-8")

    assert '"$CORTEX_CONTAINER"' in text
    assert '"$THEHIVE_CONTAINER"' in text
    assert '"$MISP_CONTAINER"' in text
    assert '"$SHUFFLE_CONTAINER"' in text
    assert 'INDEXER_PORT="${APTL_HP_WAZUH_INDEXER_9200:-9200}"' in text
    assert 'INDEXER_URL="${INDEXER_URL:-https://localhost:${INDEXER_PORT}}"' in text
    assert 'CORTEX_API_KEY=$("$SCRIPT_DIR/cortex-apikey.sh"' in text
    assert 'update_env_var CORTEX_API_KEY "$CORTEX_API_KEY"' in text
    assert "sed -i" not in text
    assert 'mktemp "${ENV_FILE}.tmp.XXXXXX"' in text
    assert "Cortex API key: provisioned for TheHive connector" in text
