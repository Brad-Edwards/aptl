"""Native owner tests for the released TechVault evidence contracts."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from aptl.core.deployment.realization import DeploymentPublishedPort
from aptl.core.evidence.adapters.techvault import TECHVAULT_LOCAL_SIDS
from aptl.core.evidence.adapters.techvault_native import (
    TechVaultNativeDependencies,
    TechVaultNativeEvidenceOwner,
)
from aptl.core.evidence.outcomes import CollectorStatus

_START = "2026-09-14T10:00:00Z"
_TRIGGER = "2026-09-14T10:00:05Z"
_FINISH = "2026-09-14T10:00:10Z"
_END = "2026-09-14T10:01:00Z"
_DIGEST = "sha256:" + "a" * 64


def _node(name, *, port=None, address=None, image=None):
    return SimpleNamespace(
        name=name,
        published_ports=(
            (DeploymentPublishedPort(container_port=port, host_port=port),)
            if port is not None
            else ()
        ),
        static_address_assignments=(
            (("dmz-net", address),) if address is not None else ()
        ),
        image=image,
    )


def _realization(project_dir: Path):
    key_relpath = Path("cortex/connector-api-key")
    key_path = (
        project_dir / ".aptl/realization/cortex-service-credentials" / key_relpath
    )
    key_path.parent.mkdir(parents=True)
    key_path.write_text("connector-key\n", encoding="utf-8")
    output = SimpleNamespace(name="connector-api-key", path=str(key_relpath))
    artifact = SimpleNamespace(
        name="cortex-service-credentials",
        generator="rendered_config",
        provenance="techvault:cortex-service-credentials/v1",
        outputs=(output,),
    )
    image = SimpleNamespace(image_ref="jasonish/suricata@" + _DIGEST)
    content = (
        SimpleNamespace(
            content=SimpleNamespace(
                content_name="suricata-config",
                artifact_id="techvault-suricata-config",
                artifact_digest="sha256:" + "d" * 64,
            )
        ),
        SimpleNamespace(
            content=SimpleNamespace(
                content_name="suricata-local-rules",
                artifact_id="techvault-suricata-local-rules",
                artifact_digest="sha256:" + "e" * 64,
            )
        ),
    )
    return SimpleNamespace(
        nodes=(
            _node("cortex", port=9001),
            _node("thehive", port=9000),
            _node("wazuh-indexer", port=9200),
            _node("suricata", image=image),
            _node("kali", address="172.20.1.30"),
            _node("webapp", address="172.20.1.20"),
        ),
        placements=content,
        generated_artifacts=(artifact,),
    )


class _Backend:
    def __init__(self):
        self.probe_payload = ""

    @staticmethod
    def container_inspect(_name):
        return {"Image": _DIGEST}

    @staticmethod
    def container_image_digest(_name):
        return _DIGEST

    def container_exec_with_input(self, name, cmd, payload, *, timeout):
        assert cmd
        if name == "aptl-suricata":
            rows = [
                "d" * 64 + "  /etc/suricata/suricata.yaml",
                "e" * 64 + "  /etc/suricata/rules/local.rules",
                *(f"sid={sid}" for sid in sorted(TECHVAULT_LOCAL_SIDS)),
            ]
            return subprocess.CompletedProcess(cmd, 0, "\n".join(rows) + "\n", "")
        self.probe_payload = payload
        assert "UNION" not in " ".join(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    @staticmethod
    def container_exec(_name, cmd, *, timeout):
        event = {
            "timestamp": _FINISH,
            "src_ip": "172.20.1.30",
            "dest_ip": "172.20.1.20",
            "flow_id": 42,
            "alert": {"signature_id": 1000010},
        }
        return subprocess.CompletedProcess(cmd, 0, json.dumps(event) + "\n", "")


def _request(url, **kwargs):
    if url.endswith("/api/analyzer"):
        return [
            {
                "id": "analyzer-1",
                "analyzerDefinitionId": "TechVaultScenarioContext_1_0",
            }
        ]
    if url.endswith("/run"):
        return {"id": "job-1"}
    if "waitreport" in url:
        return {
            "status": "Success",
            "report": {"full": {"scenario_role": "attacker", "secret": "drop"}},
        }
    if url.endswith("/api/v1/status"):
        return {"services": [{"name": "Cortex", "status": "OK"}]}
    if url.endswith("/_search"):
        return {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "@timestamp": _FINISH,
                            "rule": {"id": "303020"},
                            "data": {
                                "flow_id": "42",
                                "src_ip": "172.20.1.30",
                                "dest_ip": "172.20.1.20",
                                "alert": {"signature_id": 1000010},
                            },
                        }
                    }
                ]
            }
        }
    raise AssertionError(url)


def _owner(tmp_path, backend=None, request_json=_request):
    times = iter((_TRIGGER, _FINISH, _TRIGGER))
    return TechVaultNativeEvidenceOwner(
        backend=backend or _Backend(),
        realization=_realization(tmp_path),
        project_dir=tmp_path,
        indexer_auth=("admin", "password"),
        thehive_api_key="operator-api-key",
        dependencies=TechVaultNativeDependencies(
            request_json=request_json,
            now=lambda: next(times),
            sleep=lambda _seconds: None,
        ),
    )


def test_native_owner_wires_only_the_three_native_registrations(tmp_path):
    assert set(_owner(tmp_path).sources()) == {
        "aptl.collector.cortex-enrichment",
        "aptl.collector.suricata-rule-readiness",
        "aptl.collector.suricata-wazuh-sqli",
    }


def test_cortex_owner_executes_exact_analyzer_and_projects_no_full_report(tmp_path):
    result = (
        _owner(tmp_path)
        .sources()["aptl.collector.cortex-enrichment"]
        .fetch(_START, _END)
    )

    assert result.status is CollectorStatus.OK
    assert result.records[0]["report"]["scenario_role"] == "attacker"
    assert "secret" not in result.records[0]["report"]


def test_cortex_owner_uses_runtime_thehive_api_key_without_admin_fallback(tmp_path):
    requests = []

    def request(url, **kwargs):
        requests.append((url, kwargs))
        return _request(url, **kwargs)

    result = (
        _owner(tmp_path, request_json=request)
        .sources()["aptl.collector.cortex-enrichment"]
        .fetch(_START, _END)
    )

    assert result.status is CollectorStatus.OK
    status_request = next(item for item in requests if item[0].endswith("/status"))
    assert status_request[1]["auth_header"] == "Bearer operator-api-key"


def test_suricata_owner_joins_native_success_with_admitted_and_realized_identity(
    tmp_path,
):
    result = (
        _owner(tmp_path)
        .sources()["aptl.collector.suricata-rule-readiness"]
        .fetch(_START, _END)
    )
    text = b"".join(result.chunks).decode()

    assert result.status is CollectorStatus.OK
    assert "image_ref=jasonish/suricata@sha256:" in text
    assert "content_identity.suricata-local-rules=" in text
    assert text.count("local_sid=") == 16
    assert "/etc/" not in text


def test_sqli_owner_keeps_probe_body_off_argv_and_requires_flow_join(tmp_path):
    backend = _Backend()
    result = (
        _owner(tmp_path, backend)
        .sources()["aptl.collector.suricata-wazuh-sqli"]
        .fetch(_START, _END)
    )

    assert result.status is CollectorStatus.OK
    assert "UNION" in backend.probe_payload
    assert result.observer_effect == "one fixed POST /login containing UNION SELECT"


def test_missing_connector_credential_is_source_unavailable(tmp_path):
    realization = _realization(tmp_path)
    key = (
        tmp_path
        / ".aptl/realization/cortex-service-credentials/cortex/connector-api-key"
    )
    key.unlink()
    owner = TechVaultNativeEvidenceOwner(
        backend=_Backend(),
        realization=realization,
        project_dir=tmp_path,
        indexer_auth=("admin", "password"),
        thehive_api_key="operator-api-key",
        dependencies=TechVaultNativeDependencies(
            request_json=_request,
            sleep=lambda _seconds: None,
        ),
    )

    assert owner.cortex_query(_START, _END) is None
