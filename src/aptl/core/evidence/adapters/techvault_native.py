"""Trusted native owners for the four TechVault capture registrations.

The public SDL chooses no URL, command, credential, path, or executable.  This
module binds the exact code-owned TechVault registrations to bounded native
operations derived from the admitted realization.  Raw service responses and
credentials remain inside this owner; the source adapters receive only the
allowlisted projections their contracts validate.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aptl.core.deployment._compose_stateful_model import artifact_source_path
from aptl.core.evidence.adapters.techvault import (
    CORTEX_ANALYZER_ID,
    CORTEX_OBSERVABLE,
    SURICATA_SQLI_SID,
    WAZUH_SQLI_RULE_ID,
    CortexEnrichmentSource,
    SuricataRuleReadinessSource,
    SuricataWazuhSqliSource,
)
from aptl.utils.curl_safe import basic_auth_header, curl_json

_CORTEX_REGISTRATION = "aptl.collector.cortex-enrichment"
_READINESS_REGISTRATION = "aptl.collector.suricata-rule-readiness"
_SQLI_REGISTRATION = "aptl.collector.suricata-wazuh-sqli"
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_SURICATA_CONTAINER = "aptl-suricata"
_KALI_CONTAINER = "aptl-kali"

_SURICATA_READINESS_SCRIPT = r"""
set -eu
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
suricata -T -c /etc/suricata/suricata.yaml >"$tmp" 2>&1
grep -Eq '(^|[^0-9])3 rule files processed([^0-9]|$)' "$tmp"
grep -Eq '(^|[^0-9])0 rules failed([^0-9]|$)' "$tmp"
grep -Fq 'Configuration provided was successfully loaded' "$tmp"
sha256sum /etc/suricata/suricata.yaml /etc/suricata/rules/local.rules
sed -nE 's/.*sid:([0-9]+).*/sid=\1/p' /etc/suricata/rules/local.rules
""".strip()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded(value: object) -> bool:
    try:
        return (
            len(json.dumps(value, separators=(",", ":"), default=str).encode())
            <= _MAX_SOURCE_BYTES
        )
    except (TypeError, ValueError, RecursionError):
        return False


def _node(realization: object, name: str) -> object | None:
    return next(
        (
            item
            for item in getattr(realization, "nodes", ())
            if getattr(item, "name", None) == name
        ),
        None,
    )


def _published_url(
    realization: object, name: str, port: int, scheme: str
) -> str | None:
    node = _node(realization, name)
    if node is None:
        return None
    matches = [
        item
        for item in getattr(node, "published_ports", ())
        if getattr(item, "container_port", None) == port
        and getattr(item, "protocol", "tcp") == "tcp"
    ]
    if len(matches) != 1 or getattr(matches[0], "host_port", None) is None:
        return None
    host = getattr(matches[0], "host_ip", "127.0.0.1")
    if host not in {"127.0.0.1", "::1", "localhost"}:
        return None
    return f"{scheme}://127.0.0.1:{matches[0].host_port}"


def _generated_output(
    realization: object, project_dir: Path, provenance: str, output_name: str
) -> str | None:
    artifacts = [
        item
        for item in getattr(realization, "generated_artifacts", ())
        if getattr(item, "provenance", None) == provenance
    ]
    if len(artifacts) != 1:
        return None
    outputs = [
        item
        for item in getattr(artifacts[0], "outputs", ())
        if getattr(item, "name", None) == output_name
    ]
    if len(outputs) != 1:
        return None
    root = artifact_source_path(project_dir, artifacts[0]).resolve()
    target = (root / outputs[0].path).resolve()
    if not target.is_relative_to(root):
        return None
    try:
        value = target.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def _content_identities(realization: object) -> dict[str, str] | None:
    required = {"suricata-config", "suricata-local-rules"}
    identities: dict[str, str] = {}
    for placement in getattr(realization, "placements", ()):
        content = getattr(placement, "content", None)
        name = getattr(content, "content_name", None)
        if name not in required:
            continue
        artifact_id = getattr(content, "artifact_id", None)
        digest = getattr(content, "artifact_digest", None)
        if not isinstance(artifact_id, str) or not isinstance(digest, str):
            return None
        identities[name] = f"{artifact_id}@{digest}"
    return identities if set(identities) == required else None


def _webapp_address(realization: object) -> str | None:
    kali = _node(realization, "kali")
    webapp = _node(realization, "webapp")
    if kali is None or webapp is None:
        return None
    kali_networks = dict(getattr(kali, "static_address_assignments", ()))
    web_networks = dict(getattr(webapp, "static_address_assignments", ()))
    shared = sorted(set(kali_networks) & set(web_networks))
    return web_networks[shared[0]] if len(shared) == 1 else None


def _connector_projection(
    value: object, *, cortex_context: bool = False
) -> dict[str, str] | None:
    if isinstance(value, Mapping):
        name = str(value.get("name", value.get("service", "")))[:128]
        status = str(value.get("status", "")).upper()
        local_context = cortex_context or "cortex" in name.lower()
        if local_context and status == "OK":
            return {"name": name or "cortex", "status": "OK"}
        for key, item in value.items():
            found = _connector_projection(
                item,
                cortex_context=local_context or "cortex" in str(key).lower(),
            )
            if found is not None:
                return found
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes):
        for item in value:
            found = _connector_projection(item, cortex_context=cortex_context)
            if found is not None:
                return found
    return None


def _inside_window(value: object, start_iso: str, end_iso: str) -> bool:
    try:
        instant = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        start = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False
    return start <= instant <= end


class TechVaultNativeEvidenceOwner:
    """Own the bounded native operations behind three TechVault sources."""

    def __init__(
        self,
        *,
        backend: object,
        realization: object,
        project_dir: Path,
        indexer_auth: tuple[str, str],
        thehive_api_key: str,
        request_json: Callable[..., object | None] = curl_json,
        now: Callable[[], str] = _iso_now,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._backend = backend
        self._realization = realization
        self._project_dir = project_dir
        self._indexer_auth = indexer_auth
        self._thehive_api_key = thehive_api_key
        self._request_json = request_json
        self._now = now
        self._sleep = sleep
        self._cortex_url = _published_url(realization, "cortex", 9001, "http")
        self._thehive_url = _published_url(realization, "thehive", 9000, "http")
        self._indexer_url = _published_url(realization, "wazuh-indexer", 9200, "https")
        self._connector_key = _generated_output(
            realization,
            project_dir,
            "techvault:cortex-service-credentials/v1",
            "connector-api-key",
        )
        self._webapp_ip = _webapp_address(realization)

    def sources(self) -> dict[str, object]:
        """Return exact registration-id to source bindings."""

        kwargs: dict[str, Any] = {
            "poll_attempts": 30,
            "poll_interval_seconds": 2.0,
        }
        if self._sleep is not None:
            kwargs["sleep"] = self._sleep
        return {
            _CORTEX_REGISTRATION: CortexEnrichmentSource(self.cortex_query),
            _READINESS_REGISTRATION: SuricataRuleReadinessSource(
                self.suricata_readiness_query
            ),
            _SQLI_REGISTRATION: SuricataWazuhSqliSource(
                self.trigger_sqli,
                self.query_suricata,
                self.query_wazuh,
                **kwargs,
            ),
        }

    def cortex_query(self, start_iso: str, end_iso: str) -> Mapping[str, object] | None:
        """Execute the exact analyzer and read TheHive's native connector status."""

        if (
            not self._cortex_url
            or not self._thehive_url
            or not self._connector_key
            or not self._thehive_api_key
        ):
            return None
        auth = f"Bearer {self._connector_key}"
        analyzers = self._request_json(
            f"{self._cortex_url}/api/analyzer", auth_header=auth, timeout=30
        )
        if not isinstance(analyzers, list) or not _bounded(analyzers):
            return None
        selected = [
            item
            for item in analyzers
            if isinstance(item, Mapping)
            and item.get("analyzerDefinitionId") == CORTEX_ANALYZER_ID
            and item.get("id")
        ]
        if len(selected) != 1:
            return None
        started_at = self._now()
        job = self._request_json(
            f"{self._cortex_url}/api/analyzer/{selected[0]['id']}/run",
            auth_header=auth,
            body={"data": CORTEX_OBSERVABLE, "dataType": "ip", "tlp": 2, "pap": 2},
            method="POST",
            timeout=30,
        )
        if not isinstance(job, Mapping) or not job.get("id"):
            return None
        report = self._request_json(
            f"{self._cortex_url}/api/job/{job['id']}/waitreport?atMost=2minute",
            auth_header=auth,
            timeout=150,
        )
        connector = self._request_json(
            f"{self._thehive_url}/api/v1/status",
            auth_header=f"Bearer {self._thehive_api_key}",
            timeout=30,
        )
        finished_at = self._now()
        if not isinstance(report, Mapping) or not _bounded(report):
            return None
        full = (
            (report.get("report") or {}).get("full")
            if isinstance(report.get("report"), Mapping)
            else None
        )
        if isinstance(full, str):
            try:
                full = json.loads(full)
            except json.JSONDecodeError:
                return None
        projected_connector = _connector_projection(connector)
        if not isinstance(full, Mapping) or projected_connector is None:
            return None
        return {
            "analyzers": [
                {
                    "id": str(item.get("analyzerDefinitionId", "")),
                    "enabled": bool(item.get("id")),
                }
                for item in analyzers
                if isinstance(item, Mapping) and item.get("analyzerDefinitionId")
            ],
            "report": {
                "analyzer_id": CORTEX_ANALYZER_ID,
                "observable": CORTEX_OBSERVABLE,
                "status": str(report.get("status", "")),
                "started_at": started_at,
                "finished_at": finished_at,
                "scenario_role": str(full.get("scenario_role", "")),
            },
            "connector": projected_connector,
        }

    def suricata_readiness_query(
        self, _start_iso: str, _end_iso: str
    ) -> Mapping[str, object] | None:
        """Join admitted identities with a native configuration/readback probe."""

        node = _node(self._realization, "suricata")
        image = getattr(node, "image", None) if node is not None else None
        image_ref = getattr(image, "image_ref", None)
        identities = _content_identities(self._realization)
        image_digest_read = getattr(self._backend, "container_image_digest", None)
        image_digest = (
            image_digest_read(_SURICATA_CONTAINER)
            if callable(image_digest_read)
            else None
        )
        execute = getattr(self._backend, "container_exec_with_input", None)
        if (
            not isinstance(image_ref, str)
            or not isinstance(image_digest, str)
            or identities is None
            or not callable(execute)
        ):
            return None
        result = execute(
            _SURICATA_CONTAINER,
            ["sh", "-s"],
            _SURICATA_READINESS_SCRIPT,
            timeout=120,
        )
        if result.returncode != 0 or len(result.stdout.encode()) > _MAX_SOURCE_BYTES:
            return None
        digests: dict[str, str] = {}
        sids: list[int] = []
        for line in result.stdout.splitlines():
            if line.startswith("sid="):
                try:
                    sids.append(int(line.removeprefix("sid=")))
                except ValueError:
                    return None
                continue
            fields = line.split()
            if len(fields) == 2 and len(fields[0]) == 64:
                if fields[1] == "/etc/suricata/suricata.yaml":
                    digests["suricata-config"] = "sha256:" + fields[0]
                elif fields[1] == "/etc/suricata/rules/local.rules":
                    digests["suricata-local-rules"] = "sha256:" + fields[0]
        return {
            "image_ref": image_ref,
            "image_digest": image_digest,
            "content_identities": identities,
            "realized_byte_digests": digests,
            "native_configuration_ok": True,
            "selected_sources": ["suricata-builtin", "techvault-local"],
            "local_sids": sids,
        }

    def trigger_sqli(self) -> Mapping[str, object] | None:
        """Send one fixed participant-equivalent Kali login probe."""

        if not self._webapp_ip:
            return None
        execute = getattr(self._backend, "container_exec_with_input", None)
        if not callable(execute):
            return None
        trigger_id = "aptl-probe-" + secrets.token_hex(8)
        triggered_at = self._now()
        payload = (
            "username=%27+UNION+SELECT+%27"
            + trigger_id
            + "%27--&password=aptl-observation-probe"
        )
        result = execute(
            _KALI_CONTAINER,
            [
                "curl",
                "-fsS",
                "-o",
                "/dev/null",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/x-www-form-urlencoded",
                "--data-binary",
                "@-",
                f"http://{self._webapp_ip}/login",
            ],
            payload,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        return {
            "trigger_id": trigger_id,
            "method": "POST",
            "path": "/login",
            "source_ip": CORTEX_OBSERVABLE,
            "destination_ip": self._webapp_ip,
            "contains_union_select": True,
            "triggered_at": triggered_at,
        }

    def query_suricata(
        self, start_iso: str, end_iso: str
    ) -> Sequence[Mapping[str, object]] | None:
        """Read a bounded EVE tail and retain exact fresh SQLi alerts only."""

        result = self._backend.container_exec(
            _SURICATA_CONTAINER,
            ["tail", "-c", str(_MAX_SOURCE_BYTES + 1), "/var/log/suricata/eve.json"],
            timeout=30,
        )
        raw = result.stdout.encode()
        if result.returncode != 0 or len(raw) > _MAX_SOURCE_BYTES:
            return None
        events: list[Mapping[str, object]] = []
        for line in result.stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            alert = event.get("alert") if isinstance(event, Mapping) else None
            if (
                isinstance(event, Mapping)
                and isinstance(alert, Mapping)
                and alert.get("signature_id") == SURICATA_SQLI_SID
                and _inside_window(event.get("timestamp"), start_iso, end_iso)
            ):
                events.append(event)
        return events[:256]

    def query_wazuh(
        self, start_iso: str, end_iso: str
    ) -> Sequence[Mapping[str, object]] | None:
        """Query the bounded Wazuh window for exact rule 303020 alerts."""

        if not self._indexer_url:
            return None
        response = self._request_json(
            f"{self._indexer_url}/wazuh-alerts-4.x-*/_search",
            auth_header=basic_auth_header(*self._indexer_auth),
            body={
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {"rule.id": WAZUH_SQLI_RULE_ID}},
                            {
                                "range": {
                                    "@timestamp": {"gte": start_iso, "lte": end_iso}
                                }
                            },
                        ]
                    }
                },
                "size": 100,
                "sort": [{"@timestamp": "asc"}],
            },
            insecure=True,
            timeout=30,
        )
        if not isinstance(response, Mapping) or not _bounded(response):
            return None
        hits = (
            (response.get("hits") or {}).get("hits")
            if isinstance(response.get("hits"), Mapping)
            else None
        )
        if not isinstance(hits, list):
            return None
        normalized: list[Mapping[str, object]] = []
        for hit in hits:
            source = hit.get("_source", hit) if isinstance(hit, Mapping) else None
            if not isinstance(source, Mapping):
                continue
            item = dict(source)
            item["timestamp"] = source.get("timestamp", source.get("@timestamp"))
            normalized.append(item)
        return normalized


__all__ = ("TechVaultNativeEvidenceOwner",)
