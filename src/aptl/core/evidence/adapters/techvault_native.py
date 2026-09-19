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
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlunsplit

from aptl.core.evidence.adapters.techvault import (
    CORTEX_ANALYZER_ID,
    CORTEX_OBSERVABLE,
    SURICATA_SQLI_SID,
    WAZUH_SQLI_RULE_ID,
    CortexEnrichmentSource,
    SuricataRuleReadinessSource,
    SuricataWazuhSqliSource,
)
from aptl.core.evidence.adapters.techvault_native_support import (
    MAX_SOURCE_BYTES,
    bounded,
    connector_projection,
    content_identities,
    find_node,
    generated_output,
    inside_window,
    published_url,
    utc_iso_now,
    webapp_endpoint,
)
from aptl.utils.curl_safe import basic_auth_header, curl_json

_CORTEX_REGISTRATION = "aptl.collector.cortex-enrichment"
_READINESS_REGISTRATION = "aptl.collector.suricata-rule-readiness"
_SQLI_REGISTRATION = "aptl.collector.suricata-wazuh-sqli"
_SURICATA_CONTAINER = "aptl-suricata"
_KALI_CONTAINER = "aptl-kali"
_TIMESTAMP_FIELD = "@timestamp"

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


@dataclass(frozen=True)
class TechVaultNativeDependencies:
    """Injectable boundaries used by deterministic owner tests."""

    request_json: Callable[..., object | None] = curl_json
    now: Callable[[], str] = utc_iso_now
    sleep: Callable[[float], None] | None = None


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
        dependencies: TechVaultNativeDependencies | None = None,
    ) -> None:
        """Bind trusted operations to one admitted TechVault realization."""

        selected_dependencies = dependencies or TechVaultNativeDependencies()
        self._backend = backend
        self._realization = realization
        self._project_dir = project_dir
        self._indexer_auth = indexer_auth
        self._thehive_api_key = thehive_api_key
        self._request_json = selected_dependencies.request_json
        self._now = selected_dependencies.now
        self._sleep = selected_dependencies.sleep
        self._cortex_url = published_url(realization, "cortex", 9001, "http")
        # The pinned pack declares this listener as HTTP. Legacy static
        # Compose's TLS projection is not authority over the selected SDL.
        self._thehive_url = published_url(realization, "thehive", 9000, "http")
        self._indexer_url = published_url(realization, "wazuh-indexer", 9200, "https")
        self._connector_key = generated_output(
            realization,
            project_dir,
            "techvault:cortex-service-credentials/v1",
            "connector-api-key",
        )
        endpoint = webapp_endpoint(realization)
        self._webapp_ip = endpoint[0] if endpoint is not None else None
        self._webapp_port = endpoint[1] if endpoint is not None else None

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

        prerequisites = self._cortex_prerequisites()
        if prerequisites is None:
            return None
        cortex_url, thehive_url, auth = prerequisites
        analyzers = self._request_json(
            f"{cortex_url}/api/analyzer", auth_header=auth, timeout=30
        )
        if not isinstance(analyzers, list) or not bounded(analyzers):
            return None
        selected = [
            item
            for item in analyzers
            if isinstance(item, Mapping)
            and item.get("analyzerDefinitionId") == CORTEX_ANALYZER_ID
            and item.get("id")
        ]
        return self._run_cortex_query(
            cortex_url,
            thehive_url,
            auth,
            analyzers,
            selected,
        )

    def _cortex_prerequisites(self) -> tuple[str, str, str] | None:
        """Return complete Cortex/TheHive endpoint credentials when available."""

        result = None
        if (
            self._cortex_url
            and self._thehive_url
            and self._connector_key
            and self._thehive_api_key
        ):
            result = (
                self._cortex_url,
                self._thehive_url,
                f"Bearer {self._connector_key}",
            )
        return result

    def _run_cortex_query(
        self,
        cortex_url: str,
        thehive_url: str,
        auth: str,
        analyzers: list[object],
        selected: list[Mapping[str, object]],
    ) -> Mapping[str, object] | None:
        """Run the uniquely selected analyzer and project its bounded response."""

        if len(selected) != 1:
            return None
        started_at = self._now()
        job = self._request_json(
            f"{cortex_url}/api/analyzer/{selected[0]['id']}/run",
            auth_header=auth,
            body={"data": CORTEX_OBSERVABLE, "dataType": "ip", "tlp": 2, "pap": 2},
            method="POST",
            timeout=30,
        )
        if not isinstance(job, Mapping) or not job.get("id"):
            return None
        return self._read_cortex_result(
            cortex_url,
            thehive_url,
            auth,
            analyzers,
            str(job["id"]),
            started_at,
        )

    def _read_cortex_result(
        self,
        cortex_url: str,
        thehive_url: str,
        auth: str,
        analyzers: list[object],
        job_id: str,
        started_at: str,
    ) -> Mapping[str, object] | None:
        """Read and reduce Cortex report plus TheHive connector health."""

        report = self._request_json(
            f"{cortex_url}/api/job/{job_id}/waitreport?atMost=2minute",
            auth_header=auth,
            timeout=150,
        )
        connector = self._read_thehive_connector(thehive_url)
        finished_at = self._now()
        if not isinstance(report, Mapping) or not bounded(report):
            return None
        return self._project_cortex_result(
            analyzers, report, connector, started_at, finished_at
        )

    def _read_thehive_connector(self, thehive_url: str) -> object:
        """Poll the read-only connector status through its startup refresh race."""

        connector: object = None
        sleep = self._sleep or time.sleep
        for attempt in range(30):
            connector = self._request_json(
                f"{thehive_url}/api/v1/status",
                auth_header=f"Bearer {self._thehive_api_key}",
                timeout=30,
            )
            if connector_projection(connector) is not None:
                break
            if attempt < 29:
                sleep(2.0)
        return connector

    @staticmethod
    def _project_cortex_result(
        analyzers: list[object],
        report: Mapping[str, object],
        connector: object,
        started_at: str,
        finished_at: str,
    ) -> Mapping[str, object] | None:
        """Project only evidence-contract fields from native service responses."""

        report_body = report.get("report")
        full = report_body.get("full") if isinstance(report_body, Mapping) else None
        if isinstance(full, str):
            try:
                full = json.loads(full)
            except json.JSONDecodeError:
                return None
        projected_connector = connector_projection(connector)
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

        node = find_node(self._realization, "suricata")
        image = getattr(node, "image", None) if node is not None else None
        image_ref = getattr(image, "image_ref", None)
        identities = content_identities(self._realization)
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
        if result.returncode != 0 or len(result.stdout.encode()) > MAX_SOURCE_BYTES:
            return None
        parsed = self._parse_suricata_readiness(result.stdout)
        outcome = None
        if parsed is not None:
            digests, sids = parsed
            outcome = {
                # A locally built backend image has a tag in the plan and an
                # immutable image ID only after realization.  Report their
                # observed digest binding without pretending the author pinned
                # the local implementation in advance.
                "image_ref": f"{image_ref.split('@', 1)[0]}@{image_digest}",
                "image_digest": image_digest,
                "content_identities": identities,
                "realized_byte_digests": digests,
                "native_configuration_ok": True,
                "selected_sources": ["suricata-builtin", "techvault-local"],
                "local_sids": sids,
            }
        return outcome

    @staticmethod
    def _parse_suricata_readiness(
        stdout: str,
    ) -> tuple[dict[str, str], list[int]] | None:
        """Parse exact digest and SID lines from the bounded native probe."""

        digests: dict[str, str] = {}
        sids: list[int] = []
        valid = True
        paths = {
            "/etc/suricata/suricata.yaml": "suricata-config",
            "/etc/suricata/rules/local.rules": "suricata-local-rules",
        }
        for line in stdout.splitlines():
            if line.startswith("sid="):
                try:
                    sids.append(int(line.removeprefix("sid=")))
                except ValueError:
                    valid = False
                    break
                continue
            fields = line.split()
            if len(fields) == 2 and len(fields[0]) == 64 and fields[1] in paths:
                digests[paths[fields[1]]] = "sha256:" + fields[0]
        return (digests, sids) if valid else None

    def trigger_sqli(self) -> Mapping[str, object] | None:
        """Send one fixed participant-equivalent Kali login probe."""

        execute = getattr(self._backend, "container_exec_with_input", None)
        if not self._webapp_ip or self._webapp_port is None or not callable(execute):
            return None
        trigger_id = "aptl-probe-" + secrets.token_hex(8)
        triggered_at = self._now()
        payload = (
            "username=%27+UNION+SELECT+%27"
            + trigger_id
            + "%27--&password=aptl-observation-probe"  # NOSONAR S2068: fixed probe
        )
        endpoint = urlunsplit(
            ("http", f"{self._webapp_ip}:{self._webapp_port}", "/login", "", "")
        )
        result = execute(
            _KALI_CONTAINER,
            [
                "curl",
                "-sS",
                "-o",
                "/dev/null",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/x-www-form-urlencoded",
                "--data-binary",
                "@-",
                endpoint,
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
            ["tail", "-c", str(MAX_SOURCE_BYTES + 1), "/var/log/suricata/eve.json"],
            timeout=30,
        )
        raw = result.stdout.encode()
        if result.returncode != 0 or len(raw) > MAX_SOURCE_BYTES:
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
                and inside_window(event.get("timestamp"), start_iso, end_iso)
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
                                    _TIMESTAMP_FIELD: {"gte": start_iso, "lte": end_iso}
                                }
                            },
                        ]
                    }
                },
                "size": 100,
                "sort": [{_TIMESTAMP_FIELD: "asc"}],
            },
            insecure=True,
            timeout=30,
        )
        return self._normalize_wazuh_response(response)

    @staticmethod
    def _normalize_wazuh_response(
        response: object,
    ) -> Sequence[Mapping[str, object]] | None:
        """Reduce a bounded indexer response to its allowlisted hit sources."""

        if not isinstance(response, Mapping) or not bounded(response):
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
            item["timestamp"] = source.get("timestamp", source.get(_TIMESTAMP_FIELD))
            normalized.append(item)
        return normalized


__all__ = ("TechVaultNativeDependencies", "TechVaultNativeEvidenceOwner")
