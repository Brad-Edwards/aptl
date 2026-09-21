"""Adapter-owned native owners for the TechVault capture registrations.

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
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlunsplit

from aptl_techvault.evidence.techvault import (
    CORTEX_OBSERVABLE,
    SURICATA_SQLI_SID,
    WAZUH_SQLI_RULE_ID,
    CortexEnrichmentSource,
    SuricataRuleReadinessSource,
    SuricataWazuhSqliSource,
)
from aptl_techvault.evidence._techvault_native_cortex import (
    TechVaultNativeCortexMixin,
)
from aptl_techvault.evidence.techvault_misp_readiness import (
    MispAuthenticatedApiReadinessSource,
)
from aptl_techvault.evidence.techvault_native_readiness import (
    admitted_misp_state,
    declared_endpoint_agents,
    misp_readiness,
    wazuh_agent_readiness,
)
from aptl_techvault.evidence.techvault_wazuh_agent_readiness import (
    WazuhAgentReadinessSource,
)
from aptl_techvault.evidence.techvault_native_support import (
    MAX_SOURCE_BYTES,
    bounded,
    content_identities,
    find_node,
    generated_output,
    generated_output_path,
    inside_window,
    published_url,
    utc_iso_now,
    webapp_endpoint,
)
from aptl.utils.curl_safe import basic_auth_header, curl_json
from aptl_techvault.evidence.techvault_telemetry_stimulus import (
    emit_missing_agent_events,
)

_CORTEX_REGISTRATION = "aptl.collector.cortex-enrichment"
_MISP_READINESS_REGISTRATION = "aptl.collector.misp-authenticated-api-readiness"
_WAZUH_AGENT_REGISTRATION = "aptl.collector.wazuh-agent-readiness"
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


class TechVaultNativeEvidenceOwner(TechVaultNativeCortexMixin):
    """Own the bounded native operations behind the TechVault sources."""

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
        self._thehive_url = published_url(realization, "thehive", 9000, "https")
        self._thehive_ca_path = generated_output_path(
            realization,
            project_dir,
            "techvault:soc-certificate-profile/v1",
            "ca-certificate",
        )
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
            **self._misp_readiness_source(),
            _WAZUH_AGENT_REGISTRATION: WazuhAgentReadinessSource(
                self.wazuh_agent_readiness_query,
                tuple(declared_endpoint_agents(self._realization)),
            ),
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

    def _misp_readiness_source(self) -> dict[str, object]:
        """Bind the MISP source only when the plan admits a state to compare.

        Without admitted values there is nothing to compare an observation
        with, so no source is offered at all and the demand reports itself
        uncovered -- rather than a source that would accept whatever it saw.
        """

        admitted = admitted_misp_state(self._realization)
        if admitted is None:
            return {}
        return {
            _MISP_READINESS_REGISTRATION: MispAuthenticatedApiReadinessSource(
                self.misp_readiness_query, admitted
            )
        }

    def misp_readiness_query(
        self, _start_iso: str, _end_iso: str
    ) -> Mapping[str, object] | None:
        """Observe MISP, its database and its cache through the admitted plan."""

        return misp_readiness(self._backend, self._realization)

    def wazuh_agent_readiness_query(
        self, start_iso: str, end_iso: str
    ) -> Mapping[str, object] | None:
        """Correlate each declared endpoint agent with the manager's roster."""

        observed = self._observe_agent_readiness(start_iso, end_iso)
        return self._refresh_agent_telemetry(observed, start_iso, end_iso)

    def _observe_agent_readiness(
        self, start_iso: str, end_iso: str
    ) -> Mapping[str, object] | None:
        """Read the manager roster using the admitted scenario identities."""

        return wazuh_agent_readiness(
            getattr(self._backend, "container_exec_with_input", None),
            self._realization,
            self._project_dir,
            start_iso,
            end_iso,
        )

    def _refresh_agent_telemetry(
        self,
        observed: Mapping[str, object] | None,
        start_iso: str,
        end_iso: str,
    ) -> Mapping[str, object] | None:
        """Stimulate only stale declared hosts, then await native freshness."""

        if observed is None:
            return None
        hosts = observed.get("hosts", ())
        missing = [
            str(host["node_ref"])
            for host in hosts
            if isinstance(host, Mapping) and host.get("telemetry_fresh") is False
        ]
        deadline = self._agent_refresh_deadline(missing, end_iso)
        if deadline is None:
            return observed
        sleep = self._sleep or time.sleep
        for _attempt in range(30):
            if datetime.fromisoformat(self._now().replace("Z", "+00:00")) >= deadline:
                break
            sleep(2.0)
            observed = self._observe_agent_readiness(start_iso, end_iso)
            if observed is None or self._all_agent_telemetry_fresh(observed):
                break
        return observed

    def _agent_refresh_deadline(
        self, missing: list[str], end_iso: str
    ) -> datetime | None:
        """Start bounded re-observation only after real stimulus was emitted."""

        if not missing or not self._emit_missing_agent_events(missing):
            return None
        try:
            return datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _emit_missing_agent_events(self, missing: list[str]) -> bool:
        """Trigger real source activity for stale admitted endpoint agents."""

        declared = {
            node: sources
            for node, (_enrollment, sources) in declared_endpoint_agents(
                self._realization
            ).items()
        }
        try:
            return emit_missing_agent_events(
                self._backend, self._realization, missing, declared, self.trigger_sqli
            )
        except Exception:
            return False

    @staticmethod
    def _all_agent_telemetry_fresh(observed: Mapping[str, object]) -> bool:
        """Require every corroborated host to carry a fresh telemetry marker."""

        return all(
            isinstance(host, Mapping) and host.get("telemetry_fresh") is True
            for host in observed.get("hosts", ())
        )

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
