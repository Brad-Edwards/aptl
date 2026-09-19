"""Cortex analyzer execution and TheHive connector projection."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping

from aptl.core.evidence.adapters.techvault import (
    CORTEX_ANALYZER_ID,
    CORTEX_OBSERVABLE,
)
from aptl.core.evidence.adapters.techvault_native_support import (
    bounded,
    connector_projection,
)


class TechVaultNativeCortexMixin:
    """Provide the bounded Cortex/TheHive query owned by TechVault evidence."""

    def cortex_query(self, start_iso: str, end_iso: str) -> Mapping[str, object] | None:
        """Execute the exact analyzer and read TheHive's connector status."""

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
                ca_cert_path=self._thehive_ca_cert,
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
        """Project only evidence-contract fields from native responses."""

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


__all__ = ("TechVaultNativeCortexMixin",)
