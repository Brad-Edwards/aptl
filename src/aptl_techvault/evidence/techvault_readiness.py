"""Adapter-owned Suricata readiness evidence for TechVault."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from aptl.core.evidence.adapters.sources import SourceResult
from aptl.core.evidence.outcomes import CollectorStatus

TECHVAULT_LOCAL_SIDS = frozenset(
    {
        1000001,
        1000002,
        1000010,
        1000011,
        1000012,
        1000020,
        1000030,
        1000031,
        1000040,
        1000050,
        1000060,
        1000061,
        1000070,
        1000080,
        1000090,
        1000091,
    }
)
_SHA256_PREFIX = "sha256:"


class SuricataRuleReadinessSource:
    """Validate native Suricata configuration and emit path-free readiness text."""

    def __init__(
        self, query: Callable[[str, str], Mapping[str, object] | None]
    ) -> None:
        """Bind the trusted native Suricata readiness query owner."""

        self._query = query

    def fetch(self, start_iso: str, end_iso: str) -> SourceResult:
        payload = self._query(start_iso, end_iso)
        if payload is None:
            return _failure(CollectorStatus.SOURCE_UNAVAILABLE)
        if not _valid_readiness_payload(payload):
            return _failure()
        digests = payload["realized_byte_digests"]
        identities = payload["content_identities"]
        lines = [
            f"image_ref={payload['image_ref']}",
            f"image_digest={payload['image_digest']}",
            "native_configuration=ok",
            "source=suricata-builtin",
            "source=techvault-local",
            *(
                f"content_identity.{key}={identities[key]}"
                for key in sorted(identities)
            ),
            *(f"content_digest.{key}={digests[key]}" for key in sorted(digests)),
            *(f"local_sid={sid}" for sid in sorted(TECHVAULT_LOCAL_SIDS)),
            f"local_rule_count={len(TECHVAULT_LOCAL_SIDS)}",
        ]
        return SourceResult(
            status=CollectorStatus.OK,
            chunks=(("\n".join(lines) + "\n").encode(),),
            media_type="text/plain",
            source_pipeline={
                "source_refs": [
                    {
                        "ref_kind": "other",
                        "ref_id": (
                            "nodes.suricata.runtime.network_detection_engines."
                            "suricata-engine.rule_sources.suricata-builtin"
                        ),
                    },
                    {
                        "ref_kind": "other",
                        "ref_id": (
                            "nodes.suricata.runtime.network_detection_engines."
                            "suricata-engine.rule_sources.techvault-local"
                        ),
                    },
                ]
            },
        )


def _failure(status: CollectorStatus = CollectorStatus.MID_RUN_LOSS) -> SourceResult:
    """Build a source result that retains no unvalidated native payload."""

    return SourceResult(status=status)


def _valid_readiness_payload(payload: Mapping[str, object]) -> bool:
    """Validate exact image, content, source, and rule identities."""

    digests = payload.get("realized_byte_digests")
    identities = payload.get("content_identities")
    sources = payload.get("selected_sources")
    sids = payload.get("local_sids")
    image_ref = payload.get("image_ref")
    image_digest = payload.get("image_digest")
    return (
        payload.get("native_configuration_ok") is True
        and isinstance(image_ref, str)
        and _sha256(image_digest)
        and image_ref.endswith(f"@{image_digest}")
        and _valid_content_identity(digests, identities)
        and _valid_rule_selection(sources, sids)
    )


def _valid_content_identity(digests: object, identities: object) -> bool:
    """Validate admitted content identities against realized byte digests."""

    required = {"suricata-config", "suricata-local-rules"}
    if not isinstance(digests, Mapping) or not isinstance(identities, Mapping):
        return False
    return (
        set(digests) == required
        and all(_sha256(value) for value in digests.values())
        and set(identities) == required
        and all(
            isinstance(value, str)
            and f"@{_SHA256_PREFIX}" in value
            and value.rsplit("@", 1)[-1] == digests.get(key)
            for key, value in identities.items()
        )
    )


def _valid_rule_selection(sources: object, sids: object) -> bool:
    """Validate exact rule-source and local-SID selections."""

    if (
        not isinstance(sources, Sequence)
        or isinstance(sources, str | bytes)
        or not isinstance(sids, Sequence)
        or isinstance(sids, str | bytes)
    ):
        return False
    return (
        set(sources) == {"suricata-builtin", "techvault-local"}
        and len(sids) == len(TECHVAULT_LOCAL_SIDS)
        and {int(value) for value in sids if isinstance(value, int | str)}
        == TECHVAULT_LOCAL_SIDS
    )


def _sha256(value: object) -> bool:
    """Validate a canonical lower-case SHA-256 identity."""

    if not isinstance(value, str) or not value.startswith(_SHA256_PREFIX):
        return False
    tail = value.removeprefix(_SHA256_PREFIX)
    return len(tail) == 64 and all(char in "0123456789abcdef" for char in tail)


__all__ = ("SuricataRuleReadinessSource", "TECHVAULT_LOCAL_SIDS")
