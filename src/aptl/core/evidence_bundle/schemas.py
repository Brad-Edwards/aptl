"""Exact published RAES JSON Schemas for the canonical artifacts in a bundle.

A third party validates the bundle's canonical artifacts against the SAME schema
bytes RAES published — not an APTL-generated approximation. Schemas are read
from the installed ``raes_contracts`` corpus (``corpus_family_root(SCHEMAS)``)
with their checksums, ``$id``, and the RAES distribution version, so the bundle
is self-describing and offline-verifiable.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import metadata
from pathlib import Path

import raes_contracts.corpus as corpus

_CONTRACT_TO_FILENAME_SUFFIX = ".json"


@dataclass(frozen=True)
class SchemaArtifact:
    """One published RAES JSON Schema included in the bundle."""

    contract_id: str
    corpus_relpath: str
    schema_id: str
    raes_version: str
    digest: str
    size: int
    content: bytes

    @property
    def bundle_path(self) -> str:
        return f"schemas/{self.corpus_relpath}"


@lru_cache(maxsize=1)
def _schemas_root() -> Path:
    """Return the installed RAES corpus SCHEMAS family root (cached)."""
    return Path(corpus.corpus_family_root(corpus.SCHEMAS))


@lru_cache(maxsize=1)
def _raes_version() -> str:
    """Return the installed ``raes`` distribution version, or ``"unknown"``."""
    try:
        return metadata.version("raes")
    # ``raes`` is always installed in-tree, so this fallback is unreachable in
    # tests; it is excluded from coverage via ``[tool.coverage.report]``
    # ``exclude_also`` in pyproject.toml rather than an inline pragma (S139).
    except metadata.PackageNotFoundError:
        return "unknown"


def _contract_filename(contract_id: str) -> str:
    """Map a contract id to its schema filename (``.../v1`` -> ``...-v1.json``)."""
    return contract_id.replace("/", "-") + _CONTRACT_TO_FILENAME_SUFFIX


def resolve_schema(contract_id: str) -> SchemaArtifact | None:
    """Return the published schema for ``contract_id`` or ``None`` if absent.

    Searches the trusted installed RAES corpus (not the untrusted run tree). A
    contract with no matching published schema yields ``None``; the caller
    records a limitation rather than fabricating one.
    """
    root = _schemas_root()
    filename = _contract_filename(contract_id)
    matches = sorted(p for p in root.rglob(filename) if p.is_file())
    if not matches:
        return None
    path = matches[0]
    content = path.read_bytes()
    try:
        schema_id = json.loads(content).get("$id", "")
    except (ValueError, TypeError):
        schema_id = ""
    return SchemaArtifact(
        contract_id=contract_id,
        corpus_relpath=path.relative_to(root).as_posix(),
        schema_id=schema_id,
        raes_version=_raes_version(),
        digest=f"sha256:{hashlib.sha256(content).hexdigest()}",
        size=len(content),
        content=content,
    )


def collect_schemas(contract_ids: set[str]) -> tuple[list[SchemaArtifact], list[str]]:
    """Resolve every contract id to its published schema.

    Returns ``(schemas, unresolved_contract_ids)`` with schemas sorted by
    corpus path for deterministic ordering.
    """
    resolved: list[SchemaArtifact] = []
    unresolved: list[str] = []
    for contract_id in sorted(contract_ids):
        artifact = resolve_schema(contract_id)
        if artifact is None:
            unresolved.append(contract_id)
        else:
            resolved.append(artifact)
    resolved.sort(key=lambda a: a.corpus_relpath)
    return resolved, unresolved


__all__ = ["SchemaArtifact", "resolve_schema", "collect_schemas"]
