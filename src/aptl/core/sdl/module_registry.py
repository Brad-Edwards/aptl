"""Registry-aware SDL module resolution and publishing."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import Field, ValidationError, model_validator

from aptl.core.sdl._base import SDLModel
from aptl.core.sdl._errors import SDLParseError
from aptl.core.sdl.scenario import ImportDecl, ModuleDescriptor, Scenario

LOCKFILE_NAME = "aptl.lock.json"
TRUST_POLICY_NAME = "aptl-trust.yaml"
OCI_LAYOUT_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.aptl.module.config.v1+json"
OCI_BUNDLE_MEDIA_TYPE = "application/vnd.aptl.module.bundle.v1+tar+gzip"
LOCKFILE_SCHEMA_VERSION = "aptl-lock/v1"
TRUST_POLICY_SCHEMA_VERSION = "aptl-trust/v1"
OCI_LAYOUT_SCHEMA_VERSION = "aptl-module-oci/v1"


def _sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _descriptor_digest(exports: dict[str, list[str]]) -> str:
    return _sha256_digest(
        json.dumps(exports, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _normalize_exact_or_range(version: str) -> SpecifierSet | None:
    value = (version or "*").strip()
    if value in {"", "*"}:
        return None
    if any(token in value for token in "<>!=~"):
        return SpecifierSet(value)
    return SpecifierSet(f"=={value}")


def _satisfies_version(actual: str, requested: str) -> bool:
    spec = _normalize_exact_or_range(requested)
    if spec is None:
        return True
    try:
        version = Version(actual)
    except InvalidVersion:
        return actual == requested
    return version in spec


class RegistryTrustPolicy(SDLModel):
    require_signatures: bool = True
    trusted_signers: dict[str, str] = Field(default_factory=dict)
    allow_insecure_http: bool = False


class TrustPolicy(SDLModel):
    schema_version: str = TRUST_POLICY_SCHEMA_VERSION
    allow_unsigned_local_sources: bool = True
    registries: dict[str, RegistryTrustPolicy] = Field(default_factory=dict)


class LockRecord(SDLModel):
    source: str
    namespace: str
    requested_version: str = "*"
    resolved_source: str
    module_id: str
    module_version: str
    manifest_digest: str
    content_digest: str
    export_hash: str
    signer_id: str = ""


class Lockfile(SDLModel):
    schema_version: str = LOCKFILE_SCHEMA_VERSION
    imports: list[LockRecord] = Field(default_factory=list)


@dataclass(frozen=True)
class ResolvedModule:
    import_decl: ImportDecl
    module_descriptor: ModuleDescriptor
    root_file: Path
    resolved_source: str
    manifest_digest: str = ""
    content_digest: str = ""
    export_hash: str = ""
    signer_id: str = ""


def _scenario_module_descriptor(scenario: Scenario, *, source_id: str) -> ModuleDescriptor:
    if scenario.module is not None:
        return scenario.module
    normalized_source_id = source_id.replace("\\", "/")
    if "/" not in normalized_source_id:
        normalized_source_id = f"local/{normalized_source_id}"
    return ModuleDescriptor(
        id=normalized_source_id,
        version=scenario.version,
        parameters=sorted(scenario.variables.keys()),
        exports={
            section: sorted(getattr(scenario, section).keys())
            for section in (
                "nodes",
                "infrastructure",
                "features",
                "conditions",
                "vulnerabilities",
                "metrics",
                "evaluations",
                "tlos",
                "goals",
                "entities",
                "injects",
                "events",
                "scripts",
                "stories",
                "content",
                "accounts",
                "relationships",
                "agents",
                "objectives",
                "workflows",
            )
            if getattr(scenario, section)
        },
        description=scenario.description,
    )


def load_trust_policy(base_dir: Path) -> TrustPolicy:
    path = base_dir / TRUST_POLICY_NAME
    if not path.exists():
        return TrustPolicy()
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return TrustPolicy.model_validate(payload)


def load_lockfile(base_dir: Path) -> Lockfile | None:
    path = base_dir / LOCKFILE_NAME
    if not path.exists():
        return None
    return Lockfile.model_validate_json(path.read_text(encoding="utf-8"))


def write_lockfile(base_dir: Path, lockfile: Lockfile) -> Path:
    path = base_dir / LOCKFILE_NAME
    path.write_text(
        json.dumps(lockfile.model_dump(mode="python"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _public_key_bytes(encoded_key: str) -> bytes:
    try:
        return base64.b64decode(encoded_key.encode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive
        raise SDLParseError(f"Invalid trusted signer public key: {exc}") from exc


def _signable_payload(
    module_descriptor: ModuleDescriptor,
    *,
    content_digest: str,
) -> bytes:
    return json.dumps(
        {
            "module_id": module_descriptor.id,
            "module_version": module_descriptor.version,
            "exports": module_descriptor.exports,
            "content_digest": content_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _verify_signatures(
    *,
    signatures: list[dict[str, str]],
    trust_policy: RegistryTrustPolicy,
    module_descriptor: ModuleDescriptor,
    content_digest: str,
) -> str:
    payload = _signable_payload(module_descriptor, content_digest=content_digest)
    for signature_entry in signatures:
        signer_id = str(signature_entry.get("signer_id", ""))
        signature_b64 = str(signature_entry.get("signature", ""))
        public_key = trust_policy.trusted_signers.get(signer_id)
        if not signer_id or not signature_b64 or not public_key:
            continue
        try:
            key = Ed25519PublicKey.from_public_bytes(_public_key_bytes(public_key))
            key.verify(base64.b64decode(signature_b64.encode("utf-8")), payload)
            return signer_id
        except (InvalidSignature, ValueError):
            continue
    raise SDLParseError("No valid trusted signer signature found for OCI module")


def _parse_oci_source(source: str) -> tuple[str, str]:
    ref = source.removeprefix("oci:")
    if "://" in ref:
        ref = ref.split("://", 1)[1]
    if "/" not in ref:
        raise SDLParseError(f"Invalid OCI source '{source}'")
    registry, repository = ref.split("/", 1)
    if not registry or not repository:
        raise SDLParseError(f"Invalid OCI source '{source}'")
    return registry, repository


def _registry_base_url(registry: str, *, allow_insecure_http: bool) -> str:
    if registry.startswith("http://") or registry.startswith("https://"):
        return registry.rstrip("/")
    if allow_insecure_http or registry.startswith(("localhost:", "127.0.0.1:", "localhost/", "127.0.0.1/")):
        return f"http://{registry}".rstrip("/")
    return f"https://{registry}".rstrip("/")


def _json_request(url: str, *, headers: dict[str, str] | None = None) -> Any:
    request = Request(url, headers=headers or {})
    try:
        with urlopen(request) as response:  # noqa: S310 - explicit OCI fetch
            return json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, json.JSONDecodeError) as exc:
        raise SDLParseError(f"Failed to fetch OCI metadata from {url}: {exc}") from exc


def _bytes_request(url: str, *, headers: dict[str, str] | None = None) -> bytes:
    request = Request(url, headers=headers or {})
    try:
        with urlopen(request) as response:  # noqa: S310 - explicit OCI fetch
            return response.read()
    except (HTTPError, URLError) as exc:
        raise SDLParseError(f"Failed to fetch OCI blob from {url}: {exc}") from exc


def _select_tag(tags: list[str], requested_version: str) -> str:
    spec = _normalize_exact_or_range(requested_version)
    if spec is None:
        versions = []
        for tag in tags:
            try:
                versions.append((Version(tag), tag))
            except InvalidVersion:
                continue
        if versions:
            return max(versions)[1]
        if tags:
            return sorted(tags)[-1]
        raise SDLParseError("OCI module has no published tags")
    matching: list[tuple[Version, str]] = []
    for tag in tags:
        try:
            version = Version(tag)
        except InvalidVersion:
            continue
        if version in spec:
            matching.append((version, tag))
    if matching:
        return max(matching)[1]
    raise SDLParseError(
        f"No OCI module tag satisfies requested version '{requested_version}'"
    )


def _oci_cache_dir(base_dir: Path) -> Path:
    return base_dir / ".aptl" / "module-cache"


def _extract_bundle_to_cache(
    *,
    bundle_bytes: bytes,
    manifest_digest: str,
    root_file: str,
    base_dir: Path,
) -> Path:
    cache_dir = _oci_cache_dir(base_dir) / manifest_digest
    root_path = cache_dir / root_file
    if root_path.exists():
        return root_path
    cache_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(bundle_bytes), mode="r:gz") as tar:
        try:
            tar.extractall(cache_dir, filter="data")
        except TypeError:  # pragma: no cover - Python < 3.12 fallback
            tar.extractall(cache_dir)
    if not root_path.exists():
        raise SDLParseError(
            f"Resolved OCI module bundle is missing declared root file '{root_file}'"
        )
    return root_path


def _lock_record_for(lockfile: Lockfile | None, import_decl: ImportDecl) -> LockRecord | None:
    if lockfile is None:
        return None
    for record in lockfile.imports:
        if (
            record.source == import_decl.normalized_source
            and record.namespace == import_decl.namespace
            and record.requested_version == (import_decl.version or "*")
        ):
            return record
    return None


def _verify_allowed_parameters(
    import_decl: ImportDecl,
    descriptor: ModuleDescriptor,
) -> None:
    allowed = set(descriptor.parameters)
    disallowed = sorted(name for name in import_decl.parameters if name not in allowed)
    if disallowed:
        raise SDLParseError(
            f"Import parameters not allowed by module '{descriptor.id}': "
            + ", ".join(disallowed)
        )


def _validate_digest_pin(actual_digest: str, expected_digest: str, *, source: str) -> None:
    if not expected_digest:
        return
    normalized_actual = actual_digest.removeprefix("sha256:")
    normalized_expected = expected_digest.removeprefix("sha256:")
    if normalized_actual != normalized_expected:
        raise SDLParseError(
            f"Digest mismatch for import '{source}': {expected_digest!r} != {actual_digest!r}"
        )


def resolve_import(
    import_decl: ImportDecl,
    *,
    base_dir: Path,
    lockfile: Lockfile | None = None,
    trust_policy: TrustPolicy | None = None,
) -> ResolvedModule:
    trust_policy = trust_policy or TrustPolicy()
    source = import_decl.normalized_source
    if source.startswith("locked:"):
        locked_ref = source.removeprefix("locked:")
        if lockfile is None:
            raise SDLParseError(
                f"Locked import '{source}' requires {LOCKFILE_NAME}"
            )
        record = next(
            (
                candidate
                for candidate in lockfile.imports
                if candidate.resolved_source == locked_ref or candidate.source == locked_ref
            ),
            None,
        )
        if record is None:
            raise SDLParseError(
                f"Locked import '{source}' is not present in {LOCKFILE_NAME}"
            )
        delegated = ImportDecl(
            source=record.source,
            namespace=import_decl.namespace or record.namespace,
            version=record.requested_version,
            parameters=dict(import_decl.parameters),
            digest=import_decl.digest or record.content_digest,
        )
        return resolve_import(
            delegated,
            base_dir=base_dir,
            lockfile=lockfile,
            trust_policy=trust_policy,
        )
    if source.startswith("local:"):
        relative = source.removeprefix("local:")
        import_path = (base_dir / relative).resolve()
        if not import_path.exists():
            raise SDLParseError(f"Imported SDL file not found: {relative}")
        from aptl.core.sdl.parser import _load_normalized_data

        imported_raw = _load_normalized_data(
            import_path.read_text(encoding="utf-8"),
            path=import_path,
        )
        imported_scenario = Scenario.model_validate(imported_raw)
        descriptor = _scenario_module_descriptor(
            imported_scenario,
            source_id=relative.replace("\\", "/"),
        )
        content_digest = f"sha256:{_sha256_digest(import_path.read_bytes())}"
        if not _satisfies_version(descriptor.version, import_decl.version):
            raise SDLParseError(
                f"Import '{relative}' requested version {import_decl.version!r} "
                f"but module declares {descriptor.version!r}"
            )
        if not trust_policy.allow_unsigned_local_sources:
            raise SDLParseError(
                "Local SDL imports are disabled by trust policy because unsigned local "
                "sources are not allowed"
            )
        _validate_digest_pin(content_digest, import_decl.digest, source=source)
        locked = _lock_record_for(lockfile, import_decl)
        if locked is not None and locked.content_digest:
            _validate_digest_pin(content_digest, locked.content_digest, source=source)
        _verify_allowed_parameters(import_decl, descriptor)
        return ResolvedModule(
            import_decl=import_decl,
            module_descriptor=descriptor,
            root_file=import_path,
            resolved_source=str(import_path),
            content_digest=content_digest,
            export_hash=_descriptor_digest(descriptor.exports),
        )

    if not source.startswith("oci:"):
        raise SDLParseError(f"Unsupported import source '{source}'")

    registry, repository = _parse_oci_source(source)
    registry_policy = trust_policy.registries.get(registry)
    if registry_policy is None:
        raise SDLParseError(f"Registry '{registry}' is not allowed by trust policy")
    base_url = _registry_base_url(
        registry,
        allow_insecure_http=registry_policy.allow_insecure_http,
    )
    locked = _lock_record_for(lockfile, import_decl)
    manifest_ref = locked.manifest_digest if locked is not None else None
    if manifest_ref is None:
        tags_payload = _json_request(
            f"{base_url}/v2/{quote(repository, safe='/')}/tags/list"
        )
        tags = list(tags_payload.get("tags") or [])
        manifest_ref = _select_tag(tags, import_decl.version)
    manifest_bytes = _bytes_request(
        f"{base_url}/v2/{quote(repository, safe='/')}/manifests/{quote(str(manifest_ref), safe=':@/')}",
        headers={"Accept": OCI_LAYOUT_MEDIA_TYPE},
    )
    manifest_digest = f"sha256:{_sha256_digest(manifest_bytes)}"
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    if locked is not None and locked.manifest_digest != manifest_digest:
        raise SDLParseError(
            f"Lockfile digest mismatch for import '{source}': "
            f"{locked.manifest_digest!r} != {manifest_digest!r}"
        )
    config = manifest.get("config", {})
    layer = next(
        (
            candidate
            for candidate in manifest.get("layers", [])
            if candidate.get("mediaType") == OCI_BUNDLE_MEDIA_TYPE
        ),
        None,
    )
    if not config or not layer:
        raise SDLParseError(f"OCI module '{source}' is missing config or bundle layer")
    config_digest = str(config.get("digest", ""))
    layer_digest = str(layer.get("digest", ""))
    config_payload = json.loads(
        _bytes_request(
            f"{base_url}/v2/{quote(repository, safe='/')}/blobs/{quote(config_digest, safe=':@/')}"
        ).decode("utf-8")
    )
    bundle_bytes = _bytes_request(
        f"{base_url}/v2/{quote(repository, safe='/')}/blobs/{quote(layer_digest, safe=':@/')}"
    )
    if f"sha256:{_sha256_digest(bundle_bytes)}" != layer_digest:
        raise SDLParseError(f"OCI module '{source}' bundle digest verification failed")
    try:
        descriptor = ModuleDescriptor.model_validate(config_payload.get("module", {}))
    except ValidationError as exc:
        raise SDLParseError(f"OCI module '{source}' has invalid module descriptor: {exc}") from exc
    if locked is not None and locked.module_id != descriptor.id:
        raise SDLParseError(
            f"Lockfile module id mismatch for import '{source}': "
            f"{locked.module_id!r} != {descriptor.id!r}"
        )
    if not _satisfies_version(descriptor.version, import_decl.version):
        raise SDLParseError(
            f"OCI import '{source}' requested version {import_decl.version!r} "
            f"but resolved module declares {descriptor.version!r}"
        )
    content_digest = layer_digest
    _validate_digest_pin(content_digest, import_decl.digest, source=source)
    signer_id = ""
    if registry_policy.require_signatures:
        signer_id = _verify_signatures(
            signatures=list(config_payload.get("signatures", [])),
            trust_policy=registry_policy,
            module_descriptor=descriptor,
            content_digest=content_digest,
        )
    root_file = str(config_payload.get("root_file", "module.yaml"))
    resolved_root = _extract_bundle_to_cache(
        bundle_bytes=bundle_bytes,
        manifest_digest=manifest_digest.replace("sha256:", ""),
        root_file=root_file,
        base_dir=base_dir,
    )
    _verify_allowed_parameters(import_decl, descriptor)
    export_hash = _descriptor_digest(descriptor.exports)
    if locked is not None and locked.export_hash != export_hash:
        raise SDLParseError(
            f"Lockfile export hash mismatch for import '{source}'"
        )
    return ResolvedModule(
        import_decl=import_decl,
        module_descriptor=descriptor,
        root_file=resolved_root,
        resolved_source=f"{registry}/{repository}@{manifest_digest}",
        manifest_digest=manifest_digest,
        content_digest=content_digest,
        export_hash=export_hash,
        signer_id=signer_id,
    )


def resolve_lock_records(
    root_path: Path,
    *,
    trust_policy: TrustPolicy | None = None,
) -> Lockfile:
    from aptl.core.sdl.parser import _load_normalized_data

    trust_policy = trust_policy or load_trust_policy(root_path.parent)
    root_data = _load_normalized_data(root_path.read_text(encoding="utf-8"), path=root_path)
    imports = [ImportDecl.model_validate(item) for item in root_data.get("imports", [])]
    records: list[LockRecord] = []
    for import_decl in imports:
        resolved = resolve_import(
            import_decl,
            base_dir=root_path.parent,
            trust_policy=trust_policy,
        )
        records.append(
            LockRecord(
                source=import_decl.normalized_source,
                namespace=import_decl.namespace or resolved.module_descriptor.id.split("/")[-1],
                requested_version=import_decl.version or "*",
                resolved_source=resolved.resolved_source,
                module_id=resolved.module_descriptor.id,
                module_version=resolved.module_descriptor.version,
                manifest_digest=resolved.manifest_digest,
                content_digest=resolved.content_digest,
                export_hash=resolved.export_hash,
                signer_id=resolved.signer_id,
            )
        )
    return Lockfile(imports=records)


def _collect_local_bundle_files(
    root_path: Path,
    *,
    seen: set[Path] | None = None,
) -> dict[Path, bytes]:
    from aptl.core.sdl.parser import _load_normalized_data

    seen = set() if seen is None else set(seen)
    resolved = root_path.resolve()
    if resolved in seen:
        raise SDLParseError(f"Import cycle detected at {resolved}")
    seen.add(resolved)
    payload = _load_normalized_data(root_path.read_text(encoding="utf-8"), path=root_path)
    files = {resolved: root_path.read_bytes()}
    for raw_import in payload.get("imports", []):
        import_decl = ImportDecl.model_validate(raw_import)
        source = import_decl.normalized_source
        if not source.startswith("local:"):
            raise SDLParseError(
                "Publishing modules with remote OCI imports is not supported; "
                "publish a self-contained local module graph"
            )
        child_path = (resolved.parent / source.removeprefix("local:")).resolve()
        files.update(_collect_local_bundle_files(child_path, seen=seen))
    return files


def publish_module_to_oci_layout(
    root_path: Path,
    *,
    output_dir: Path,
    signer_id: str = "",
    private_key_path: Path | None = None,
) -> dict[str, Any]:
    from aptl.core.sdl.parser import parse_sdl_file

    scenario = parse_sdl_file(root_path, skip_semantic_validation=True)
    descriptor = _scenario_module_descriptor(
        scenario,
        source_id=str(root_path.name),
    )
    files = _collect_local_bundle_files(root_path)
    relative_files = {
        path.relative_to(root_path.parent).as_posix(): content
        for path, content in files.items()
    }
    bundle_buffer = io.BytesIO()
    with tarfile.open(fileobj=bundle_buffer, mode="w:gz") as tar:
        for relative_name, content in sorted(relative_files.items()):
            info = tarfile.TarInfo(name=relative_name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    bundle_bytes = bundle_buffer.getvalue()
    content_digest = f"sha256:{_sha256_digest(bundle_bytes)}"
    signatures: list[dict[str, str]] = []
    if signer_id and private_key_path is not None:
        private_key = serialization.load_pem_private_key(
            private_key_path.read_bytes(),
            password=None,
        )
        if not isinstance(private_key, Ed25519PrivateKey):
            raise SDLParseError("Publishing key must be an Ed25519 private key")
        signature = private_key.sign(
            _signable_payload(descriptor, content_digest=content_digest)
        )
        signatures.append(
            {
                "signer_id": signer_id,
                "signature": base64.b64encode(signature).decode("utf-8"),
            }
        )
    config_payload = {
        "schema_version": OCI_LAYOUT_SCHEMA_VERSION,
        "root_file": root_path.name,
        "module": descriptor.model_dump(mode="python", by_alias=True),
        "signatures": signatures,
    }
    config_bytes = json.dumps(
        config_payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    config_digest = f"sha256:{_sha256_digest(config_bytes)}"
    manifest_payload = {
        "schemaVersion": 2,
        "mediaType": OCI_LAYOUT_MEDIA_TYPE,
        "config": {
            "mediaType": OCI_CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": len(config_bytes),
        },
        "layers": [
            {
                "mediaType": OCI_BUNDLE_MEDIA_TYPE,
                "digest": content_digest,
                "size": len(bundle_bytes),
            }
        ],
        "annotations": {
            "org.opencontainers.image.ref.name": descriptor.version,
            "io.aptl.module.id": descriptor.id,
        },
    }
    manifest_bytes = json.dumps(
        manifest_payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    manifest_digest = f"sha256:{_sha256_digest(manifest_bytes)}"
    layout_dir = output_dir / f"{descriptor.id.replace('/', '_')}-{descriptor.version}.oci"
    blobs_dir = layout_dir / "blobs" / "sha256"
    blobs_dir.mkdir(parents=True, exist_ok=True)
    (layout_dir / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}\n', encoding="utf-8")
    (blobs_dir / config_digest.removeprefix("sha256:")).write_bytes(config_bytes)
    (blobs_dir / content_digest.removeprefix("sha256:")).write_bytes(bundle_bytes)
    (blobs_dir / manifest_digest.removeprefix("sha256:")).write_bytes(manifest_bytes)
    (layout_dir / "index.json").write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": OCI_LAYOUT_MEDIA_TYPE,
                        "digest": manifest_digest,
                        "size": len(manifest_bytes),
                        "annotations": {
                            "org.opencontainers.image.ref.name": descriptor.version,
                            "io.aptl.module.id": descriptor.id,
                        },
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "layout_dir": str(layout_dir),
        "module_id": descriptor.id,
        "module_version": descriptor.version,
        "manifest_digest": manifest_digest,
        "content_digest": content_digest,
        "export_hash": _descriptor_digest(descriptor.exports),
        "signer_id": signer_id,
    }
