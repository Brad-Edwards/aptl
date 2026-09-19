"""Durable workspace ownership for Docker/Compose native resources.

Names and Docker labels are discovery hints.  Authority comes from an
owner-only, append-only receipt for the daemon-issued native identifier, bound
to one workspace, effective project namespace, daemon, and start attempt.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import uuid4

import yaml

from aptl.core.config import validate_compose_project_name
from aptl.core.lifecycle_guard import canonical_lifecycle_project_root
from aptl.utils.pathsafe import (
    REASON_NOT_FOUND,
    PathContainmentError,
    create_exclusive_nofollow,
    listdir_contained_nofollow,
    open_dir_contained_nofollow,
    read_contained_nofollow,
)

_WORKSPACE_STATE = ".aptl/lifecycle/workspace-ownership-v1.json"
_RECEIPT_ROOT = ".aptl/lifecycle/resource-receipts-v1"
_WORKSPACE_ID = re.compile(r"^[0-9a-f]{32}$")
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/+\-=]{0,254}$")
_KINDS = frozenset({"container", "network", "volume"})
_WORKSPACE_UNAVAILABLE = "workspace ownership state is unavailable"
_RECEIPT_MALFORMED = "ownership receipt inventory is malformed"
# The path-safe create-once publisher stages bytes in this same directory before
# atomically linking the final .json name. Concurrent node materialization may
# list a staging inode while another node is publishing its receipt. The staging
# file grants no authority; only the final exact .json name is decoded below.
_RECEIPT_PUBLISH_TEMP = re.compile(
    r"^\.[0-9a-f]{64}\.json\.\d+\.\d+\.tmp(?:\.\d+)?$",
    flags=re.ASCII,
)
_OVERRIDE_UNAVAILABLE = "Compose ownership override is unavailable"


class _ComposeLoader(yaml.SafeLoader):
    """Safe YAML loader with Compose's provider-only ``!reset`` tag."""


def _compose_reset(loader: _ComposeLoader, node: yaml.Node) -> object:
    """Decode a Compose reset value without permitting arbitrary YAML types."""

    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    raise yaml.constructor.ConstructorError(
        None, None, "unsupported !reset value", node.start_mark
    )


_ComposeLoader.add_constructor("!reset", _compose_reset)


class OwnershipConflictError(RuntimeError):
    """Raised when backend ownership cannot be established unambiguously."""


@dataclass(frozen=True)
class ResourceReceipt:
    """Immutable authority record for one daemon-native resource."""

    kind: str
    native_id: str
    external_name: str
    semantic_name: str
    node_address: str
    workspace_id: str
    project_name: str
    daemon_id: str
    attempt_id: str
    managed_by: str = "direct"

    def __post_init__(self) -> None:
        values = (
            self.native_id,
            self.external_name,
            self.semantic_name,
            self.workspace_id,
            self.project_name,
            self.daemon_id,
            self.attempt_id,
        )
        if (
            self.kind not in _KINDS
            or self.managed_by not in {"direct", "compose", "child"}
            or any(not _SAFE_VALUE.fullmatch(v) for v in values)
        ):
            raise OwnershipConflictError("invalid backend ownership receipt")
        if self.node_address and not _SAFE_VALUE.fullmatch(self.node_address):
            raise OwnershipConflictError("invalid backend ownership receipt")


@dataclass(frozen=True)
class WorkspaceOwnership:
    """Stable workspace identity and its bounded provider namespace."""

    root: Path
    logical_project_name: str
    workspace_id: str
    project_name: str

    @classmethod
    def load(
        cls, project_dir: Path, logical_project_name: str
    ) -> "WorkspaceOwnership | None":
        """Load an existing workspace identity without creating project state."""

        root = canonical_lifecycle_project_root(project_dir)
        logical = validate_compose_project_name(logical_project_name)
        try:
            payload = read_contained_nofollow(root, _WORKSPACE_STATE)
        except FileNotFoundError:
            return None
        except PathContainmentError as exc:
            if exc.reason == REASON_NOT_FOUND:
                return None
            raise OwnershipConflictError(_WORKSPACE_UNAVAILABLE) from exc
        except OSError as exc:
            raise OwnershipConflictError(_WORKSPACE_UNAVAILABLE) from exc
        return cls._from_payload(root, logical, payload)

    @classmethod
    def ensure(
        cls, project_dir: Path, logical_project_name: str
    ) -> "WorkspaceOwnership":
        """Load or create the workspace identity without following links."""

        root = canonical_lifecycle_project_root(project_dir)
        root.mkdir(parents=True, exist_ok=True)
        logical = validate_compose_project_name(logical_project_name)
        existing = cls.load(root, logical)
        if existing is not None:
            return existing
        try:
            payload = _create_workspace_state(root)
        except OSError as exc:
            raise OwnershipConflictError(_WORKSPACE_UNAVAILABLE) from exc
        return cls._from_payload(root, logical, payload)

    @classmethod
    def _from_payload(
        cls, root: Path, logical: str, payload: bytes
    ) -> "WorkspaceOwnership":
        """Construct the stable effective namespace from validated state."""

        workspace_id = _decode_workspace_state(payload)
        suffix = f"-w{workspace_id[:12]}"
        effective = validate_compose_project_name(
            f"{logical[: 63 - len(suffix)]}{suffix}"
        )
        return cls(root, logical, workspace_id, effective)

    def container_name(self, semantic_name: str) -> str:
        """Return a workspace-scoped external name without changing SDL identity."""

        if not _SAFE_VALUE.fullmatch(semantic_name):
            raise OwnershipConflictError("invalid semantic container name")
        marker = f"w{self.workspace_id[:12]}"
        if semantic_name.startswith("aptl-"):
            return f"aptl-{marker}-{semantic_name[5:]}"[:255]
        return f"{marker}-{semantic_name}"[:255]

    def labels(self, *, attempt_id: str) -> dict[str, str]:
        """Return opaque backend labels used only to narrow discovery."""

        if not _SAFE_VALUE.fullmatch(attempt_id):
            raise OwnershipConflictError("invalid backend attempt identity")
        return {
            "aptl.workspace.id": self.workspace_id,
            "aptl.lifecycle.project": self.project_name,
            "aptl.attempt.id": attempt_id,
        }

    def record(self, receipt: ResourceReceipt) -> None:
        """Durably publish one immutable receipt, accepting byte-identical retry."""

        if (
            receipt.workspace_id != self.workspace_id
            or receipt.project_name != self.project_name
        ):
            raise OwnershipConflictError("ownership receipt scope mismatch")
        payload = _receipt_bytes(receipt)
        relative = self._receipt_path(receipt.kind, receipt.native_id)
        try:
            create_exclusive_nofollow(self.root, relative, payload)
        except FileExistsError:
            try:
                existing = read_contained_nofollow(self.root, relative)
            except (OSError, PathContainmentError) as exc:
                raise OwnershipConflictError(
                    "immutable ownership receipt is unavailable"
                ) from exc
            if existing != payload:
                raise OwnershipConflictError("immutable ownership receipt conflicts")
        except (OSError, PathContainmentError) as exc:
            raise OwnershipConflictError(
                "immutable ownership receipt is unavailable"
            ) from exc

    def retire_deleted_volume(self, receipt: ResourceReceipt) -> None:
        """Retire a verified receipt only after teardown proved its volume absent.

        Docker volume names are reusable native identifiers. A completed
        ``stop -v`` removes the old object, so retaining its receipt would
        make the next clean start conflict with the new attempt's identity.
        The caller must first verify native absence; this method rechecks the
        exact receipt bytes and removes only its contained file.
        """

        if (
            receipt.kind != "volume"
            or receipt.workspace_id != self.workspace_id
            or receipt.project_name != self.project_name
        ):
            raise OwnershipConflictError("volume receipt scope mismatch")
        relative = self._receipt_path("volume", receipt.native_id)
        try:
            if read_contained_nofollow(self.root, relative) != _receipt_bytes(receipt):
                raise OwnershipConflictError("immutable ownership receipt conflicts")
            directory_fd = open_dir_contained_nofollow(self.root, relative.parent)
            try:
                os.unlink(relative.name, dir_fd=directory_fd)
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except (OSError, PathContainmentError) as exc:
            raise OwnershipConflictError("volume receipt retirement failed") from exc

    def receipts(self, kind: str) -> tuple[ResourceReceipt, ...]:
        """Load all strict receipts for one native resource kind."""

        if kind not in _KINDS:
            raise OwnershipConflictError("invalid backend resource kind")
        relative_dir = f"{_RECEIPT_ROOT}/{kind}"
        try:
            names = listdir_contained_nofollow(self.root, relative_dir)
        except FileNotFoundError:
            return ()
        except PathContainmentError as exc:
            if exc.reason == REASON_NOT_FOUND:
                return ()
            raise OwnershipConflictError(
                "ownership receipt inventory is unavailable"
            ) from exc
        except OSError as exc:
            raise OwnershipConflictError(
                "ownership receipt inventory is unavailable"
            ) from exc
        receipts: list[ResourceReceipt] = []
        for name in names:
            if _RECEIPT_PUBLISH_TEMP.fullmatch(name):
                continue
            if not name.endswith(".json"):
                raise OwnershipConflictError(_RECEIPT_MALFORMED)
            try:
                payload = read_contained_nofollow(self.root, f"{relative_dir}/{name}")
                receipt = _decode_receipt(payload)
            except (OSError, ValueError, TypeError, PathContainmentError) as exc:
                raise OwnershipConflictError(_RECEIPT_MALFORMED) from exc
            if (
                receipt.kind != kind
                or receipt.workspace_id != self.workspace_id
                or receipt.project_name != self.project_name
                or self._receipt_path(kind, receipt.native_id).name != name
            ):
                raise OwnershipConflictError(_RECEIPT_MALFORMED)
            receipts.append(receipt)
        return tuple(receipts)

    def candidates(
        self, selector: str, *, kind: str, daemon_id: str
    ) -> tuple[ResourceReceipt, ...]:
        """Return selector-matching receipts only when all bind to this daemon."""

        matches = tuple(
            receipt
            for receipt in self.receipts(kind)
            if selector
            in {receipt.native_id, receipt.external_name, receipt.semantic_name}
        )
        if any(receipt.daemon_id != daemon_id for receipt in matches):
            raise OwnershipConflictError("backend daemon identity changed")
        return matches

    @staticmethod
    def new_attempt_id() -> str:
        """Return a collision-resistant fallback identity for a direct start."""

        return f"attempt-{uuid4().hex}"

    @staticmethod
    def _receipt_path(kind: str, native_id: str) -> Path:
        digest = hashlib.sha256(native_id.encode("utf-8")).hexdigest()
        return Path(_RECEIPT_ROOT) / kind / f"{digest}.json"


def write_compose_ownership_override(
    ownership: WorkspaceOwnership,
    *,
    attempt_id: str,
    compose_files: tuple[Path, ...],
) -> tuple[Path, dict[str, str], dict[str, tuple[str, ...]]]:
    """Write the final provider-only ownership override and resource plan."""

    services, networks, volumes = _merged_compose_sections(compose_files)
    if not services:
        raise OwnershipConflictError("Compose ownership model has no services")
    if any(
        "networks" not in service and "network_mode" not in service
        for service in services.values()
    ):
        networks.setdefault("default", {})

    labels = ownership.labels(attempt_id=attempt_id)
    overrides, semantic_by_service, external_by_semantic = _service_overrides(
        ownership, services, labels
    )
    _add_receipted_container_names(ownership, external_by_semantic)
    _scope_container_network_modes(services, overrides, external_by_semantic)
    network_overrides, expected_networks = _resource_overrides(
        ownership, networks, labels=labels
    )
    volume_overrides, expected_volumes = _resource_overrides(
        ownership, volumes, labels=labels
    )
    document: dict[str, object] = {
        "services": overrides,
        **({"networks": network_overrides} if network_overrides else {}),
        **({"volumes": volume_overrides} if volume_overrides else {}),
    }
    payload = yaml.safe_dump(document, sort_keys=True).encode("utf-8")
    # A bounded apply retry can add direct-container receipts before writing a
    # new override. Both versions remain immutable, but they cannot share a
    # path merely because the start attempt is the same.
    digest = hashlib.sha256(attempt_id.encode("utf-8") + payload).hexdigest()[:16]
    relative = Path(".aptl/lifecycle/compose-ownership") / f"{digest}.yml"
    _write_override_payload(ownership.root, relative, payload)
    expected = {
        "container": tuple(sorted(external_by_semantic.values())),
        "network": tuple(sorted(expected_networks)),
        "volume": tuple(sorted(expected_volumes)),
    }
    return ownership.root / relative, semantic_by_service, expected


def _service_overrides(
    ownership: WorkspaceOwnership,
    services: dict[str, dict[str, object]],
    labels: dict[str, str],
) -> tuple[dict[str, dict[str, object]], dict[str, str], dict[str, str]]:
    """Build scoped service overrides and both semantic lookup maps."""

    overrides: dict[str, dict[str, object]] = {}
    semantic_by_service: dict[str, str] = {}
    external_by_semantic: dict[str, str] = {}
    for service_name, raw_service in sorted(services.items()):
        raw_name = raw_service.get("container_name")
        semantic_name = (
            raw_name
            if isinstance(raw_name, str) and "${" not in raw_name
            else f"aptl-{service_name}"
        )
        external_name = ownership.container_name(semantic_name)
        semantic_by_service[service_name] = semantic_name
        external_by_semantic[semantic_name] = external_name
        overrides[service_name] = {
            "container_name": external_name,
            "labels": labels,
        }
    return overrides, semantic_by_service, external_by_semantic


def _add_receipted_container_names(
    ownership: WorkspaceOwnership,
    external_by_semantic: dict[str, str],
) -> None:
    """Add directly materialized containers to reference rewriting.

    A Compose-managed sidecar may join the network namespace of an image-free
    node that was started directly by the generic materializer. That node is
    absent from the final Compose file set, so its immutable ownership receipt
    is the authoritative semantic-to-external-name mapping.
    """

    for receipt in ownership.receipts("container"):
        existing = external_by_semantic.get(receipt.semantic_name)
        if existing is not None and existing != receipt.external_name:
            raise OwnershipConflictError("container semantic binding conflicts")
        external_by_semantic[receipt.semantic_name] = receipt.external_name


def _scope_container_network_modes(
    services: dict[str, dict[str, object]],
    overrides: dict[str, dict[str, object]],
    external_by_semantic: dict[str, str],
) -> None:
    """Translate ``network_mode: container:`` targets to scoped names."""

    for service_name, raw_service in services.items():
        network_mode = raw_service.get("network_mode")
        if not isinstance(network_mode, str) or not network_mode.startswith(
            "container:"
        ):
            continue
        scoped = external_by_semantic.get(network_mode.partition(":")[2])
        if scoped is not None:
            overrides[service_name]["network_mode"] = f"container:{scoped}"


def _write_override_payload(root: Path, relative: Path, payload: bytes) -> None:
    """Create one immutable override, accepting a byte-identical retry."""

    try:
        create_exclusive_nofollow(root, relative, payload)
    except FileExistsError:
        try:
            existing = read_contained_nofollow(root, relative)
        except (OSError, PathContainmentError) as exc:
            raise OwnershipConflictError(_OVERRIDE_UNAVAILABLE) from exc
        if existing != payload:
            raise OwnershipConflictError("Compose ownership override conflicts")
    except (OSError, PathContainmentError) as exc:
        raise OwnershipConflictError(_OVERRIDE_UNAVAILABLE) from exc


def _resource_overrides(
    ownership: WorkspaceOwnership,
    resources: dict[str, dict[str, object]],
    *,
    labels: dict[str, str],
) -> tuple[dict[str, dict[str, object]], set[str]]:
    """Return ownership labels and exact native names for Compose resources."""

    overrides: dict[str, dict[str, object]] = {}
    expected: set[str] = set()
    for semantic_name, definition in sorted(resources.items()):
        if definition.get("external") is True:
            raise OwnershipConflictError("external Compose resources are not ownable")
        raw_name = definition.get("name")
        external_name = (
            raw_name
            if isinstance(raw_name, str) and "${" not in raw_name
            else f"{ownership.project_name}_{semantic_name}"
        )
        if not _SAFE_VALUE.fullmatch(external_name):
            raise OwnershipConflictError("invalid Compose resource name")
        overrides[semantic_name] = {"labels": labels}
        expected.add(external_name)
    return overrides, expected


def _merged_compose_sections(
    compose_files: tuple[Path, ...],
) -> tuple[
    dict[str, dict[str, object]],
    dict[str, dict[str, object]],
    dict[str, dict[str, object]],
]:
    """Return merged service, network, and volume fragments."""

    services: dict[str, dict[str, object]] = {}
    networks: dict[str, dict[str, object]] = {}
    volumes: dict[str, dict[str, object]] = {}
    for compose_file in compose_files:
        if compose_file is None or not compose_file.is_file():
            continue
        try:
            payload = (
                yaml.load(
                    compose_file.read_text(encoding="utf-8"), Loader=_ComposeLoader
                )
                or {}
            )
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise OwnershipConflictError(
                "Compose ownership model is unreadable"
            ) from exc
        if not isinstance(payload, dict):
            continue
        _merge_compose_section(services, payload.get("services"))
        _merge_compose_section(networks, payload.get("networks"))
        _merge_compose_section(volumes, payload.get("volumes"))
    return services, networks, volumes


def _merge_compose_section(
    destination: dict[str, dict[str, object]], raw_section: object
) -> None:
    """Merge one normalized Compose mapping into the ownership view."""

    if not isinstance(raw_section, dict):
        return
    for semantic_name, raw_definition in raw_section.items():
        if not isinstance(semantic_name, str):
            continue
        definition = raw_definition if isinstance(raw_definition, dict) else {}
        destination.setdefault(semantic_name, {}).update(definition)


def _create_workspace_state(root: Path) -> bytes:
    """Create the stable workspace identity or read a concurrent winner."""

    payload = _canonical_json({"schema": 1, "workspace_id": uuid4().hex})
    try:
        create_exclusive_nofollow(root, _WORKSPACE_STATE, payload)
        return payload
    except FileExistsError:
        try:
            return read_contained_nofollow(root, _WORKSPACE_STATE)
        except (OSError, PathContainmentError) as exc:
            raise OwnershipConflictError(_WORKSPACE_UNAVAILABLE) from exc
    except (OSError, PathContainmentError) as exc:
        raise OwnershipConflictError(_WORKSPACE_UNAVAILABLE) from exc


def _decode_workspace_state(payload: bytes) -> str:
    """Decode and strictly validate one workspace identity document."""

    try:
        raw = json.loads(payload)
        workspace_id = raw["workspace_id"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise OwnershipConflictError("workspace ownership state is malformed") from exc
    if (
        raw != {"schema": 1, "workspace_id": workspace_id}
        or not isinstance(workspace_id, str)
        or not _WORKSPACE_ID.fullmatch(workspace_id)
    ):
        raise OwnershipConflictError("workspace ownership state is malformed")
    return workspace_id


def _decode_receipt(payload: bytes) -> ResourceReceipt:
    """Decode one strict immutable resource receipt."""

    raw = json.loads(payload)
    if not isinstance(raw, dict) or raw.pop("schema", None) != 1:
        raise ValueError("invalid receipt schema")
    return ResourceReceipt(**raw)


def _receipt_bytes(receipt: ResourceReceipt) -> bytes:
    """Encode one receipt in canonical durable form."""

    return _canonical_json({"schema": 1, **asdict(receipt)})


def _canonical_json(payload: dict[str, object]) -> bytes:
    """Encode deterministic newline-terminated JSON."""

    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


__all__ = [
    "OwnershipConflictError",
    "ResourceReceipt",
    "WorkspaceOwnership",
    "write_compose_ownership_override",
]
