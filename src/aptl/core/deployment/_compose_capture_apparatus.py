"""Compose realization for scope-admitted evidence-capture apparatus."""

from __future__ import annotations

import json
import re
import shlex
import time
from collections.abc import Sequence
from pathlib import Path

import yaml

from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment._compose_capture_config import (
    KALI_CAPTURE_CONTAINER,
    KALI_CAPTURE_SERVICE,
    KALI_CAPTURE_VOLUME,
    KALI_CONTAINER,
    KALI_TRANSCRIPT_REGISTRATION,
    capture_compose_file,
    capture_credential_paths as _capture_credential_paths,
    capture_declaration_error as _capture_declaration_error,
    capture_requested as _capture_requested,
)
from aptl.core.lab_types import LabResult

_SAFE_ID = re.compile(r"^\w[\w.-]*$", flags=re.ASCII)
_TARGET_INGRESS_UNAVAILABLE = "aptl.capture-apparatus.target-ingress-unavailable"


def _canonical_capabilities(values: object) -> set[str]:
    """Normalize Docker/Compose capability spellings to Linux ``CAP_*`` form."""

    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return set()
    return {
        value if value.startswith("CAP_") else f"CAP_{value}"
        for value in values
        if isinstance(value, str) and value
    }


_BROKER_PATH = "/usr/local/bin/broker.py"
_KALI_INGRESS_RELOCATION = """
set -eu
umask 077
test -f /home/kali/.ssh/authorized_keys
grep -qxF -- {pivot_public_key} /home/kali/.ssh/authorized_keys || \
    printf '%s\n' {pivot_public_key} >> /home/kali/.ssh/authorized_keys
chown kali:kali /home/kali/.ssh/authorized_keys
chmod 0600 /home/kali/.ssh/authorized_keys
install -d -m 0755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-aptl-capture-broker.conf <<'EOF'
Port 2222
ListenAddress 127.0.0.1:2222
EOF
sshd -t
systemctl restart ssh
systemctl is-active --quiet ssh
sshd -T | grep -Fx 'port 2222'
sshd -T | grep -Fx 'listenaddress 127.0.0.1:2222'
""".strip()


def _safe_capture_id(value: str) -> bool:
    """Return whether an authority id is a single safe broker path segment."""

    return ".." not in value and _SAFE_ID.fullmatch(value) is not None


def _valid_expected_session_ids(values: tuple[str, ...]) -> bool:
    """Return whether a bounded expected-session census is broker-safe."""

    return bool(
        len(values) <= 2048
        and all(isinstance(value, str) and _safe_capture_id(value) for value in values)
        and len(values) == len(set(values))
    )


class ComposeCaptureApparatusMixin:
    """Add the exact admitted capture sidecar to a realization file set."""

    def _capture_apparatus_preflight(
        self, realization: DeploymentRealizationSpec, scenario_root: Path
    ) -> LabResult | None:
        """Validate capture ownership, target ingress, and credential sources."""

        error = _capture_declaration_error(realization)
        if error is None and _capture_requested(realization):
            try:
                error = self._capture_preflight_error(realization, scenario_root)
            except (OSError, TypeError, KeyError, ValueError, yaml.YAMLError):
                error = "aptl.capture-apparatus.config-unavailable"
        return LabResult(success=False, error=error) if error is not None else None

    def _capture_preflight_error(
        self, realization: DeploymentRealizationSpec, scenario_root: Path
    ) -> str | None:
        """Return a stable error after validating capture-specific resources."""

        image_addresses = {item.address for item in realization.images}
        targets = [
            node
            for node in realization.nodes
            if node.name == "kali"
            and node.container_name == KALI_CONTAINER
            and node.address not in image_addresses
        ]
        if len(targets) != 1:
            return _TARGET_INGRESS_UNAVAILABLE
        _capture_credential_paths(
            realization,
            self.realization_root,
            require_files=False,
        )
        source = scenario_root / "docker-compose.yml"
        model = (
            yaml.safe_load(source.read_text(encoding="utf-8"))
            if source.exists()
            else {}
        )
        services = model.get("services") or {}
        volumes = model.get("volumes") or {}
        collision = KALI_CAPTURE_SERVICE in services or KALI_CAPTURE_VOLUME in volumes
        return "aptl.capture-apparatus.ownership-conflict" if collision else None

    def _with_capture_apparatus_files(
        self,
        files: tuple[Path, ...],
        realization: DeploymentRealizationSpec,
    ) -> tuple[Path, ...]:
        if not _capture_requested(realization):
            return files
        apparatus = capture_compose_file(
            self._project_dir,
            realization,
            self.realization_root,
        )
        return files if apparatus in files else (*files, apparatus)

    def _prepare_capture_target(
        self, realization: DeploymentRealizationSpec
    ) -> LabResult | None:
        """Move Kali's native sshd behind the admitted sidecar-owned broker."""

        if not _capture_requested(realization):
            return None
        targets = [
            node
            for node in realization.nodes
            if node.name == "kali" and node.container_name == KALI_CONTAINER
        ]
        if len(targets) != 1:
            return LabResult(success=False, error=_TARGET_INGRESS_UNAVAILABLE)
        succeeded = self._relocate_capture_target(realization)
        return (
            None
            if succeeded
            else LabResult(success=False, error=_TARGET_INGRESS_UNAVAILABLE)
        )

    def _relocate_capture_target(self, realization: DeploymentRealizationSpec) -> bool:
        """Move Kali sshd behind the broker and return whether it became ready."""

        try:
            _sources, pivot_public = _capture_credential_paths(
                realization,
                self.realization_root,
                require_files=True,
            )
            if pivot_public.stat().st_size > 16 * 1024:
                raise ValueError("capture apparatus public key is oversized")
            public_key = pivot_public.read_text(encoding="utf-8").strip()
            if "\n" in public_key or not public_key.startswith("ssh-ed25519 "):
                raise ValueError("capture apparatus public key is invalid")
            script = _KALI_INGRESS_RELOCATION.format(
                pivot_public_key=shlex.quote(public_key)
            )
            result = self.container_exec_with_input(
                KALI_CONTAINER,
                ["sh", "-s"],
                script,
                timeout=30,
            )
        except (BackendTimeoutError, OSError, TypeError, ValueError):
            return False
        return result.returncode == 0

    def activate_capture_apparatus(
        self, *, plan_id: str, run_id: str
    ) -> dict[str, object] | None:
        """Bind the dormant broker to one admitted run, then prove it is serving."""

        if not _safe_capture_id(plan_id) or not _safe_capture_id(run_id):
            return None
        activate = [
            "python3",
            _BROKER_PATH,
            "activate",
            "--run-id",
            run_id,
            "--plan-id",
            plan_id,
            "--binding-id",
            KALI_TRANSCRIPT_REGISTRATION,
        ]
        authority = self._activate_capture_authority(activate)
        expected = {
            "run_id": run_id,
            "plan_id": plan_id,
            "binding_id": KALI_TRANSCRIPT_REGISTRATION,
        }
        return (
            authority
            if isinstance(authority, dict)
            and all(authority.get(key) == value for key, value in expected.items())
            else None
        )

    def _activate_capture_authority(
        self, activate: list[str]
    ) -> dict[str, object] | None:
        """Activate the broker and read its bounded authority after readiness."""

        authority = None
        try:
            result = self.container_exec(KALI_CAPTURE_CONTAINER, activate, timeout=30)
            status = self._ready_capture_status() if result.returncode == 0 else None
            parsed = json.loads(status.stdout) if status is not None else None
            if isinstance(parsed, dict):
                authority = parsed
        except (OSError, TypeError, ValueError):
            authority = None
        return authority

    def _ready_capture_status(self) -> object | None:
        """Poll the broker status until it reports readiness or budget expires."""

        ready = None
        for _attempt in range(30):
            status = self.container_exec(
                KALI_CAPTURE_CONTAINER,
                ["python3", _BROKER_PATH, "status"],
                timeout=5,
            )
            if status.returncode == 0:
                ready = status
                break
            time.sleep(0.2)
        return ready

    def quiesce_capture_apparatus(self) -> bool:
        """Atomically close session admission and stop every active broker."""

        try:
            result = self.container_exec(
                KALI_CAPTURE_CONTAINER,
                ["python3", _BROKER_PATH, "quiesce"],
                timeout=45,
            )
        except (OSError, TypeError, ValueError):
            return False
        return result.returncode == 0

    def export_capture_apparatus(
        self,
        *,
        expected_session_ids: Sequence[str],
    ) -> dict[str, object] | None:
        """Export only when broker custody matches the owner-supplied census."""

        expected = tuple(expected_session_ids)
        payload = (
            self._export_capture_payload()
            if _valid_expected_session_ids(expected)
            else None
        )
        accepted = payload.get("accepted_session_ids") if payload is not None else None
        reconciled = bool(
            isinstance(accepted, list)
            and all(isinstance(value, str) for value in accepted)
            and len(accepted) == len(set(accepted))
            and set(accepted) == set(expected)
        )
        return (
            {**payload, "expected_session_ids": list(expected)}
            if payload is not None and reconciled
            else None
        )

    def _export_capture_payload(self) -> dict[str, object] | None:
        """Read and decode one complete quiesced broker export."""

        payload = None
        try:
            exported = self.container_exec(
                KALI_CAPTURE_CONTAINER,
                ["python3", _BROKER_PATH, "export"],
                timeout=30,
            )
            parsed = json.loads(exported.stdout) if exported.returncode == 0 else None
            if isinstance(parsed, dict):
                payload = parsed
        except (OSError, TypeError, ValueError):
            payload = None
        return payload

    def observe_capture_apparatus(
        self, realization: DeploymentRealizationSpec
    ) -> tuple[dict[str, object], ...] | None:
        """Return native, bounded facts for every admitted apparatus resource."""

        result: tuple[dict[str, object], ...] | None = ()
        if _capture_requested(realization):
            item = realization.capture_apparatus[0]
            observation = self._capture_apparatus_observation(item)
            result = (observation,) if observation is not None else None
        return result

    def _capture_apparatus_observation(self, item: object) -> dict[str, object] | None:
        """Read and validate one exact capture sidecar from daemon state."""

        observed = self.container_inspect(item.container_name)
        kali = self.container_inspect(KALI_CONTAINER)
        if not observed or not kali:
            return None
        host = observed.get("HostConfig") or {}
        mounts = observed.get("Mounts") or []
        capture_mount = next(
            (
                mount
                for mount in mounts
                if mount.get("Destination") == "/var/log/aptl/captures"
                and mount.get("Type") == "volume"
                and mount.get("RW") is True
            ),
            None,
        )
        if not self._capture_runtime_valid(observed, kali, capture_mount):
            return None
        return {
            **item.details(),
            "image_ref": observed.get("Config", {}).get("Image"),
            "image_digest": observed.get("Image"),
            "running": True,
            "network_namespace_target": "aptl-kali",
            "pid_namespace_shared": False,
            "published_ports": [],
            "persistent_volumes": [KALI_CAPTURE_VOLUME],
            "capture_volume_access": "read_write",
            "participant_ingress": "sidecar-owned-ssh-pty-broker",
            "participant_ingress_state": "dormant-awaiting-run-binding",
            "inner_kali_ssh": "tcp://127.0.0.1:2222",
            "linux_capabilities": sorted(
                _canonical_capabilities(host.get("CapAdd"))
            ),
        }

    def _capture_runtime_valid(
        self,
        observed: dict[str, object],
        kali: dict[str, object],
        capture_mount: object,
    ) -> bool:
        """Validate ownership, isolation, mount, and privilege invariants."""

        labels = observed.get("Config", {}).get("Labels") or {}
        host = observed.get("HostConfig") or {}
        state = observed.get("State") or {}
        kali_id = kali.get("Id")
        network_mode = host.get("NetworkMode")
        namespace_modes = (
            {f"container:{kali_id}", f"container:{KALI_CONTAINER}"}
            if isinstance(kali_id, str)
            else set()
        )
        expected_add = {
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_NET_BIND_SERVICE",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SYS_CHROOT",
        }
        checks = (
            labels.get("com.docker.compose.project") == self._project_name,
            bool(state.get("Running")),
            network_mode in namespace_modes,
            host.get("PidMode") in {None, ""},
            capture_mount is not None,
            not observed.get("NetworkSettings", {}).get("Ports"),
            host.get("ReadonlyRootfs") is True,
            set(host.get("CapDrop") or ()) == {"ALL"},
            _canonical_capabilities(host.get("CapAdd")) == expected_add,
        )
        return all(checks)


__all__ = ("ComposeCaptureApparatusMixin",)
