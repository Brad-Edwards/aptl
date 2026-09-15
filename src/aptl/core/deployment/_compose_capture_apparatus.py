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
from aptl.core.deployment._compose_stateful_model import artifact_source_path
from aptl.core.deployment._ssh_key_bundle import SSH_ACCESS_PROFILE_V1
from aptl.core.lab_types import LabResult

CAPTURE_COMPOSE_FILE = "docker-compose.capture.yml"
KALI_CAPTURE_APPARATUS_ID = "aptl.apparatus.kali-session-capture"
KALI_CAPTURE_SERVICE = "kali-capture"
KALI_CAPTURE_CONTAINER = "aptl-kali-capture"
KALI_CAPTURE_VOLUME = "kali_captures"
KALI_CONTAINER = "aptl-kali"
KALI_TRANSCRIPT_REGISTRATION = "aptl.collector.redteam-session-transcript"
_SAFE_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
_CAPTURE_BIND_TARGETS = {
    "/run/aptl-source/inner_key": "kali-pivot-private-key",
    "/run/aptl-source/outer_authorized_keys": "kali-authorized-keys",
}
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


def _capture_requested(realization: DeploymentRealizationSpec) -> bool:
    return bool(realization.capture_apparatus)


def _capture_credential_paths(
    realization: DeploymentRealizationSpec,
    realization_root: Path,
    *,
    require_files: bool,
) -> tuple[dict[str, Path], Path]:
    """Resolve the exact existing Kali credentials reused by the apparatus."""

    artifacts = [
        item
        for item in realization.generated_artifacts
        if item.generator == "ssh_key_bundle"
        and item.provenance == SSH_ACCESS_PROFILE_V1
    ]
    if len(artifacts) != 1:
        raise ValueError("capture apparatus requires one TechVault SSH bundle")
    artifact = artifacts[0]
    outputs = {item.name: item for item in artifact.outputs}
    if set(_CAPTURE_BIND_TARGETS.values()) - outputs.keys():
        raise ValueError("capture apparatus credential outputs are unavailable")
    source_root = artifact_source_path(realization_root, artifact).resolve()
    root = realization_root.resolve()
    sources: dict[str, Path] = {}
    for target, output_name in _CAPTURE_BIND_TARGETS.items():
        source = (source_root / outputs[output_name].path).resolve()
        if not source.is_relative_to(root):
            raise ValueError("capture apparatus credential escaped realization root")
        if require_files and not source.is_file():
            raise ValueError("capture apparatus credential was not generated")
        sources[target] = source
    pivot_public = Path(f"{sources['/run/aptl-source/inner_key']}.pub").resolve()
    if not pivot_public.is_relative_to(root):
        raise ValueError("capture apparatus public key escaped realization root")
    if require_files and not pivot_public.is_file():
        raise ValueError("capture apparatus public key was not generated")
    return sources, pivot_public


def capture_compose_file(
    project_dir: Path,
    realization: DeploymentRealizationSpec,
    realization_root: Path,
) -> Path:
    """Write the trusted apparatus model with engine-anchored local sources."""

    root = project_dir.resolve()
    source = root / CAPTURE_COMPOSE_FILE
    model = yaml.safe_load(source.read_text(encoding="utf-8"))
    service = model["services"][KALI_CAPTURE_SERVICE]
    service["build"]["context"] = str(root)
    sources, _pivot_public = _capture_credential_paths(
        realization,
        realization_root,
        require_files=True,
    )
    for mount in service.get("volumes", ()):
        if mount.get("type") != "bind":
            continue
        path = sources.get(mount.get("target"))
        if path is None or not mount.get("read_only"):
            raise ValueError("invalid capture apparatus bind mount")
        mount["source"] = str(path)
    target = root / ".aptl" / "realization" / CAPTURE_COMPOSE_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        yaml.safe_dump(model, sort_keys=True), encoding="utf-8", newline="\n"
    )
    return target


def _capture_declaration_error(realization: DeploymentRealizationSpec) -> str | None:
    """Return a bounded error unless the immutable request is exactly supported."""

    if not _capture_requested(realization):
        return None
    if len(realization.capture_apparatus) != 1:
        return "aptl.capture-apparatus.unsupported-set"
    item = realization.capture_apparatus[0]
    if (
        item.apparatus_id != KALI_CAPTURE_APPARATUS_ID
        or item.service_name != KALI_CAPTURE_SERVICE
        or item.container_name != KALI_CAPTURE_CONTAINER
        or not item.governing_scopes
        or not item.environment_visible
    ):
        return "aptl.capture-apparatus.unsupported-declaration"
    return None


class ComposeCaptureApparatusMixin:
    """Add the exact admitted capture sidecar to a realization file set."""

    def _capture_apparatus_preflight(
        self, realization: DeploymentRealizationSpec, scenario_root: Path
    ) -> LabResult | None:
        error = _capture_declaration_error(realization)
        if error is not None:
            return LabResult(success=False, error=error)
        if not _capture_requested(realization):
            return None
        try:
            image_addresses = {item.address for item in realization.images}
            targets = [
                node
                for node in realization.nodes
                if node.name == "kali"
                and node.container_name == KALI_CONTAINER
                and node.address not in image_addresses
            ]
            if len(targets) != 1:
                return LabResult(
                    success=False,
                    error="aptl.capture-apparatus.target-ingress-unavailable",
                )
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
            if KALI_CAPTURE_SERVICE in services or KALI_CAPTURE_VOLUME in volumes:
                return LabResult(
                    success=False,
                    error="aptl.capture-apparatus.ownership-conflict",
                )
        except (OSError, TypeError, KeyError, ValueError, yaml.YAMLError):
            return LabResult(
                success=False, error="aptl.capture-apparatus.config-unavailable"
            )
        return None

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
            return LabResult(
                success=False,
                error="aptl.capture-apparatus.target-ingress-unavailable",
            )
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
        except Exception:
            return LabResult(
                success=False,
                error="aptl.capture-apparatus.target-ingress-unavailable",
            )
        if result.returncode != 0:
            return LabResult(
                success=False,
                error="aptl.capture-apparatus.target-ingress-unavailable",
            )
        return None

    def activate_capture_apparatus(
        self, *, plan_id: str, run_id: str
    ) -> dict[str, object] | None:
        """Bind the dormant broker to one admitted run, then prove it is serving."""

        if (
            _SAFE_ID.fullmatch(plan_id) is None
            or _SAFE_ID.fullmatch(run_id) is None
            or ".." in plan_id
            or ".." in run_id
        ):
            return None
        activate = [
            "python3",
            "/usr/local/bin/broker.py",
            "activate",
            "--run-id",
            run_id,
            "--plan-id",
            plan_id,
            "--binding-id",
            KALI_TRANSCRIPT_REGISTRATION,
        ]
        try:
            result = self.container_exec(KALI_CAPTURE_CONTAINER, activate, timeout=30)
            if result.returncode != 0:
                return None
            status = None
            for _attempt in range(30):
                status = self.container_exec(
                    KALI_CAPTURE_CONTAINER,
                    ["python3", "/usr/local/bin/broker.py", "status"],
                    timeout=5,
                )
                if status.returncode == 0:
                    break
                time.sleep(0.2)
            if status is None or status.returncode != 0:
                return None
            authority = json.loads(status.stdout)
        except (OSError, TypeError, ValueError):
            return None
        if not isinstance(authority, dict):
            return None
        expected = {
            "run_id": run_id,
            "plan_id": plan_id,
            "binding_id": KALI_TRANSCRIPT_REGISTRATION,
        }
        return (
            authority
            if all(authority.get(key) == value for key, value in expected.items())
            else None
        )

    def quiesce_capture_apparatus(self) -> bool:
        """Atomically close session admission and stop every active broker."""

        try:
            result = self.container_exec(
                KALI_CAPTURE_CONTAINER,
                ["python3", "/usr/local/bin/broker.py", "quiesce"],
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
        base = ["python3", "/usr/local/bin/broker.py"]
        try:
            if (
                len(expected) > 2048
                or any(
                    not isinstance(value, str)
                    or _SAFE_ID.fullmatch(value) is None
                    or ".." in value
                    for value in expected
                )
                or len(expected) != len(set(expected))
            ):
                return None
            exported = self.container_exec(
                KALI_CAPTURE_CONTAINER, [*base, "export"], timeout=30
            )
            if exported.returncode != 0:
                return None
            payload = json.loads(exported.stdout)
        except (OSError, TypeError, ValueError):
            return None
        if not isinstance(payload, dict):
            return None
        accepted = payload.get("accepted_session_ids")
        if (
            not isinstance(accepted, list)
            or any(not isinstance(value, str) for value in accepted)
            or len(accepted) != len(set(accepted))
            or set(accepted) != set(expected)
        ):
            return None
        return {**payload, "expected_session_ids": list(expected)}

    def observe_capture_apparatus(
        self, realization: DeploymentRealizationSpec
    ) -> tuple[dict[str, object], ...] | None:
        """Return native, bounded facts for every admitted apparatus resource."""

        if not _capture_requested(realization):
            return ()
        item = realization.capture_apparatus[0]
        observed = self.container_inspect(item.container_name)
        kali = self.container_inspect("aptl-kali")
        if not observed or not kali:
            return None
        labels = observed.get("Config", {}).get("Labels") or {}
        host = observed.get("HostConfig") or {}
        state = observed.get("State") or {}
        network_mode = host.get("NetworkMode")
        kali_id = kali.get("Id")
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
        if (
            labels.get("com.docker.compose.project") != self._project_name
            or not state.get("Running")
            or not isinstance(kali_id, str)
            or network_mode not in {f"container:{kali_id}", "container:aptl-kali"}
            or host.get("PidMode") not in {None, ""}
            or capture_mount is None
            or observed.get("NetworkSettings", {}).get("Ports")
            or host.get("ReadonlyRootfs") is not True
            or set(host.get("CapDrop") or ()) != {"ALL"}
            or set(host.get("CapAdd") or ())
            != {
                "CHOWN",
                "DAC_OVERRIDE",
                "NET_BIND_SERVICE",
                "SETGID",
                "SETUID",
                "SYS_CHROOT",
            }
        ):
            return None
        return (
            {
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
                "linux_capabilities": sorted(host.get("CapAdd") or ()),
            },
        )
