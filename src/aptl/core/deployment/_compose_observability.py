"""Trusted backend apparatus, kept separate from authored scenario lowering."""

from __future__ import annotations

import json
import os
from pathlib import Path

import yaml

from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.env import load_dotenv, validate_required_env
from aptl.core.lab_types import LabResult
from aptl.utils.placeholders import contains_placeholder

OBSERVABILITY_COMPOSE_FILE = "docker-compose.observability.yml"
OBSERVABILITY_SERVICES = frozenset(
    {"aptl-otel-collector", "aptl-tempo", "aptl-grafana-otel"}
)
OBSERVABILITY_NETWORK = "aptl-observability"
OBSERVABILITY_VOLUMES = frozenset({"tempo_data", "grafana_otel_data"})
_OWNERSHIP_CONFLICT = "aptl.observability-ownership-conflict"


def _model_collides(model: dict) -> bool:
    services = model.get("services") or {}
    if OBSERVABILITY_SERVICES.intersection(services):
        return True
    if OBSERVABILITY_NETWORK in (model.get("networks") or {}):
        return True
    if OBSERVABILITY_VOLUMES.intersection(model.get("volumes") or {}):
        return True
    for service in services.values():
        if service.get("container_name") in OBSERVABILITY_SERVICES:
            return True
        if OBSERVABILITY_NETWORK in (service.get("networks") or {}):
            return True
        for mount in service.get("volumes") or []:
            source = (
                mount.get("source")
                if isinstance(mount, dict)
                else mount.split(":", 1)[0]
            )
            if source in OBSERVABILITY_VOLUMES:
                return True
    return False


def _spec_collides(realization: DeploymentRealizationSpec) -> bool:
    return (
        any(
            {node.name, node.service_name, node.container_name}.intersection(
                OBSERVABILITY_SERVICES
            )
            or OBSERVABILITY_NETWORK in node.networks
            for node in realization.nodes
        )
        or any(
            network.name in {OBSERVABILITY_NETWORK, "observability"}
            for network in realization.networks
        )
        or any(
            volume.name in OBSERVABILITY_VOLUMES
            for volume in realization.persistent_volumes
        )
    )


def observability_compose_file(project_dir: Path) -> Path:
    """Anchor the trusted apparatus's config mounts to the engine, never a pack.

    The canonical asset contains no secret values. The generated copy keeps
    Compose interpolation intact, using the existing explicit operator env file.
    """
    root = project_dir.resolve()
    model = yaml.safe_load(
        (root / OBSERVABILITY_COMPOSE_FILE).read_text(encoding="utf-8")
    )
    for service in model["services"].values():
        for mount in service.get("volumes", []):
            if mount["type"] != "bind":
                continue
            source = (root / mount["source"]).resolve()
            if (
                not source.is_relative_to(root)
                or not source.is_file()
                or not mount.get("read_only")
            ):
                raise ValueError("invalid backend observability config mount")
            mount["source"] = str(source)
    target = root / ".aptl" / "realization" / OBSERVABILITY_COMPOSE_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.safe_dump(model, sort_keys=True), encoding="utf-8")
    return target


class ComposeObservabilityMixin:
    """Apparatus admission and file-set integration for every realization path."""

    def _observability_preflight(
        self, realization: DeploymentRealizationSpec, scenario_root: Path
    ) -> LabResult | None:
        if "otel" not in realization.profiles:
            return None
        try:
            source = scenario_root / "docker-compose.yml"
            model = (
                yaml.safe_load(source.read_text(encoding="utf-8"))
                if source.exists()
                else {}
            )
            if _spec_collides(realization) or _model_collides(model):
                return LabResult(success=False, error=_OWNERSHIP_CONFLICT)
            env_file = self._project_dir / ".env"
            environment = load_dotenv(env_file) if env_file.exists() else {}
            environment.update(os.environ)
            password = environment.get("GRAFANA_ADMIN_PASSWORD", "")
            if validate_required_env(
                environment, ["GRAFANA_ADMIN_PASSWORD"]
            ) or contains_placeholder(password):
                return LabResult(
                    success=False, error="aptl.observability-credential-unavailable"
                )
            observability_compose_file(self._project_dir)
        except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError):
            return LabResult(
                success=False, error="aptl.observability-config-unavailable"
            )
        return None

    def _with_observability_files(
        self, files: tuple[Path, ...], profiles: tuple[str, ...] | list[str]
    ) -> tuple[Path, ...]:
        if "otel" not in profiles:
            return files
        apparatus = observability_compose_file(self._project_dir)
        return files if apparatus in files else (*files, apparatus)

    def _start_backend_observability(
        self, profiles: tuple[str, ...]
    ) -> LabResult | None:
        """Start apparatus before any source window or scenario mutation."""
        if "otel" not in profiles:
            return None
        failure = self._observability_ownership_check()
        if failure is not None:
            return failure
        files = self._with_observability_files((), profiles)
        command = self._build_command(
            "config", ["otel"], compose_files=files, scenario_root=self._project_dir
        )
        if self._compose_syntax_error(command) is not None:
            return LabResult(success=False, error="aptl.observability-config-invalid")
        result = self._start_with_compose_files(
            ["otel"], build=False, compose_files=files, scenario_root=self._project_dir
        )
        return (
            None
            if result.success
            else LabResult(success=False, error="aptl.observability-start-failed")
        )

    def _observability_ownership_check(self) -> LabResult | None:
        """Reject existing same-name foreign containers, networks AND volumes.

        Compose refuses a foreign container name but can adopt foreign named
        volumes/networks with a warning. Inventory every reserved namespace
        before the first up; an inventory failure is not proof of absence.
        """
        names_by_kind = {
            "container": OBSERVABILITY_SERVICES,
            "network": {f"{self._project_name}_{OBSERVABILITY_NETWORK}"},
            "volume": {
                f"{self._project_name}_{name}" for name in OBSERVABILITY_VOLUMES
            },
        }
        try:
            for kind, reserved in names_by_kind.items():
                command = ["docker", kind, "ls"]
                if kind == "container":
                    command.append("-a")
                command.extend(
                    ["--format", "{{.Names}}" if kind == "container" else "{{.Name}}"]
                )
                listed = self._run(command, timeout=30)
                if listed.returncode != 0:
                    raise ValueError("inventory unavailable")
                present = reserved.intersection(listed.stdout.splitlines())
                if not present:
                    continue
                inspected = self._run(
                    ["docker", "inspect", "--type", kind, *sorted(present)], timeout=30
                )
                if inspected.returncode != 0:
                    raise ValueError("inventory unavailable")
                resources = json.loads(inspected.stdout)
                if not isinstance(resources, list) or len(resources) != len(present):
                    raise ValueError("incomplete inventory")
                for resource in resources:
                    labels = (
                        resource.get("Config", {}).get("Labels")
                        if kind == "container"
                        else resource.get("Labels")
                    )
                    if (
                        not isinstance(labels, dict)
                        or labels.get("com.docker.compose.project")
                        != self._project_name
                    ):
                        return LabResult(success=False, error=_OWNERSHIP_CONFLICT)
        except (OSError, ValueError, TypeError, AttributeError, BackendTimeoutError):
            return LabResult(
                success=False, error="aptl.observability-inventory-unavailable"
            )
        return None
