"""Remote Docker target qualification for the SSH Compose provider."""

from __future__ import annotations

from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.runtime_materialization import (
    SHARED_DOCKER_PROFILE,
    RuntimeMaterializationProfile,
)
from aptl.core.lab_types import LabResult


class SSHRuntimeAuthorityMixin:
    """Bind policy to one exact empty remote Docker target."""

    @staticmethod
    def _runtime_materialization_profile(
        realization: object,
    ) -> RuntimeMaterializationProfile:
        """Return the only containment envelope this provider has proved."""

        del realization
        return SHARED_DOCKER_PROFILE

    def _qualify_runtime_materialization_target(self) -> LabResult | None:
        """Qualify the configured remote daemon before deployment mutation."""

        if self._runtime_authority_policy.target is None:
            return None
        result = self.bind_local_docker_socket()
        return None if result.success else result

    def _selected_target_failure(self) -> LabResult | None:
        """Return a failure unless policy selects this exact SSH provider."""

        target = self._runtime_authority_policy.target
        selected = (
            target is not None
            and target.provider == "ssh-compose"
            and target.ssh_host == self._host
        )
        return (
            None
            if selected
            else LabResult(
                success=False,
                error=(
                    "Runtime authority has no exact operator-selected isolated "
                    "Docker target."
                ),
            )
        )

    def _daemon_identity_failure(self, daemon_id: str | None) -> LabResult | None:
        """Return a failure unless native identity matches policy."""

        target = self._runtime_authority_policy.target
        matches = target is not None and daemon_id == target.daemon_id
        return (
            None
            if matches
            else LabResult(
                success=False,
                error="Docker control endpoint identity changed.",
            )
        )

    @staticmethod
    def _inventory_failure(
        inventories: tuple[set[str], set[str], set[str]] | None,
    ) -> LabResult | None:
        """Return a bounded failure for foreign or unavailable resources."""

        error = None
        if inventories is None:
            error = "Isolated Docker target inventory is unavailable."
        else:
            containers, volumes, networks = inventories
            if containers:
                error = (
                    "Isolated Docker target contains foreign containers; "
                    "refusing runtime authority."
                )
            elif volumes:
                error = (
                    "Isolated Docker target contains foreign volumes; refusing "
                    "runtime authority."
                )
            elif networks - {"bridge", "host", "none"}:
                error = (
                    "Isolated Docker target contains foreign networks; refusing "
                    "runtime authority."
                )
        return LabResult(success=False, error=error) if error is not None else None

    def _record_remote_target_evidence(self, daemon_id: str) -> None:
        """Record non-containment endpoint evidence after qualification."""

        self._docker_daemon_id = daemon_id
        self._remote_target_qualified = True
        self._runtime_containment_evidence = {
            "daemon_id": daemon_id,
            "provider": "ssh-compose",
            "containment_profile": "shared-docker",
            "foreign_containers": 0,
            "foreign_volumes": 0,
            "foreign_networks": 0,
        }

    def bind_local_docker_socket(self) -> LabResult:
        """Bind and inspect the exact operator-selected remote Docker target."""

        if self._remote_target_qualified:
            return self.revalidate_local_docker_socket()
        self._runtime_containment_evidence = {}
        failure = self._selected_target_failure()
        daemon_id = self._current_docker_daemon_id() if failure is None else None
        if failure is None:
            failure = self._daemon_identity_failure(daemon_id)
        if failure is None:
            failure = self._inventory_failure(self._isolated_daemon_inventory())
        if failure is None:
            assert daemon_id is not None
            self._record_remote_target_evidence(daemon_id)
        return failure or LabResult(success=True)

    def revalidate_local_docker_socket(self) -> LabResult:
        """Re-attest the policy-bound remote daemon at mutation boundaries."""

        target = self._runtime_authority_policy.target
        daemon_id = self._current_docker_daemon_id()
        valid = (
            self._remote_target_qualified
            and target is not None
            and target.ssh_host == self._host
            and daemon_id == self._docker_daemon_id
            and daemon_id == target.daemon_id
        )
        return (
            LabResult(success=True)
            if valid
            else LabResult(
                success=False,
                error="Docker control endpoint identity changed.",
            )
        )

    def _isolated_daemon_inventory(
        self,
    ) -> tuple[set[str], set[str], set[str]] | None:
        """Return bounded native resource names used to prove an empty target."""

        commands = (
            ["docker", "ps", "-aq"],
            ["docker", "volume", "ls", "-q"],
            ["docker", "network", "ls", "--format", "{{.Name}}"],
        )
        values: list[set[str]] = []
        try:
            for command in commands:
                result = self._run(command, timeout=30)
                if result.returncode != 0:
                    return None
                values.append(
                    {
                        line.strip()
                        for line in result.stdout.splitlines()
                        if line.strip()
                    }
                )
        except (BackendTimeoutError, OSError):
            return None
        return values[0], values[1], values[2]
