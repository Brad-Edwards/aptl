"""Bounded lifecycle observation for runtime-spawned containers."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import time

from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.lab_types import LabResult


def _docker_timestamp(value: object) -> datetime | None:
    """Parse a Docker RFC3339 timestamp as an aware UTC datetime."""

    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def _container_state(info: object) -> Mapping[object, object] | None:
    """Return a normalized container state mapping."""

    state = info.get("State") if isinstance(info, Mapping) else None
    return state if isinstance(state, Mapping) else None


class ComposeSpawnedChildLifecycleMixin:
    """Observe and enforce the finite lifetime of a spawned child."""

    def _enforce_spawned_child_deadline(
        self,
        container_id: str,
        info: object,
        *,
        timeout: int,
        node_address: str,
        template_id: str,
    ) -> LabResult | None:
        """Stop an over-deadline running child and prove it became terminal."""

        state, started, failure = self._initial_child_lifecycle(
            info,
            node_address=node_address,
            template_id=template_id,
        )
        if failure is None and started is not None and state is not None:
            state, failure = self._wait_for_spawned_child(
                container_id,
                state,
                deadline=started.timestamp() + timeout,
                node_address=node_address,
                template_id=template_id,
            )
        if failure is None and self._child_is_running(state):
            failure = self._termination_result(
                container_id,
                node_address=node_address,
                template_id=template_id,
            )
        return failure

    def _initial_child_lifecycle(
        self,
        info: object,
        *,
        node_address: str,
        template_id: str,
    ) -> tuple[
        Mapping[object, object] | None,
        datetime | None,
        LabResult | None,
    ]:
        """Validate the initial state and parse a running child's start time."""

        state = _container_state(info)
        started = None
        failure = None
        if state is None:
            failure = self._lifecycle_observation_failure(node_address, template_id)
        elif self._child_is_running(state):
            started = _docker_timestamp(state.get("StartedAt"))
            if started is None:
                failure = self._lifecycle_observation_failure(
                    node_address,
                    template_id,
                )
        return state, started, failure

    @staticmethod
    def _child_is_running(state: Mapping[object, object] | None) -> bool:
        """Whether an observed child state is currently running."""

        return bool(state is not None and state.get("Running") is True)

    def _termination_result(
        self,
        container_id: str,
        *,
        node_address: str,
        template_id: str,
    ) -> LabResult:
        """Terminate an overdue child and return the stable result diagnostic."""

        terminal = self._terminate_spawned_child(container_id)
        diagnostic = (
            "Spawned child exceeded lifecycle deadline for "
            if terminal
            else "Spawned child lifecycle termination failed for "
        )
        return LabResult(
            success=False,
            error=f"{diagnostic}{node_address}/{template_id}.",
        )

    def _wait_for_spawned_child(
        self,
        container_id: str,
        state: Mapping[object, object],
        *,
        deadline: float,
        node_address: str,
        template_id: str,
    ) -> tuple[Mapping[object, object] | None, LabResult | None]:
        """Observe a running child until terminal state or its deadline."""

        failure = None
        while (
            state.get("Running") is True
            and datetime.now(timezone.utc).timestamp() < deadline
        ):
            remaining = deadline - datetime.now(timezone.utc).timestamp()
            time.sleep(min(2.0, max(0.0, remaining)))
            state = _container_state(self.container_inspect(container_id))
            if state is None:
                failure = self._lifecycle_observation_failure(
                    node_address,
                    template_id,
                )
                break
        return state, failure

    def _terminate_spawned_child(self, container_id: str) -> bool:
        """Try graceful then forced termination and observe terminal state."""

        try:
            stopped = self._run(
                ["docker", "stop", "--time", "10", container_id],
                timeout=30,
            )
            if stopped.returncode != 0:
                stopped = self._run(["docker", "kill", container_id], timeout=30)
        except BackendTimeoutError:
            stopped = None
        observed_state = _container_state(self.container_inspect(container_id))
        return bool(
            stopped is not None
            and stopped.returncode == 0
            and observed_state is not None
            and observed_state.get("Running") is False
        )

    @staticmethod
    def _lifecycle_observation_failure(
        node_address: str,
        template_id: str,
    ) -> LabResult:
        """Return the stable fail-closed lifecycle observation error."""

        return LabResult(
            success=False,
            error=(
                "Spawned-child lifecycle observation failed for "
                f"{node_address}/{template_id}."
            ),
        )
