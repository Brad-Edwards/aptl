"""Backend-observed service-health helpers for realization (issue #578).

``compose up -d`` only proves containers were created, so realization waits until
every container is running and every container that defines a healthcheck reports
healthy. These pin that state machine, including the fail-fast and timeout paths.
"""

from __future__ import annotations

import pytest

from aptl.core.deployment._compose_service_health import (
    container_health,
    container_running,
    container_settled,
    container_completed_one_shot,
    unhealthy_container_reasons,
    wait_for_realized_health,
)


def _info(running=True, health=None, platform="linux", *, status=None, exit_code=0, restart="unless-stopped"):
    state = {"Running": running}
    if status is not None:
        state["Status"] = status
        state["ExitCode"] = exit_code
    if health is not None:
        state["Health"] = {"Status": health}
    return {
        "State": state,
        "Platform": platform,
        "HostConfig": {"RestartPolicy": {"Name": restart}},
    }


@pytest.mark.parametrize(
    "info,expected",
    [
        ({}, ""),
        ({"State": "nope"}, ""),
        (_info(), ""),
        (_info(health="healthy"), "healthy"),
        (_info(health="unhealthy"), "unhealthy"),
        (_info(health="starting"), "starting"),
    ],
)
def test_container_health(info, expected):
    assert container_health(info) == expected


@pytest.mark.parametrize(
    "info,expected",
    [({}, False), ({"State": "nope"}, False), (_info(running=False), False), (_info(), True)],
)
def test_container_running(info, expected):
    assert container_running(info) is expected


@pytest.mark.parametrize(
    "info,expected",
    [
        (_info(), True),  # running, no healthcheck
        (_info(health="healthy"), True),
        (_info(health="unhealthy"), False),
        (_info(health="starting"), False),
        (_info(running=False), False),
        ({}, False),
    ],
)
def test_container_settled(info, expected):
    assert container_settled(info) is expected


class _FakeBackend:
    def __init__(self, states):
        # states: {name: info dict or list of info dicts polled in order}
        self._states = {k: (v if isinstance(v, list) else [v]) for k, v in states.items()}
        self._calls = {k: 0 for k in states}

    def container_inspect(self, name):
        if name not in self._states:
            return {}
        seq = self._states[name]
        idx = min(self._calls[name], len(seq) - 1)
        self._calls[name] += 1
        return seq[idx]


def test_unhealthy_container_reasons_enumerates_each_failure():
    backend = _FakeBackend(
        {
            "aptl-a": _info(),  # fine
            "aptl-b": _info(running=False),  # not running
            "aptl-c": _info(health="unhealthy"),  # unhealthy
            # aptl-d absent -> never created
        }
    )
    reasons = unhealthy_container_reasons(backend, ["aptl-a", "aptl-b", "aptl-c", "aptl-d"])
    joined = " ".join(reasons)
    assert "aptl-a" not in joined
    assert "not running" in joined and "aptl-b" in joined
    assert "unhealthy" in joined and "aptl-c" in joined
    assert "was never created" in joined and "aptl-d" in joined


def test_wait_returns_empty_when_no_containers():
    assert wait_for_realized_health(_FakeBackend({}), []) == []


def test_wait_fails_fast_on_missing_container():
    # compose already returned, so an absent container is terminal, not polled.
    calls = {"n": 0}

    class _Sleep:
        def __call__(self, _):
            calls["n"] += 1

    sleep = _Sleep()
    reasons = wait_for_realized_health(
        _FakeBackend({}), ["aptl-missing"], sleep=sleep
    )
    assert reasons == ["container 'aptl-missing' was never created"]
    assert calls["n"] == 0  # never entered the poll loop


def test_wait_returns_empty_once_all_settle():
    backend = _FakeBackend({"aptl-a": _info(health="healthy"), "aptl-b": _info()})
    assert wait_for_realized_health(backend, ["aptl-a", "aptl-b"]) == []


def test_wait_times_out_with_reasons_when_never_healthy():
    # Container exists but stays "starting"; a stepped clock crosses the deadline.
    backend = _FakeBackend({"aptl-a": _info(health="starting")})
    clock = iter([0.0, 1.0, 2.0, 100.0, 200.0, 300.0])

    reasons = wait_for_realized_health(
        backend,
        ["aptl-a"],
        timeout=10,
        interval=1,
        time_source=lambda: next(clock),
        sleep=lambda _: None,
    )
    assert reasons
    assert "aptl-a" in " ".join(reasons)
    assert "not 'healthy'" in " ".join(reasons)


def _one_shot(*, status="exited", exit_code=0, restart="no"):
    return _info(running=False, status=status, exit_code=exit_code, restart=restart)


def test_completed_one_shot_is_settled():
    """A run-to-completion container (restart no, exit 0) is settled, not down.

    The Cortex index initializer creates its index and exits by design. Before
    this, the health wait treated its exited container as "not running" and never
    succeeded -- forcing the admitted-plan retry on every single boot.
    """
    info = _one_shot()
    assert container_completed_one_shot(info) is True
    assert container_settled(info) is True


def test_a_service_that_exited_is_not_a_completed_one_shot():
    """A stay-up service that exited is a real failure, exit code notwithstanding."""
    info = _info(running=False, status="exited", exit_code=0, restart="unless-stopped")
    assert container_completed_one_shot(info) is False
    assert container_settled(info) is False


def test_a_one_shot_that_errored_is_not_settled():
    """A one-shot that exited non-zero failed its job."""
    info = _one_shot(exit_code=1)
    assert container_completed_one_shot(info) is False
    assert container_settled(info) is False


def test_unhealthy_reasons_skips_a_completed_one_shot():
    """A completed one-shot must not appear as a health failure reason."""
    from aptl.core.deployment._compose_service_health import unhealthy_container_reasons

    class _Backend:
        def container_inspect(self, name):
            if name == "aptl-cortex-index-init":
                return _one_shot()
            return _info(running=True)

    reasons = unhealthy_container_reasons(
        _Backend(), ["aptl-cortex-index-init", "aptl-wazuh-manager"]
    )
    assert reasons == []
