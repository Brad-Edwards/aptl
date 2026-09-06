"""The generic systemd substrate's target-daemon capability gate (issue #955).

The substrate's non-privileged posture depends on `--security-opt
writable-cgroups=true` (Docker Engine 28.0+, moby#48828), which clears the
read-only flag on the container's own namespace-scoped cgroup2 mount.

Two facts about that option make this gate a safety control rather than a
convenience check:

1. Docker does NOT gate it on cgroup version. On cgroup v1 a writable cgroupfs
   re-enables the `release_agent` host-code-execution escape and exposes a
   writable device controller, so requesting it before proving v2 is a
   regression -- and neither Docker nor runc will refuse it on our behalf.
   moby#49333 records this as accepted, documented-only risk upstream.
2. A daemon older than 28.0 rejects it with `invalid --security-opt 2:
   "writable-cgroups=true"` -- byte-identical in shape to its reply for any
   unknown option. That string is not a capability signal and must never be
   parsed as one.

So the gate is ORDERED and JOINED: prove cgroup v2, then prove engine support,
and fail closed on anything else. There is deliberately no fallback to the
retired privileged recipe: a fallback would make the realized security posture
a silent function of the operator's Docker version.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from aptl.core.deployment._compose_substrate_gate import (
    SUBSTRATE_MIN_DOCKER_ENGINE,
    require_substrate_daemon_support,
)
from aptl.core.deployment.errors import BackendSeedError


def _runner(*, cgroup_version="2", engine_version="29.5.0", fail=()):
    """A fake list-form `_run` answering the gate's two probes.

    Mirrors the backend's own runner contract (argv list in, completed-process
    out) so the gate stays exercised through the seam it really uses -- the
    backend's configured runner, which for an SSH backend carries the remote
    DOCKER_HOST. A local-host probe would interrogate the wrong daemon.
    """

    calls: list[list[str]] = []

    def run(cmd, **kwargs):
        del kwargs
        calls.append(list(cmd))
        joined = " ".join(cmd)
        if "info" in cmd:
            if "info" in fail:
                return MagicMock(returncode=1, stdout="", stderr="daemon unreachable")
            return MagicMock(returncode=0, stdout=f"{cgroup_version}\n", stderr="")
        if "version" in joined:
            if "version" in fail:
                return MagicMock(returncode=1, stdout="", stderr="daemon unreachable")
            return MagicMock(returncode=0, stdout=f"{engine_version}\n", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    run.calls = calls
    return run


class TestSupportedDaemon:
    def test_cgroup_v2_and_a_current_engine_pass(self):
        run = _runner()

        require_substrate_daemon_support(run)  # does not raise

    def test_the_exact_minimum_engine_is_accepted(self):
        major, minor = SUBSTRATE_MIN_DOCKER_ENGINE

        require_substrate_daemon_support(_runner(engine_version=f"{major}.{minor}.0"))

    def test_engine_version_compares_numerically_not_lexically(self):
        # "5.0.0" > "28.0.0" as strings; 5 < 28 as numbers. A string compare
        # here would admit an ancient daemon and reject a future one.
        require_substrate_daemon_support(_runner(engine_version="128.0.0"))
        with pytest.raises(BackendSeedError):
            require_substrate_daemon_support(_runner(engine_version="5.0.0"))


class TestFailsClosed:
    @pytest.mark.parametrize(
        "cgroup_version",
        [
            pytest.param("1", id="cgroup-v1"),
            pytest.param("", id="empty"),
            pytest.param("unknown", id="unparseable"),
        ],
    )
    def test_a_non_v2_daemon_is_refused(self, cgroup_version):
        with pytest.raises(BackendSeedError) as excinfo:
            require_substrate_daemon_support(_runner(cgroup_version=cgroup_version))

        assert "cgroup" in str(excinfo.value).lower()

    def test_an_engine_older_than_the_floor_is_refused(self):
        with pytest.raises(BackendSeedError) as excinfo:
            require_substrate_daemon_support(_runner(engine_version="27.5.1"))

        # The operator needs the required version to act on the failure.
        assert "28" in str(excinfo.value)

    @pytest.mark.parametrize("probe", ["info", "version"])
    def test_a_failed_probe_is_refused_not_assumed(self, probe):
        # An unanswerable question is not a yes. A probe that errors must fail
        # closed rather than fall through to the retired privileged recipe.
        with pytest.raises(BackendSeedError):
            require_substrate_daemon_support(_runner(fail=(probe,)))

    def test_an_unparseable_engine_version_is_refused(self):
        with pytest.raises(BackendSeedError):
            require_substrate_daemon_support(_runner(engine_version="not-a-version"))

    def test_the_diagnostic_carries_no_raw_daemon_stderr(self):
        with pytest.raises(BackendSeedError) as excinfo:
            require_substrate_daemon_support(_runner(fail=("info",)))

        assert "daemon unreachable" not in str(excinfo.value)


class TestOrdering:
    """cgroup v2 is proved FIRST, and a v1 daemon never reaches the engine probe.

    This is the safety property, not a style preference: `writable-cgroups=true`
    is dangerous precisely on the daemons that would otherwise reach step 2.
    """

    def test_a_v1_daemon_never_reaches_the_engine_probe(self):
        run = _runner(cgroup_version="1")

        with pytest.raises(BackendSeedError):
            require_substrate_daemon_support(run)

        assert not any("version" in " ".join(cmd) for cmd in run.calls), (
            "a cgroup v1 daemon must be refused before the engine probe runs"
        )

    def test_the_cgroup_probe_runs_before_the_engine_probe(self):
        run = _runner()

        require_substrate_daemon_support(run)

        kinds = ["info" if "info" in cmd else "version" for cmd in run.calls]
        assert kinds == ["info", "version"]
