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
then refuse the daemon modes that cannot run the posture (rootless,
userns-remap), and fail closed on anything else. There is deliberately no fallback to the
retired privileged recipe: a fallback would make the realized security posture
a silent function of the operator's Docker version.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aptl.core.deployment._compose_substrate_gate import (
    SUBSTRATE_MIN_DOCKER_ENGINE,
    compose_services_requesting_writable_cgroups,
    require_rootful_daemon,
    require_substrate_daemon_support,
)
from aptl.core.deployment.errors import BackendSeedError


_ROOTFUL = '["name=apparmor","name=seccomp,profile=builtin","name=cgroupns"]'


def _runner(
    *, cgroup_version="2", engine_version="29.5.0", security_options=_ROOTFUL, fail=()
):
    """A fake list-form `_run` answering the gate's three probes.

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
        if "SecurityOptions" in joined:
            if "security" in fail:
                return MagicMock(returncode=1, stdout="", stderr="daemon unreachable")
            return MagicMock(returncode=0, stdout=f"{security_options}\n", stderr="")
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
        run = _runner(engine_version="5.0.0")
        with pytest.raises(BackendSeedError):
            require_substrate_daemon_support(run)


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
        run = _runner(cgroup_version=cgroup_version)
        with pytest.raises(BackendSeedError) as excinfo:
            require_substrate_daemon_support(run)

        assert "cgroup" in str(excinfo.value).lower()

    def test_an_engine_older_than_the_floor_is_refused(self):
        run = _runner(engine_version="27.5.1")
        with pytest.raises(BackendSeedError) as excinfo:
            require_substrate_daemon_support(run)

        # The operator needs the required version to act on the failure.
        assert "28" in str(excinfo.value)

    @pytest.mark.parametrize("probe", ["info", "version", "security"])
    def test_a_failed_probe_is_refused_not_assumed(self, probe):
        # An unanswerable question is not a yes. A probe that errors must fail
        # closed rather than fall through to the retired privileged recipe.
        run = _runner(fail=(probe,))
        with pytest.raises(BackendSeedError):
            require_substrate_daemon_support(run)

    def test_an_unparseable_engine_version_is_refused(self):
        run = _runner(engine_version="not-a-version")
        with pytest.raises(BackendSeedError):
            require_substrate_daemon_support(run)

    @pytest.mark.parametrize(
        ("security_options", "mode"),
        [
            pytest.param(
                '["name=seccomp,profile=builtin","name=rootless","name=cgroupns"]',
                "rootless",
                id="rootless",
            ),
            pytest.param(
                '["name=apparmor","name=seccomp,profile=builtin","name=userns"]',
                "userns-remap",
                id="userns-remap",
            ),
        ],
    )
    def test_an_unqualified_daemon_mode_is_refused_by_name(self, security_options, mode):
        # Both modes reject an explicit writable-cgroups request at create
        # (moby daemon/oci_linux.go). Refusing here names the cause before any
        # mutation instead of an opaque "failed to start base container".
        run = _runner(security_options=security_options)
        with pytest.raises(BackendSeedError) as excinfo:
            require_substrate_daemon_support(run)

        assert mode in str(excinfo.value)

    @pytest.mark.parametrize(
        "security_options",
        [
            pytest.param("not json", id="unparseable"),
            pytest.param('{"name": "rootless"}', id="not-a-list"),
            pytest.param("[1, 2]", id="not-strings"),
        ],
    )
    def test_malformed_security_options_are_refused(self, security_options):
        run = _runner(security_options=security_options)
        with pytest.raises(BackendSeedError):
            require_substrate_daemon_support(run)

    def test_a_daemon_reporting_no_security_options_is_not_misread_as_unqualified(
        self,
    ):
        # `{{json .SecurityOptions}}` renders a nil list as `null`.
        require_substrate_daemon_support(_runner(security_options="null"))

    def test_the_diagnostic_carries_no_raw_daemon_stderr(self):
        run = _runner(fail=("info",))
        with pytest.raises(BackendSeedError) as excinfo:
            require_substrate_daemon_support(run)

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

    def test_the_probes_run_cgroup_then_engine_then_daemon_mode(self):
        run = _runner()

        require_substrate_daemon_support(run)

        def kind(cmd):
            joined = " ".join(cmd)
            if "SecurityOptions" in joined:
                return "mode"
            return "cgroup" if "info" in cmd else "version"

        assert [kind(cmd) for cmd in run.calls] == ["cgroup", "version", "mode"]


class TestRootfulDaemonForEveryScenario:
    """Lab start refuses a rootless daemon whatever the scenario selects (#1053).

    LilRAE does not support rootless Docker, so this refusal cannot wait for a
    systemd node to need writable cgroups. It asks only the daemon-mode
    question: a scenario without systemd nodes is not newly held to the
    substrate's cgroup v2, engine and userns-remap requirements.
    """

    def test_a_rootless_daemon_is_refused_by_name(self):
        run = _runner(
            security_options='["name=seccomp,profile=builtin","name=rootless"]'
        )

        with pytest.raises(BackendSeedError) as excinfo:
            require_rootful_daemon(run)

        assert "rootless" in str(excinfo.value)

    @pytest.mark.parametrize(
        "security_options",
        [
            pytest.param(_ROOTFUL, id="rootful"),
            pytest.param('["name=seccomp,profile=builtin","name=userns"]', id="userns"),
            pytest.param("null", id="no-security-options"),
        ],
    )
    def test_only_the_daemon_mode_is_asked(self, security_options):
        run = _runner(
            cgroup_version="1",
            engine_version="20.10.0",
            security_options=security_options,
        )

        require_rootful_daemon(run)  # does not raise

        assert run.calls == [
            ["docker", "info", "--format", "{{json .SecurityOptions}}"]
        ]

    def test_an_unanswered_probe_is_refused_without_daemon_stderr(self):
        run = _runner(fail=("security",))
        with pytest.raises(BackendSeedError) as excinfo:
            require_rootful_daemon(run)

        message = str(excinfo.value)
        assert "rootful" in message
        assert "substrate" not in message
        assert "daemon unreachable" not in message


class TestComposePathSelection:
    """A Compose-managed systemd service needs the same daemon support.

    `reverse` takes the substrate's posture through Compose rather than through
    `start_base_container`, so without this selection it would reach the daemon
    ungated and an unsupported engine would surface only as Docker's opaque
    `invalid --security-opt` at create.
    """

    _COMPOSE = Path(__file__).parents[1] / "docker-compose.yml"

    def test_the_reverse_profile_requests_writable_cgroups(self):
        assert compose_services_requesting_writable_cgroups(
            [self._COMPOSE], ["reverse"]
        ) == ("reverse",)

    def test_the_default_profiles_request_nothing(self):
        from aptl.core.config import ContainerSettings

        assert (
            compose_services_requesting_writable_cgroups(
                [self._COMPOSE], ContainerSettings().enabled_profiles()
            )
            == ()
        )

    def test_an_excluded_or_unselected_service_is_not_counted(self):
        assert (
            compose_services_requesting_writable_cgroups(
                [self._COMPOSE], ["reverse"], exclude_services=["reverse"]
            )
            == ()
        )
        assert (
            compose_services_requesting_writable_cgroups(
                [self._COMPOSE], ["reverse"], only_services=["kali"]
            )
            == ()
        )

    def test_an_explicit_target_is_selected_without_its_profile(self):
        # core-F2: `docker compose up reverse` starts the profiled service even
        # when the `reverse` profile is not enabled, so it must still be gated.
        assert compose_services_requesting_writable_cgroups(
            [self._COMPOSE], ["soc"], only_services=["reverse"]
        ) == ("reverse",)

    def test_an_explicit_target_that_is_also_excluded_is_not_selected(self):
        assert (
            compose_services_requesting_writable_cgroups(
                [self._COMPOSE],
                [],
                exclude_services=["reverse"],
                only_services=["reverse"],
            )
            == ()
        )

    def test_an_unprofiled_service_is_always_selected(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  node:\n"
            "    image: example\n"
            "    security_opt: [writable-cgroups=true]\n"
        )

        assert compose_services_requesting_writable_cgroups([compose], []) == (
            "node",
        )

    def test_an_unreadable_model_names_nothing(self, tmp_path):
        broken = tmp_path / "broken.yml"
        broken.write_text("services: [unclosed\n")

        assert (
            compose_services_requesting_writable_cgroups(
                [broken, tmp_path / "missing.yml"], ["reverse"]
            )
            == ()
        )
