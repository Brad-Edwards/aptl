"""Built-artifact proof that a second installed pack adapter needs no core edit."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
from textwrap import dedent

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[1]


def _build_second_adapter(tmp_path: Path) -> Path:
    """Build and install a real distribution exposing all issue-980 seams."""

    if shutil.which("uv") is None:
        pytest.skip("uv is required for the installed-adapter artifact proof")
    project = tmp_path / "otherpack-adapter"
    package = project / "src" / "otherpack_adapter"
    package.mkdir(parents=True)
    (project / "pyproject.toml").write_text(
        dedent(
            """
            [build-system]
            requires = ["hatchling"]
            build-backend = "hatchling.build"

            [project]
            name = "otherpack-aptl-adapter"
            version = "1.0.0"

            [project.entry-points."aptl.scenario_startup"]
            otherpack = "otherpack_adapter:startup"

            [project.entry-points."aptl.pack_backend_interactions"]
            "otherpack.aptl" = "otherpack_adapter:serving"

            [project.entry-points."aptl.scenario_capture"]
            "otherpack.aptl" = "otherpack_adapter:capture"

            [project.entry-points."aptl.scenario_planning_compatibility"]
            "otherpack.aptl" = "otherpack_adapter:planning"

            [project.entry-points."aptl.scenario_verifiers"]
            "otherpack.aptl" = "otherpack_adapter:verifier"

            [tool.hatch.build.targets.wheel]
            packages = ["src/otherpack_adapter"]
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (package / "__init__.py").write_text(
        dedent(
            """
            from aptl.backends.identity import BackendIdentity
            from aptl.backends.pack_interaction import (
                ComponentGroupMembership,
                PackBackendInteractionResult,
            )
            from aptl.backends.scenario_capture import ScenarioCaptureContribution
            from aptl.backends.scenario_planning_compatibility import PlanningCompatibilityDecision
            from aptl.backends.scenario_startup import ScenarioStartupPlan
            from aptl.core.evidence.adapters.sources import SourceResult
            from aptl.core.evidence.outcomes import CollectorStatus
            from aptl.core.experiment.capture_registry import (
                CaptureLimits,
                CaptureVisibility,
                CollectorRegistration,
            )
            from raes_backend_protocols.capabilities import ObservationCaptureOffer
            from aptl.validation.scenario_verification import (
                QualifiedTarget,
                ScenarioIdentity,
                VerificationCheck,
                VerificationReport,
                VerificationStatus,
            )

            DIGEST = "sha256:" + "a" * 64
            BACKEND = BackendIdentity(
                "aptl", "0.1.0", "full-remote-control-plane",
                provider="docker", transport="docker",
            )
            SCENARIO = ScenarioIdentity(
                "otherpack", DIGEST, source_kind="env-pack", version="1.0.0"
            )

            class Startup:
                extension_api_version = "1"
                supported_pack_id = "otherpack"
                supported_pack_versions = ("1.0.0",)
                supported_pack_set_digests = (DIGEST,)

                @staticmethod
                def resolve(_bundle):
                    return ScenarioStartupPlan(
                        seed_script="scripts/seed.sh",
                        required_profiles=("blue-team",),
                        activation_profiles=("blue-team",),
                    )

                @staticmethod
                def realize_runtime(backend, _nodes):
                    backend.started = True
                    return []

            class Serving:
                provider_id = "otherpack-serving"
                extension_api_version = "1"
                supported_pack_id = "otherpack"
                supported_pack_versions = ("1.0.0",)
                supported_pack_set_digests = (DIGEST,)
                backend_target_name = "aptl"
                backend_target_versions = ("0.1.0",)
                backend_profiles = ("full-remote-control-plane",)
                backend_transports = ("docker", "docker-compose")

                @staticmethod
                def resolve(context):
                    return PackBackendInteractionResult(tuple(
                        ComponentGroupMembership(address, ("blue-team",))
                        for address in context.component_addresses
                    ))

            class Capture:
                provider_id = "otherpack-capture"
                extension_api_version = "1"
                supported_pack_id = "otherpack"
                supported_pack_versions = ("1.0.0",)
                supported_pack_set_digests = (DIGEST,)
                backend_target_name = "aptl"
                backend_target_versions = ("0.1.0",)
                backend_profiles = ("full-remote-control-plane",)
                backend_transports = ("docker", "docker-compose")

                @staticmethod
                def resolve(_context):
                    offer = ObservationCaptureOffer(
                        offer_id="otherpack.collector.events",
                        offer_version="1.0.0",
                        output_contract="experiment-evidence-record-v1",
                        field_selectors=frozenset({""}),
                        artifact_roles=frozenset({"service_materialization_readback"}),
                        media_types=frozenset({"application/json"}),
                        capture_kind="observation",
                        source_classes=frozenset({"native"}),
                        source_refs=frozenset({"nodes.smoke-box"}),
                        scopes=frozenset({"Exact curl package readiness."}),
                        channel_kinds=frozenset({"participant-observation"}),
                        channel_refs=frozenset(),
                        window_kinds=frozenset({"system_under_test"}),
                        integrity_modes=frozenset({"checksum"}),
                        sensitivity="plain",
                        availability="available",
                        fidelity="complete",
                        disclosure="redacted",
                        retention_policy_refs=frozenset({"run_lifetime"}),
                        export_policy="not-required",
                        redaction_policy="redact_secrets",
                        scope_refs=frozenset({"nodes.smoke-box"}),
                    )
                    registration = CollectorRegistration(
                        registration_id="otherpack.collector.events",
                        implementation_version="1.0.0",
                        contract_version="experiment-capture-spec/v1",
                        channel_kind="participant-observation",
                        capture_kind="observation",
                        capture_scope="scenario",
                        window_kinds=frozenset({"system_under_test"}),
                        media_types=frozenset({"application/json"}),
                        required_artifact_roles=frozenset({"service_materialization_readback"}),
                        supported_sensitivities=frozenset({"plain"}),
                        supports_redaction=True,
                        integrity_modes=frozenset({"checksum"}),
                        sealing_modes=frozenset({"digest"}),
                        supports_chain_of_custody=False,
                        supports_retention=True,
                        supports_loss_disclosure=True,
                        visibility_class=CaptureVisibility.EVALUATOR_ONLY,
                        limits=CaptureLimits(4096, 10, 60),
                        redaction_policies=frozenset({"redact_secrets"}),
                        retention_policies=frozenset({"run_lifetime"}),
                        capture_offer=offer,
                    )
                    return ScenarioCaptureContribution(
                        registrations=(registration,),
                        native_registration_ids=frozenset({registration.registration_id}),
                        runtime_adapter=Capture(),
                    )

                @staticmethod
                def native_sources(_request):
                    class Source:
                        @staticmethod
                        def fetch(_start, _end):
                            return SourceResult(
                                status=CollectorStatus.OK,
                                chunks=(b'{"second_pack":true}\\n',),
                                media_type="application/json",
                            )
                    return {"otherpack.collector.events": Source()}

            class Planning:
                provider_id = "otherpack-planning"
                extension_api_version = "1"
                supported_pack_id = "otherpack"
                supported_pack_versions = ("1.0.0",)
                supported_pack_set_digests = (DIGEST,)
                backend_target_name = "aptl"
                backend_target_versions = ("0.1.0",)
                backend_profiles = ("full-remote-control-plane",)
                backend_transports = ("docker", "docker-compose")

                @staticmethod
                def resolve(_context):
                    return PlanningCompatibilityDecision(runtime_max_nodes=2048)

            class Verifier:
                plugin_id = "otherpack"
                extension_api_version = "2"
                qualified_targets = (QualifiedTarget(SCENARIO, BACKEND),)

                @staticmethod
                def run(context):
                    check = VerificationCheck(
                        "otherpack-ready", VerificationStatus.PASSED
                    )
                    return VerificationReport(
                        status=VerificationStatus.PASSED,
                        scenario=context.scenario,
                        backend=context.backend,
                        run_id=context.run_id,
                        attempt_id=context.attempt_id,
                        checks=(check,),
                    )

            startup = Startup()
            serving = Serving()
            capture = Capture()
            planning = Planning()
            verifier = Verifier()
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    dist = tmp_path / "dist"
    completed = subprocess.run(
        [
            "uv",
            "build",
            "--wheel",
            "--no-build-isolation",
            "--out-dir",
            str(dist),
            str(project),
        ],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    wheel = next(dist.glob("*.whl"))
    installed = tmp_path / "installed"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(installed),
            str(wheel),
        ],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    return installed


def _write_second_pack(tmp_path: Path) -> Path:
    """Author the independent pack content consumed by production admission."""

    pack = tmp_path / "otherpack"
    sdl = pack / "sdl"
    sdl.mkdir(parents=True)
    (sdl / "otherpack.sdl.yaml").write_text(
        dedent(
            """
            name: otherpack
            description: Independent issue-980 adapter proof.
            nodes:
              smoke-box:
                type: compute
                os: linux
                runtime:
                  packages:
                    - {manager: apt, name: curl, version: "*"}
            evidence_requirements:
              package-readiness:
                description: Records bounded package readiness.
                source_refs: [nodes.smoke-box]
                scope_refs: [nodes.smoke-box]
                scope: Exact curl package readiness.
                boundary_kind: system_under_test
                channel: api_response
                media_types: [application/json]
                artifact_role: service_materialization_readback
                sensitivity: plain
                redaction: redact_secrets
                integrity: checksum
                retention: run_lifetime
                loss_disclosure: required
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (pack / "scripts").mkdir()
    (pack / "scripts" / "seed.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    return pack


@pytest.mark.integration
def test_second_installed_pack_starts_captures_plans_and_verifies(
    tmp_path: Path,
) -> None:
    """A real second distribution traverses every generic adapter boundary."""

    installed = _build_second_adapter(tmp_path)
    pack_root = _write_second_pack(tmp_path)
    script = dedent(
        """
        import os
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from aptl.backends import raes, raes_evaluator
        from aptl.backends.identity import BackendIdentity
        from aptl.backends.scenario_capture import ScenarioCaptureContext
        from aptl.backends.scenario_capture_discovery import resolve_scenario_capture
        from aptl.backends.scenario_planning_compatibility import ScenarioPlanningCompatibilityContext
        from aptl.backends.scenario_planning_compatibility_discovery import resolve_scenario_planning_compatibility
        from aptl.backends.scenario_startup import select_scenario_startup, run_scenario_runtime
        from aptl.core.config import AptlConfig
        from aptl.core.evidence.adapters.sources import SourceResult
        from aptl.core.evidence.adapters.wiring import build_collectors
        from aptl.core.evidence.outcomes import CollectorStatus
        from aptl.core.evidence.protocol import CollectorContext
        from aptl.core.evidence.outcomes import AcquisitionDisposition
        from aptl.core.lab_types import LabResult
        from aptl.core.lab import _LabStartContext, _step_acquire_required_native_evidence
        from aptl.core.runstore import LocalRunStore
        from aptl.core.scenario_bundle import PackIdentity, ScenarioBundle, ScenarioSourceKind
        from aptl.validation.scenario_verification import ScenarioIdentity, VerificationContext, VerificationStatus
        from aptl.validation.scenario_verification_discovery import verify_scenario
        from raes_contracts.runtime_state import OperationState

        digest = "sha256:" + "a" * 64
        pack = PackIdentity("otherpack", "1.0.0", digest)
        backend_identity = BackendIdentity(
            "aptl", "0.1.0", "full-remote-control-plane",
            provider="docker", transport="docker",
        )
        pack_root = Path(os.environ["OTHERPACK_ROOT"])
        bundle = ScenarioBundle(
            "otherpack", pack_root, pack_root / "sdl/otherpack.sdl.yaml",
            ScenarioSourceKind.ENV_PACK, pack,
        )

        startup = select_scenario_startup(bundle)
        config = AptlConfig(lab={"name": "otherpack"}, containers={})
        backend = MagicMock()
        backend.started = False
        backend.project_dir = Path.cwd()
        backend.bind_local_docker_socket.return_value = LabResult(success=True)
        backend.qualify_runtime_materialization.return_value = LabResult(success=True)
        backend.realize.return_value = LabResult(success=True, message="started")
        backend.container_exists.return_value = True
        backend.container_inspect.return_value = {
            "Platform": "linux",
            "State": {"Status": "running", "Running": True},
        }
        backend.host_list_lab_networks.return_value = []
        def container_exec(_container, command, **_kwargs):
            if command == ["cat", "/etc/os-release"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout='ID=debian\\nVERSION_ID="12"\\n',
                )
            if command and command[0] == "dpkg-query":
                return SimpleNamespace(
                    returncode=0, stdout="curl\\t1.0\\tamd64\\n"
                )
            return SimpleNamespace(returncode=1, stdout="")
        backend.container_exec.side_effect = container_exec
        admitted = raes.admit_raes_scenario(
            Path.cwd(), config, backend,
            bundle=bundle, startup_selection=startup,
        )
        assert admitted.capture_selection is not None
        assert [binding.registration_id for binding in admitted.capture_plan.bindings] == [
            "otherpack.collector.events"
        ]
        start_outcome = raes.start_raes_scenario(
            Path.cwd(), config, backend, admitted=admitted
        )
        assert start_outcome.lab_result.success, start_outcome.lab_result.error
        assert backend.realize.called
        assert run_scenario_runtime(pack, backend, (), selection=startup) == []
        assert backend.started is True
        assert start_outcome.selected_profiles == ["blue-team"]
        assert startup.plan.required_profiles == ("blue-team",)

        capture = resolve_scenario_capture(ScenarioCaptureContext(pack, backend_identity))
        assert capture.distribution == "otherpack-aptl-adapter"
        source = SimpleNamespace(
            fetch=lambda _start, _end: SourceResult(
                status=CollectorStatus.OK, records=[{"second_pack": True}]
            )
        )
        collector = build_collectors(
            {"otherpack.collector.events": source}, capture.registry
        )["otherpack.collector.events"]
        clock = SimpleNamespace(now=lambda: "2026-09-21T00:00:00Z")
        handle = collector.start(CollectorContext(
            "trial", "run", "attempt", SimpleNamespace(), 10.0, clock
        ))
        collector_outcome = collector.stop(handle)
        assert collector_outcome.status is CollectorStatus.OK
        assert b"second_pack" in collector_outcome.chunks[0]

        run_store = LocalRunStore(Path.cwd() / "runs")
        capture_context = _LabStartContext(
            backend=backend,
            project_dir=Path.cwd(),
            skip_seed=False,
            raw_env={},
            admitted_start=admitted,
            raes_outcome=start_outcome,
            run_store=run_store,
            run_id="second-pack-run",
        )
        assert capture_context.env is None
        raes_evaluator.refresh_evidence_truth = lambda **kwargs: SimpleNamespace(
            status=OperationState.SUCCEEDED,
            snapshot=kwargs["snapshot"],
        )
        capture_failure = _step_acquire_required_native_evidence(capture_context)
        assert capture_failure is None, capture_failure
        acquired = capture_context.native_evidence_acquisition
        assert acquired.disposition is AcquisitionDisposition.SEALED_READY
        assert len(acquired.records) == 1
        assert (
            run_store.get_run_path("second-pack-run")
            / f"evidence/capture-plans/{admitted.capture_plan.plan_id}.json"
        ).read_bytes() == admitted.capture_plan.canonical_bytes

        planning = resolve_scenario_planning_compatibility(
            ScenarioPlanningCompatibilityContext(pack, backend_identity)
        )
        assert planning.decision.runtime_max_nodes == 2048
        report = verify_scenario(VerificationContext(
            run_id="run",
            attempt_id="attempt",
            scenario=ScenarioIdentity(
                "otherpack", digest, source_kind="env-pack", version="1.0.0"
            ),
            backend=backend_identity,
        ))
        assert report.status is VerificationStatus.PASSED, report.diagnostics
        assert report.distribution == "otherpack-aptl-adapter"
        """
    )
    env = os.environ.copy()
    source_root = str(_REPO_ROOT / "src")
    env["PYTHONPATH"] = os.pathsep.join(
        (str(installed), source_root, env.get("PYTHONPATH", ""))
    )
    env["OTHERPACK_ROOT"] = str(pack_root)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
