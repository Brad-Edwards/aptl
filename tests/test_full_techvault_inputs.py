"""Canonical package source remains independent of reduced project fixtures."""

from pathlib import Path

import pytest

from aptl.core.config import AptlConfig
from aptl.core.scenario_bundle import env_pack_bundle

ROOT = Path(__file__).resolve().parents[1]


def test_pack_reference_resolves_full_runtime_through_same_bundle(tmp_path):
    import hashlib

    from aptl.validation.curated_live_proof import expected_bundle_matrix
    from aptl.validation.participant_profile import resolve_profile_scenario
    from aptl.validation.participant_profile_models import EnvPackScenarioReference

    bundle = env_pack_bundle(tmp_path / "stage")
    reference = EnvPackScenarioReference(
        source="env-pack",
        identity=bundle.pack_identity,
        path="sdl/techvault.sdl.yaml",
        sha256=hashlib.sha256(bundle.sdl_path.read_bytes()).hexdigest(),
    )
    config = AptlConfig()
    resolved = resolve_profile_scenario(
        ROOT, config, reference, staging_root=tmp_path / "resolved"
    )
    assert resolved.pack_identity == bundle.pack_identity
    assert resolved.root != ROOT
    matrix = expected_bundle_matrix(ROOT, config, resolved)
    assert {"kali", "victim", "misp", "thehive", "shuffle-backend", "suricata"} <= set(
        matrix.expected_services
    )
    assert {"kali-ssh-proxy", "webapp-proxy", "wazuh-sidecar-db"}.isdisjoint(
        matrix.expected_services
    )
    assert "soc-workstation" in matrix.expected_services
    assert set(matrix.expected_services) == set(matrix.realized_nodes)
    bad = reference.model_copy(update={"sha256": "0" * 64})
    with pytest.raises(ValueError, match="digest"):
        resolve_profile_scenario(ROOT, config, bad, staging_root=tmp_path / "bad")


def test_generated_full_profile_covers_all_real_mcp_and_browser_surfaces(tmp_path):
    from aptl.appliance.inputs import _write_full_profile
    from aptl.core.assets import materialize
    from aptl.validation.curated_live_proof import expected_bundle_matrix
    from aptl.validation.participant_mcp_smoke import _validate_profile_binding
    from aptl.validation.participant_profile import load_participant_profile
    from aptl_techvault.participant_smoke import FULL_TECHVAULT_SMOKE_OPERATIONS

    project = tmp_path / "project"
    materialize(project)
    bundle = env_pack_bundle(tmp_path / "pack")
    matrix = expected_bundle_matrix(project, AptlConfig(), bundle)
    from aptl.workbench.profiles import profile_for

    for role in ("red", "blue"):
        for server in profile_for(role).servers:
            artifact = project / server.artifact_ref
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text("released build fixture")
    roles = {
        "scenario." + service: "sha256:" + "a" * 64
        for service in matrix.expected_services
    }
    _write_full_profile(project, bundle, matrix, roles)
    resolved = load_participant_profile(
        project, Path("participant-profiles/techvault-full-v1/profile.json")
    )
    assert resolved.scenario_bundle.pack_identity == bundle.pack_identity
    assert resolved.manifest.capabilities.workbench_profiles == ("red", "blue")
    assert len(resolved.mcp_server_ids) == 7
    assert len(resolved.browser_refs) == 6
    _validate_profile_binding(resolved, FULL_TECHVAULT_SMOKE_OPERATIONS)


def test_full_smoke_rejects_structured_backend_failures():
    import json

    from aptl_techvault.participant_smoke import _successful_json

    def result(value):
        return {"content": [{"type": "text", "text": json.dumps(value)}]}

    assert _successful_json(result([]))
    assert not _successful_json(result({"success": False}))
    assert not _successful_json(result({"error": "authentication failed"}))
    assert not _successful_json(result("service unavailable"))


def test_kali_smoke_requires_successful_command_without_fixed_numeric_uid():
    import json

    from aptl_techvault.participant_smoke import _kali_user

    def result(code, output):
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {"success": True, "output": {"code": code, "stdout": output}}
                    ),
                }
            ]
        }

    assert _kali_user(result(0, "uid=1001(kali) gid=1001(kali)"))
    assert not _kali_user(result(254, "uid=1000(kali)"))
    assert not _kali_user(result(0, "uid=0(root)"))
