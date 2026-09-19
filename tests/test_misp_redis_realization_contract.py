"""Issue #912: consume MISP/Redis's released contract without post-start repair."""

from __future__ import annotations

from types import SimpleNamespace
from importlib.metadata import version
from pathlib import Path
import re

import pytest
from raes.parser import parse_sdl_file

from aptl.core.deployment._misp_cache_credential import (
    MISP_CACHE_CONFIG_OUTPUT,
    MISP_CACHE_PASSWORD_OUTPUT,
    realize_misp_cache_credential,
)
from aptl.core.deployment._misp_server_tls import (
    MISP_SERVER_TLS_MOUNT_DESTINATION,
    realize_misp_server_tls,
)
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactOutput,
    DeploymentGeneratedArtifactRealization,
)
from aptl.core.soc_ca import derive_soc_service_certs
from tests.helpers import techvault_scenario_path
from tests.test_env_pack_realization import _realize_pack

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _enum(value: object) -> object:
    return getattr(value, "value", value)


# --------------------------------------------------------------------------
# The released pack is what unblocks this issue; assert what it now authors.
# --------------------------------------------------------------------------


def test_released_pack_authors_the_misp_and_cache_contract(tmp_path: Path) -> None:
    """6.1.0 closes OpenRAE/env-packs#280, which is this issue's release gate."""

    assert version("raes-env-packs") == "6.1.0"
    scenario = parse_sdl_file(techvault_scenario_path(tmp_path))

    application = scenario.nodes["misp"].runtime.platform_applications[0]
    bindings = {
        binding.binding_id: (binding.target_node_ref, binding.target_service_ref)
        for binding in application.upstream_bindings
    }
    assert bindings["misp-relational-store"] == ("misp-db", "mysql")
    assert bindings["misp-cache-store"] == ("misp-redis", "redis")

    settings = {setting.setting_id: setting.value for setting in application.settings}
    assert settings["misp-canonical-url"] == "https://misp.techvault.local"

    cache = scenario.nodes["misp-redis"].runtime
    datastore = cache.datastore_services[0]
    assert datastore.authorization_ref == "misp-redis-authorization"
    authorization = cache.app_authorizations[0]
    assert authorization.auth_enabled is True
    # The pack requires authentication without choosing the bytes: the
    # credential is explicitly value-free, which is what makes generating it a
    # legitimate backend choice rather than an invented one.
    principal = authorization.principals[0]
    assert _enum(principal.credential_classification) == "redacted"

    listener = scenario.nodes["misp"].runtime.service_listeners[0]
    assert listener.readiness.probe == "misp-authenticated-api-operation"
    assert "authenticated" in listener.readiness.criteria.lower()


# --------------------------------------------------------------------------
# What APTL selects under that contract.
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def realization(tmp_path_factory):
    return _realize_pack(tmp_path_factory.mktemp("misp-realization"))


def test_the_cache_is_authenticated_without_putting_the_secret_in_argv(realization):
    """The credential reaches the server through a file, never the command."""

    cache = next(node for node in realization.nodes if node.name == "misp-redis")
    command = list(cache.runtime.container.command)

    assert command == ["redis-server", "/run/aptl-redis/redis.conf"]
    assert list(cache.runtime.container.entrypoint) == [
        "/bin/sh",
        "-ec",
        "install -d -m 0755 -o root -g root /run/aptl-redis && "
        "install -m 0400 -o redis -g redis /etc/redis/redis.conf "
        '/run/aptl-redis/redis.conf && exec docker-entrypoint.sh "$@"',
        "--",
    ]
    assert "/tmp/" not in " ".join(cache.runtime.container.entrypoint)
    # `--requirepass <value>` would work, and would also publish the credential
    # in the container's command line and in `docker inspect`.
    assert "--requirepass" not in command

    artifact = next(
        item
        for item in realization.generated_artifacts
        if item.name == "misp-cache-credential"
    )
    consumer = artifact.consumers[0]
    assert consumer.node_name == "misp-redis"
    assert consumer.access_mode == "read_only"
    assert consumer.selected_outputs == (MISP_CACHE_CONFIG_OUTPUT,)

    password = next(
        output
        for output in artifact.outputs
        if output.name == MISP_CACHE_PASSWORD_OUTPUT
    )
    # Producer-private means no consumer can bind it: MISP receives the value
    # through environment delivery instead.
    assert password.disposition == "producer_private"
    delivery = artifact.environment_consumers[0]
    assert delivery.node_name == "misp"
    assert delivery.environment_variable == "REDIS_PASSWORD"


def test_misp_receives_the_authored_identity_not_a_backend_default(realization):
    """BASE_URL comes from the authored setting, not from `localhost`."""

    misp = next(node for node in realization.nodes if node.name == "misp")
    environment = {item.name: item for item in misp.runtime.environment}

    assert environment["BASE_URL"].value == "https://misp.techvault.local"
    assert environment["REDIS_HOST"].value == "misp-redis"
    # The generated cache credential is bound by reference and carries no value
    # in the plan.
    assert environment["REDIS_PASSWORD"].value == ""
    assert _enum(environment["REDIS_PASSWORD"].value_classification) == "redacted"
    # The operator supplies the admin key; it is never a fixture.
    assert _enum(environment["ADMIN_KEY"].value_classification) == "operator_secret"
    assert environment["ADMIN_KEY"].value == ""


def test_the_leaf_is_delivered_where_the_selected_image_reads_it(realization):
    """A mounted certificate the image never reads is not an activated one."""

    artifact = next(
        item
        for item in realization.generated_artifacts
        if item.name == "misp-server-tls"
    )
    consumer = artifact.consumers[0]

    assert consumer.node_name == "misp"
    assert consumer.mount_destination == MISP_SERVER_TLS_MOUNT_DESTINATION
    assert consumer.access_mode == "read_only"
    assert sorted(output.path for output in artifact.outputs) == ["cert.pem", "key.pem"]
    # The pack produces the material; this delivery must not run before it.
    # The reference is canonicalized to the realized address at merge, because
    # stateful validation, cycle detection and execution all compare exact
    # addresses -- the SDL shorthand the profile writes would pass execution
    # ordering and then be rejected by preflight.
    assert artifact.ordering_dependencies == (
        "provision.generated-artifact.techvault-soc-certificates",
    )
    # The pack's own neutral delivery is untouched and still authoritative.
    bundle = next(
        item
        for item in realization.generated_artifacts
        if item.name == "techvault-soc-certificates"
    )
    misp_consumer = next(item for item in bundle.consumers if item.node_name == "misp")
    assert misp_consumer.mount_destination == "/opt/techvault/soc-certs"


def test_the_certificate_covers_the_authored_host(realization):
    """A lab CA is useless if the leaf omits the name consumers are told to use."""

    from aptl.core.deployment._authored_service_hosts import authored_service_hosts

    hosts = authored_service_hosts(realization)
    assert "misp.techvault.local" in hosts["misp"]

    certs = derive_soc_service_certs(("lab-ca.pem", "misp/server.pem"), hosts)
    misp = next(cert for cert in certs if cert.name == "misp")
    assert "misp.techvault.local" in misp.sans
    assert "misp" in misp.sans


def test_unrelated_https_settings_do_not_expand_certificate_identity():
    """A webhook or documentation URL is not the node's service identity."""

    from aptl.core.deployment._authored_service_hosts import authored_service_hosts

    setting = SimpleNamespace(
        setting_id="incident-webhook-url",
        value="https://collector.example.invalid/hook",
    )
    runtime = SimpleNamespace(
        platform_applications=(SimpleNamespace(settings=(setting,)),)
    )
    realization = SimpleNamespace(
        nodes=(SimpleNamespace(name="misp", runtime=runtime),)
    )

    assert authored_service_hosts(realization) == {}


# --------------------------------------------------------------------------
# The producers.
# --------------------------------------------------------------------------


def _cache_artifact() -> DeploymentGeneratedArtifactRealization:
    return DeploymentGeneratedArtifactRealization(
        address="backend.generated-artifact.misp-cache-credential",
        name="misp-cache-credential",
        generator="rendered_config",
        lifecycle="reuse_valid",
        provenance="techvault:misp-cache-credential/v2",
        outputs=(
            DeploymentGeneratedArtifactOutput(
                name=MISP_CACHE_PASSWORD_OUTPUT,
                path="cache-password",
                sensitivity="secret",
                disposition="producer_private",
            ),
            DeploymentGeneratedArtifactOutput(
                name=MISP_CACHE_CONFIG_OUTPUT,
                path="redis.conf",
                sensitivity="secret",
            ),
        ),
        consumers=(),
    )


def _cache_paths(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / ".aptl/realization/misp-cache-credential"
    return root / "cache-password", root / "redis.conf"


def _cache_acl_token(config_file: Path) -> str | None:
    """Inspect the ACL shape without exposing a generated credential on failure."""

    match = re.fullmatch(
        r"user default reset on >([A-Za-z0-9_-]{43,128}) "
        r"~\* \+@read \+@write \+@connection \+@transaction -@dangerous\n"
        r"appendonly no\nmaxmemory-policy noeviction\n",
        config_file.read_text(encoding="utf-8"),
    )
    return match.group(1) if match else None


def test_the_cache_credential_is_generated_owner_only_and_reused(tmp_path):
    assert realize_misp_cache_credential(_cache_artifact(), tmp_path) is None
    password_file, config_file = _cache_paths(tmp_path)

    password = password_file.read_text(encoding="utf-8").strip()
    assert password
    credential_matches = _cache_acl_token(config_file) == password
    assert credential_matches
    assert password_file.stat().st_mode & 0o777 == 0o600
    assert config_file.stat().st_mode & 0o777 == 0o600
    # Redis parses its config by whitespace, so a credential with a space in it
    # would silently change the directive rather than the value.
    assert not any(character.isspace() for character in password)

    assert realize_misp_cache_credential(_cache_artifact(), tmp_path) is None
    assert password_file.read_text(encoding="utf-8").strip() == password


def test_a_drifted_cache_config_is_regenerated_rather_than_reused(tmp_path):
    """Two ends authenticating with different values is worse than neither."""

    assert realize_misp_cache_credential(_cache_artifact(), tmp_path) is None
    password_file, config_file = _cache_paths(tmp_path)
    original = password_file.read_text(encoding="utf-8").strip()
    config_file.write_text("requirepass something-else\n", encoding="utf-8")

    assert realize_misp_cache_credential(_cache_artifact(), tmp_path) is None

    regenerated = password_file.read_text(encoding="utf-8").strip()
    assert regenerated != original
    credential_matches = _cache_acl_token(config_file) == regenerated
    assert credential_matches


def test_a_symlinked_cache_output_is_never_reused(tmp_path):
    assert realize_misp_cache_credential(_cache_artifact(), tmp_path) is None
    password_file, _config_file = _cache_paths(tmp_path)
    outside = tmp_path / "outside-password"
    outside.write_text(password_file.read_text(encoding="utf-8"), encoding="utf-8")
    password_file.unlink()
    password_file.symlink_to(outside)

    assert realize_misp_cache_credential(_cache_artifact(), tmp_path) is not None


def test_a_cache_artifact_off_its_contract_is_refused(tmp_path):
    artifact = DeploymentGeneratedArtifactRealization(
        **{**_cache_artifact().__dict__, "lifecycle": "replace"}
    )
    assert realize_misp_cache_credential(artifact, tmp_path) is not None


def _tls_artifact() -> DeploymentGeneratedArtifactRealization:
    return DeploymentGeneratedArtifactRealization(
        address="backend.generated-artifact.misp-server-tls",
        name="misp-server-tls",
        generator="rendered_config",
        lifecycle="reuse_valid",
        provenance="techvault:misp-server-tls/v1",
        outputs=(
            DeploymentGeneratedArtifactOutput(
                name="server-certificate", path="cert.pem", sensitivity="public"
            ),
            DeploymentGeneratedArtifactOutput(
                name="server-private-key", path="key.pem", sensitivity="secret"
            ),
        ),
        consumers=(),
    )


def _stage_bundle(tmp_path: Path, certificate: str, key: str) -> None:
    bundle = tmp_path / "config/soc_certs/misp"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "server.pem").write_text(certificate, encoding="utf-8")
    (bundle / "server.key").write_text(key, encoding="utf-8")


def test_the_leaf_is_staged_under_the_names_the_image_reads(tmp_path):
    _stage_bundle(tmp_path, "CERTIFICATE\n", "PRIVATE KEY\n")

    assert realize_misp_server_tls(_tls_artifact(), tmp_path) is None

    root = tmp_path / ".aptl/realization/misp-server-tls"
    assert (root / "cert.pem").read_text(encoding="utf-8") == "CERTIFICATE\n"
    assert (root / "key.pem").read_text(encoding="utf-8") == "PRIVATE KEY\n"
    assert (root / "key.pem").stat().st_mode & 0o777 == 0o600


def test_a_rotated_leaf_replaces_the_staged_copy(tmp_path):
    """A stale copy would keep serving a certificate the bundle has retired."""

    _stage_bundle(tmp_path, "FIRST\n", "FIRST KEY\n")
    assert realize_misp_server_tls(_tls_artifact(), tmp_path) is None
    _stage_bundle(tmp_path, "SECOND\n", "SECOND KEY\n")

    assert realize_misp_server_tls(_tls_artifact(), tmp_path) is None

    root = tmp_path / ".aptl/realization/misp-server-tls"
    assert (root / "cert.pem").read_text(encoding="utf-8") == "SECOND\n"


def test_a_missing_bundle_fails_closed_rather_than_staging_nothing(tmp_path):
    assert realize_misp_server_tls(_tls_artifact(), tmp_path) is not None


def test_a_symlinked_bundle_leaf_is_not_staged(tmp_path):
    _stage_bundle(tmp_path, "CERTIFICATE\n", "PRIVATE KEY\n")
    key = tmp_path / "config/soc_certs/misp/server.key"
    outside = tmp_path / "outside-key"
    outside.write_text("PRIVATE KEY\n", encoding="utf-8")
    key.unlink()
    key.symlink_to(outside)

    assert realize_misp_server_tls(_tls_artifact(), tmp_path) is not None


# --------------------------------------------------------------------------
# The mutation is gone.
# --------------------------------------------------------------------------


def test_no_post_realization_misp_or_cache_repair_script_survives():
    """The obsolete container-recreating path is absent from the installed assets."""

    assert not (PROJECT_ROOT / "scripts" / "envpack-soar-fixups.sh").exists()
    seed = (PROJECT_ROOT / "scripts" / "seed-prime.sh").read_text(encoding="utf-8")
    assert "envpack-soar-fixups.sh" not in seed


# --------------------------------------------------------------------------
# Producers must run in dependency order, not address order.
# --------------------------------------------------------------------------


def test_the_leaf_is_staged_after_the_bundle_that_produces_it(tmp_path, monkeypatch):
    """The whole prerequisite pass, not the producer in isolation.

    The realization spec sorts artifacts by address, and
    `backend.generated-artifact.misp-server-tls` sorts before
    `provision.generated-artifact.techvault-soc-certificates`. Iterating that
    order stages the leaf before the bundle exists, so a fresh realization root
    fails at startup. Only running the real pass catches that.
    """

    from aptl.core.deployment.docker_compose import DockerComposeBackend

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    order: list[str] = []

    def _record(_self, artifact, scenario_root, realization):
        order.append(artifact.name)
        if artifact.name == "misp-server-tls":
            bundle = scenario_root / "config/soc_certs/misp"
            assert bundle.is_dir(), "leaf staged before its producer ran"
        elif artifact.name == "techvault-soc-certificates":
            target = scenario_root / "config/soc_certs/misp"
            target.mkdir(parents=True, exist_ok=True)
            (target / "server.pem").write_text("CERT\n", encoding="utf-8")
            (target / "server.key").write_text("KEY\n", encoding="utf-8")
        return None

    monkeypatch.setattr(
        DockerComposeBackend, "_realize_one_generated_artifact", _record
    )
    realization = _ordering_spec()

    assert backend._realize_stateful_prerequisites(realization, tmp_path) is None
    assert order.index("techvault-soc-certificates") < order.index("misp-server-tls")


def _ordering_spec():
    from aptl.core.deployment.realization import DeploymentRealizationSpec

    def artifact(address, name, deps=()):
        return DeploymentGeneratedArtifactRealization(
            address=address,
            name=name,
            generator="certificate_bundle"
            if "certificates" in name
            else "rendered_config",
            lifecycle="reuse_valid",
            provenance="techvault:soc-certificate-profile/v1",
            outputs=(),
            consumers=(),
            ordering_dependencies=deps,
        )

    return DeploymentRealizationSpec(
        profiles=(),
        nodes=(),
        networks=(),
        generated_artifacts=(
            artifact(
                "backend.generated-artifact.misp-server-tls",
                "misp-server-tls",
                ("provision.generated-artifact.techvault-soc-certificates",),
            ),
            artifact(
                "provision.generated-artifact.techvault-soc-certificates",
                "techvault-soc-certificates",
            ),
        ),
    )


@pytest.mark.integration
def test_stateful_preflight_accepts_the_delivery_dependency(tmp_path):
    """Execution ordering is not the only thing that reads the dependency.

    `stateful_realization_errors` validates every ordering reference against
    exact realized addresses *before* any artifact runs, so a reference that
    only the execution-time resolver understands stops the Compose pipeline at
    preflight and never reaches the ordering this test's sibling covers.
    """

    from aptl.core.deployment._compose_stateful_graph import stateful_realization_errors

    realization = _realize_pack(tmp_path)
    delivery = next(
        item
        for item in realization.generated_artifacts
        if item.name == "misp-server-tls"
    )
    addresses = {item.address for item in realization.generated_artifacts}

    assert set(delivery.ordering_dependencies) <= addresses
    spec = realization.deployment_spec(sorted(realization.profiles))
    assert stateful_realization_errors(spec, local_artifacts=True) == []
