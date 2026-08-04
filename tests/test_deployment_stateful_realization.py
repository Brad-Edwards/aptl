"""Tests for backend-owned generated artifacts and persistent volumes."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aptl.core.credentials import PathContainmentError
from aptl.core.certs import CertResult
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment._compose_stateful_realization import (
    stateful_override_payload,
    stateful_realization_errors,
    write_stateful_override,
)
from aptl.core.deployment._stateful_certificates import (
    certificate_bundle_evidence,
    validate_certificate_bundle,
)
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactOutput,
    DeploymentGeneratedArtifactRealization,
    DeploymentImageRealization,
    DeploymentNetworkAttachment,
    DeploymentNodeRealization,
    DeploymentPersistentVolumeRealization,
    DeploymentRealizationSpec,
    DeploymentServicePort,
    DeploymentStatefulConsumer,
)
from aptl.core.deployment.ssh_compose import SSHComposeBackend


def _consumer(
    *,
    node: str = "wazuh-indexer",
    service: str = "wazuh.indexer",
    destination: str = "/usr/share/wazuh-indexer/certs",
    access_mode: str = "read_only",
) -> DeploymentStatefulConsumer:
    return DeploymentStatefulConsumer(
        target_address=f"provision.node.{node}",
        node_name=node,
        service_name=service,
        mount_destination=destination,
        access_mode=access_mode,  # type: ignore[arg-type]
    )


def _spec() -> DeploymentRealizationSpec:
    artifact = DeploymentGeneratedArtifactRealization(
        address="provision.generated-artifact.wazuh-indexer-certs",
        name="wazuh-indexer-certs",
        generator="certificate_bundle",
        lifecycle="reuse_valid",
        provenance="config/certs.yml",
        outputs=(
            DeploymentGeneratedArtifactOutput(
                name="root-ca", path="root-ca.pem", sensitivity="public"
            ),
            DeploymentGeneratedArtifactOutput(
                name="indexer-key",
                path="wazuh.indexer-key.pem",
                sensitivity="secret",
            ),
        ),
        consumers=(_consumer(),),
    )
    volume = DeploymentPersistentVolumeRealization(
        address="provision.persistent-volume.wazuh-indexer-data",
        name="wazuh-indexer-data",
        lifecycle="retain",
        access_mode="read_write_once",
        consumers=(
            _consumer(
                destination="/var/lib/wazuh-indexer",
                access_mode="read_write",
            ),
        ),
        ordering_dependencies=(artifact.address,),
    )
    return DeploymentRealizationSpec(
        profiles=("wazuh",),
        nodes=(
            DeploymentNodeRealization(
                address="provision.node.wazuh-indexer",
                name="wazuh-indexer",
                service_name="wazuh.indexer",
                container_name="aptl-wazuh-indexer",
                networks=("security-net",),
                network_attachments=(
                    DeploymentNetworkAttachment(
                        network="security-net", ipv4_address="172.20.0.12"
                    ),
                ),
                services=(
                    DeploymentServicePort(
                        name="indexer-api", port=9200, protocol="tcp"
                    ),
                ),
            ),
        ),
        networks=(),
        images=(
            DeploymentImageRealization(
                address="provision.node.wazuh-indexer",
                service_name="wazuh.indexer",
                source_name="wazuh-indexer",
                source_version="4.x",
                image_ref="wazuh/wazuh-indexer:4.12.0",
                mode="pull",
                policy_rule="approved-alias",
            ),
        ),
        generated_artifacts=(artifact,),
        persistent_volumes=(volume,),
    )


def _rendered_config_spec() -> DeploymentRealizationSpec:
    artifact = DeploymentGeneratedArtifactRealization(
        address="provision.generated-artifact.wazuh-manager-config",
        name="wazuh-manager-config",
        generator="rendered_config",
        lifecycle="regenerate_on_change",
        provenance="config/wazuh_cluster/wazuh_manager.conf",
        outputs=(
            DeploymentGeneratedArtifactOutput(
                name="manager-config",
                path="wazuh_manager.conf",
                sensitivity="secret",
            ),
        ),
        consumers=(
            _consumer(
                node="wazuh-manager",
                service="wazuh.manager",
                destination="/wazuh-config-mount/etc/ossec.conf",
            ),
        ),
    )
    return DeploymentRealizationSpec(
        profiles=("wazuh",),
        nodes=(
            DeploymentNodeRealization(
                address="provision.node.wazuh-manager",
                name="wazuh-manager",
                service_name="wazuh.manager",
                container_name="aptl-wazuh-manager",
                networks=(),
            ),
        ),
        networks=(),
        generated_artifacts=(artifact,),
    )


def _certificate_outputs() -> tuple[DeploymentGeneratedArtifactOutput, ...]:
    return (
        DeploymentGeneratedArtifactOutput("root-ca", "root-ca.pem", "public"),
        DeploymentGeneratedArtifactOutput(
            "manager-root-ca", "root-ca-manager.pem", "public"
        ),
        DeploymentGeneratedArtifactOutput(
            "indexer-key", "wazuh.indexer-key.pem", "secret"
        ),
        DeploymentGeneratedArtifactOutput(
            "indexer-cert", "wazuh.indexer.pem", "public"
        ),
    )


def _effective_payload(
    tmp_path: Path, spec: DeploymentRealizationSpec
) -> dict[str, object]:
    payload = stateful_override_payload(tmp_path, "aptl-test", spec)
    volumes = payload.get("volumes", {})
    assert isinstance(volumes, dict)
    for name, definition in volumes.items():
        assert isinstance(definition, dict)
        definition["name"] = f"aptl-test_{name}"
    return payload


def _write_certificate_bundle(
    root: Path,
    *,
    leaf_key_matches: bool = True,
    san: str = "wazuh.indexer",
) -> tuple[Path, tuple[DeploymentGeneratedArtifactOutput, ...]]:
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wazuh Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert_key = leaf_key
    if not leaf_key_matches:
        cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wazuh.indexer")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(cert_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    certs_dir = root / "config/wazuh_indexer_ssl_certs"
    certs_dir.mkdir(parents=True, mode=0o700)
    pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    (certs_dir / "root-ca.pem").write_bytes(pem)
    (certs_dir / "root-ca-manager.pem").write_bytes(pem)
    (certs_dir / "wazuh.indexer.pem").write_bytes(
        leaf_cert.public_bytes(serialization.Encoding.PEM)
    )
    (certs_dir / "wazuh.indexer-key.pem").write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    for path in certs_dir.iterdir():
        path.chmod(0o644)
    config = root / "config/certs.yml"
    config.write_text(
        "nodes:\n  indexer:\n    - name: wazuh.indexer\n      ip: wazuh.indexer\n"
    )
    return certs_dir, _certificate_outputs()


def test_stateful_override_uses_contained_artifact_and_project_volume(
    tmp_path: Path,
) -> None:
    override = write_stateful_override(tmp_path, "aptl-test", _spec())

    assert override == tmp_path / ".aptl/realization/compose.stateful.yml"
    raw_override = override.read_text()
    # Wazuh is realized generically now: the stateful override carries only the
    # declared cert + volume mount merges, not a wholesale !override service
    # definition (its image/networks/env come from the generated base compose).
    assert "!override" not in raw_override
    payload = yaml.safe_load(raw_override)
    mounts = payload["services"]["wazuh.indexer"]["volumes"]
    assert mounts[-3:] == [
        {
            "type": "bind",
            "source": str(tmp_path / "config/wazuh_indexer_ssl_certs/root-ca.pem"),
            "target": "/usr/share/wazuh-indexer/certs/root-ca.pem",
            "read_only": True,
        },
        {
            "type": "bind",
            "source": str(
                tmp_path / "config/wazuh_indexer_ssl_certs/wazuh.indexer-key.pem"
            ),
            "target": "/usr/share/wazuh-indexer/certs/wazuh.indexer-key.pem",
            "read_only": True,
        },
        {
            "type": "volume",
            "source": "wazuh-indexer-data",
            "target": "/var/lib/wazuh-indexer",
            "read_only": False,
        },
    ]
    # The mount-only override does not restate image/networks -- those are the
    # base compose's job under generic realization.
    assert "image" not in payload["services"]["wazuh.indexer"]
    assert payload["volumes"] == {
        "wazuh-indexer-data": {
            "labels": {
                "org.aptl.realization.address": (
                    "provision.persistent-volume.wazuh-indexer-data"
                ),
                "org.aptl.realization.lifecycle": "retain",
                "org.aptl.realization.project": "aptl-test",
            }
        }
    }


def test_stateful_override_rejects_symlinked_generated_path(tmp_path: Path) -> None:
    (tmp_path / ".aptl").symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    spec = _spec()

    with pytest.raises(PathContainmentError):
        write_stateful_override(tmp_path, "aptl-test", spec)


def test_stateful_validation_rejects_remote_artifact_consumers() -> None:
    errors = stateful_realization_errors(_spec(), local_artifacts=False)

    assert errors == [
        "Generated artifacts cannot be materialized for a remote Docker daemon."
    ]


def test_old_compose_is_rejected_before_artifact_mutation(
    tmp_path: Path, monkeypatch
) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    monkeypatch.setattr(
        backend,
        "_run",
        lambda cmd, **kwargs: MagicMock(
            returncode=0,
            stdout="2.23.3",
            stderr="",
        ),
    )
    monkeypatch.setattr(
        backend,
        "_realize_stateful_prerequisites",
        lambda spec, scenario_root: pytest.fail(
            "artifact mutation ran before version rejection"
        ),
    )

    result = backend.realize(_spec(), scenario_root=tmp_path)

    assert result.success is False
    assert "2.24.4 or later" in result.error


def test_ssh_backend_fails_before_any_docker_side_effect(
    tmp_path: Path, monkeypatch
) -> None:
    backend = SSHComposeBackend(tmp_path, host="example.test", user="aptl")
    monkeypatch.setattr(
        backend,
        "_run",
        lambda *args, **kwargs: pytest.fail("Docker must not run before rejection"),
    )

    result = backend.realize(_spec(), scenario_root=tmp_path)

    assert result.success is False
    assert "remote Docker daemon" in result.error


def test_certificate_materialization_rejects_symlinked_output_before_docker(
    tmp_path: Path,
    monkeypatch,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    config = tmp_path / "config"
    config.mkdir()
    (config / "wazuh_indexer_ssl_certs").symlink_to(outside, target_is_directory=True)
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    monkeypatch.setattr(
        backend,
        "_run",
        lambda *args, **kwargs: pytest.fail(
            "Docker must not run through a symlinked artifact path"
        ),
    )

    result = backend._realize_certificate_bundle(
        _spec().generated_artifacts[0], tmp_path
    )

    assert result is not None
    assert result.success is False
    assert "containment" in result.error.lower()


def test_missing_declared_certificate_output_blocks_before_image_side_effect(
    tmp_path: Path,
    monkeypatch,
) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    certs_dir = tmp_path / "config/wazuh_indexer_ssl_certs"
    certs_dir.mkdir(parents=True)
    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_realization.ensure_ssl_certs",
        lambda project_dir, **_kwargs: CertResult(
            success=True,
            generated=False,
            certs_dir=certs_dir,
        ),
    )
    monkeypatch.setattr(
        backend,
        "_prepare_realization_images",
        lambda realization, scenario_root, realization_root=None: pytest.fail(
            "image side effect ran before artifact validation"
        ),
    )
    monkeypatch.setattr(
        backend,
        "_run",
        lambda cmd, **kwargs: MagicMock(
            returncode=0,
            stdout="2.24.4" if "version" in cmd else "",
            stderr="",
        ),
    )

    result = backend.realize(_spec(), scenario_root=tmp_path)

    assert result.success is False
    assert "missing declared output" in result.error.lower()
    assert "root-ca.pem" not in result.error


def test_rendered_config_materializes_at_canonical_contained_path(
    tmp_path: Path,
) -> None:
    template = tmp_path / "config/wazuh_cluster/wazuh_manager.conf"
    template.parent.mkdir(parents=True)
    template.write_text(
        "<ossec_config><cluster><key>old</key></cluster></ossec_config>"
    )
    (tmp_path / ".env").write_text(
        "INDEXER_USERNAME=admin\n"
        "INDEXER_PASSWORD=nonplaceholder-indexer\n"
        "API_USERNAME=api-user\n"
        "API_PASSWORD=nonplaceholder-api\n"
        "WAZUH_CLUSTER_KEY=bounded-test-cluster-key\n"
    )
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")

    result = backend._realize_stateful_prerequisites(_rendered_config_spec(), tmp_path)

    assert result is None
    rendered = tmp_path / ".aptl/config/wazuh_cluster/wazuh_manager.conf"
    assert rendered.is_file()
    assert "bounded-test-cluster-key" in rendered.read_text()


def test_certificate_bundle_validates_pair_chain_san_and_permissions(
    tmp_path: Path,
) -> None:
    certs_dir, outputs = _write_certificate_bundle(tmp_path)

    provenance = tmp_path / "config/certs.yml"
    assert validate_certificate_bundle(certs_dir, outputs, provenance) == []
    evidence = certificate_bundle_evidence(certs_dir, outputs, provenance)
    assert evidence is not None
    assert evidence["chain_valid"] is True
    assert evidence["san_valid"] is True
    assert len(evidence["public_root_sha256"]) == 64


def test_certificate_bundle_without_a_provenance_document_still_validates_crypto(
    tmp_path: Path,
) -> None:
    """An env-pack bundle has no provenance document, only a profile identity.

    Realization already scopes the document check that way; observation must
    too, or a correctly issued pack bundle validates as "identity does not match
    its provenance", loses its evidence, and the SEM-218 gate rejects
    certificates APTL just issued (issue #875). Every cryptographic
    relationship is still enforced -- only the comparison that has no document
    to compare against is skipped.
    """

    certs_dir, outputs = _write_certificate_bundle(tmp_path)

    assert validate_certificate_bundle(certs_dir, outputs, None) == []
    evidence = certificate_bundle_evidence(certs_dir, outputs, None)
    assert evidence is not None
    assert len(evidence["public_root_sha256"]) == 64


def test_certificate_bundle_without_a_provenance_document_still_rejects_bad_keys(
    tmp_path: Path,
) -> None:
    certs_dir, outputs = _write_certificate_bundle(tmp_path, leaf_key_matches=False)

    assert validate_certificate_bundle(certs_dir, outputs, None) == [
        "Certificate bundle contains a key/certificate mismatch."
    ]
    assert certificate_bundle_evidence(certs_dir, outputs, None) is None


def test_certificate_bundle_rejects_private_key_mismatch(tmp_path: Path) -> None:
    certs_dir, outputs = _write_certificate_bundle(tmp_path, leaf_key_matches=False)

    errors = validate_certificate_bundle(
        certs_dir, outputs, tmp_path / "config/certs.yml"
    )

    assert errors == ["Certificate bundle contains a key/certificate mismatch."]


def test_certificate_bundle_rejects_unexpected_san(tmp_path: Path) -> None:
    certs_dir, outputs = _write_certificate_bundle(tmp_path, san="other.example")

    errors = validate_certificate_bundle(
        certs_dir, outputs, tmp_path / "config/certs.yml"
    )

    assert errors == ["Certificate bundle identity does not match its provenance."]


def test_certificate_bundle_rejects_writable_private_key(tmp_path: Path) -> None:
    certs_dir, outputs = _write_certificate_bundle(tmp_path)
    (certs_dir / "wazuh.indexer-key.pem").chmod(0o666)

    errors = validate_certificate_bundle(
        certs_dir, outputs, tmp_path / "config/certs.yml"
    )

    assert errors == ["Certificate bundle output permissions are unsafe."]


def test_certificate_bundle_rejects_traversable_host_directory(
    tmp_path: Path,
) -> None:
    certs_dir, outputs = _write_certificate_bundle(tmp_path)
    certs_dir.chmod(0o755)

    errors = validate_certificate_bundle(
        certs_dir, outputs, tmp_path / "config/certs.yml"
    )

    assert errors == ["Certificate bundle output permissions are unsafe."]


def test_generated_compose_model_is_validated_before_up(
    tmp_path: Path, monkeypatch
) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    commands: list[list[str]] = []
    monkeypatch.setattr(
        backend,
        "_realize_stateful_prerequisites",
        lambda spec, scenario_root: None,
    )
    monkeypatch.setattr(
        backend,
        "_prepare_realization_images",
        lambda spec, scenario_root, realization_root=None: (None, None),
    )
    monkeypatch.setattr(backend, "_ensure_realization_networks", lambda spec: [])
    monkeypatch.setattr(backend, "_realize_content", lambda spec, scenario_root: None)
    spec = _spec()

    def run(cmd, **kwargs):
        commands.append(cmd)
        return MagicMock(
            returncode=0,
            stdout=(
                "2.24.4"
                if "version" in cmd
                else json.dumps(_effective_payload(tmp_path, spec))
                if "config" in cmd
                else ""
            ),
            stderr="",
        )

    monkeypatch.setattr(backend, "_run", run)
    monkeypatch.setattr(
        backend,
        "_realization_result",
        lambda start_result, spec: start_result,
    )

    result = backend.realize(spec, build=False, scenario_root=tmp_path)

    assert result.success is True
    config_index = next(i for i, cmd in enumerate(commands) if "config" in cmd)
    up_index = next(i for i, cmd in enumerate(commands) if "up" in cmd)
    assert config_index < up_index
    assert commands[config_index][-4:] == [
        "config",
        "--no-interpolate",
        "--format",
        "json",
    ]


def test_effective_compose_model_rejects_undeclared_certificate_mount(
    tmp_path: Path, monkeypatch
) -> None:
    """An extra mount of cert material beyond the declared outputs is rejected.

    Wazuh is realized generically now, so extra *non-cert* mounts from the
    generated base compose are expected and allowed; the effective-model check no
    longer strict-matches the whole service. But undeclared *certificate*
    material must still be caught -- a mount whose source is under a cert bundle
    root but is not a declared output leaks key material (issue #875).
    """
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    spec = _spec()
    payload = _effective_payload(tmp_path, spec)
    payload["services"]["wazuh.indexer"]["volumes"].append(
        {
            "type": "bind",
            "source": str(
                tmp_path / "config/wazuh_indexer_ssl_certs/wazuh.indexer.pem"
            ),
            "target": "/usr/share/wazuh-indexer/certs/leaked.pem",
            "read_only": True,
        }
    )
    monkeypatch.setattr(
        backend,
        "_realize_stateful_prerequisites",
        lambda spec, scenario_root: None,
    )
    monkeypatch.setattr(
        backend,
        "_prepare_realization_images",
        lambda spec, scenario_root, realization_root=None: (None, None),
    )
    monkeypatch.setattr(backend, "_ensure_realization_networks", lambda spec: [])
    monkeypatch.setattr(backend, "_realize_content", lambda spec, scenario_root: None)
    monkeypatch.setattr(
        backend,
        "_run",
        lambda cmd, **kwargs: MagicMock(
            returncode=0,
            stdout=("2.24.4" if "version" in cmd else json.dumps(payload)),
            stderr="",
        ),
    )

    result = backend.realize(spec, build=False, scenario_root=tmp_path)

    assert result.success is False
    assert "undeclared certificate material" in result.error


def test_invalid_generated_compose_model_blocks_up(tmp_path: Path, monkeypatch) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    commands: list[list[str]] = []
    monkeypatch.setattr(
        backend,
        "_realize_stateful_prerequisites",
        lambda spec, scenario_root: None,
    )
    monkeypatch.setattr(
        backend,
        "_prepare_realization_images",
        lambda spec, scenario_root, realization_root=None: (None, None),
    )
    monkeypatch.setattr(backend, "_ensure_realization_networks", lambda spec: [])
    monkeypatch.setattr(backend, "_realize_content", lambda spec, scenario_root: None)

    def run(cmd, **kwargs):
        commands.append(cmd)
        return MagicMock(
            returncode=1 if "config" in cmd else 0,
            stdout="2.24.4" if "version" in cmd else "",
            stderr="sensitive expanded compose model",
        )

    monkeypatch.setattr(backend, "_run", run)

    result = backend.realize(_spec(), build=False, scenario_root=tmp_path)

    assert result.success is False
    assert result.error == "Generated Compose model validation failed."
    assert not any("up" in cmd for cmd in commands)
    assert "sensitive" not in result.error


def test_stateful_wazuh_readiness_is_authenticated_and_observed(
    tmp_path: Path, monkeypatch
) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    (tmp_path / ".env").write_text(
        "INDEXER_USERNAME=indexer-user\n"
        "INDEXER_PASSWORD=indexer-password\n"
        "API_USERNAME=api-user\n"
        "API_PASSWORD=api-password\n"
    )
    monkeypatch.setattr(
        backend,
        "container_inspect",
        lambda name: {
            "NetworkSettings": {
                "Ports": {
                    "9200/tcp": [{"HostPort": "19200"}],
                    "55000/tcp": [{"HostPort": "55001"}],
                }
            }
        },
    )
    checked: list[tuple[str, str, str]] = []
    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_readiness.check_indexer_ready",
        lambda url, username, password: (
            checked.append((url, username, password)) or True
        ),
    )
    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_readiness.check_manager_api_ready",
        lambda url, username, password: (
            checked.append((url, username, password)) or True
        ),
    )
    spec = _spec()
    manager_consumer = _consumer(
        node="wazuh-manager",
        service="wazuh.manager",
        destination="/etc/ssl/wazuh",
    )
    spec = DeploymentRealizationSpec(
        profiles=spec.profiles,
        nodes=(
            *spec.nodes,
            DeploymentNodeRealization(
                address="provision.node.wazuh-manager",
                name="wazuh-manager",
                service_name="wazuh.manager",
                container_name="aptl-wazuh-manager",
                networks=(),
            ),
        ),
        networks=(),
        generated_artifacts=(
            DeploymentGeneratedArtifactRealization(
                **{
                    **spec.generated_artifacts[0].__dict__,
                    "consumers": (
                        *spec.generated_artifacts[0].consumers,
                        manager_consumer,
                    ),
                }
            ),
        ),
    )

    result = backend._verify_stateful_authenticated_readiness(spec)

    assert result is None
    assert checked == [
        ("https://localhost:19200", "indexer-user", "indexer-password"),
        ("https://localhost:55001", "api-user", "api-password"),
    ]
    assert backend.authenticated_readiness == {
        "wazuh.indexer": True,
        "wazuh.manager": True,
    }


def test_authenticated_readiness_polls_until_credentials_are_accepted(
    tmp_path: Path, monkeypatch
) -> None:
    """A transient 401 right after health-settle is retried, not fatal.

    The indexer's security index (loaded from internal_users.yml) and the
    manager API keep initializing after the healthcheck first passes, so the
    probe must poll rather than fail on the first 401 (issue #875).
    """

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    (tmp_path / ".env").write_text(
        "INDEXER_USERNAME=indexer-user\n"
        "INDEXER_PASSWORD=indexer-password\n"
        "API_USERNAME=api-user\n"
        "API_PASSWORD=api-password\n"
    )
    monkeypatch.setattr(
        backend,
        "container_inspect",
        lambda name: {
            "NetworkSettings": {
                "Ports": {
                    "9200/tcp": [{"HostPort": "19200"}],
                    "55000/tcp": [{"HostPort": "55001"}],
                }
            }
        },
    )
    # The indexer rejects credentials on the first two probes, then accepts.
    indexer_attempts = {"n": 0}

    def _indexer_ready(url, username, password):
        indexer_attempts["n"] += 1
        return indexer_attempts["n"] >= 3

    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_readiness.check_indexer_ready",
        _indexer_ready,
    )
    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_readiness.check_manager_api_ready",
        lambda url, username, password: True,
    )
    slept: list[float] = []
    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_readiness.time.sleep",
        slept.append,
    )

    spec = _spec()
    manager_consumer = _consumer(
        node="wazuh-manager",
        service="wazuh.manager",
        destination="/etc/ssl/wazuh",
    )
    spec = DeploymentRealizationSpec(
        profiles=spec.profiles,
        nodes=(
            *spec.nodes,
            DeploymentNodeRealization(
                address="provision.node.wazuh-manager",
                name="wazuh-manager",
                service_name="wazuh.manager",
                container_name="aptl-wazuh-manager",
                networks=(),
            ),
        ),
        networks=(),
        generated_artifacts=(
            DeploymentGeneratedArtifactRealization(
                **{
                    **spec.generated_artifacts[0].__dict__,
                    "consumers": (
                        *spec.generated_artifacts[0].consumers,
                        manager_consumer,
                    ),
                }
            ),
        ),
    )

    result = backend._verify_stateful_authenticated_readiness(spec)

    assert result is None
    assert indexer_attempts["n"] == 3
    assert len(slept) == 2  # two retries before the third probe succeeded
    assert backend.authenticated_readiness == {
        "wazuh.indexer": True,
        "wazuh.manager": True,
    }


# -- ssh_key_bundle dispatch and image-free delivery (issue #875) -------------


def _ssh_artifact(consumers=()) -> DeploymentGeneratedArtifactRealization:
    """An ssh_key_bundle artifact shaped like the TechVault declaration."""

    return DeploymentGeneratedArtifactRealization(
        address="provision.generated-artifact.techvault-ssh-keys",
        name="techvault-ssh-keys",
        generator="ssh_key_bundle",
        lifecycle="regenerate_on_change",
        provenance="techvault:ssh-access-profile/v1",
        outputs=(
            DeploymentGeneratedArtifactOutput(
                name="operator-private-key",
                path="operator/control-plane-key",
                sensitivity="secret",
                disposition="producer_private",
            ),
            DeploymentGeneratedArtifactOutput(
                name="workstation-dev-private-key",
                path="dev-user/.ssh/id_rsa",
                sensitivity="secret",
            ),
            DeploymentGeneratedArtifactOutput(
                name="target-authorized-keys",
                path="labadmin/.ssh/authorized_keys",
                sensitivity="restricted",
            ),
        ),
        consumers=consumers,
    )


def _stub_ssh_generator(monkeypatch, *, error=None):
    """Replace the key generator so no ssh-keygen runs and no ~/.ssh is touched."""

    staged: list[Path] = []

    def _generate(artifact, staging_root, **kwargs):
        staged.append(staging_root)
        if error is not None:
            return error
        for output in artifact.outputs:
            path = staging_root / output.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"material for {output.name}\n", encoding="utf-8")
        return None

    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_realization.realize_ssh_key_bundle",
        _generate,
    )
    return staged


def test_ssh_key_bundle_is_generated_under_its_canonical_contained_root(
    tmp_path: Path, monkeypatch
) -> None:
    """The bundle is a scenario-local artifact under the realization root."""

    from aptl.core.deployment._compose_stateful_constants import (
        SSH_KEY_BUNDLE_ROOT_RELPATH,
    )

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    staged = _stub_ssh_generator(monkeypatch)

    assert backend._realize_one_generated_artifact(_ssh_artifact(), tmp_path) is None

    assert staged == [
        tmp_path.resolve() / SSH_KEY_BUNDLE_ROOT_RELPATH / "techvault-ssh-keys"
    ]


def test_ssh_key_bundle_generation_failure_fails_the_realization_closed(
    tmp_path: Path, monkeypatch
) -> None:
    """A generator error becomes a fail-closed LabResult, not a partial range."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    _stub_ssh_generator(monkeypatch, error="ssh-keygen unavailable")

    result = backend._realize_one_generated_artifact(_ssh_artifact(), tmp_path)

    assert result is not None
    assert result.success is False
    assert "ssh-keygen unavailable" in result.error


def test_ssh_key_bundle_path_outside_the_scenario_root_is_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """A staging root that escapes the bundle is rejected before generation."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_realization.realize_ssh_key_bundle",
        lambda *args, **kwargs: pytest.fail("must not generate outside the bundle"),
    )
    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_realization.artifact_source_path",
        lambda root, artifact: tmp_path.parent / "elsewhere" / "keys",
    )

    result = backend._realize_ssh_key_bundle(_ssh_artifact(), tmp_path)

    assert result is not None
    assert result.success is False
    assert "containment" in result.error.lower()


def test_an_unsupported_generator_kind_is_refused(tmp_path: Path) -> None:
    """APTL never silently skips a generated artifact it cannot produce."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    artifact = DeploymentGeneratedArtifactRealization(
        **{**_ssh_artifact().__dict__, "generator": "quantum_entropy_bundle"}
    )

    result = backend._realize_one_generated_artifact(artifact, tmp_path)

    assert result is not None
    assert result.success is False
    assert "unsupported" in result.error


def _image_free_consumer(node: str, *, selected: tuple[str, ...]):
    return DeploymentStatefulConsumer(
        target_address=f"provision.node.{node}",
        node_name=node,
        service_name=node,
        mount_destination="/home",
        access_mode="read_only",
        selected_outputs=selected,
    )


def test_image_free_consumers_receive_their_selected_outputs_as_placed_files(
    tmp_path: Path, monkeypatch
) -> None:
    """An image-free node has no Compose service to mount into (issue #875).

    Its consumer's selected outputs are placed into the container as files
    instead, at the same destination the mount model would have bound them to,
    and a producer_private output is never among them.
    """

    from aptl.backends.raes_materializer import PlaceFileOp

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    _stub_ssh_generator(monkeypatch)
    consumer = _image_free_consumer(
        "workstation",
        selected=(
            "workstation-dev-private-key",
            "target-authorized-keys",
            "operator-private-key",  # producer_private: must be dropped
        ),
    )
    realization = DeploymentRealizationSpec(
        profiles=(), nodes=(), networks=(),
        generated_artifacts=(_ssh_artifact((consumer,)),),
    )

    failure, ops = backend._image_free_generated_artifact_ops(
        realization, frozenset({"provision.node.workstation"}), tmp_path
    )

    assert failure is None
    placed = ops["provision.node.workstation"]
    assert all(isinstance(op, PlaceFileOp) for op in placed)
    assert [(op.path, op.mode) for op in placed] == [
        ("/home/dev-user/.ssh/id_rsa", "0600"),  # secret -> owner-only
        ("/home/labadmin/.ssh/authorized_keys", "0644"),
    ]
    assert placed[0].content == "material for workstation-dev-private-key\n"


def test_an_artifact_with_no_image_free_consumer_is_not_generated_here(
    tmp_path: Path, monkeypatch
) -> None:
    """Compose consumers get bind mounts; this path must not duplicate that work."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    staged = _stub_ssh_generator(monkeypatch)
    consumer = _image_free_consumer("kali", selected=("target-authorized-keys",))
    realization = DeploymentRealizationSpec(
        profiles=(), nodes=(), networks=(),
        generated_artifacts=(_ssh_artifact((consumer,)),),
    )

    failure, ops = backend._image_free_generated_artifact_ops(
        realization, frozenset({"provision.node.workstation"}), tmp_path
    )

    assert (failure, ops) == (None, {})
    assert staged == []


def test_a_generator_failure_stops_image_free_placement(
    tmp_path: Path, monkeypatch
) -> None:
    """Nothing is placed from an artifact that failed to generate."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    _stub_ssh_generator(monkeypatch, error="no entropy source")
    consumer = _image_free_consumer("workstation", selected=("target-authorized-keys",))
    realization = DeploymentRealizationSpec(
        profiles=(), nodes=(), networks=(),
        generated_artifacts=(_ssh_artifact((consumer,)),),
    )

    failure, ops = backend._image_free_generated_artifact_ops(
        realization, frozenset({"provision.node.workstation"}), tmp_path
    )

    assert failure is not None
    assert failure.success is False
    assert ops == {}


def test_a_declared_output_that_never_materialized_stops_image_free_placement(
    tmp_path: Path, monkeypatch
) -> None:
    """An absent output would otherwise be placed as an empty file in the node."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_realization.realize_ssh_key_bundle",
        lambda artifact, staging_root, **kwargs: None,  # reports success, writes nothing
    )
    consumer = _image_free_consumer("workstation", selected=("target-authorized-keys",))
    realization = DeploymentRealizationSpec(
        profiles=(), nodes=(), networks=(),
        generated_artifacts=(_ssh_artifact((consumer,)),),
    )

    failure, ops = backend._image_free_generated_artifact_ops(
        realization, frozenset({"provision.node.workstation"}), tmp_path
    )

    assert failure is not None
    assert failure.success is False
    assert "missing for image-free consumer" in failure.error
    assert "labadmin/.ssh/authorized_keys" in failure.error
    assert ops == {}


# -- SOC certificate bundle and flag-signing keys (issue #875) ---------------


def _soc_artifact(paths=("lab-ca.pem", "misp/server.pem", "thehive/keystore.p12")):
    return DeploymentGeneratedArtifactRealization(
        address="provision.generated-artifact.soc-certs",
        name="soc-certs",
        generator="certificate_bundle",
        lifecycle="regenerate_on_change",
        provenance="techvault:soc-certificate-profile/v1",
        outputs=tuple(
            DeploymentGeneratedArtifactOutput(
                name=path.replace("/", "-"), path=path, sensitivity="restricted"
            )
            for path in paths
        ),
        consumers=(),
    )


def _stub_soc_certs(monkeypatch, *, written=(), success=True, error=""):
    """Replace the SOC CA generator; record the derived per-service request set."""

    from aptl.core.soc_ca import CertResult as SocCertResult

    requested: list[tuple[str, ...]] = []

    def _ensure(project_dir, services):
        requested.append(tuple(service.name for service in services))
        certs_dir = Path(project_dir) / "config/soc_certs"
        for relpath in written:
            path = certs_dir / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("pem\n", encoding="utf-8")
        return SocCertResult(
            success=success, generated=True, certs_dir=certs_dir, error=error
        )

    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_realization.ensure_soc_certs", _ensure
    )
    return requested


def test_the_soc_service_set_is_derived_from_the_declared_bundle_outputs(
    tmp_path: Path, monkeypatch
) -> None:
    """APTL must not decide the range's SOC service identity (issue #875).

    The certificate requests come from the SDL-declared output paths, so a pack
    that declares a different set of SOC services gets that set issued, with no
    APTL-side registry to keep in sync.
    """

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    artifact = _soc_artifact()
    requested = _stub_soc_certs(
        monkeypatch, written=[o.path for o in artifact.outputs]
    )

    assert backend._realize_one_generated_artifact(artifact, tmp_path) is None

    # Root-level CA output names no service; each first path segment does.
    assert requested == [("misp", "thehive")]


def test_a_soc_bundle_missing_a_declared_output_fails_closed(
    tmp_path: Path, monkeypatch
) -> None:
    """A service whose certificate never landed must not reach a booting range."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    artifact = _soc_artifact()
    _stub_soc_certs(monkeypatch, written=["lab-ca.pem", "misp/server.pem"])

    result = backend._realize_one_generated_artifact(artifact, tmp_path)

    assert result is not None
    assert result.success is False
    assert "thehive/keystore.p12" in result.error


def test_a_failed_soc_generator_fails_closed(tmp_path: Path, monkeypatch) -> None:
    """The generator's own error is surfaced rather than swallowed."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    _stub_soc_certs(monkeypatch, success=False, error="no openssl")

    result = backend._realize_one_generated_artifact(_soc_artifact(), tmp_path)

    assert result is not None
    assert result.success is False
    assert "no openssl" in result.error


def _flag_artifact():
    return DeploymentGeneratedArtifactRealization(
        address="provision.generated-artifact.flag-keys",
        name="flag-keys",
        generator="rendered_config",
        lifecycle="regenerate_on_change",
        provenance="techvault:flag-signing-profile/v2",
        outputs=(
            DeploymentGeneratedArtifactOutput(
                name="webapp-key", path="webapp/flag.key", sensitivity="secret"
            ),
        ),
        consumers=(),
    )


def test_flag_signing_keys_are_generated_under_their_canonical_root(
    tmp_path: Path, monkeypatch
) -> None:
    """The flag-signing profile is dispatched by provenance, not generator kind."""

    from aptl.core.deployment._compose_stateful_constants import (
        FLAG_SIGNING_ROOT_RELPATH,
    )

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    staged: list[Path] = []
    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_realization.realize_flag_signing_keys",
        lambda artifact, staging_root: staged.append(staging_root),
    )

    assert backend._realize_one_generated_artifact(_flag_artifact(), tmp_path) is None

    assert staged == [tmp_path.resolve() / FLAG_SIGNING_ROOT_RELPATH / "flag-keys"]


def test_a_flag_signing_generation_failure_fails_closed(
    tmp_path: Path, monkeypatch
) -> None:
    """A per-node signing key that was not produced stops the realization."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_realization.realize_flag_signing_keys",
        lambda artifact, staging_root: "unsupported signing profile",
    )

    result = backend._realize_one_generated_artifact(_flag_artifact(), tmp_path)

    assert result is not None
    assert result.success is False
    assert "unsupported signing profile" in result.error


@pytest.mark.parametrize(
    ("artifact_factory", "expected"),
    [
        (_flag_artifact, "Flag-signing key path failed containment validation."),
        (_soc_artifact, "SOC certificate path failed containment validation."),
    ],
)
def test_a_generated_artifact_path_outside_the_bundle_is_refused(
    tmp_path: Path, monkeypatch, artifact_factory, expected
) -> None:
    """Containment is checked before the generator runs, for every profile."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    for name in ("realize_flag_signing_keys", "ensure_soc_certs"):
        monkeypatch.setattr(
            f"aptl.core.deployment._compose_stateful_realization.{name}",
            lambda *args, **kwargs: pytest.fail("must not generate outside the bundle"),
        )
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "soc_certs").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_realization.artifact_source_path",
        lambda root, artifact: tmp_path.parent / "elsewhere" / "keys",
    )

    result = backend._realize_one_generated_artifact(artifact_factory(), tmp_path)

    assert result is not None
    assert result.success is False
    assert result.error == expected


# -- the generated image-node content override (issue #875) ------------------


def _content_override_spec(tmp_path: Path):
    from aptl.core.deployment.realization import DeploymentContentRealization

    return DeploymentRealizationSpec(
        profiles=(),
        nodes=(
            DeploymentNodeRealization(
                address="provision.node.tempo", name="tempo", service_name="tempo",
                container_name="aptl-tempo", networks=(),
            ),
        ),
        networks=(),
        images=(
            DeploymentImageRealization(
                address="provision.node.tempo", service_name="tempo",
                source_name="img", source_version="1", image_ref="img:1",
                mode="pull", policy_rule="allowed-source",
            ),
        ),
        content=(
            DeploymentContentRealization(
                address="provision.content.tempo-config",
                target_address="provision.node.tempo",
                content_name="tempo-config",
                volume_suffix="tempo_config",
                dest_relpath="etc/tempo/tempo.yaml",
                source_kind="inline-text",
                inline_text="storage: local\n",
            ),
        ),
    )


def test_the_content_override_is_written_under_the_realization_root(
    tmp_path: Path,
) -> None:
    """A generated (env-pack) base needs its image nodes' content bound in."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    scenario_root = tmp_path / "pack"
    scenario_root.mkdir()
    realization_root = tmp_path / "engine"
    realization_root.mkdir()

    path = backend._write_image_node_content_override(
        _content_override_spec(tmp_path), scenario_root, realization_root
    )

    assert path == realization_root / ".aptl/realization/compose.content.yml"
    document = yaml.safe_load(path.read_text())
    mount = document["services"]["tempo"]["volumes"][0]
    assert mount["target"] == "/etc/tempo/tempo.yaml"
    assert mount["read_only"] is True
    # Nothing generated inside the pristine, digest-validated pack.
    assert not (scenario_root / ".aptl").exists()


def test_an_in_tree_scenario_writes_no_content_override(tmp_path: Path) -> None:
    """A checked-in docker-compose.yml already binds its own image-node config."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    assert (
        backend._write_image_node_content_override(
            _content_override_spec(tmp_path), tmp_path, tmp_path
        )
        is None
    )


def test_no_image_node_content_means_no_override_file(tmp_path: Path) -> None:
    """An empty override would add a Compose file with nothing in it."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    empty = DeploymentRealizationSpec(profiles=(), nodes=(), networks=())

    assert (
        backend._write_image_node_content_override(empty, tmp_path, tmp_path) is None
    )
    assert not (tmp_path / ".aptl/realization/compose.content.yml").exists()


def _seedable_spec(tmp_path: Path):
    """One image node and one image-free node, each declaring content."""

    from aptl.core.deployment.realization import DeploymentContentRealization

    def _item(name, target):
        return DeploymentContentRealization(
            address=f"provision.content.{name}",
            target_address=target,
            content_name=name,
            volume_suffix=name,
            dest_relpath=f"etc/{name}.yaml",
            source_kind="inline-text",
            inline_text="k: v\n",
        )

    base = _content_override_spec(tmp_path)
    return DeploymentRealizationSpec(
        **{
            **base.__dict__,
            "content": (
                _item("tempo-config", "provision.node.tempo"),
                _item("workstation-config", "provision.node.workstation"),
            ),
        }
    )


def test_image_node_content_is_not_also_seeded_for_a_generated_base(
    tmp_path: Path, monkeypatch
) -> None:
    """Bound-in content must not be re-resolved and staged into the pack.

    For an env-pack base, image-node content is delivered as a Compose bind
    mount; seeding it as well would re-resolve the bytes and write them under
    the pristine pack, breaking its digest-validated inventory (issue #875).
    """

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    seeded: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        backend,
        "realize_content",
        lambda content, **kwargs: seeded.append(
            tuple(item.content_name for item in content)
        ),
    )
    scenario_root = tmp_path / "pack"
    scenario_root.mkdir()  # no docker-compose.yml: a generated base

    assert backend._realize_content(_seedable_spec(tmp_path), scenario_root) is None

    assert seeded == [("workstation-config",)]


def test_an_in_tree_scenario_still_seeds_every_content_item(
    tmp_path: Path, monkeypatch
) -> None:
    """In-tree keeps the original seed path, image nodes included."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    seeded: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        backend,
        "realize_content",
        lambda content, **kwargs: seeded.append(
            tuple(item.content_name for item in content)
        ),
    )
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    assert backend._realize_content(_seedable_spec(tmp_path), tmp_path) is None

    assert seeded == [("tempo-config", "workstation-config")]


def test_a_seed_failure_fails_the_realization_closed(
    tmp_path: Path, monkeypatch
) -> None:
    """A content placement that could not be seeded stops the run."""

    from aptl.core.deployment.errors import BackendSeedError

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")

    def _boom(content, **kwargs):
        raise BackendSeedError("seed container exited 1")

    monkeypatch.setattr(backend, "realize_content", _boom)
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    result = backend._realize_content(_seedable_spec(tmp_path), tmp_path)

    assert result is not None
    assert result.success is False
    assert "seed container exited 1" in result.error


def test_a_spec_with_no_content_seeds_nothing(tmp_path: Path, monkeypatch) -> None:
    """Nothing to place means the step falls through to the next one."""

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    monkeypatch.setattr(
        backend,
        "realize_content",
        lambda *args, **kwargs: pytest.fail("no content should have been seeded"),
    )
    empty = DeploymentRealizationSpec(profiles=(), nodes=(), networks=())

    assert backend._realize_content(empty, tmp_path) is None
