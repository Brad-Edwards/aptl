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
    assert "wazuh.indexer: !override" in raw_override
    payload = yaml.safe_load(raw_override.replace("!override", ""))
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
    assert payload["services"]["wazuh.indexer"]["image"] == (
        "wazuh/wazuh-indexer:4.12.0"
    )
    assert payload["services"]["wazuh.indexer"]["networks"] == {
        "aptl-security": {"ipv4_address": "172.20.0.12"}
    }
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
        lambda spec: pytest.fail("artifact mutation ran before version rejection"),
    )

    result = backend.realize(_spec())

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

    result = backend.realize(_spec())

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

    result = backend._realize_certificate_bundle(_spec().generated_artifacts[0])

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
        lambda realization: pytest.fail(
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

    result = backend.realize(_spec())

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

    result = backend._realize_stateful_prerequisites(_rendered_config_spec())

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
    monkeypatch.setattr(backend, "_realize_stateful_prerequisites", lambda spec: None)
    monkeypatch.setattr(
        backend, "_prepare_realization_images", lambda spec: (None, None)
    )
    monkeypatch.setattr(backend, "_ensure_realization_networks", lambda spec: [])
    monkeypatch.setattr(backend, "_realize_content", lambda spec: None)
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

    result = backend.realize(spec, build=False)

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


def test_effective_compose_model_rejects_inherited_stateful_mount(
    tmp_path: Path, monkeypatch
) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    spec = _spec()
    payload = _effective_payload(tmp_path, spec)
    payload["services"]["wazuh.indexer"]["volumes"].append(
        {
            "type": "bind",
            "source": str(tmp_path / "unexpected"),
            "target": "/unexpected",
            "read_only": True,
        }
    )
    monkeypatch.setattr(backend, "_realize_stateful_prerequisites", lambda spec: None)
    monkeypatch.setattr(
        backend, "_prepare_realization_images", lambda spec: (None, None)
    )
    monkeypatch.setattr(backend, "_ensure_realization_networks", lambda spec: [])
    monkeypatch.setattr(backend, "_realize_content", lambda spec: None)
    monkeypatch.setattr(
        backend,
        "_run",
        lambda cmd, **kwargs: MagicMock(
            returncode=0,
            stdout=("2.24.4" if "version" in cmd else json.dumps(payload)),
            stderr="",
        ),
    )

    result = backend.realize(spec, build=False)

    assert result.success is False
    assert "unexpected mounts" in result.error


def test_invalid_generated_compose_model_blocks_up(tmp_path: Path, monkeypatch) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    commands: list[list[str]] = []
    monkeypatch.setattr(backend, "_realize_stateful_prerequisites", lambda spec: None)
    monkeypatch.setattr(
        backend, "_prepare_realization_images", lambda spec: (None, None)
    )
    monkeypatch.setattr(backend, "_ensure_realization_networks", lambda spec: [])
    monkeypatch.setattr(backend, "_realize_content", lambda spec: None)

    def run(cmd, **kwargs):
        commands.append(cmd)
        return MagicMock(
            returncode=1 if "config" in cmd else 0,
            stdout="2.24.4" if "version" in cmd else "",
            stderr="sensitive expanded compose model",
        )

    monkeypatch.setattr(backend, "_run", run)

    result = backend.realize(_spec(), build=False)

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
        "aptl.core.deployment._compose_stateful_realization.check_indexer_ready",
        lambda url, username, password: (
            checked.append((url, username, password)) or True
        ),
    )
    monkeypatch.setattr(
        "aptl.core.deployment._compose_stateful_realization.check_manager_api_ready",
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
