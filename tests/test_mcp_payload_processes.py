"""Initialize every built MCP from an extracted payload without its build tree."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

import pytest

from aptl.utils.mcp_packaging import archive_project, flatten_common_dependencies
from tests.test_mcp_transport_processes import initialize, request

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "linux", reason="Linux payload"),
]
REPO = Path(__file__).resolve().parents[1]
SERVERS = (
    "red",
    "reverse",
    "indexer",
    "wazuh",
    "network",
    "soar",
    "casemgmt",
    "threatintel",
)


def _copy_readonly(source, target):
    # The fixture only reads these build outputs. Separate directory entries let
    # the packaging code replace its own links without modifying the checkout.
    try:
        os.link(source, target)
    except OSError:
        shutil.copy2(source, target)
    return target


def _runtime_ca(extracted):
    """Supply a fresh public trust anchor, normally generated at guest startup."""
    from datetime import UTC, datetime, timedelta
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "payload-test")]
    )
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = extracted / "config/soc_certs/lab-ca.pem"
    path.parent.mkdir(parents=True)
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


@pytest.mark.parametrize("server", SERVERS)
def test_extracted_mcp_initializes_without_original_build_tree(tmp_path, server):
    node = shutil.which("node")
    assert node, "Build all MCPs and install Node before this integration test"
    project = tmp_path / "build-tree"
    for package in ("aptl-mcp-common", "mcp-" + server):
        source = REPO / "mcp" / package
        destination = project / "mcp" / package
        destination.mkdir(parents=True)
        for name in (
            "build",
            "node_modules",
            "package.json",
            "package-lock.json",
            "docker-lab-config.json",
        ):
            path = source / name
            if name == "docker-lab-config.json" and package == "aptl-mcp-common":
                continue
            assert path.exists(), f"Missing MCP build input: {path}"
            if path.is_dir():
                shutil.copytree(
                    path,
                    destination / name,
                    symlinks=True,
                    copy_function=_copy_readonly,
                )
            else:
                _copy_readonly(path, destination / name)
    flatten_common_dependencies(project)
    archive = tmp_path / "project.tar"
    archive_project(project, archive)
    shutil.rmtree(project)
    extracted = tmp_path / "extracted"
    with tarfile.open(archive) as payload:
        payload.extractall(extracted, filter="data")
    archive.unlink()
    _runtime_ca(extracted)
    package = extracted / "mcp" / ("mcp-" + server)
    env = {"PATH": os.defpath, "HOME": str(tmp_path), "APTL_MCP_DISABLE_DOTENV": "1"}
    variables = re.findall(
        r"\$\{([A-Z0-9_]+)\}", (package / "docker-lab-config.json").read_text()
    )
    env.update(
        {
            name: "1" if name.startswith("APTL_HP_") else "fixture-value"
            for name in variables
        }
    )
    # No service calls: initialization and inventory verify the complete module
    # graph without using Docker, network targets, capture or real credentials.
    process = subprocess.Popen(
        [node, str(package / "build/index.js")],
        cwd=extracted,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert "tools" in initialize(process)["capabilities"]
        inventory = request(process, "tools/list", 2, {})
        assert inventory["tools"]
    finally:
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
