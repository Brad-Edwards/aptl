"""Registry-aware SDL composition and packaging tests."""

from __future__ import annotations

import base64
import json
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from aptl.cli.main import app
from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.sdl._errors import SDLParseError, SDLValidationError
from aptl.core.sdl.module_registry import (
    LOCKFILE_NAME,
    load_lockfile,
    publish_module_to_oci_layout,
)
from aptl.core.sdl.parser import parse_sdl_file


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")
    return path


def _local_module(path: Path, *, version: str = "1.2.3", exports: str = "nodes: [vm]\ninfrastructure: [vm]") -> Path:
    exports_block = "\n".join(
        f"    {line}" for line in textwrap.dedent(exports).strip().splitlines()
    )
    return _write(
        path,
        "\n".join(
            [
                "name: shared",
                f"version: {version}",
                "module:",
                "  id: acme/shared",
                f"  version: {version}",
                "  exports:",
                exports_block,
                "nodes:",
                "  vm:",
                "    type: vm",
                "    os: linux",
                "    resources: {ram: 1 gib, cpu: 1}",
                "infrastructure:",
                "  vm: 1",
            ]
        ),
    )


def _flat_equivalent(path: Path) -> Path:
    return _write(
        path,
        """
        name: flat
        nodes:
          shared.vm:
            type: vm
            os: linux
            resources: {ram: 1 gib, cpu: 1}
        infrastructure:
          shared.vm: 1
        """,
    )


def _root_import(path: Path, import_body: str) -> Path:
    lines = textwrap.dedent(import_body).strip().splitlines()
    import_lines = [f"  - {lines[0].strip()}"]
    import_lines.extend(f"    {line.strip()}" for line in lines[1:])
    import_block = "\n".join(import_lines)
    return _write(
        path,
        "\n".join(
            [
                "name: root",
                "imports:",
                import_block,
            ]
        ),
    )


class _OCIHandler(BaseHTTPRequestHandler):
    repo = ""
    tag = ""
    manifest_digest = ""
    manifest_bytes = b""
    blobs: dict[str, bytes] = {}

    def do_GET(self) -> None:  # noqa: N802
        if self.path == f"/v2/{self.repo}/tags/list":
            payload = json.dumps({"name": self.repo, "tags": [self.tag]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path in {
            f"/v2/{self.repo}/manifests/{self.tag}",
            f"/v2/{self.repo}/manifests/{self.manifest_digest}",
        }:
            self.send_response(200)
            self.send_header(
                "Content-Type", "application/vnd.oci.image.manifest.v1+json"
            )
            self.send_header("Content-Length", str(len(self.manifest_bytes)))
            self.end_headers()
            self.wfile.write(self.manifest_bytes)
            return
        blob_prefix = f"/v2/{self.repo}/blobs/"
        if self.path.startswith(blob_prefix):
            digest = self.path.removeprefix(blob_prefix)
            blob = self.blobs.get(digest)
            if blob is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)
            return
        self.send_error(404)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        del format, args


class _OCIRegistry:
    def __init__(self, layout_dir: Path, repo: str) -> None:
        index_payload = json.loads((layout_dir / "index.json").read_text(encoding="utf-8"))
        manifest_digest = index_payload["manifests"][0]["digest"]
        tag = index_payload["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"]
        manifest_bytes = (layout_dir / "blobs" / "sha256" / manifest_digest.removeprefix("sha256:")).read_bytes()
        blobs = {
            f"sha256:{blob.name}": blob.read_bytes()
            for blob in (layout_dir / "blobs" / "sha256").iterdir()
        }
        handler = type(
            "Handler",
            (_OCIHandler,),
            {
                "repo": repo,
                "tag": tag,
                "manifest_digest": manifest_digest,
                "manifest_bytes": manifest_bytes,
                "blobs": blobs,
            },
        )
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.host, self.port = self._server.server_address
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "_OCIRegistry":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        del exc_type, exc, tb
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def test_local_path_source_and_locked_imports_compile_equivalently(tmp_path: Path):
    module_path = _local_module(tmp_path / "shared.yaml")
    root_path = _root_import(
        tmp_path / "root-path.yaml",
        "path: shared.yaml\n            namespace: shared",
    )
    root_source = _root_import(
        tmp_path / "root-source.yaml",
        "source: local:shared.yaml\n            namespace: shared\n            version: 1.2.3",
    )
    flat = _flat_equivalent(tmp_path / "flat.yaml")

    runner = CliRunner()
    resolve_result = runner.invoke(app, ["sdl", "resolve", str(root_source)])
    assert resolve_result.exit_code == 0, resolve_result.output
    lockfile = load_lockfile(tmp_path)
    assert lockfile is not None
    record = lockfile.imports[0]

    root_locked = _root_import(
        tmp_path / "root-locked.yaml",
        f"source: locked:{record.resolved_source}\n            namespace: shared",
    )

    path_model = compile_runtime_model(parse_sdl_file(root_path))
    source_model = compile_runtime_model(parse_sdl_file(root_source))
    locked_model = compile_runtime_model(parse_sdl_file(root_locked))
    flat_model = compile_runtime_model(parse_sdl_file(flat))

    assert (
        path_model.node_deployments.keys()
        == source_model.node_deployments.keys()
        == locked_model.node_deployments.keys()
        == flat_model.node_deployments.keys()
    )
    assert (
        path_model.networks.keys()
        == source_model.networks.keys()
        == locked_model.networks.keys()
        == flat_model.networks.keys()
    )
    assert module_path.exists()


def test_local_import_digest_mismatch_fails_closed(tmp_path: Path):
    _local_module(tmp_path / "shared.yaml")
    root = _root_import(
        tmp_path / "root.yaml",
        "source: local:shared.yaml\n            namespace: shared\n            digest: sha256:deadbeef",
    )

    with pytest.raises(SDLParseError, match="Digest mismatch"):
        parse_sdl_file(root)


def test_module_exports_are_enforced_for_importers(tmp_path: Path):
    _write(
        tmp_path / "shared.yaml",
        """
        name: shared
        version: 1.2.3
        module:
          id: acme/shared
          version: 1.2.3
          exports:
            nodes: [vm]
            infrastructure: [vm]
        nodes:
          vm:
            type: vm
            os: linux
            resources: {ram: 1 gib, cpu: 1}
            conditions: {health: ops}
            roles: {ops: operator}
        infrastructure:
          vm: 1
        conditions:
          health: {command: /bin/true, interval: 15}
        """,
    )
    root = _write(
        tmp_path / "root.yaml",
        """
        name: root
        imports:
          - source: local:shared.yaml
            namespace: shared
        metrics:
          uptime:
            type: conditional
            condition: shared.health
            max-score: 100
        """,
    )

    with pytest.raises(SDLValidationError):
        parse_sdl_file(root)


def test_import_cycles_and_namespace_collisions_are_rejected(tmp_path: Path):
    a = _write(
        tmp_path / "a.yaml",
        """
        name: a
        imports:
          - source: local:b.yaml
            namespace: other
        """,
    )
    _write(
        tmp_path / "b.yaml",
        """
        name: b
        imports:
          - source: local:a.yaml
            namespace: other
        """,
    )
    with pytest.raises(SDLParseError, match="Import cycle detected"):
        parse_sdl_file(a)

    _local_module(tmp_path / "one.yaml")
    _local_module(tmp_path / "two.yaml")
    root = _write(
        tmp_path / "collision.yaml",
        """
        name: collision
        imports:
          - source: local:one.yaml
            namespace: shared
          - source: local:two.yaml
            namespace: shared
        """,
    )
    with pytest.raises(SDLParseError, match="collides on nodes"):
        parse_sdl_file(root)


def test_sdl_resolve_and_verify_detect_lockfile_drift(tmp_path: Path):
    _local_module(tmp_path / "shared.yaml")
    root = _root_import(
        tmp_path / "root.yaml",
        "source: local:shared.yaml\n            namespace: shared",
    )
    runner = CliRunner()

    result = runner.invoke(app, ["sdl", "resolve", str(root)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / LOCKFILE_NAME).exists()

    verify = runner.invoke(app, ["sdl", "verify-imports", str(root)])
    assert verify.exit_code == 0, verify.output

    _local_module(tmp_path / "shared.yaml", version="1.2.4")
    stale = runner.invoke(app, ["sdl", "verify-imports", str(root)])
    assert stale.exit_code != 0
    assert "stale" in stale.output.lower()


def test_signed_oci_import_resolution_and_publish_cli(tmp_path: Path):
    module_path = _local_module(tmp_path / "shared.yaml")
    runner = CliRunner()

    private_key = Ed25519PrivateKey.generate()
    private_key_path = tmp_path / "signing-key.pem"
    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    publish = runner.invoke(
        app,
        [
            "sdl",
            "publish",
            str(module_path),
            "--output-dir",
            str(tmp_path / "dist"),
            "--signer-id",
            "test-signer",
            "--private-key",
            str(private_key_path),
        ],
    )
    assert publish.exit_code == 0, publish.output
    publish_payload = json.loads(publish.stdout)
    layout_dir = Path(publish_payload["layout_dir"])

    with _OCIRegistry(layout_dir, repo="acme/shared") as registry:
        _write(
            tmp_path / "aptl-trust.yaml",
            f"""
            schema_version: aptl-trust/v1
            registries:
              "127.0.0.1:{registry.port}":
                require_signatures: true
                allow_insecure_http: true
                trusted_signers:
                  test-signer: "{base64.b64encode(public_key).decode('utf-8')}"
            """,
        )
        root = _root_import(
            tmp_path / "root-oci.yaml",
            f"source: oci:127.0.0.1:{registry.port}/acme/shared\n            namespace: shared\n            version: '>=1.0,<2.0'",
        )
        resolve = runner.invoke(app, ["sdl", "resolve", str(root)])
        assert resolve.exit_code == 0, resolve.output

        lockfile = load_lockfile(tmp_path)
        assert lockfile is not None
        assert lockfile.imports[0].module_version == "1.2.3"

        locked = _root_import(
            tmp_path / "root-locked.yaml",
            f"source: locked:{lockfile.imports[0].resolved_source}\n            namespace: shared",
        )
        flat = _flat_equivalent(tmp_path / "flat.yaml")
        remote_model = compile_runtime_model(parse_sdl_file(root))
        locked_model = compile_runtime_model(parse_sdl_file(locked))
        flat_model = compile_runtime_model(parse_sdl_file(flat))

        assert (
            remote_model.node_deployments.keys()
            == locked_model.node_deployments.keys()
            == flat_model.node_deployments.keys()
        )


def test_untrusted_and_unsigned_oci_imports_fail_closed(tmp_path: Path):
    module_path = _local_module(tmp_path / "shared.yaml")
    unsigned = publish_module_to_oci_layout(module_path, output_dir=tmp_path / "dist")
    layout_dir = Path(unsigned["layout_dir"])

    with _OCIRegistry(layout_dir, repo="acme/shared") as registry:
        root = _root_import(
            tmp_path / "root-oci.yaml",
            f"source: oci:127.0.0.1:{registry.port}/acme/shared\n            namespace: shared\n            version: 1.2.3",
        )
        with pytest.raises(SDLParseError, match="not allowed by trust policy"):
            parse_sdl_file(root)

        _write(
            tmp_path / "aptl-trust.yaml",
            f"""
            schema_version: aptl-trust/v1
            registries:
              "127.0.0.1:{registry.port}":
                require_signatures: true
                allow_insecure_http: true
                trusted_signers: {{}}
            """,
        )
        with pytest.raises(SDLParseError, match="No valid trusted signer signature found"):
            parse_sdl_file(root)
