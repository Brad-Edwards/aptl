"""Real OpenSSH and built MCP interoperability, without a deployed lab.

Run after mcp/build-all-mcps.sh. Runtime identity/capture observations are test
fixtures, not evidence of full TechVault boot or production qualification.
"""

import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import pytest

from aptl.workbench.access_clients import client_entries
from aptl.workbench.client_files import publish_client_config
from aptl.workbench.dispatch import key_fingerprint, restricted_key, sshd_policy
from aptl.workbench.guest_binding import GuestDispatchBinding
from tests.test_mcp_access import access_record, grant

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform != "linux", reason="dedicated OpenSSH process requires Linux"
    ),
]
REPO = Path(__file__).resolve().parents[1]


def private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


class Transport:
    def __init__(self, root, node, sshd, keygen):
        self.root = root
        self.clients = root / "client"
        self.clients.mkdir(mode=0o700)
        for name in ("host_key", "client_key"):
            subprocess.run(
                [keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)],
                check=True,
            )
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        public = (root / "host_key.pub").read_text().strip()
        client_public = (root / "client_key.pub").read_text().strip()
        self.record = access_record(
            outer_endpoint=dict(address="127.0.0.1", port=self.port),
            host_key_fingerprint=key_fingerprint(public),
        )
        self.grant = grant(public_key_fingerprint=key_fingerprint(client_public))
        self.binding = GuestDispatchBinding(
            schema_version="aptl.mcp-dispatch/v1",
            access=self.record,
            grants=(self.grant,),
            project_dir=root,
            node_executable=Path(node),
            management_home=root,
            docker_socket=root / "unused-docker.sock",
            run_id="c" * 32,
            delivery="rootful-integration",
        )
        self.binding_path = root / "binding.json"
        self.write_binding()
        private_json(
            root / "observation.json",
            dict(
                boot_id=self.record.guest_boot_id,
                daemon_id=self.record.guest_daemon_id,
                project=self.record.guest_project,
                containers=self.record.container_ids,
                run_id=self.binding.run_id,
                capture=dict(ready=True, run_id=self.binding.run_id),
            ),
        )
        private_json(
            root / "processes.json",
            {
                "aptl-red": dict(
                    argv=[node, str(REPO / "mcp/mcp-red/build/index.js")],
                    cwd=str(root),
                    env={
                        "PATH": os.defpath,
                        "HOME": str(root),
                        "APTL_MCP_DISABLE_DOTENV": "1",
                        "APTL_HP_KALI_SSH_PROXY_2023": "2023",
                        "APTL_STATE_DIR": str(root / ".aptl"),
                        "APTL_MCP_ADMITTED_RUN_ID": self.binding.run_id,
                    },
                )
            },
        )
        executable = root / "dispatch"
        executable.write_text(
            "#!/bin/sh\nexec "
            + shlex.quote(sys.executable)
            + " -P "
            + shlex.quote(str(REPO / "tests/fixtures/mcp_transport_dispatch.py"))
            + ' "$@"\n'
        )
        executable.chmod(0o700)
        (root / "authorized_keys").write_text(
            restricted_key(
                public_key=client_public,
                executable=executable,
                binding=self.binding_path,
                grant_id=self.grant.grant_id,
            )
        )
        (root / "authorized_keys").chmod(0o600)
        username = pwd.getpwuid(os.getuid()).pw_name
        config = root / "sshd_config"
        config.write_text(
            sshd_policy(
                port=self.port,
                username=username,
                host_key=root / "host_key",
                authorized_keys=root / "authorized_keys",
            )
            + f"PidFile {root / 'sshd.pid'}\n"
        )
        self.log = (root / "sshd.log").open("w")
        self.listener = subprocess.Popen(
            [sshd, "-D", "-e", "-f", str(config)],
            stdout=self.log,
            stderr=self.log,
        )
        known = self.clients / "known_hosts"
        known.write_text(f"[127.0.0.1]:{self.port} {public}\n")
        known.chmod(0o600)
        self.entries = client_entries(
            self.record,
            self.grant,
            ssh_executable=Path(shutil.which("ssh")),
            identity_file=root / "client_key",
            known_hosts=known,
            username=username,
        )
        for client in ("claude", "codex"):
            publish_client_config(self.clients, client, self.record, self.entries)

    def write_binding(self):
        self.binding_path.write_text(self.binding.model_dump_json())
        self.binding_path.chmod(0o600)

    def connect(self, selector=None, server="red"):
        entry = self.entries["aptl-seat-1-" + server]
        args = list(entry["args"])
        if selector is not None:
            args[-1] = selector
        return subprocess.Popen(
            [entry["command"], *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def close(self):
        self.listener.terminate()
        self.listener.wait(timeout=10)
        self.log.close()


@pytest.fixture
def transport():
    node, sshd, keygen = (shutil.which(name) for name in ("node", "sshd", "ssh-keygen"))
    if (
        not all((node, sshd, keygen))
        or not (REPO / "mcp/mcp-red/build/index.js").is_file()
    ):
        pytest.fail(
            "Build the MCPs and install Node/OpenSSH before this integration test"
        )
    if os.getuid() == 0:
        pytest.skip(
            "Run as an ordinary user; the production listener forbids root login"
        )
    # StrictModes requires safe ancestors; never change the user's home permissions.
    with tempfile.TemporaryDirectory(
        prefix=".aptl-mcp-test-", dir=Path.home()
    ) as directory:
        test = Transport(Path(directory), node, sshd, keygen)
        try:
            for _ in range(50):
                if test.listener.poll() is not None:
                    pytest.fail((test.root / "sshd.log").read_text())
                try:
                    with socket.create_connection(
                        ("127.0.0.1", test.port), timeout=0.1
                    ):
                        break
                except OSError:
                    time.sleep(0.05)
            yield test
        finally:
            test.close()


def request(process, method, identifier, params):
    import select

    process.stdin.write(
        json.dumps(dict(jsonrpc="2.0", id=identifier, method=method, params=params))
        + "\n"
    )
    process.stdin.flush()
    assert select.select([process.stdout], [], [], 15)[0], "MCP response timed out"
    line = process.stdout.readline()
    assert line, process.stderr.read()
    result = json.loads(line)
    assert "error" not in result, result
    return result["result"]


def initialize(process):
    return request(
        process,
        "initialize",
        1,
        dict(
            protocolVersion="2024-11-05",
            capabilities={},
            clientInfo=dict(name="transport-test", version="1"),
        ),
    )


def test_real_ssh_relay_and_mcp_reject_role_escape_and_revoke(transport):
    process = transport.connect()
    try:
        assert initialize(process)["capabilities"] == {"tools": {}}
        from jsonschema import Draft202012Validator

        inventory = request(process, "tools/list", 2, {})
        for tool in inventory["tools"]:
            Draft202012Validator.check_schema(tool["inputSchema"])
        result = request(process, "tools/call", 3, dict(name="kali_info", arguments={}))
        info = json.loads(result["content"][0]["text"])
        assert info["target_name"] == "Kali Linux"
        assert info["ssh_user"] == "kali"
        transport.binding = transport.binding.model_copy(
            update={"grants": (transport.grant.model_copy(update={"revoked": True}),)}
        )
        transport.write_binding()
        process.wait(timeout=15)
        assert process.stdout.read() == ""
    finally:
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=10)
    transport.binding = transport.binding.model_copy(
        update={"grants": (transport.grant,)}
    )
    transport.write_binding()
    for selector in (
        "bash",
        "aptl-mcp-v1 instance-1 1 aptl-indexer",
        "aptl-mcp-v1 replacement 1 aptl-red",
    ):
        denied = transport.connect(selector)
        stdout, _ = denied.communicate(timeout=15)
        assert denied.returncode != 0
        assert stdout == ""


def test_real_transport_rejects_changed_runtime_identity(transport):
    observed = json.loads((transport.root / "observation.json").read_text())
    observed["containers"] = {"kali": "d" * 64}
    private_json(transport.root / "observation.json", observed)
    denied = transport.connect()
    stdout, _ = denied.communicate(timeout=15)
    assert denied.returncode != 0
    assert stdout == ""


def test_browser_terminal_uses_real_mcp_and_checks_role(transport, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    from aptl.workbench import guest_binding
    from aptl.workbench.app import BrowserPrincipal
    from aptl.workbench.browser_mcp import attach_browser_mcp
    from tests.fixtures.mcp_transport_dispatch import launch, observe

    monkeypatch.setattr(guest_binding, "observe_guest", observe)
    monkeypatch.setattr(guest_binding.GuestAdmission, "launch", launch)
    cleanups = []
    original_cleanup = guest_binding.GuestAdmission.cleanup

    def cleanup(admission, clean):
        cleanups.append(clean)
        original_cleanup(admission, clean)

    monkeypatch.setattr(guest_binding.GuestAdmission, "cleanup", cleanup)
    caller = [BrowserPrincipal(transport.grant.grant_id, ("red",))]
    app = FastAPI()
    attach_browser_mcp(
        app,
        binding_path=transport.binding_path,
        grant_id=transport.grant.grant_id,
        authorizer=lambda _: caller[0],
        guide="<script>untrusted guide</script>",
    )
    with TestClient(app) as client:
        assert "&lt;script&gt;" in client.get("/guide/").text
        assert client.get("/desktop/kali/").status_code == 200
        with client.websocket_connect("/workbench/mcp/aptl-red") as ws:
            ws.send_json(
                dict(
                    jsonrpc="2.0",
                    id=1,
                    method="initialize",
                    params=dict(
                        protocolVersion="2024-11-05",
                        capabilities={},
                        clientInfo=dict(name="browser-test", version="1"),
                    ),
                )
            )
            assert ws.receive_json()["result"]["capabilities"] == {"tools": {}}
            ws.send_json(
                dict(
                    jsonrpc="2.0",
                    id=2,
                    method="tools/call",
                    params=dict(
                        name="kali_info",
                        arguments={},
                    ),
                )
            )
            info = json.loads(ws.receive_json()["result"]["content"][0]["text"])
            assert info["target_name"] == "Kali Linux"
        caller[0] = BrowserPrincipal(transport.grant.grant_id, ("blue",))
        assert client.get("/desktop/kali/").status_code == 403
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/workbench/mcp/aptl-red"):
                pass
    assert cleanups == [True]


def test_blue_indexer_process_queries_controlled_https_service(transport):
    import base64
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import ssl
    import threading

    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            hits.append((self.path, self.headers.get("Authorization"), body))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"hits":{"hits":[{"_id":"transport-proof"}]}}')

        def log_message(self, *_):
            pass

    root = transport.root
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(root / "https.key"),
            "-out",
            str(root / "https.crt"),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "https.crt", root / "https.key")
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    upstream.socket = context.wrap_socket(upstream.socket, server_side=True)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    transport.grant = transport.grant.model_copy(update={"profile": "blue"})
    transport.binding = transport.binding.model_copy(
        update={"grants": (transport.grant,)}
    )
    transport.write_binding()
    transport.entries = client_entries(
        transport.record,
        transport.grant,
        ssh_executable=Path(shutil.which("ssh")),
        identity_file=root / "client_key",
        known_hosts=transport.clients / "known_hosts",
        username=pwd.getpwuid(os.getuid()).pw_name,
    )
    processes = json.loads((root / "processes.json").read_text())
    process_config = processes.pop("aptl-red")
    process_config["argv"][1] = str(REPO / "mcp/mcp-indexer/build/index.js")
    process_config["env"].update(
        {
            "APTL_HP_WAZUH_INDEXER_9200": str(upstream.server_port),
            "APTL_HP_WAZUH_MANAGER_55000": str(upstream.server_port),
            "INDEXER_USERNAME": "test-user",
            "INDEXER_PASSWORD": "test-password",
            "API_USERNAME": "test-user",
            "API_PASSWORD": "test-password",
        }
    )
    private_json(root / "processes.json", {"aptl-indexer": process_config})
    process = transport.connect(server="indexer")
    try:
        initialize(process)
        response = request(
            process,
            "tools/call",
            2,
            dict(
                name="indexer_query",
                arguments={"body": {"size": 1}},
            ),
        )
        assert "transport-proof" in json.dumps(response)
        assert len(hits) == 1
        assert hits[0][0] == "/wazuh-alerts-4.x-*/_search"
        assert (
            hits[0][1]
            == "Basic " + base64.b64encode(b"test-user:test-password").decode()
        )
        assert hits[0][2]["size"] == 1
    finally:
        process.communicate(timeout=15)
        upstream.shutdown()
        thread.join(timeout=5)
        upstream.server_close()
