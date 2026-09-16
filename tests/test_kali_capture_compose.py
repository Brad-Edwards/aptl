"""Static least-intrusion checks for the admitted Kali capture sidecar."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import time
import uuid

import pytest
import yaml

from aptl.core.deployment._compose_capture_apparatus import _KALI_INGRESS_RELOCATION

_ROOT = Path(__file__).parent.parent


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=30
        ).returncode
        == 0
    )


@pytest.fixture(scope="module")
def capture_image():
    if not _docker_available():
        pytest.skip("docker daemon not available")
    image = "aptl-kali-capture-test-" + uuid.uuid4().hex
    built = subprocess.run(
        [
            "docker",
            "build",
            "-t",
            image,
            "-f",
            "containers/kali-capture/Dockerfile",
            ".",
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if built.returncode != 0:
        pytest.fail("kali capture integration image failed to build")
    try:
        yield image
    finally:
        subprocess.run(
            ["docker", "image", "rm", "-f", image],
            capture_output=True,
            text=True,
            timeout=120,
        )


def _capture_service() -> dict:
    document = yaml.safe_load((_ROOT / "docker-compose.capture.yml").read_text())
    return document["services"]["kali-capture"]


def _generate_ed25519_key(path: Path) -> None:
    if shutil.which("ssh-keygen") is None:
        pytest.skip("ssh-keygen is not available")
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_capture_sidecar_owns_sink_with_only_ssh_daemon_capabilities():
    service = _capture_service()

    assert service["network_mode"] == "container:aptl-kali"
    assert not service.get("ports")
    assert set(service["cap_add"]) == {
        "CHOWN",
        "DAC_OVERRIDE",
        "NET_BIND_SERVICE",
        "SETGID",
        "SETUID",
        "SYS_CHROOT",
    }
    assert not {
        "AUDIT_CONTROL",
        "AUDIT_WRITE",
        "SYS_PACCT",
        "NET_RAW",
        "NET_ADMIN",
    } & set(service["cap_add"])
    assert "pid" not in service
    assert service.get("read_only") is True
    assert "ALL" in service["cap_drop"]


def test_capture_sidecar_has_only_required_writable_filesystems():
    service = _capture_service()
    mounts = service["volumes"]
    capture = next(item for item in mounts if item["source"] == "kali_captures")
    keys = [item for item in mounts if str(item["source"]).startswith("generated:")]

    assert capture == {
        "type": "volume",
        "source": "kali_captures",
        "target": "/var/log/aptl/captures",
    }
    assert {item["source"] for item in keys} == {
        "generated:kali-pivot-private-key",
        "generated:kali-authorized-keys",
    }
    assert {item["target"] for item in keys} == {
        "/run/aptl-source/inner_key",
        "/run/aptl-source/outer_authorized_keys",
    }
    assert not any("operator-private-key" in str(item["source"]) for item in mounts)
    assert all(item["read_only"] is True for item in keys)
    assert set(service["tmpfs"]) == {"/run", "/tmp"}


def test_capture_sidecar_sets_key_mode_before_dropping_file_ownership():
    entrypoint = (_ROOT / "containers" / "kali-capture" / "entrypoint.sh").read_text()

    install = "install -m 0400 /run/aptl-source/inner_key /run/aptl-inner/id_ed25519"
    chown = "chown kali:kali /run/aptl-inner/id_ed25519"
    assert install in entrypoint
    assert chown in entrypoint
    assert entrypoint.index(install) < entrypoint.index(chown)
    assert "install -m 0400 -o kali" not in entrypoint
    assert "install -d -m 0755 /run/sshd" in entrypoint


@pytest.mark.integration
def test_capture_entrypoint_applies_key_ownership_with_declared_capabilities(
    capture_image, tmp_path
):
    inner_key = tmp_path / "inner_key"
    authorized_keys = tmp_path / "authorized_keys"
    inner_key.write_text("private-test-key\n")
    authorized_keys.write_text("ssh-ed25519 AAAATEST aptl-test\n")
    inner_key.chmod(0o400)
    authorized_keys.chmod(0o444)
    container = "aptl-capture-entrypoint-test-" + uuid.uuid4().hex
    command = [
        "docker",
        "run",
        "-d",
        "--name",
        container,
        "--read-only",
        "--tmpfs",
        "/run:rw,nosuid,nodev,size=16m",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=16m",
        "--tmpfs",
        "/var/log:rw,nosuid,nodev,size=16m",
        "--cap-drop",
        "ALL",
    ]
    for capability in (
        "CHOWN",
        "DAC_OVERRIDE",
        "NET_BIND_SERVICE",
        "SETGID",
        "SETUID",
        "SYS_CHROOT",
    ):
        command.extend(("--cap-add", capability))
    command.extend(
        (
            "--security-opt",
            "no-new-privileges:true",
            "--mount",
            f"type=bind,src={inner_key},dst=/run/aptl-source/inner_key,readonly",
            "--mount",
            "type=bind,"
            f"src={authorized_keys},"
            "dst=/run/aptl-source/outer_authorized_keys,readonly",
            capture_image,
        )
    )
    created = subprocess.run(
        command, capture_output=True, text=True, check=True, timeout=120
    )
    container_id = created.stdout.strip()
    try:
        observed = None
        for _attempt in range(30):
            observed = subprocess.run(
                [
                    "docker",
                    "exec",
                    container_id,
                    "stat",
                    "-c",
                    "%U:%G %a",
                    "/run/aptl-inner/id_ed25519",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if observed.returncode == 0:
                break
            time.sleep(0.2)
        assert observed is not None
        assert observed.returncode == 0
        assert observed.stdout.strip() == "kali:kali 400"
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container_id],
            capture_output=True,
            text=True,
            timeout=120,
        )


@pytest.mark.integration
def test_capture_sidecar_accepts_a_real_kali_session_and_preserves_identity(
    capture_image, tmp_path
):
    if shutil.which("ssh") is None:
        pytest.skip("ssh client is not available")
    inner_key = tmp_path / "inner_key"
    outer_key = tmp_path / "outer_key"
    _generate_ed25519_key(inner_key)
    _generate_ed25519_key(outer_key)
    container = "aptl-capture-session-test-" + uuid.uuid4().hex
    command = [
        "docker",
        "run",
        "-d",
        "--name",
        container,
        "--read-only",
        "--tmpfs",
        "/run:rw,nosuid,nodev,size=32m",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=16m",
        "--tmpfs",
        "/var/log:rw,nosuid,nodev,size=32m",
        "--tmpfs",
        "/home/kali:rw,nosuid,nodev,size=16m",
        "--cap-drop",
        "ALL",
    ]
    for capability in (
        "CHOWN",
        "DAC_OVERRIDE",
        "NET_BIND_SERVICE",
        "SETGID",
        "SETUID",
        "SYS_CHROOT",
    ):
        command.extend(("--cap-add", capability))
    # The integration fixture co-locates the *inner target sshd* in this one
    # container. Production runs that daemon in aptl-kali, whose ordinary
    # Docker capability set includes these; neither capability is present in
    # the capture-sidecar declaration verified by the static tests above.
    command.extend(("--cap-add", "AUDIT_WRITE", "--cap-add", "KILL"))
    command.extend(
        (
            "--security-opt",
            "no-new-privileges:true",
            "-p",
            "127.0.0.1::22",
            "--mount",
            f"type=bind,src={inner_key},dst=/run/aptl-source/inner_key,readonly",
            "--mount",
            f"type=bind,src={inner_key}.pub,dst=/run/aptl-source/inner_key.pub,readonly",
            "--mount",
            f"type=bind,src={outer_key}.pub,dst=/run/aptl-source/outer_authorized_keys,readonly",
            capture_image,
        )
    )
    created = subprocess.run(
        command, capture_output=True, text=True, check=True, timeout=120
    )
    container_id = created.stdout.strip()
    try:
        state = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", container_id],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if state.stdout.strip() != "true":
            logs = subprocess.run(
                ["docker", "logs", container_id],
                capture_output=True,
                text=True,
                timeout=30,
            )
            pytest.fail(f"capture container exited during startup: {logs.stderr}")
        inner_setup = """
set -eu
chown kali:kali /home/kali
install -d -m 0700 /home/kali/.ssh
chown kali:kali /home/kali/.ssh
install -m 0600 /run/aptl-source/inner_key.pub /home/kali/.ssh/authorized_keys
chown kali:kali /home/kali/.ssh/authorized_keys
install -d -m 0755 /run/sshd
ssh-keygen -q -t ed25519 -N '' -f /run/aptl-sshd/inner_host_key
cat > /run/aptl-sshd/inner_sshd_config <<'EOF'
Port 2222
ListenAddress 127.0.0.1
HostKey /run/aptl-sshd/inner_host_key
PidFile /run/aptl-sshd/inner_sshd.pid
AuthorizedKeysFile /home/kali/.ssh/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers kali
UsePAM no
PermitTTY yes
EOF
/usr/sbin/sshd -f /run/aptl-sshd/inner_sshd_config
""".strip()
        setup_result = subprocess.run(
            ["docker", "exec", "-i", container_id, "sh", "-s"],
            input=inner_setup,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert setup_result.returncode == 0, setup_result.stderr
        inner_connection = subprocess.run(
            [
                "docker",
                "exec",
                "--user",
                "kali",
                container_id,
                "ssh",
                "-i",
                "/run/aptl-inner/id_ed25519",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-p",
                "2222",
                "kali@127.0.0.1",
                "printf inner-ok",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert inner_connection.returncode == 0, inner_connection.stderr
        assert inner_connection.stdout == "inner-ok"
        activation = subprocess.run(
            [
                "docker",
                "exec",
                container_id,
                "python3",
                "/usr/local/bin/broker.py",
                "activate",
                "--run-id",
                "run-1",
                "--plan-id",
                "capture-plan-1",
                "--binding-id",
                "aptl.collector.redteam-session-transcript",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if activation.returncode != 0:
            logs = subprocess.run(
                ["docker", "logs", container_id],
                capture_output=True,
                text=True,
                timeout=30,
            )
            pytest.fail(
                "capture activation failed: "
                f"stdout={activation.stdout!r} stderr={activation.stderr!r} "
                f"logs={logs.stderr!r}"
            )
        ready = None
        for _attempt in range(60):
            ready = subprocess.run(
                [
                    "docker",
                    "exec",
                    container_id,
                    "python3",
                    "/usr/local/bin/broker.py",
                    "status",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if ready.returncode == 0:
                break
            time.sleep(0.2)
        if ready is None or ready.returncode != 0:
            logs = subprocess.run(
                ["docker", "logs", container_id],
                capture_output=True,
                text=True,
                timeout=30,
            )
            pytest.fail(
                f"capture SSH daemon did not become ready: {ready!r}; "
                f"logs={logs.stderr!r}"
            )
        exact_inner = subprocess.run(
            [
                "docker",
                "exec",
                "--user",
                "kali",
                container_id,
                "ssh",
                "-tt",
                "-p",
                "2222",
                "-i",
                "/run/aptl-inner/id_ed25519",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "UserKnownHostsFile=/run/aptl-inner/known_hosts",
                "kali@127.0.0.1",
                "printf exact-inner-ok",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if exact_inner.returncode != 0:
            pytest.fail(f"exact inner SSH failed: {exact_inner.stderr!r}")
        assert "exact-inner-ok" in exact_inner.stdout
        port_result = subprocess.run(
            ["docker", "port", container_id, "22/tcp"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        port = port_result.stdout.strip().rsplit(":", 1)[-1]
        environment = {
            **os.environ,
            "APTL_SESSION_ID": "session-1",
            "APTL_RUN_ID": "run-1",
            "APTL_TRACE_ID": "run-1",
        }
        connected = subprocess.run(
            [
                "ssh",
                "-i",
                str(outer_key),
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "SendEnv=APTL_SESSION_ID APTL_RUN_ID APTL_TRACE_ID",
                "-p",
                port,
                "kali@127.0.0.1",
                "printf capture-ok",
            ],
            capture_output=True,
            text=True,
            env=environment,
            timeout=30,
        )
        if connected.returncode != 0:
            logs = subprocess.run(
                ["docker", "logs", container_id],
                capture_output=True,
                text=True,
                timeout=30,
            )
            capture_state = subprocess.run(
                [
                    "docker",
                    "exec",
                    container_id,
                    "sh",
                    "-c",
                    "find /run/aptl-capture /var/log/aptl/captures -ls; "
                    "python3 /usr/local/bin/broker.py export",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            pytest.fail(
                f"brokered SSH failed: stdout={connected.stdout!r} "
                f"stderr={connected.stderr!r} logs={logs.stderr!r} "
                f"capture_stdout={capture_state.stdout!r} "
                f"capture_stderr={capture_state.stderr!r}"
            )
        assert "capture-ok" in connected.stdout
        subprocess.run(
            [
                "docker",
                "exec",
                container_id,
                "python3",
                "/usr/local/bin/broker.py",
                "quiesce",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=45,
        )
        exported = subprocess.run(
            [
                "docker",
                "exec",
                container_id,
                "python3",
                "/usr/local/bin/broker.py",
                "export",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        payload = json.loads(exported.stdout)
        assert payload["accepted_session_ids"] == ["session-1"]
        assert [item["session_id"] for item in payload["sessions"]] == ["session-1"]
        ownership = subprocess.run(
            [
                "docker",
                "exec",
                container_id,
                "stat",
                "-c",
                "%U:%G %a",
                "/run/aptl-capture",
                "/run/aptl-inner",
                "/var/log/aptl/captures",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        assert ownership.stdout.splitlines() == ["kali:kali 700"] * 3
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container_id],
            capture_output=True,
            text=True,
            timeout=120,
        )


@pytest.mark.integration
def test_kali_ingress_relocation_produces_the_admitted_sshd_configuration(
    capture_image,
):
    public_key = "ssh-ed25519 AAAATEST aptl-kali-pivot"
    setup = """
mkdir -p /run/sshd /home/kali/.ssh
touch /home/kali/.ssh/authorized_keys
chown -R kali:kali /home/kali/.ssh
ssh-keygen -A
cat > /usr/local/bin/systemctl <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 /usr/local/bin/systemctl
""".strip()
    inspect = """
printf 'mode='
stat -c '%U:%G %a' /home/kali/.ssh/authorized_keys
sshd -T | grep -E '^(port|listenaddress) '
""".strip()
    script = "\n".join(
        (
            setup,
            _KALI_INGRESS_RELOCATION.format(pivot_public_key=shlex.quote(public_key)),
            inspect,
        )
    )

    result = subprocess.run(
        ["docker", "run", "--rm", "-i", "--entrypoint", "sh", capture_image, "-s"],
        input=script,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, result.stderr
    assert "mode=kali:kali 600" in result.stdout
    assert "port 2222" in result.stdout
    assert "listenaddress 127.0.0.1:2222" in result.stdout


def test_capture_sidecar_is_not_part_of_unadmitted_base_compose():
    base = yaml.safe_load((_ROOT / "docker-compose.yml").read_text())

    assert "kali-capture" not in base["services"]
    assert "kali_captures" not in base.get("volumes", {})
