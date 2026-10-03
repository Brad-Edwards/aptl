#!/usr/bin/env python3
"""Start the browser desktop from one disposable seat overlay."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

SOURCE = Path("/opt/aptl/desktop")
RUNTIME = Path("/var/lib/aptl/overlay/desktop")
ADMIN_PASSWORD = Path("/var/lib/aptl/overlay/desktop-admin-password")


def connection_sql(rdp_password: str) -> str:
    """Grant the fixed browser identity one RDP connection."""

    if not rdp_password or any(c in rdp_password for c in "\x00\r\n"):
        raise ValueError("RDP password is invalid")
    password_hex = rdp_password.encode("utf-8").hex()
    return f"""
INSERT INTO guacamole_entity (name, type) VALUES ('participant', 'USER');
INSERT INTO guacamole_user (entity_id, password_hash, password_date)
SELECT entity_id, decode('{secrets.token_hex(32)}', 'hex'), CURRENT_TIMESTAMP
FROM guacamole_entity WHERE name = 'participant' AND type = 'USER';
INSERT INTO guacamole_connection (connection_name, protocol)
VALUES ('Seat Desktop', 'rdp');
INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value)
SELECT connection_id, parameter_name, parameter_value FROM guacamole_connection,
(VALUES ('hostname', 'host.docker.internal'), ('port', '3389'),
        ('username', 'aptl'), ('password', convert_from(decode('{password_hex}', 'hex'), 'UTF8')),
        ('security', 'any'), ('ignore-cert', 'true'),
        ('color-depth', '16'), ('resize-method', 'display-update'))
AS parameters(parameter_name, parameter_value)
WHERE connection_name = 'Seat Desktop';
INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)
SELECT entity_id, connection_id, 'READ'::guacamole_object_permission_type
FROM guacamole_entity, guacamole_connection
WHERE name = 'participant' AND type = 'USER' AND connection_name = 'Seat Desktop';
"""


def _write_private(path: Path, data: str) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _credentials() -> dict[str, str]:
    RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = RUNTIME / "credentials.json"
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("invalid desktop credentials path")
        values = json.loads(path.read_text(encoding="utf-8"))
    else:
        values = {"database": secrets.token_hex(32), "rdp": secrets.token_hex(32)}
        _write_private(path, json.dumps(values, sort_keys=True))
    if ADMIN_PASSWORD.exists():
        info = ADMIN_PASSWORD.stat()
        if ADMIN_PASSWORD.is_symlink() or info.st_uid != 0 or info.st_mode & 0o077:
            raise RuntimeError("administrative password file is unsafe")
        values["rdp"] = ADMIN_PASSWORD.read_text(encoding="utf-8")
    if (set(values) != {"database", "rdp"}
            or not isinstance(values["database"], str)
            or len(values["database"]) != 64
            or any(c not in "0123456789abcdef" for c in values["database"])
            or not isinstance(values["rdp"], str)
            or not values["rdp"]
            or any(c in values["rdp"] for c in "\x00\r\n")):
        raise RuntimeError("invalid desktop credentials")
    return values


def prepare() -> dict[str, str]:
    """Materialize private configuration without modifying the golden disk."""

    values = _credentials()
    initdb = RUNTIME / "initdb"
    initdb.mkdir(mode=0o700, exist_ok=True)
    shutil.copyfile(SOURCE / "guac-schema.sql", initdb / "001-schema.sql")
    shutil.copyfile(SOURCE / "desktop-compose.yml", RUNTIME / "compose.yml")
    shutil.copyfile(SOURCE / "desktop-nginx.conf", RUNTIME / "nginx.conf")
    _write_private(initdb / "002-seat.sql", connection_sql(values["rdp"]))
    # The pinned postgres:alpine image runs its database process as UID 70.
    # Let only that account read the password-bearing one-time seed.
    for path in (initdb, initdb / "001-schema.sql", initdb / "002-seat.sql"):
        os.chown(path, 70, 70)
        os.chmod(path, 0o700 if path == initdb else 0o600)
    _write_private(
        RUNTIME / "desktop.env", f"APTL_GUAC_DB_PASSWORD={values['database']}\n"
    )
    subprocess.run(
        ["chpasswd"], input=f"aptl:{values['rdp']}\n", text=True,
        capture_output=True, check=True,
    )
    return values


def main() -> None:
    prepare()
    subprocess.run(["systemctl", "start", "xrdp"], check=True)
    subprocess.run(
        ["docker", "compose", "--env-file", str(RUNTIME / "desktop.env"),
         "-f", str(RUNTIME / "compose.yml"), "up", "-d", "--wait",
         "--wait-timeout", "180"],
        check=True,
    )
    deadline = time.monotonic() + 120
    while True:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8080/", timeout=3) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError("desktop gateway did not become ready")
        time.sleep(1)


if __name__ == "__main__":
    main()
