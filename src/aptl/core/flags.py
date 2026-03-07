"""CTF flag collection and verification.

Reads dynamically generated CTF flags from running lab containers and
provides token-based signature verification for automated scoring.
"""

import hashlib
import re
import subprocess
from dataclasses import dataclass

from aptl.utils.logging import get_logger

log = get_logger("flags")

# Default signing key (known to scoring engine).
DEFAULT_FLAG_KEY = "aptl-flag-key-2024"

# Flag file locations per container.  Maps docker container name to
# a dict of {level: (flag_path, description)}.
FLAG_LOCATIONS: dict[str, dict[str, tuple[str, str]]] = {
    "aptl-victim": {
        "user": ("/home/labadmin/user.txt", "RCE on victim"),
        "root": ("/root/root.txt", "Privesc on victim"),
    },
    "aptl-workstation": {
        "user": ("/home/dev-user/user.txt", "Access workstation"),
        "root": ("/root/root.txt", "Privesc on workstation"),
    },
    "aptl-webapp": {
        "user": ("/app/user.txt", "RCE on webapp"),
        "root": ("/root/root.txt", "Privesc on webapp"),
    },
    "aptl-ad": {
        "user": ("/opt/flags/user.txt", "AD user compromise"),
        "root": ("/root/root.txt", "Domain admin"),
    },
    "aptl-fileshare": {
        "user": ("/srv/shares/shared/user-flag.txt", "SMB access"),
        "root": ("/root/root.txt", "Privesc on fileshare"),
    },
}

# Regex to extract flag and token from a flag file.
_FLAG_RE = re.compile(r"Flag:\s+(APTL\{[^}]+\})")
_TOKEN_RE = re.compile(r"Token:\s+(aptl:v1:\S+)")


@dataclass
class CapturedFlag:
    """A single captured CTF flag with its signed token."""

    flag: str
    token: str
    path: str
    container: str
    level: str
    description: str


def _docker_exec_read(container: str, path: str) -> str | None:
    """Read a file from a running container. Returns None on failure."""
    try:
        result = subprocess.run(
            ["docker", "exec", container, "cat", path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout
    except (subprocess.TimeoutExpired, OSError) as e:
        log.debug("Failed to read %s:%s: %s", container, path, e)
    return None


def _parse_flag_file(content: str) -> tuple[str, str] | None:
    """Extract (flag, token) from flag file content."""
    flag_match = _FLAG_RE.search(content)
    token_match = _TOKEN_RE.search(content)
    if flag_match and token_match:
        return flag_match.group(1), token_match.group(1)
    return None


def collect_flags(
    containers: list[str] | None = None,
) -> dict[str, dict[str, dict]]:
    """Collect CTF flags from running lab containers.

    Args:
        containers: Optional list of container names to collect from.
            If None, collects from all known containers.

    Returns:
        Nested dict: {container_name: {level: {flag, token, path, description}}}.
        Only includes containers/levels where the flag was successfully read.
    """
    targets = containers or list(FLAG_LOCATIONS.keys())
    result: dict[str, dict[str, dict]] = {}

    for container in targets:
        if container not in FLAG_LOCATIONS:
            continue

        levels = FLAG_LOCATIONS[container]
        container_flags: dict[str, dict] = {}

        for level, (path, description) in levels.items():
            content = _docker_exec_read(container, path)
            if content is None:
                log.warning(
                    "Could not read %s flag from %s:%s",
                    level, container, path,
                )
                continue

            parsed = _parse_flag_file(content)
            if parsed is None:
                log.warning(
                    "Could not parse flag from %s:%s",
                    container, path,
                )
                continue

            flag, token = parsed
            container_flags[level] = {
                "flag": flag,
                "token": token,
                "path": path,
                "description": description,
            }

        if container_flags:
            result[container] = container_flags

    log.info(
        "Collected flags from %d containers (%d total)",
        len(result),
        sum(len(v) for v in result.values()),
    )
    return result


def verify_token(token: str, key: str = DEFAULT_FLAG_KEY) -> bool:
    """Verify a signed flag token.

    Token format: aptl:v1:<hostname>:<level>:<nonce>:<signature>
    Signature: md5(key:hostname:level:nonce)

    Args:
        token: The token string to verify.
        key: The signing key.

    Returns:
        True if the signature is valid.
    """
    parts = token.split(":")
    if len(parts) != 6 or parts[0] != "aptl" or parts[1] != "v1":
        return False

    _, _, hostname, level, nonce, signature = parts
    expected = hashlib.md5(
        f"{key}:{hostname}:{level}:{nonce}".encode()
    ).hexdigest()
    return signature == expected
