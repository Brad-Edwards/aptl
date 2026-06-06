#!/usr/bin/env python3
"""Generate scenarios/techvault/nodes/wazuh-indexer.sdl.yaml from the captured
evidence bundle in this directory.

This is a one-shot evidence-to-SDL transformer, not a runtime tool. Run it after
``capture-evidence.sh`` to refresh the SDL node file. The generated YAML is
deterministic given the same evidence inputs; commit the YAML, not the
intermediate dictionaries.
"""

from __future__ import annotations

import gzip
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ASSET_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = ASSET_DIR / "evidence"
REPO_ROOT = ASSET_DIR.parents[3]
OUTPUT = REPO_ROOT / "scenarios" / "techvault" / "nodes" / "wazuh-indexer.sdl.yaml"

IMAGE_DIGEST = "wazuh/wazuh-indexer@sha256:3691b3b27658695aad0c6879b412a001caf233ebbc1a5ba15647053aa03a2299"


def load_json(name: str) -> Any:
    path = EVIDENCE_DIR / name
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as fh:
        return json.load(fh)


def runtime_section(name: str) -> list[str]:
    text = (EVIDENCE_DIR / "runtime-baseline.txt").read_text(encoding="utf-8")
    marker = f"--{name}--\n"
    if marker not in text:
        return []
    _, rest = text.split(marker, 1)
    next_marker = re.search(r"\n--[a-z0-9-]+--\n", rest)
    section = rest[: next_marker.start()] if next_marker else rest
    return [line for line in section.strip().splitlines() if line]


def indexer_state_section(name: str) -> str:
    text = (EVIDENCE_DIR / "wazuh-indexer-state.txt").read_text(encoding="utf-8")
    marker = f"--{name}--"
    if marker not in text:
        return ""
    # The capture writes ``echo --foo--`` between sections, so every marker
    # begins with ``--``.  Outputs that don't end with a newline run straight
    # into the next ``--``-prefixed marker on the same line, so split on the
    # marker substring rather than a newline boundary.
    _, rest = text.split(marker, 1)
    # Skip the trailing newline produced by the echo when present.
    if rest.startswith("\n"):
        rest = rest[1:]
    # Find the next ``--<token>--`` marker.  Require ``--`` plus at least one
    # token char to avoid matching `--` mid-content (e.g. ``Xms1g --..`` JVM
    # options).  Reject candidates that look like CLI flags (``--add-opens``)
    # by demanding the closing ``--`` follows a short token.
    next_match = None
    for cand in re.finditer(r"(?<![\w-])--[a-z0-9][a-z0-9-]{0,40}--", rest):
        next_match = cand
        break
    if not next_match:
        return rest.strip()
    return rest[: next_match.start()].strip()


def parse_history_jsonl() -> list[dict]:
    rows = []
    for line in (EVIDENCE_DIR / "docker-history.image.jsonl").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def normalize_created_by(s: str) -> str:
    # ACES reserves ${...} for scenario variables; convert braced shell
    # parameter syntax to the unbraced equivalent for SDL strings only.
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", r"$\1", s)


def derive_build_instructions(history_rows: list[dict]) -> list[dict]:
    instructions: list[dict] = []
    for row in history_rows:
        created_by = normalize_created_by(row.get("CreatedBy", ""))
        upper = created_by.upper()
        instr_type = "run"
        if upper.startswith("/BIN/SH "):
            instr_type = "run"
        if upper.startswith("RUN "):
            instr_type = "run"
            created_by = created_by[4:]
        elif upper.startswith("COPY "):
            instr_type = "copy"
            created_by = created_by[5:]
        elif upper.startswith("ADD "):
            instr_type = "add"
            created_by = created_by[4:]
        elif upper.startswith("ARG "):
            instr_type = "arg"
            created_by = created_by[4:]
        elif upper.startswith("ENV "):
            instr_type = "env"
            created_by = created_by[4:]
        elif upper.startswith("CMD "):
            instr_type = "cmd"
            created_by = created_by[4:]
        elif upper.startswith("ENTRYPOINT "):
            instr_type = "entrypoint"
            created_by = created_by[11:]
        elif upper.startswith("EXPOSE "):
            instr_type = "expose"
            created_by = created_by[7:]
        elif upper.startswith("WORKDIR "):
            instr_type = "workdir"
            created_by = created_by[8:]
        elif upper.startswith("USER "):
            instr_type = "user"
            created_by = created_by[5:]
        elif upper.startswith("LABEL "):
            instr_type = "label"
            created_by = created_by[6:]
        elif upper.startswith("VOLUME "):
            instr_type = "volume"
            created_by = created_by[7:]
        else:
            instr_type = "run"
        instructions.append(
            {
                "instruction": instr_type,
                "arguments": [created_by.strip()],
                "description": "Observed from docker history.",
            }
        )
    return instructions


def derive_build_layers(history_rows: list[dict], image_inspect: list[dict]) -> list[dict]:
    rootfs_layers = []
    if image_inspect:
        rootfs_layers = image_inspect[0].get("RootFS", {}).get("Layers", []) or []
    layers = []
    rootfs_idx = 0
    for row in history_rows:
        created_by = normalize_created_by(row.get("CreatedBy", ""))
        size_str = row.get("Size", "0B")
        size_bytes = parse_size(size_str)
        empty = size_bytes == 0
        digest = ""
        if not empty and rootfs_idx < len(rootfs_layers):
            digest = rootfs_layers[rootfs_idx]
            rootfs_idx += 1
        layers.append(
            {
                "digest": digest,
                "created_by": created_by,
                "size": size_bytes,
                "empty": empty,
                "description": (
                    "Observed from docker history; digest is RootFS layer "
                    "digest where Docker inspect exposed one."
                ),
            }
        )
    return layers


def parse_size(size_str: str) -> int:
    size_str = size_str.strip()
    if not size_str or size_str == "0B":
        return 0
    units = {"B": 1, "KB": 1_000, "MB": 1_000_000, "GB": 1_000_000_000}
    m = re.match(r"^([0-9.]+)\s*([KMG]?B)$", size_str)
    if not m:
        return 0
    val = float(m.group(1))
    return int(val * units[m.group(2)])


def derive_build_config(image_inspect: list[dict]) -> dict:
    config = image_inspect[0].get("Config", {}) if image_inspect else {}
    default_env = []
    for raw in config.get("Env") or []:
        if "=" not in raw:
            continue
        name, value = raw.split("=", 1)
        default_env.append(
            {
                "name": name,
                "value": value,
                "value_classification": "plain",
                "description": "",
            }
        )
    return {
        "entrypoint": config.get("Entrypoint") or [],
        "command": config.get("Cmd") or [],
        "working_directory": config.get("WorkingDir") or "/",
        "exposed_ports": list((config.get("ExposedPorts") or {}).keys()),
        "labels": config.get("Labels") or {},
        "default_environment": default_env,
        "description": "",
    }


def derive_source_inputs() -> list[dict]:
    compose_yml = REPO_ROOT / "docker-compose.yml"
    indexer_yml = REPO_ROOT / "config" / "wazuh_indexer" / "wazuh.indexer.yml"
    internal_users_yml = REPO_ROOT / "config" / "wazuh_indexer" / "internal_users.yml"
    src_checksums = (EVIDENCE_DIR / "source-checksums.txt").read_text(encoding="utf-8")
    checksums = {}
    for line in src_checksums.splitlines():
        if not line.strip():
            continue
        parts = line.split("  ", 1)
        if len(parts) == 2:
            checksums[parts[1].strip()] = parts[0].strip()
    return [
        {
            "identifier": "config-wazuh_indexer-wazuh-indexer-yml",
            "source_path": "config/wazuh_indexer/wazuh.indexer.yml",
            "destination_path": "/usr/share/wazuh-indexer/opensearch.yml",
            "checksum": checksums.get("config/wazuh_indexer/wazuh.indexer.yml", ""),
            "checksum_algorithm": "sha256" if checksums.get("config/wazuh_indexer/wazuh.indexer.yml") else "",
            "description": "APTL source-owned OpenSearch configuration bound into the Wazuh indexer runtime.",
        },
        {
            "identifier": "config-wazuh_indexer-internal-users-yml",
            "source_path": "config/wazuh_indexer/internal_users.yml",
            "destination_path": "/usr/share/wazuh-indexer/opensearch-security/internal_users.yml",
            "checksum": checksums.get("config/wazuh_indexer/internal_users.yml", ""),
            "checksum_algorithm": "sha256" if checksums.get("config/wazuh_indexer/internal_users.yml") else "",
            "description": "APTL source-owned OpenSearch Security internal users seed mounted into the Wazuh indexer runtime.",
        },
        {
            "identifier": "config-wazuh_indexer_ssl_certs-root-ca-pem",
            "source_path": "config/wazuh_indexer_ssl_certs/root-ca.pem",
            "destination_path": "/usr/share/wazuh-indexer/certs/root-ca.pem",
            "checksum": "",
            "checksum_algorithm": "",
            "description": "Generated lab CA mounted into the Wazuh indexer certs tree; bytes are generated per lab start.",
        },
        {
            "identifier": "config-wazuh_indexer_ssl_certs-wazuh-indexer-pem",
            "source_path": "config/wazuh_indexer_ssl_certs/wazuh.indexer.pem",
            "destination_path": "/usr/share/wazuh-indexer/certs/wazuh.indexer.pem",
            "checksum": "",
            "checksum_algorithm": "",
            "description": "Generated indexer server certificate mounted into the Wazuh indexer certs tree.",
        },
        {
            "identifier": "config-wazuh_indexer_ssl_certs-wazuh-indexer-key-pem",
            "source_path": "config/wazuh_indexer_ssl_certs/wazuh.indexer-key.pem",
            "destination_path": "/usr/share/wazuh-indexer/certs/wazuh.indexer.key",
            "checksum": "",
            "checksum_algorithm": "",
            "description": "Generated indexer server private key bound into the Wazuh indexer runtime; raw bytes are operator-secret material and intentionally omitted from evidence.",
        },
        {
            "identifier": "config-wazuh_indexer_ssl_certs-admin-pem",
            "source_path": "config/wazuh_indexer_ssl_certs/admin.pem",
            "destination_path": "/usr/share/wazuh-indexer/certs/admin.pem",
            "checksum": "",
            "checksum_algorithm": "",
            "description": "Generated security-plugin admin certificate mounted into the Wazuh indexer certs tree.",
        },
        {
            "identifier": "config-wazuh_indexer_ssl_certs-admin-key-pem",
            "source_path": "config/wazuh_indexer_ssl_certs/admin-key.pem",
            "destination_path": "/usr/share/wazuh-indexer/certs/admin-key.pem",
            "checksum": "",
            "checksum_algorithm": "",
            "description": "Generated security-plugin admin private key bound into the Wazuh indexer runtime; raw bytes are operator-secret material and intentionally omitted from evidence.",
        },
    ]


def parse_mounts(container_inspect: list[dict]) -> list[dict]:
    mounts = container_inspect[0].get("Mounts", [])
    out = []
    for m in mounts:
        source_kind = "bind" if m["Type"] == "bind" else "volume"
        source = m.get("Name") or m.get("Source") or ""
        stability = "volume_backed" if source_kind == "volume" else "stable"
        backend_generated = source_kind == "volume" and source.startswith("aptl_")
        out.append(
            {
                "target": m["Destination"],
                "source": source,
                "source_sensitivity": "unknown",
                "source_kind": source_kind,
                "filesystem_type": "",
                "read_only": not m.get("RW", True),
                "options": [m.get("Mode") or ""],
                "options_sensitivity": "unknown",
                "propagation": m.get("Propagation") or "unknown",
                "stability": stability,
                "backend_generated": backend_generated,
                "description": (
                    "Compose-declared Wazuh indexer named-volume mount."
                    if source_kind == "volume"
                    else "Compose-declared Wazuh indexer bind mount."
                ),
            }
        )
    return out


_STAT_LINE_RE = re.compile(
    r"^(?P<entry_type>\w+(?:\s\w+)?)\s+(?P<perm>\S+)\s+(?P<mode>\d+)\s+(?P<uid>\d+)\s+(?P<owner>\S+)\s+(?P<gid>\d+)\s+(?P<group>\S+)\s+(?P<size>\d+)\s+(?P<mtime>\d+)\s+(?P<path>.+)$"
)


def _stat_kind_to_entry_type(stat_kind: str) -> str:
    stat_kind = stat_kind.strip().lower()
    if "directory" in stat_kind:
        return "directory"
    if "symbolic link" in stat_kind:
        return "symlink"
    if "regular file" in stat_kind:
        return "file"
    if "regular empty file" in stat_kind:
        return "file"
    return "file"


def parse_filesystem_entries() -> list[dict]:
    tree_lines = (EVIDENCE_DIR / "filesystem-tree.txt").read_text(encoding="utf-8").splitlines()
    checksum_map: dict[str, str] = {}
    checksum_lines = (EVIDENCE_DIR / "filesystem-checksums.txt").read_text(encoding="utf-8").splitlines()
    for line in checksum_lines:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("  ", 1)
        if len(parts) == 2:
            checksum_map[parts[1]] = parts[0]
    entries = []
    for line in tree_lines:
        m = _STAT_LINE_RE.match(line)
        if not m:
            continue
        path = m.group("path")
        entry_type = _stat_kind_to_entry_type(m.group("entry_type"))
        digest = ""
        digest_algo = ""
        sensitivity = "plain"
        description = ""
        digest_value = checksum_map.get(path, "")
        if digest_value:
            if digest_value.startswith("<OMITTED-"):
                # ACES disallows content_digest without a digest_algorithm; record
                # the omission classification on the entry instead.
                sensitivity = "redacted"
                description = (
                    f"Private TLS key material; raw content checksum omitted as {digest_value}."
                )
            else:
                digest = digest_value
                digest_algo = "sha256"
        owner = m.group("owner")
        group = m.group("group")
        entries.append(
            {
                "path": path,
                "entry_type": entry_type,
                "presence": "present",
                "owner_user": owner if owner != "UNKNOWN" else "UNKNOWN",
                "owner_group": group if group != "UNKNOWN" else "UNKNOWN",
                "uid": int(m.group("uid")),
                "gid": int(m.group("gid")),
                "mode": m.group("mode").zfill(4),
                "size": int(m.group("size")),
                "content_digest": digest,
                "digest_algorithm": digest_algo,
                "source_path": "",
                "provenance": (
                    "docker exec; docs/aces/inventory/wazuh.indexer/evidence/filesystem-tree.txt; "
                    "docs/aces/inventory/wazuh.indexer/evidence/filesystem-checksums.txt"
                ),
                "stability": "stable",
                "sensitivity": sensitivity,
                "description": description,
            }
        )
    return entries


def parse_processes() -> list[dict]:
    out = []
    for line in runtime_section("process-list"):
        # Tab-separated: pid \t uid \t name \t cmdline
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        pid_s, uid_s, name, cmdline = parts[0], parts[1], parts[2], "\t".join(parts[3:])
        try:
            pid = int(pid_s)
        except ValueError:
            continue
        cmd_args = cmdline.split(" ") if cmdline else []
        role = "supervisor" if pid == 1 else "worker"
        try:
            uid_int = int(uid_s)
        except ValueError:
            uid_int = -1
        user = "wazuh-indexer" if uid_int == 1000 else ("root" if uid_int == 0 else "")
        out.append(
            {
                "name": f"{name}-{pid}",
                "pid": pid,
                "parent_pid": None,
                "command": cmd_args,
                "command_redacted": False,
                "role": role,
                "user": user,
                "group": "",
                "working_directory": "",
                "description": "Observed by /proc enumeration inside the running Wazuh indexer container.",
            }
        )
    return out


def _env_name_is_secret(name: str) -> bool:
    """Mirror ACES `name_indicates_secret` so generated env vars stay compliant.

    ACES `RuntimeEnvironmentVariable` requires that a variable whose NAME looks
    secret-bearing (e.g. `PWD` → `pwd`, anything with `key`/`token`/`secret`/
    `passwd`/`credential`) omit its value. Import the canonical predicate when
    aces_sdl is importable so this generator tracks the upstream token list; fall
    back to a vendored subset otherwise.
    """
    try:
        from aces_sdl.runtime_values import name_indicates_secret

        return bool(name_indicates_secret(name))
    except Exception:
        lowered = name.lower().replace("-", "_")
        tokens = (
            "access_key", "access_token", "api_key", "auth_key", "client_key",
            "client_secret", "credential", "passphrase", "passwd", "password",
            "private_key", "pwd", "secret", "shared_key", "token",
        )
        if any(tok in lowered for tok in tokens):
            return True
        return "key" in [p for p in re.split(r"[^a-z0-9]+", lowered) if p]


def parse_environment() -> list[dict]:
    out = []
    for line in runtime_section("environment"):
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        # An already-<REDACTED ...> value, or a name ACES treats as secret-bearing,
        # must be encoded as redacted with the value omitted.
        sensitive = "<REDACTED" in value or _env_name_is_secret(key)
        out.append(
            {
                "name": key,
                "value": "" if sensitive else value,
                "value_classification": "redacted" if sensitive else "plain",
                "provenance": "runtime",
                "source": "docs/aces/inventory/wazuh.indexer/evidence/runtime-baseline.txt",
                "description": (
                    "Value omitted: ACES requires secret-bearing-named runtime env vars to omit their value."
                    if sensitive and "<REDACTED" not in value
                    else ""
                ),
            }
        )
    return out


def parse_local_identity() -> dict:
    group_by_gid: dict[int, str] = {}
    groups_raw = []
    for line in runtime_section("groups"):
        parts = line.split(":")
        if len(parts) < 4:
            continue
        gid = int(parts[2])
        group_name = parts[0]
        group_by_gid[gid] = group_name
        members = [m for m in parts[3].split(",") if m]
        groups_raw.append(
            {
                "name": group_name,
                "gid": gid,
                "members": members,
                "provenance": "image",
                "description": "getent group from inside the running container.",
            }
        )
    users = []
    for line in runtime_section("users"):
        parts = line.split(":")
        if len(parts) < 7:
            continue
        uid = int(parts[2])
        gid = int(parts[3])
        shell = parts[6]
        users.append(
            {
                "username": parts[0],
                "uid": uid,
                "primary_gid": gid,
                "primary_group": group_by_gid.get(gid, ""),
                "gecos": parts[4],
                "home": parts[5],
                "shell": shell,
                "supplemental_groups": [],
                "disabled": False,
                "locked": False,
                "no_login": shell in {"/sbin/nologin", "/usr/sbin/nologin", "/bin/false"},
                "provenance": "image",
                "stability": "stable",
                "description": "",
            }
        )
    return {
        "users": users,
        "groups": groups_raw,
        "description": "Local passwd/group database observed at snapshot time.",
    }


_DOCKER_NET_LABEL = {
    "aptl_aptl-security": "techvault.security-net",
}


def parse_network_endpoints(container_inspect: list[dict]) -> dict:
    cfg = container_inspect[0].get("Config", {}) or {}
    nets = container_inspect[0].get("NetworkSettings", {}).get("Networks", {})
    endpoints = []
    for net_name, net_meta in nets.items():
        endpoints.append(
            {
                "network": _DOCKER_NET_LABEL.get(net_name, net_name),
                "network_id": net_meta.get("NetworkID", ""),
                "network_id_stability": "ephemeral",
                "endpoint_id": net_meta.get("EndpointID", ""),
                "endpoint_id_stability": "ephemeral",
                "backend_generated": True,
                "ip_address": net_meta.get("IPAddress", ""),
                "ip_prefix_length": net_meta.get("IPPrefixLen", 0),
                "gateway": net_meta.get("Gateway", ""),
                "mac_address": net_meta.get("MacAddress", ""),
                "aliases": [a for a in (net_meta.get("Aliases") or []) if "." in a or "-" in a],
                "dns_names": [d for d in (net_meta.get("DNSNames") or []) if "." in d or "-" in d],
                "generated_dns_names": [d for d in (net_meta.get("DNSNames") or []) if not ("." in d or "-" in d)],
                "backend": None,
                "description": "Docker Compose aptl-security network endpoint observed by docker inspect.",
            }
        )
    ports = container_inspect[0].get("NetworkSettings", {}).get("Ports", {}) or {}
    published = []
    for container_port, bindings in (ports or {}).items():
        port_int_match = re.match(r"^(\d+)/(\w+)$", container_port)
        if not port_int_match:
            continue
        port_int = int(port_int_match.group(1))
        proto = port_int_match.group(2)
        for binding in bindings or []:
            published.append(
                {
                    "container_port": port_int,
                    "protocol": proto,
                    "host_ip": binding.get("HostIp", ""),
                    "host_port": int(binding.get("HostPort", "0") or 0),
                    "description": f"Compose host publication {binding.get('HostPort','')}:{port_int}.",
                }
            )
    return {
        "hostname": cfg.get("Hostname", "") or "",
        "domainname": cfg.get("Domainname", "") or "",
        "endpoints": endpoints,
        "published_ports": published,
    }


def parse_packages_from_syft() -> list[dict]:
    sbom = load_json("syft-sbom.cyclonedx.json.gz")
    out = []
    for comp in sbom.get("components", []):
        manager = ""
        purl = comp.get("purl") or ""
        if purl:
            m = re.match(r"^pkg:([^/]+)/", purl)
            if m:
                manager = m.group(1)
        properties = comp.get("properties") or []
        arch = ""
        source = ""
        for p in properties:
            name = p.get("name", "")
            if name.endswith(":architecture"):
                arch = p.get("value", "")
            elif name.endswith(":source"):
                source = p.get("value", "")
        out.append(
            {
                "manager": manager or comp.get("type", ""),
                "name": comp.get("name", ""),
                "version": comp.get("version", ""),
                "architecture": arch,
                "source": source,
                "purl": purl,
            }
        )
    return sorted(out, key=lambda r: (r["manager"], r["name"], r["version"]))


def parse_vulnerabilities() -> list[dict]:
    findings = load_json("trivy-vulnerability-list.json")
    captured_at = (EVIDENCE_DIR / "captured-at-utc.txt").read_text(encoding="utf-8").strip()
    out = []
    for f in findings:
        out.append(
            {
                "id": f.get("id", ""),
                "package_name": f.get("package_name", ""),
                "installed_version": f.get("installed_version", ""),
                "severity": (f.get("severity", "") or "").lower(),
                "scanner": "trivy",
                "image_digest": IMAGE_DIGEST,
                "scan_time": captured_at,
                "fixed_version": f.get("fixed_version", ""),
                "advisory_url": f.get("primary_url", ""),
                "scanner_version": "0.70.0",
                "scanner_database": "trivy-db",
            }
        )
    return out


# ACES expressivity gaps blocking full datastore encoding. Observed structured
# facts in these dimensions live in the evidence bundle + mapping ledger
# (disposition blocked_by_aces_gap); they are NOT forced into SDL prose.
ACES_GAP_CARDINALITY = "Brad-Edwards/aces#468"  # cluster/partition uuid, doc count, store size, creation, status
ACES_GAP_MAPPINGS = "Brad-Edwards/aces#469"  # structured index mapping + template-body schema
ACES_GAP_NODE_PROVENANCE = "Brad-Edwards/aces#470"  # engine version/build/plugin-version/heap/publish addresses


def parse_datastore_services() -> list[dict]:
    """Parse OpenSearch state into a single RuntimeDatastoreService entry.

    The shape conforms to the ACES ``RuntimeDatastoreService`` schema:
    cluster + nodes + partitions (search-index profile) + transport_security
    + bounded settings list. Dimensions ACES cannot type today — per-index and
    cluster cardinality/size/identity (ACES #468), structured index mappings and
    template bodies (ACES #469), and node engine provenance (ACES #470) — are
    deliberately NOT stuffed into description prose here; they are captured in
    the evidence bundle and recorded as blocked_by_aces_gap facts in the mapping
    ledger. The SDL encodes only what has a typed home.
    """
    cluster_health = json.loads(indexer_state_section("cluster-health"))
    cluster_stats = json.loads(indexer_state_section("cluster-stats-summary"))
    nodes_local = json.loads(indexer_state_section("nodes-local-summary"))
    cluster_settings = json.loads(indexer_state_section("cluster-settings"))
    cat_indices_text = indexer_state_section("cat-indices")
    cat_plugins_text = indexer_state_section("cat-plugins")
    indices = json.loads(cat_indices_text) if cat_indices_text else []
    plugins = json.loads(cat_plugins_text) if cat_plugins_text else []

    node_id, node = next(iter(nodes_local["nodes"].items()))
    transport_publish = node.get("transport_address", "")

    allowed_roles = {"cluster_manager", "data", "ingest", "coordinating", "ml", "seed", "coordinator"}
    role_list_raw = list(node.get("roles", []) or [])
    node_roles: list[str] = []
    other_roles: list[str] = []
    for r in role_list_raw:
        if r in allowed_roles:
            node_roles.append(r)
        else:
            other_roles.append(r)
            node_roles.append("other")
    node_role_note = (
        f" OpenSearch roles outside the ACES vocabulary mapped to 'other': {', '.join(other_roles)}."
        if other_roles
        else ""
    )
    nodes_out = [
        {
            "node_id": node_id,
            "name": node.get("name", ""),
            "roles": node_roles,
            "is_coordinator": True,
            "address": transport_publish,
            # Engine version, build hash, per-plugin versions, JVM heap, and the
            # http/transport publish-address split have no typed RuntimeDatastoreNode
            # home; observed in evidence and blocked on ACES #470. Do NOT inline them.
            "description": (
                "Single OpenSearch member of the TechVault Wazuh indexer cluster."
                + node_role_note
                + f" Engine version / build hash / per-plugin versions / JVM heap / publish-address split"
                f" are observed in docs/aces/inventory/wazuh.indexer/evidence/wazuh-indexer-state.txt"
                f" and blocked on {ACES_GAP_NODE_PROVENANCE} (no typed node-provenance fields)."
            ),
        }
    ]

    partitions = []
    for idx in indices:
        partitions.append(
            {
                "partition_id": idx["index"].replace(".", "-").replace(":", "-"),
                "kind": "index",
                "name": idx["index"],
                "shard_count": int(idx.get("pri", "0") or 0),
                "replica_count": int(idx.get("rep", "0") or 0),
                "health": idx.get("health", ""),
                # uuid, doc count, deleted count, store size, creation date, and
                # open/closed status have no typed RuntimeDatastorePartition home;
                # observed in evidence (cat-indices + mapping census) and blocked on
                # ACES #468 (cardinality/size/identity) and #469 (structured mapping).
                # They are intentionally NOT inlined into this description.
                "description": (
                    f"OpenSearch index partition; cardinality/size/identity (uuid, doc count, "
                    f"store size, creation date, open/closed status) blocked on {ACES_GAP_CARDINALITY}, "
                    f"structured field mapping blocked on {ACES_GAP_MAPPINGS}; both observed in evidence."
                ),
            }
        )

    node_settings = node.get("settings", {}) or {}

    def _setting(key: str, value: str, description: str) -> dict:
        return {
            "setting_id": key.replace(".", "-"),
            "name": key,
            "value": str(value),
            "scope": "node",
            "provenance": "configuration_file",
            "classification": "plain",
            "description": description,
        }

    settings = [
        _setting(
            "discovery.type",
            node_settings.get("discovery", {}).get("type", "single-node"),
            "Single-node discovery is the realized cluster posture.",
        ),
        _setting(
            "network.host",
            node_settings.get("network", {}).get("host", "0.0.0.0"),
            "OpenSearch HTTP/transport bind address.",
        ),
        _setting(
            "http.port",
            node_settings.get("http", {}).get("port", "9200-9299"),
            "OpenSearch REST API port range; the first port (9200) is bound and host-published.",
        ),
        _setting(
            "transport.tcp.port",
            node_settings.get("transport", {}).get("tcp", {}).get("port", "9300-9399"),
            "OpenSearch transport TCP port range; transport is cluster-internal only.",
        ),
        _setting(
            "http.type",
            node_settings.get("http", {}).get("type", ""),
            "OpenSearch Security overrides the HTTP transport to its mutual-TLS netty wrapper.",
        ),
        _setting(
            "transport.type",
            node_settings.get("transport", {}).get("type", ""),
            "OpenSearch Security overrides the transport class to its mutual-TLS netty wrapper.",
        ),
        {
            "setting_id": "plugins-index_state_management-template_migration-control",
            "name": "plugins.index_state_management.template_migration.control",
            "value": str(
                cluster_settings.get("persistent", {})
                .get("plugins", {})
                .get("index_state_management", {})
                .get("template_migration", {})
                .get("control", "")
            ),
            "scope": "cluster",
            "provenance": "operator_override",
            "classification": "plain",
            "description": "Only persistent cluster setting observed via _cluster/settings.",
        },
    ]

    cluster_block = {
        "cluster_id": "techvault-wazuh-indexer-cluster",
        "name": cluster_health.get("cluster_name", ""),
        "health": cluster_health.get("status", ""),
        "discovery_mode": "single-node",
        "partitioner": "opensearch_default",
        "native_protocol_version": node.get("version", ""),
        # cluster uuid, node count, aggregate shard/doc/store totals have no typed
        # RuntimeDatastoreCluster home; observed in evidence and blocked on ACES #468.
        "description": (
            "Single-node OpenSearch cluster. Cluster uuid, node count, and aggregate "
            f"shard/doc/store totals blocked on {ACES_GAP_CARDINALITY}; observed in "
            "docs/aces/inventory/wazuh.indexer/evidence/wazuh-indexer-state.txt."
        ),
    }

    transport_security = {
        "transport_security_id": "techvault-wazuh-indexer-mtls",
        "mode": "mutual_tls",
        "client_verification": True,
        "node_verification": False,
        "description": (
            "OpenSearch Security mutual-TLS using bind-mounted PEM material under "
            "/usr/share/wazuh-indexer/certs/; transport hostname verification disabled per Wazuh-indexer default. "
            "Admin DN allowlist 'CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US' encoded under the OpenSearch Security identity authority."
        ),
    }

    # Plugin NAMES have a typed home (engine_plugins: list[str]); per-plugin
    # VERSION does not — blocked on ACES #470.
    engine_plugin_ids = sorted({p.get("component", "") for p in plugins if p.get("component")})

    # Template NAMES have a typed home (templates: list[str]); the structured
    # template BODY (settings + mappings + index_patterns) does not — blocked on
    # ACES #469. Names are encoded; bodies live in evidence.
    cat_templates_text = indexer_state_section("cat-templates")
    template_names = (
        sorted({t.get("name", "") for t in json.loads(cat_templates_text) if t.get("name")})
        if cat_templates_text
        else []
    )

    return [
        {
            "datastore_service_id": "techvault-wazuh-indexer",
            "service": "wazuh-indexer-rest",
            "engine": "opensearch",
            "data_model": "search_index",
            "protocol": "https",
            "version": node.get("version", ""),
            "name": "TechVault Wazuh Indexer",
            "cluster": cluster_block,
            "nodes": nodes_out,
            "partitions": partitions,
            "templates": template_names,
            "engine_plugins": engine_plugin_ids,
            "transport_security": transport_security,
            "settings": settings,
            "description": (
                "Wazuh indexer (OpenSearch 2.19.1 fork) datastore service for the steady-state TechVault lab; "
                "persistence mounted at /var/lib/wazuh-indexer via the wazuh-indexer-data named volume. "
                "Encoded: cluster identity (typed fields), node membership/roles, per-index partition geometry "
                "(shard/replica/health), transport mutual-TLS, settings, plugin + template NAMES. "
                f"Blocked on ACES gaps: per-index/cluster cardinality+size+identity ({ACES_GAP_CARDINALITY}), "
                f"structured index mapping + template bodies ({ACES_GAP_MAPPINGS}), node engine provenance + "
                f"per-plugin versions ({ACES_GAP_NODE_PROVENANCE}). Blocked dimensions live in the evidence bundle "
                "and the mapping ledger, not in this prose."
            ),
        }
    ]


def parse_identity_authorities() -> list[dict]:
    internal_users_yml = indexer_state_section("internal-users-yml")
    internal_users = yaml.safe_load(internal_users_yml) or {}

    user_subjects: list[dict] = []
    for user_name, body in internal_users.items():
        if user_name == "_meta":
            continue
        attributes = []
        for attr_name, attr_value in (body.get("attributes", {}) or {}).items():
            attributes.append(
                {
                    "name": attr_name,
                    "values": [str(attr_value)],
                    "value_classification": "plain",
                }
            )
        backend_roles = list(body.get("backend_roles", []) or [])
        attributes.append(
            {
                "name": "backend_roles",
                "values": backend_roles,
                "value_classification": "plain",
            }
        )
        attributes.append(
            {
                "name": "reserved",
                "values": [str(bool(body.get("reserved", False))).lower()],
                "value_classification": "plain",
            }
        )
        attributes.append(
            {
                "name": "demo_description",
                "values": [body.get("description", "") or ""],
                "value_classification": "plain",
            }
        )
        user_subjects.append(
            {
                "subject_id": f"internal-user-{user_name.replace('_','-')}",
                "kind": "user",
                "name": user_name,
                "display_name": user_name,
                "principal_name": user_name,
                "distinguished_name": "",
                "domain": "",
                "enabled": True,
                "origin": "built_in" if body.get("reserved") else "provisioned",
                "service_principal_names": [],
                "attributes": attributes,
            }
        )

    # Add the admin DN as a separate subject so the SDL records the admin
    # allowlist that the OpenSearch security plugin treats as a privileged
    # cluster identity.
    user_subjects.append(
        {
            "subject_id": "admin-dn-allowlist",
            "kind": "user",
            "name": "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US",
            "display_name": "admin (Wazuh-indexer admin DN)",
            "principal_name": "admin",
            "distinguished_name": "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US",
            "domain": "Wazuh",
            "enabled": True,
            "origin": "operator",
            "service_principal_names": [],
            "attributes": [
                {
                    "name": "role",
                    "values": ["plugins.security.authcz.admin_dn"],
                    "value_classification": "plain",
                }
            ],
        }
    )

    security_config = json.loads(indexer_state_section("security-config-summary"))
    services_out: list[dict] = []
    for domain_id, body in security_config.get("config", {}).get("dynamic", {}).get("authc", {}).items():
        services_out.append(
            {
                "service_id": f"authc-{domain_id.replace('_','-')}",
                "service": "wazuh-indexer-rest",
                "protocol": "other",
                "address": "0.0.0.0",
                "port": 9200,
                "description": (
                    f"OpenSearch Security authc domain '{domain_id}' "
                    f"(http_enabled={body.get('http_enabled')}, "
                    f"order={body.get('order','')}, "
                    f"authenticator={body.get('http_authenticator',{}).get('type','')}, "
                    f"backend={body.get('authentication_backend',{}).get('type','')})."
                ),
            }
        )
    for domain_id, body in security_config.get("config", {}).get("dynamic", {}).get("authz", {}).items():
        services_out.append(
            {
                "service_id": f"authz-{domain_id.replace('_','-')}",
                "service": "wazuh-indexer-rest",
                "protocol": "other",
                "address": "0.0.0.0",
                "port": 9200,
                "description": (
                    f"OpenSearch Security authz domain '{domain_id}' "
                    f"(http_enabled={body.get('http_enabled')}, "
                    f"backend={body.get('authorization_backend',{}).get('type','')})."
                ),
            }
        )

    # Role mappings are captured as opaque role-kind subjects so the authority
    # records every realized role (and its backend-role / user / host membership)
    # without introducing cross-authority relationships the validator cannot
    # resolve (membership shapes live in the evidence file / mapping ledger).
    rolesmapping = json.loads(indexer_state_section("security-rolesmapping"))
    role_subjects: list[dict] = []
    for role_name, mapping in sorted(rolesmapping.items()):
        role_subjects.append(
            {
                "subject_id": f"role-{role_name.replace('_','-').replace('/','-').replace(':','-')}",
                "kind": "role",
                "name": role_name,
                "display_name": role_name,
                "principal_name": role_name,
                "distinguished_name": "",
                "domain": "",
                "enabled": True,
                "origin": "built_in" if mapping.get("reserved") else "provisioned",
                "service_principal_names": [],
                "attributes": [
                    {
                        "name": "backend_roles",
                        "values": list(mapping.get("backend_roles", []) or []),
                        "value_classification": "plain",
                    },
                    {
                        "name": "users",
                        "values": list(mapping.get("users", []) or []),
                        "value_classification": "plain",
                    },
                    {
                        "name": "hosts",
                        "values": list(mapping.get("hosts", []) or []),
                        "value_classification": "plain",
                    },
                    {
                        "name": "and_backend_roles",
                        "values": list(mapping.get("and_backend_roles", []) or []),
                        "value_classification": "plain",
                    },
                    {
                        "name": "reserved",
                        "values": [str(bool(mapping.get("reserved", False))).lower()],
                        "value_classification": "plain",
                    },
                ],
            }
        )
    user_subjects.extend(role_subjects)

    return [
        {
            "identity_authority_id": "techvault-wazuh-indexer-opensearch-security",
            "kind": "authorization_system",
            "name": "Wazuh indexer OpenSearch Security",
            "namespace": "wazuh-indexer",
            "domain_name": "",
            "realm": "opensearch-security",
            "issuer": "",
            "tenant_id": "",
            "base_dn": "",
            "description": (
                "OpenSearch Security plugin acting as the local identity authority for the Wazuh indexer's "
                "HTTP and transport layers; basic_internal_auth_domain (order 4, intern backend) is the only "
                "HTTP-enabled authc domain. Configuration shipped via bind-mounted "
                "/usr/share/wazuh-indexer/opensearch-security/{internal_users,roles,roles_mapping,config,action_groups}.yml."
            ),
            "services": services_out,
            "subjects": user_subjects,
            "policies": [],
            "relationships": [],
        }
    ]


def parse_service_listeners() -> list[dict]:
    return [
        {
            "service_listener_id": "opensearch-rest-9200",
            "service": "wazuh-indexer-rest",
            "address": "0.0.0.0",
            "port": 9200,
            "protocol": "tcp",
            "address_family": "ipv4",
            "scope": "wildcard",
            "bind_interface": "",
            "socket_path": "",
            "process_ref": "",
            "process_name": "java",
            "published_port_refs": [],
            "readiness": None,
            "provenance": "docker_inspect",
            "evidence_refs": [
                "docs/aces/inventory/wazuh.indexer/evidence/wazuh-indexer-state.txt",
                "docs/aces/inventory/wazuh.indexer/evidence/wazuh-indexer-api-probe.json",
            ],
            "description": (
                "OpenSearch REST API on TCP/9200 (mutual-TLS HTTPS); reached by Filebeat from wazuh.manager and by "
                "the Wazuh dashboard. Host-published 9200:9200."
            ),
        },
        {
            "service_listener_id": "opensearch-transport-9300",
            "service": "wazuh-indexer-transport",
            "address": "0.0.0.0",
            "port": 9300,
            "protocol": "tcp",
            "address_family": "ipv4",
            "scope": "wildcard",
            "bind_interface": "",
            "socket_path": "",
            "process_ref": "",
            "process_name": "java",
            "published_port_refs": [],
            "readiness": None,
            "provenance": "docker_inspect",
            "evidence_refs": [
                "docs/aces/inventory/wazuh.indexer/evidence/wazuh-indexer-state.txt",
            ],
            "description": (
                "OpenSearch transport TCP on 9300 (mutual-TLS); cluster-internal only and not host-published; "
                "idle in the single-node cluster."
            ),
        },
    ]


def parse_health(container_inspect: list[dict]) -> dict:
    state = container_inspect[0].get("State", {})
    health = state.get("Health", {})
    log = []
    for entry in (health.get("Log") or [])[-5:]:
        output = entry.get("Output") or ""
        redacted = "<REDACTED" in output
        log.append(
            {
                "start": entry.get("Start", ""),
                "end": entry.get("End", ""),
                "exit_code": entry.get("ExitCode", 0),
                "output": output,
                "output_redacted": redacted,
            }
        )
    return {
        "status": health.get("Status", ""),
        "failing_streak": health.get("FailingStreak", 0),
        "log": log,
        "description": (
            "Docker healthcheck runs curl -ks https://localhost:9200 and treats HTTP 401 Unauthorized as readiness; "
            "OpenSearch Security challenges the unauthenticated request which proves the listener is up."
        ),
    }


def parse_operational_policy(container_inspect: list[dict]) -> dict:
    host = container_inspect[0].get("HostConfig", {})
    return {
        "restart": host.get("RestartPolicy", {}).get("Name", ""),
        "resource_limits": {
            "memory": host.get("Memory", 0),
            "memory_swap": host.get("MemorySwap", 0),
            "cpu": host.get("NanoCpus", 0) / 1_000_000_000 if host.get("NanoCpus") else 0,
            "pids": host.get("PidsLimit"),
            "open_files": next(
                (u.get("Hard", 0) for u in (host.get("Ulimits") or []) if u.get("Name") == "nofile"),
                0,
            ),
            "description": (
                "Docker host resource policy from container inspect; memlock ulimit -1/-1 (unlimited) is set per "
                "the Compose service to allow OpenSearch to lock its heap into RAM."
            ),
        },
        "description": "Compose restart/resource policy and Docker ulimit observed from compose plus docker inspect.",
    }


def parse_container_block(container_inspect: list[dict]) -> dict:
    cfg = container_inspect[0].get("Config", {}) or {}
    host = container_inspect[0].get("HostConfig", {}) or {}
    return {
        "entrypoint": cfg.get("Entrypoint") or [],
        "command": cfg.get("Cmd") or [],
        "log_driver": (host.get("LogConfig") or {}).get("Type", ""),
        "log_options": (host.get("LogConfig") or {}).get("Config") or {},
        "namespaces": {
            "cgroup": host.get("CgroupnsMode", "") or "",
            "ipc": host.get("IpcMode", "") or "",
            "pid": host.get("PidMode", "") or "",
            "userns": host.get("UsernsMode", "") or "",
            "uts": "container-hostname" if not host.get("UTSMode") else host.get("UTSMode"),
        },
        "privileged": bool(host.get("Privileged", False)),
        "read_only_rootfs": bool(host.get("ReadonlyRootfs", False)),
        "publish_all_ports": bool(host.get("PublishAllPorts", False)),
        "autoremove": host.get("AutoRemove"),
        "shm_size": host.get("ShmSize"),
        "masked_paths": list(host.get("MaskedPaths") or []),
        "read_only_paths": list(host.get("ReadonlyPaths") or []),
        "cgroup_parent": host.get("CgroupParent", "") or "",
        "runtime_name": host.get("Runtime", "") or "",
        "init_process": host.get("Init"),
        "devices": list(host.get("Devices") or []),
        "device_cgroup_rules": list(host.get("DeviceCgroupRules") or []),
        "seccomp_profile": "",
        "security_opt": list(host.get("SecurityOpt") or []),
        "extra_hosts": list(host.get("ExtraHosts") or []),
        "dns": list(host.get("Dns") or []),
        "dns_options": list(host.get("DnsOptions") or []),
        "dns_search": list(host.get("DnsSearch") or []),
        "group_add": list(host.get("GroupAdd") or []),
        "description": "Docker container host/security configuration observed from docker inspect.",
    }


def parse_linux_capabilities() -> dict:
    # PID 1 cap bounding set captured in runtime-baseline.txt
    text = "\n".join(runtime_section("capabilities-pid1"))
    cap_eff = re.search(r"CapEff:\s*([0-9a-fA-F]+)", text)
    cap_bnd = re.search(r"CapBnd:\s*([0-9a-fA-F]+)", text)
    docker_default_effective = [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_RAW",
        "CAP_SYS_CHROOT",
        "CAP_MKNOD",
        "CAP_AUDIT_WRITE",
        "CAP_SETFCAP",
    ]
    description_parts = []
    if cap_eff:
        description_parts.append(f"PID 1 CapEff mask observed as {cap_eff.group(1)}")
    if cap_bnd:
        description_parts.append(f"CapBnd mask {cap_bnd.group(1)} (Docker default)")
    description = (
        "; ".join(description_parts)
        + ". OpenSearch JVM drops to effective=0 after applying memlock; the Docker default bounding set is preserved."
        if description_parts
        else "PID 1 effective capabilities are zero post-startup; the Docker default bounding set is preserved."
    )
    return {
        "required": [],
        "effective": docker_default_effective if (cap_bnd and cap_bnd.group(1).lower() == "a80425fb") else [],
        "add": [],
        "drop": [],
        "process_overrides": [],
        "description": description,
    }


def build_node() -> dict:
    container_inspect = load_json("docker-inspect.container.json")
    image_inspect = load_json("docker-inspect.image.json")
    history_rows = parse_history_jsonl()

    runtime = {}
    runtime["mounts"] = parse_mounts(container_inspect)
    runtime["filesystem_inventory"] = parse_filesystem_entries()
    runtime["processes"] = parse_processes()
    runtime["environment"] = parse_environment()
    runtime["local_identity"] = parse_local_identity()
    runtime["linux_capabilities"] = parse_linux_capabilities()
    runtime["operational_policy"] = parse_operational_policy(container_inspect)
    runtime["container"] = parse_container_block(container_inspect)
    runtime["health"] = parse_health(container_inspect)
    runtime["network"] = parse_network_endpoints(container_inspect)
    runtime["service_listeners"] = parse_service_listeners()
    runtime["identity_authorities"] = parse_identity_authorities()
    runtime["file_services"] = []
    runtime["mail_services"] = []
    runtime["applications"] = []
    runtime["database_services"] = []
    runtime["dns_services"] = []
    runtime["network_sensors"] = []
    runtime["network_detection_engines"] = []
    runtime["security_monitoring_managers"] = []
    runtime["datastore_services"] = parse_datastore_services()
    runtime["packages"] = parse_packages_from_syft()
    runtime["package_vulnerabilities"] = parse_vulnerabilities()

    build = {
        "base_image": "amazonlinux:2023",
        "base_image_digest": "",
        "dockerfile_path": "upstream Wazuh indexer Dockerfile not present in APTL checkout",
        "instructions": derive_build_instructions(history_rows),
        "layers": derive_build_layers(history_rows, image_inspect),
        "config": derive_build_config(image_inspect),
        "source_inputs": derive_source_inputs(),
        "attestation": {
            "status": "absent",
            "verification": "not_applicable",
            "attestation_type": "none",
            "predicate_type": "",
            "evidence_reference": "docs/aces/inventory/wazuh.indexer/evidence/docker-buildx-imagetools.image.raw.json",
            "description": (
                "No registry-visible OCI/in-toto/SLSA build attestation was captured for this upstream image digest."
            ),
        },
        "description": (
            "Observed upstream Wazuh indexer image provenance from docker inspect/history; "
            "raw Docker history remains in the inventory evidence bundle."
        ),
    }

    node = {
        "type": "vm",
        "description": (
            "Wazuh indexer container and participant-visible OpenSearch datastore inventory captured from the steady-state "
            "TechVault lab."
        ),
        "source": {
            "name": "wazuh/wazuh-indexer",
            "version": IMAGE_DIGEST,
            "build": build,
        },
        "resources": {"ram": 2147483648, "cpu": 1},
        "os": "linux",
        "os_version": "Amazon Linux 2023.8.20250818",
        "features": {},
        "conditions": {"techvault.wazuh-indexer-ready": "wazuh-indexer-root"},
        "injects": {},
        "vulnerabilities": [],
        "roles": {"wazuh-indexer-root": {"username": "root", "entities": []}},
        "services": [
            {"port": 9200, "protocol": "tcp", "name": "wazuh-indexer-rest", "description": ""},
            {"port": 9300, "protocol": "tcp", "name": "wazuh-indexer-transport", "description": ""},
        ],
        "asset_value": None,
        "runtime": runtime,
    }
    return node


class IndentedDumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def main() -> int:
    node = build_node()
    doc = {"name": "techvault-node-wazuh-indexer", "nodes": {"wazuh-indexer": node}}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        yaml.dump(
            doc,
            Dumper=IndentedDumper,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=120,
        ),
        encoding="utf-8",
    )
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
