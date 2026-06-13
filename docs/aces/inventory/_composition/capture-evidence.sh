#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-$(git rev-parse --show-toplevel)}"
OUT="${OUT:-$ROOT/docs/aces/inventory/_composition}"
EVIDENCE="$OUT/evidence"

mkdir -p "$EVIDENCE"

date -u +"%Y-%m-%dT%H:%M:%SZ" >"$EVIDENCE/captured-at-utc.txt"
cat >"$EVIDENCE/capture-limits.txt" <<'LIMITS'
Composition capture scope:
- Non-destructive snapshot: did not run `aptl lab stop -v && aptl lab start`.
- Reads committed SDL, docker-compose.yml, and existing per-asset inventory bundles.
- Trivy, Syft, osquery, and mtree-style filesystem scans are not applicable at composition level because this target is a runtime-composed scenario, not a single image/rootfs.
- Per-asset bundles own scanner, SBOM, package, filesystem, and live container baselines.
- Raw secret values are intentionally not copied into composition evidence; only ownership/classification and sanitized placement summaries are retained.
- Workflow execution traces, attack traces, post-attack state, and SOC analyst timing are out of scope for issue #329.
LIMITS

python3 - "$ROOT" "$EVIDENCE" <<'PY'
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import json
import sys

import yaml

root = Path(sys.argv[1])
evidence = Path(sys.argv[2])


def load_yaml(relative: str) -> dict:
    with (root / relative).open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data or {}


def write_json(name: str, payload: dict | list) -> None:
    path = evidence / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def namespaced(value: str) -> str:
    if not value:
        return value
    if value.startswith("techvault."):
        return value
    return f"techvault.{value}"


def node_ref(value: str) -> str:
    if not value:
        return value
    value = value.removeprefix("nodes.")
    if value.startswith("techvault."):
        parts = value.split(".")
        return ".".join(parts[:2])
    return namespaced(value.split(".", maxsplit=1)[0])


def property_pairs(properties) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(properties, dict):
        for key, value in properties.items():
            pairs.append((namespaced(str(key)), str(value)))
    elif isinstance(properties, list):
        for item in properties:
            if isinstance(item, dict):
                for key, value in item.items():
                    pairs.append((namespaced(str(key)), str(value)))
    return pairs


infrastructure = load_yaml("scenarios/techvault/sections/infrastructure.sdl.yaml").get("infrastructure", {})
relationships = load_yaml("scenarios/techvault/sections/relationships.sdl.yaml").get("relationships", {})
accounts = load_yaml("scenarios/techvault/sections/accounts.sdl.yaml").get("accounts", {})
content = load_yaml("scenarios/techvault/sections/content.sdl.yaml").get("content", {})
root_sdl = load_yaml("scenarios/techvault.sdl.yaml")
compose = load_yaml("docker-compose.yml")

networks = []
static_assignments = []
node_links = []
for name, spec in sorted(infrastructure.items()):
    spec = spec or {}
    props = spec.get("properties")
    if isinstance(props, dict) and "cidr" in props:
        networks.append(
            {
                "id": namespaced(name),
                "cidr": str(props.get("cidr", "")),
                "gateway": str(props.get("gateway", "")),
                "internal": bool(props.get("internal", False)),
            }
        )
        continue
    for link in spec.get("links") or []:
        node_links.append({"node": namespaced(name), "network": link})
    for network, address in property_pairs(props):
        static_assignments.append(
            {"node": namespaced(name), "network": network, "address": address}
        )

write_json(
    "composition-network-topology.json",
    {
        "source": "scenarios/techvault/sections/infrastructure.sdl.yaml",
        "networks": networks,
        "node_links": node_links,
        "static_assignments": static_assignments,
    },
)

edges = []
for name, spec in sorted(infrastructure.items()):
    for target in (spec or {}).get("dependencies") or []:
        edges.append(
            {
                "id": f"infrastructure.{name}.depends-on.{target}",
                "kind": "infrastructure_dependency",
                "source": namespaced(name),
                "target": node_ref(str(target)),
            }
        )
for name, spec in sorted(relationships.items()):
    spec = spec or {}
    edges.append(
        {
            "id": f"relationship.{name}",
            "kind": "relationship",
            "source": node_ref(str(spec.get("source", ""))),
            "target": node_ref(str(spec.get("target", ""))),
            "relationship_type": str(spec.get("type", "")),
        }
    )
for service, spec in sorted((compose.get("services") or {}).items()):
    depends_on = (spec or {}).get("depends_on") or []
    if isinstance(depends_on, dict):
        depends = sorted(depends_on)
    else:
        depends = list(depends_on)
    for target in depends:
        edges.append(
            {
                "id": f"compose.{service}.depends-on.{target}",
                "kind": "compose_depends_on",
                "source": node_ref(service.replace(".", "-")),
                "target": node_ref(str(target).replace(".", "-")),
            }
        )

write_json(
    "composition-dependency-graph.json",
    {
        "sources": [
            "scenarios/techvault/sections/infrastructure.sdl.yaml",
            "scenarios/techvault/sections/relationships.sdl.yaml",
            "docker-compose.yml",
        ],
        "edges": edges,
    },
)

volume_uses = defaultdict(list)
bind_mounts = []
for service, spec in sorted((compose.get("services") or {}).items()):
    for volume in (spec or {}).get("volumes") or []:
        if isinstance(volume, str):
            parts = volume.split(":")
            source = parts[0]
            target = parts[1] if len(parts) > 1 else ""
            mode = parts[2] if len(parts) > 2 else ""
        elif isinstance(volume, dict):
            source = str(volume.get("source", ""))
            target = str(volume.get("target", ""))
            mode = str(volume.get("mode", ""))
        else:
            continue
        if not source:
            continue
        entry = {"service": service, "source": source, "target": target, "mode": mode}
        if source.startswith(".") or source.startswith("/"):
            bind_mounts.append(entry)
        else:
            volume_uses[source].append(entry)

write_json(
    "composition-mount-sharing.json",
    {
        "source": "docker-compose.yml",
        "shared_volumes": [
            {
                "volume": volume,
                "services": sorted({item["service"] for item in uses}),
                "mounts": uses,
            }
            for volume, uses in sorted(volume_uses.items())
            if len({item["service"] for item in uses}) > 1
        ],
        "service_local_volumes": [
            {
                "volume": volume,
                "services": sorted({item["service"] for item in uses}),
                "mounts": uses,
            }
            for volume, uses in sorted(volume_uses.items())
            if len({item["service"] for item in uses}) == 1
        ],
        "bind_mounts": bind_mounts,
    },
)

relationship_items = []
for name, spec in sorted(relationships.items()):
    spec = spec or {}
    relationship_items.append(
        {
            "id": namespaced(name),
            "type": spec.get("type", ""),
            "source": node_ref(str(spec.get("source", ""))),
            "target": node_ref(str(spec.get("target", ""))),
            "has_database_access": bool(spec.get("database_access")),
            "has_mail_access": bool(spec.get("mail_access")),
            "has_forwarding_edge": bool(spec.get("forwarding_edge")),
            "has_service_integration": bool(spec.get("service_integration")),
            "has_proxy_upstream": bool(spec.get("proxy_upstream")),
        }
    )
write_json(
    "composition-relationship-index.json",
    {
        "source": "scenarios/techvault/sections/relationships.sdl.yaml",
        "relationship_count": len(relationship_items),
        "relationships": relationship_items,
    },
)

accounts_by_node: dict[str, list[dict[str, object]]] = defaultdict(list)
for account_id, spec in sorted(accounts.items()):
    spec = spec or {}
    node = spec.get("node") or "unassigned"
    accounts_by_node[namespaced(str(node).removeprefix("techvault."))].append(
        {
            "id": account_id,
            "username": spec.get("username", ""),
            "auth_method": spec.get("auth_method", ""),
            "password_strength": spec.get("password_strength", ""),
            "disabled": bool(spec.get("disabled", False)),
        }
    )
write_json(
    "composition-account-host-map.json",
    {
        "source": "scenarios/techvault/sections/accounts.sdl.yaml",
        "account_count": len(accounts),
        "raw_secret_values_included": False,
        "accounts_by_node": dict(sorted(accounts_by_node.items())),
    },
)

content_items = []
for item_id, spec in sorted(content.items()):
    spec = spec or {}
    source = spec.get("source") if isinstance(spec.get("source"), dict) else {}
    targets = []
    if spec.get("target"):
        targets.append(spec.get("target"))
    if spec.get("destination"):
        targets.append(spec.get("destination"))
    content_items.append(
        {
            "id": item_id,
            "type": spec.get("type", ""),
            "targets": [str(target) for target in targets if target],
            "path": spec.get("path", ""),
            "source_name": source.get("name", ""),
            "source_version": source.get("version", ""),
            "sensitive": bool(spec.get("sensitive", False)),
        }
    )
write_json(
    "composition-content-placement.json",
    {
        "source": "scenarios/techvault/sections/content.sdl.yaml",
        "item_count": len(content_items),
        "items": content_items,
    },
)

inventory_root = root / "docs" / "aces" / "inventory"
per_asset = []
for ledger in sorted(inventory_root.glob("*/mapping-ledger.yaml")):
    if ledger.parent.name.startswith("_"):
        continue
    data = yaml.safe_load(ledger.read_text(encoding="utf-8")) or {}
    asset = data.get("asset", {})
    per_asset.append(
        {
            "asset": ledger.parent.name,
            "asset_id": asset.get("id", ledger.parent.name),
            "aptl_issue": asset.get("aptl_issue", ""),
            "fact_count": len(data.get("facts") or []),
            "mapping_ledger": str(ledger.relative_to(root)),
            "readme": str((ledger.parent / "README.md").relative_to(root)),
            "evidence_dir": str((ledger.parent / "evidence").relative_to(root)),
        }
    )
write_json(
    "composition-per-asset-index.json",
    {
        "source": "docs/aces/inventory/*/mapping-ledger.yaml",
        "asset_count": len(per_asset),
        "assets": per_asset,
    },
)

imports = root_sdl.get("imports") or []
write_json(
    "composition-sdl-surface-index.json",
    {
        "sources": [
            "scenarios/techvault.sdl.yaml",
            "scenarios/techvault/sections/infrastructure.sdl.yaml",
            "scenarios/techvault/sections/relationships.sdl.yaml",
            "scenarios/techvault/sections/accounts.sdl.yaml",
            "scenarios/techvault/sections/content.sdl.yaml",
        ],
        "import_count": len(imports),
        "node_import_count": len([item for item in imports if "/nodes/" in str(item.get("source", ""))]),
        "section_import_count": len([item for item in imports if "/sections/" in str(item.get("source", ""))]),
        "infrastructure_count": len(infrastructure),
        "relationship_count": len(relationships),
        "account_count": len(accounts),
        "content_count": len(content),
        "forwarding_agent_count": len(root_sdl.get("forwarding_agents") or []),
    },
)
PY

python3 - "$ROOT" "$EVIDENCE" <<'PY'
from pathlib import Path
import hashlib
import sys

root = Path(sys.argv[1])
evidence = Path(sys.argv[2])
manifest = evidence / "evidence-sha256sums.txt"
lines = []
for path in sorted(evidence.iterdir()):
    if not path.is_file() or path.name == manifest.name:
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    lines.append(f"{digest}  {path.relative_to(root)}")
manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
