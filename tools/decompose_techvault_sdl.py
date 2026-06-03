#!/usr/bin/env python3
"""Decompose the TechVault SDL into ACES module imports.

The script is intentionally mechanical:

1. Parse the current flat TechVault SDL.
2. Ask ACES composition to produce the canonical `techvault.*` namespaced
   expansion for that flat payload.
3. Split that namespaced payload into importable fragments with unprefixed
   local keys and already-rewritten references.
4. Parse the modular root and compare it to the canonical expansion.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import shutil
import tempfile
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_PATH = REPO_ROOT / "scenarios" / "techvault.sdl.yaml"
MODULE_DIR = REPO_ROOT / "scenarios" / "techvault"
NAMESPACE = "techvault"

HASHMAP_SECTIONS = (
    "nodes",
    "infrastructure",
    "features",
    "conditions",
    "vulnerabilities",
    "metrics",
    "evaluations",
    "tlos",
    "goals",
    "entities",
    "injects",
    "events",
    "scripts",
    "stories",
    "content",
    "accounts",
    "relationships",
    "agents",
    "objectives",
    "workflows",
)

GROUPED_SECTIONS = (
    "infrastructure",
    "features",
    "conditions",
    "vulnerabilities",
    "content",
    "accounts",
    "relationships",
)


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise TypeError(f"{path} did not load as a YAML mapping")
    return data


def _dump_yaml(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            dict(data),
            allow_unicode=False,
            sort_keys=False,
            width=120,
        ),
        encoding="utf-8",
    )


def _strip_namespace(name: str) -> str:
    prefix = f"{NAMESPACE}."
    if not name.startswith(prefix):
        raise ValueError(f"Expected {name!r} to start with {prefix!r}")
    return name.removeprefix(prefix)


def _metadata(data: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: data[key]
        for key in ("name", "version", "description")
        if key in data
    }


def _canonical_namespaced_payload(flat_data: dict[str, Any]) -> dict[str, Any]:
    from aces_sdl.composition import expand_sdl_modules
    from aces_sdl.parser import _load_normalized_data
    from aces_sdl.scenario import Scenario

    with tempfile.TemporaryDirectory(prefix="techvault-sdl-") as temp_name:
        temp_dir = Path(temp_name)
        module_path = temp_dir / "techvault-flat.sdl.yaml"
        root_path = temp_dir / "root.sdl.yaml"
        _dump_yaml(module_path, flat_data)
        _dump_yaml(
            root_path,
            {
                **_metadata(flat_data),
                "imports": [
                    {
                        "source": "local:techvault-flat.sdl.yaml",
                        "namespace": NAMESPACE,
                    }
                ],
            },
        )
        root_data = _load_normalized_data(root_path.read_text(encoding="utf-8"), path=root_path)
        expanded, _, _, _ = expand_sdl_modules(root_data, path=root_path)
    _rewrite_composition_gaps(expanded)
    return Scenario.model_validate(expanded).model_dump(mode="json", by_alias=True)


def _rewrite_composition_gaps(data: dict[str, Any]) -> None:
    """Patch nested refs that ACES PR #465 composition does not rewrite yet."""

    infrastructure = data.get("infrastructure", {})
    vulnerabilities = data.get("vulnerabilities", {})
    if not isinstance(infrastructure, Mapping) or not isinstance(vulnerabilities, Mapping):
        return

    for node in (data.get("nodes") or {}).values():
        if not isinstance(node, dict):
            continue
        runtime = node.get("runtime")
        if not isinstance(runtime, dict):
            continue

        network = runtime.get("network")
        if isinstance(network, dict):
            for endpoint in network.get("endpoints", []):
                if not isinstance(endpoint, dict):
                    continue
                network_ref = endpoint.get("network")
                prefixed = f"{NAMESPACE}.{network_ref}"
                if isinstance(network_ref, str) and prefixed in infrastructure:
                    endpoint["network"] = prefixed

        for application in runtime.get("applications", []):
            if not isinstance(application, dict):
                continue
            for route in application.get("routes", []):
                if not isinstance(route, dict):
                    continue
                route["vulnerability_refs"] = [
                    f"{NAMESPACE}.{ref}" if isinstance(ref, str) and f"{NAMESPACE}.{ref}" in vulnerabilities else ref
                    for ref in route.get("vulnerability_refs", [])
                ]


def _fragment_for_section(
    *,
    section: str,
    payload: Mapping[str, Any],
    name: str,
) -> dict[str, Any]:
    return {
        "name": name,
        section: {
            _strip_namespace(key): value
            for key, value in payload.items()
        },
    }


def _write_modules(expected: dict[str, Any]) -> list[str]:
    if MODULE_DIR.exists():
        shutil.rmtree(MODULE_DIR)
    imports: list[str] = []

    nodes = expected.get("nodes", {})
    if isinstance(nodes, Mapping):
        for namespaced_node, node_payload in nodes.items():
            node_name = _strip_namespace(namespaced_node)
            rel_path = Path("techvault") / "nodes" / f"{node_name}.sdl.yaml"
            _dump_yaml(
                REPO_ROOT / "scenarios" / rel_path,
                {
                    "name": f"techvault-node-{node_name}",
                    "nodes": {node_name: node_payload},
                },
            )
            imports.append(str(rel_path))

    for section in GROUPED_SECTIONS:
        payload = expected.get(section, {})
        if not isinstance(payload, Mapping) or not payload:
            continue
        rel_path = Path("techvault") / "sections" / f"{section}.sdl.yaml"
        _dump_yaml(
            REPO_ROOT / "scenarios" / rel_path,
            _fragment_for_section(
                section=section,
                payload=payload,
                name=f"techvault-{section}",
            ),
        )
        imports.append(str(rel_path))

    unhandled = [
        section
        for section in HASHMAP_SECTIONS
        if section not in GROUPED_SECTIONS
        and section != "nodes"
        and isinstance(expected.get(section), Mapping)
        and expected.get(section)
    ]
    if unhandled:
        raise ValueError(f"Unhandled non-empty SDL sections: {', '.join(unhandled)}")

    return imports


def _write_root(flat_data: Mapping[str, Any], imports: list[str]) -> None:
    root = {
        **_metadata(flat_data),
        "imports": [
            {
                "source": f"local:{rel_path}",
                "namespace": NAMESPACE,
            }
            for rel_path in imports
        ],
    }
    _dump_yaml(SCENARIO_PATH, root)


def _assert_equivalent(expected: dict[str, Any]) -> None:
    from aces_sdl import parse_sdl_file

    actual = parse_sdl_file(SCENARIO_PATH).model_dump(mode="json", by_alias=True)
    comparable_keys = ("name", "version", "description", *HASHMAP_SECTIONS)
    differences = [
        key
        for key in comparable_keys
        if expected.get(key) != actual.get(key)
    ]
    if differences:
        raise AssertionError("Modular expansion differs for: " + ", ".join(differences))


def main() -> None:
    flat_data = _load_yaml(SCENARIO_PATH)
    if flat_data.get("imports"):
        from aces_sdl import parse_sdl_file

        scenario = parse_sdl_file(SCENARIO_PATH)
        print(
            f"{SCENARIO_PATH.relative_to(REPO_ROOT)} already imports "
            f"{len(flat_data['imports'])} modules and expands to {len(scenario.nodes)} nodes"
        )
        return

    expected = _canonical_namespaced_payload(flat_data)
    imports = _write_modules(expected)
    _write_root(flat_data, imports)
    _assert_equivalent(expected)
    print(f"Wrote {len(imports)} TechVault SDL module imports under {MODULE_DIR.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
