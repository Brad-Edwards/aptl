"""Module/import expansion for multi-file SDL scenarios."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from aptl.core.sdl._base import is_variable_ref
from aptl.core.sdl._errors import SDLParseError, SDLInstantiationError
from aptl.core.sdl.instantiate import instantiate_scenario
from aptl.core.sdl.module_registry import (
    load_lockfile,
    load_trust_policy,
    resolve_import,
)
from aptl.core.sdl.parser import _load_normalized_data
from aptl.core.sdl.entities import flatten_entities
from aptl.core.sdl.scenario import ImportDecl, ModuleDescriptor, Scenario

_HASHMAP_SECTIONS = (
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


def _prefix(namespace: str, name: str) -> str:
    return f"{namespace}.{name}" if namespace else name


def _private_prefix(namespace: str, name: str) -> str:
    return _prefix(namespace, f"__private.{name}")


def _maybe_rename(name: str, name_map: Mapping[str, str]) -> str:
    if not name or is_variable_ref(name):
        return name
    return name_map.get(name, name)


def _explicit_exports(
    scenario: Scenario,
    descriptor: ModuleDescriptor,
) -> dict[str, set[str]]:
    if scenario.module is None:
        return {
            section: set(getattr(scenario, section).keys())
            for section in _HASHMAP_SECTIONS
            if getattr(scenario, section)
        } | {"entities": set(flatten_entities(scenario.entities))}
    return {
        section: set(names)
        for section, names in descriptor.exports.items()
    } | {"entities": set(descriptor.exports.get("entities", []))}


def _symbol_index(
    scenario: Scenario,
    *,
    namespace: str,
    descriptor: ModuleDescriptor,
) -> dict[str, dict[str, str] | set[str]]:
    entities = set(flatten_entities(scenario.entities))
    exported = _explicit_exports(scenario, descriptor)
    named: dict[str, str] = {}
    section_maps: dict[str, dict[str, str]] = {}
    for section_name in _HASHMAP_SECTIONS:
        section = getattr(scenario, section_name, {})
        if isinstance(section, Mapping):
            section_map = {
                name: (
                    _prefix(namespace, name)
                    if name in exported.get(section_name, set())
                    else _private_prefix(namespace, name)
                )
                for name in section.keys()
            }
            section_maps[section_name] = section_map
            named.update(section_map)
    entity_map = {
        name: (
            _prefix(namespace, name)
            if name in exported.get("entities", set())
            else _private_prefix(namespace, name)
        )
        for name in entities
    }
    named.update(entity_map)
    return {
        "nodes": section_maps.get("nodes", {}),
        "infrastructure": section_maps.get("infrastructure", {}),
        "features": section_maps.get("features", {}),
        "conditions": section_maps.get("conditions", {}),
        "vulnerabilities": section_maps.get("vulnerabilities", {}),
        "metrics": section_maps.get("metrics", {}),
        "evaluations": section_maps.get("evaluations", {}),
        "tlos": section_maps.get("tlos", {}),
        "goals": section_maps.get("goals", {}),
        "entities": entity_map,
        "injects": section_maps.get("injects", {}),
        "events": section_maps.get("events", {}),
        "scripts": section_maps.get("scripts", {}),
        "stories": section_maps.get("stories", {}),
        "content": section_maps.get("content", {}),
        "accounts": section_maps.get("accounts", {}),
        "relationships": section_maps.get("relationships", {}),
        "agents": section_maps.get("agents", {}),
        "objectives": section_maps.get("objectives", {}),
        "workflows": section_maps.get("workflows", {}),
        "named": named,
    }


def _validate_descriptor_exports(
    scenario: Scenario,
    descriptor: ModuleDescriptor,
) -> None:
    for section_name, exported_names in descriptor.exports.items():
        if section_name == "entities":
            available_names = set(flatten_entities(scenario.entities))
        else:
            section_payload = getattr(scenario, section_name, None)
            available_names = (
                set(section_payload.keys())
                if isinstance(section_payload, Mapping)
                else set()
            )
        undefined = sorted(set(exported_names) - available_names)
        if undefined:
            raise SDLParseError(
                f"Module '{descriptor.id}' exports undefined {section_name}: "
                + ", ".join(undefined)
            )


def _rewrite_node(payload: dict[str, Any], symbols: dict[str, dict[str, str] | set[str]]) -> None:
    payload["features"] = {
        _maybe_rename(name, symbols["features"]): role
        for name, role in payload.get("features", {}).items()
    }
    payload["conditions"] = {
        _maybe_rename(name, symbols["conditions"]): role
        for name, role in payload.get("conditions", {}).items()
    }
    payload["injects"] = {
        _maybe_rename(name, symbols["injects"]): role
        for name, role in payload.get("injects", {}).items()
    }
    payload["vulnerabilities"] = [
        _maybe_rename(name, symbols["vulnerabilities"])
        for name in payload.get("vulnerabilities", [])
    ]
    for role in payload.get("roles", {}).values():
        if isinstance(role, dict):
            role["entities"] = [
                _maybe_rename(name, symbols["entities"])
                for name in role.get("entities", [])
            ]


def _rewrite_infrastructure(payload: dict[str, Any], symbols: dict[str, dict[str, str] | set[str]]) -> None:
    payload["dependencies"] = [
        _maybe_rename(name, symbols["named"])
        for name in payload.get("dependencies", [])
    ]
    payload["links"] = [
        _maybe_rename(name, symbols["named"])
        for name in payload.get("links", [])
    ]
    properties = payload.get("properties")
    if isinstance(properties, list):
        rewritten: list[dict[str, Any]] = []
        for item in properties:
            if isinstance(item, dict):
                rewritten.append(
                    {
                        _maybe_rename(name, symbols["named"]): value
                        for name, value in item.items()
                    }
                )
            else:
                rewritten.append(item)
        payload["properties"] = rewritten


def _rewrite_feature(payload: dict[str, Any], symbols: dict[str, dict[str, str] | set[str]]) -> None:
    payload["dependencies"] = [
        _maybe_rename(name, symbols["features"])
        for name in payload.get("dependencies", [])
    ]
    payload["vulnerabilities"] = [
        _maybe_rename(name, symbols["vulnerabilities"])
        for name in payload.get("vulnerabilities", [])
    ]


def _rewrite_entity(payload: dict[str, Any], symbols: dict[str, dict[str, str] | set[str]]) -> None:
    payload["vulnerabilities"] = [
        _maybe_rename(name, symbols["vulnerabilities"])
        for name in payload.get("vulnerabilities", [])
    ]
    payload["tlos"] = [
        _maybe_rename(name, symbols["tlos"])
        for name in payload.get("tlos", [])
    ]
    payload["events"] = [
        _maybe_rename(name, symbols["events"])
        for name in payload.get("events", [])
    ]
    for child in payload.get("entities", {}).values():
        if isinstance(child, dict):
            _rewrite_entity(child, symbols)


def _rewrite_objective_window_ref(ref: str, workflow_names: Mapping[str, str]) -> str:
    if "." not in ref or is_variable_ref(ref):
        return ref
    workflow_name, step_name = ref.rsplit(".", 1)
    if workflow_name not in workflow_names:
        return ref
    return f"{workflow_names[workflow_name]}.{step_name}"


def _rewrite_workflow(payload: dict[str, Any], symbols: dict[str, dict[str, str] | set[str]]) -> None:
    for step in payload.get("steps", {}).values():
        if not isinstance(step, dict):
            continue
        if step.get("objective"):
            step["objective"] = _maybe_rename(
                str(step["objective"]), symbols["objectives"]
            )
        if step.get("workflow"):
            step["workflow"] = _maybe_rename(
                str(step["workflow"]), symbols["workflows"]
            )
        if step.get("compensate_with"):
            step["compensate_with"] = _maybe_rename(
                str(step["compensate_with"]), symbols["workflows"]
            )
        when = step.get("when")
        if isinstance(when, dict):
            when["conditions"] = [
                _maybe_rename(name, symbols["conditions"])
                for name in when.get("conditions", [])
            ]
            when["metrics"] = [
                _maybe_rename(name, symbols["metrics"])
                for name in when.get("metrics", [])
            ]
            when["evaluations"] = [
                _maybe_rename(name, symbols["evaluations"])
                for name in when.get("evaluations", [])
            ]
            when["tlos"] = [
                _maybe_rename(name, symbols["tlos"])
                for name in when.get("tlos", [])
            ]
            when["goals"] = [
                _maybe_rename(name, symbols["goals"])
                for name in when.get("goals", [])
            ]
            when["objectives"] = [
                _maybe_rename(name, symbols["objectives"])
                for name in when.get("objectives", [])
            ]


def _namespace_payload(
    payload: dict[str, Any],
    imported: Scenario,
    namespace: str,
) -> dict[str, Any]:
    namespaced = dict(payload)
    descriptor = imported.module or ModuleDescriptor(
        id=imported.name,
        version=imported.version,
        parameters=sorted(imported.variables.keys()),
        exports={
            section: sorted(getattr(imported, section).keys())
            for section in _HASHMAP_SECTIONS
            if getattr(imported, section)
        },
    )
    _validate_descriptor_exports(imported, descriptor)
    symbols = _symbol_index(imported, namespace=namespace, descriptor=descriptor)

    for node in namespaced.get("nodes", {}).values():
        if isinstance(node, dict):
            _rewrite_node(node, symbols)
    for infra in namespaced.get("infrastructure", {}).values():
        if isinstance(infra, dict):
            _rewrite_infrastructure(infra, symbols)
    for feature in namespaced.get("features", {}).values():
        if isinstance(feature, dict):
            _rewrite_feature(feature, symbols)
    for metric in namespaced.get("metrics", {}).values():
        if isinstance(metric, dict) and metric.get("condition"):
            metric["condition"] = _maybe_rename(
                str(metric["condition"]), symbols["conditions"]
            )
    for evaluation in namespaced.get("evaluations", {}).values():
        if isinstance(evaluation, dict):
            evaluation["metrics"] = [
                _maybe_rename(name, symbols["metrics"])
                for name in evaluation.get("metrics", [])
            ]
    for tlo in namespaced.get("tlos", {}).values():
        if isinstance(tlo, dict) and tlo.get("evaluation"):
            tlo["evaluation"] = _maybe_rename(
                str(tlo["evaluation"]), symbols["evaluations"]
            )
    for goal in namespaced.get("goals", {}).values():
        if isinstance(goal, dict):
            goal["tlos"] = [
                _maybe_rename(name, symbols["tlos"])
                for name in goal.get("tlos", [])
            ]
    for entity in namespaced.get("entities", {}).values():
        if isinstance(entity, dict):
            _rewrite_entity(entity, symbols)
    for inject in namespaced.get("injects", {}).values():
        if isinstance(inject, dict):
            if inject.get("from_entity"):
                inject["from_entity"] = _maybe_rename(
                    str(inject["from_entity"]), symbols["entities"]
                )
            inject["to_entities"] = [
                _maybe_rename(name, symbols["entities"])
                for name in inject.get("to_entities", [])
            ]
            inject["tlos"] = [
                _maybe_rename(name, symbols["tlos"])
                for name in inject.get("tlos", [])
            ]
    for event in namespaced.get("events", {}).values():
        if isinstance(event, dict):
            event["conditions"] = [
                _maybe_rename(name, symbols["conditions"])
                for name in event.get("conditions", [])
            ]
            event["injects"] = [
                _maybe_rename(name, symbols["injects"])
                for name in event.get("injects", [])
            ]
    for script in namespaced.get("scripts", {}).values():
        if isinstance(script, dict):
            script["events"] = {
                _maybe_rename(name, symbols["events"]): value
                for name, value in script.get("events", {}).items()
            }
    for story in namespaced.get("stories", {}).values():
        if isinstance(story, dict):
            story["scripts"] = [
                _maybe_rename(name, symbols["scripts"])
                for name in story.get("scripts", [])
            ]
    for content in namespaced.get("content", {}).values():
        if isinstance(content, dict) and content.get("target"):
            content["target"] = _maybe_rename(
                str(content["target"]), symbols["nodes"]
            )
    for account in namespaced.get("accounts", {}).values():
        if isinstance(account, dict) and account.get("node"):
            account["node"] = _maybe_rename(
                str(account["node"]), symbols["nodes"]
            )
    for relationship in namespaced.get("relationships", {}).values():
        if isinstance(relationship, dict):
            if relationship.get("source"):
                relationship["source"] = _maybe_rename(
                    str(relationship["source"]), symbols["named"]
                )
            if relationship.get("target"):
                relationship["target"] = _maybe_rename(
                    str(relationship["target"]), symbols["named"]
                )
    for agent in namespaced.get("agents", {}).values():
        if isinstance(agent, dict):
            if agent.get("entity"):
                agent["entity"] = _maybe_rename(
                    str(agent["entity"]), symbols["entities"]
                )
            agent["starting_accounts"] = [
                _maybe_rename(name, symbols["accounts"])
                for name in agent.get("starting_accounts", [])
            ]
            knowledge = agent.get("initial_knowledge")
            if isinstance(knowledge, dict):
                knowledge["hosts"] = [
                    _maybe_rename(name, symbols["nodes"])
                    for name in knowledge.get("hosts", [])
                ]
                knowledge["subnets"] = [
                    _maybe_rename(name, symbols["infrastructure"])
                    for name in knowledge.get("subnets", [])
                ]
                knowledge["accounts"] = [
                    _maybe_rename(name, symbols["accounts"])
                    for name in knowledge.get("accounts", [])
                ]
            agent["allowed_subnets"] = [
                _maybe_rename(name, symbols["infrastructure"])
                for name in agent.get("allowed_subnets", [])
            ]
    for objective in namespaced.get("objectives", {}).values():
        if not isinstance(objective, dict):
            continue
        if objective.get("agent"):
            objective["agent"] = _maybe_rename(
                str(objective["agent"]), symbols["agents"]
            )
        if objective.get("entity"):
            objective["entity"] = _maybe_rename(
                str(objective["entity"]), symbols["entities"]
            )
        objective["targets"] = [
            _maybe_rename(name, symbols["named"])
            for name in objective.get("targets", [])
        ]
        objective["depends_on"] = [
            _maybe_rename(name, symbols["objectives"])
            for name in objective.get("depends_on", [])
        ]
        success = objective.get("success")
        if isinstance(success, dict):
            for field_name, symbol_key in (
                ("conditions", "conditions"),
                ("metrics", "metrics"),
                ("evaluations", "evaluations"),
                ("tlos", "tlos"),
                ("goals", "goals"),
            ):
                success[field_name] = [
                    _maybe_rename(name, symbols[symbol_key])
                    for name in success.get(field_name, [])
                ]
        window = objective.get("window")
        if isinstance(window, dict):
            for field_name, symbol_key in (
                ("stories", "stories"),
                ("scripts", "scripts"),
                ("events", "events"),
                ("workflows", "workflows"),
            ):
                window[field_name] = [
                    _maybe_rename(name, symbols[symbol_key])
                    for name in window.get(field_name, [])
                ]
            window["steps"] = [
                _rewrite_objective_window_ref(name, symbols["workflows"])
                for name in window.get("steps", [])
            ]
    for workflow in namespaced.get("workflows", {}).values():
        if isinstance(workflow, dict):
            _rewrite_workflow(workflow, symbols)

    for section_name in _HASHMAP_SECTIONS:
        section_payload = namespaced.get(section_name)
        if not isinstance(section_payload, dict):
            continue
        namespaced[section_name] = {
            symbols[section_name].get(name, _prefix(namespace, name)): value
            for name, value in section_payload.items()
        }
    namespaced["variables"] = {}
    namespaced["module"] = None
    namespaced["imports"] = []
    return namespaced


def _merge_sections(
    root: dict[str, Any],
    incoming: dict[str, Any],
    *,
    path: Path,
) -> dict[str, Any]:
    merged = dict(root)
    for section_name in _HASHMAP_SECTIONS:
        current = dict(merged.get(section_name, {}))
        additions = dict(incoming.get(section_name, {}))
        collisions = sorted(set(current).intersection(additions))
        if collisions:
            raise SDLParseError(
                f"Import from {path} collides on {section_name}: {', '.join(collisions)}"
            )
        current.update(additions)
        merged[section_name] = current
    merged["imports"] = []
    return merged


def _import_decl(value: Any) -> ImportDecl:
    if isinstance(value, ImportDecl):
        return value
    return ImportDecl.model_validate(value)


def expand_sdl_modules(
    data: dict[str, Any],
    *,
    path: Path,
    seen: set[Path] | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Expand local SDL imports into one canonical merged payload."""

    seen = set() if seen is None else set(seen)
    resolved_path = path.resolve()
    if resolved_path in seen:
        raise SDLParseError(f"Import cycle detected at {resolved_path}", path=path)
    seen.add(resolved_path)

    merged = dict(data)
    merged.setdefault("imports", [])
    merged.setdefault("version", "*")
    namespaces: dict[str, str] = {}
    lockfile = load_lockfile(resolved_path.parent)
    trust_policy = load_trust_policy(resolved_path.parent)

    for raw_import in list(merged.get("imports", [])):
        import_decl = _import_decl(raw_import)
        if "__private." in import_decl.namespace:
            raise SDLParseError(
                "Import namespaces may not contain the reserved '__private' segment",
                path=path,
            )
        resolved_import = resolve_import(
            import_decl,
            base_dir=resolved_path.parent,
            lockfile=lockfile,
            trust_policy=trust_policy,
        )
        import_path = resolved_import.root_file
        imported_raw = _load_normalized_data(
            import_path.read_text(encoding="utf-8"),
            path=import_path,
        )
        imported_expanded, imported_namespaces = expand_sdl_modules(
            imported_raw,
            path=import_path,
            seen=seen,
        )
        try:
            imported_scenario = Scenario.model_validate(imported_expanded)
            imported_instantiated = instantiate_scenario(
                imported_scenario,
                parameters=import_decl.parameters,
                validate_semantics=False,
            )
        except SDLInstantiationError as exc:
            raise SDLParseError(str(exc), path=import_path) from exc
        imported_instantiated.module = resolved_import.module_descriptor
        namespace = import_decl.namespace or resolved_import.module_descriptor.id.split("/")[-1]
        namespaced_payload = _namespace_payload(
            imported_instantiated.model_dump(mode="python", by_alias=True),
            imported_instantiated,
            namespace,
        )
        merged = _merge_sections(merged, namespaced_payload, path=import_path)
        namespaces[str(import_path)] = namespace
        namespaces.update(imported_namespaces)

    merged["imports"] = []
    return merged, namespaces
