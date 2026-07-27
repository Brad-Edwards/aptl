"""Deterministic redaction for volatile participant proof identifiers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping


def redact_volatile_proof_identifiers(
    proof: dict[str, object],
    participant_address: str,
) -> dict[str, object]:
    """Normalize per-run IDs before evidence is committed."""

    replacements = {}
    replacements.update(_operation_id_replacements(proof))
    replacements.update(_episode_id_replacements(proof))
    replacements.update(_action_instance_replacements(proof, participant_address))
    return _replace_proof_strings(proof, replacements)


def _operation_id_replacements(proof: Mapping[str, object]) -> dict[str, str]:
    """Return replacements for per-run operation ids."""

    receipt = proof.get("operation_receipt")
    replacements: dict[str, str] = {}
    if isinstance(receipt, Mapping):
        operation_id = receipt.get("operation_id")
        if isinstance(operation_id, str) and operation_id:
            replacements[operation_id] = "operation-id-redacted"
    return replacements


def _episode_id_replacements(proof: Mapping[str, object]) -> dict[str, str]:
    """Return replacements for per-run participant episode ids."""

    results = proof.get("participant_episode_results")
    replacements: dict[str, str] = {}
    if isinstance(results, Mapping):
        for result in results.values():
            if isinstance(result, Mapping):
                episode_id = result.get("episode_id")
                if isinstance(episode_id, str) and episode_id:
                    replacements[episode_id] = "episode-id-redacted"
    return replacements


def _action_instance_replacements(
    proof: Mapping[str, object],
    participant_address: str,
) -> dict[str, str]:
    """Return replacements for per-run participant action-instance ids."""

    replacements: dict[str, str] = {}
    redacted = f"{participant_address}.action-instance-redacted"
    for event in _iter_behavior_events(proof):
        action_instance_id = event.get("action_instance_id")
        if isinstance(action_instance_id, str) and action_instance_id:
            replacements[action_instance_id] = redacted
    return replacements


def _iter_behavior_events(
    proof: Mapping[str, object],
) -> Iterable[Mapping[str, object]]:
    """Yield behavior-history event mappings from the proof payload."""

    behavior_history = proof.get("participant_behavior_history")
    if isinstance(behavior_history, Mapping):
        for events in behavior_history.values():
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, Mapping):
                    yield event


def _replace_proof_strings(
    value: object,
    replacements: Mapping[str, str],
) -> object:
    """Apply redactions recursively across a proof payload."""

    result = value
    if isinstance(value, str):
        result = _replace_string(value, replacements)
    elif isinstance(value, list):
        result = [_replace_proof_strings(item, replacements) for item in value]
    elif isinstance(value, dict):
        result = {
            str(_replace_proof_strings(key, replacements)): _replace_proof_strings(
                item, replacements
            )
            for key, item in value.items()
        }
    return result


def _replace_string(value: str, replacements: Mapping[str, str]) -> str:
    """Apply digest and identifier redactions to one string value."""

    result = value
    if value.startswith("sha256:") and len(value) > len("sha256:") + 16:
        result = "sha256:redacted-proof-digest"
    else:
        for old, new in replacements.items():
            result = result.replace(old, new)
    return result
