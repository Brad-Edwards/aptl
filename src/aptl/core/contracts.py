"""Pure-predicate seam for lab-orchestration runtime contracts (ADR-031).

Each predicate is a cheap, side-effect-free read over already-built
dataclasses. They are the inputs to `icontract.require` decorators on
the `_step_*` consumers in `aptl.core.lab` and any future operation
boundary that wants to assert lab-state preconditions without
duplicating env parsing, config schema, or Docker probes.

ADR-031 guardrails enforced here by construction:

- No Docker / network / filesystem mutation / API / secret-reading
  inside any predicate.
- Profile state derives from `ContainerSettings.enabled_profiles()`,
  not a second hardcoded profile list.
- Predicate names are narrow labels safe to embed in
  `icontract.require` descriptions; no secret-bearing object's
  `repr()` enters the predicate or its result.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig
    from aptl.core.env import EnvVars


def env_is_loaded(env: "EnvVars | None") -> bool:
    """True iff the typed env binding has been populated.

    The orchestration step `_step_load_env` is the only writer; callers
    that consume `ctx.env` use this predicate to refuse running before
    that step.
    """
    return env is not None


def config_is_loaded(config: "AptlConfig | None") -> bool:
    """True iff the strict `AptlConfig` has been loaded for this run."""
    return config is not None


def backend_is_initialized(backend: Any) -> bool:
    """True iff a deployment backend has been resolved for this run.

    `aptl.core.deployment.backend.DeploymentBackend` is a Protocol, so
    the predicate is a presence check; type conformance is enforced at
    construction sites in `aptl.core.deployment`.
    """
    return backend is not None


def ssh_key_is_ready(path: "Path | None") -> bool:
    """True iff `_step_ensure_ssh_keys` recorded a key path on the context.

    The predicate is a population check, not a disk-existence check —
    file existence is the responsibility of the step that produced it
    and of the SSH probe that consumes it (ADR-031: no filesystem reads
    inside contracts).
    """
    return path is not None


def required_profiles_enabled(
    config: "AptlConfig",
    required: frozenset[str],
) -> bool:
    """True iff every profile in ``required`` is enabled in ``config``.

    Reads `config.containers.enabled_profiles()` — the canonical
    Pydantic-validated profile list — and tests subset containment.
    An empty ``required`` is trivially satisfied, which keeps the
    predicate composable for callers that build the requirement set
    dynamically.
    """
    enabled = set(config.containers.enabled_profiles())
    return required.issubset(enabled)
