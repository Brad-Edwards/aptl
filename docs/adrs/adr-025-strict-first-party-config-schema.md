# ADR-025: Strict first-party config schema

## Status

accepted

## Date

2026-05-05

## Context

APTL's checked-in `aptl.json` is first-party project configuration consumed by
the Python control plane described in [ADR-007](adr-007-python-cli-control-plane.md).
The canonical loading path is `aptl.core.config.load_config`, which parses JSON
and validates it into `AptlConfig` and nested Pydantic models before CLI,
deployment, lab lifecycle, run storage, and API code use it.

The nested models already reject unknown keys with `ConfigDict(extra="forbid")`,
but the top-level `AptlConfig` has allowed unknown sections. That has let dead
top-level sections live in `aptl.json` without any runtime consumer, and it would
also let spelling mistakes pass validation.

This differs from external payload models, such as third-party MISP API records,
where ignoring provider-owned extra fields can be correct because APTL does not
own the upstream schema.

## Decision

Treat `aptl.json` as a strict first-party schema at every level.

- Top-level `AptlConfig` and nested first-party config models should reject
  unknown keys through Pydantic validation.
- A top-level section may be present in checked-in `aptl.json` only when it has
  an explicit Pydantic model field and at least one runtime consumer or documented
  owner in the control plane.
- Future config additions must enter through `src/aptl/core/config.py` first,
  then be consumed by the relevant domain boundary (`core/lab.py`,
  `core/deployment`, run storage, API response schema, or another existing
  control-plane owner). Do not add pass-through dictionaries for speculative
  future use.
- Unknown keys in user-authored `aptl.json` are errors, not warnings. Silent or
  warn-only handling is reserved for compatibility migrations with an explicit
  removal window.

## Consequences

### Positive

- Typos and stale sections fail during `aptl config validate`, lab startup, and
  any other path that uses `load_config`.
- The checked-in config stays aligned with the fields that the runtime actually
  consumes.
- Validation remains centralized in Pydantic instead of being duplicated in CLI,
  API, deployment, or lab lifecycle code.

### Negative

- Users carrying older local configs with stale top-level sections must remove
  or migrate them before commands run.
- Intentional future config needs a real schema and owner before it can be
  checked in.

### Risks

- API paths that load config should continue to surface validation failures
  clearly; adding strictness without preserving the existing loading boundary
  could produce inconsistent CLI/API behavior.
- Do not confuse first-party `aptl.json` strictness with external API payload
  handling. Provider-owned records may still need tolerant models at ingestion
  boundaries.

## References

- [ADR-005](adr-005-docker-compose-profiles.md): `aptl.json` drives Docker
  Compose profile selection
- [ADR-007](adr-007-python-cli-control-plane.md): Python CLI and Pydantic
  validation are the control-plane boundary
- Issue [#190](https://github.com/Brad-Edwards/aptl/issues/190)—top-level
  config drift is silent
