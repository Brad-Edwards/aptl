# Property-Based Parser Regression Tests

This note captures the repo-level guardrails for property-based tests that
exercise parser-style boundaries such as credentials rendering, `.env`
loading, strict first-party config validation, redaction, and SDL parsing.
It complements the SDL-specific fuzz suite in `tests/test_sdl_fuzz.py`.

## Scope

Property-based tests are appropriate for code that accepts attacker-controlled
or operator-authored strings and then parses, normalizes, validates, redacts,
or renders them. Current canonical candidates include:

- `aptl.core.credentials.sync_dashboard_config()` and
  `aptl.core.credentials.sync_manager_config()`
- `aptl.core.env.load_dotenv()` and `env_vars_from_dict()`
- `aptl.core.config.load_config()` / `AptlConfig`
- `aptl.utils.redaction.redact()`
- SDL parser and scalar parser helpers under `aptl.core.sdl`

## Guardrails

- Mark property-based tests with `pytest.mark.fuzz`; default `pytest` skips
  them via `pyproject.toml`, and `pytest -m fuzz` is the canonical manual run.
- Use Hypothesis deadlines on parser/performance regression tests so pathological
  regex or string-walk behavior fails as a test, not as a hung job.
- Assert bounded, classified outcomes: a fuzzed parser either returns a valid
  value/artifact or raises the existing public error type for that boundary.
  Do not accept unhandled `TypeError`, `KeyError`, `AttributeError`, runaway
  CPU, partial writes, or silent stale output.
- Keep fuzz fixtures synthetic and local. Do not read real `.env` files, emit
  real secrets, call Docker, start services, or cross process/network boundaries.
- Reuse existing path layout helpers and canonical source/rendered locations
  when testing credential rendering; do not add caller-controlled output paths
  just to make tests easier.
- When generated inputs include secret-shaped values, assert through artifact
  structure and redaction outcomes rather than logging or snapshotting raw
  generated secrets.

## Boundary Ownership

- Strict durable config shape belongs to `AptlConfig` and Pydantic validation.
  Tests should not create a second config schema or duplicate allowed profile
  names.
- `.env` parsing and required variable checks belong to `aptl.core.env`.
  Tests should exercise that boundary directly instead of parsing `.env`
  syntax in helper code.
- Credential rendering belongs to `aptl.core.credentials`: project-root
  containment, no-symlink generated paths, XML/YAML escaping, atomic writes,
  and `CredentialRenderError` / `PathContainmentError` semantics remain part
  of the contract.
- Serialization-boundary secret handling belongs to `aptl.utils.redaction`
  and ADR-029. New parser tests must not introduce a parallel secret taxonomy.
- SDL parse failures must stay inside `SDLParseError` /
  `SDLValidationError`.

## Non-Goals

- Do not use property tests to redesign parser APIs, exception hierarchies,
  config ownership, or generated artifact locations.
- Do not make fuzz tests part of the default suite unless the repo-wide
  `pytest` marker policy changes first.
- Do not replace targeted unit tests for known security regressions; property
  tests are additional coverage for input-space exploration.
