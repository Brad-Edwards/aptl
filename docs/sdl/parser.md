# SDL Parser Behavior

The parser (`aptl.core.sdl.parser`) transforms raw YAML into a validated `Scenario` object through three stages: key normalization, shorthand expansion, and model construction.

This layer is intentionally about syntax, normalization, and structural model
construction. It is usually an `FM0` surface under the repository's
[coding standards](../reference/coding-standards.md): parser work normally
needs ordinary tests, not state-machine modeling or solver-backed formal
artifacts, unless it also introduces new semantic invariants above raw syntax.

## Key Normalization

YAML field keys (Pydantic struct fields) are normalized to lowercase with hyphens converted to underscores:

- `Name` → `name`
- `Min-Score` → `min_score`
- `start-time` → `start_time`

**User-defined names are preserved as-is.** Node names, feature names, account names, entity fact keys, and other HashMap keys are not transformed. This ensures cross-references remain consistent.

```yaml
# "My-Switch" is preserved, "Type" is normalized to "type"
nodes:
  My-Switch:
    Type: Switch
```

## Shorthand Expansion

Several shorthand forms are expanded before model construction:

| Shorthand | Expands To |
|-----------|------------|
| `source: "pkg-name"` | `source: {name: "pkg-name", version: "*"}` |
| `infrastructure: {node: 3}` | `infrastructure: {node: {count: 3}}` |
| `roles: {admin: "username"}` | `roles: {admin: {username: "username"}}` |
| `min-score: 50` | `min-score: {percentage: 50}` |
| `features: [svc-a, svc-b]` (on nodes) | `features: {svc-a: "", svc-b: ""}` |

Source expansion only applies to actual SDL `source` fields. It is skipped inside `relationships` and `agents` where `source` is a plain string reference, and it does not fire on user-defined map keys that merely happen to be named `source`.

Shorthand expansion also works when the shorthand value is a full variable placeholder. For example, `infrastructure: {web: ${replicas}}` expands to `infrastructure: {web: {count: ${replicas}}}`, and `min-score: ${pass_pct}` expands to `min-score: {percentage: ${pass_pct}}`.

## Variables

Full-value `${var_name}` placeholders are preserved as literal strings during parsing. Structural validation currently accepts placeholders in ordinary string fields, common scalar/time fields, many reference values, and selected leaf enum-backed property fields. The parser does not substitute variables or evaluate expressions. It also rejects placeholders in user-defined mapping keys, because those keys define the SDL symbol table and must stay concrete.

The intended boundary is:

- **Concrete identifiers**: mapping keys that define named scenario elements such as `nodes.web`, `features.apache`, `accounts.db-admin`, `relationships.app-to-db`
- **Variable-backed values**: attributes on those elements such as hostnames, ports, counts, CIDRs, paths, timings, descriptions, and other field values

So a hostname may come from `${hostname}`, but a node key like `web` may not.

## OCR Duration Grammar

Script and event times accept the documented OCR time units:

- `y`, `year`
- `mon`, `month`
- `w`, `week`
- `d`, `day`
- `h`, `hour`
- `m`, `min`, `minute`
- `s`, `sec`, `second`
- `ms`, `us`/`µs`, `ns`

Durations may be written with spaces or `+` separators, such as `1h 30min`
or `1m+30`. Sub-second values are rounded up to whole seconds, so `1 ms`
parses as `1`. Negative numeric durations are rejected rather than silently
coerced.

## Format Boundary

The parser accepts one format:

- **SDL format:** Top-level `name` field plus SDL sections

Legacy APTL scenario YAMLs with a `metadata` block are intentionally rejected in this branch. They must be migrated to SDL before parsing.

## Validation Pipeline

1. **YAML parsing** — `yaml.safe_load()`
2. **Key normalization** — lowercase field keys, preserve user names
3. **Shorthand expansion** — source, infrastructure, roles, min-score, feature lists
4. **Pydantic construction** — structural validation (types, ranges, required fields)
5. **Semantic validation** — cross-reference checks plus variable-reference checks (22 passes, see [validation.md](validation.md))

On success, the returned `Scenario` may still carry non-fatal advisories in `scenario.advisories` (for example, VM nodes without explicit `resources`).

## API

```python
from aptl.core.sdl import parse_sdl, parse_sdl_file

# Parse from string
scenario = parse_sdl(yaml_string)

# Parse from file
scenario = parse_sdl_file(Path("scenario.yaml"))

# Structural validation only (skip cross-reference checks)
scenario = parse_sdl(yaml_string, skip_semantic_validation=True)
```

## Error Types

- `SDLParseError` — YAML syntax errors, structural validation failures
- `SDLValidationError` — semantic validation failures (has `.errors` list with all issues)
