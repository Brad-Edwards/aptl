# SDL Parser Behavior

The parser (`aptl.core.sdl.parser`) transforms raw YAML into a validated `Scenario` object through three stages: key normalization, shorthand expansion, and model construction.

## Key Normalization

YAML field keys (Pydantic struct fields) are normalized to lowercase with hyphens converted to underscores:

- `Name` → `name`
- `Min-Score` → `min_score`
- `start-time` → `start_time`

**User-defined names are preserved as-is.** Node names, feature names, account names, and other HashMap keys are not transformed. This ensures cross-references remain consistent.

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

Source expansion is skipped inside `relationships` and `agents` sections where `source` is a plain string reference, not a package Source.

## Format Auto-Detection

The parser handles two formats:

- **OCR SDL format:** Top-level `name` field, OCR sections
- **APTL legacy format:** `metadata` block with `id`, `name`, `difficulty`, etc.

Detection: if the normalized data contains a `metadata` key with a dict value, it's APTL legacy. Both formats can coexist in the same YAML.

## Validation Pipeline

1. **YAML parsing** — `yaml.safe_load()`
2. **Key normalization** — lowercase field keys, preserve user names
3. **Shorthand expansion** — source, infrastructure, roles, min-score, feature lists
4. **Pydantic construction** — structural validation (types, ranges, required fields)
5. **Semantic validation** — cross-reference checks (21+ passes, see [validation.md](validation.md))

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
