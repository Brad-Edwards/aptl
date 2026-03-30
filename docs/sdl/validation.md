# SDL Semantic Validation

The semantic validator (`aptl.core.sdl.validator.SemanticValidator`) runs 21 named passes after Pydantic structural validation. It collects all errors rather than failing on the first, so authors see every issue at once.

## Validation Passes

### OCR SDL passes (ported from Rust `Scenario::formalize()`)

| Pass | What It Checks |
|------|----------------|
| `verify_nodes` | Features, conditions, injects, vulnerabilities referenced by nodes exist in their respective sections. Role names on feature/condition/inject assignments must match declared node `roles`. Node names ≤ 35 characters. |
| `verify_infrastructure` | Every infrastructure entry has a matching node. Links reference existing switch/network entries. Dependencies reference existing infrastructure entries. Switch nodes cannot have count > 1, and nodes with conditions cannot scale above 1. Complex property IPs must be valid IPs within the linked switch's CIDR. ACL `from_net` and `to_net` references are each checked and must resolve to switch/network entries. |
| `verify_features` | Vulnerability references exist. Dependency references exist. **Dependency cycle detection** via topological sort. |
| `verify_conditions` | (Structural: command+interval XOR source — enforced by Pydantic) |
| `verify_vulnerabilities` | (Structural: CWE format — enforced by Pydantic) |
| `verify_metrics` | Conditional metrics reference existing conditions. Each condition used by at most one metric. |
| `verify_evaluations` | Referenced metrics exist. Absolute min-score doesn't exceed sum of metric max-scores. |
| `verify_tlos` | Referenced evaluations exist. |
| `verify_goals` | Referenced TLOs exist. |
| `verify_entities` | TLO, vulnerability, and event references on entities (including nested) exist. |
| `verify_injects` | from-entity and to-entities reference existing (possibly nested) entities. TLO references exist. |
| `verify_events` | Condition and inject references exist. |
| `verify_scripts` | Event references exist. Event times within script start/end bounds. |
| `verify_stories` | Script references exist. |
| `verify_roles` | Entity references in node roles resolve to flattened entity names. |

### Extension passes

| Pass | What It Checks |
|------|----------------|
| `verify_content` | Content targets reference existing VM nodes. |
| `verify_accounts` | Account nodes reference existing VM nodes. |
| `verify_relationships` | Source and target resolve to any named element in any section, including variables, relationships, and content item names. |
| `verify_agents` | Entity references resolve. Starting accounts and initial-knowledge accounts exist in accounts section. Allowed subnets and initial-knowledge subnets must resolve to switch-backed infrastructure entries. Initial-knowledge hosts must resolve to VM nodes. Initial-knowledge services exist in `nodes.*.services[].name`. |
| `verify_objectives` | Objective actors resolve (`agent` or `entity`). Objective actions must be declared by the referenced agent. Targets resolve to named scenario elements. Success criteria resolve to declared conditions/metrics/evaluations/TLOs/goals. Optional windows resolve to stories/scripts/events and must remain internally consistent. Objective dependencies must resolve and stay acyclic. |
| `verify_variables` | Checks that full-value `${var}` placeholders reference declared variables. Structural validation of typed defaults and `allowed_values` still happens in the `Variable` model itself. |

When a field contains an unresolved `${var}` placeholder, reference-oriented passes treat it as deferred rather than as a broken concrete reference. The validator still does not substitute values; it only checks that the placeholder names exist.

## Advisories

Successful parses may still carry non-fatal advisories on `Scenario.advisories`. These are not validation errors and do not block parsing.

Current advisory coverage:

- VM nodes without `resources` are allowed, but emit an advisory because some deployment backends may not be able to instantiate them without explicit sizing defaults.

## Error Reporting

All passes run to completion. Errors are collected into a list and raised as a single `SDLValidationError`:

```python
try:
    scenario = parse_sdl(yaml_string)
except SDLValidationError as e:
    print(f"{len(e.errors)} errors found:")
    for error in e.errors:
        print(f"  - {error}")
```

## Cross-Reference Resolution

The `_all_named_elements()` method collects keys from all top-level sections for relationship validation, plus nested entity dot-paths and content item `name` values. This means a relationship can reference any node, feature, condition, vulnerability, infrastructure entry, metric, evaluation, TLO, goal, entity (including nested), inject, event, script, story, content entry, content item, account, agent, objective, relationship, or variable.
