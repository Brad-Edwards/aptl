# SDL Semantic Validation

The semantic validator (`aptl.core.sdl.validator.SemanticValidator`) runs 20 named passes after Pydantic structural validation. It collects all errors rather than failing on the first, so authors see every issue at once.

## Validation Passes

### OCR SDL passes (ported from Rust `Scenario::formalize()`)

| Pass | What It Checks |
|------|----------------|
| `verify_nodes` | Features, conditions, injects, vulnerabilities referenced by nodes exist in their respective sections. Role names on feature/condition/inject assignments match node's roles. Node names ≤ 35 characters. |
| `verify_infrastructure` | Every infrastructure entry has a matching node. Links and dependencies reference existing infrastructure entries. Switch nodes cannot have count > 1. Complex property IPs are within linked node's CIDR. ACL from/to network references exist. |
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
| `verify_content` | Content targets reference existing nodes. |
| `verify_accounts` | Account nodes reference existing nodes. |
| `verify_relationships` | Source and target resolve to any named element in any section. |
| `verify_agents` | Entity references resolve. Starting accounts and initial-knowledge accounts exist in accounts section. Allowed subnets and initial-knowledge subnets exist in infrastructure. Initial-knowledge hosts exist in nodes. Initial-knowledge services exist in `nodes.*.services[].name`. |
| `verify_variables` | Structural validation of typed defaults and `allowed_values`. `${var}` substitution in other sections is still checked at instantiation time. |

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

The `_all_named_elements()` method collects keys from all sections for relationship validation. This means a relationship can reference any node, feature, condition, vulnerability, account, entity (including nested), metric, evaluation, TLO, goal, inject, event, script, story, content item, or agent.
