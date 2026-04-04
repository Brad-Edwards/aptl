# SDL Semantic Validation

The semantic validator (`aptl.core.sdl.validator.SemanticValidator`) runs 22 named passes after Pydantic structural validation. It collects all errors rather than failing on the first, so authors see every issue at once.

Under the repository's [coding standards](../reference/coding-standards.md),
this layer is primarily an `FM1` and `FM2` surface. It is where static semantic
invariants such as cross-reference resolution, ambiguity, uniqueness,
reachability, and fail-closed graph constraints are enforced. Those invariants
must stay aligned with the runtime compiler and planner contracts rather than
becoming a validator-only interpretation of the SDL.

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
| `verify_relationships` | Source and target resolve to any named element in any section, including variables, relationships, content item names, named service bindings, and named ACL rules. Ambiguous bare refs are rejected with qualified alternatives. |
| `verify_agents` | Entity references resolve. Starting accounts and initial-knowledge accounts exist in accounts section. Allowed subnets and initial-knowledge subnets must resolve to switch-backed infrastructure entries. Initial-knowledge hosts must resolve to VM nodes. Initial-knowledge services exist in `nodes.*.services[].name`. |
| `verify_objectives` | Objective actors resolve (`agent` or `entity`). Objective actions must be declared by the referenced agent. Targets resolve to named scenario elements, including qualified service/ACL refs and section-qualified top-level refs. Ambiguous bare refs are rejected with qualified alternatives. Success criteria resolve to declared conditions/metrics/evaluations/TLOs/goals. Optional windows resolve through one shared normalized analysis over stories/scripts/events/workflows/workflow-steps, must remain internally consistent, and fail closed on dangling or out-of-window refs. Objective dependencies must resolve and stay acyclic. |
| `verify_workflows` | Workflow `start` and every referenced step must exist. `objective`/`retry` steps must reference declared objectives. Predicate refs must resolve to declared conditions/metrics/evaluations/TLOs/goals/objectives, and step-state refs must resolve to prior executable steps whose state is guaranteed to be known before the predicate runs. Workflow graphs must be acyclic and fully reachable from `start`. Parallel joins must be explicit barriers, every explicit branch path must converge on the declared join, branch-local state remains scoped until the join, and post-join predicates may inspect only branch steps guaranteed on every path within their branch before the join. |
| `verify_variables` | Checks that full-value `${var}` placeholders reference declared variables. Structural validation of typed defaults and `allowed_values` still happens in the `Variable` model itself. |

When a field contains an unresolved `${var}` placeholder, reference-oriented
passes treat it as deferred rather than as a broken concrete reference. The
validator still does not substitute values; the later repo-owned instantiation
phase performs substitution, type-checking, and concrete revalidation before
runtime compilation.

The SDL validator is intentionally structural/semantic. The SDL-native runtime
compiler performs additional fail-closed binding checks, including node-local
feature dependency enforcement and bound-resource reference resolution.

## Static Semantic Invariants

The validator is the main enforcement point for static SDL semantics, but not
the only source of truth. The same rules must remain consistent with compiled
runtime models and downstream runtime contracts.

Typical invariant categories in this layer include:

- cross-reference existence and disambiguation
- uniqueness rules for names and bindings
- acyclic dependency and workflow graphs
- fail-closed resolution for ambiguous or missing references
- reachability and convergence constraints
- “guaranteed to be known before evaluation” visibility rules

In coding-standards terms:

- `FM1` covers static semantic rules such as ambiguity, uniqueness, and
  fail-closed reference resolution
- `FM2` covers graph/constraint rules such as reachability, visibility, and
  consistency across validator and compiled/runtime forms

Workflows are the clearest current example. Their syntax is described in YAML,
but the important semantics live here and in the runtime architecture: which
steps are reachable, which joins are legal, and which prior step states are
knowable before a predicate executes.

Objective windows are now the clearest current `FM2` example. Their authoring
surface is still simple YAML, but the semantic meaning comes from one shared
analysis pass that resolves normalized references, checks story/script/event and
workflow/step consistency, derives refresh semantics, and feeds both validator
errors and compiled runtime forms.

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

Generic refs are indexed in two forms:

- bare names like `webapp` when they are unique in the generic-ref namespace
- qualified names like `nodes.webapp`, `features.postgres`, `infrastructure.dmz-net`, or `content.mailbox.items.invoice.eml`

The index also includes nested entity dot-paths, named service bindings (`nodes.<node>.services.<service_name>`), and named ACL rules (`infrastructure.<infra>.acls.<acl_name>`). This means a relationship can reference any node, feature, condition, vulnerability, infrastructure entry, metric, evaluation, TLO, goal, entity (including nested), inject, event, script, story, content entry, content item, account, agent, objective, workflow, relationship, variable, named service binding, or named ACL rule. When a bare ref maps to multiple elements, validation fails and asks the author to use one of the qualified alternatives.
