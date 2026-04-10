# ADR-016: Workflows, Targetable Sub-Objects, and Leaf Enum Variables in the SDL

## Status

accepted

## Date

2026-03-29

## Context

[ADR-014](adr-014-scenario-description-language.md) established the SDL as a backend-agnostic scenario specification language grounded in the Open Cyber Range (OCR) SDL. [ADR-015](adr-015-declarative-sdl-objectives.md) then restored declarative experiment objectives to the SDL itself.

When the branch started authoring large, design-first SDL scenarios, three authoring gaps became clear:

- Some scenario posture choices needed to be parameterized, but leaf enum-backed property fields still rejected `${var}` placeholders.
- Objectives could target nodes, features, relationships, and content, but not directly target named service bindings or named ACL rules, which forced authors to introduce indirection for important control paths.
- Stories/scripts/events gave a temporal layer, and `depends_on` gave partial ordering, but branchy and parallel experiment control still had to be flattened rather than expressed directly.

Precedent review suggested a coherent direction:

- **OCR** keeps declarative exercise assessment semantics in the specification layer.
- **CACAO** models workflow intent, targets, and variables declaratively while leaving execution adapters external.
- **OCSF** and **CybORG** both support the idea that service endpoints and network control objects are meaningful scenario elements rather than hidden implementation detail.

The branch therefore needed a fuller SDL, not a return to legacy runtime-coupled schema.

## Decision

Extend the SDL in three coordinated ways.

### 1. Allow `${var}` in non-discriminant leaf enum-backed property fields

Full-value `${var}` placeholders are allowed in selected leaf enum-backed property fields such as:

- `accounts.*.password_strength`
- `entities.*.role`
- `nodes.*.os`
- `nodes.*.asset_value.{confidentiality,integrity,availability}`
- `infrastructure.*.acls[*].action`
- `objectives.*.success.mode`

Discriminant or schema-shaping enum fields remain concrete, especially section `type` tags and other fields that change the active model shape.

### 2. Make named service bindings and named ACL rules first-class target refs

Nested sub-objects become directly referenceable when explicitly named:

- named VM service bindings resolve as `nodes.<node>.services.<service_name>`
- named ACL rules resolve as `infrastructure.<infra>.acls.<acl_name>`

These refs participate in the same objective/relationship resolution rules as other named scenario elements. Service names must be unique within a node, and ACL names must be unique within an infrastructure entry.

### 3. Add a first-class `workflows` section

The SDL gains a declarative workflow graph layer that composes declared objectives without introducing a second action-step schema.

The initial workflow surface supports:

- `objective` steps
- `if` branches over declarative predicates
- `parallel` fanout with explicit join
- `end` terminal steps

Workflow graphs are DAGs: every referenced step must exist, every step must be reachable from `start`, and cycles are rejected.

Objective windows may additionally scope themselves to `workflows` and qualified `steps` using `<workflow>.<step>` syntax. Stories/scripts/events remain the temporal layer; workflows add a logical decision layer.

## Consequences

### Positive

- Scenario posture can now be parameterized more naturally without giving up a concrete symbol table.
- Important control and trust paths such as service endpoints and ACL decisions can be targeted directly instead of only through indirection.
- Branching and parallel experiment logic is now declarative and inspectable in the SDL itself.
- Large example scenarios can encode more of the actual experiment design they intend to run later.

### Negative

- The language surface grows again, increasing the amount of documentation and validation logic that must stay coherent.
- Qualified refs and workflow names introduce more naming conventions that authors must learn.
- Some CACAO concepts are still intentionally excluded, so the presence of `workflows` may create pressure to add richer step types.

### Risks

- Authors may overread workflow semantics as executor behavior unless the distinction between declarative control logic and runtime implementation remains explicit.
- Allowing `${var}` in some enum-backed fields but not others creates a sharper policy surface that docs and errors must explain well.
- Workflow step refs use dotted syntax, so workflow and step names must remain compatible with that addressing scheme.
