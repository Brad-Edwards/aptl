# SDL Design Precedents

Every SDL element is adapted from an existing system or standard. This document traces each element to its source.

The SDL does not borrow every concern from the same place. In practice:

- the **section layout and author-facing YAML surface** start from Open Cyber
  Range SDL
- **exercise intent, variables, and workflow graph shape** draw primarily from
  CACAO
- **cross-object reference style** draws from STIX
- **control-flow semantics** are tightened using mature workflow and
  state-machine systems such as AWS Step Functions, Argo Workflows, and W3C
  SCXML
- **portable runtime/result contracts** follow the language-neutral boundary
  style used by systems such as Kubernetes, Temporal, and OpenC2

So the source tables below explain both where a section's author-facing shape
comes from and, where needed, which systems inform its execution semantics.

## Core Structure (from Open Cyber Range SDL)

The 14 base sections start from the [OCR SDL](https://github.com/Open-Cyber-Range/SDL-parser) v0.21.2 surface and are adapted into Python/Pydantic. This branch aims for coverage parity across the adopted OCR concepts while remaining its own SDL; when behavior diverges or OCR's own sources disagree, this document states branch behavior explicitly instead of making clone-level compatibility claims. The OCR SDL was developed by the Norwegian Cyber Range (CR14/NTNU).


| SDL Element                | OCR Source                | Changes                                             |
| -------------------------- | ------------------------- | --------------------------------------------------- |
| Scenario                   | `Scenario` struct         | Added APTL extension fields                         |
| Node (VM/Switch)           | `Node`, `VM`, `Switch`    | Added `os`, `os_version`, `services`, `asset_value` |
| Resources                  | `Resources`               | Human-readable RAM parsing via Python               |
| Role                       | `Role`                    | Direct port                                         |
| InfraNode                  | `InfraNode`               | Added `acls`, `internal` flag                       |
| Feature                    | `Feature`                 | Direct port                                         |
| Condition                  | `Condition`               | Added `timeout`, `retries`, `start_period`          |
| Vulnerability              | `Vulnerability`           | Direct port                                         |
| Metric/Evaluation/TLO/Goal | OCR scoring pipeline      | Direct port                                         |
| Entity                     | `Entity` + OCR entity surface | Direct port, including OCR fact maps            |
| Inject/Event/Script/Story  | OCR orchestration         | Direct port                                         |
| Source                     | `Source` (name + version) | Made provider-neutral                               |


## Extensions by Source

### From CybORG CAGE Challenge


| SDL Element             | CybORG Source                               | What We Adapted                               |
| ----------------------- | ------------------------------------------- | --------------------------------------------- |
| `Agent`                 | `Agents:` section (Scenario YAML)           | Actions, starting sessions, reward calculator |
| `InitialKnowledge`      | `INT:` (Initial Network Topology)           | Known hosts and subnets at start              |
| `Agent.allowed_subnets` | `AllowedSubnets:`                           | Network scope constraints                     |
| `AssetValue`            | `ConfidentialityValue`, `AvailabilityValue` | Extended to CIA triad                         |
| `ACLRule`               | `Subnets.NACLs`                             | Simplified from nested dict to flat rule list |
| `Objective.agent/actions` | Agent identity + action space             | Objective actor binding and optional action subset validation |


### From CyRIS


| SDL Element | CyRIS Source                              | What We Adapted                                   |
| ----------- | ----------------------------------------- | ------------------------------------------------- |
| `Content`   | `copy_content`, `emulate_traffic_capture` | Generalized to file/dataset/directory types       |
| `Account`   | `add_account`, `modify_account`           | Added groups, password_strength, SPN, auth_method |


### From STIX 2.1


| SDL Element                | STIX Source                             | What We Adapted                            |
| -------------------------- | --------------------------------------- | ------------------------------------------ |
| `Relationship`             | Relationship SRO (typed directed edges) | Simplified to 7 relationship types         |
| Cross-reference validation | STIX object referencing model           | Source/target resolve to any named element |


### From CACAO v2.0


| SDL Element           | CACAO Source                       | What We Adapted                                                        |
| --------------------- | ---------------------------------- | ---------------------------------------------------------------------- |
| `Variable`            | `playbook_variables`               | Types, defaults, allowed_values                                        |
| `${var}` substitution | CACAO variable substitution syntax | Deferred to instantiation time                                         |
| `Objective`           | agent/target/workflow context      | Declarative actor-target-window-success binding without runtime probes |
| `Workflow`            | workflow-step graph patterns       | Branching/parallel objective composition with SDL-only step types      |


### Control-Flow Semantics from Mature Workflow Systems

These sources do not define the YAML keys directly, but they strongly inform
how APTL interprets workflow behavior after parsing.

| Concern | Primary Sources | What We Adapted |
| ------- | --------------- | --------------- |
| Conditional branching over declared predicates | AWS Step Functions `Choice`, CACAO conditional steps | Explicit decision nodes with typed predicate dependencies instead of backend-local branching rules |
| Parallel branch execution and convergence | AWS Step Functions `Parallel`, W3C SCXML `parallel`, Argo DAG fan-out/fan-in patterns | Parallel branches are explicit, joins are explicit barriers, and foreign entry into a join is rejected |
| Retry and terminal outcome meaning | AWS Step Functions `Retry`/`Catch`, Argo retry strategy | Retry behavior is part of workflow semantics rather than a hidden adapter loop |
| Observable step state | Step Functions execution-visible state, SCXML completion semantics | Only selected step kinds expose portable lifecycle/outcome state for predicates and backend results |
| Workflow semantics as a first-class assurance surface | SCXML state-machine model, Kepler FM guidance for workflows/state machines | Workflow changes are treated as `FM3` state-machine work, not just parser changes |


### Runtime Boundary and Contract Precedents

These sources inform the runtime/result contract rather than the SDL YAML
surface.

| Concern | Primary Sources | What We Adapted |
| ------- | --------------- | --------------- |
| Language-neutral backend boundary | Kubernetes API objects, Temporal payload/history model, OpenC2 abstract model + JSON serialization | Backends exchange plain-data, versioned workflow result envelopes rather than Python object identity |
| Explicit compiled contract between definition and execution | Kubernetes versioned object schemas, Temporal workflow definition vs event-history separation | Compiler emits a dedicated `result_contract` instead of forcing the manager to infer semantics from incidental planner payloads |
| Internal typed adapters behind a plain-data boundary | Temporal SDK data conversion, Kubernetes typed models over portable representations | Python typed workflow result models are internal normalization helpers, not the backend protocol |


### From OCSF


| SDL Element     | OCSF Source         | What We Adapted                  |
| --------------- | ------------------- | -------------------------------- |
| `OSFamily` enum | `Device.os.type_id` | Vocabulary for OS classification |
| `ServicePort`   | `NetworkEndpoint`   | Simplified port/protocol/name; named bindings become first-class refs |


### From Docker / Deployment Patterns


| SDL Element                              | Source                          | What We Adapted              |
| ---------------------------------------- | ------------------------------- | ---------------------------- |
| `SimpleProperties.internal`              | Docker Compose `internal: true` | Network egress blocking flag |
| `Condition.timeout/retries/start_period` | Docker health check fields      | Direct mapping               |


## Deliberate Omissions

These were considered and explicitly excluded:


| Concept                                 | Why Excluded                       | Where It Belongs              |
| --------------------------------------- | ---------------------------------- | ----------------------------- |
| Port mappings (host:container)          | Backend-specific deployment detail | Provider binding layer        |
| Volume mounts                           | Backend-specific deployment detail | Provider binding layer        |
| Linux capabilities (NET_RAW, SYS_ADMIN) | Backend-specific security config   | Provider binding layer        |
| Docker Compose profiles                 | Backend-specific grouping          | Provider binding layer        |
| Dockerfile/build context                | Backend-specific build detail      | Provider binding layer        |
| Container entrypoints                   | Backend-specific runtime config    | Provider binding layer        |
| Gymnasium/PettingZoo API bindings       | Framework coupling                 | Agent runtime layer           |
| Terraform module composition            | Requires compositional model       | Future: module system         |
| Full CACAO workflow surface             | Current SDL keeps workflows objective-centric and excludes loops / switch / exceptions | Future: richer control flow |
| Full Step Functions / SCXML execution model | Current SDL adopts only the parts needed for objective-centric branching, retry, and explicit joins | Future: richer workflow/event semantics if the SDL grows beyond current scope |
| VSDL SMT verification                   | Too heavyweight for broad default use today | Selective future extension beyond the lightweight formal-methods policy |
