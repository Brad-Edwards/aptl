# SDL Design Precedents

Every SDL element is adapted from an existing system or standard. This document traces each element to its source.

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


### From CyRIS


| SDL Element | CyRIS Source                              | What We Adapted                                   |
| ----------- | ----------------------------------------- | ------------------------------------------------- |
| `Content`   | `copy_content`, `emulate_traffic_capture` | Generalized to file/dataset/directory types       |
| `Account`   | `add_account`, `modify_account`           | Added groups, password_strength, SPN, auth_method |


### From CALDERA / Atomic Red Team


| SDL Element               | Source                                   | What We Adapted              |
| ------------------------- | ---------------------------------------- | ---------------------------- |
| `PlatformCommand`         | CALDERA `platforms.{os}.{shell}.command` | Per-OS command variants      |
| `PlatformCommand.cleanup` | Atomic Red Team `cleanup_command`        | Teardown action per platform |


### From STIX 2.1


| SDL Element                | STIX Source                             | What We Adapted                            |
| -------------------------- | --------------------------------------- | ------------------------------------------ |
| `Relationship`             | Relationship SRO (typed directed edges) | Simplified to 7 relationship types         |
| Cross-reference validation | STIX object referencing model           | Source/target resolve to any named element |


### From CACAO v2.0


| SDL Element           | CACAO Source                       | What We Adapted                 |
| --------------------- | ---------------------------------- | ------------------------------- |
| `Variable`            | `playbook_variables`               | Types, defaults, allowed_values |
| `${var}` substitution | CACAO variable substitution syntax | Deferred to instantiation time  |


### From OCSF


| SDL Element         | OCSF Source                   | What We Adapted                               |
| ------------------- | ----------------------------- | --------------------------------------------- |
| `OSFamily` enum     | `Device.os.type_id`           | Vocabulary for OS classification              |
| `ServicePort`       | `NetworkEndpoint`             | Simplified port/protocol/name                 |
| `ExpectedDetection` | Detection Finding event class | `product_name`, `severity_id`, `analytic_uid` |


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
| CACAO workflow steps                    | Overlaps with OCR stories/scripts  | Future: reconciliation needed |
| VSDL SMT verification                   | Research question                  | Future: formal methods layer  |
