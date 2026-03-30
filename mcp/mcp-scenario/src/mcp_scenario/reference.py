"""Comprehensive SDL reference documentation for agent consumption.

This module provides the full SDL syntax and semantics reference that
agents need to generate valid scenarios without access to the APTL
source code.
"""

SDL_REFERENCE = r"""
# APTL Scenario Description Language (SDL) Reference

## Overview

The SDL is a YAML-based language for defining cybersecurity exercise
scenarios. A scenario is a single YAML document with up to 21 named
sections. Only `name` is required; all other sections are optional.

Key conventions:
- Keys are **case-insensitive** (`Name` = `name`) and **hyphens become
  underscores** (`min-score` = `min_score`).
- User-defined identifiers (node names, feature names, etc.) are
  **preserved as-is** — they form the scenario's symbol table.
- Cross-references between sections use these identifiers.
- `${variable_name}` placeholders can appear in most value positions.
  They are NOT resolved at parse time.
- Unknown keys are **rejected** (extra="forbid").

---

## Top-Level Structure

```yaml
name: my-scenario          # REQUIRED — string identifier
description: >             # Optional multi-line description
  A brief description.

# --- 21 optional sections (all are dicts keyed by user-defined names) ---
nodes: {}
infrastructure: {}
features: {}
conditions: {}
vulnerabilities: {}
metrics: {}
evaluations: {}
tlos: {}
goals: {}
entities: {}
injects: {}
events: {}
scripts: {}
stories: {}
content: {}
accounts: {}
relationships: {}
agents: {}
objectives: {}
workflows: {}
variables: {}
```

---

## Section Reference

### 1. nodes

Defines VMs and network switches. Each key is a node name (max 35 chars).

```yaml
nodes:
  # A network switch (layer-2 segment)
  corp-net:
    type: Switch          # REQUIRED: "VM" or "Switch"
    description: Corporate network

  # A virtual machine
  web-server:
    type: VM              # REQUIRED
    description: Web application server
    os: linux             # Optional: windows, linux, macos, freebsd, other
    os_version: "22.04"   # Optional string
    source: ubuntu-server # Shorthand for {name: "ubuntu-server", version: "*"}
    # or longhand:
    # source:
    #   name: ubuntu-server
    #   version: "22.04"
    resources:
      ram: 4 GiB          # Human-readable: GiB, MiB, GB, MB, etc.
      cpu: 2              # Integer >= 1
    features:             # Dict of feature-name -> role-name (or "")
      nginx: web-admin
    conditions:           # Dict of condition-name -> role-name (or "")
      http-healthy: web-admin
    injects:              # Dict of inject-name -> role-name (or "")
      advisory: web-admin
    vulnerabilities:      # List of vulnerability names
      - sqli-login
    roles:                # Dict of role-name -> Role
      web-admin:
        username: admin
        entities: [blue-team.web-ops]  # Optional entity refs
    services:             # List of ServicePort
      - port: 443
        protocol: tcp     # Default: "tcp"
        name: https       # Optional unique name
        description: ""   # Optional
      - port: 8080
        name: admin-ui
    asset_value:          # Optional CIA triad valuation
      confidentiality: high   # none, low, medium, high, critical
      integrity: critical
      availability: medium
```

**Switch restrictions**: Switch nodes cannot have source, resources, os,
os_version, features, conditions, injects, vulnerabilities, roles,
services, or asset_value.

**Shorthand forms**:
- `features: [nginx, redis]` → `features: {nginx: "", redis: ""}`
- `conditions: [healthy]` → `conditions: {healthy: ""}`
- `roles: {admin: "root"}` → `roles: {admin: {username: "root"}}`

---

### 2. infrastructure

Deployment topology — maps node names to deployment parameters.
Every key MUST match a node defined in `nodes`.

```yaml
infrastructure:
  # Switch with CIDR properties
  corp-net:
    count: 1              # Integer >= 1 (switches must be 1)
    properties:           # SimpleProperties for switches
      cidr: 10.0.0.0/24
      gateway: 10.0.0.1
      internal: true      # Optional bool, default false
    acls:                 # Optional access control rules
      - name: allow-http  # Optional unique name
        direction: in     # Optional: in/out
        from_net: dmz     # Infrastructure name (must be a switch)
        to_net: ""        # Optional
        protocol: tcp     # Default: "any"
        ports: [80, 443]  # List of int (1-65535)
        action: allow     # "allow" or "deny"

  # VM with links and dependencies
  web-server:
    count: 1              # Shorthand: `web-server: 3`
    links:                # Must reference switch infrastructure entries
      - corp-net
    dependencies:         # Must reference other infrastructure entries
      - db-server
    properties:           # Complex properties (list of dicts)
      - corp-net: 10.0.0.10  # link-name: IP (must be within CIDR)
```

**Shorthand**: `web-server: 3` → `web-server: {count: 3}`

**Validation rules**:
- Links must reference switch/network nodes
- Dependencies must reference defined infrastructure
- IP addresses must fall within linked CIDR ranges
- Gateway must be within its CIDR
- Switch nodes cannot have count > 1
- Links and dependencies must be unique

---

### 3. features

Software deployed onto VMs. Supports dependency graphs.

```yaml
features:
  nginx:
    type: Service         # REQUIRED: Service, Configuration, or Artifact
    source: nginx         # Optional Source reference
    dependencies: [base-packages]  # Other feature names
    vulnerabilities: [cve-2024-1234]  # Vulnerability names
    destination: /opt/app # For Artifact type
    description: ""
    environment: []       # List of env var strings
```

---

### 4. conditions

Monitoring checks run on VMs. Either command-based OR source-based.

```yaml
conditions:
  http-healthy:
    command: "curl -sf http://localhost/ || exit 1"  # REQUIRED (if no source)
    interval: 30          # REQUIRED with command (seconds, >= 1)
    timeout: 10           # Optional (>= 1)
    retries: 3            # Optional (>= 0)
    start_period: 5       # Optional (>= 0)
    description: ""
    environment: []

  # OR source-based:
  custom-check:
    source: health-checker-pkg
    description: "Source-based health check"
```

**Rule**: Cannot have both `command` and `source`. Command requires interval.

---

### 5. vulnerabilities

CWE-classified vulnerabilities.

```yaml
vulnerabilities:
  sqli-login:
    name: SQL Injection   # REQUIRED
    description: Auth bypass via SQL injection  # REQUIRED
    technical: true       # Bool, default false
    class: CWE-89         # REQUIRED, must match CWE-NNN format
```

---

### 6. metrics

Scoring metrics — manual or conditional.

```yaml
metrics:
  blue-uptime:
    type: conditional     # REQUIRED: "manual" or "conditional"
    max-score: 100        # REQUIRED integer >= 1
    condition: http-healthy  # REQUIRED for conditional, forbidden for manual

  ir-report:
    type: manual
    max-score: 50
    artifact: true        # Optional bool (manual only)
```

**Rules**:
- Manual: no `condition` allowed, `artifact` optional
- Conditional: `condition` required, no `artifact` allowed

---

### 7. evaluations

Groups of metrics with pass/fail thresholds.

```yaml
evaluations:
  web-resilience:
    metrics: [blue-uptime, ir-report]  # REQUIRED, min 1
    min-score: 75         # Shorthand for {percentage: 75}
    # Or longhand:
    # min-score:
    #   percentage: 75    # 0-100
    # Or absolute:
    #   absolute: 120     # >= 0
    name: ""              # Optional
    description: ""
```

**Rule**: min-score must have EITHER `absolute` or `percentage`, not both.

---

### 8. tlos (Training Learning Objectives)

Each TLO links to one evaluation.

```yaml
tlos:
  maintain-services:
    name: Maintain critical services
    evaluation: web-resilience  # REQUIRED, must exist in evaluations
    description: ""
```

---

### 9. goals

High-level goals composed of TLOs.

```yaml
goals:
  blue-team-goal:
    tlos: [maintain-services]  # REQUIRED, min 1, must exist in tlos
    name: ""
    description: ""
```

---

### 10. entities

Organizations, teams, and people. Recursive hierarchy with dot-notation
references (e.g., `blue-team.soc`).

```yaml
entities:
  blue-team:
    name: Blue Team
    role: blue            # white, green, red, blue
    mission: Defend the network
    categories: []        # List of strings
    vulnerabilities: []   # Vulnerability names
    tlos: [maintain-services]
    facts: {}             # Dict of key-value pairs
    events: []            # Event names
    entities:             # Nested entities
      soc:
        name: SOC Analyst
      ir:
        name: Incident Responder

  red-team:
    name: Red Team
    role: red
    mission: Penetrate the network
```

Referenced as: `blue-team`, `blue-team.soc`, `blue-team.ir`

---

### 11. injects

Actions injected between entities during an exercise.

```yaml
injects:
  phishing-wave:
    source: phishing-pack           # Optional Source
    from_entity: red-team           # Must be defined entity
    to_entities: [blue-team, green] # Must be defined entities
    tlos: [maintain-services]       # TLO names
    description: ""
    environment: []
```

**Rule**: Must have BOTH `from_entity` and `to_entities`, or NEITHER.

---

### 12. events

Triggered actions combining conditions and injects.

```yaml
events:
  phishing-delivery:
    conditions: [phish-delivered]  # Condition names
    injects: [phishing-wave]      # Inject names
    source: event-handler          # Optional Source
    name: ""
    description: ""
```

---

### 13. scripts

Timed sequences of events with human-readable durations.

```yaml
scripts:
  phase-one:
    start-time: 0           # REQUIRED duration
    end-time: 2 hour        # REQUIRED, must be >= start-time
    speed: 1.0              # REQUIRED float > 0
    events:                  # REQUIRED dict, min 1 entry
      phishing-delivery: 45 min  # event-name: time (within bounds)
      escalation: 1h 30min
    name: ""
    description: ""
```

**Duration syntax**: `"10min 2 sec"`, `"1 week 1day 1h"`, `"1 mon"`,
`"500ms"`, `"1 us"`, bare numbers (treated as seconds).

**Units**: y/year, mon/month, w/week, d/day, h/hr/hour, m/min/minute,
s/sec/second, ms/msec/millisecond, us/usec/microsecond, ns/nsec/nanosecond.

---

### 14. stories

Top-level orchestration — groups of scripts.

```yaml
stories:
  exercise-day:
    scripts: [phase-one, phase-two]  # REQUIRED, min 1
    speed: 1.0                        # Float >= 1.0, default 1.0
    name: ""
    description: ""
```

---

### 15. content

Data placed into scenario systems (files, datasets, directories).

```yaml
content:
  patient-records:
    type: dataset         # REQUIRED: file, dataset, directory
    target: ehr-db        # REQUIRED (must be a VM node)
    format: sql           # Optional
    source: synthetic-phi # Required for dataset if no items
    sensitive: true       # Bool, default false
    tags: [phi, patients]
    items:                # For dataset: list of ContentItem
      - name: record-1.sql
        tags: [phi]
        description: ""

  config-file:
    type: file
    target: web-server
    path: /etc/app/config.yml  # REQUIRED for file type
    text: "key: value"         # Optional inline content
    destination: ""

  data-dir:
    type: directory
    target: web-server
    destination: /srv/data     # REQUIRED for directory type
```

**Rules**:
- All types require `target`
- `file` requires `path`
- `dataset` requires `source` or non-empty `items`
- `directory` requires `destination`

---

### 16. accounts

User accounts within scenario systems.

```yaml
accounts:
  admin-user:
    username: admin         # REQUIRED
    node: web-server        # REQUIRED (must be a VM node)
    groups: [Admins]
    password_strength: strong  # weak, medium, strong, none
    auth_method: password      # Default: "password"
    mail: admin@corp.local
    spn: "HTTP/web.corp.local"  # Kerberos SPN
    shell: /bin/bash
    home: /home/admin
    disabled: false
    description: ""
```

---

### 17. relationships

Typed directed edges between scenario elements (STIX 2.1 style).

```yaml
relationships:
  web-auth:
    type: authenticates_with   # REQUIRED (see types below)
    source: flask-app          # REQUIRED (any named element)
    target: ad-service         # REQUIRED (any named element)
    description: ""
    properties:                # Arbitrary key-value metadata
      protocol: SAML
```

**Relationship types**: `authenticates_with`, `trusts`, `federates_with`,
`connects_to`, `depends_on`, `manages`, `replicates_to`

---

### 18. agents

Autonomous participants (adapted from CybORG).

```yaml
agents:
  red-operator:
    entity: red-team          # REQUIRED (must be a defined entity)
    actions: [Scan, Exploit, Pivot]
    starting_accounts: [compromised-user]  # Account names
    initial_knowledge:
      hosts: [web-server]          # VM node names
      subnets: [dmz-net]           # Switch infrastructure names
      services: [https]            # Named service refs
      accounts: [admin-user]       # Account names
    allowed_subnets: [dmz-net, corp-net]  # Switch infra names
    reward_calculator: ImpactScore
    description: ""
```

---

### 19. objectives

Declarative experiment objectives binding actors to goals.

```yaml
objectives:
  red-foothold:
    agent: red-operator     # Exactly one of agent OR entity
    # entity: red-team      # (mutually exclusive with agent)
    actions: [Scan, Exploit]  # Must be subset of agent's actions
    targets:                  # Any targetable named element
      - web-server
      - nodes.web-server.services.https  # Qualified ref
      - infrastructure.corp-net.acls.allow-http  # ACL ref
      - web-auth             # Relationship ref
    success:                  # REQUIRED
      mode: all_of            # all_of (default) or any_of
      conditions: [foothold-established]
      metrics: [red-access]
      evaluations: []
      tlos: []
      goals: []
      # Must reference at least one item across all lists
    window:                   # Optional orchestration scope
      stories: [exercise-day]
      scripts: [phase-one]
      events: [phishing-delivery]
      workflows: [main-flow]
      steps: [main-flow.step-1]  # Must use "workflow.step" syntax
    depends_on: []              # Other objective names
    name: ""
    description: ""
```

**Rules**:
- Must have exactly one of `agent` or `entity`
- Actions must be subset of the referenced agent's actions
- Targets cannot reference variables, objectives, or workflows
- Window scripts must be within referenced stories
- Window events must be within referenced scripts
- Objective dependencies cannot form cycles

---

### 20. workflows

Declarative experiment control graphs.

```yaml
workflows:
  main-flow:
    start: begin            # REQUIRED (must be a defined step)
    description: ""
    steps:                  # REQUIRED dict, min 1
      begin:
        type: objective     # REQUIRED: objective, if, parallel, end
        objective: red-foothold  # For type=objective
        next: check-result       # Optional next step

      check-result:
        type: if
        when:               # REQUIRED for if
          conditions: [foothold-established]
          # Can also use: metrics, evaluations, tlos, goals, objectives
          # Must reference at least one
        then: exploit-phase  # REQUIRED step name
        else: fallback       # REQUIRED step name

      exploit-phase:
        type: parallel
        branches: [branch-a, branch-b]  # REQUIRED, unique
        next: done           # Optional join step

      branch-a:
        type: objective
        objective: red-exfil

      branch-b:
        type: objective
        objective: red-persist

      fallback:
        type: objective
        objective: red-recon
        next: done

      done:
        type: end
```

**Step type rules**:
- `objective`: requires `objective`, optional `next`
- `if`: requires `when`, `then`, `else`; no other fields
- `parallel`: requires `branches` (unique), optional `next`
- `end`: no fields allowed except `description`

**Validation**: No cycles, all steps reachable from `start`.

---

### 21. variables

Scenario parameterization (CACAO v2.0 style).

```yaml
variables:
  attack_speed:
    type: number           # REQUIRED: string, integer, boolean, number
    default: 1.0           # Must match declared type
    description: Speed multiplier for attack scripts
    allowed_values: [0.5, 1.0, 2.0]  # Must match type
    required: false        # Bool, default false
```

Variables are referenced as `${variable_name}` throughout the scenario.
They are NOT resolved at parse time.

---

## Cross-Reference Rules

The semantic validator enforces these cross-reference constraints:

1. **Node features** → must exist in `features` section
2. **Node conditions** → must exist in `conditions` section
3. **Node injects** → must exist in `injects` section
4. **Node vulnerabilities** → must exist in `vulnerabilities` section
5. **Node role entities** → must exist in `entities` (dot-notation)
6. **Infrastructure entries** → must match a `nodes` entry
7. **Infrastructure links** → must reference switch nodes
8. **Infrastructure dependencies** → must reference other infra entries
9. **Feature dependencies** → must reference other features (no cycles)
10. **Feature vulnerabilities** → must exist in `vulnerabilities`
11. **Metric conditions** → must exist in `conditions` (unique per metric)
12. **Evaluation metrics** → must exist in `metrics`
13. **Evaluation min-score** → absolute cannot exceed sum of metric max-scores
14. **TLO evaluations** → must exist in `evaluations`
15. **Goal TLOs** → must exist in `tlos`
16. **Entity TLOs/vulnerabilities/events** → must exist in respective sections
17. **Inject entities** → must exist in flattened `entities`
18. **Event conditions/injects** → must exist in respective sections
19. **Script events** → must exist in `events`; times within bounds
20. **Story scripts** → must exist in `scripts`
21. **Content targets** → must be VM nodes
22. **Account nodes** → must be VM nodes
23. **Relationship source/target** → any named element
24. **Agent entities** → must exist in flattened entities
25. **Agent accounts/subnets/knowledge** → must exist in respective sections
26. **Objective agents/entities** → must exist in respective sections
27. **Objective actions** → must be subset of agent's actions
28. **Objective targets** → any targetable element (not variables/objectives/workflows)
29. **Objective dependencies** → no cycles
30. **Workflow steps** → reachable from start, no cycles
31. **Variable references** → must be defined in `variables`

---

## Source Shorthand

Any `source` field accepts shorthand:
- `source: "package-name"` → `{name: "package-name", version: "*"}`
- `source: {name: "pkg", version: "1.2.3"}` (longhand)

Exception: In `relationships` and `agents`, `source` is a plain string
reference (not a Source package).

---

## Infrastructure Shorthand

- `web-server: 3` → `web-server: {count: 3}`

## Min-Score Shorthand

- `min-score: 75` → `min-score: {percentage: 75}`
"""

SECTION_SUMMARIES = {
    "nodes": "VMs and network switches — the building blocks of the scenario topology.",
    "infrastructure": "Deployment topology — instance counts, network links, dependencies, IPs, ACLs.",
    "features": "Software deployed onto VMs — services, configurations, artifacts with dependency graphs.",
    "conditions": "Monitoring checks — command-based (command + interval) or source-based.",
    "vulnerabilities": "CWE-classified vulnerabilities planted in the scenario.",
    "metrics": "Scoring metrics — manual (human-graded) or conditional (automated).",
    "evaluations": "Groups of metrics with pass/fail thresholds.",
    "tlos": "Training Learning Objectives — each linked to one evaluation.",
    "goals": "High-level goals composed of TLOs.",
    "entities": "Organizations, teams, people — recursive hierarchy with dot-notation refs.",
    "injects": "Actions injected between entities during an exercise.",
    "events": "Triggered actions combining conditions and injects.",
    "scripts": "Timed sequences of events with human-readable durations.",
    "stories": "Top-level orchestration — groups of scripts.",
    "content": "Data placed into scenario systems — files, datasets, directories.",
    "accounts": "User accounts within scenario systems.",
    "relationships": "Typed directed edges between elements (STIX 2.1 style).",
    "agents": "Autonomous participants with actions, knowledge, and constraints.",
    "objectives": "Declarative experiment objectives binding actors to goals.",
    "workflows": "Declarative experiment control graphs over objectives.",
    "variables": "Scenario parameterization with types, defaults, and constraints.",
}
