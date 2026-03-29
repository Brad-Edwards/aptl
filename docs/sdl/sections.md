# SDL Sections Reference

A scenario is a YAML document with a required top-level `name` and up to 19 named sections. Aside from `name`, all sections are optional.

## Section Overview

### From Open Cyber Range SDL (14 sections)

| Section | Type | Purpose |
|---------|------|---------|
| `nodes` | `dict[str, Node]` | VMs and network switches — the compute/network topology |
| `infrastructure` | `dict[str, InfraNode]` | Deployment topology: counts, links, dependencies, IP/CIDR, ACLs |
| `features` | `dict[str, Feature]` | Software (Service/Configuration/Artifact) deployed to VMs |
| `conditions` | `dict[str, Condition]` | Health checks (command+interval or library source) |
| `vulnerabilities` | `dict[str, Vulnerability]` | CWE-classified vulnerabilities assigned to nodes/features |
| `metrics` | `dict[str, Metric]` | Scoring: Manual (human-graded) or Conditional (automated) |
| `evaluations` | `dict[str, Evaluation]` | Metric groups with pass/fail thresholds |
| `tlos` | `dict[str, TLO]` | Training Learning Objectives linked to evaluations |
| `goals` | `dict[str, Goal]` | High-level goals composed of TLOs |
| `entities` | `dict[str, Entity]` | Teams, organizations, people (recursive, with exercise roles) |
| `injects` | `dict[str, Inject]` | Actions between entities during exercises |
| `events` | `dict[str, Event]` | Triggered actions combining conditions + injects |
| `scripts` | `dict[str, Script]` | Timed event sequences with human-readable durations |
| `stories` | `dict[str, Story]` | Top-level exercise orchestration grouping scripts |

### Extended Sections (5 sections)

| Section | Type | Purpose | Adapted From |
|---------|------|---------|--------------|
| `content` | `dict[str, Content]` | Data placed into systems (files, datasets, emails) | CyRIS `copy_content` |
| `accounts` | `dict[str, Account]` | User accounts on nodes (AD users, SSH, DB users) | CyRIS `add_account` |
| `relationships` | `dict[str, Relationship]` | Typed edges between elements (auth, trust, federation) | STIX Relationship SRO |
| `agents` | `dict[str, Agent]` | Autonomous participants (actions, knowledge, scope) | CybORG Agents |
| `variables` | `dict[str, Variable]` | Parameterization (types, defaults, substitution) | CACAO playbook_variables |

---

## Nodes

Nodes are the compute and network elements of the scenario.

```yaml
nodes:
  corp-switch:
    type: Switch
    description: Corporate LAN

  web-server:
    type: VM
    os: linux                           # windows, linux, macos, freebsd, other
    os_version: "Ubuntu 22.04"
    source: ubuntu-22.04                # provider-neutral image reference
    resources:
      ram: 4 GiB                        # human-readable: GiB, MiB, GB, MB
      cpu: 2
    features:                           # dict form: {feature: role} or list form: [feature]
      nginx: web-admin
    conditions:
      web-health: web-admin
    vulnerabilities: [sqli, xss]
    roles:
      web-admin: www-data               # shorthand: role: username
      operator:                         # longhand
        username: ops
        entities: [blue-team.alice]     # binds to entity
    services:                           # exposed network services
      - port: 80
        protocol: tcp
        name: http
      - port: 443
        name: https
    asset_value:                        # CIA triad (from CybORG)
      confidentiality: high
      integrity: medium
      availability: critical
```

**Switch** nodes are pure connectivity objects. They may define `type` and an optional `description`, but `source`, `resources`, `os`, `os_version`, `features`, `conditions`, `injects`, `vulnerabilities`, `roles`, `services`, and `asset_value` are rejected.

**Feature list shorthand:** `features: [nginx, php]` expands to `{nginx: "", php: ""}` (no role binding required).

When `features`, `conditions`, or `injects` use the `{name: role}` form, the role must be declared in the node's `roles` map.

---

## Infrastructure

Maps node names to deployment parameters.

```yaml
infrastructure:
  corp-switch:
    count: 1
    properties:
      cidr: 10.0.0.0/24
      gateway: 10.0.0.1
      internal: true                    # blocks internet egress
    acls:                               # network access controls (from CybORG NACLs)
      - direction: in
        from_net: dmz-switch
        protocol: tcp
        ports: [443]
        action: allow
      - direction: in
        from_net: dmz-switch
        action: deny

  web-server:
    count: 1                            # shorthand: web-server: 1
    links: [corp-switch]
    dependencies: [db-server]
    properties:                         # per-link IP assignments
      - corp-switch: 10.0.0.10
```

**Shorthand:** `web-server: 3` expands to `{count: 3}`.

`links` are switch/network connectivity references, not arbitrary infrastructure edges. If a node has attached `conditions`, its `count` must stay at `1` so the condition-to-node binding remains unambiguous. Per-link IP assignments must be valid IP addresses within the linked switch's CIDR.

---

## Features

Software deployed onto VMs. Three types: Service, Configuration, Artifact.

```yaml
features:
  nginx:
    type: Service
    source: nginx-1.24
  php-config:
    type: Configuration
    source: php-8.2-config
    dependencies: [nginx]               # deployed after nginx; cycles rejected
  log-agent:
    type: Artifact
    source: filebeat-8
    destination: /opt/filebeat
    environment: ["ELASTICSEARCH_HOST=10.0.0.5"]
```

---

## Conditions

Health checks with optional timeout/retries/start_period.

```yaml
conditions:
  web-alive:
    command: "curl -sf http://localhost/ || exit 1"
    interval: 15
    timeout: 5
    retries: 3
    start_period: 30
  scanner:
    source: vuln-scanner-pkg            # alternative: library-based check
```

Must have either `command` + `interval` or `source`, not both.

---

## Vulnerabilities

CWE-classified weaknesses. The `class` field is validated against `CWE-\d+`.

```yaml
vulnerabilities:
  sqli:
    name: SQL Injection
    description: SQLi in login form allows auth bypass
    technical: true
    class: CWE-89
```

---

## Scoring Pipeline: Metrics, Evaluations, TLOs, Goals

```
Conditions → Metrics → Evaluations → TLOs → Goals
```

```yaml
metrics:
  service-uptime:
    type: CONDITIONAL
    max-score: 100
    condition: web-alive
  report-quality:
    type: MANUAL
    max-score: 50
    artifact: true

evaluations:
  overall:
    metrics: [service-uptime, report-quality]
    min-score: 75                       # shorthand = percentage
    # or: min-score: {absolute: 100}

tlos:
  web-defense:
    name: Web Application Defense
    evaluation: overall

goals:
  pass-exercise:
    tlos: [web-defense]
```

---

## Entities

Recursive team/organization hierarchy with exercise roles and OCR-style
fact maps.

```yaml
entities:
  blue-team:
    name: Blue Team
    role: Blue
    mission: Defend infrastructure
    tlos: [web-defense]
    facts:
      department: SOC
      primary-shift: nights
    entities:
      alice: {name: Alice}
      bob: {name: Bob}
  red-team:
    name: Red Team
    role: Red                           # White, Green, Red, Blue
```

Nested entities are referenced via dot-notation: `blue-team.alice`.

---

## Orchestration: Injects, Events, Scripts, Stories

```yaml
injects:
  phishing-email:
    source: phishing-pkg
    from-entity: red-team
    to-entities: [blue-team]

events:
  attack-wave:
    conditions: [scanner]
    injects: [phishing-email]

scripts:
  main-timeline:
    start-time: 5 min                  # OCR units: y, mon, w, d, h, m/min, s/sec, ms, us, ns
    end-time: 2 hour
    speed: 1.0
    events:
      attack-wave: 30 min

stories:
  exercise:
    speed: 1
    scripts: [main-timeline]
```

Sub-second durations are rounded up to the nearest second, so `1 ms`,
`1 us`, and `1 ns` all parse as `1`.

---

## Content

Data placed into scenario systems. Adapted from CyRIS `copy_content`.

```yaml
content:
  phishing-emails:
    type: dataset
    target: exchange-server
    destination: /var/mail/
    format: eml
    sensitive: true
    items:
      - name: "Q3 Budget.eml"
        tags: [phishing, macro]
  flag-file:
    type: file
    target: victim
    path: /var/www/html/flag.txt
    text: "FLAG{found_it}"
  seed-data:
    type: dataset
    target: database
    source: customer-pii-seed          # large dataset via package reference
    format: sql
```

`target` must reference a VM node, not a switch/network node.

---

## Accounts

User accounts within scenario nodes. Adapted from CyRIS `add_account`.

```yaml
accounts:
  domain-admin:
    username: Administrator
    node: dc01
    groups: [Domain Admins]
    password_strength: strong           # weak, medium, strong, none
  svc-sql:
    username: svc_mssql
    node: dc01
    password_strength: weak
    spn: "MSSQL/db.corp.local"         # Kerberos SPN
    auth_method: password               # password, key, certificate
    mail: ""
```

`node` must reference a VM node, not a switch/network node.

---

## Relationships

Typed directed edges between any named scenario elements. Adapted from STIX Relationship SROs.

```yaml
relationships:
  exchange-auth:
    type: authenticates_with
    source: exchange-service
    target: ad-ds
  domain-trust:
    type: trusts
    source: child-domain
    target: parent-domain
    properties:
      trust_type: parent-child
      trust_direction: bidirectional
  sso:
    type: federates_with
    source: adfs
    target: azure-ad
    properties: {protocol: SAML}
  app-to-db:
    type: connects_to
    source: webapp
    target: postgres
    properties: {protocol: tcp, port: "5432"}
```

Types: `authenticates_with`, `trusts`, `federates_with`, `connects_to`, `depends_on`, `manages`, `replicates_to`.

Relationship endpoints resolve against the scenario's named elements, including top-level section keys, nested entity dot-paths, variables, other relationships, and content item `name` values.

---

## Agents

Autonomous scenario participants. Adapted from CybORG CAGE Challenge.

```yaml
agents:
  red-agent:
    entity: red-team                    # references entities section
    actions: [Scan, Exploit, Escalate]
    starting_accounts: [phished-user]   # references accounts section
    initial_knowledge:
      hosts: [user0]                    # known at scenario start
      subnets: [user-net]
      services: [ssh]                   # references nodes.*.services[].name
      accounts: [helpdesk-user]         # references accounts section
    allowed_subnets: [user-net, corp-net]
    reward_calculator: HybridImpactPwn
```

`initial_knowledge.hosts` references VM node names, `subnets` references switch-backed infrastructure names, `services` references service names declared in `nodes.*.services`, and `accounts` references entries in the `accounts` section. `allowed_subnets` follows the same switch-backed infrastructure rule.

---

## Variables

Scenario parameterization. Adapted from CACAO playbook_variables.

```yaml
variables:
  domain_name:
    type: string
    default: "corp.local"
    description: Active Directory domain name
  num_workstations:
    type: integer
    default: 5
  admin_strength:
    type: string
    default: weak
    allowed_values: [weak, medium, strong]
    required: false
```

Variables are referenced as `${var_name}` in other sections. They are **not resolved at parse time** — resolution happens at instantiation.

Full-value placeholders are currently supported in ordinary string fields, common scalar fields (counts, booleans, scores, timings, RAM/CPU, ports), and many reference values. The semantic validator checks that `${var_name}` refers to a declared variable, but substitution still happens later during instantiation. User-defined mapping keys and enum-backed fields still need concrete values today.

`default` and every entry in `allowed_values` must match the declared `type`. If `allowed_values` is provided, `default` must be one of those values.

---

## Scoring: Exercise Assessment vs Automated Validation

The SDL's scoring pipeline (conditions → metrics → evaluations → TLOs → goals) is for **exercise assessment** — human-evaluated team exercises like Locked Shields or CCDC where white team judges grade performance.

**Automated validation** (APTL's ObjectiveType with wazuh_alert/command_output/file_exists auto-evaluation) is a **runtime concern** that lives outside the SDL, in `aptl.core.objectives`. The SDL specifies *what success looks like* via the scoring pipeline; the runtime determines *whether it happened* via automated checks.
