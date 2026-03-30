"""Detachable SDL example scenarios for agent learning.

Each example demonstrates different SDL patterns and complexity levels.
Agents can request examples by name or by the patterns they demonstrate.
"""

EXAMPLES: dict[str, dict[str, str]] = {
    "minimal": {
        "description": (
            "Absolute minimum valid scenario — just a name. "
            "Shows that all sections are optional."
        ),
        "patterns": "minimal, skeleton",
        "sdl": """\
name: minimal-scenario
description: The simplest possible valid SDL scenario.
""",
    },
    "simple-webapp-pentest": {
        "description": (
            "Small red-vs-blue web application penetration test. "
            "Demonstrates nodes, infrastructure, features, conditions, "
            "vulnerabilities, metrics, evaluations, TLOs, goals, entities, "
            "and the scoring pipeline."
        ),
        "patterns": "basic, scoring-pipeline, nodes, infrastructure, red-blue",
        "sdl": """\
name: simple-webapp-pentest
description: >
  Basic web application penetration test with a vulnerable Flask app,
  a database, and red/blue teams.

nodes:
  dmz:
    type: Switch
    description: DMZ network segment
  internal:
    type: Switch
    description: Internal network segment

  webapp:
    type: VM
    os: linux
    source: flask-app
    resources: {ram: 1 GiB, cpu: 1}
    features: {flask-service: app-admin}
    conditions: {webapp-healthy: app-admin}
    vulnerabilities: [sqli-login]
    services:
      - {port: 443, name: webapp-https}
    roles:
      app-admin:
        username: appuser

  db-server:
    type: VM
    os: linux
    source: postgres
    resources: {ram: 2 GiB, cpu: 1}
    conditions: {db-healthy: dba}
    services:
      - {port: 5432, name: db-postgres}
    roles:
      dba:
        username: postgres

infrastructure:
  dmz:
    count: 1
    properties: {cidr: 10.0.1.0/24, gateway: 10.0.1.1}
  internal:
    count: 1
    properties: {cidr: 10.0.2.0/24, gateway: 10.0.2.1, internal: true}
  webapp:
    count: 1
    links: [dmz, internal]
    properties:
      - dmz: 10.0.1.10
      - internal: 10.0.2.10
  db-server:
    count: 1
    links: [internal]
    dependencies: [webapp]
    properties:
      - internal: 10.0.2.20

features:
  flask-service:
    type: Service
    source: flask-vulnerable-app
    description: Vulnerable Flask web application

conditions:
  webapp-healthy:
    command: "curl -sf http://localhost:8080/ || exit 1"
    interval: 15
  db-healthy:
    command: "pg_isready -U postgres"
    interval: 10

vulnerabilities:
  sqli-login:
    name: SQL Injection in Login
    description: Authentication bypass via SQL injection in the login form
    technical: true
    class: CWE-89

metrics:
  blue-webapp-uptime:
    type: conditional
    max-score: 100
    condition: webapp-healthy
  blue-ir-quality:
    type: manual
    max-score: 50
    artifact: true

evaluations:
  blue-defense:
    metrics: [blue-webapp-uptime, blue-ir-quality]
    min-score: 60

tlos:
  defend-webapp:
    name: Defend the web application
    evaluation: blue-defense

goals:
  blue-goal:
    tlos: [defend-webapp]

entities:
  red-team:
    name: Red Team
    role: red
    mission: Exploit the web application and access database
  blue-team:
    name: Blue Team
    role: blue
    mission: Detect and respond to the attack
    tlos: [defend-webapp]
""",
    },
    "orchestrated-exercise": {
        "description": (
            "Demonstrates the orchestration pipeline: injects, events, "
            "scripts, stories with human-readable durations."
        ),
        "patterns": "orchestration, timing, injects, events, scripts, stories",
        "sdl": """\
name: orchestrated-exercise
description: >
  Demonstrates the SDL orchestration pipeline with timed events,
  injects between entities, and multi-phase scripts.

nodes:
  corp-net: {type: Switch, description: Corporate network}
  mail-server:
    type: VM
    os: linux
    source: postfix
    resources: {ram: 2 GiB, cpu: 1}
    conditions: {mail-healthy: mail-admin}
    roles:
      mail-admin: postfix

conditions:
  mail-healthy:
    command: "postfix status"
    interval: 30
  phish-delivered:
    command: "/usr/local/bin/check-phish"
    interval: 60

infrastructure:
  corp-net:
    count: 1
    properties: {cidr: 10.0.0.0/24, gateway: 10.0.0.1}
  mail-server:
    count: 1
    links: [corp-net]

entities:
  white-cell:
    name: Exercise Control
    role: white
  red-team:
    name: Red Team
    role: red
  blue-team:
    name: Blue Team
    role: blue

injects:
  morning-brief:
    source: morning-briefing-doc
    from_entity: white-cell
    to_entities: [blue-team]
    description: Daily briefing with normal operational context
  phishing-wave:
    source: phishing-lure-pack
    from_entity: red-team
    to_entities: [blue-team]
    description: Spear-phishing emails targeting helpdesk staff

events:
  briefing:
    injects: [morning-brief]
  phishing-delivery:
    conditions: [phish-delivered]
    injects: [phishing-wave]

scripts:
  morning-phase:
    start-time: 0
    end-time: 2 hour
    speed: 1.0
    events:
      briefing: 10 min
      phishing-delivery: 45 min
  afternoon-phase:
    start-time: 2 hour
    end-time: 5 hour
    speed: 1.0
    events:
      phishing-delivery: 3 hour

stories:
  exercise-day:
    scripts: [morning-phase, afternoon-phase]
""",
    },
    "agents-and-objectives": {
        "description": (
            "Demonstrates autonomous agents, objectives with success "
            "criteria, dependency chains, and objective windows."
        ),
        "patterns": "agents, objectives, dependencies, success-criteria, windows",
        "sdl": """\
name: agents-and-objectives
description: >
  Demonstrates the agent and objective system with dependency chains,
  success criteria, and orchestration windows.

nodes:
  dmz: {type: Switch}
  internal: {type: Switch}
  web-server:
    type: VM
    os: linux
    resources: {ram: 2 GiB, cpu: 1}
    conditions: {web-healthy: admin}
    services:
      - {port: 443, name: https}
    roles:
      admin: webadmin

  db-server:
    type: VM
    os: linux
    resources: {ram: 4 GiB, cpu: 2}
    conditions: {db-healthy: dba}
    services:
      - {port: 5432, name: postgres}
    roles:
      dba: postgres

infrastructure:
  dmz:
    count: 1
    properties: {cidr: 10.0.1.0/24, gateway: 10.0.1.1}
  internal:
    count: 1
    properties: {cidr: 10.0.2.0/24, gateway: 10.0.2.1, internal: true}
  web-server:
    count: 1
    links: [dmz]
  db-server:
    count: 1
    links: [internal]
    dependencies: [web-server]

conditions:
  web-healthy:
    command: "curl -sf https://localhost/ || exit 1"
    interval: 15
  db-healthy:
    command: "pg_isready"
    interval: 10
  foothold-detected:
    command: "/opt/detect/check-foothold"
    interval: 30

metrics:
  red-foothold:
    type: conditional
    max-score: 100
    condition: foothold-detected

evaluations:
  red-access:
    metrics: [red-foothold]
    min-score: {percentage: 50}

tlos:
  achieve-access:
    evaluation: red-access

goals:
  red-goal:
    tlos: [achieve-access]

entities:
  red-team:
    name: Red Team
    role: red
    mission: Gain access to the database
  blue-team:
    name: Blue Team
    role: blue
    mission: Detect and contain the attack

accounts:
  web-user:
    username: webapp
    node: web-server
    password_strength: weak
  db-admin:
    username: postgres
    node: db-server
    password_strength: strong

agents:
  red-recon:
    entity: red-team
    actions: [Scan, Enumerate]
    initial_knowledge:
      hosts: [web-server]
      subnets: [dmz]
      services: [https]
    allowed_subnets: [dmz]
    reward_calculator: ReconScore

  red-exploit:
    entity: red-team
    actions: [Exploit, Pivot, Exfiltrate]
    starting_accounts: [web-user]
    initial_knowledge:
      hosts: [web-server, db-server]
      subnets: [dmz, internal]
      services: [https, postgres]
      accounts: [db-admin]
    allowed_subnets: [dmz, internal]
    reward_calculator: ImpactScore

injects:
  recon-report:
    from_entity: red-team
    to_entities: [red-team]

events:
  recon-complete:
    injects: [recon-report]

scripts:
  attack-phase:
    start-time: 0
    end-time: 4 hour
    speed: 1.0
    events:
      recon-complete: 1 hour

stories:
  attack-day:
    scripts: [attack-phase]

objectives:
  red-reconnaissance:
    agent: red-recon
    actions: [Scan, Enumerate]
    targets: [web-server]
    success:
      conditions: [web-healthy]
    window:
      stories: [attack-day]
      scripts: [attack-phase]

  red-exploit-db:
    agent: red-exploit
    actions: [Exploit, Pivot]
    targets: [db-server, nodes.db-server.services.postgres]
    success:
      goals: [red-goal]
    depends_on: [red-reconnaissance]
    window:
      stories: [attack-day]
""",
    },
    "variables-and-content": {
        "description": (
            "Demonstrates variables for parameterization, content placement, "
            "accounts, and relationships."
        ),
        "patterns": "variables, content, accounts, relationships, parameterization",
        "sdl": """\
name: variables-and-content
description: >
  Demonstrates variables for scenario parameterization, content
  placement (files, datasets), accounts, and relationships.

variables:
  vm_count:
    type: integer
    default: 1
    description: Number of web server instances
    allowed_values: [1, 2, 4]
  db_password_strength:
    type: string
    default: "weak"
    description: Database password strength for the exercise
    allowed_values: ["weak", "medium", "strong"]
  enable_monitoring:
    type: boolean
    default: true
    description: Whether to enable SOC monitoring

nodes:
  corp-net: {type: Switch}
  web-server:
    type: VM
    os: linux
    resources: {ram: 2 GiB, cpu: 1}
    roles:
      admin: webadmin
  db-server:
    type: VM
    os: linux
    resources: {ram: 4 GiB, cpu: 2}
    roles:
      dba: postgres

infrastructure:
  corp-net:
    count: 1
    properties: {cidr: 10.0.0.0/24, gateway: 10.0.0.1}
  web-server:
    count: ${vm_count}
    links: [corp-net]
  db-server:
    count: 1
    links: [corp-net]
    dependencies: [web-server]

content:
  customer-data:
    type: dataset
    target: db-server
    format: sql
    source: synthetic-customer-records
    sensitive: true
    tags: [pii, customers]

  app-config:
    type: file
    target: web-server
    path: /etc/app/config.yml
    text: |
      database:
        host: db-server
        port: 5432
        name: appdb

  shared-docs:
    type: directory
    target: web-server
    destination: /srv/shared

accounts:
  app-service:
    username: appsvc
    node: web-server
    groups: [AppServices]
    password_strength: medium
  db-admin:
    username: postgres
    node: db-server
    groups: [DBA]
    password_strength: ${db_password_strength}
  analyst:
    username: analyst
    node: web-server
    groups: [SOC]
    password_strength: strong
    mail: analyst@corp.local

entities:
  corp:
    name: Corporation
    role: blue

features:
  web-app:
    type: Service
    source: flask-app

relationships:
  web-auth-db:
    type: authenticates_with
    source: web-app
    target: db-admin
    description: Web app authenticates to database
    properties:
      protocol: tcp
      port: "5432"
  web-to-db:
    type: connects_to
    source: web-server
    target: db-server
  db-replication:
    type: replicates_to
    source: db-server
    target: db-server
""",
    },
    "workflow-branching": {
        "description": (
            "Demonstrates workflow control flow: objective steps, "
            "if/then/else branching, parallel execution, and end nodes."
        ),
        "patterns": "workflows, branching, parallel, control-flow",
        "sdl": """\
name: workflow-branching
description: >
  Demonstrates workflow control-flow: sequential objectives,
  conditional branching, parallel execution, and termination.

nodes:
  net: {type: Switch}
  target:
    type: VM
    os: linux
    resources: {ram: 2 GiB, cpu: 1}
    conditions: {target-up: admin}
    roles:
      admin: root

infrastructure:
  net:
    count: 1
    properties: {cidr: 10.0.0.0/24, gateway: 10.0.0.1}
  target:
    count: 1
    links: [net]

conditions:
  target-up:
    command: "true"
    interval: 10
  recon-done:
    command: "/opt/check-recon"
    interval: 30
  exploit-done:
    command: "/opt/check-exploit"
    interval: 30

metrics:
  recon-score:
    type: conditional
    max-score: 50
    condition: recon-done
  exploit-score:
    type: conditional
    max-score: 100
    condition: exploit-done

evaluations:
  attack-eval:
    metrics: [recon-score, exploit-score]
    min-score: 50

tlos:
  complete-attack:
    evaluation: attack-eval

goals:
  red-goal:
    tlos: [complete-attack]

entities:
  red-team:
    name: Red Team
    role: red

agents:
  attacker:
    entity: red-team
    actions: [Scan, Exploit, Persist, Exfil]
    allowed_subnets: [net]
    initial_knowledge:
      subnets: [net]

objectives:
  recon:
    agent: attacker
    actions: [Scan]
    targets: [target]
    success:
      conditions: [recon-done]
  exploit:
    agent: attacker
    actions: [Exploit]
    targets: [target]
    success:
      conditions: [exploit-done]
    depends_on: [recon]
  persist:
    agent: attacker
    actions: [Persist]
    targets: [target]
    success:
      metrics: [exploit-score]
    depends_on: [exploit]
  exfil:
    agent: attacker
    actions: [Exfil]
    targets: [target]
    success:
      goals: [red-goal]
    depends_on: [exploit]

workflows:
  attack-flow:
    start: do-recon
    steps:
      do-recon:
        type: objective
        objective: recon
        next: check-recon

      check-recon:
        type: if
        when:
          conditions: [recon-done]
        then: do-exploit
        else: finish

      do-exploit:
        type: objective
        objective: exploit
        next: post-exploit

      post-exploit:
        type: parallel
        branches: [do-persist, do-exfil]
        next: finish

      do-persist:
        type: objective
        objective: persist

      do-exfil:
        type: objective
        objective: exfil

      finish:
        type: end
""",
    },
}


def list_examples() -> list[dict[str, str]]:
    """Return metadata for all available examples."""
    return [
        {"name": name, "description": ex["description"], "patterns": ex["patterns"]}
        for name, ex in EXAMPLES.items()
    ]


def get_example(name: str) -> dict[str, str] | None:
    """Return a specific example by name, or None if not found."""
    return EXAMPLES.get(name)
