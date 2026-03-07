# Minimum Viable Enterprise + Agentic SOC

> **Status**: Design document. Phases 1-3 are implemented. Phase 4 and the Windows VM (172.20.3.0/24 Endpoints subnet) are not yet implemented. Network topology, container IPs, and SOC tooling described below reflect the current running lab. The Endpoints subnet and Caldera remain planned.

## Where We Started

APTL started as Wazuh SIEM, one Linux victim, Kali, a reverse engineering container, and MCP servers. The Python CLI handles lab lifecycle.

The gap: one host with one exploitable service. No identity infrastructure, no real applications, no email, no database, no network segmentation. On the blue side, no threat intel platform, no case management, no automated response, no network IDS.

## The Core Design Question

What's the smallest set of infrastructure and applications that lets you exercise the most common enterprise attack chains, with enough telemetry that an agentic SOC has real work to do?

The answer comes from working backward from the kill chain. The three attack patterns that matter most in real enterprise breaches are:





Web app compromise -> privesc -> lateral movement -> data exfiltration



Credential theft (phishing or exposed creds) -> AD/identity abuse -> domain compromise



Misconfigured service -> initial access -> persistence -> discovery -> pivot

If you can run all three of those end-to-end with agents on both sides, you have something genuinely useful.



The Minimum Viable Enterprise

What You Need (and Why)

graph TB
    subgraph dmz [DMZ - 172.20.1.0/24]
        WebApp["Web App Server<br/>nginx + Flask/Node"]
        MailSrv["Mail Server<br/>Postfix + Dovecot"]
        DNS["DNS Server<br/>Bind9"]
    end

    subgraph internal [Internal - 172.20.2.0/24]
        AD["Identity Provider<br/>Samba AD DC"]
        DB["Database<br/>PostgreSQL"]
        FileShare["File Server<br/>Samba"]
        LinuxSrv["Linux App Server<br/>Rocky Linux"]
    end

    subgraph endpoints [Endpoints - 172.20.3.0/24 NOT IMPLEMENTED]
        WinVM["Windows 11<br/>AD-joined, VM<br/>PLANNED"]
    end

    subgraph security [Security Stack - 172.20.0.0/24]
        Wazuh["Wazuh SIEM<br/>existing"]
        Suricata["Suricata IDS<br/>network tap"]
        MISP["MISP / OpenCTI<br/>threat intel"]
        TheHive["TheHive<br/>case management"]
        Shuffle["Shuffle SOAR<br/>playbooks"]
    end

    subgraph redteam [Red Team - 172.20.4.0/24]
        Kali["Kali Linux<br/>existing"]
    end

    Kali --> dmz
    Kali --> internal
    Kali --> endpoints

    dmz --> internal
    WebApp --> DB
    MailSrv --> AD

    internal --> security
    dmz --> security
    endpoints --> security

    Suricata -.->|"network flows"| Wazuh
    TheHive -.->|"enrichment"| MISP
    Shuffle -.->|"automation"| TheHive
    Shuffle -.->|"response"| Wazuh

Enterprise Services (8 containers + 1 VM)

1. Identity Provider -- Samba AD DC (new container)





Why: AD is the backbone of enterprise attacks. Kerberoasting, pass-the-hash, Golden Ticket, GPO abuse -- none of these exist without it.



What: Samba 4 AD Domain Controller. Creates techvault.local domain with 10-15 user accounts (from existing TechVault personas), groups, OUs. Some accounts with weak passwords, some with SPNs set for Kerberoasting.



Telemetry: LDAP/Kerberos auth logs -> Wazuh. Failed logins, unusual auth patterns, service ticket requests.

2. Web Application Server (enhanced victim container)





Why: Web apps are the #1 initial access vector. The current cmd.php is a toy.



What: A real (but intentionally vulnerable) TechVault customer portal. Login, file upload, API endpoints, admin panel. OWASP Top 10 vulnerabilities: SQLi, XSS, IDOR, weak auth, exposed endpoints. Backed by the PostgreSQL database.



Telemetry: Access logs, application logs, WAF-like events -> Wazuh.

3. PostgreSQL Database (new container)





Why: Every enterprise has a database. SQL injection needs a real database. Data exfiltration needs real data.



What: PostgreSQL with TechVault schema -- users table (with password hashes), customer data, files metadata, API keys, audit logs. Seeded with realistic data.



Telemetry: Query logs, auth events, slow queries -> Wazuh.

4. Email Server (new container)





Why: Phishing is the most common initial access vector. Email credentials are used for lateral movement. Email headers leak internal infrastructure details.



What: Docker-mailserver (Postfix + Dovecot). Handles @techvault.local mail for the 10-15 AD users. Receives mail from Kali for phishing simulations.



Telemetry: SMTP logs, auth events, suspicious attachment indicators -> Wazuh.

5. File Server (new container)





Why: Lateral movement target. Data collection point. Misconfigured shares are a classic finding.



What: Samba file shares integrated with AD. Department shares (engineering, finance, HR) with intentional permission gaps. Contains planted sensitive files (credentials.txt, database backups, SSH keys).



Telemetry: File access logs, permission changes, unusual access patterns -> Wazuh.

6. DNS Server (new container)





Why: Internal DNS is required for AD to function. DNS is also the most common C2 channel and the best source of network discovery data.



What: Bind9 serving techvault.local zone. Resolves all internal hostnames. Query logging enabled.



Telemetry: DNS query logs -> Wazuh. Enables detection of DNS tunneling, DGA domains, unusual query patterns.

7. Linux Application Server (repurposed/enhanced victim)





Why: The existing victim becomes one of several targets rather than the only one.



What: Rocky Linux running the web app backend, cron jobs, SSH. Has sudo misconfigurations, SUID binaries, writable cron paths for privilege escalation.



Telemetry: System logs, auditd, Falco, Wazuh agent (existing).

8. Windows 11 Endpoint (VM via Aurora or local KVM)





Why: AD attacks require a domain-joined Windows machine. Most enterprise endpoints are Windows. EDR evasion testing requires a real OS, not a container.



What: Windows 11 joined to techvault.local, logged in as a TechVault employee. Has Office docs, browser history, saved credentials. Wazuh agent + optionally a commercial EDR (XSIAM, as in existing Aurora notes).



Telemetry: Windows Event Logs, Sysmon, PowerShell logging, Wazuh agent -> SIEM.

## Network Segmentation

The lab uses 4 Docker bridge networks (implemented):





DMZ (172.20.1.0/24): Web app, mail, DNS -- externally reachable from Kali



Internal (172.20.2.0/24): AD, database, file server, app server -- reachable from DMZ (simulating a pivot)



Endpoints (172.20.3.0/24): Windows VM -- planned, not yet implemented



Security (172.20.0.0/24): Wazuh stack, MISP, TheHive, Shuffle -- management network



Red Team (172.20.4.0/24): Kali -- initially can only reach DMZ (forces realistic attack progression)

Docker networks with controlled inter-network routing. The Kali container starts with access only to the DMZ. Reaching internal requires compromising a DMZ host first (or finding a route). This is what forces realistic multi-step attacks.



The Agentic SOC Stack

Security Tools (4-5 new containers)

1. Suricata IDS (new container)





Why: Network-level detection is the biggest gap. Wazuh sees host logs but is blind to network traffic. C2 detection, lateral movement, exfiltration all happen on the wire.



What: Suricata in IDS mode, tapping the lab network. ET Open rules + custom rules. Alerts forwarded to Wazuh via Eve JSON -> Filebeat.



MCP integration: Query Suricata alerts, manage rules.

2. MISP (new container, or OpenCTI)





Why: Threat intel is the starting point of proactive defense. IOC correlation turns raw alerts into meaningful investigations. An agentic SOC needs structured threat data to reason about.



What: MISP instance with feeds enabled (abuse.ch, OTX, CIRCL). Pre-loaded with IOCs relevant to lab scenarios. Integrated with Wazuh for IOC matching.



MCP integration: New mcp-threatintel server. Query IOCs, submit new indicators, correlate with SIEM alerts, pull threat reports.

3. TheHive (new container)





Why: Case management is what turns alerts into investigations. Without it, the blue team agent has no way to track, document, or escalate findings.



What: TheHive 5 with Cortex for automated enrichment. Alert escalation from Wazuh -> TheHive. Case templates for common incident types.



MCP integration: New mcp-casemgmt server. Create cases, add observables, run analyzers, update case status, generate reports.

4. Shuffle SOAR (new container, or n8n)





Why: Automated response is what makes the SOC agentic beyond just the AI layer. Playbooks for common responses: block IP, disable account, isolate host, enrich IOC.



What: Shuffle with pre-built playbooks wired to Wazuh alerts and TheHive cases. Webhook triggers from SIEM alerts.



MCP integration: New mcp-soar server. Trigger playbooks, check execution status, manage response actions.

5. Caldera (optional, new container)





Why: Automated adversary emulation with MITRE ATT&CK mapping. Gives the red team agent structured attack scenarios instead of ad-hoc commands.



What: MITRE Caldera with agents deployed on victim hosts. Pre-built adversary profiles for common attack chains.



MCP integration: Extend mcp-red or new server to trigger Caldera operations and retrieve results.

Enhanced Wazuh Configuration

The current Wazuh setup needs expansion:





Suricata integration: Eve JSON ingestion, network alert correlation



Active Directory monitoring: LDAP/Kerberos event rules, failed auth chains



Sigma rules: Import community Sigma rules converted to Wazuh format



IOC matching: Wazuh CDB lists populated from MISP feeds



Active response: Automated actions (block IP, disable user) triggered by rules



The MCP Layer

Current MCP Servers





mcp-red (Kali commands) -- keep, extend



mcp-wazuh (SIEM queries, rule creation) -- keep, extend significantly



mcp-reverse (binary analysis) -- keep



mcp-indexer (Wazuh Indexer queries) -- keep

New MCP Servers Needed

mcp-threatintel -- MISP/OpenCTI integration





Query IOCs by type (IP, domain, hash, email)



Submit new indicators from investigations



Search for related threat reports



Correlate observables with SIEM alerts



Pull ATT&CK technique mappings

mcp-casemgmt -- TheHive integration





Create incident cases from alerts



Add observables and evidence



Run Cortex analyzers (VirusTotal, abuse.ch, WHOIS)



Update case status and timeline



Generate investigation reports



Link related cases

mcp-soar -- Shuffle/response integration





Trigger response playbooks



Check playbook execution status



Manage block lists and allow lists



Execute containment actions (isolate host, disable account)



Query action history

mcp-network -- Suricata/network integration





Query network IDS alerts



Search flow data



Manage Suricata rules



Analyze PCAP data



Query DNS logs

Expanded mcp-wazuh capabilities





Sigma rule deployment



Active response triggering



Agent management (list agents, check status)



FIM (file integrity monitoring) queries



Vulnerability scan results



SCA (security configuration assessment) results



Agentic Workflows

With the infrastructure and MCP layer above, here's what becomes possible:

Red Team Agent Workflow





Recon: Scan DMZ via Kali, enumerate DNS, discover web app and mail server



Initial Access: Exploit web app SQLi to get database credentials, or send phishing email to harvest AD credentials



Establish Foothold: Get shell on web server via web app exploit



Privilege Escalation: Find sudo misconfiguration or SUID binary on Linux, or Kerberoast on AD



Lateral Movement: Use harvested creds to access file server, pivot to internal network



Data Collection: Grab sensitive files from file shares, dump database



Exfiltration: Exfil data via DNS tunneling or HTTPS

Blue Team Agent Workflow





Alert Triage: Wazuh alert fires -> agent queries alert details, correlates with recent events



IOC Enrichment: Extract IPs, domains, hashes -> query MISP for known threats



Investigation: Query SIEM for related activity across all hosts, check network IDS alerts



Case Creation: Open TheHive case, attach observables and timeline



Containment: Trigger SOAR playbook to block attacker IP, disable compromised account



Detection Engineering: Write new Wazuh/Suricata rule to catch the technique used



Forensics: If malware found, submit to reverse engineering container for analysis



Report: Generate incident report with timeline, IOCs, recommendations

Purple Team Automation

The endgame: orchestrated attack/detect cycles





Red agent executes MITRE ATT&CK technique T1190 (exploit public-facing app)



System checks: did Wazuh detect it? Did Suricata fire? What was the detection latency?



Blue agent investigates and responds



System scores: detection coverage, response time, investigation quality



Repeat across technique library, generate ATT&CK coverage heatmap



What Stays Docker vs. What Needs VMs

Docker (everything except Windows):





All Linux services (AD, web app, DB, mail, file server, DNS)



All security tools (Wazuh, Suricata, MISP, TheHive, Shuffle)



Kali, reverse engineering



This keeps the "start with one command" experience

VM (Windows only):





Windows 11 endpoint via KVM (Aurora setup already planned)



Optional: Windows Server for real AD (Samba AD covers 80% of use cases)

Resource estimate for the full stack:





Current APTL: ~5GB RAM



Enterprise services: +4-5GB (AD, web app, DB, mail, file server, DNS)



Security stack: +6-8GB (MISP ~2GB, TheHive ~2GB, Shuffle ~1GB, Suricata ~1GB, expanded Wazuh ~2GB)



Windows VM: +4-6GB



Total: 20-24GB RAM -- fits on a 32GB machine, comfortable on 64GB



Phased Implementation

Phase 1: Enterprise Attack Surface (Docker-only additions)





Samba AD DC with TechVault domain and users



PostgreSQL with seeded data



Vulnerable web application (TechVault portal)



Network segmentation (3+ Docker networks with routing)



Enhanced Wazuh rules for AD, web app, database events



Suricata IDS with network tap

This alone transforms the lab. You go from "one host with a PHP shell" to "multi-host enterprise with identity, web app, database, and network monitoring." Red team agent can now run real attack chains. Blue team agent has meaningful alerts to investigate.

Phase 2: SOC Tooling





MISP with threat feeds



TheHive with case templates



Shuffle SOAR with response playbooks



New MCP servers: threatintel, casemgmt, soar, network



Wazuh integrations: Suricata, MISP IOC matching, active response

This is what makes the blue team agentic. Without case management and threat intel, the agent can only query logs. With these tools, it can run a full investigation workflow.

Phase 3: Extended Enterprise





Email server (phishing scenarios)



File server (lateral movement, data collection)



Windows VM joined to domain



DNS server for internal resolution and C2 detection



Caldera for structured adversary emulation

Phase 4: Autonomous Purple Team





Scenario engine with MITRE ATT&CK mapping



Automated attack/detect scoring



Coverage gap analysis



Report generation



Scenario library (10-20 mapped attack chains)



Key Decision Points

Before starting implementation, a few choices to make:





Identity: Samba AD DC (Docker, good enough for 80% of AD attacks) vs. Windows Server AD (VM, full fidelity). Samba is simpler but won't support all AD attack techniques.



Threat Intel: MISP (mature, heavier, ~2GB RAM) vs. OpenCTI (newer, GraphQL API, heavier still). MISP is more proven and has better Wazuh integration.



SOAR: Shuffle (open source, Docker-native, good API) vs. n8n (more general, better UI). Shuffle is purpose-built for security.



Web App: Build a custom TechVault app (realistic but effort) vs. deploy DVWA/Juice Shop (quick but generic). A hybrid -- Juice Shop behind TechVault branding -- might be the pragmatic path.



Network IDS: Suricata (better community rules, JSON output, Wazuh integration) vs. Zeek (richer metadata, steeper learning curve). Suricata is the easier win.



Windows: Required for Phase 3 or skip entirely? Without Windows, you lose AD-joined endpoint attacks, but Phases 1-2 still work.
