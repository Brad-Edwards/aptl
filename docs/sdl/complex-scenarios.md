# Complex SDL Scenario Designs

This document is the up-front design pass for several intentionally
large, high-state SDL example scenarios. The goal is to design the
experiments first, then encode them in SDL, rather than letting the
current parser surface dictate the scenario concept.

The corresponding specifications live in `examples/*.sdl.yaml`.

## Design Principles

- Stress multiple trust boundaries at once: identity, network,
  application, data, vendor access, and recovery paths.
- Include both attack and defense experiments, not just topology.
- Use the declarative experiment surface we now have:
  scoring, entities, orchestration, agents, objectives, and variables.
- Prefer scenarios we could plausibly instantiate later rather than
  abstract toy graphs.
- Surface authoring friction explicitly when the SDL makes a concept
  awkward or requires approximation.

## Scenario 1: Hospital Ransomware on Surgery Day

**Filename:** `examples/hospital-ransomware-surgery-day.sdl.yaml`

### Exercise Question

Can a hospital blue team preserve clinical operations and recover from
third-party-access ransomware during a live surgery-day crisis while a
red team attempts data theft and radiology disruption?

### Topology Shape

- Public access edge for mail and VPN
- Corporate IT segment
- Clinical application segment
- Identity segment
- Security operations segment
- Backup / recovery segment
- Vendor support segment

### Key Systems

- Secure mail gateway
- VPN concentrator
- Active Directory / IdP
- Exchange
- EHR application tier
- EHR database tier
- PACS / radiology archive
- Medical device gateway
- Backup vault
- SIEM / SOC node
- Vendor jump host

### Key State

- PHI dataset in the EHR database
- DICOM/radiology archive in PACS
- Phishing lure dataset in Exchange
- Vendor support credential material
- Immutable backup manifest and restore runbooks

### Exercise Narrative

1. A vendor advisory and phishing wave arrive ahead of the clinical day.
2. Red obtains a foothold through email or vendor access.
3. Red laterally moves through identity and application paths toward EHR
   and PACS.
4. Red attempts simultaneous PHI theft and clinical disruption during the
   surgery window.
5. Blue must contain access, preserve patient-facing availability, and
   restore from trusted backups.

### Intended Declarative Semantics

- Red objectives: establish foothold, exfiltrate PHI, disrupt radiology
- Blue objectives: detect the intrusion, preserve EHR/PACS availability,
  restore from immutable backups, produce an incident report
- Windows tied to an exercise story with pre-surgery, live-clinic, and
  recovery phases
- Success based on a mix of conditional uptime metrics and manual
  reporting / recovery evaluation

### SDL Stress Surface

- All 21 sections
- Hybrid IT + clinical + vendor trust boundaries
- Multiple agents with distinct initial knowledge and subnet scope
- Objectives that target systems, relationships, and content

## Scenario 2: SatCom Supply-Chain Release Poisoning

**Filename:** `examples/satcom-release-poisoning.sdl.yaml`

### Exercise Question

Can a platform engineering team detect and contain a poisoned signed
release before it propagates from CI/CD into regional edge gateways,
while maintaining customer telemetry and tenant isolation?

### Topology Shape

- Corporate engineering network
- Build / CI network
- Control-plane management network
- Edge gateway network
- Telemetry network
- Customer / federation boundary
- Security monitoring network

### Key Systems

- Git forge
- CI runner
- Artifact registry
- Signing/HSM service
- Control-plane API
- East and west regional edge gateways
- Telemetry broker
- Customer portal
- Support bastion
- SIEM
- Vendor and customer identity providers

### Key State

- Release manifests and golden configs
- Registry credentials and signing material
- Customer API keys
- Rollback playbooks and canary reports

### Exercise Narrative

1. Engineering enters a release freeze for a planned rollout.
2. Red compromises a build or support path and poisons a candidate
   release.
3. The poisoned artifact is promoted to canary and then toward
   production.
4. Blue must detect the trust break, stop promotion, roll back affected
   gateways, and preserve tenant telemetry.

### Intended Declarative Semantics

- Red objectives: gain build access, poison a signed artifact, propagate
  to at least one edge region
- Blue objectives: validate artifact trust, halt release, preserve
  telemetry, complete rollback before deadline
- Release timing parameterized with variables for ring and rollback
  deadline
- Relationships express management, federation, authentication, and
  replication paths

### SDL Stress Surface

- Variables used in deployment and exercise properties
- Rich relationship graph around release, trust, and management
- Multi-agent experiment with overlapping but distinct objectives

## Scenario 3: Port Authority Surge and Yard Disruption

**Filename:** `examples/port-authority-surge-response.sdl.yaml`

### Exercise Question

Can a port authority maintain customs integrity and safe yard operations
during a cargo-surge day while a red team tampers with manifests and
degrades crane/HMI operations?

### Topology Shape

- Public shipping / portal edge
- Terminal IT segment
- Customs / partner link
- Yard OT segment
- Safety network
- Vendor maintenance network
- Security monitoring network
- Backup / historian network

### Key Systems

- Shipping portal
- Manifest database
- Terminal operating system
- Port identity provider
- Customs gateway
- Yard HMI
- Crane PLC
- Camera analytics
- Historian
- Vendor jump host
- SOC node
- Backup vault

### Key State

- Cargo manifests
- Hazardous materials list
- Customs hold records
- Yard camera clips
- Maintenance procedures and recovery runbooks

### Exercise Narrative

1. The port starts a surge day with elevated inbound cargo.
2. Red manipulates manifest data and attempts to degrade OT visibility
   and crane control.
3. Customs and port operations must continue coordinated work across
   organizational boundaries.
4. Blue must preserve safety, validate cargo integrity, and recover
   terminal throughput.

### Intended Declarative Semantics

- Red objectives: tamper with manifests, degrade yard operations
- Blue objectives: preserve customs clearance fidelity, maintain safe HMI
  control, recover throughput
- Story phases cover arrival, customs surge, disruption, and blackstart
  recovery
- Entities model port IT, yard ops, customs, vendor, red, and white cell

### SDL Stress Surface

- IT/OT crossover without requiring runtime-only deployment semantics
- Relationship targets that matter to the experiment, not just topology
- Content-heavy environment with both operational and evidentiary data
