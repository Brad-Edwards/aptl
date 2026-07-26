# Guided Purple Participant Profile

`guided-purple` version 1 is APTL's bounded workshop and classroom profile. It
freezes one attack-detect-investigate-purple narrative without creating an
event-specific scenario, Compose profile, or source fork.

The versioned binding is
`participant-profiles/guided-purple-v1/profile.json`. It references, by path
and SHA-256 digest, the narrative, existing `techvault-attacker-target`
scenario, non-secret `aptl.json`, readiness suite, and staged asset lock.

Unknown fields, unsafe paths, digest drift, scenario catalog drift, and a
required narrative operation without a readiness check all fail closed.

## Required guided loop

The participant path is deliberately small:

1. open the staged participant guide;
2. use the red workbench to prove the real Kali backend and desktop;
3. generate bounded failed SSH authentication attempts against the victim;
4. switch to the guided-blue workbench;
5. find the resulting Wazuh rule 5710 alert through the indexer MCP;
6. investigate the same event through the Wazuh MCP and `soc-wazuh` browser
   projection; and
7. bind the attack, detection, and investigation to one run record.

SMB enumeration, web SQL injection, MISP, TheHive, Cortex, Shuffle, Suricata,
and the wider enterprise are optional research or facilitator material. They
are not part of version 1 qualification.

## Derived runtime and participant surfaces

APTL derives the service and network surface from the catalog entry, ACES
planning and dependency closure, the strict profile config, and the Compose
profile index. The current derivation selects `kali`, `victim`, `wazuh`, and
`otel`, producing ten steady-state services:

- Kali, its capture sidecar, and its loopback SSH proxy;
- the monitored victim;
- Wazuh manager, indexer, and dashboard; and
- OpenTelemetry Collector, Tempo, and Grafana.

Both missing and unexpected services fail qualification.

The participant profile composes the workbench contracts introduced by #821:

| Phase | Workbench | MCP servers | Browser bookmarks |
| --- | --- | --- | --- |
| Attack | `red` | `aptl-red` | `aptl-guide`, `kali-desktop` |
| Detect and investigate | `guided-blue` | `aptl-indexer`, `aptl-wazuh` | `aptl-guide`, `soc-wazuh` |

The profile derives these surfaces from the workbench registry rather than
copying them. The full `blue` workbench remains unchanged for research use.
Case management, network IDS, SOAR, threat intelligence, and their bookmarks
must be absent from a guided-purple participant session.

Each enabled MCP qualification starts the real server, checks its exact
workbench tool inventory, invokes a bounded backend operation, and validates
the semantic result. Process health or tool discovery alone is insufficient.

## Staged asset contract

`participant-profiles/guided-purple-v1/asset-lock.json` locks the profile
documents, scenario, Compose model, released MCP builds and dependency locks,
and every required OCI image identity. Qualification fails if any contained
asset digest drifts.

After staging, the profile must complete without downloads, image pulls, image
builds, or package resolution. The profile asset lock is an input to #823's
signed appliance payload; it is not that outer payload manifest.

## Budget and report contract

The declared minimum fixture is x86-64 with 8 vCPUs, 16 GiB of memory, and
100 GiB of disk. Version 1 ceilings are:

| Dimension | Ceiling |
| --- | ---: |
| Peak profile CPU | 90% |
| Peak profile memory | 12 GiB |
| Staged profile assets | 50 GiB |
| Unique compressed OCI content | 15 GiB |
| Unique expanded OCI content | 35 GiB |
| Peak runtime disk | 30 GiB |
| Cold start | 900 seconds |
| Warm start | 300 seconds |
| Clean inner reset | 600 seconds |

These values are conformance limits, not claimed measurements.

The machine-readable report binds the profile and asset-lock digests to the
hardware fixture, derived and actual runtime matrices, exact workbench/MCP/
browser surfaces, readiness results, denied-egress counters, measurements,
run record, and snapshot.

`aptl lab qualify-profile --report <path> --public-key <path> --run-id <id>`
verifies the report's Ed25519 attestation against the qualification pipeline's
trusted public key, verifies the content digests and correlation of its run
record and range snapshot, re-derives the expected surface, evaluates every
conformance layer, and persists the redacted result. It exits nonzero for
invalid, unauthenticated, or nonconforming evidence. The protected
qualification pipeline controls the trusted key; a key selected by the report
producer is not a trust anchor.

## Relation to the appliance work

#820, #821, and #822 are peer inputs to #823. This profile owns the bounded
inner workload and clean lab reset. #822 owns zone/egress enforcement. #823
owns the signed outer appliance, kiosk lifecycle, physical-host exposure, and
disposable seat reset, and consumes this profile's lock and qualification
report.

## Full research stack

`techvault-operational` remains the full developer and research scenario. It
adds the enterprise, Suricata, MISP, TheHive, Cortex, Shuffle, and other
systems and needs more than 20 GiB of Docker memory. Its readiness or resource
results are not evidence for `guided-purple`.
