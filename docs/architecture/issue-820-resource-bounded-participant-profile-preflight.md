# Issue #820: Resource-Bounded Participant Profile

This note records the implementation boundary for APTL's reusable bounded
participant lab profile. ADR-049 owns the disposable appliance around the lab;
this issue owns the inner APTL workload that the appliance will carry.

## Dependency direction

Issues #820, #821, and #822 are peers:

- #820 defines and qualifies the bounded APTL lab profile.
- #821 supplies the in-appliance workbench profiles and their exact MCP and
  bookmark inventories.
- #822 enforces appliance zones, egress, and physical-host exposure.
- #823 consumes all three outputs to assemble and qualify the disposable
  appliance artifact.

The participant profile therefore does not reference an appliance payload,
require #823 output, or duplicate #822 listener policy. Its qualification
report is an input to #823's broader appliance qualification.

## Profile authority

`participant-profiles/guided-purple-v1/profile.json` is the versioned binding.
It references immutable inputs by contained path and SHA-256 digest:

- the required, optional, and facilitator-only narrative;
- the existing `techvault-attacker-target` RAES scenario;
- the non-secret `AptlConfig`;
- the readiness suite;
- the staged profile asset lock;
- the #821 workbench profile sequence; and
- minimum hardware plus resource and lifecycle ceilings.

The profile is not another topology. APTL continues to derive services and
networks from the scenario catalog, RAES planning and dependency closure,
`AptlConfig`, and the Compose profile index. Both missing and unexpected
steady-state services fail qualification.

Unknown manifest fields, unsafe paths, digest drift, scenario/catalog drift,
unrecognised workbench profiles, and required narrative operations without
readiness checks fail closed.

## Frozen guided narrative

Version 1 requires one attack → detect → investigate → purple loop:

1. open the staged guide and Kali desktop projections;
2. prove the real Kali backend with `id`;
3. generate bounded failed SSH logins against the declared victim;
4. find the resulting Wazuh rule 5710 event through the indexer MCP;
5. retrieve it through the Wazuh MCP;
6. inspect it through the `soc-wazuh` browser projection; and
7. correlate those results in one run record.

SMB, web SQL injection, Suricata, MISP, TheHive, Cortex, Shuffle, and the
enterprise range remain full-research material. No event-specific scenario,
Compose profile, image, MCP server, or source fork is introduced.

## Workbench and capability surface

The delivery sequence is `red` followed by `guided-blue`. These are #821
workbench profiles, not copied allow-lists:

- `red` contributes `aptl-red`, `aptl-guide`, and `kali-desktop`;
- `guided-blue` contributes `aptl-indexer`, `aptl-wazuh`, `aptl-guide`, and
  `soc-wazuh`.

The participant-profile loader derives the union of MCP server IDs and browser
bookmarks from those workbench definitions. Qualification requires the exact
workbench sequence and exact derived MCP/browser surfaces.

Each allowed MCP must initialize, return the exact tool inventory defined by
its workbench `ServerProfile`, and complete its bounded semantic backend
operation. A successful process start, TCP connect, or `tools/list` call alone
does not pass. Disabled full-blue servers and bookmarks must be absent.

#822 owns network listener and egress enforcement. #823 owns the appliance
participant route and proves the combined artifact. This profile supplies the
capability expectations they consume.

## Staged assets

`asset-lock.json` is the content-addressed closure for version 1. It locks the
profile inputs, Compose model, released MCP artifacts/dependency locks, and
the exact OCI identities required by the derived service set. Profile loading
verifies every project-contained entry and validates every OCI digest
relationship before qualification.

Profile startup is staged-only. The qualification report fails if startup or
the guided workflow records a download, image pull, image build, or package
resolution. Developer starts may retain their normal conveniences, but they
are not qualification evidence.

The asset lock is intentionally separate from ADR-049's signed appliance
payload manifest. #823 embeds this locked closure and binds it into the signed
outer artifact.

## Readiness and qualification

`readiness.json` is the machine-readable required-check set. The report must
contain that exact set (no missing or extra check IDs), and all checks must pass.
It also records:

- exact expected and actual services and networks;
- actual workbench profiles, MCP servers, and browser bookmarks;
- minimum-hardware identity;
- denied-egress and post-stage resolution counters;
- peak CPU and memory;
- staged profile-asset, unique compressed-image, unique expanded-image, and
  peak runtime-disk sizes;
- cold start, warm start, and clean inner reset durations; and
- canonical run-record and snapshot references.

Those are inner workload measurements. Guest OS, kiosk lifecycle, physical
host listeners, and disposable-seat replacement are outer appliance concerns
measured by #823.

`aptl lab qualify-profile --report <path> --public-key <path> --run-id <id>`
reloads the bound profile, verifies the qualification pipeline's Ed25519
attestation plus the content-addressed run record and range snapshot,
re-derives the runtime surface from that authenticated snapshot, evaluates the
strict report, and persists the redacted result through the configured run
store. It exits nonzero for invalid, unauthenticated, or nonconforming
evidence. The protected pipeline supplies the trusted key independently of the
report producer.

## Acceptance mapping

- Clean minimum-hardware boot: exact hardware plus cold-start evidence.
- Measured memory, disk, start, warm start, and reset: typed measurements
  evaluated against the versioned ceilings.
- Real MCP smoke: the red backend proof and attack run before the indexer and
  Wazuh alert checks, with exact `tools/list` validation.
- Disabled service absence: exact derived service matrix and exact
  workbench/MCP/browser surfaces.
- No post-stage downloads: asset-lock identity, denied egress, and zero
  pull/build/download/package-resolution counters.
- Complete guided workflow: every narrative operation maps to a required
  readiness check.
- Bounded versus full research: the participant reference and workshop
  material name the excluded research systems explicitly.

## Non-goals

This issue does not implement the disposable appliance, host kiosk, seat
replacement, outer signed payload, network zones, physical-host publication,
or a general role system. It does not change RAES scenario meaning, add a
second start path, or turn the full blue workbench into a workshop-specific
profile.
