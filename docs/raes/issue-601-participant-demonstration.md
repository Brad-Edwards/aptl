# Issue 601: TechVault participant demonstration

## Selected scenario

The study uses the `techvault-participant-study` environment pack in
OpenRAE/env-packs. It is a copy of the proven TechVault pack with a narrow
participant-control addition: four instructions, four injects, four events,
one ordered script, one story, red and blue participant behavior
specifications, exact logical-time windows, and four delivery-evidence
requirements. The scenario declares Claude Code through the realization
profile `participant-implementation-manifest:claude-code`.

The diagnostic run admitted the earlier pack set digest
`sha256:94dc0236f3e2d4c62db782040acd73b1739ba0bf12adec580289a916fbfcce5a`.
The released 0.1.1 study pack has set digest
`sha256:fdde7b1a8b9377f7ddd473417de1f3fd3e24549e4560d8d6392f1727b3af5357`.
Run `run_20261004T012853Z` admitted that released identity through the normal
lab lifecycle.
The study pack remains `built`; that lifecycle state makes no claim that an
attempt produced golden proof.

RAES parses and compiles the participant identities, instructions, occurrence
order, control transitions, evidence references, and shared logical time. APTL
selects the installed realization adapter named by the compiled profile,
projects the role-specific MCP tools from the admitted red or blue profile,
and persists each completed delivery through the existing RAES evidence
boundary. APTL contains no study prompt, participant name, or study-specific
sequence.

## SDL-authored sequence

The scenario's `participant-study-sequence` is:

| Logical tick | Participant | Inject | Effect |
| ---: | --- | --- | --- |
| 1 | red | `red-participant-start` | Direct the red participant to perform the bounded login-route probe. |
| 3 | red | `red-participant-stop` | Stop further red tool use and request the red participant's final account. |
| 5 | blue | `blue-participant-start` | Tell the blue participant that red activity has stopped and direct the investigation. |
| 7 | blue | `blue-participant-stop` | Stop further blue tool use and request the blue participant's final account. |

The start and stop instructions for a participant use the same provider
session. Red and blue use distinct sessions and distinct admitted MCP tool
sets. Delivery fails closed if a prompt, role, realization profile, exact time
window, control transition, or evidence binding is missing or unsupported.

## Reproduce the run

As of October 3, 2026, the upstream release candidates are available on PyPI:
[RAES 6.0.1](https://pypi.org/project/raes/6.0.1/) and
[env-packs 6.2.0](https://pypi.org/project/raes-env-packs/6.2.0/).
The latter requires RAES 6.0.1 and includes the TechVault study correction from
[env-packs PR #402](https://github.com/OpenRAE/env-packs/pull/402).
[RAES #1401](https://github.com/OpenRAE/rae/issues/1401) is closed.
The release-availability blocker described in the September 28 progress
record has therefore cleared.

This branch pins RAES 6.0.1 and env-packs 6.2.0 and binds the regenerated 0.1.1
pack identities. The October 4 run below verifies the installed participant
and clean lab lifecycle. It remains an unsealed lab-start archive because the
lab-start path does not own an admitted experiment terminal context; that
limitation is preserved in the exported bundle.

Parallel delivery work also affects reproducibility:
[APTL #1186](https://github.com/OpenRAE/lilrae/issues/1186) covers persistent
guest sudo provisioning and the optional host tailnet relay;
[APTL #1194](https://github.com/OpenRAE/lilrae/issues/1194) investigates the
shipped seat's need for manual Docker network correction. A future seat-based
qualification must record the selected image digest, embedded software
revision, Docker daemon/context, and observed network attachments. A source
fix alone does not prove that an existing seat contains it. Preserve occupied
seats and their sessions; the issue 601 status update does not alter either
parallel branch, worktree, or live seat.

1. Install pinned, published builds containing the corrected env pack, the
   matching APTL adapter, and a RAES runtime that accepts participant-inject
   delivery addresses as temporal subjects. Record their distribution versions,
   lockfile identity, and qualified pack digest.
2. Sign into the host Claude Code CLI using the participant operator's own
   account. Provider authentication remains in that CLI's host session and is
   not copied into SDL, `aptl.json`, the generated MCP files, or the run
   archive. Set `experiment.participant_models.claude` to an immutable model
   identifier; Vertex identifiers may use the `@YYYYMMDD` suffix. When the
   authenticated CLI uses Vertex, provide its region through the host's
   `CLOUD_ML_REGION` environment variable.
3. Use a separate project for this experiment. Set its `scenario.identity` to
   `techvault-participant-study` and `scenario.source` to `env-pack` in
   `aptl.json`. Keep the existing deployment and container selection. The
   repository configuration and seat images select standard `techvault`.
4. Run `aptl lab start`. Normal admission validates and compiles the pack,
   realizes TechVault, synchronizes MCP credentials, and then delivers the four
   compiled participant injects in logical-time order. No separate readiness
   command, manual prompt command, or direct experiment script is involved.
5. Inspect `participant/inject-deliveries.jsonl` for the four bounded delivery
   index entries and `evidence/records/` for their portable
   `experiment-evidence-record/v1` records. The content-addressed evidence
   retains each exact instruction, provider response, delivery identity,
   participant identity, model, and non-secret provider metadata. The public
   index carries hashes, a non-secret conversation-continuity digest, and
   record identities rather than prompt, response, or session bodies.
6. Verify or export the retained bundle through the normal run archival flow
   when the attempt reaches the applicable terminal state. Report absent seals,
   capture loss, participant deviations, and unsupported conclusions as such.

A clean completion record requires a successful volume-reset stop, the four
delivery records, the native evidence and control/crossing records, the
terminal run provenance record, and a verified sealed bundle. The start result
alone does not establish the terminal archive.

## Evidence and claim limits

### Published-component lifecycle run

Run `run_20261004T012853Z` used committed branch revision `3d0e8c8f`, the
published RAES 6.0.1 and env-packs 6.2.0
distributions, study pack 0.1.1 at set digest
`sha256:fdde7b1a8b9377f7ddd473417de1f3fd3e24549e4560d8d6392f1727b3af5357`,
Docker Engine 29.5.0, Docker Compose 5.1.3, and the authenticated host Claude
Code CLI with model `claude-sonnet-5`. The ordinary
`aptl lab start --clean --yes --scenario techvault-participant-study` command
returned `Lab is ready`; the subsequent `aptl lab stop -v -y` returned
`Lab stopped successfully` and removed the range.

The retained archive establishes:

- four delivered injects in SDL order at logical ticks 1, 3, 5, and 7;
- five required native evidence records, four participant-delivery records,
  and a transcript-finalization record;
- eight accepted participant-control occurrences and sixteen API-423 crossing
  occurrences;
- a terminal participant-study clock coordinate of tick 7, microstep 0;
- distinct red and blue role-scoped MCP configurations with continuity inside
  each participant's start/stop pair; and
- a successful clean start and volume-removing stop without manual service or
  network repair.

The exported 25-member evidence bundle verified with root identity
`sha256:82929cd1d895de3ef05d06254f96faf5223cf68436ccdea0114f0add9a1c674f`.
It reports two limitations: `provenance/run-provenance.json` is absent and no
verified archive seal is available. The bundle is therefore an independently
integrity-verified, unsealed engineering artifact. It does not satisfy the
terminal experiment-seal condition above and does not establish participant
correctness, detector quality, or a scientific outcome.

### Four-inject qualification run

The later `run_20260927T190733Z` delivered four injects, nine evidence records,
eight control occurrences, and sixteen crossing occurrences through a local
engineering setup. That setup used temporary dependency and configuration
changes plus manual Wazuh baseline recovery. Its 23-member exported bundle
verified byte integrity but was unsealed and lacked
`provenance/run-provenance.json`. It is diagnostic evidence only and does not
qualify issue 601 against published contracts.

Run `run_20260925T153251Z` completed through the ordinary `aptl lab start`
path with Claude Code 2.1.282, the authenticated host CLI, and the immutable
provider model `claude-haiku-4-5-20251001`. The terminal start result was
`Lab is ready`.
The retained evidence establishes:

- four delivered injects in the SDL-authored order: red start at tick 1, red
  stop at tick 3, blue start at tick 5, and blue stop at tick 7;
- four distinct content-addressed participant-delivery records plus the five
  required native TechVault records;
- one shared conversation-continuity digest for the red pair, one for the blue
  pair, and distinct digests across the two participants;
- raw provider session identifiers withheld in both participant records while
  the non-secret continuity digests remain available in the public index;
- a terminal RAES participant-study clock coordinate of tick 7, microstep 0,
  sequence 4;
- eight accepted participant-control occurrences: a proposal and external
  direction for each delivery;
- sixteen API-423 crossing occurrences: four requested/decided pairs for each
  participant, with all semantic gates admitted by the SDL-derived policy;
- successful provider results with no permission denials for every turn: red
  start used 45 provider turns, red stop used one, blue start used 25, and blue
  stop used one;
- 44 independently retained red Kali MCP call entries. The blue provider
  responses describe the SQL-injection investigation and Wazuh/Suricata
  findings, but the current MCP-side call ledger does not independently
  enumerate the blue tool calls.

The run directory is an unsealed local engineering qualification artifact. It
demonstrates delivery, ordering, role separation, session continuity, tool
compartment construction, and retained provider outcomes. It does not prove
that every participant statement is correct or promote the attempt to a sealed
scientific result. The subsequent `aptl lab stop` removed the lab but reported
`aptl.scenario-evidence.required-transcript-finalization-failed`; the retained
run therefore makes no successful terminal-transcript or archival-seal claim.

### Retained transcript contract after issue #1201

New TechVault transcript evidence uses `aptl-techvault-transcript/v2`. Its
`transcript_entries` retain ordered frames, direction, timestamps, and close
reason. Each entry has a `terminal_ref` derived from the broker session identity
and validated custody digest; the raw session ID is not retained. The ordinary
evidence redactor still removes secret-shaped values within frame `data`.
The adapter scans joined terminal frames for credentials split across transport
reads. When a joined scan detects a secret that individual frames missed, it
withholds the affected direction's frame data; cross-direction ambiguity or
oversized scan context withholds the session's frame data while retaining its
structure and custody metadata.

`source_chain_digest` names the digest of the original, unredacted broker frame
chain, validated before projection. It cannot authenticate text after redaction.
The evidence record's `raw_content.content_checksum` and blob URI digest instead
identify the exact retained redacted bytes. Finalization validates the stored
v2 blob against the admitted transcript and frame counts before it records a
successful terminal outcome. Bundle closure checks the self-contained v2 shape
for a record pinned to the transcript collector and reports
`aptl.evidence-bundle.invalid-transcript` on failure. Portable bundle checksum
verification checks bytes and inventory; it does not independently compare the
transcript with the broker census. If the referenced capture plan is missing or
malformed, bundle closure reports `aptl.evidence-bundle.capture-plan-unavailable`
because it cannot qualify the adapter semantics.

### Research and product coordination

The October 4 run supplies the APTL-side engineering evidence requested by
[APTL #558](https://github.com/OpenRAE/lilrae/issues/558). Its run identity,
pack digest, backend and participant realization, ordered delivery evidence,
native evaluator evidence, topology/run manifest, redaction behavior, and
limitations are recorded here and under `runs/run_20261004T012853Z/` in the
executing workspace. The run also extends the real participant action surface
proved by [APTL #554](https://github.com/OpenRAE/lilrae/issues/554). The local
run directory remains an unsealed engineering artifact and is not a published
research bundle.

[Hub #15](https://github.com/OpenRAE/hub/issues/15) defines APTL as the advanced
TechVault experience on the LilRAE personal/local backend. The pack identity,
scenario MCP selection, participant implementation profile, provider model,
backend identity, and evidence limitations captured by this run are inputs to
that walkthrough. This attempt used APTL's current backend implementation, so
it does not establish Hub #15's released-LilRAE execution criterion.

[LilRAE #1221](https://github.com/OpenRAE/lilrae/issues/1221) owns the future paired
LilRAE and BigRAE invariant ledger. This APTL run contributes a candidate
portable evidence shape and participant sequence. It is not one side of a
LilRAE-versus-APTL comparison and makes no cross-backend equivalence,
participant-performance, or detector-quality claim.

### Earlier transport evidence

An earlier engineering run, `run_20260925T021526Z`, established that an
authenticated Claude Code 2.1.282 process could use the realized red MCP path
against TechVault. It issued one SQL-injection request and received
`500 Internal Server Error`, matching an invalid-login baseline. Its finalized
red transcript retained 30 events and its 17-member unsealed bundle verified
with root identity
`sha256:749b99d4998e7451dfd68f2c785e6d6b7a6b590496ada00e8a994c81101f1780`.
That run used a manual direct prompt before the SDL participant sequence was
implemented. It is useful engineering evidence for the transport and target,
but it does not qualify the four-inject design described here.

A completed four-inject run can establish that the identified pack compiled,
the normal APTL lifecycle delivered the authored instructions in order to the
declared installed participant realization, the role profiles constrained the
available MCP tools, and the four delivery records were retained. It does not
by itself establish that an injection succeeded, that the defensive conclusion
was correct, that the participant obeyed every instruction, or that a run is
scientifically complete or sealed. Those claims require the corresponding
observed target evidence, evaluator assessment, capture completeness, and
terminal archival state.
