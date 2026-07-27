# Bounded Participant Agency Readiness

APTL's issue-557 readiness gate proves that one exact RAES 2.0 model can drive
bounded green, red, and blue participant behavior through the conformant APTL
backend. It is a qualification operation, not study capture.

The selected authored input is
`scenarios/bounded-participant-agency-techvault.sdl.yaml`. APTL retains its
source digest, compiled-model digest, exact execution plan, realization, and
run identity as the authority for every turn.

The privileged 26-action realization registry is available only when both
authorities match the approved pre-capture candidate:

- authored source SHA-256:
  `9683f2539bdefbd99635924d2a6fce27b144e12f382cd74d2f3e10d10ecb7616`;
- compiled model SHA-256:
  `099209f578da193ce88e201cc86887ae8ca4587a6b9c6b1a570ed195047d4c8c`.

The compiled digest covers the complete model in the versioned
`aptl.raes-runtime-model-artifact/v1` envelope, serialized as RFC 8785
canonical JSON. Unsupported values fail serialization; the identity never
uses insertion order or lossy `str()` coercion.

Each admitted action maps to a fixed semantic operation over the declared
synthetic portal, customer, support, assessment, alert, or response state.
The action result reports only preconditions and effects established by a
separate readback of those action-specific fields. Evidence is staged during
native execution and published only after the RAES base runtime accepts the
typed outcome and history transition. The first publication is one immutable,
atomic action transaction containing both participant and evaluator
projections:

```text
runs/<run-id>/evaluator/participant-action-transactions/<action-digest>.json
```

The participant and evaluator JSONL streams are recoverable projections of
that record. A projection failure cannot erase or reverse an already accepted
RAES transition, but it adds an explicit operation diagnostic and fails
readiness.

## Deterministic Qualification

Start the selected lab, then run:

```bash
aptl lab start \
  --scenario bounded-participant-agency-techvault \
  --skip-seed

aptl lab participant-readiness \
  --suite \
  --provider deterministic \
  --run-id participant-qualification-pre-capture
```

The suite:

- executes the authored-order positive trajectories for all nine behaviors;
- admits every one of the 26 compiled actions through RAES v2;
- enumerates the complete finite cross-product of governed argument choices
  rather than collapsing each action to one default;
- exercises boundary challenges BC-01 through BC-10;
- verifies rejected challenges have no behavior event, action evidence, or
  independently observed episode-state effect;
- verifies identical and conflicting replay do not duplicate an effect;
- records exact authority digests and structured participant/control/action
  evidence; and
- records `official_capture_started: false`.

The root report is:

```text
runs/<run-id>/participant/readiness-suite-report.json
```

Each positive trajectory and boundary challenge has its own child run. The
root report lists their stable run IDs and evidence paths.

## Installed Provider Qualification

The installed-provider modes use one provider-specific, non-placeholder
credential lease:

- Claude Code: `ANTHROPIC_API_KEY`
- Codex CLI: `CODEX_API_KEY`

The child receives no action tools, MCP servers, shell, Docker, SSH, browser,
or backend handle. It only chooses one complete candidate from the delivered
RAES decision surface. APTL presents the installed provider with a bounded,
numbered transport view containing every action identity and governed argument
map. The number is a transient alias for one delivered `proposal_ref`; APTL
resolves it to the unchanged full selection before RAES admission. The complete
delivered solicitation remains the evidence authority.

Each finite governed choice is represented by a distinct proposal, and the
selected values materially determine the native semantic operation and
independent readback. RAES re-resolves the exact state cut, delivery,
apparatus, proposal, and governed arguments before APTL can execute a closed
realization. Missing, malformed, duplicate, or out-of-range transport choices
fail before admission. Installed-provider prompts remain bounded to 32,768
characters.

Run each implementation separately:

```bash
aptl lab participant-readiness \
  --suite \
  --provider claude \
  --installed-turns 8 \
  --run-id participant-qualification-claude-pre-capture

aptl lab participant-readiness \
  --suite \
  --provider codex \
  --installed-turns 8 \
  --run-id participant-qualification-codex-pre-capture
```

Each command repeats the deterministic qualification and adds bounded green,
red, and blue episodes for that installed implementation. Missing or unsafe
executables, credentials, malformed output, timeouts, and out-of-surface
selections fail with redacted readiness evidence.

## Single-Trajectory Diagnostics

Use the diagnostic mode when isolating one behavior:

```bash
aptl lab participant-readiness \
  --single-trajectory \
  --provider deterministic \
  --behavior blue-response \
  --turns 6 \
  --run-id participant-blue-response-diagnostic
```

Terminal participant failures are retained as typed outcomes. They do not by
themselves mean the control boundary failed, but a positive readiness
trajectory passes only when every requested terminal outcome succeeded.
Expected-failure boundary challenges remain separate checks.

Do not use any readiness command as an official study run. Pilot scheduling,
official capture, and corpus acceptance remain explicit steps in the related
research runbook.
