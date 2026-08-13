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
  `7a29b45d3949ccf083ea048261421096ab81d94b4524a3ac37426a8ed09998f7`.

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

Installed providers do not inherit a product default model. Freeze the exact
non-secret provider selection in `aptl.json`:

```json
{
  "experiment": {
    "participant_models": {
      "claude": "claude-sonnet-4-5-20250929",
      "codex": "gpt-5-nano-2025-08-07"
    },
    "participant_credential_sources": {
      "claude": {
        "kind": "process-environment",
        "variable": "APTL_PARTICIPANT_CLAUDE_CREDENTIAL"
      },
      "codex": {
        "kind": "process-environment",
        "variable": "APTL_PARTICIPANT_CODEX_CREDENTIAL"
      }
    }
  }
}
```

The selected model is passed explicitly to the provider process. Missing,
invalid, unsupported, or inaccessible selections fail closed; APTL does not
fall back to another model. Credentials remain separate from this
configuration. For every solicitation, both installed adapters bind the same
exact response schema using their provider-native structured-output mechanism:
one integer `candidate`, bounded from zero through the final candidate alias
delivered for that state cut, with no additional properties. Codex receives
each distinct range schema from a private, create-once file inside the run
directory. APTL still parses the result independently and resolves the alias
only against the complete delivered solicitation.

The source descriptor is non-secret; the variable it names holds the secret.
Set only the source needed for the provider being qualified, then validate the
same materialized project used by either a PyPI installation or repository
checkout:

```bash
export APTL_PARTICIPANT_CLAUDE_CREDENTIAL='<provider credential>'
export APTL_PARTICIPANT_CODEX_CREDENTIAL='<provider credential>'

aptl config validate --project-dir /path/to/lab
aptl config show --project-dir /path/to/lab
```

`aptl lab init` writes an empty `participant_credential_sources` map and tells
the operator that installed-participant sources are not configured. This is
the safe default: deterministic readiness and ordinary lab startup need no
model credential. The operator must add and confirm the descriptor before an
installed-provider run. APTL reads exactly that configured variable, maps it to
the selected adapter's provider-native delivery alias, and does not fall back
to `ANTHROPIC_API_KEY`, `CODEX_API_KEY`, saved product login state, or user
configuration. Missing, empty, placeholder, NUL-bearing, oversized, malformed,
or unavailable sources fail before provider launch without printing the
locator or value.

The initial `process-environment` source proves explicit source selection,
bounded local possession, private product-state isolation, and local reference
cleanup. It does not prove delegation, issuer expiry, renewal, secure erasure,
or upstream revocation. See
[ADR-052](../adrs/adr-052-configured-participant-credential-sourcing.md) for the
research, threat model, alternatives, and future resolver seam.

The child receives no action tools, MCP servers, shell, Docker, SSH, browser,
or backend handle. It only chooses one complete candidate from the delivered
RAES decision surface. APTL presents the installed provider with a bounded,
numbered transport view containing every action identity whose declared
prerequisites hold at that exact state cut, with every governed argument map.
The number is a transient alias for one delivered `proposal_ref`; APTL resolves
it to the unchanged full selection before RAES admission. The complete
delivered solicitation remains the evidence authority.

While an action is eligible, each finite governed choice is represented by a
distinct proposal, and the selected values materially determine the native
semantic operation and independent readback. Projection and realization
admission independently enforce successful-observation prerequisites; a
sign-out requires a fresh authentication after any earlier sign-out. RAES
re-resolves the exact state cut, delivery, apparatus, proposal, and governed
arguments before APTL can execute a closed realization. Missing, malformed,
duplicate, stale, or out-of-range transport choices fail before admission.
Installed-provider prompts remain bounded to 32,768 characters.

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

The root `aptl.participant-agency-qualification/v3` identifies the installed
provider and model. Each child `aptl.participant-agency-readiness/v3` does the
same, including failures before the first turn, and carries a
`participant_source_binding` projection. The projection records the provider,
source and resolver kinds, descriptor digest, config reference, delivery
contract, the exact adapter isolation controls applied, acquisition/isolation
results and observation times, honest expiry/renewal/revocation support, and
local cleanup result and observation time. It excludes the
variable locator, value, secret-derived data, account identity, raw provider
errors, and private paths. The safe effective-config identity similarly stores
only locator-free `participant_source_descriptors`. An installed trajectory is
not passing unless local cleanup is `succeeded`.

Successful and rejected solicitations write
`aptl.participant-control-evidence/v2` records that join the provider/model pair
to the RAES implementation manifest, implementation selection, and canonical
configuration ref/digest. These records are the proof that the qualified CLI
implementation actually used the configured model under the selected RAES
apparatus.

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
