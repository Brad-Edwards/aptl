# Paper Scenario Realization

APTL includes `paper-agent-loop`, a catalog scenario based on the ACES paper
reference scenario from Brad-Edwards/aces#598. It is the first dynamic
realization path for ADR-046: the ACES plan is interpreted into typed node,
network, participant, and evaluator intent, then handed to `DeploymentBackend`
for backend side effects. The paper participant action is realized from a
compiled runtime binding: the `paper-agent-behavior` behavior specification
carries an `aptl-participant-runtime-binding/v1` payload on its
`x-aptl:participant-runtime-binding` governed extension, which APTL parses into
the container command, success markers, target evidence references, and
participant snapshot surfaces. The binding is backend-private topology data, so
it rides the behavior-spec extension seam rather than being planted as scenario
content on the participant container (issue #691).

Run it through the public path:

```bash
aptl lab start --scenario paper-agent-loop
```

The required container profiles are derived from the compiled ACES resources.
For the current Docker Compose backend, APTL starts the required service set and
then reconciles the realized containers onto the paper topology:

- `red-workbench` binds to `aptl-kali` on `redteam-net` and `dmz-net`.
- `customer-portal` binds to `aptl-webapp` on `dmz-net` and `internal-net`.
- `customer-db` binds to `aptl-db` on `internal-net`.
- `wazuh-manager` and `wazuh-indexer` bind to the Wazuh manager/indexer services
  on `security-net`, with the manager also on `internal-net`.

The participant workbench is not attached to `internal-net` or `security-net`.
The participant action binding for `participant.behavior.paper-agent` is parsed
from the compiled `paper-agent-behavior` behavior specification's
`x-aptl:participant-runtime-binding` extension. It executes the compiled
`participant.action-contract.probe-customer-portal-login` contract by resolving
service refs from the runtime plan and Compose backend mapping, then checks the
portal login endpoint from Kali and records negative boundary markers for
direct database and Wazuh API reachability. Those markers are evaluator-only
negative-boundary evidence: they are kept out of the observation boundary's
participant-visible projection (the internal DB and Wazuh endpoint identities
never appear in `observable_refs` / `disclosed_refs`). Wazuh evidence likewise
remains evaluator-only rather than participant-visible task context or a
detection-quality claim.

## Evidence surfaces

The paper scenario's non-content evidence surfaces follow ADR-046's Paper
Scenario Evidence Modeling Addendum:

- The **participant terminal observation** is owned by the `paper-agent-view`
  observation boundary and carried at runtime by the
  `participant-observation-envelope-v1` carrier; it is neither placed content
  nor an authored evidence requirement.
- **Wazuh corroboration** and **negative boundary checks** are authored ACES
  `evidence_requirements` (`wazuh-evidence`, `boundary-check-evidence`). These
  declare portable capture intent (source/scope/trigger/boundary, channel,
  sensitivity, redaction, integrity, retention, and loss-disclosure) and are
  not proof that capture occurred.
- The only remaining `content:` entry is the participant-visible task brief,
  which lowers to a typed content realization on the existing `kali_operations`
  named volume (`/home/kali/operations/scenario/task.md`).

The upstream paper SDL still carries OCR-style `metrics`, `evaluations`, `tlos`,
and `goals` as source content. APTL does not declare or realize that SDL scoring
chain after ACES ADR-073; planning records unsupported evaluator-section
diagnostics for those resources while retaining the condition/objective
evaluation surface that belongs to the runtime target.

The participant behavior, action-contract, observation-boundary, action-instance,
and shared-state snapshot entries are emitted from the runtime-selected
participant/action/boundary addresses. They must not reuse the legacy TechVault
SSH participant identifiers when the paper scenario supplies its own compiled
runtime binding.

## Upstream Provenance

The scenario is an APTL realization variant of the ACES #598 paper scenario,
pinned to the upstream `paper-agent-loop.sdl.yaml` content that introduced the
participant behavior/action/observation surfaces. APTL adds condition bindings
needed for local evaluator resources and omits the optional policy-gate
provenance surface because this repository does not yet ship a real
`participant-policy-gate` backend service. The realized concerns in this issue
are the red workbench, DMZ portal, internal database, Wazuh evaluator evidence
surface, participant action, and negative network boundary checks.

Related work:

- Brad-Edwards/aces#598: authored paper scenario.
- Brad-Edwards/aces#600: second backend proof for the paper scenario.
- Brad-Edwards/aptl#554: participant runtime implementation provenance.
