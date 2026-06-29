# Paper Scenario Realization

APTL includes `paper-agent-loop`, a catalog scenario based on the ACES paper
reference scenario from Brad-Edwards/aces#598. It is the first dynamic
realization path for ADR-046: the ACES plan is interpreted into typed node,
network, participant, and evaluator intent, then handed to `DeploymentBackend`
for backend side effects.

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
The participant action binding for `participant.behavior.paper-agent` executes
the compiled `participant.action-contract.probe-customer-portal-login` contract:
it checks the portal login endpoint from Kali and records negative boundary
markers for direct database and Wazuh API reachability. Those markers are
participant-runtime evidence for the boundary; Wazuh evidence remains
evaluator-only and is registered as pending evaluator/runtime state rather than
participant-visible task context or a detection-quality claim.

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
