# ADR-057: Agent Execution Compartments

## Status

proposed

## Date

2026-09-05

## Context

The workbench minimizes child environments and disables provider tools for
bounded decisions. MCP-driven sessions can execute commands on range nodes.
Neither an empty tool list nor a private working directory confines an
installed executable running as the operator. The local process runner also
has confirmed deadline and descendant-cleanup gaps.

[The sandboxing assessment](../reviews/962-lilrae-readiness/agent-sandboxing.md)
compares current mechanisms and candidate OS/container/VM boundaries. It also
separates host integrity from RAES participant control.

## Proposed decision

Use explicit execution profiles with independently tested guarantees:

| Profile | Execution and admission |
| --- | --- |
| Deterministic bounded action | No external model credential; selected action runs through the admitted RAES path |
| Managed decision provider | Structured decisions; no action tools; external process/FS/network/resource confinement before making a sandbox claim |
| Managed tool participant | Explicit MCP/tool inventory, narrow backend broker, per-consumer credentials and enforced local compartment |
| Unmanaged external client | Operator controls the client; LilRAE claims only the broker/range boundary it actually enforces |
| Sealed participant seat | Optional VM delivery qualified for the exact guest, host and device/network configuration |

LilRAE owns out-of-world host/process/provider/credential security. RAES owns
portable participant-control profiles, crossings, effects and conformance.
An intentional in-world influence may be delivered under a permissive profile.
A host escape or evaluator-store compromise invalidates the realization; it
is not fabricated as an in-world participant event.

Select mechanisms through LilRAE #6. Use established OS/process and container
facilities before inventing a sandbox. Capability restriction and explicit
broker authority form the initial useful control surface. Dynamic information
flow control, shielding and other semantic controls remain candidates under
RAES #1068 and LilRAE #21/#22; they do not replace OS containment.

The external compartment must cover the provider process, MCP subprocesses,
descendants and their outbound connections. Provider-internal shell sandboxing
is defense in depth, not containment of the provider itself. Tool annotations,
prompt instructions and command regular expressions cannot authorize arbitrary
shell execution safely. Where a shell is required by the scenario, isolate its
execution boundary and disclose its authority.

Do not expose daemon sockets, host homes, evaluator stores, model credentials
or unrestricted network paths to range participants. Use narrow per-consumer
brokers, with finite calls, input/output, wall time, process, memory and storage
limits. Separate installation/update access from episode execution. Missing
required confinement fails before launch without an unsandboxed fallback.

Provider CLI versions and enabled features are qualification inputs. Probe
actual tools and forbidden paths; flags alone are not evidence. Credential
cleanup means ending possession in owned state, unless an upstream revocation
mechanism is actually implemented and tested.

## Existing ADR disposition

Clarify ADR-003, ADR-004, ADR-029, ADR-032, ADR-033, ADR-041, ADR-042,
ADR-049 and proposed ADR-052. Preserve capture authenticity and the stronger
seat boundary; neither establishes confidentiality against the host operator.

## Verification and delivery

[#963](https://github.com/Brad-Edwards/aptl/issues/963) fixes process supervision;
[#856](https://github.com/Brad-Edwards/aptl/issues/856) owns configured participant
credentials; [#491](https://github.com/Brad-Edwards/aptl/issues/491) owns local
isolation profile selection/qualification. #455 and #456 must consume the
portable and broker authority decisions instead of creating parallel semantics.

Required tests use synthetic files, credentials and endpoints: forbidden reads
and writes, Unix sockets, private and external destinations, descendant escape,
output/input exhaustion, cancellation, missing sandbox support, reset and
provider-version drift. Optional gVisor/Kata/microVM trials must include the
scenario's actual raw networking, service-manager, capture and filesystem needs.
