# Agent Sandboxing Assessment

Source review date: 2026-09-05. Candidate mechanisms below were researched, not
installed or benchmarked as part of this review. Recommendations are engineering
judgments for the reviewed product, not certifications from their authors.

## Current capability

| Boundary | What APTL currently implements | What remains unproven or absent |
| --- | --- | --- |
| Managed decisions | Minimal child environment, private provider homes, structured output, disabled action tools | Same-user installed executable still needs external filesystem/process/network confinement; #963 exposes supervision gaps |
| Managed MCP participant | Selected server inventory and provider tool restrictions; remote commands reach range nodes | MCPs themselves run with host process authority, including capture's Docker access; tool restrictions do not confine that process |
| Range workloads | Docker networks, published-port selection, component readback, some admission controls | Elevated init flags, unaudited privilege fields, default-path egress and management reachability defects |
| Evidence | Sidecar-owned capture and host archive/seal mechanisms | Protects against specified range-writer paths; it does not protect against an operator/host compromise or all capture admission failures |
| Optional sealed seat | Signed payload/launch and guest boundary/egress machinery | Exact release/platform/live qualification remains necessary; it is not the default host-Docker boundary |

The local installed Codex CLI reported 0.153.4. Its help supports the flags used
by the decision adapter, but a CLI flag and a private home do not prove the
provider process is externally confined. No provider or model request was run.

## Mechanism comparison

| Mechanism | Useful protection | Limits and fit for LilRAE |
| --- | --- | --- |
| Provider tool permissions | Restrict the model's available actions | Keep as defense in depth; not an OS boundary around provider or MCP code |
| OS process compartment | Restrict readable/writable files, sockets and network destinations with low startup overhead | First candidate for managed decision/MCP processes. Must fail closed on unsupported platforms and supervise descendants/resources |
| Hardened Docker / rootless Docker | Namespace/capability/seccomp controls; rootless reduces daemon/runtime privilege | Fits existing local driver. Shared-kernel limits remain; systemd, packet capture, privileged networking and platform behavior need qualification |
| gVisor | User-space kernel intercepts workload system calls, reducing host-kernel exposure | Promising for bounded agent/tool containers. Custom networking, tracing, service-manager and syscall compatibility can affect cyber-range fidelity |
| Kata Containers | Lightweight VM isolation behind a container runtime interface | Potential stronger profile, with hypervisor/runtime integration and compatibility costs; not an automatic Compose drop-in |
| Firecracker microVM | Small KVM VM boundary with constrained device model and jailer | Useful specialized Linux profile; guest image, networking, lifecycle, host configuration and nested-virtualization requirements add product work |
| Existing full VM seat | Contains the complete backend/range inside a disposable guest | Best reuse candidate for untrusted participant delivery; retain explicit supported-host, device, reset and recovery scope |

Docker's documentation treats daemon access as a powerful host authority and
explains capability and kernel isolation limits. Rootless mode runs daemon and
containers in a user namespace. This reduces one privilege boundary without
establishing VM-equivalent isolation or proving TechVault compatibility.
[Docker security](https://docs.docker.com/engine/security/),
[rootless mode](https://docs.docker.com/engine/security/rootless/),
[seccomp profiles](https://docs.docker.com/engine/security/seccomp/).

gVisor documents a separate application kernel, resource controls supplied by
the host, and specialized APIs it does not pass through. That supports a
bounded agent-container experiment; it does not support claiming all Kali,
systemd, raw-packet or capture behavior works unchanged.
[gVisor security model](https://gvisor.dev/docs/architecture_guide/security/),
[application compatibility](https://gvisor.dev/docs/user_guide/compatibility/).

Kata places containers inside lightweight VMs. Firecracker uses KVM and a
restricted device model; its jailer and production-host guidance are part of
the deployment story. Choosing either means owning the complete host/guest
integration and evidence, not merely adding a runtime name to configuration.
[Kata architecture](https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/README.md),
[Firecracker design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md),
[jailer](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md),
[host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md).

## Provider controls have narrower scope

Official OpenAI guidance says the local command sandbox and command network
proxy govern model-generated commands and their descendants. MCP connections,
model/authentication traffic, connectors, browser activity and other service
connections use separate controls. A read-only command sandbox therefore does
not confine the whole installed client or its MCP ecosystem. Use external
confinement for the guarantee LilRAE owns, and pin/probe provider behavior.
[OpenAI agent approvals and security](https://learn.chatgpt.com/docs/agent-approvals-security).

Claude Code documents its Bash sandbox using Seatbelt on macOS and Bubblewrap
on Linux/WSL2. Its documented scope is the Bash tool; required sandbox failure
and unsandboxed retry behavior need explicit configuration. The standalone
sandbox runtime is a candidate to assess for arbitrary managed subprocesses,
with its own limitations. Do not infer that `--tools ''` enables this boundary.
[Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing),
[sandbox runtime](https://github.com/anthropics/sandbox-runtime).

Landlock provides unprivileged Linux access restrictions with kernel/ABI
availability constraints. Treat it as one composable OS mechanism, not a
portable standalone solution for network policy, process supervision and
resource exhaustion.
[Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html).

## Recommended sequence

1. Fix process lifetime, credential grants, private writes, Docker authority and
   ordinary-local egress. Keep deterministic bounded actions as the tiny
   credential-free journey.
2. Under LilRAE #6 and APTL #491, qualify an external process compartment for
   managed decision providers and selected MCPs. Keep user-installed external
   clients explicitly unmanaged; claim the broker/range boundary only.
3. Assess rootless/hardened Docker and gVisor on one representative agent/tool
   workload. Measure cold/warm startup, memory, I/O, network and capture behavior.
   Select a stronger runtime only when the selected profile justifies the cost.
4. Reuse and qualify the VM seat for untrusted workshops/participants. Consider
   Kata or Firecracker only if measured requirements make that a better delivery
   mechanism. Do not migrate the default product to a VM requirement by assumption.

Required negative tests include synthetic host-file reads/writes; sockets and
daemon APIs; IPv4/IPv6, DNS, direct-IP and redirect egress; cloud-metadata and
host-gateway destinations; credential canaries; descendant/session escape;
output and disk exhaustion; missing sandbox support; cancellation; restart and
reset. A policy that cannot be installed must prevent launch. A domain allowlist
still needs a data-disclosure policy for what may be sent to an allowed provider.

## Participant control is a separate axis

[RAES #1068](https://github.com/OpenRAE/rae/issues/1068) owns portable
participant-control architecture. LilRAE #6 selects mechanisms; #21 implements
and #22 proves them. Capability restriction, monitors, approval/editing,
resource controls, shielding and dynamic information flow control can compose
only as the adopted contracts permit.

OS containment protects backend integrity outside the declared world. A
permissive in-world experiment can intentionally expose an agent to hostile
content. A strict control profile must prove zero prohibited delivery/effect at
the actual crossing. Neither model obedience nor a schema-only test proves
this. Conversely, an IFC mechanism does not prevent a container escape or
unauthorized host credential access. Report these as distinct claims.
