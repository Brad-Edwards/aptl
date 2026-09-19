# Issue #956 SDL Runtime Authority Materialization Preflight

APTL must faithfully realize the runtime state authored in valid SDL. RAES owns
the meaning of that state; APTL selects a deployment backend, lowers supported
values without narrowing them, and verifies the effective native state.

This boundary is deliberately different from appliance isolation:

- `aptl lab start` runs the scenario on the selected deployment backend. With
  the default local Docker backend, authored privilege can confer authority over
  the operator host. That is intentional behavior, not a containment claim.
- `aptl seat start` is the secure path. Its sealed appliance boundary owns host
  isolation, controller separation, egress policy, and recovery semantics.

The normal lab path must therefore never reject, strip, or substitute an SDL
value merely because it is dangerous on shared Docker. In particular,
`privileged`, capability additions, unconfined security profiles, devices,
host-like namespaces, host bind mounts, and declared Docker-socket authority
are valid materialization requests when the backend can express and observe
them.

## Admission and realization

The authoritative chain is:

`SDL -> RAES parse/semantics/compile/plan -> DeploymentRealizationSpec -> selected backend -> native readback`

The selected backend performs a read-only graph qualification before workspace
receipts, generated deployment files, image pulls/builds, volumes, networks, or
containers are created. Qualification answers only whether the backend can
faithfully lower and later observe the requested contract. It is not a safety
policy or a second SDL validator.

For the Compose backend, supported fields are lowered into the generated or
effective Compose model and compared with the admitted realization before
startup. Current supported dimensions include:

- entrypoint, command, logging, read-only root filesystem, shared-memory size,
  runtime and cgroup parent;
- privilege, capability add/drop, security options, seccomp, devices, device
  cgroup rules, and supported namespace modes;
- bind, named-volume, and tmpfs mounts, including supported propagation;
- DNS, search/options, extra hosts, supplemental groups, and standard init; and
- declared Docker orchestration authority and its exact read-write socket bind.

Unsupported materialization still fails before mutation. Examples include
container fields with no faithful Compose lowering, custom-init contracts,
capability dimensions that cannot be represented, or image-free substrate
features the generic materializer does not implement. Diagnostics identify the
compiled node, portable field, backend profile, and concrete limitation.

## Fidelity and readback

APTL does not infer authored intent from image names, product names, Compose
profiles, or local policy. It does not intersect SDL with an operator allowlist.
Exact authored values remain exact; omitted or open values follow RAES
realization authority and existing backend-choice rules.

Effective-model validation detects dropped, substituted, or undeclared runtime
state before startup. After startup, independent Docker/guest observation
corroborates supported container fields, capabilities, namespaces, devices,
mounts, identities, filesystem state, and orchestration authority. Planned
values are not accepted as observation evidence.

The normal lab path may still enforce integrity rules that preserve the
admitted contract: a Docker socket appears only on the declared authority
holder, endpoint overrides do not redirect it, image identities and child
correlation remain exact, and cleanup stays scoped to resources APTL owns.
Those checks prevent accidental drift; they do not turn local Docker into a
secure containment boundary.

## Product and adapter boundaries

Core APTL code is product-neutral. TechVault-specific runtime parameters,
participant smoke behavior, and pack conventions enter through the installed
adapter seam. Core materialization code consumes RAES and deployment models and
must not import `aptl_techvault` or branch on TechVault node/service names.

Tests use a small product-neutral SDL fixture to exercise the materialization
envelope. Release validation also requires the official TechVault scenario to
pass as a user would experience it from an installed wheel: initialize a fresh
lab, run plain `aptl lab start`, inspect native state, and stop the APTL-owned
lab. A successful unit test cannot substitute for that outcome. The full suite
remains a CI/CD responsibility; local iteration uses targeted tests.

## Non-goals

- This issue does not make `aptl lab start` safe for untrusted SDL.
- It does not move seat/appliance containment into the normal lab backend.
- It does not add a runtime-authority policy file, per-field allowlist, product
  exception, or parallel runtime schema.
- It does not authorize broad cleanup or mutation of non-APTL Docker resources.
- It does not claim support for a field the selected backend cannot faithfully
  lower and independently observe.
