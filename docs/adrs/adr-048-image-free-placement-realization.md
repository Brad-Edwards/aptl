# ADR-048: APTL Image-Free, Placement-Based Realization Envelope

## Status

accepted

## Date

2026-07-20

## Last Updated

2026-07-20

## Context

ADR-035 adopted ACES SDL and wired APTL in as a conformant ACES backend.
ADR-046 established dynamic realization: APTL compiles an authored ACES SDL into
a typed `RuntimeModel`, plans an `ExecutionPlan`, interprets it into
`AptlRealization` and `DeploymentRealizationSpec`, and applies it through the
deployment backend. ADR-046's Image Realization Addendum (issue #574) then
defined a node's realized identity as an image: a node `source` is either
pulled (a pullable image reference) or built (from captured `source.build`
provenance).

Issue #581 exposes why that image model is the wrong foundation for APTL's
realization envelope. The whole point of APTL being an ACES-conformant backend
is to demonstrate that an arbitrary conformant ACES SDL dynamically composes
into a meaningfully realistic range within a backend's realization envelope. A
pre-baked appliance image (for example `wazuh/wazuh-manager:4.x` or
`docker.elastic.co/...`) already contains the node's software, services,
content, accounts, and configuration. When a node is realized by pulling or
building such an image, the SDL is not driving the realization; the image is.
The range's meaningful detail lives outside the SDL, in a hand-curated image
specific to one scenario. That proves nothing about ACES's ability to compose
ranges. It re-encodes the previously hand-built Docker lab in ACES clothing.

ACES already models the surface needed to do this properly. A compiled
`ProvisioningPlan` carries not only nodes and networks but placements:
`feature-binding`, `content-placement`, and `account-placement`. A node's
`runtime` (`RuntimeConfiguration`) is a deep declarative desired-state contract:
`packages`, `software_components`, `filesystem_inventory`, `local_identity`,
`identity_authorities`, `service_manager_units`, and typed service families such
as `security_monitoring_managers` (Wazuh) and `network_detection_engines`
(Suricata). `Source` is backend-agnostic. So ACES can express an operating
system plus everything running on it; the backend, not an appliance image, is
responsible for materializing that state.

The ACES reference backend (`aces_reference_backend`, RUN-314) realizes plans
over an in-process or OCI driver. It is an emulation backend: its driver stands
up a container from an `image_ref` and records placements for provenance without
installing software. It proves the plan-interpretation and provenance shape, not
real materialization.

APTL is a single-user, local, Docker-based cyber range. That is a load-bearing
property, not an implementation detail. APTL and Shifter (full cloud VMs) are
the two distinct real conformant backends alongside the ACES libvirt reference;
backend diversity is the research value of ACES conformance. APTL must therefore
remain Docker-based and must not migrate to libvirt or VMs, since doing so would
collapse the set of distinct conformant backends.

## Decision

APTL realizes a node's meaningful state from the compiled ACES
`ProvisioningPlan` and `RuntimeConfiguration`, not from a pre-baked appliance
image. This supersedes ADR-046's Image Realization Addendum as APTL's
node-realization model.

1. **Placements and declared runtime state are the realization mechanism.** A
   node's software (`packages`, `software_components`, `feature-binding`), data
   and configuration (`content-placement`, `filesystem_inventory`), and
   identities (`account-placement`, `local_identity`) are realized by the
   backend applying the declared ACES desired state onto a node, at the
   granularity the current `docker-compose.yml` expresses or better. The SDL and
   its compiled plan are the sole authority for what a node contains.

2. **A generic base substrate is permitted; an appliance image is not.** A node
   still runs on some container base. A generic operating-system base image (the
   substrate a container needs to exist) is allowed. What is forbidden is an
   appliance image that encodes the node's scenario-meaningful software,
   services, content, accounts, or configuration outside the SDL. The test is:
   would this node realize into the same meaningful range if the image were
   replaced by a generic base of the same OS family? If not, the range detail is
   being smuggled in through the image and the realization is invalid.

3. **APTL stays Docker-based and local.** No migration to libvirt or VM targets.
   APTL's realization envelope is designed for its own affordances, a
   single-user local Docker range, not as a copy of the reference backend. This
   ADR sets the foundation for APTL's entire ACES realization envelope, optimized
   for security, maintainability, extensibility, and reliability, not for the
   minimum needed to boot one scenario.

4. **Expressivity gaps are surfaced upstream, never worked around.** When the
   ACES contract cannot express a fact a realistic node needs, the fix is an ACES
   issue against the contract (repo `Brad-Edwards/aces`), not an APTL-local
   schema, a scenario-name branch, an appliance image, or a silent backend
   injection. Where the ACES realization posture legitimately admits
   backend-supplied detail, that detail is authored as an open realization scope
   (`AuthorRealizationPosture.OPEN`), not smuggled in under a closed-world
   default. Surfacing expressivity gaps is an intended output of this work.

5. **`docker-compose.yml` is not an authoring or topology authority.** Any
   retained Compose file is derived reference output only. It is never a
   topology, recovery, packaging, validation, or parity input. Realization,
   lifecycle, and parity all key on the admitted execution identity and the typed
   realization, per ADR-046.

6. **Parity is bidirectional.** Static and live gates prove the realized range
   equals the admitted graph: both missing and unexpected runtime objects
   (containers, networks, volumes, mounts, ports, dependencies, placements) fail.
   A healthy subset is not parity.

The canonical authority chain remains ADR-046's: catalog/SDL, ACES
parse/compile/plan, `interpret_provisioning_plan`, `AptlRealization`,
`DeploymentRealizationSpec`, deployment backend, observation. This ADR changes
what a node's realized content comes from (declared desired state onto a base,
not an appliance image), not the pipeline that carries it.

### Generic materializer contract (the invariant)

APTL's provisioner is a scenario-agnostic materializer. It contains no
per-product, per-node, or per-scenario branch. There is no `wazuh`, `ad`, `misp`,
`shuffle`, or `techvault` special case anywhere. It realizes any conformant node
purely from that node's declared desired state, and this invariant is what proves
ACES can compose an arbitrary conformant SDL. If APTL needs a product-specific
code path to stand a node up, the design has failed the bar.

Concretely, for every node the materializer:

1. **Base substrate.** Starts a generic base-OS container image derived solely
   from the node's `os` and `os_version` through a small, fixed,
   scenario-independent base-image map. There is no per-node image and no
   appliance image.
2. **Software.** Installs the node's declared `runtime.packages` and
   `software_components` (package-manager provenance) via the declared package
   manager. Software identity comes from the SDL, not a baked image.
3. **Filesystem and config.** Places the declared `content` (file, directory, or
   dataset) and `runtime.filesystem_inventory` entries, using APTL's existing
   containment, symlink-rejection, and atomic-write discipline.
4. **Identity.** Creates the declared `runtime.local_identity` (users, groups,
   sudo) and realizes `accounts`, including domain-bound accounts through the
   existing directory provider.
5. **Services.** Installs, enables, and starts the declared `service_manager_units`
   and the units implied by the typed runtime service families, through one
   generic service-unit mechanism, never a product-named startup path.
6. **Runtime wiring.** Applies declared networks, mounts, published ports,
   environment (reference names and classification only), Linux capabilities, and
   container settings.
7. **Verify.** Observes the realized node and asserts it satisfies the declared
   runtime desired-state contract by read-after-write. A fact APTL cannot
   observe and verify is not claimed as realized.

APTL's backend manifest is expanded to honestly declare exactly the realization
kinds the materializer both materializes and verifies (`packages`,
`software_components`, service units and families, `filesystem_inventory`,
`local_identity`), drawn from ACES's published controlled vocabularies. A
declared node fact that APTL cannot express, materialize, and verify generically
is either an ACES contract gap (file an ACES issue) or a blocking admission
diagnostic, never a product-specific workaround and never a silent drop.
Capability-specific knowledge (which packages, which config, which service units
make a working Wazuh) lives entirely in the SDL.

## Consequences

### Positive

- APTL becomes a genuine demonstration that arbitrary conformant ACES SDLs
  realize into meaningful ranges, the actual research claim, rather than a
  re-skin of a hand-built Compose lab.
- The realization envelope generalizes beyond TechVault: any node describable by
  ACES features, content, and accounts realizes without a bespoke image.
- Expressivity gaps in ACES are surfaced as concrete upstream issues, improving
  the contract for every conformant backend.

### Negative / costs

- Substantially more realization work than pulling images: features, content,
  and accounts must be provisioned onto a base substrate. TechVault is large; a
  full local range may need 20GB+ of memory. This is accepted.
- The TechVault SDL must declare node features, content, and accounts at
  docker-compose granularity or better. Nodes that previously leaned on an
  appliance image must express that capability declaratively.
- This is a large change delivered as one branch, many commits, one PR.
- The image-based node realization from ADR-046's Image Realization Addendum and
  its supporting code is superseded and removed from the operational path.

### Risks

- Some node capabilities may exceed the current ACES expressivity, or exceed what
  a single generic base-OS container can host. Mitigation: file ACES contract
  issues and, where legitimate, author open realization scopes; never fall back
  to an appliance image. A node that cannot yet be realized image-free fails
  admission loudly rather than silently regressing to an image.

## Supersession

This ADR supersedes ADR-046's Image Realization Addendum (issue #574): a node's
realized software, content, accounts, and configuration is no longer sourced
from a pulled or built appliance image. ADR-046 otherwise remains authoritative
for the dynamic realization pipeline, network realization, generated-model and
lifecycle contract, and parity model. ADR-046's addendum is annotated to point
here.
