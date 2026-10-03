# Issue #1194: Seat Network Investigation

This records the investigation and network fix for
[issue #1194](https://github.com/Brad-Edwards/aptl/issues/1194). The historical
omitted reconciliation call reproduces the reported symptom. The current
retained seat already contains #1170. Remaining defects were accepting network
command success without endpoint readback and recommending removal of Docker's
built-in bridge during subnet conflicts. The original incident's exact image
and manual correction remain unknown.

The occupied heron1 and heron2 guests were not entered or modified. Host-side
observations were read-only. Experiments used a separate disposable overlay;
the matching immutable disk and neighboring checkout stayed unchanged.

## Current Delivery Identity

The retained seat-state records for both users identify generation 3 and the
same immutable image. Running QEMU disk arguments identify each user's
`instances/seat-01.qcow2` overlay under their private seat directory.

| Identity | Value |
| --- | --- |
| OCI manifest | `sha256:caf5a22669824672f5214f80fe86e6c6544d09a8a4771e399eb325d20352ee4f` |
| Guest disk | `sha256:d8f6751b9cc2a4167bacba0e37ea7da47b48819bcfb5373bf302b1e080234b5f` |
| Config, in matching build record | `sha256:0bb399740d48718cc5d86dcbc8f0eb0c17b59dda8d0a8e9c945ebaadc07677cc` |
| Source, in matching clean build record | `4203871dedbb74dfea5f2f34ea67bc8728f2a82b` |
| Source commit time | `2026-10-01T05:54:11+02:00` |
| Staged application wheel | `aptl_labs-6.0.0-py3-none-any.whl` |
| Staged wheel SHA-256 | `35f8bd32277bc0cf6ae2893dec2e2258af151a97b98ec24e8eb78208bf229fd7` |
| Staged release marker | `APTL_SEAT_COMMIT=4203871dedbb` |

The matching local build record and payload are retained in the neighboring
APTL checkout at
`build/seat-1178-release-4203871d/{out,input/payload}`. Its publication log
records the same OCI manifest and disk identities. The immutable inputs were
inspected read-only. The build record
declares `dirty_source: false`. The disk itself was not rehashed during this
inspection. Read-only extraction of its baked release marker confirmed
`APTL_SEAT_COMMIT=4203871dedbb`. No occupied overlay was mounted. The disposable
experiment used a minimal Debian image copied from the matching staged archive,
without pulling a replacement image.

The source commit descends from #1170's merge commit
`f3b9b3c5dc7e851b172084b97c8d922d9a263325`. Inspection of the actual staged
application wheel confirms that `_realize_without_compose()` calls
`reconcile_image_free_networks(self, realization)`.

This establishes the **current retained selection and matching build inputs**.
It does not establish the image or software used when the participant reported
v5.5.0, prove that the running guest still uses the baked entrypoint, or account
for changes within its overlay. The older #1162 acceptance image is a different
identity and must not be substituted as heron1's baseline.

## Historical Software And Provisioning

At the v5.5.0 tag, `_realize_without_compose()` returns after materialization
without post-materialization network reconciliation. #1170 adds the call and
propagates its failures. That is an established historical software defect,
not yet a proven explanation of this particular incident.

Provisioning at the matching generation-3 source enables `docker.service`,
adds the desktop account to the Docker group, and installs a fixed launcher
using `/opt/aptl/app` and `/opt/aptl/python`. This describes the baked rootful
guest service; it does not observe the incident's effective daemon or context.
The host's rootless QEMU namespace is a separate boundary. The report's
rootless-Docker description remains unverified.

## Separate Scenario Planning Observations

The current checkout's real RAES parser, runtime planner, provisioning
interpreter, and deployment-spec conversion were exercised without realizing
containers. Pack acquisition used a temporary directory inside this checkout;
the default pack's parameters came from the existing exact-pack runtime
parameter provider. None of the five selections produced realization errors.

| Selection | Source | Nodes | Compose images | Startup route |
| --- | --- | --- | --- | --- |
| Default `techvault` | Acquired env-pack | 25 | 15 | `_needs_compose()` is true; mixed realization |
| Explicit `bounded-participant-agency-techvault` | Project-tree SDL | 6 | 0 | Fully image-free |
| Explicit `techvault-attacker-target` | Project-tree SDL | 4 | 0 | Compose; no generic runtime declarations |
| Explicit `techvault-defensive-min` | Project-tree SDL | 3 | 0 | Compose; no generic runtime declarations |
| Explicit `techvault-enterprise-web` | Project-tree SDL | 6 | 0 | Compose; no generic runtime declarations |

Both specs retain `dmz-net`, `internal-net`, `redteam-net`, and `security-net`.
The bounded spec retains these declared node attachments and static addresses:

| Node | Attachments |
| --- | --- |
| `webapp` | `dmz-net=172.20.1.20`, `internal-net=172.20.2.25` |
| `db` | `internal-net=172.20.2.11` |
| `workstation` | `internal-net=172.20.2.40` |
| `kali` | `redteam-net=172.20.4.30`, `dmz-net=172.20.1.30`, `internal-net=172.20.2.35` |
| `defender-console` | `security-net=172.20.0.10`, `dmz-net=172.20.1.10`, `internal-net=172.20.2.30` |
| `event-store` | `security-net=172.20.0.12` |

These planning observations are separate from the guest experiment below.
The five selections have real-parser/planner/lowering regressions: each must
reject successful connect commands whose containers remain on the default
bridge. Zero explicit images does not itself select the generic materializer;
the node's runtime declaration also matters.

## Controlled Disposable Guest Experiment

A qcow2 overlay used the matching retained generation-3 disk as a read-only
backing file. The guest had two CPUs, 4 GiB RAM, no forwarded ports, restricted
QEMU user networking, and normal lab first boot disabled. Six minimal Debian
keepalive containers used the bounded SDL's real lowered node names, network
policy, links and static addresses. Backend ownership, network creation,
container creation, reconciliation and inspection operated on real Docker.

The baked guest reported Docker **29.1.3**, cgroup v2, AppArmor, built-in seccomp
and private cgroup namespaces. The default bridge was `172.17.0.0/16`. The
backend and desktop `aptl` account reached the same daemon identity. This
confirms the pristine generation-3 environment, not the historical participant
shell or overlay. No rootless guest daemon was observed.

| Controlled case | Result | Observed topology |
| --- | --- | --- |
| Baked backend, historical reconciliation call suppressed | Success | All six nodes only on `bridge`, `172.17.0.2`–`172.17.0.7`, no aliases |
| Same backend and containers, #1170 call restored | Success | Every declared address above, required aliases present, no default bridge |
| Current network methods on the same guest | Success | Every declared address and alias required by fresh endpoint readback |

`getent hosts webapp` from the realized `kali` container succeeded after #1170's
reconciliation. This demonstrates Docker DNS resolution on a declared shared
network. It does not establish service or participant-workflow readiness.

The current-method pass loads the changed network mixins and helpers into the
baked process and delegates its image-free wrapper to the shared result method.
This validates the edited mechanics on that daemon, not a newly baked wheel or
published seat. Experimental containers/networks were removed by receipt-owned
native identity before the disposable guest powered off.

The experiment replaces package/service materialization with generic keepalive
creation. Suppressing only the reconciliation call isolates the historical
control-flow defect with the baked backend, daemon and topology held constant.
It does not replay a complete v5.5.0 installation or recover the original manual
command. The owner instructed this run to proceed with available evidence
because nobody knows the missing incident details.

## Default Docker Network Correction

A separate synthetic declaration, `172.17.10.0/24`, overlapped the observed
bridge and was refused before network creation. The baked diagnostic wrongly
recommended `docker network rm bridge`. The updated diagnostic identifies the
built-in bridge and offers non-overlapping scenario subnets or an
operator-planned daemon `bip` change and restart.

Daemon-wide bridge settings are distinct from container attachments. Docker
explains the configuration and restart requirements in its
[bridge driver reference](https://docs.docker.com/engine/network/drivers/bridge/).
APTL performs no automatic bridge rewrite, subnet substitution, context switch
or daemon restart.

The pristine `172.17.0.0/16` bridge does **not** overlap TechVault's `172.20.*`
subnets. A changed daemon bridge is a plausible explanation for the reported
manual correction, but was not reproduced on the retained clean image and is
not established as the original cause. Daemon/context selection remains a
separate hypothesis without historical evidence.

## Shared Startup Mechanics And Remaining Fix

All normal CLI starts require RAES SDL admission. A RAES boundary receipt means
ACL enforcement; an SDL without ACL rules can have no such receipt. The
lower-level `core.lab.start_lab()` compatibility helper still calls
`backend.start()` without admission. No production callers were found; the
owner requested handling that admission gap separately from #1194.

Generic and Compose nodes require different creation methods, but both now
finish through `_reconcile_declared_networks()`. The image-free-only wrapper
is removed. Fresh readback requires each declared endpoint, exact authored
static IPv4 address (or a nonempty allocated IPv4 for unpinned attachments) and
required DNS alias. Explicit attachments remain
authoritative even with empty legacy network-name tuples. Empty static
addresses trigger repair. Failed commands or failed readback prevent readiness
and preserve bootstrap-bridge connectivity. #1170's published-port bridge
exception remains intact.

Successful disconnect commands also require readback: extra project endpoints
must be absent, and a removed default bridge must actually be gone. Other
workspaces' networks remain outside cleanup authority.

Online generic materialization can install missing packages before applying
final internal-network topology. Moving all pre-create binding ahead of those
installs would break cold starts; that attempted change was removed. Existing
ACL/appliance pre-start isolation stays in force. Fully image-free and mixed
scenarios share that materializer and the final network check; there is no
participant-name branch.

The remaining fix strengthens realization evidence and built-in bridge refusal,
rather than duplicating #1170. A seat with pre-#1170 code needs an immutable
image containing that fix. Generation 3 already contains it. Receiving this
additional improvement requires publishing and selecting an image built from
the merged revision; a source change or package version string does not update
a selected seat automatically.

## Delivery Coverage And Validation

The known qualification gap is route coverage: seat smoke starts default
TechVault, whose mixed path already reconciled networks, without explicitly
starting the bounded fully image-free scenario. #1170's existing tests mock
materialization and reconciliation, so they prove call propagation without
observing actual endpoints. The installed-wheel boot assertion also lacked an
independent endpoint check. Those gaps permit this defect class. Original
incident-time qualification evidence is unavailable, so no specific historical
run is blamed.

The fix extends the existing installed-wheel boot/teardown CI job to observe
the owned `smoke-net` endpoint, allocated IPv4 address and `smoke-box` DNS alias.
Default-bridge-only state fails even if the published port works. The existing
image-free real-Docker integration test independently checks declared
endpoints. No second qualification controller or scenario-specific repair is
introduced.

Targeted TDD observed missing endpoint, wrong/empty static address, missing
alias, explicit-only attachment and invalid built-in bridge-removal guidance
fail before their fixes. Four boot-gate endpoint cases also failed before
enforcement. Tests cover both routes, real lowering of all five selections,
conflict diagnostics and existing published-port behavior. Full suites,
installed-wheel cold boot and long qualification stay in CI/CD.

The pre-push review identified an unpinned-address gap. Three missing/empty
allocated-IPv4 cases failed before the repair; a positive allocation case
confirms that no static address is invented. The shared check now rejects those
states while preserving the bootstrap bridge.

## Acceptance Mapping

- [x] Issue criterion 1: current delivery identity, baked revision and matching
  provisioning are recorded above; incident-time overlay changes remain unknown.
- [x] Issue criterion 2: the owner confirms the exact manual correction is
  unavailable; attachment, daemon selection and global bridge settings remain
  distinct throughout the experiment and diagnostics.
- [x] Issue criterion 3, as refined by the owner: the disposable overlay uses
  the matching retained disk and reproduces the omitted-call symptom, then
  verifies #1170 with the same containers and topology. Historical-replay and
  fixture-workload limitations are stated above.
- [x] Issue criterion 4: `tests/test_compose_network_readback.py` plans default
  TechVault and each bounded/curated selection independently.
- [x] Issue criterion 5: the controlled causal result, qualification gaps,
  remaining readback/diagnostic defects and immutable delivery correction are
  recorded above without asserting an unproven historical cause.
- [x] Issue criterion 6: `_compose_network_realization.py` and
  `_compose_realization_networks.py` enforce observed topology;
  `_compose_network_conflicts.py` gives actionable bridge refusal;
  `scripts/ci/assert_boot_realization.py` and the existing installed-wheel job
  independently require the declared endpoint. Focused and live-test coverage
  is in `tests/test_compose_network_readback.py`, `tests/test_boot_realization_gate.py`
  and `tests/test_imagefree_admission_integration.py`.
- [x] User clarification: `_compose_realization.py` and `_compose_post_start.py`
  call the same `_reconcile_declared_networks()` method, preserving canonical
  package-bootstrap and ACL ordering.
