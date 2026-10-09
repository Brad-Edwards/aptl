# Issue #1186: Desktop Seat Privilege Preflight

The supplied [issue #1186](https://github.com/Brad-Edwards/aptl/issues/1186)
is the delivery contract; no formal requirement is attached.
Inspection used repository commit `980f4076`. This guidance defines boundaries
and acceptance risks, not an implementation plan or qualification evidence.
Keep [ADR-060](../adrs/adr-060-vm-only-seat-containment.md)'s VM boundary,
[ADR-061](../adrs/adr-061-gateless-vm-seat-access.md)'s desktop delivery, and
[ADR-029](../adrs/adr-029-control-plane-secret-handling.md)'s secret rules.

## Privilege And Identity Boundaries

The operator chooses `administrative` or `event` when creating the seat's
launch contract. A missing selection, cancelled prompt, EOF, or absent password
input is not an explicit empty password. Automation must express the mode and
password choice separately; acquisition's `--yes` does not select privileges.
Once loaded, omission means reuse the stored selection. A conflicting selection
fails before mutation and directs the operator to explicit reset/reload.

| Selection | Guest `aptl` contract |
| --- | --- |
| Administrative, nonempty password | The chosen Unix account password authenticates sudo; the managed rule requires authentication. |
| Administrative, explicitly empty password | A managed `NOPASSWD:ALL` rule; retain a nonempty generated xrdp password, rather than an empty Unix login password. |
| Event | No effective sudo authorization, no Docker group membership, and no access to the rootful guest Docker socket through modes, ACLs, or another transport. |

Keep direct Docker membership out of both new modes: administrative users can
invoke Docker through sudo. Otherwise a password-bearing mode still supplies a
password-free route to guest root. Do not change host account groups or sudoers.
Check effective authorization, including primary/supplementary groups and all
sudoers includes; deleting `90-aptl-desktop` alone is insufficient. Use a single
root-owned managed sudoers file, mode `0440`, validated with `visudo` before
publication. A password-required rule must remain effective despite inherited
sudo defaults or other grants; test cold authentication with the sudo timestamp
cache cleared. Scope account changes to `aptl`, preserving unrelated accounts.

The immutable baseline has a locked `aptl` account, no sudo authorization and
no Docker membership. Only an admitted overlay applies the operator's choice.
The image includes code and declares support for the privilege contract, never
an operator-selected mode, chosen password, or reusable password hash.

There is one Unix password for `aptl`, shared by normal sudo/PAM and xrdp.
`appliance/guest/seat-desktop.py:prepare()` currently overwrites it with the
generated RDP password on every boot. For password-bearing administration,
xrdp and its Guacamole connection must use the chosen account password and
remain synchronized across restarts. Keep the database credential independent.
Do not add a second PAM stack, privileged helper, or separate sudo password
store to work around this identity boundary.

`connection_sql()` currently accepts only generated hex and interpolates it.
That is not safe for arbitrary operator passwords. Preserve passwords exactly;
use safe PostgreSQL value binding/escaping for connection storage, and send
account updates through `chpasswd` stdin. Bound input and reject unsupported
line framing, NUL and encoding cases before staging, without echoing the value.
Do not silently trim, shell-expand, truncate, or restrict passwords to hex.

## Launch Lifetime And Compatibility

Reuse `seat/launch_descriptor.py`'s immutable, digest-bound launch projection
as the authority for the non-secret mode and authentication choice. Extend its
closed model with one shared typed selection, not an independent privilege
JSON/config tree. `SeatRecord` remains lifecycle metadata; any mode projection
must derive from the descriptor and cannot become another policy authority.

The current `generation` is also an access-revocation counter:
`lifecycle.stop_seat()` advances it while keeping the overlay, `instance_id`,
and launch descriptor. Bind the privilege selection to the loaded overlay's
instance and immutable descriptor, preserve it when access generations advance,
and bind each readiness result to the current challenge. Do not rotate the
password or reinterpret mode on stop/start, guest reboot, host reconciliation,
or an already-running start. Only explicit reset/reload may change the launch
selection. Do not change access-revocation semantics to make this binding easy.

Use `StartSeatOptions` and the existing stage/start/reset/recover/update owners.
Account for `with_mappings()`'s manual option copy, automatic allocation's
recursive start, fresh `SeatRecord` constructors on success/failure, and
`model_copy(update=...)`, which does not perform fresh Pydantic validation.
No entry path may drop the selection or infer privilege from default options.
Reset and update destroy password-bearing overlay state: require fresh secret
input before destructive work when the chosen mode needs it, or leave an
explicitly staged, unready seat awaiting that input. Never substitute empty
input or replay a forgotten secret from normal host metadata.

Version the changed launch contract and declare its support in the signed
`SeatImageConfig`, generated by `write-seat-image-config.py`. Its parser is
strict: adding an unknown field at only the writer or consumer fails elsewhere.
Retain deliberate legacy parsing with legacy behavior. Missing capability in
an old image must never be interpreted as event mode or as enforcement of a
new password choice. Refuse new privilege options for unsupported images.
Sticky image selection, retained image/config/trust bytes and existing live
overlays remain unchanged until explicit operator update/reset. A new bake and
signature are required; changing the CLI alone cannot deliver this contract.

## Required Cross-Cutting Passage Points

Paths are repository-relative. These incumbents own the corresponding gates;
their existence does not imply their present implementations suffice unchanged.

| Layer and canonical incumbents | Required passage |
| --- | --- |
| Operator input: `src/aptl/cli/seat.py`, `seat/context.py` | Prompts stay at the CLI boundary and on stderr; stdout remains bounded JSON. Use hidden terminal input or a deliberately selected private file/FD for automation. No password-valued command option or ambient environment fallback. Cancellation changes nothing. Secret-bearing option objects must not expose secrets through their repr or dump. |
| Config: `src/aptl/core/config.py` (`AptlConfig`), `cli/_common.py`, `core/env.py` | Durable config is non-secret and strict under ADR-025. If a non-secret default is needed, extend the canonical model with a consumer; explicit launch selection wins and loaded selection remains sticky. Passwords/hashes never enter `aptl.json`, checked-in env, or the lab's runtime `.env`. Provider `ProcessEnvironmentCredentialSource` is a provider-sign-in contract, not a guest account credential store. |
| Parse and binding: `seat/launch_descriptor.py`, `seat/image_config.py`, `utils/strict_json.py`, `seat/models.py` | Closed, bounded, versioned shapes; reject duplicates, unknown fields and invalid mode/password combinations. Use canonical launch bytes and descriptor-digest binding. Share selection validation between host and guest; do not introduce parallel enums/parsers or store password-derived digests in public metadata. |
| Persistence and ownership: `seat/locking.py`, `seat/persistence.py`, `seat/paths.py`, `seat/access.py`, `utils/pathsafe.py`, `seat/overlay_cleanup.py` | Serialize selection, staging, retries and cleanup with the existing mutation locks. Build new private staging I/O on shared `pathsafe` descriptor-relative create/read/remove helpers and existing owner/mode checks; a resolve-then-open check or leaf-only no-follow does not protect parent races. Treat a pending secret as private staging material, never a `SeatRecord` field. Clean owned staging copies after confirmed application and on cancellation/reset; interrupted application must retry the same selection or fail closed. Publish an application receipt only after account and sudoers checks succeed. |
| Host/guest and OS exposure: `seat/vm.py`, `seat/exposure.py`, `appliance/guest/aptl-launch.mount`, `aptl-appliance-first-boot.service` | Reuse the private VM launch transport without adding a writable host share or host Docker access. For any secret file on the read-only 9p mount, prove guest-root-only readability: `security_model=none` exposes host UID/mode semantics, and host owner `0600` can admit guest `aptl` when UIDs match. Enforce root-only guest traversal or an equivalently private existing transport. QEMU argv, fw_cfg, systemd Environment/ExecStart, shell tracing, process environment, serial output and guest journals must contain no chosen password/hash. The guest cannot unlink a read-only host staging file; host cleanup owns that operation. |
| Guest application and authorization: `appliance/guest/seat-desktop.py`, `aptl-appliance-first-boot`, `provision-offline.sh`, `scan-golden.sh` | Verify the launch descriptor and private input before privileged account mutation. Currently desktop startup precedes descriptor verification in `guest_services`/lab startup; close that ordering gap. Validate sudoers and effective groups/socket permissions before starting the participant desktop or emitting readiness. Baked `xrdp.service` is enabled independently, so service ordering must prevent a login before policy application. Preserve the first-boot service's root identity, private umask and sandbox; validate `/etc` writes and ownership under its actual systemd restrictions. |
| Desktop/MCP env and filesystem shapes: `appliance/guest/desktop-handoff.py`, `desktop-mcp-smoke.py`, `src/aptl/core/lab.py`, `workbench/profiles.py`, `mcp/aptl-mcp-common/src/config.ts` | Preserve `mcpServers` command/args/string-env shape, contained built artifacts, admitted run/state bindings, `.env` placeholder loading and narrow home/run/lifecycle handoff. Do not inject sudo credentials into MCP env or broaden project ownership/socket permissions to repair event access. Keep root lab startup and guest-local SSH/API MCP transports working as the actual unprivileged desktop identity, including fresh supplementary groups. |
| Image trust and runtime admission: `seat/image_trust.py`, `retained_image.py`, `image_selection.py`, `readiness.py`, `src/aptl/core/appliance_boundary*.py` | Preserve Cosign/config/disk digest checks, capacity/mapping validation, private namespace, real forbidden-reachability checks and instance/nonce/descriptor-bound readiness. Successful current privilege verification must precede readiness; a PID, open gateway, or saved application marker is insufficient. Report only non-secret mode/check outcomes through existing projections. |
| Errors, logs and artifacts: `seat/errors.py` (`SeatLauncherError`), `SeatLaunchError`, `cli/seat.py:_fail/_emit`, `utils/redaction.py`, `core/telemetry.py`, `core/runstore.py`, common MCP redaction/telemetry | Reuse bounded error codes and shared redaction where serialization is needed. Do not print Pydantic input errors, subprocess stderr, chained tracebacks, stdin, SQL, credentials JSON, or option dumps containing chosen secrets. The Python logging setup does not automatically redact arbitrary messages; prevention and shared boundary redaction remain necessary. No new exception hierarchy, secret taxonomy, log pipeline, or credential-bearing status DTO. |

Plaintext or shadow hashes needed by the running guest remain in its private
overlay only; the selected account password also becomes a Guacamole connection
secret. Keep that database, seed SQL and credential state inaccessible to event
`aptl`, absent from golden bytes, and out of run evidence, exports and logs.
Do not rely on a redactor recognizing an arbitrary naked password. Owner-only
files and Pydantic secret reprs do not make unrestricted serialization safe.

Related incumbents confirm the boundaries without becoming new seat owners:
`tools/workshop/hosted_seat.py` already uses `pathsafe` for create-once private
credentials and a separate non-secret summary, while `core/credentials.py`
owns safe generated service configuration. Reuse those security patterns.
`scripts/setup-rdp.sh` and `scripts/provision-range.sh` configure Ubuntu/RDP
in the older hosted range. The latter logs its generated passphrase and passes
it through SQL/process arguments; those existing exposures are findings, not
safe patterns to copy. They are outside this preflight's authorized edits.
Do not transplant the hosted range's ambient credential fallback, destructive
cleanup, or cloud/host account workflow into disposable VM seats.

## Recovery, Qualification And Scope

Prove a separate operator-controlled root or Ubuntu administrative path. The
golden scan requires all shadow passwords locked, and QEMU uses `-serial none`;
an account name or reset command alone is not evidence of usable administration.
Select and document a concrete recovery route using the existing guest/VM or
stopped-overlay maintenance tooling. Any needed credentials are provisioned
privately at load time, separately from `aptl`, with no shared baked password
and no new participant-facing publication. Preserve root lab startup in both
modes. Recovery must not depend on the event account regaining Docker or sudo.

Use the existing `build-seat-image.sh` / `provision-offline.sh` /
`scan-golden.sh` baseline gate and `qualify-seat-image.sh` /
`seat-qualification-smoke.sh` qualification owner. The current qualification
disables first-boot and runs root-only lab checks: it cannot attest launch-mode
application or unprivileged desktop behavior. Extend evidence through the
actual launcher, systemd startup and Guacamole/xrdp path for both modes and
both administrative password choices. Preserve offline closure, clean-source
`seat-build-record.py`, Cosign publication and fresh anonymous boot evidence.
Image cuts remain independent of package release workflows.

Targeted tests extend the existing CLI, lifecycle, persistence, launch-descriptor,
image-config/build/trust and desktop suites in `tests/`. Required evidence covers
missing versus explicitly empty input; correct/incorrect password and cold sudo
authentication; effective sudo/groups/socket permissions; real event MCP and
lab startup; independent recovery; canary non-leakage across argv, env, JSON,
exceptions, logs and image bytes; unsafe files and malformed shapes; restart,
reconciliation, concurrent/partial application, reset/update and legacy images.
Use `bash tools/run-targeted-tests.sh` with relevant paths and staged-file
`pre-commit run`; full suites, clean lab lifecycle and strict docs builds belong
to CI/CD under `.ground-control.yaml` and `.gc/plan-rules.md`. Unit assertions
about script text or mocked root commands cannot replace real-VM permission
and password evidence.

Remove this PR's host relay source `scripts/appliance/seat-tailnet-relay.py`,
unit `scripts/appliance/aptl-seat-tailnet@.service`, associated
`tests/test_seat_tailnet_relay.py`, and the hosted-desktop relay section in
`docs/reference/appliance-seat-launcher.md` during implementation. This is
repository scope cleanup, not authorization to stop services, alter Tailscale
Serve/ACLs, remove installed host files, or modify running seats. Unrelated web
proxy/Tailscale references are outside this cleanup. Update the launcher
reference's unconditional sudo claim when behavior ships.

The extensibility seam is the typed non-secret launch selection plus its signed
image capability/version and private credential-input parameter at load time.
Keep supported mode validation centralized; a future credential source can feed
the same application boundary without changing baked scripts or creating a
second lifecycle. Do not build a generic privilege-policy service for two modes.

Non-goals are implementation in this preflight, host sudo/group changes, live
overlay migration, retroactive event enforcement on old signed images, a new
browser login or host MCP enrollment, provider-credential changes, scenario
credential cleanup, internal guest workload isolation (#1127), and egress
policy (#1182). Event account restrictions do not establish a new containment
claim for the deliberately vulnerable range.
