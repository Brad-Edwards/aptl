# Issue #824 Kiosk Launcher, Reset, And Recovery Preflight

This note sets the design guardrails for the host-side appliance seat launcher.
It is guidance, not an implementation plan. [ADR-049](../adrs/adr-049-sealed-disposable-lab-appliance.md),
[Issue #823](issue-823-versioned-disposable-appliance-preflight.md), and the
[appliance boundary contract](../components/appliance-boundary.md) already own
the signed payload, disposable overlay, guest boundary policy, and start-gate
verdict. Issue #824 owns the physical-host lifecycle adapter that consumes
those contracts without widening them.

No new ADR is needed. The unresolved risk is turning the launcher into a second
control plane that re-describes guest readiness, bypasses the signed boundary
contracts, or leaks recovery authority into the participant surface.

## Architecture Decisions And Guardrails

- The launcher is an outer seat-lifecycle adapter, not a new
  `DeploymentBackend`, RAES provider, profile selector, readiness engine,
  operator API, or host-resident APTL runtime. It verifies a sealed release,
  creates or selects one disposable overlay, starts or stops one VM, captures
  one authenticated host observation, and projects one coarse seat state.
- Use one seat state vocabulary distinct from inner lab lifecycle. The host
  state is about release admission and appliance availability
  (`empty`, `staged`, `starting`, `ready`, `needs-reset`, `recoverable-failure`,
  `tainted`); it must not reuse or reinterpret `StartupOutcome`,
  participant episode state, scenario objective state, or container health.
- Seat reset means power off plus overlay destruction plus fresh overlay
  creation from the selected verified golden. It is not `aptl lab stop -v`,
  `docker compose down -v`, `AptlParticipantRuntime.reset()`, a reboot, or
  an in-guest repair flow.
- Recovery is a separate authenticated instructor surface. The participant
  kiosk/browser gets only the participant endpoint; instructor operations
  inspect coarse health, stop, reset, replace, and explicitly taint a seat for
  break-glass replacement. Recovery is not a hidden participant route, shell,
  Docker proxy, log browser, or terminal backdoor.
- Host validation is prereq admission plus launch observation, not ad hoc bash
  checks spread across scripts. Hardware virtualization, usable RAM, free disk,
  supported hypervisor, release version, loopback publication inventory, and
  forbidden host reachability must pass through one closed validation surface
  before a seat is marked ready.
- Kiosk mode is presentation only. The browser/display wrapper may control full
  screen, restart-on-exit, and logout return-to-start behavior, but it must not
  own seat truth, readiness logic, release selection, or recovery authority.
- Surviving host reboot is a state-transition problem, not a persistence excuse.
  Persist only the selected verified release reference, overlay path, seat id,
  and bounded lifecycle metadata needed to reconcile the next boot. Do not
  persist guest credentials, raw logs, run evidence, or scenario service
  details on the host.

## Cross-Cutting Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| Signed payload and overlay contract | `src/aptl/appliance/{models,manifest,launch,build,bootstrap}.py`, `src/aptl/cli/appliance.py`, [Issue #823](issue-823-versioned-disposable-appliance-preflight.md), and [ADR-049](../adrs/adr-049-sealed-disposable-lab-appliance.md) already own release verification, launch descriptors, disposable overlays, and create-once bootstrap identity. The launcher must consume these; it must not define a second release manifest, overlay schema, or reset contract. |
| Host/guest boundary gate | `ApplianceBoundaryPolicy`, `ApplianceBoundaryBinding`, `HostBoundaryObservation`, `qualify_appliance_boundary()`, and `run_appliance_boundary_gate()` already own the signed host publication contract and fatal observed-vs-desired verdict. The launcher supplies the authenticated host observation and consumes the resulting bounded inventory; it must not replace this with bespoke "seat health" rules. |
| Inner startup diagnostics | `LabResult`, `StartupOutcome`, `StartupDiagnostic`, ADR-030, and the existing lab start flow own in-guest lifecycle and redacted diagnostics. Host UX may project a coarse summary from them, but must not fork their schema, invent new readiness classes for guest failures, or expose raw stderr/logs. |
| Host capability detection | `src/aptl/core/hostenv.py` and `src/aptl/core/sysreqs.py` already contain host OS and tool-probing patterns with bounded results and install hints. Extend that style for KVM/libvirt, disk, and memory checks instead of embedding one-off shell parsing into launcher scripts. |
| Logging and redaction | `src/aptl/utils/logging.py`, `src/aptl/utils/redaction.py`, ADR-029, and bounded CLI error patterns in `src/aptl/cli/appliance.py` remain the canonical observability surface. Recovery diagnostics may expose stable codes, release ids/digests, resource pressure, and operator actions only. |
| Strict config boundary | `AptlConfig`, `load_config()`, ADR-025, and the release/launch descriptor models remain authoritative for durable config and signed runtime inputs. Host seat state is not an `aptl.json` extension, environment bag, or duplicate copy of the launch descriptor. |

## Security And Validation Passage

The intended design has to pass all of these layers:

- **Release trust boundary:** use `verify_release_directory()`,
  `prepare_launch_descriptor()`, and the closed appliance models before any
  overlay or VM action. Unsupported release version, digest mismatch, missing
  trust anchor, or unsupported adapter capability fails closed before launch.
- **Overlay and seat state boundary:** use `OverlayCreateRequest`,
  `create_disposable_overlay()`, and `initialize_overlay_state()` for mutable
  state creation. Never create overlays by hand, never reopen the golden for
  writing, and never persist seat credentials outside guest overlay state.
- **Host prerequisite gate:** follow the `hostenv`/`sysreqs` pattern for CPU
  virtualization, hypervisor availability, disk headroom, memory headroom, and
  required launcher tools. The output must be bounded and actionable, not raw
  command output.
- **Boundary observation gate:** supply one authenticated
  `HostBoundaryObservation` matching the selected release/binding and pass it to
  `run_appliance_boundary_gate()`. The host surface satisfies security only if
  it proves exact loopback-only participant/recovery listeners and forbidden
  host/LAN reachability remains blocked.
- **Process and OS exposure gate:** preserve fixed-argv subprocess execution
  patterns. Do not place secrets in argv, env dumps, unit files, desktop files,
  browser command lines, URLs, logs, support bundles, or host persistence. The
  host must not expose Docker, guest shells, clipboard/share channels, USB
  forwarding, or writable host mounts into the participant VM.
- **Error and report envelope:** reuse bounded CLI/API error style and
  redaction. Seat failures may report stable codes such as bad release,
  low-disk, no-KVM, failed-boundary-gate, interrupted-boot, or corrupt-overlay.
  They must not return raw libvirt/QEMU stderr, guest logs, policy text,
  credentials, or scenario topology.

## Extensibility Seam

The seam is one versioned host seat contract:

`(seat_id, selected_release_id, launch_descriptor_digest, overlay_ref, host_observation_id, lifecycle_state, taint_state)`

It is metadata about one outer seat only. The next reasonable change (another
supported hypervisor adapter or a fleet-oriented recovery service) should add
an adapter behind this seam while continuing to consume the same signed release,
overlay, and boundary-observation contracts. It must not fork the guest
manifest, readiness suite, participant routes, or recovery vocabulary.

## Whole-Repository Surface

- `src/aptl/appliance/`, `src/aptl/cli/appliance.py`, and the appliance release
  reference docs.
- `src/aptl/core/{appliance_boundary,appliance_boundary_gate,appliance_boundary_inventory,hostenv,sysreqs,lab,lab_types}.py`.
- `docs/adrs/adr-049-sealed-disposable-lab-appliance.md`,
  `docs/components/appliance-boundary.md`, and
  `docs/reference/appliance-release.md`.
- Guest first-boot assets under `appliance/guest/`.
- Test surfaces already exercising appliance release, boundary inventory, boot,
  guest assets, and CLI behavior.
- Host OS and runtime layers that will see the artifact: systemd/session
  startup, kiosk browser wrapper, QEMU/KVM or libvirt, loopback listener
  inventory, and instructor recovery entrypoint.

## Gotchas And Anti-Patterns

- Do not turn the launcher into an alternate `aptl lab` frontend that parses
  scenario state, drives Docker, or interprets guest health internally.
- Do not create a second host-observation schema, second readiness taxonomy,
  second exception hierarchy, or second release-config format for seat state.
- Do not let kiosk/logout/reboot behavior imply reset. Only explicit overlay
  destruction returns a seat to known-good security state.
- Do not expose participant shell access on the physical host, even if "locked
  down". Participant shell, participant sudo, host Docker access, shared
  folders, host clipboard, and USB forwarding are all out of bounds.
- Do not treat VM power-on, browser open, TCP reachability, or a green guest
  container as seat readiness. Ready requires verified release admission and a
  passing boundary/start gate.
- Do not store seat secrets, scenario credentials, raw guest logs, or evidence
  on the host just to simplify diagnostics or recovery.
- Do not use break-glass console repair as a normal recovery path. Any
  interactive guest recovery taints the seat and requires replacement before
  participant reuse.

## Non-Goals And Implementation Boundary

- This preflight does not implement the launcher, kiosk wrapper, systemd unit,
  libvirt domain, recovery UI, or seat-state persistence.
- It does not change RAES, `DeploymentBackend`, participant/runtime DTOs,
  startup/readiness schemas, the signed appliance release format, or the APP-1
  boundary schema.
- It does not authorize host-resident agents, MCP servers, scenario service
  publications, Docker authority, or participant-visible recovery controls.
