# Issue #1000 Partial Boot And Manual Release QA Preflight

This note fixes the architecture boundary for issue #1000. It is guidance, not
an implementation plan, and it does not perform the defect fixes or rewrite the
QA manual. No new ADR is needed: ADR-023 and ADR-037 own deployment inventory,
ADR-029 owns secret handling, ADR-030 owns startup outcomes, ADR-034 owns SOC
TLS and host exposure, ADR-044 owns run records, ADR-046 owns declared runtime
realization, and issue #905 already defines project lifecycle ownership and
checked residual-state observation.

## Findings And Decisions

Keep four claims separate:

| Claim | Authority | Meaning |
| --- | --- | --- |
| Project container state | `DeploymentBackend` observation | Every container owned by the validated deployment project is enumerated, including `created` and `exited` containers. |
| Startup outcome | `LabResult` / `StartupOutcome` | The complete public start workflow reached its terminal post-finalization state. |
| Live scenario verdict | `LiveGateReport` | The admitted RAES graph and observed range satisfy structural and semantic live checks. |
| Manual release QA | The release QA record | A person drove the released product and captured evidence for the required journeys on both install paths. |

None implies another. In particular, one running container does not make the
lab ready, a ready startup does not prove detection or SOAR, and a passing live
gate does not replace the manual product pass.

The following decisions apply:

1. **Retire `aptl-mcp-endpoints`; do not renumber it.** The selected SDL now
   declares the MISP, TheHive, and Shuffle host publications, and APTL realizes
   them through `runtime.network.published_ports`. The raw `alpine/socat`
   container duplicates those bindings, bypasses the realization/readback
   contract, and is undeclared runtime. Remove the function, invocation, and
   comments that claim it owns MCP reachability. Do not replace it with another
   proxy, alternate ports, a Compose sidecar, or an allowlist in the live gate.
2. **Declared publications remain exact.** Preserve the existing loopback-only
   bindings and strict lab-CA verification. The three host-run MCP clients keep
   using their canonical `https://localhost:{8443,9000,3443}` endpoints. A
   collision fails through the existing published-port conflict/realization
   path; it is not silently remapped or hidden behind a proxy.
3. **Status is project inventory, not Compose-service inventory.** `aptl lab
   status` must enumerate all containers carrying the validated project
   identity, including directly realized containers and every state. One
   backend-owned checked inventory primitive should feed both status and
   snapshot inventory; it may union the Compose-project and APTL-lifecycle
   label queries by immutable container ID, but must not join a `docker compose
   ps` subset to a separate CLI-only `docker ps` result. An `aptl-` name prefix
   is not an ownership authority. Before observing, status must load a present
   strict `aptl.json` and select its configured backend and project name, just
   as other lifecycle operations do. A missing config may retain the existing
   recovery default; an invalid present config or a failed backend selection is
   an explicit status error, never permission to inspect the local default
   `aptl` project instead.
4. **`LabStatus.running` keeps its narrow meaning.** Adding stopped containers
   to `LabStatus.containers` must not redefine `running` as "project residue
   exists," "all containers are ready," or "realization passed." Derive it
   from observed running state and render the inventory even when it is false.
   Readiness and parity retain their own contracts.
5. **Startup performs a terminal project-container attestation.** The check
   occurs after every startup step capable of creating, replacing, restarting,
   or stopping a container, including the temporary seed/fixup path. An
   observation error or any project-owned container not running is fatal:
   `StartupOutcome.FAILED`, non-zero CLI exit, and a bounded error naming the
   container, observed state/status, exit code, and redacted Docker state error
   when available. It is not a `degraded_unusable` warning because the
   acceptance contract expressly forbids success over a non-running container.
   This is a successful-start invariant, not implicit rollback: after a failed
   start, project-scoped residue may remain for diagnosis and the operator is
   directed to the explicit stop or clean-boot recovery from issue #905. Normal
   start must not silently delete or reconcile that failed range.
6. **The final observation and startup record cannot disagree silently.** If
   the startup snapshot remains earlier than a late infrastructure mutation,
   label it as an earlier phase and capture terminal state separately. Prefer
   one terminal observation for the success decision and startup inventory.
   Never overwrite a create-once or sealed run artifact to make stale evidence
   look current.
7. **The live-gate parity rule stays bidirectional and unconditional.** An
   undeclared container fails whether it is running, created, exited, or in an
   unknown state. Change only the diagnostic truthfulness: report its observed
   state/status rather than asserting that it is running. Do not filter stopped
   containers or add an infrastructure exception.
8. **There is one human QA entry point.** Replace the obsolete content in
   `docs/testing/smoke-test-plan.md` with the release manual. Reconcile
   `docs/components/mcp-smoke-test-protocol.md` by reducing it to a pointer or
   moving its current MCP material into the manual. Do not retain two competing
   pass criteria, and do not describe the retired `aptl scenario` engine,
   `containers` config block, or an agent team as the executor.
9. **Manual evidence is per release and per install path.** Every required step
   has a separate pass/fail and evidence reference for (a) a clean environment
   initialized from the built distribution and (b) a clean source checkout of
   the exact release candidate. No result is inherited across paths, and
   `SKIP`, "container healthy," or an automated test result is not a pass for a
   required human action.
10. **The release cut point is the release-PR merge.** The QA manual and
    `docs/releasing.md` must require the recorded pass before that merge. Since
    a final PyPI version does not exist before it is cut, the pre-cut package
    path uses the exact candidate wheel/sdist built from the release candidate;
    the source path uses the same commit. The publish workflow must not be
    described as validating an already-published PyPI version before release.
    A post-publish `pip install aptl-labs==X.Y.Z` check is corroboration, not the
    release-blocking pass. If byte identity between tested and published wheels
    becomes mandatory, preserve/promote the tested artifact rather than
    rebuilding a nominally equivalent one.

The release manual should identify every step with: stable ID; blocking status;
exact release, pack/plugin, OS, architecture, Docker/Compose, and install-path
identity; prerequisites; action; expected observation; actual observation;
PASS/FAIL; evidence reference; operator; and timestamp. The Wazuh, expected-rule
detection, Suricata-to-SIEM, real-alert Shuffle, TheHive/Cortex, MISP, all eight
MCP, archive-integrity, and teardown rows in the issue are release-blocking.
For every named MCP, the operator must attempt the check and record whether it
responded. A selected target must complete a real target-backed operation;
where the exact release scenario deliberately does not realize a target (as
the default TechVault scenario currently omits reverse), the `mcp-reverse` row
passes only by recording the expected unavailability and citing declaration
and realized-inventory evidence. That is a tested negative result, not `SKIP`,
and it must not be generalized into permission to ignore an unexpectedly
missing MCP.

## Required Reuse And Cross-Cutting Passage

| Layer | Canonical incumbent and required passage |
| --- | --- |
| Scenario and host exposure | RAES parsing/planning, `raes_realization_values.published_ports()`, `DeploymentPublishedPort`, `_compose_port_realization`, generated Compose, and `raes_runtime_observation._observe_published_ports()` remain the declaration-to-readback chain. Do not infer ports from MCP JSON or the retired proxy. |
| Lifecycle and final outcome | `orchestrate_lab_start()`, `_LabStartContext`, `_LAB_START_STEPS`, `LabResult`, `StartupOutcome`, `StartupDiagnostic`, `_emit_diagnostic()`, and the issue #905 lifecycle lock remain the sole public-start contract. |
| Project inventory | `DeploymentBackend`, local/SSH Compose backends, `_compose_queries`, `LabStatus`, `ProjectRuntimePresence`, project labels, and the existing `container_inspect()` detail seam own enumeration and state. Consolidate their query/parsing logic instead of adding another inventory DTO or raw command in core/CLI. |
| User projections | `cli.lab._emit_status_text()`, `api.schemas.ContainerInfo` / `LabStatusResponse`, the API lab router, and `web/src/lib/types.ts` project core status. They do not recalculate ownership or readiness. |
| Snapshot and persistence | `capture_snapshot()`, `RangeSnapshot.to_dict()`, `LocalRunStore` redacting JSON/JSONL writes, run provenance, and `aptl runs` remain the machine evidence boundary. Manual evidence indexes may reference these artifacts; they do not define another experiment/run schema. |
| Live validation | `validate_live_deployment()`, `_live_gate_checks`, `_live_gate_readiness`, `LiveGateCheck`, `LiveGateReport`, and the existing scenario-verifier plugin keep their current failure taxonomy. |
| Logging and observability | `get_logger()`, the existing startup progress callback, `_emit_diagnostic()`, and ADR-029 redaction own operator-visible lifecycle signals. Log the terminal phase, normalized outcome, bounded container identifiers/states, and aggregate counts; do not add a telemetry schema or emit raw backend output. |
| MCP and TLS | The eight `mcp/*/docker-lab-config.json` files, `aptl-mcp-common` config loading, endpoint-origin checks, `HTTPClient`, `verify_ssl`, and `ca_cert_path` remain canonical. MISP, TheHive, and Shuffle continue through ADR-034's lab CA, never a process-global TLS bypass. |
| Packaging/install paths | `_asset_manifest.py`, `hatch_build.py`, `aptl.core.assets`, `aptl lab init`, package-content tests, and the clean-install wheel job define the distribution path. A clean exact-commit checkout defines the source path. |
| Release workflow | `docs/releasing.md`, release-please configuration, `.github/workflows/release-please.yml`, the release PR, and GitHub environment approval are the existing cut/publish convention. Manual QA gates the human merge decision; it is not restated as a fake automated smoke job. |
| Teardown proof | `stop_lab(remove_volumes=True)`, `_compose_stop`, project-scoped cleanup/volume inventory, checked absence, and `scripts/ci/assert_project_teardown.py` own the no-container/no-volume assertion. Never use a daemon-wide prune or a name-prefix-only check. |
| Repository gates | Focused pytest suites, the installed-wheel check, MCP consumer builds where common code changes, docs lint/MkDocs strict build, `pytest`, and `pre-commit run --all-files` remain mandatory. Compose, Dockerfile, or `config/` changes additionally require the clean-machine lifecycle gate from `.gc/plan-rules.md`. |

## Security And Host-Layer Guardrails

- **Config shape and project identity:** load the strict `AptlConfig` /
  `DeploymentConfig` (`extra="forbid"`) and pass
  `validate_compose_project_name()` before using a project value in argv, label
  filters, cleanup, evidence, or logs. This issue needs no new config key or
  environment toggle.
- **RAES and env-pack validation:** the installed pack remains immutable input
  and must pass its manifest/content validation, RAES parser/semantic gates,
  planning, capability admission, realization, and published-port readback.
  Do not patch the staged pack or create an APTL mirror of its runtime schema.
- **Environment and secrets:** `.env` continues through `hydrate_dotenv()`,
  `load_dotenv()`, `env_vars_from_dict()`, and placeholder rejection. The
  endpoint retirement needs no credential. Do not copy the fixup's existing
  raw `docker run -e ...` style into new work; operator secrets belong in the
  established env/generated-file boundaries, not host process argv.
- **TLS and network exposure:** keep host publications on `127.0.0.1`, preserve
  the declared exact ports, and keep `verify_ssl=true` plus the lab CA for the
  three SOC MCP clients. Do not use `-k`, `verify_ssl=false`,
  `NODE_TLS_REJECT_UNAUTHORIZED`, an all-interface bind, or proxy termination
  to make QA pass.
- **Docker/SSH boundary:** all runtime queries and inspect calls go through the
  configured backend with list-form argv and bounded timeouts, preserving the
  SSH backend's selected daemon. Label filters must never widen to unrelated
  containers on a shared host.
- **State parsing:** normalize Docker's array/NDJSON/field-name variations once.
  Treat an empty response caused by command or parse failure as an observation
  failure, not an empty healthy project. Bound the number and length of
  reported failures.
- **Error envelopes:** use `LabResult` and `_emit_diagnostic()`; pass free-form
  Docker state errors through `redact()` and do not expose raw stderr, inspect
  payloads, commands, environment, paths, or tracebacks through CLI, API, SSE,
  logs, telemetry, or run records. The existing seed path logs raw captured
  stderr today; do not reuse that as the final-attestation reporting pattern.
- **Manual evidence:** screenshots, HTTP output, MCP responses, alert bodies,
  case/analyzer results, and playbook output can contain API tokens, cookies,
  usernames, internal data, or planted credentials. Capture the minimum proof,
  redact before attachment, and never publish browser storage, auth headers,
  private keys, `.env`, full generated config, or unreviewed logs.
- **Persistence:** structured runtime evidence uses `LocalRunStore` redacting
  writers and `RangeSnapshot.to_dict()`. Opaque screenshots are deliberately
  classified human evidence and need review before storage; file permissions,
  a private issue, or an archive location are not substitutes for redaction.
- **API/web auth:** no new status or QA endpoint is needed. Existing API token,
  Host/CSRF/session, response-model, and SSE boundaries remain in force; a
  frontend must not infer readiness from English status text.

## Extensibility Seams

- Project inventory is parameterized by the validated deployment project and
  includes all states by contract. A future backend implements the same checked
  `LabStatus` semantics without emulating Docker CLI text. If a future declared
  one-shot node legitimately permits a terminal non-running state, that policy
  must come from its typed RAES lifecycle contract; never add a container-name
  exception.
- Host endpoints remain parameterized in SDL `published_ports`. If MCP clients
  later need dynamically assigned ports, extend the existing resolved-port /
  endpoint-config generation seam. Do not resurrect a proxy or teach each MCP
  a different discovery rule.
- Manual QA rows are parameterized by release identity and install path, with
  separate observations. New product journeys add a stable row to the one
  manual and report template; they do not create another protocol document.
- The release seam is an immutable candidate artifact plus exact source commit
  and a human approval/evidence reference. It can later gain artifact promotion
  or a stricter approval check without automating the human product actions.

## Gotchas And Anti-Patterns

- `docker compose ps` without `-a` omits non-running containers; Compose service
  enumeration can also omit directly realized project containers. Changing
  only one flag does not establish project-wide accounting.
- The plain `lab_status(project_dir)` path currently constructs the default
  local Compose backend without loading a present project config. Fixing
  enumeration while retaining that selection path would still report the
  wrong project for a custom project name or the wrong daemon for SSH.
- `host_list_lab_containers()` currently narrows by the `aptl-` name prefix and
  returns `[]` on failure. Neither behavior is sufficient as the only
  authoritative final-start observation.
- `LabStatus.running = bool(containers)` becomes false semantics once inventory
  includes stopped rows. Keep presence, running, complete readiness, and RAES
  parity distinct.
- The seed/fixup phase runs after the current startup snapshot/run-record step
  and can mutate container state. A pre-seed snapshot is not terminal startup
  proof.
- Making `envpack-soar-fixups.sh` fail fast improves error propagation but does
  not replace the final backend observation: the seed step intentionally maps
  script failure to a non-fatal startup diagnostic.
- Do not promote every seed/content failure to a lifecycle failure. The hard
  rule is narrower: failed observation or any project-owned non-running
  container is fatal; existing capability diagnostics still classify failures
  that leave a sound running range.
- Do not parse the live gate's English diagnostic to drive startup, or reuse
  `LiveGateReport` as `LabStatus`. These are different boundaries.
- Do not mark an MCP as passed because its Node process starts or `tools/list`
  works. Invoke a real read/action against its live target and capture the
  bounded result; the issue requires all eight servers.
- Do not use the historical automated smoke suites, health checks, or the live
  gate as substitutes for the manual pass. They remain useful prerequisites and
  corroborating evidence.
- Do not claim the final PyPI artifact was tested before it existed. Name the
  exact candidate bytes/commit honestly, then separately record post-publish
  corroboration if performed.

## Non-Goals And Boundaries

This issue does not automate the manual pass, create a general QA workflow
engine, add a new run/evidence schema, redesign RAES or the deployment backend,
change service ports, weaken TLS, add MCP discovery, or repair unrelated
MISP/Redis env-pack defects. It does not make every readiness or seeding warning
fatal, redesign release-please, or turn fast CI into a full SOC lab run.

The implementation boundary is limited to retiring the obsolete endpoint
container; making status and terminal startup observation complete and
truthful; correcting the live-gate wording without weakening parity; replacing
the obsolete manual with one release-blocking evidence protocol; reconciling
the MCP protocol; and binding that human record to the existing release cut
decision.
