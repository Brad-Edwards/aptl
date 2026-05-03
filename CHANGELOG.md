
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `aptl lab continuity-audit` — orchestrator-side purple-team continuity carve-out. Detects and reverts blanket kali source-IP DROP/REJECT rules on target containers (`-A INPUT -s <kali_ip> -j DROP` with no port/protocol/payload qualifier), preserving granular blue tradecraft. Complements ADR-021's in-band `aptl-firewall-drop` whitelist by catching bypass paths: custom AR scripts, raw iptables in Wazuh manager command fields, and manual researcher mistakes. Audit is stateless and idempotent; events are archived to the active run's `continuity-events.jsonl` when a session is open. Runs unconditionally — APTL is the purple-team lab — with the formal `scenario.mode == PURPLE` gate landing alongside the SDL `mode` field in [#263](https://github.com/Brad-Edwards/aptl/issues/263). Implements [#252](https://github.com/Brad-Edwards/aptl/issues/252); architectural rationale in [ADR-024](docs/adrs/adr-024-orchestrator-side-purple-continuity-carve-out.md). New module `src/aptl/core/continuity.py`, CLI command in `src/aptl/cli/lab.py`, and 38 unit tests plus 3 LIVE_LAB integration tests in `tests/test_continuity.py`. Manual smoke validation: `scripts/test-continuity-audit.sh`.
- `docs/components/default-defensive-posture.md` — captures the lab's intentionally-weak starting posture across Suricata, Wazuh detection rules, Wazuh active-response, MISP IOCs, Shuffle, TheHive, AD identity controls, and network segmentation. Tags every surface with one of three banners: `WEAKNESS BY DESIGN` (target's intentional vulnerability — red exploits, blue hardens), `STARTING POSTURE` (defensive coupling wired but disabled, empty, or absent — blue enables per iteration), or `BASELINE ENABLED` (defensive tool already on at first boot — Wazuh detection rules, Suricata IDS — what blue couples downstream). Researchers can distinguish target weaknesses, blue tools that ship inert, and always-on baselines whose downstream coupling is what blue actually controls. Linked from `docs/index.md`. Documents [#251](https://github.com/Brad-Edwards/aptl/issues/251); references SOC-001, SOC-002, SOC-006, SIEM-005, SIEM-006, SCN-001 and ADRs 019/021/022. The forward-looking scenario-`mode` contract is captured in a clearly-labelled appendix. Companion follow-up [#263](https://github.com/Brad-Edwards/aptl/issues/263) tracks the SCN-001 vocabulary mismatch (the requirement statement references a `mode` field that doesn't exist in the post-refactor SDL even though several scenario YAMLs still declare it).
- `aptl config show` — pretty-prints the resolved `AptlConfig` (Pydantic model) under the project's `aptl.json`, including default values for unset fields. Supports `--json` for machine-readable output. Implements **CLI-007**. Issue [#138](https://github.com/Brad-Edwards/aptl/issues/138).
- `aptl config validate` — validates `aptl.json` via the same loader (`core/config.find_config()` + `load_config()`) used by every deployment command. Reports invalid JSON, missing fields, type errors, and impossible profile combinations with non-zero exit. Implements **CLI-002**.
- `aptl container list` / `aptl container shell <name>` / `aptl container logs <name>` — the three commands required by **CLI-004**, finally implemented. `list` enumerates project containers via the deployment backend; `shell` opens an interactive TTY (tries `/bin/bash`, falls back to `/bin/sh` if missing); `logs` streams container output to the parent terminal. All three work uniformly against local Docker Compose and SSH-remote backends. Architectural rationale in [ADR-023](docs/adrs/adr-023-container-interaction-in-deployment-backend.md).
- `DeploymentBackend` Protocol (`src/aptl/core/deployment/backend.py`) gains six container-interaction methods: `container_list`, `container_logs`, `container_logs_capture`, `container_shell`, `container_exec`, `container_inspect`. Both `DockerComposeBackend` and `SSHComposeBackend` implement them; SSH inherits the captured methods and overrides a new `_run_streaming` helper to inject `DOCKER_HOST=ssh://…` for the streaming variants. Supersedes ADR-013's "container interaction is out of scope" clause.
- `tests/test_cli_config.py` (13 tests), `tests/test_cli_container.py` (12 tests), and 22 new tests in `tests/test_deployment_backend.py` covering the six new Protocol methods on both backends.
- `docs/adrs/adr-023-container-interaction-in-deployment-backend.md` — design rationale: Protocol vs sibling Protocol, `docker compose ps` for `list` but raw `docker` for the rest (consistent with the container names users see), bash→sh fallback only when `--shell` is unspecified.
- `aptl-misp-suricata-sync` service — first long-running Python daemon in the lab. Polls MISP's `POST /attributes/restSearch` filtered by the configured tag (default `aptl:enforce`), translates each IOC into a Suricata `alert` rule, and triggers Suricata rule reload via its unix-command socket. Translator output: `ip-src` matches source side, `ip-dst` matches destination side, `domain`/`hostname` match `dns.query`, `url` matches `http.host` plus `http.uri` (path only when non-trivial), and `sha256`/`sha1`/`md5` are aggregated into per-type sidecar list files (`misp-<type>.list`) referenced by a single `file.data; filesha256:<list>` rule each — Suricata's hash keywords take a list file, not an inline digest. Rules go to a dedicated `/etc/suricata/rules/misp/misp-iocs.rules` separate from operator-authored `local.rules`. Issue [#250](https://github.com/Brad-Edwards/aptl/issues/250); architectural rationale in [ADR-022](docs/adrs/adr-022-misp-driven-suricata-rules.md).
- `src/aptl/services/misp_suricata_sync/` — service implementation under a new `aptl.services` namespace (sets the layout precedent for future Python daemons): `config.py` (Pydantic v2 env-driven `ServiceConfig`), `models.py` (`MispAttribute`, `RenderedRule`, `TranslationResult` DTOs), `misp_client.py` (curl-subprocess client with bare-API-key `Authorization` header — never logged), `translator.py` (pure rendering: hard-codes `alert` action per ADR-019, deterministic `SID_BASE + crc32(type|value)` allocation, `|XX|`-hex content escaping, timestamp-free header for write idempotency), `rule_writer.py` (atomic `<path>.tmp`+`replace`, idempotent), `suricata_reloader.py` (~30-line unix-command JSON client; no `suricatasc` dependency), `main.py` (SIGTERM-aware loop, also writes per-type hash list sidecars).
- `containers/misp-suricata-sync/Dockerfile` — `python:3.11-slim` + curl + the aptl wheel, installed via `pip install .`. Runs as root so it can write to the bind-mounted host directory `./config/suricata/rules/misp/` (matches the lab's broader pattern; see ADR-020).
- `config/suricata/rules/misp/misp-iocs.rules` plus empty `misp-md5.list` / `misp-sha1.list` / `misp-sha256.list` — seed files shipped in the repo so Suricata's `rule-files:` list and any `filemd5:`/`filesha1:`/`filesha256:` directives resolve cleanly on the very first `aptl lab start`, before the sync service has had a chance to write.
- `tests/test_misp_suricata_sync.py` — 58 unit tests covering every submodule. Includes the ADR-019 regression guard `test_action_is_always_alert_never_drop`, the rule-injection guard `test_rejects_quote_or_semicolon_in_value_via_escape`, the destination-direction guard `test_ip_dst_emits_destination_side_alert_ip_rule`, and the idempotency guard `test_header_has_no_timestamp_so_render_is_idempotent`.
- `docs/adrs/adr-022-misp-driven-suricata-rules.md` — design decisions: tag-graduated enforcement, alert-only per ADR-019, dedicated rule file, deterministic SIDs, MISP-down preserves last-known-good, unix-command socket for live reload, per-type hash list sidecars for correct Suricata hash matching.

### Changed

- `core/snapshot.py`, `core/flags.py`, `core/collectors.py` — refactored to route container `exec`/`inspect`/`logs` through the deployment backend instead of raw `subprocess` calls to `docker exec` / `docker inspect` / `docker logs`. Snapshot and flag/log capture now work correctly against SSH-remote labs (previously they silently targeted the local Docker daemon). Host-level operations (`docker version`, `docker compose version`, `docker ps -a --filter name=aptl-`, `docker network ls/inspect`) remain raw. **Caller-visible**: `capture_snapshot`, `collect_flags`, `collect_suricata_eve`, and `collect_container_logs` now take a `backend: DeploymentBackend` parameter; `core/lab.py:_step_capture_snapshot` and `cli/lab.py` `status --json` updated accordingly.
- `docs/troubleshooting/index.md` and `docs/deployment.md` — replace `docker compose ps` / `docker compose logs` / `docker exec -it … /bin/bash` recipes with the equivalent `aptl container list` / `aptl container logs <name>` / `aptl container shell <name>` so they work against SSH-remote labs out of the box.
- `config/suricata/suricata.yaml` — adds `unix-command:` socket at `/var/run/suricata/suricata-command.socket` (used by the sync service for live rule reload) and includes `/etc/suricata/rules/misp/misp-iocs.rules` in the `rule-files:` list. The operator-authored `local.rules` is unchanged.
- `docker-compose.yml` — new `misp-suricata-sync` service on the `soc` profile (`172.20.0.19` on `aptl-security`, depends on `misp` health + `suricata` started, 128m memory limit). Suricata and the sync service share `./config/suricata/rules/misp/` as a host-side bind mount so the seed files are available on first start; the sync service additionally shares the `suricata_command_socket` named volume with Suricata so it can speak the unix-command JSON protocol.
- `pyproject.toml` — adds `aptl-misp-suricata-sync` console script entry pointing at `aptl.services.misp_suricata_sync.main:main`.
- `README.md` — adds one-line mention of the MISP→Suricata sync under the SOC Stack section, with a pointer to ADR-019 explaining the alert-only constraint.

- `MISP_API_KEY` is now a required env var (no hardcoded default) for both the MISP server and every downstream consumer in this PR. `.env.example` ships a placeholder; the server's `ADMIN_KEY` and the sync service's `MISP_API_KEY` resolve to the same `${MISP_API_KEY:?...}` reference so they stay aligned. Implements SEC-005 for the SOC IOC pipeline.
- `MISP_CA_CERT_PATH` is wired through `aptl-misp-suricata-sync`'s config and curl wrapper as the verify-ON hook for SOC stack consumers. Lab default is `MISP_VERIFY_SSL=false` because MISP self-signs and there is no shared lab CA today; flipping the env var with a CA bundle enables real verification. Full lab-managed CA / verify-on-by-default work is tracked in **SEC-006** (DRAFT) and [#258](https://github.com/Brad-Edwards/Brad-Edwards/aptl/issues/258).

### Notes

- Default lab posture is the service running with zero IOCs tagged `aptl:enforce` — blue's job per iteration is to populate intel and graduate it. Submitting an IOC via the `aptl-threatintel` MCP with the `aptl:enforce` tag, then waiting one sync interval (default 300s), produces a rule in `misp-iocs.rules` and a Suricata reload.
- This issue's "blocking" framing in #250 is updated by ADR-019: in the lab's current IDS-only posture, MISP-driven rules are detection, not prevention. Real packet-level enforcement remains the Wazuh AR path (#248/#249).
- **Upgrade note for existing labs:** the `aptl-misp` container only honors `ADMIN_KEY` on first database init. If you're upgrading from a lab that ran with the previous hardcoded admin key (`JHx...`), MISP's database still has that old key and the new `${MISP_API_KEY}` env var won't take effect — the sync service will then fail to authenticate forever. Run `aptl lab stop -v` to wipe the persisted MISP volume, set `MISP_API_KEY` in `.env`, and `aptl lab start` for a fresh init. Skip this step only if you can rotate the admin key in MISP's UI yourself before the next sync attempt.

## [6.6.0] - 2026-05-02

### Added

- `containers/_wazuh-agent/aptl-firewall-drop.sh` — wrapper script that consults a kali-IP whitelist before forwarding to Wazuh's upstream `firewall-drop` active-response (AR) script. Installed at `/var/ossec/active-response/bin/aptl-firewall-drop` on every Wazuh agent in the lab (4 in-process + 2 sidecars) at image build time. Issue [#249](https://github.com/Brad-Edwards/aptl/issues/249); architectural rationale in [ADR-021](docs/adrs/adr-021-active-response-whitelist-via-wrapper.md).
- `config/wazuh_cluster/etc/lists/active-response-whitelist` — kali source-IP whitelist consulted by the wrapper. Pre-seeded with kali's three lab IPs (`172.20.4.30`, `172.20.1.30`, `172.20.2.35`); update by editing this file and running `aptl lab stop -v && aptl lab start`.
- `config/wazuh_cluster/wazuh_manager.conf` — new `<command>` block for `aptl-firewall-drop` (declares `<expect>srcip</expect>` so the manager won't dispatch on alerts missing srcip) and four representative `<active-response>` blocks (webapp brute force / SQL injection, AD Kerberos attack, database exfiltration). All blocks ship `<disabled>yes</disabled>` and `<timeout>120</timeout>`. The severity gate is implicit: each `<rules_id>` is already at level ≥ 10 in the lab's custom rule files. Blue removes the `<disabled>` tag per iteration to enable. Wazuh's AR matchers are OR'd, so `<level>` next to `<rules_id>` would broaden the block to every level-N+ alert — see ADR-021 / `docs/components/wazuh-active-response.md`.
- `tests/test_wazuh_active_response.py` — pytest integration tests (lab-up). Asserts the wrapper-command declaration, every `<active-response>` block enforces the carve-outs, the whitelist file is present on each agent with the kali IPs, and the wrapper short-circuits / forwards / logs correctly across `add` / `delete` and whitelisted / non-whitelisted srcip cases.
- `scripts/test-wazuh-ar-whitelist.sh` — manual end-to-end script proving the wrapper consults the whitelist and forwards cleanup unconditionally.
- `docs/components/wazuh-active-response.md` — blue-facing reference covering the AR architecture, available commands, wiring procedure, whitelist design, severity gate, timeout strategy, default posture, `disable-account` manual procedure (AC#4), and troubleshooting.
- `docs/adrs/adr-021-active-response-whitelist-via-wrapper.md` — records the wrapper-vs-CDB-list decision and notes the orchestrator-side complement in [#252](https://github.com/Brad-Edwards/aptl/issues/252).

### Changed

- The pre-existing rule-5763 SSH brute-force `<active-response>` block — was enabled and used bare `firewall-drop` with a 600s timeout. Now `<disabled>yes</disabled>` by default, references `aptl-firewall-drop` (so the kali whitelist is consulted), timeout reduced to 120s. Behavior is preserved and re-enable-able by deleting the `<disabled>` tag. **This is a deliberate weakening** of the prior auto-block to make the starting posture uniformly off — per #249 AC#6 ("Default starting posture: all `<active-response>` blocks disabled — blue's job over iters is to enable and tune them"). Researchers reading run results can now distinguish what blue actually enabled vs what was always on.
- `containers/_wazuh-agent/install.sh` — adds `jq` to the agent base image so the wrapper can parse Wazuh AR JSON cleanly.

### Notes

- Issue [#249](https://github.com/Brad-Edwards/aptl/issues/249) is the third milestone in the prevention chain set by [ADR-019](docs/adrs/adr-019-suricata-ids-only-prevention-via-wazuh-ar.md): #247 closed (Suricata stays IDS), #248 shipped in v6.5.0 (in-process agents), #249 ships in this release (AR wiring + kali whitelist). The orchestrator-side post-iter complement to the in-band whitelist is [#252](https://github.com/Brad-Edwards/aptl/issues/252) and ships separately.
- Only `aptl-firewall-drop` honors the whitelist in this release. The `<command>` blocks for `host-deny` / `disable-account` / `route-null` remain declared (so blue can wire AR to them per-iteration) but do not consult the whitelist; scope `<rules_id>` conservatively when enabling AR via those commands. Generalizing the standalone-script pattern to additional AR commands is documented as future work in ADR-021.

## [6.5.0] - 2026-05-02

### Changed

- Wazuh agents on the four service-target containers (`webapp`, `fileshare`, `ad`, `dns`) now run **in-process** alongside the primary service under `supervisord`, replacing the sidecar pattern introduced in v6.3.0. Each target gains `cap_add: [NET_ADMIN]` and a memory bump to 512m so active-response (`firewall-drop`) installed by Wazuh can call `iptables` on the target's own network namespace — the precondition the sidecars couldn't deliver because their iptables operated on a different namespace. Issue [#248](https://github.com/Brad-Edwards/aptl/issues/248); architectural rationale in [ADR-020](docs/adrs/adr-020-wazuh-agents-in-process-vs-sidecar.md).
- Shared `containers/_wazuh-agent/` directory now houses the registration script, ossec.conf template, and apt-install helper used by both the in-process targets and the remaining sidecar image; the four affected target images plus the sidecar build from the repo root so the shared files resolve.
- The four sidecar service entries `wazuh-sidecar-{webapp,fileshare,ad,dns}` are deleted from `docker-compose.yml`. `wazuh-sidecar-db` remains as a documented carve-out (postgres:16-alpine has no first-party Wazuh package; deferred). `wazuh-sidecar-suricata` remains because Suricata's deployment is governed by ADR-019.
- `wazuh_manager.conf` adds `<auth><force><enabled>yes</enabled>...</force></auth>` so agent-auth can re-register a same-named agent at a new IP — the manager-side mechanism the in-process takeover relies on. Wazuh 4.12's agent-auth has no `-F` flag, so the force semantics live in the manager config.

### Notes

- Issue [#248](https://github.com/Brad-Edwards/aptl/issues/248) is the second of three in the prevention chain set by [ADR-019](docs/adrs/adr-019-suricata-ids-only-prevention-via-wazuh-ar.md): #247 closed (Suricata stays IDS), #248 ships in this release (in-process agents), [#249](https://github.com/Brad-Edwards/aptl/issues/249) wires the AR `<command>` + `<active-response>` blocks with the mandatory kali-IP whitelist.
- The db carve-out is documented; if a future scenario needs AR on db specifically, plan a custom postgres-with-agent image as separate work. The carve-out is not a permanent design choice.

## [6.4.0] - 2026-05-02

### Notes

- Issue [#247](https://github.com/Brad-Edwards/aptl/issues/247) (switch Suricata to inline IPS via NFQ) closed as "decision recorded" via [ADR-019](docs/adrs/adr-019-suricata-ids-only-prevention-via-wazuh-ar.md). Two implementation paths were attempted on the branch: NFQ on the host's `DOCKER-USER` chain — failed due to upstream-acknowledged "bridge+nfqueue has never worked well" ([Suricata Support #2135](https://redmine.openinfosecfoundation.org/issues/2135)) — and L3-routing IPS via a multi-homed Suricata container — failed because Docker 26+ installs anti-spoof rules in `ip raw PREROUTING` (`ip daddr X iifname != bridge_X drop`) that block cross-bridge routed traffic before it reaches the routing namespace. Suricata's deployment is unchanged from the v6.3.0 baseline (passive IDS, pcap on dmz/internal/security). Packet-level prevention is delivered via Wazuh active-response on in-process agents in [#248](https://github.com/Brad-Edwards/aptl/issues/248) and [#249](https://github.com/Brad-Edwards/aptl/issues/249), which together give blue real packet drops at the host firewall layer with kali-IP carve-outs that keep the purple loop functional.

## [6.3.0] - 2026-05-01

### Added

- `wazuh-jwt` auth type in the shared `aptl-mcp-common` library, with one-time `POST {auth_url}` exchange against the Wazuh manager and per-`HTTPClient` token cache, so MCP servers can call manager endpoints that require Bearer JWT (rule file uploads, manager restart) without each tool re-authenticating
- Raw-string body passthrough in `aptl-mcp-common`'s `predefined_query` handler, so MCPs can ship raw XML payloads (Wazuh rule files) through `tools/call` without object-merge corruption
- `restart_manager` and `get_rule_file` actions on `mcp-indexer` for full create-author-restart-verify rule-management cycles from a blue-team agent's MCP surface
- `wazuh-sidecar` container template (Debian 12 + wazuh-agent 4.12.0) — single image used by six per-service sidecars (`fileshare`, `ad`, `dns`, `webapp`, `db`, `suricata`) configured via `WAZUH_MANAGER` / `AGENT_NAME` / `LOG_PATHS` / `LOG_FORMAT` env so a fresh `aptl lab start` ships samba, BIND9 query, gunicorn access/error, postgres query, and Suricata `eve.json` events into the SIEM without modifying upstream container images
- `webapp_logs` named volume bound to `aptl-webapp:/var/log/gunicorn`, picked up by the webapp sidecar so HTTP access events reach Wazuh independently of the `aptl-webapp -> rsyslog -> SIEM_IP:514` forwarder (which had been intermittent across iterations)

### Changed

- `mcp-indexer.create_rule` writes to `/var/ossec/etc/rules/zzz_purple_loop.xml` via `wazuh-jwt` auth instead of overwriting `local_rules.xml` with HTTP basic; rules authored during purple-loop iterations now land in a dedicated, namespaced file and the manager loads them after `webapp_rules.xml` so child rules can `<if_sid>` into the existing 302xxx surface
- `mcp-red.docker-lab-config.json` targets the kali container at its docker-internal address `172.20.4.30:22` instead of the host-port `localhost:2023`, so MCP-mediated commands reach the kali interface inside the lab subnets rather than the host port mapping that depends on profile-specific port exposure
- `wazuh_manager.conf` now declares `<rule_dir>etc/rules</rule_dir>` alongside the bundled `<rule_dir>ruleset/rules</rule_dir>`; without this, every API-driven `PUT /rules/files/<name>` failed with API error 1209 even though the rule_include lines below it referenced files in that directory
- `kali_redteam_rules.xml` rules 300001 / 300002 / 300003 demoted from level 3 to level 1 — these fire per SSH session boundary and the MCP-mediated red-team agent generates 30-40 of them per iteration, which previously buried higher-severity authored detections in dashboard scrolling
- `seed-prime.sh` now persists provisioned `THEHIVE_API_KEY` plus the lab's stable `MISP_API_KEY` and `SHUFFLE_API_KEY` defaults back to `.env` (mode 600), so the `aptl-casemgmt`, `aptl-threatintel`, and `aptl-soar` MCP servers — which spawn fresh per tool call and load `.env` at startup via `aptl-mcp-common` — authenticate cleanly to TheHive, MISP, and Shuffle without manual rewiring of `.mcp.json`
- `orchestrate_lab_start` step 14: after `seed-prime.sh` completes, sync any existing project `.mcp.json`'s per-server env blocks for `aptl-casemgmt` / `aptl-threatintel` / `aptl-soar` from the freshly-written `.env`. Idempotent — only refreshes the three known dynamic key entries, and is a no-op if `.mcp.json` does not exist (fresh checkouts) or already matches

### Notes

- These changes ground a real, MCP-only AI purple-team loop and address the telemetry-layer gaps that produced "open" verdicts in the 2026-04-30 evidentiary run: fileshare/postgres/dns containers having no Wazuh agent, intermittent webapp log shipping, and Suricata `eve.json` not being ingested. POST-body invisibility in Wazuh's web access decoder remains a structural limitation; closing it requires app-level structured logging, which is out of scope for this version.

## [6.2.0] - 2026-04-01

### Added

- SDL workflow `while` step type for loop and retry-with-variation control flow, modeled as a single DAG node with `when` predicate, `body` step reference, optional `next`, and optional `max-iterations` cap
- `on-error` field on `objective`, `while`, and `parallel` workflow steps for declarative error recovery path specification
- `step-outcomes` field on workflow predicates allowing `if` and `while` predicates to branch based on the success or failure of previously executed workflow steps
- ADR-018 documenting control flow primitive design decisions

## [6.1.0] - 2026-03-30

### Added

- Runtime package (`aptl.core.runtime`) rebuilt around an SDL-native compile/plan/execute flow instead of a flat generic step DAG
- Runtime compiler (`runtime/compiler.py`) — pure `compile_runtime_model(Scenario) -> RuntimeModel` pass that separates reusable SDL definitions from bound runtime instances
- Composite execution planner (`runtime/planner.py`) — pure `plan(RuntimeModel, BackendManifest, RuntimeSnapshot) -> ExecutionPlan` reconciliation with `CREATE`/`UPDATE`/`DELETE`/`UNCHANGED`
- Runtime contract hardening — plans are provenance-bound to target/manifest/base snapshot, raw planner output is unbound by default until explicitly targeted, runtime targets self-validate both manifest/component shape and invokable protocol signatures, capability-relevant variable refs fail closed when undeclared or field-invalid, finite variable domains are revalidated against the SDL fields they parameterize before backend capability checks run, declared-but-unbounded domains defer with warnings, ordering graphs fail closed on runtime-visible cycles, backend exceptions/invalid lifecycle returns become structured diagnostics instead of crashes, and runtime resources now distinguish ordering dependencies from refresh dependencies
- Domain-specific capability model (`runtime/capabilities.py`) — `ProvisionerCapabilities`, `OrchestratorCapabilities`, and `EvaluatorCapabilities` composed by an explicit `BackendManifest`
- Typed runtime state (`RuntimeSnapshot`) and structured diagnostics for planner and manager lifecycle errors
- Backend registry (`runtime/registry.py`) redesigned around separate manifest introspection and target creation paths
- RuntimeManager (`runtime/manager.py`) now compiles, plans, applies provisioning, starts evaluator/orchestration only when their plans have actionable work, and tears down in explicit domain order
- Stub backends (`aptl.backends.stubs`) rewritten to the new contracts with in-memory snapshot, orchestration, and evaluation behavior
- 15 new runtime tests across 4 test files covering compiler/model binding, planner reconciliation and capability validation, registry manifest introspection, manager lifecycle ordering, and a realistic SDL regression

## [6.0.1] - 2026-03-29

### Fixed

- SDL parser now catches `pydantic.ValidationError` instead of bare `Exception`, so implementation bugs propagate as real errors instead of masquerading as parse failures
- Removed dead `VM` and `Switch` classes from `nodes.py` — the unified `Node` class with type discrimination replaced them
- Validator node-name-length check now uses the `MAX_NODE_NAME_LENGTH` constant instead of a hardcoded `35`
- Replaced `list.pop(0)` with `deque.popleft()` in topological sort for O(1) per operation
- Removed redundant `_all_entity_names()` update since `flatten_entities` already includes top-level keys
- Fixed overly permissive assertion in `test_hyphenated_keys` — now pins the expected preserved-key behavior
- Moved `TestPlatformCommand` from `test_sdl_models.py` to `tests/test_attacks.py` since `PlatformCommand` lives in `aptl.core.attacks`, not the SDL package
- Corrected ADR-014 file count from 24 to 21 (reflecting compat.py/defenses.py/attacks.py removal in 6.0.0)

## [6.0.0] - 2026-03-29

### Changed

- **BREAKING**: Removed APTL legacy fields from SDL Scenario model — `metadata`, `mode`, `containers`, `preconditions`, `scoring`, `attack_chain`, `steps`, and `defenses` are no longer part of the SDL specification. The legacy `objectives` block was not kept verbatim; it was replaced by declarative SDL `objectives`, and the SDL now also includes first-class `workflows` for branching/parallel objective control. The SDL now has one clean identity: 21 specification sections with `name` as the only required field.
- **BREAKING**: Removed backward-compatibility layer (`sdl/compat.py`) and the `scenarios.py` re-export shim. Runtime code that imported `ScenarioDefinition`, `validate_scenario_containers`, or APTL-specific types from `aptl.core.scenarios` will need updating.
- **BREAKING**: APTL legacy scenario YAMLs (with `metadata` block) no longer parse through the SDL. They require migration to SDL format.
- Tightened structural validation for the new SDL sections: `content` now requires a `target` plus type-specific anchors (`path`, `source|items`, or `destination`), `accounts` require `node`, and `agents` require `entity`.
- Parser boundary tightened: `${var}` placeholders are now rejected in user-defined mapping keys, keeping SDL identifiers concrete at parse/validate time.
- Variable handling expanded: full `${var}` placeholders are now accepted in selected leaf enum-backed property fields (`accounts.password_strength`, `entities.role`, `nodes.os`, `nodes.asset_value.*`, `infrastructure.acls.action`, `objectives.success.mode`) while discriminant `type` fields remain concrete.
- Named service bindings and named ACL rules are now first-class symbolic refs for objectives and relationships via `nodes.<node>.services.<service_name>` and `infrastructure.<infra>.acls.<acl_name>`.
- Added SDL `workflows` section for branching and parallel objective graphs with DAG validation, reachability checks, and objective-window workflow/step binding.
- Moved runtime evaluation models to standalone modules: `aptl.core.objectives` (ObjectiveType, Objective, WazuhAlertValidation, etc.) and `aptl.core.attacks` (AttackStep, MitreReference, ExpectedDetection, etc.). These are runtime evaluation mechanics, distinct from the declarative objective semantics carried by the SDL.
- Removed 6 APTL-specific semantic validation passes from the SDL validator
- Framing: OCR scoring pipeline (conditions → metrics → evaluations → TLOs → goals) stays in the SDL, and the SDL now also carries declarative objectives. Backend-specific automated validation remains a runtime concern outside the language itself.

### Removed

- `src/aptl/core/sdl/compat.py` — legacy backward-compatibility shim
- `src/aptl/cli/scenario.py` — removed with the legacy scenario runtime cutover
- `src/aptl/api/routers/scenarios.py` — removed with the legacy scenario runtime cutover
- `src/aptl/core/engine.py`, `src/aptl/core/evaluators.py`, `src/aptl/core/scoring.py`, `src/aptl/core/run_assembler.py` — removed pending a new SDL-native runtime
- `src/aptl/core/sdl/defenses.py` — free-form defense config (underspecified)
- `src/aptl/core/sdl/attacks.py` — moved to `aptl.core.attacks`
- `tests/test_sdl_compat.py` — tests for removed compat layer

## [5.3.0] - 2026-03-29

### Added

- Property-based fuzz testing for SDL parser (`tests/test_sdl_fuzz.py`) — 6 Hypothesis strategies generating ~1,050 random inputs per run; excluded from default pytest via `fuzz` marker, run with `pytest -m fuzz`
- Real-world scenario stress tests (`tests/test_sdl_realworld.py`) — 6 scenarios from Incalmo/MHBench, NICE Challenge, CCDC, HTB ProLab, Metasploitable 2, and Locked Shields IT/OT/SCADA
- SDL documentation suite (`docs/sdl/`) — index, sections reference, parser behavior, semantic validation (24 passes), design precedents, limitations, and testing guide
- ADR-014: Scenario Description Language architecture decision record
- `hypothesis>=6.0.0` added to dev dependencies

### Changed

- `pyproject.toml` pytest config: added `fuzz` marker and `addopts = "-m 'not fuzz'"` to exclude fuzz tests from default runs

## [5.2.0] - 2026-03-29

### Added

- SDL `relationships` section for typed directed edges between scenario elements — adapted from STIX 2.1 Relationship SROs. Supports `authenticates_with`, `trusts`, `federates_with`, `connects_to`, `depends_on`, `manages`, `replicates_to` with free-form properties dict for type-specific metadata (trust_type, protocol, etc.). This is how identity/directory/trust emerges: accounts describe *who*, features describe *what provides auth*, relationships describe *how they connect*
- SDL `agents` section for autonomous scenario participants — adapted from CybORG CAGE Challenge agent definitions. Each agent has an entity reference (team/role), available actions, starting accounts, initial knowledge (known hosts/subnets), and allowed subnet scope. Agent specifications are framework-agnostic (no Gymnasium coupling)
- SDL `variables` section for scenario parameterization — adapted from CACAO v2.0 playbook_variables. Named variables with types (string/integer/boolean/number), defaults, descriptions, and allowed_values. Variables are stored as `${name}` strings in the model and resolved at instantiation time, not parse time
- Semantic validator passes: `verify_relationships` (source/target resolve to any named element), `verify_agents` (entity/account/subnet/host references resolve), `verify_variables` (structural validation)
- Source expansion now correctly skips `relationships` and `agents` sections where `source` is a string reference, not a package Source
- Stress test scenarios 12 (CybORG CAGE-2 with red/blue/green agents, starting accounts, initial knowledge) and 13 (multi-domain AD with parent-child trust, ADFS federation, and parameterized variables)
- 25 new tests for relationship, agent, and variable models and cross-reference validation

## [5.1.0] - 2026-03-29

### Added

- SDL `content` section for data-in-systems: files, datasets (emails, DB records, pcaps), directory structures placed into scenario nodes — adapted from CyRIS `copy_content` pattern
- SDL `accounts` section for user accounts within scenario nodes: AD users, SSH users, email accounts with password strength, Kerberos SPNs, group memberships — adapted from CyRIS `add_account` and CybORG agent sessions
- Network access control rules (`acls`) on infrastructure nodes — adapted from CybORG `Subnets.NACLs` pattern
- Network `internal` flag on `SimpleProperties` for egress-blocked networks
- Host OS family and version fields on nodes (`os`, `os_version`) — vocabulary from OCSF `Device.os`
- CIA triad `asset_value` on nodes — adapted from CybORG `ConfidentialityValue`/`AvailabilityValue`
- `ServicePort` model for exposed network services on nodes (port/protocol/name) — simplified from OCSF `NetworkEndpoint`
- `PlatformCommand` on attack steps for per-OS command variants with cleanup — adapted from CALDERA `platforms.{os}.{shell}.command` and Atomic Red Team `cleanup_command`
- Health check extensions on conditions: `timeout`, `retries`, `start_period`
- Feature-list shorthand on nodes: `features: [svc-a, svc-b]` expands to dict with empty role binding
- Scenario 11 stress test: Exchange server with mailboxes, accounts, ACLs, phishing lure content, asset values
- 30 new tests for all extension models, validator passes, and shorthand expansion

## [5.0.0] - 2026-03-28

### Added

- Formal Scenario Description Language (SDL) package (`src/aptl/core/sdl/`) ported from the Open Cyber Range SDL, extended for APTL's domain, and decoupled from backend-specific infrastructure
- 14 OCR SDL sections: nodes (VM/Switch), infrastructure (topology/IP/CIDR), features (Service/Configuration/Artifact with cycle-detected dependency graphs), conditions (command/source monitoring), vulnerabilities (CWE-classified), metrics/evaluations/TLOs/goals (full scoring pipeline), entities (recursive org/team/person hierarchy with exercise roles), orchestration (injects/events/scripts/stories with human-readable durations)
- APTL extensions integrated into the SDL: objectives with auto-evaluation (wazuh_alert, command_output, file_exists), attack steps with MITRE ATT&CK mapping and OCSF-aligned expected detections, defense configurations, preconditions, scenario metadata, scoring with time bonuses and hint penalties
- Semantic validator (`validator.py`) with 21 cross-reference passes: node/feature/condition/vulnerability existence checks, infrastructure link and IP/CIDR validation, feature dependency cycle detection, metric/evaluation/TLO/goal reference chains, entity hierarchy validation, inject/event/script/story reference chains, MITRE technique format validation, mode-objective consistency
- SDL parser (`parser.py`) with case-insensitive key normalization, hyphen-to-underscore conversion, shorthand expansion (source strings, infrastructure counts, role strings, min-score integers), and auto-detection of APTL legacy vs OCR SDL format
- Backend-agnostic `Source(name, version)` reference type — no deployment handler coupling
- 117 new tests across 4 test files: structural model validation, semantic cross-reference validation, parser normalization/shorthand/format-detection, and backward compatibility

### Changed

- `src/aptl/core/scenarios.py` is now a backward-compatibility shim re-exporting all names from `aptl.core.sdl` — all 8 consumer files continue working with zero import changes (BREAKING: internal module restructuring)

## [4.17.0] - 2026-03-26

### Added

- Scenario runtime engine with async evaluation loop (`src/aptl/core/engine.py`) — periodically checks non-manual objectives against live infrastructure (Wazuh alerts, command output, file existence) and updates session state incrementally
- Objective evaluators (`src/aptl/core/evaluators.py`) — async functions for each `ObjectiveType`: `evaluate_wazuh_alert` queries the Wazuh Indexer ES API, `evaluate_command_output` runs `docker exec` and checks output, `evaluate_file_exists` checks file presence and content in containers
- Scoring engine (`src/aptl/core/scoring.py`) — computes scenario scores from completed objectives, hint penalties, and time-based bonuses with linear decay
- `aptl scenario run <name>` CLI command — combined start + evaluation loop + stop with Ctrl+C graceful shutdown and real-time progress reporting
- `aptl scenario evaluate` CLI command — single evaluation pass against an active session for debugging and scripting
- `aptl scenario status` now displays current score, objective completion breakdown, and pass/fail status
- `ScenarioSession.set_evaluating()` and `set_active_from_evaluating()` methods — the `EVALUATING` session state is now actively used during evaluation cycles
- OTel `aptl.evaluation` child spans emitted for each objective evaluation cycle
- 45 new tests: evaluator unit tests (`test_evaluators.py`), scoring tests (`test_scoring.py`), engine integration tests (`test_engine.py`), CLI command tests (`test_cli_evaluate.py`)

## [4.16.1] - 2026-03-25

### Fixed

- Test helper `_find_node()` returns absolute path via `shutil.which()` instead of bare `"node"` string, fixing `_server_available()` check that caused MCP protocol tests to skip on systems without NVM
- Deploy workflow: use `aptl lab start` instead of raw `docker compose up`, fixing missing SSL certs and credential sync on fresh deploys
- Deploy workflow: exclude root-owned and runtime directories from rsync --delete (SSL certs, venv, keys, runs, node_modules, tools/misp-mcp-server)
- SSL cert check now verifies root-ca.pem exists, not just the directory — fixes regeneration after empty directory is left behind
- SSH key generation target changed from `containers/keys/` to `keys/` to match docker-compose.yml bind mounts
- Deploy workflow: force-stop containers and prune networks before rsync to prevent "Address already in use" on redeploy

### Changed

- SonarCloud scan now waits for Quality Gate result (`-Dsonar.qualitygate.wait=true`), failing the CI job if the gate is red
- Branch protection on `main` and `dev`: "SonarCloud Code Analysis" is now a required status check

## [4.16.0] - 2026-03-24

### Added

- `APTL_ALLOWED_ORIGINS` environment variable for configurable CORS origins (defaults unchanged)
- SSH deployment parameter validation (host, user, port, key path) in `SSHComposeBackend`
- Integration tests exercising full API-to-core request paths (`test_api_integration.py`)
- PID re-verification via `/proc/{pid}/cmdline` before SIGKILL in kill switch (TOCTOU mitigation)
- File locking (`fcntl.flock`) for `session.json` concurrent access safety

### Fixed

- Credential sync: YAML password double-quote escaping and XML cluster key entity escaping in `credentials.py`
- WebSocket terminal: empty Origin header now correctly rejected (was bypassing origin check)
- Scenario CLI: `shutdown_tracing()` wrapped in try/finally to prevent span loss on exception
- Deploy workflow: replaced fixed 30s sleep with 120s polling loop for container health verification
- Kill switch test: SIGTERM/SIGKILL ordering now asserted by index, not just membership

### Changed

- TheHive Elasticsearch image updated from 7.17.24 to 7.17.28 (security patches)

## [4.15.1] - 2026-03-23

### Fixed

- Deploy workflow: replace remote `git clone` with `rsync` from runner to fix clone failures on hosts without GitHub credentials (curl 56 connection reset)

## [4.15.0] - 2026-03-22

### Added

- Deployment backend abstraction layer (DEP-001, #233):
  - `DeploymentBackend` Protocol in `src/aptl/core/deployment/backend.py` defining the lifecycle interface (start, stop, status, kill, pull_images)
  - `DockerComposeBackend` wrapping existing Docker Compose subprocess logic as the default backend
  - `SSHComposeBackend` enabling remote deployment over SSH via `DOCKER_HOST=ssh://user@host`
  - `DeploymentConfig` Pydantic model with provider selection and SSH configuration fields
  - Factory function `get_backend()` for config-driven backend instantiation
  - `deployment` section in `aptl.json` for backend configuration (backward-compatible default)
  - ADR-013 documenting the deployment abstraction decision
  - Existing `start_lab()`, `stop_lab()`, `lab_status()`, and `kill_lab_containers()` functions accept optional `backend` parameter while maintaining full backward compatibility

## [4.14.0] - 2026-03-22

### Added

- Network egress firewall on Docker networks (SAF-002, #231):
  - `aptl-dmz`, `aptl-internal`, and `aptl-redteam` networks now use `internal: true` to block internet egress
  - Prevents autonomous agents from scanning or attacking external targets
  - `aptl-security` remains non-internal so SOC tools can reach threat feeds and rule updates
  - Multi-homed management containers (dns, wazuh, suricata) retain internet via security network
  - Host port mappings (SSH to victim/kali) unaffected by internal flag
  - Wazuh agent and Falco pre-installed in victim, workstation, and kali container images at build time (runtime install scripts skip downloads when packages are already present)
  - Static consistency tests enforce egress controls in `test_consistency.py`
  - Networking architecture docs updated with egress control and upgrade details

## [4.13.0] - 2026-03-22

### Added

- Emergency kill switch for all agent and MCP operations (SAF-001, #229):
  - `aptl kill` CLI command terminates all MCP server processes (SIGTERM + SIGKILL fallback)
  - `--containers` flag force-stops all lab Docker containers via `docker compose kill`
  - POST `/api/lab/kill` endpoint for web UI emergency button
  - Automatic cleanup of active scenario sessions and trace context files
  - Core `kill.py` module with resilient process discovery via `/proc/*/cmdline`

## [4.12.0] - 2026-03-21

### Added

- OpenTelemetry integration replacing custom JSONL tracing systems (OBS-001, #225):
  - Python `telemetry.py` module: OTel TracerProvider with OTLP HTTP exporter, trace context generation/propagation, span creation for scenario lifecycle events
  - TypeScript `telemetry.ts` module: OTel NodeTracerProvider with OTLP proto exporter, cross-process trace context via `.aptl/trace-context.json`, `traceToolCall()` wrapper with GenAI SIG attributes
  - Docker infrastructure: OTel Collector (`otel` profile), Grafana Tempo (72h retention), Grafana UI at port 3100
  - OTel Collector config, Tempo config, and Grafana datasource provisioning in `config/otel/`
  - Run archive `traces/spans.json` containing all OTel spans fetched from Tempo
  - `trace_id` field in session state and run manifest for distributed tracing correlation
  - `collect_traces()` collector querying Tempo HTTP API by trace ID
  - ADR-012 documenting the OpenTelemetry integration decision

### Changed

- `aptl lab start` now always includes `--profile otel` for the observability stack
- Run manifest includes `trace_id` field
- `.mcp.json.example` uses `OTEL_EXPORTER_OTLP_ENDPOINT` instead of `APTL_TRACE_DIR`
- MCP server startup initializes OTel tracing; shutdown flushes spans
- `assemble_run()` no longer takes `events` parameter; collects traces from Tempo instead

### Removed

- `src/aptl/core/events.py` (EventLog, EventType, Event, make_event) — replaced by OTel spans
- `mcp/aptl-mcp-common/src/tracing.ts` (ToolTracer, ToolTrace) — replaced by OTel spans
- `tests/test_events.py` — replaced by `tests/test_telemetry.py`
- `APTL_TRACE_DIR` environment variable and `.aptl/traces/` directory
- `collect_mcp_traces()` from collectors (replaced by `collect_traces()`)
- `scenario/events.jsonl` and `agents/traces.jsonl` from run archive format

## [4.11.1] - 2026-03-21

### Fixed

- SonarCloud quality gate failure: new code coverage below 80% threshold
  - Added tests for `container-state.ts`, route load functions, `getScenario()` API, `subscribeLabEvents`, and SSE reconnect logic in lab store
  - Scoped vitest coverage to `src/` only, eliminating `build/`, `.svelte-kit/`, and `node_modules/` noise from lcov report
  - All new TypeScript files now at 100% coverage (56 tests across 7 test files)

## [4.11.0] - 2026-03-21

### Added

- Interactive scenario workbench view at `/scenarios/[id]` (UI-001, #223):
  - Block-composition architecture: `buildBlockSequence()` pure function maps scenario data to typed `WorkbenchBlock[]` discriminated union, separating data logic from rendering
  - 9 workbench block components: NarrativeBlock (markdown), TerminalBlock (xterm.js wrapper), SiemQueryBlock (stub), ContainerStatusBlock (SSE-driven), HintToggle (progressive disclosure), ObjectiveBlock, AttackStepBlock, WorkbenchStatusBar (sticky), SectionDivider
  - Full `ScenarioDefinition` TypeScript type hierarchy mirroring Python Pydantic models (metadata, steps, objectives, scoring, attack chain, MITRE references)
  - `renderMarkdown()` utility using `marked` + DOMPurify for safe runtime markdown rendering
  - Scenario card links from Lab Home page to workbench view
  - `prose-aptl` CSS class for dark-themed markdown prose styling
  - Progressive hint disclosure with escalating point penalties shown in amber
  - SIEM query blocks display query JSON with disabled "Run Query" button (ready for OpenSearch integration)
  - Copyable attack step commands with clipboard feedback
  - Lazy-mounted terminals in attack step blocks to avoid mass WebSocket connections
  - Stable block keys for Svelte each-block diffing
  - Shared `stateColor()` utility for container state badge colors
  - Unit tests for block sequence builder (11 tests), markdown renderer (9 tests), and HintToggle component (7 tests)
  - `marked` and `dompurify` dependencies added
  - Vitest `resolve.conditions: ['browser']` fix for Svelte 5 component testing with jsdom
  - Route load function uses SvelteKit `error()` for proper HTTP status propagation

### Security

- WebSocket terminal endpoint now validates the `Origin` header before accepting connections, blocking cross-site WebSocket hijacking (CSWSH) — previously any website visited while the lab was running could open a shell on lab containers because CORS middleware does not protect WebSocket upgrades
- `ALLOWED_ORIGINS` constant shared between CORS middleware and WebSocket origin check in `aptl.api.deps` to prevent drift

## [4.10.0] - 2026-03-21

### Added

- In-browser terminal for container SSH access via xterm.js and WebSocket (#221):
  - WebSocket endpoint `ws /api/terminal/ws/{container}` with asyncssh PTY relay for all SSH-capable containers
  - `Terminal.svelte` component: xterm.js wrapper with FitAddon, WebLinksAddon, APTL dark theme, auto-resize
  - Full-page terminal route at `/terminal/{container}` with back navigation
  - "Terminal" link on ContainerCard when container is running and SSH-capable
  - Vite dev server WebSocket proxy (`ws: true`) for `/api` endpoint
  - `asyncssh>=2.17.0` added to `web` optional dependencies
  - WebSocket endpoint tests covering validation, stdin/stdout relay, resize, disconnect cleanup, and error handling

## [4.9.2] - 2026-03-20

### Fixed

- API response models use `Optional[str] = None` instead of `str = ""` for error fields
- SSE generator implements exponential backoff and circuit breaker (terminates after 10 consecutive errors)
- CORS tightened to `GET`/`POST` methods and `Content-Type`/`Accept` headers only
- Lab start endpoint has 30-minute timeout via `asyncio.wait_for`
- All API routers use FastAPI `Depends()` for `get_project_dir` injection (testable, validates directory exists)
- `get_project_dir()` returns HTTP 503 when project directory does not exist
- Hardcoded container list in config router replaced with dynamic `ContainerSettings.model_fields`
- `ContainerSettings.enabled_profiles()` uses `model_fields` instead of hardcoded list
- Docker CLI installed via official APT repo with GPG verification instead of `curl | sh`
- Production web Docker image uses `npm ci --omit=dev` instead of copying full `node_modules`
- Uvicorn production config: `--workers`, `--log-level info`, `--timeout-keep-alive 65`, `--access-log`
- Frontend SSE reconnects with generation counter to prevent race conditions
- Frontend error text truncated to 500 characters
- `+page.svelte` checks `error != null` instead of truthy for nullable error field

### Added

- Structured logging (`aptl.utils.logging`) in all API routers and `create_app()`
- `+error.svelte` dark-themed error page with status code and back link
- Accessibility: `role="status"`/`role="img"`, `aria-label` on status dots, badges, spinner, buttons; `sr-only` loading text
- Expert difficulty gets distinct violet badge (was same red as advanced)
- HTML meta tags: `description`, `theme-color` (#1a1d23), `apple-mobile-web-app-capable`
- `.dockerignore` files for project root and `web/`
- Docker socket security documentation in README
- SonarCloud config includes `web/src` sources and `web/coverage/lcov.info`
- CI workflow runs web frontend tests with coverage
- Vitest coverage config (v8 provider, lcov reporter)

### Removed

- Unused `web/src/lib/stores/scenarios.ts`
- Unused `getScenarios` import from `+page.ts`
- `httpx` from `web` optional deps (already in `dev`; CI installs both)

## [4.9.1] - 2026-03-20

### Fixed

- CI SonarCloud workflow installs `.[dev,web]` so API tests find `fastapi` (#219)
- API test files gracefully skip via `pytest.importorskip` when web deps are absent

## [4.9.0] - 2026-03-20

### Added

- Notebook-style web UI Phase 1 MVP (SYS-010, ADR-011) (#219):
  - FastAPI backend (`src/aptl/api/`) wrapping existing `aptl.core` modules — no domain logic duplication
  - REST endpoints: `GET /api/lab/status`, `POST /api/lab/start`, `POST /api/lab/stop`, `GET /api/scenarios`, `GET /api/scenarios/{id}`, `GET /api/config`, `GET /api/health`
  - SSE endpoint `GET /api/lab/events` for real-time container status updates
  - SvelteKit frontend (`web/`) with Tailwind CSS v4, dark theme (indigo/violet/teal palette)
  - Lab Home page with container status grid, start/stop controls, scenario listing with difficulty/mode badges
  - `aptl web serve` CLI command to start the API server on port 8400
  - `web` optional dependency group: FastAPI, uvicorn, sse-starlette, httpx
  - Docker Compose `web` profile with `aptl-web-api` (172.20.0.40:8400) and `aptl-web-ui` (172.20.0.41:3000) services
  - Backend tests (`test_api_lab.py`, `test_api_scenarios.py`, `test_api_config.py`) and frontend API tests
  - ADR-011 status: proposed -> accepted

## [4.8.0] - 2026-03-20

### Added

- Architecture Decision Records (ADRs) section in docs with MADR-format template and 11 ADRs documenting all significant architectural decisions from v2.0.0 through v4.7.0 (#217)

## [4.7.0] - 2026-03-20

### Changed

- Upgraded CI actions to Node.js 24-compatible versions: `actions/checkout@v6`, `actions/setup-python@v6`, `actions/setup-node@v6` (#211)
- Migrated from deprecated `SonarSource/sonarcloud-github-action` to `SonarSource/sonarqube-scan-action@v7` (#211)

## [4.6.8] - 2026-03-20

### Fixed

- SonarCloud quality gate failing with 0% TypeScript coverage — CI workflow now runs vitest with coverage in `mcp/aptl-mcp-common/` before the SonarCloud scan, generating `lcov.info` that the existing sonar config already expects (#211)
- Added `mcp/aptl-mcp-common/tests` to `sonar.tests` so SonarCloud recognizes TS test files as test sources
- Fixed SonarCloud "can't be indexed twice" error — `mcp/**/tests/**` added to `sonar.exclusions` so test files under `mcp/` are excluded from source analysis while still indexed via `sonar.tests` (#211)

## [4.6.7] - 2026-03-08

### Fixed

- Persistent SSH sessions stranded callers on close/timeout — `cleanup()` now rejects all pending command promises and clears per-command timeouts (#189)

## [4.6.6] - 2026-03-08

### Fixed

- `aptl scenario stop` did not load project `.env` into `os.environ` before calling `assemble_run()` — collectors for Wazuh Indexer, TheHive, MISP, and Shuffle got empty-string fallbacks for API keys and silently skipped data collection, losing SOC telemetry (#184)
- Collector HTTP timeout was 20s — MISP and TheHive regularly exceed this on cold queries, causing silent data loss; raised to 120s to match test helper timeouts (#184)

## [4.6.5] - 2026-03-08

### Fixed

- `sync_manager_config()` cluster key regex vulnerable to polynomial backtracking (ReDoS) — replaced `re.DOTALL` regex with linear-time string search for `<cluster>` blocks (#183)

## [4.6.4] - 2026-03-08

### Fixed

- `sync_manager_config()` corrupted TLS config by replacing all `<key>` elements — regex now scoped to only match `<key>` inside `<cluster>` blocks, leaving `<indexer><ssl><key>` untouched (#183)

## [4.6.3] - 2026-03-08

### Fixed

- TheHive case collector missing `end_iso` upper bound — queries now use `_and` with both `_gte` and `_lte` filters on `_createdAt` so results exclude cases created after the scenario ended (#196)
- MISP event collector missing `end_iso` upper bound — added client-side post-filter on event timestamps since MISP `restSearch` only supports a lower-bound `timestamp` parameter (#196)

## [4.6.2] - 2026-03-08

### Fixed

- `aptl scenario start` now validates that all required lab profiles are enabled before starting a session — previously allowed starting scenarios with disabled containers, leading to impossible objectives (#195)

## [4.6.1] - 2026-03-08

### Fixed

- `ensure_ssl_certs()` hangs forever when sudo requires a password — added `sudo -n` (non-interactive) flag so it fails immediately instead of prompting (#194)
- `ensure_ssl_certs()` subprocess calls had no timeouts — added `timeout=300` for docker compose cert generation and `timeout=30` for sudo chown (#194)
- Improved error messages when sudo requires a password, with actionable guidance to run chown manually or configure passwordless sudo
- MISP healthcheck passed on 503 "MISP is loading..." because `curl -ks` without `-f` succeeds on any HTTP response — added `-f` flag and nginx reload on failure to recover from stale PHP-FPM socket after entrypoint init

## [4.6.0] - 2026-03-08

### Added

- Windows RE workstation setup scripts for automated tool installation (#116):
  - `setup-vs-buildtools.ps1` — Visual Studio 2022 Build Tools with C++ workload, Windows 11 SDK, Spectre-mitigated libraries
  - `setup-wdk.ps1` — Windows Driver Kit for kernel driver analysis (requires VS Build Tools)
  - `setup-ghidra.ps1` — Ghidra decompiler/disassembler with AdoptOpenJDK 17
  - `setup-x64dbg.ps1` — x64dbg/x32dbg debugger (portable)
  - `setup-sysinternals.ps1` — Full Sysinternals Suite with auto-EULA acceptance
  - `setup-python-re.ps1` — Python 3.12 with RE libraries (pefile, yara-python, capstone, unicorn, keystone-engine, floss, capa)
  - `setup-re-tools.ps1` — Orchestrator that runs all tools in dependency order with summary report

## [4.5.0] - 2026-03-08

### Added

- `aptl lab status --json` flag to output full range snapshot as JSON (#93)
- `aptl lab status --output FILE` flag to write JSON snapshot to file with 0600 permissions (#93)
- Per-container network IPs and port mappings in range snapshot
- Service endpoint discovery (Dashboard, Indexer, API) from running containers
- SSH endpoint discovery (victim, kali, reverse) from running containers

### Changed

- Lab orchestration step 11 now captures a range snapshot instead of generating a static text file
- SSH connectivity tests (step 10) now retry with `wait_for_service` (60s timeout, 5s interval) instead of single-shot

### Removed

- `connections.py` module — replaced by runtime snapshot with real Docker data
- `test_connections.py` — replaced by `test_snapshot_status.py`
- `lab_connections.txt` references from `.gitignore` and docs

### Fixed

- `check_manager_api_ready` always failed — `curl -f` exits 22 on 401, but Wazuh API uses token auth so root endpoint always returns 401 with basic auth. Now checks for any HTTP response instead
- SSH connectivity tests ran before containers were healthy, always reported failure
- `test_cli.py::test_stop_with_volumes_flag` now passes `--yes` to bypass data loss confirmation prompt
- SonarCloud reported 0% coverage — CI workflow never ran pytest before scanning. Added Python setup, dependency install, and `pytest --cov` step to `sonarcloud.yml`
- Added `[tool.coverage.xml]` output config to `pyproject.toml` so `coverage.xml` is generated for SonarQube

## [4.4.0] - 2026-03-07

### Fixed

- Documentation technical accuracy review across all 25 docs (#81):
  - Fixed wrong IPs throughout: victim 172.20.0.20→172.20.2.20, kali 172.20.0.30→172.20.4.30, Suricata .19→.50, MISP .15→.16, TheHive .16→.18, Cortex .18→.22, Shuffle .17→.20/.21, DNS .13→.22
  - Replaced flat 172.20.0.0/16 network references with correct 4-subnet architecture (security, dmz, internal, redteam)
  - Fixed `docker exec wazuh.manager` → `docker exec aptl-wazuh-manager` (and indexer/dashboard) in wazuh-siem.md
  - Fixed MCP server path `dist/index.js` → `build/index.js` in kali-redteam.md
  - Fixed broken link to nonexistent `wazuh-blueteam.md` in wazuh-siem.md
  - Fixed nonexistent `aptl_aptl-network` network name in victim-containers.md
  - Added missing `mcp-indexer` to README architecture diagram
  - Replaced `mcp-windows-re` (nonexistent) with `mcp-indexer` in enterprise-infrastructure.md
  - Marked 172.20.3.0/24 Endpoints subnet and Windows VM as not yet implemented in enterprise-infrastructure.md
  - Rewrote networking.md and architecture/index.md to reflect actual multi-network topology
  - Rewrote mcp-integration.md to include all 8 MCP servers
  - Fixed victim-template-guide.md IP subnet references

## [4.3.1] - 2026-03-07

### Added

- Data loss confirmation prompt when running `aptl lab stop -v` — warns about volume destruction and requires explicit confirmation; skip with `--yes`/`-y` (#171)

## [4.3.0] - 2026-03-07

### Added

- Static consistency tests (`tests/test_consistency.py`) validating docker-compose.yml container names, code references, profile config, and MCP build script coverage (#170)

## [4.2.3] - 2026-03-07

### Fixed

- `mcp/build-all-mcps.sh` only built 4 of 8 MCP servers — added mcp-wazuh, mcp-casemgmt, mcp-network, mcp-threatintel (#169)

## [4.2.2] - 2026-03-07

### Removed

- `start-lab.sh` — replaced by Python CLI `aptl lab start`; updated all documentation references (#168)

## [4.2.1] - 2026-03-07

### Fixed

- Wazuh services missing explicit `container_name` in docker-compose.yml — auto-generated names broke when repo cloned to non-`aptl` directory; updated all script and code references (#167)

## [4.2.0] - 2026-03-07

### Added

- SonarCloud integration for continuous code quality analysis — `sonar-project.properties` and `.github/workflows/sonarcloud.yml` (#165)

## [4.1.3] - 2026-03-07

### Fixed

- Wazuh archives index always empty — Filebeat wazuh module only had `alerts` fileset enabled; added `archives` fileset via `config/wazuh_cluster/filebeat_wazuh_module.yml` bind-mount (#140)

## [4.1.2] - 2026-03-07

### Fixed

- Victim container missing sshd log monitoring — ossec.conf template with `/var/log/secure` localfile entry now applied before agent starts (#139)

## [4.1.1] - 2026-03-07

### Added

- Range snapshot capture in experiment runs — records software versions, container state, Wazuh rules inventory, network config, and config file hashes as `snapshot.json` (#156)
- S3 export for experiment run data — `aptl runs export` packages runs as tar.gz with SHA-256 checksums, optional S3 upload via `--s3-bucket` with metadata tags (#157)
- `aptl[s3]` optional dependency group for boto3

### Fixed

- Snapshot used wrong container names (`aptl-wazuh-manager` → `aptl-wazuh.manager-1`) causing all Wazuh data to be empty
- Snapshot indexer version read from non-existent file; now extracted from opensearch jar filename

## [4.1.0] - 2026-03-02

### Added

- TechVault Enterprise prime research scenario (`scenarios/prime-enterprise.yaml`) — 11-step attack chain with full MITRE ATT&CK mapping
- Automated SOC tool seeding in `aptl lab start` (Step 13) via `scripts/seed-prime.sh`
- `--skip-seed` flag on `aptl lab start` to bypass SOC provisioning
- Seed scripts: `seed-misp.sh` (threat intel IOCs), `seed-shuffle.sh` (SOAR workflows), `thehive-apikey.sh` (API key provisioning)
- Workstation container with planted credential artifacts (SSH keys, .pgpass, .env, credentials.json, bash history)
- Run assembler and collector modules for post-scenario data collection
- MISP MCP server virtualenv with pymisp and mcp[cli]
- 587 tests (up from ~174), including full end-to-end SOC pipeline validation

### Fixed

- Suricata crash-loop: missing `SMTP_SERVERS`/`TELNET_SERVERS` vars in suricata.yaml; `eth0` interface not found in host mode. Switched to pcap mode on Docker networks
- Suricata local rules: unescaped pipe and semicolon chars in content matches
- TheHive-ES memory starvation: 256MB JVM heap in 512MB container caused Cassandra query timeouts. Doubled heap to 512MB, container limit to 1GB
- All SOC healthchecks standardized to `start_period: 300s`, `retries: 15` for reliable cold starts
- Wazuh Manager entrypoint patched to fix rule path loading (`patch-rule-path.py`)
- TheHive API key provisioning timeout (was 10s, takes ~24s on first run)

### Changed

- All test timeouts doubled across helpers, smoke tests, and integration tests for infrastructure reliability
- Suricata moved from `network_mode: host` to Docker networks (dmz, internal, security) with pcap capture

## [4.0.1] - 2026-02-22

### Added

- Full SOC stack integration: MISP threat intel, TheHive case management, Shuffle SOAR, Suricata IDS
- Enterprise infrastructure: Samba AD DC, PostgreSQL database, vulnerable webapp, file server
- 7 MCP servers operational: kali-ssh, reverse-sandbox-ssh, shuffle, indexer, wazuh, misp, thehive
- Automated test suites: `test_smoke.py` (20 tests) and `test_range_integration.py` (40 tests)
- Seed scripts for MISP (IOCs, attack patterns) and Shuffle (Alert-to-Case workflow)
- Range smoke test protocol with 3 validation layers (automated pytest, agent MCP, manual fallback)
- Prime scenario specification for research data collection (`scenarios/prime-scenario.md`)

### Fixed

- Wazuh `rules_summary` error 1201 caused by malformed decoder XML files
- TheHive 401 Unauthorized from org mismatch (`admin` -> `APTL`) in MCP config
- MISP `search_misp` Tag KeyError from PyMISP response format change
- MISP `get_misp_stats` calling non-existent `misp.stats()` method
- Indexer `params.index` override silently ignored due to hardcoded URL (added `{index}` template)
- Shuffle SOAR MCP built against non-existent single-execution API endpoint
- MCP common `api-handlers.ts` URL parameter substitution for `{key}` placeholders

### Removed

- `mcp-windows-re` server (container not deployed, functionality covered by reverse-sandbox-ssh)

## [4.0.0] - 2026-02-07

### Added

- Python CLI (`aptl lab start|stop|status`) porting start-lab.sh to a 12-step orchestration
- Core modules: ssh, sysreqs, credentials, certs, services, connections, lab, config, env
- 174 unit tests covering all new modules
- Docker image pre-pulling step before compose up for download progress visibility
- Shared container base scripts and configs in `containers/base/`

### Changed

- Victim and reverse containers refactored to use shared base layer
- MCP server entry points deduplicated via shared `startServer()` in aptl-mcp-common
- MCP tool handlers use typed argument interfaces
- AptlConfig now tolerates extra fields and optional lab section to match real aptl.json

### Removed

- Gaming API, Minetest, and Minecraft containers and MCP servers
- CTF scenarios
- Stale infrastructure (Terraform configs, QRadar files)
- Unenforced MCP config fields

### Fixed

- Wazuh Manager API port 55000 not mapped in docker-compose.yml, breaking `wazuh_create_detection_rule` MCP tool
- Regex injection in credential sync: passwords with `\1`, `$`, backslashes no longer corrupt config files
- Missing `--build` flag in compose up caused stale container images after Dockerfile changes
- Certificate generation reported `generated=False` when only chown failed after successful generation
- Connection info file written world-readable; now set to 0o600
- Missing public key existence check after ssh-keygen could crash with unhandled FileNotFoundError
- SSH key comment mismatch: Python used `aptl-lab` vs bash `aptl-local-lab`
- `lab_status` failed to parse NDJSON output from `docker compose ps --format json`
- `lab stop` was a no-op because compose down ran without profile flags
- Incorrect MCP paths throughout docs
- Wrong doc comment in mcp-reverse
- API handler referencing non-existent property

## [3.0.15] - 2026-02-03

### Added
- Basic CTF scenario setup script

## [3.0.14] - 2026-01-31

### Fixed
- systemd issues leading to Kali not starting

## [3.0.13] - 2025-11-17

### Fixed

- Wazuh agent version mismatch - pinned all agents to 4.12.0 to match manager version

## [3.0.12] - 2025-09-11

### Added

- Scenario resource: Gaming API database and data generation
- Scenario resource: Gaming API API endpoints

### Fixed

- Wazuh custom rules

## [3.0.11] - 2025-09-07

### Added

- Proxmox Windows VM deployment

## [3.0.10] - 2025-09-07

### Added

- Gaming API container with mock game server API
- Behavioural Analysis demo design

## [3.0.9] - 2025-09-03

### Added

- Behavioural analysis scenario support
- All MCPs build on each lab start

## [3.0.8] - 2025-09-03

### Added

- EDR agents are configurable
- Demo ctf scenario files
- Windows reverse engineering container in AWS
- MCP common library
- Consolidated mcps into `mcp/` directory

## [3.0.7] - 2025-09-01

### Fixed

- radare2 installation issue in reverse engineering container
- missing mcp-reverse files
- wrong port in mcp-reverse

## [3.0.6] - 2025-09-01

### Added

- Reverse engineering container and MCP
- Reverse engineering container guide
- Reverse engineering MCP server

### Changed

- Moved MCP servers to `mcp/` directory

## [3.0.5] - 2025-09-01

### Added

- Container configuration file for lab deployment

## [3.0.4] - 2025-08-31

### Added

- Add API tools to mcp common library
- Wazuh MCP server

## [3.0.3] - 2025-08-30

### Changed

- Made SSH MCP servers fully configuration driven
- Migrated SSH MCP server common code to `aptl-mcp-common` library

### Fixed

- Test coverage for `aptl-mcp-common` library

## [3.0.2] - 2025-08-30

### Changed

- Migrated mcp-red to use common library

## [3.0.1] - 2025-08-30

### Changed

- Extracted SSH session management to `aptl-mcp-common` library
- Migrated minetest-client MCP to use common library
- Fixed session metadata immutability bug
- Replaced synchronous file I/O with async
- Added timeout/buffer constants

## [3.0.0] - 2025-08-25

### Added

- Minetest server container and MCP
- Minetest client container and MCP
- Minecraft server container and MCP

### Fixed

- Syslog streaming to SIEM is now working for application logs
- Victim template guide instructions are now more clear

## [2.0.6] - 2025-08-25

### Added

- Kali container Wazuh agent with CLI command logging

## [2.0.5] - 2025-08-25

### Added

- Unit tests for mcp-red and mcp-blue
- ESLint and Prettier for both MCP servers
- JSDoc for key functions
- Zod IP address validation

### Fixed

- Extract command parsing from handleShellOutput

## [2.0.4] - 2025-08-24

### Added

- Falco runtime security monitoring with Modern eBPF in victim containers
- Wazuh rules for processing Falco alerts by priority level (Info through Emergency)
- Complete ossec.conf template replacing XML sed manipulation
- Single lab-install.service for coordinated installation
- Add basic CTF scenario setup script for integration testing

### Fixed

- Streamlined documentation

## [2.0.3] - 2025-08-23

### Added

- **mcp-red auto-targets Kali box** - this is a security and agent ergonomics feature.

### Fixed

## [2.0.2] - 2025-08-23

### Added

- **Wazuh Agent Installation**: Added Wazuh agent (monitor only)installation to victim container

### Fixed

- **Wazuh SIEM Configuration**: Fixed SIEM configuration to use correct port and IP address
  - Changed port from 514 to 1514
  - Changed IP address from 172.20.0.10 to 172.20.0.11

### Removed

- **Victim syslog streaming to SIEM**: Removed syslog streaming to SIEM

## [2.0.1] - 2025-08-15

### Added

- **Wazuh Blue Team MCP Server**: AI agent integration for SIEM operations
  - Query alerts and logs via OpenSearch API
  - Create custom detection rules
  - Get SIEM status and configuration

### Fixed

- Documentation cleanup and consistency improvements

## [2.0.0] - 2025-08-06

### Changed

- **Complete Architecture Overhaul**: Migrated from AWS/Terraform to local Docker deployment
  - Replaced AWS EC2 instances with Docker containers
  - Replaced qRadar Community Edition with Wazuh SIEM stack

- **SIEM Change**: Default SIEM changed to Wazuh for low-resource open-source local deployment

- **Documentation Updates**: Updated to reflect new Docker infrastructure
  - All commands updated for Docker environment
  - MkDocs documentation structure

- **Container Architecture**: Five-container Docker Compose deployment

### Removed

- All AWS/Terraform infrastructure code
- qRadar Community Edition integration

### Breaking Changes

- Complete deployment model change from AWS to Docker
- Different network addressing scheme
- New access methods (SSH port forwarding vs AWS)
- SIEM interface change (Wazuh vs qRadar)

## [1.1.6] - 2025-07-30

### Added

- **Possible Game CTF Scenarios**: Added notes for possible game CTF scenarios
  - MC bleedingpipe - picking on MC is a crime
  - phpBB cred stuffing - picking on php is not
  - capcom.sys driver - oldie but a goodie

### Fixed

- **Kali Dockerfile**: Properly bootstrap GPG keyring without insecure flags
  - Removed dangerous `--allow-insecure-repositories` and `--allow-unauthenticated` flags
  - Simplified keyring setup by using pre-installed keyring in base image
  - Ensured proper keyring update before package installation

## [1.1.5] - 2025-07-28

### Security

- **Network Isolation**: Enhanced security for AI red team operations to prevent unintended external access
  - Removed internet gateway access from Kali and victim instances to contain automated activities
  - Implemented internal-only communication between lab instances using security group references
  - Preserved SIEM internet access for updates and licensing requirements
  - Maintained admin SSH access through bastion host for troubleshooting and management

### Fixed

- **Network Module Dependencies**: Resolved circular dependency issues in security group configurations
  - Separated security group rules into explicit resources to break circular references
  - Improved terraform planning and apply reliability for network infrastructure
  - Enhanced network module maintainability and extensibility

### Technical Notes

- Network isolation specifically designed for autonomous AI red team scenarios
- Lab instances can communicate internally but cannot initiate external connections
- SIEM maintains external connectivity for proper security monitoring functionality
- All existing functionality preserved with enhanced security boundaries
- Added explicit protocol support (TCP, UDP, ICMP, ESP, AH, GRE) and comprehensive admin access for all scenario types

## [1.1.4] - 2025-07-27

### Added

- **VitePress Documentation Site**: Complete documentation infrastructure with modern static site generation
  - Professional documentation site with navigation, search, and responsive design
  - Mermaid diagram support for architecture visualization
  - Optimized for GitHub Pages deployment with proper base path configuration
- **Comprehensive Documentation Restructure**: Broke down monolithic README into focused, topic-specific guides
  - `getting-started.md` - Prerequisites, setup process, cost estimation, and security considerations
  - `deployment.md` - Infrastructure deployment steps, timing, access details, and cleanup procedures
  - `qradar-setup.md` - qRadar installation, configuration, and red team logging setup
  - `red-team-mcp.md` - Kali MCP server setup, AI client configuration, and available tools
  - `exercises.md` - Purple team exercises, MITRE ATT&CK techniques, and simulation scripts
  - `ai-red-teaming.md` - Autonomous attack demonstrations and AI agent configuration
  - `architecture.md` - Detailed system design, network topology, and component descriptions
  - `troubleshooting.md` - Common issues, debugging procedures, and resolution steps

### Changed

- **README Focus**: Restructured main README to emphasize autonomous cyber operations purpose
  - Clear articulation of blue team practice and autonomous cyber weapons awareness objectives
  - Emphasis on educational demonstration of AI-driven attack capabilities
  - Direct links to comprehensive documentation site for technical details
  - Streamlined content removing duplication with detailed documentation pages
- **Technical Tone**: Adjusted documentation tone to be more professional and technical
  - Removed marketing-style language in favor of neutral, technical descriptions
  - Maintained focus on educational and awareness objectives
  - Improved clarity and precision in technical explanations

### Technical Notes

- All content functionally equivalent to original README with improved organization
- GitHub Pages integration with proper link structure to VitePress site
- Documentation site available at `https://brad-edwards.github.io/aptl/`
- Preserved all commands, scripts, and technical procedures without modification

## [1.1.3] - 2025-07-26

### Added

- **Cursor IDE Integration**: Development environment configuration for enhanced AI assistant support
  - `.cursor/environment.json` for automated dependency installation and MCP server building
  - `.cursor/mcp.json` for red team MCP server integration with proper absolute paths
  - `.cursor/rules/no-jumping-ahead.mdc` for AI assistant behavior guidelines and technical writing standards

### Changed

- **Git Ignore Updates**: Modified `.gitignore` to selectively include Cursor configuration files
  - Added specific inclusions for `.cursor/environment.json`, `.cursor/mcp.json`, and `.cursor/rules/`
  - Maintained exclusion of other `.cursor/` files for privacy

## [1.1.2] - 2025-07-26

### Security

- **S3 Bucket Enumeration Protection**: Enhanced infrastructure security to prevent cost exploitation attacks
  - Implemented UUID-based naming for all S3 buckets to prevent predictable bucket enumeration
  - Bootstrap bucket: `aptl-bootstrap-${uuid}` instead of predictable names
  - Main infrastructure bucket: `aptl-main-${uuid}` for state storage
  - DynamoDB tables also use UUID suffixes for consistency
- **Separate State Storage**: Implemented isolated S3 buckets for different infrastructure components
  - Bootstrap infrastructure manages its own state bucket
  - Main infrastructure manages its own separate state bucket
  - No hardcoded bucket names in repository code

### Added

- **State Migration Automation**: Helper scripts for seamless S3 state migration
  - `create_backend.sh` scripts in both bootstrap and main infrastructure directories
  - Automated backend.tf generation from terraform outputs
  - Simplified workflow: deploy → create backend → migrate state

### Changed

- **Required Deployment Workflow**: Updated to use separate S3 buckets with UUID naming
  1. Deploy bootstrap: `terraform apply` → `./create_backend.sh` → `terraform init -migrate-state`
  2. Deploy main infrastructure: `terraform apply` → `./create_backend.sh` → `terraform init -migrate-state`
- **Random Provider**: Added HashiCorp random provider to both bootstrap and main infrastructure
- **Backend Configuration**: Each component creates and manages its own S3 backend

### Technical Notes

- All bucket names use UUIDs generated at deployment time
- No breaking changes to existing variable names or module interfaces
- State storage is fully isolated between bootstrap and main infrastructure
- Migration scripts handle the complexity of moving from local to S3 state

## [1.1.1] - 2025-07-24

### Changed

- **qRadar-Only Deployment**: Simplified SIEM selection to use qRadar Community Edition as the default and primary option
  - Changed `siem_type` default from "splunk" to "qradar" in terraform.tfvars.example and variables.tf
  - Updated documentation to present qRadar as the single SIEM option
  - Preserved all Splunk infrastructure code for potential future re-enablement
- **Documentation Updates**: Removed multi-SIEM references and Splunk-specific sections from README.md and CLAUDE.md
  - Streamlined installation instructions to focus on qRadar workflow
  - Updated cost estimates to reflect qRadar-only deployment (~$287/month)
  - Removed Splunk integration from roadmap (feature already implemented but de-emphasized)

### Technical Notes

- All Splunk modules, variables, and conditional logic preserved in codebase
- No breaking changes to existing terraform configuration
- Users can still manually set `siem_type = "splunk"` if needed
- Validation continues to accept both "splunk" and "qradar" values

## [1.1.0] - 2025-06-07

### Added

- **Splunk Enterprise Security support**: Alternative to qRadar using c5.4xlarge instance
  - SIEM selection via `siem_type` variable in terraform.tfvars
  - Automated Splunk installation and configuration scripts
  - Pre-configured `keplerops-aptl-redteam` index for red team log separation
- **Kali red team activity logging**: Structured logging of attack commands and network activities
  - `log_redteam_command()`, `log_redteam_network()`, `log_redteam_auth()` functions
  - SIEM-specific rsyslog routing (port 5514 for Splunk, 514 for qRadar)
  - Attack simulation scripts: `simulate_redteam_operations.sh`, `simulate_port_scan.sh`
  - Structured log fields: RedTeamActivity, RedTeamCommand, RedTeamTarget, RedTeamResult

### Changed

- Updated Splunk version references to use current 9.4.x series downloads
- Enhanced Kali Linux instance configuration with red team logging integration
- Improved SIEM configuration scripts for both platforms

### Fixed

- Outdated Splunk download URLs causing 404 errors during installation
- MCP server terraform path resolution issues after infrastructure reorganization
- Template syntax errors in Kali user_data script

## [1.0.1] - 2025-06-03

### Added

- **Kali Linux Red Team Instance**: New t3.micro Kali Linux instance for red team operations
- **Model Context Protocol (MCP) Server**: AI-powered red team tool integration
  - `kali_info` tool for lab instance information
  - `run_command` tool for remote command execution on lab targets
  - TypeScript implementation with full test suite
  - Integration with VS Code/Cursor and Cline AI assistants
- **Enhanced Security Groups**: Precise traffic rules for realistic attack scenarios
  - Kali can attack victim on all ports
  - Kali and victim can send logs to SIEM
  - Removed overly broad subnet-wide access
- **Documentation Updates**:
  - Architecture diagram with attack flow visualization
  - MCP setup instructions for both Cursor and Cline
  - Project-local configuration examples

### Fixed

- Terraform path resolution issues in MCP server
- JSON configuration syntax errors in project settings
- Inter-instance connectivity for red team exercises

## [1.0.0] - 2025-06-01

### Added

- Complete Terraform automation for AWS deployment
- VPC with public subnet and security groups configuration
- IBM qRadar Community Edition 7.5 SIEM setup automation
- RHEL 9.6 victim machine with automated log forwarding
- System preparation and installation scripts for qRadar
- Pre-built security event generators
- MITRE ATT&CK technique simulators (T1078, T1110, T1021, T1055, T1003, T1562)
- Brute force and lateral movement attack scenarios
- Connection verification and debugging tools
- AI Red Team Agent integration with Cline/Cursor
- Documentation for AI-powered autonomous red teaming
- Complete setup and deployment guide
- Troubleshooting documentation with common issues
- Cost estimation and security considerations
- SPDX license headers (BUSL-1.1) throughout codebase
- Legal disclaimer and usage warnings
- Roadmap for upcoming features

### Known Issues

- qRadar CE limited to 5,000 EPS and 30-day trial license
- Manual ISO transfer required (~5GB file size)
- Installation process takes 1-2 hours
- High operational cost (~$280/month if left running continuously)

### Security

- Access restricted to single IP address via security groups
- Isolated VPC environment for contained testing
- Automated SSH key configuration
- Minimal attack surface on victim machine
