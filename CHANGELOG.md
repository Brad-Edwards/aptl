
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.10.0] - 2026-03-21

### Added

- In-browser terminal for container SSH access via xterm.js and WebSocket (#221):
  - WebSocket endpoint `ws /api/terminal/ws/{container}` with asyncssh PTY relay for victim, kali, and reverse containers
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
