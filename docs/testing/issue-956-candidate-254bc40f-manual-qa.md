# Issue 956 release-candidate manual QA — 2026-09-20

This is an operator-assisted execution record for
[`smoke-test-plan.md`](smoke-test-plan.md) against the exact head of
[PR #1110](https://github.com/Brad-Edwards/aptl/pull/1110). It is not release
approval: a human operator still has to review the evidence and sign off the
manual gate before merge. Earlier wheel runs against `6514ea0b` and
`1685c887` are diagnostic history, not substituted for either result below.

## Candidate and environment

| Field | Value |
| --- | --- |
| Release version | `5.5.0` |
| Release PR / tested head | `#1110` / `254bc40f3c94d020045ae75216efcbc343afda53` |
| Wheel / SHA-256 | `aptl_labs-5.5.0-py3-none-any.whl` / `57547cc1e45ad33c7faf825b82e6b81ba1d737c77ee3b76e93ccc8e4bfd18221` |
| Sdist / SHA-256 | `aptl_labs-5.5.0.tar.gz` / `72a5ea494ebf73e8457d496d263d7f1f79bee3841ba5c5710213c027644b1251` |
| RAES pack | `techvault` `0.1.0`, set digest `sha256:db98a9daa62a092a0c6b001217027d7f4ad489889e95d01050e77f148e8ef29b` |
| Host | Ubuntu 24.04, x86_64; Python 3.12.3; Docker Engine 29.5.0; Compose 5.1.3 |
| Distribution project | `/tmp/aptl-956-finalqa.9rlEpA/head254-a-project`, initialized by the exact wheel in a fresh venv |
| Source checkout | `/tmp/aptl-956-finalqa.9rlEpA/head254-b-source`, fresh GitHub clone detached at the tested head |
| Evidence location | Local QA projects above; only bounded, reviewed observations are reproduced here |
| Primary operator | Operator-assisted CLI, MCP-protocol, and strict-TLS browser exercise; human release sign-off pending |
| Time zone | Europe/Berlin (UTC+02:00); event timestamps below are UTC |
| QA start / finish | 2026-09-20 02:14–02:56 CEST |

The local screenshots, browser profiles, generated configuration, and raw run
bundles are not published: they require separate redaction review. This record
contains credential-free observations and stable identifiers that reviewers can
compare with the local evidence. Neither `.env` nor browser storage is included.

## Path A — exact wheel

The installed wheel reported `aptl 5.5.0` and `raes 5.0.0`. Its startup run
was `run_20260920T001432Z`; the project prefix was `aptl-w693e66892150`.

| ID | Result | Actual observation | Evidence |
| --- | --- | --- | --- |
| QA-START | PASS | `aptl lab start` exited 0 and reported “Lab is ready”; plain and JSON status showed 28 running project containers, with no MCP-endpoint container; runs list named the canonical startup run. | A01 |
| QA-LIVE | PASS | The same run passed all nine live-gate checks. | A02 |
| QA-WAZUH | PASS | Strict-TLS browser login showed eight active and zero disconnected agents; Threat Hunting displayed 1,097 recent alerts. | A03 |
| QA-DETECT | PASS | MCP Kali SQLi returned HTTP 200 and produced Wazuh rule `302010` on the webapp agent. | A04 |
| QA-SURICATA | PASS | The sensor-namespace request returned HTTP 200; Suricata signature `1000010` reached Wazuh as rule `303020`. | A05 |
| QA-SOAR | PASS | Shuffle executed the exact A04 alert, finished with two successful actions, and created a linked TheHive case. | A06 |
| QA-CASE | PASS | The case retained that alert, accepted a source-IP observable, and a strict-TLS UI-launched Cortex analyzer job succeeded. | A07 |
| QA-MISP | PASS | Strict-TLS browser login at the canonical MISP origin showed seeded event #1 and the indicator; MCP read back attribute #1. | A08 |
| QA-MCP-RED | PASS | `kali_info` returned target metadata and `kali_run_command whoami` returned `kali`. | A09 |
| QA-MCP-WAZUH | PASS | A time-bounded MCP query retrieved the exact A04 alert and rule. | A10 |
| QA-MCP-INDEXER | PASS | A time-bounded MCP query retrieved the same indexed document. | A11 |
| QA-MCP-SOAR | PASS | MCP listed and retrieved the seeded workflow and confirmed the terminal real-alert execution. | A06 |
| QA-MCP-CASE | PASS | MCP listed the linked case and added its source-IP observable. | A07 |
| QA-MCP-TI | PASS | MCP found `ip-src` `172.20.4.30` in event #1, attribute #1. | A08 |
| QA-MCP-NET | PASS | A time-bounded MCP query found A05's Suricata/Wazuh event and signature. | A12 |
| QA-MCP-REVERSE | PASS | The shipped server completed MCP initialize/list/call and returned structured `expected-unavailable` for the deliberately omitted reverse target. | A13 |
| QA-ARCHIVE | PASS | The startup run was shown, its 15-member bundle exported, and independent verification succeeded with unsealed limitations disclosed. | A14 |
| QA-TEARDOWN | PASS | Scoped stop and project teardown assertion found no owned containers, networks, or volumes. | A15 |

### Path-A bounded observations

- **A01** — `qa-start.txt` ends in `Lab is ready.`; `qa-start-status.txt`
  accounts for 28 running project containers, and `qa-start-status.json` has
  the matching inventory. `qa-start-runs.txt` names
  `run_20260920T001432Z`. No `aptl-mcp-endpoints` container appears.
- **A02** — `qa-live.txt`: `scenario=techvault backend=aptl
  plugin=techvault from aptl-labs==5.5.0: PASSED`, including defensive-stack
  readiness and runtime-orchestration containment.
- **A03** — Browser TLS verification stayed enabled. Wazuh showed
  `Active (8)`, `Disconnected (0)` and the Threat Hunting dashboard's
  1,097 total alerts in the last 24 hours.
- **A04** — MCP action at `2026-09-20T00:28:47–49Z`: Kali target
  `172.20.1.30`, exit 0, HTTP 200. Wazuh hit `K7g3vKABCzMrdCXPPFpz`
  at `00:28:49.610Z`, rule `302010`, agent `techvault-webapp-agent`.
- **A05** — Sensor request at `00:29:13Z` returned HTTP 200. Suricata
  reported source `172.20.1.128`, destination `172.20.1.20`, signature
  `1000010`; Wazuh hit `LLg3vKABCzMrdCXPnloQ` at `00:29:15.210Z`
  with rule `303020` on `techvault-suricata-agent`.
- **A06** — Workflow `65199028-d34d-48d8-987c-5e0d23b4b47d`, execution
  `badd510c-dff3-4202-bce1-0dd2398ee446`: the input contained A04's exact
  alert and rule; terminal state `FINISHED` with two `SUCCESS` actions. Case
  `~3977352` linked the alert and rule.
- **A07** — MCP added observable `~4305056`, type `ip`, value
  `172.20.1.30`. TheHive UI launched `TechVaultScenarioContext`; Cortex job
  `zH84vKABnb9aRBjrxSBB` completed `Success`, and the observable acquired
  its analyzer report.
- **A08** — Canonical `https://misp.techvault.local/` authenticated with
  valid TLS and showed `APTL Lab - Known Threat Actors` event #1 with
  `172.20.4.30`. MCP returned `ip-src`, event id `1`, attribute id `1`.
- **A09–A12** — Target-backed MCP red, Wazuh, indexer, SOAR, threat-intel,
  and network calls returned HTTP 200 or a successful target command. The
  Wazuh/indexer query used `00:28:45–55Z`; the network query used
  `00:29:10–20Z` and found signature `1000010`.
- **A13** — Full MCP protocol call to shipped `mcp-reverse` returned
  `{"outcome":"expected-unavailable","operation":"reverse_run_command"}`;
  A01 inventory had no reverse target.
- **A14** — Manifest identifies TechVault, backend `aptl`, package `5.5.0`,
  pack `techvault` `0.1.0`, A01's Suricata container and A02's passed live
  gate. Export root
  `sha256:4007af1c901c40f37cc49d15aee68c261e287a693af3c9ab7d3cc1fb18b02f7e`,
  15 members; `verify-bundle` returned `OK: bundle verified`. This is an
  **unsealed startup bundle**: no #444 seal or
  `provenance/run-provenance.json` is claimed.
- **A15** — `Lab stopped successfully.` and
  `Project 'aptl': no containers, networks, or volumes remain.` The two
  path-A browser trust entries were then removed.

## Path B — exact source commit

The clean GitHub checkout was detached at the exact PR head before any
generated files existed. A fresh editable venv reported `aptl 5.5.0` and
`raes 5.0.0`. The startup run was `run_20260920T003540Z`; the project prefix
was `aptl-wdc2fe6d41dfb`.

| ID | Result | Actual observation | Evidence |
| --- | --- | --- | --- |
| QA-START | PASS | Source `aptl lab start` exited 0 and reported “Lab is ready”; plain and JSON status showed 28 running containers and no MCP-endpoint container; runs list named the new startup run. | B01 |
| QA-LIVE | PASS | The path-B run passed all nine live-gate checks. | B02 |
| QA-WAZUH | PASS | Strict-TLS browser login showed eight active and zero disconnected agents; Threat Hunting displayed 1,097 recent alerts. | B03 |
| QA-DETECT | PASS | Source-path MCP Kali SQLi returned HTTP 200 and produced a new Wazuh rule `302010` alert. | B04 |
| QA-SURICATA | PASS | A separate sensor-namespace request returned HTTP 200; Suricata signature `1000010` reached Wazuh as rule `303020`. | B05 |
| QA-SOAR | PASS | Shuffle executed the exact B04 alert and finished with two successful actions; the linked TheHive case was visible. | B06 |
| QA-CASE | PASS | The source-path case retained alert linkage and source-IP observable; the Cortex analyzer succeeded and its report was visible in TheHive UI. | B07 |
| QA-MISP | PASS | Strict-TLS browser login at the canonical MISP origin showed seeded event #1 and its indicator; MCP read back attribute #1. | B08 |
| QA-MCP-RED | PASS | `kali_info` returned target metadata and `kali_run_command whoami` returned `kali`. | B09 |
| QA-MCP-WAZUH | PASS | A time-bounded MCP query retrieved the exact B04 alert and rule. | B10 |
| QA-MCP-INDEXER | PASS | A time-bounded MCP query retrieved the same indexed document. | B11 |
| QA-MCP-SOAR | PASS | MCP listed and retrieved the seeded workflow and confirmed the terminal real-alert execution. | B06 |
| QA-MCP-CASE | PASS | MCP listed the linked case and added its source-IP observable. | B07 |
| QA-MCP-TI | PASS | MCP found `ip-src` `172.20.4.30` in event #1, attribute #1. | B08 |
| QA-MCP-NET | PASS | A time-bounded MCP query found B05's Suricata/Wazuh event and signature. | B12 |
| QA-MCP-REVERSE | PASS | The shipped server completed MCP initialize/list/call and returned structured `expected-unavailable` for the deliberately omitted reverse target. | B13 |
| QA-ARCHIVE | PASS | The path-B startup run was shown, its 15-member bundle exported, and independent verification succeeded with unsealed limitations disclosed. | B14 |
| QA-TEARDOWN | PASS | Scoped stop and project teardown assertion found no owned containers, networks, or volumes. | B15 |

### Path-B bounded observations

- **B01** — `qa-start.txt` ends in `Lab is ready.`; `qa-start-status.txt`
  and `qa-start-status.json` account for 28 running containers, with no
  `aptl-mcp-endpoints`. `qa-start-runs.txt` names
  `run_20260920T003540Z`. Before startup, the checkout was clean and detached
  at `254bc40f3c94d020045ae75216efcbc343afda53`.
- **B02** — `qa-live.txt`: `scenario=techvault backend=aptl
  plugin=techvault from aptl-labs==5.5.0: PASSED` with all nine checks,
  including defensive-stack readiness and runtime-orchestration containment.
  A separate absolute-path source-venv probe, with only `/usr/bin:/bin` on
  `PATH`, returned `0 raes 5.0.0`; the CLI does not depend on venv `PATH`
  activation to find its companion RAES executable.
- **B03** — Browser TLS verification stayed enabled. Wazuh showed
  `Active (8)`, `Disconnected (0)` and 1,097 Threat Hunting alerts in the last
  24 hours.
- **B04** — MCP action at `2026-09-20T00:51:33–35Z`: Kali target
  `172.20.1.30`, exit 0, HTTP 200. Wazuh hit `lRZMvKABGjg9Zj4fLLi8`
  at `00:51:36.727Z`, rule `302010`, agent `techvault-webapp-agent`.
- **B05** — Sensor request at `00:52:02Z` returned HTTP 200. Suricata
  reported source `172.20.1.128`, destination `172.20.1.20`, signature
  `1000010`; Wazuh hit `lxZMvKABGjg9Zj4fjrha` at `00:52:04.212Z`
  with rule `303020` on `techvault-suricata-agent`.
- **B06** — Workflow `e049052c-6c7d-44ce-ab82-16965bc5ed92`, execution
  `2b3b9440-34f4-4964-a8f9-ebfd53319e08`: its input contained B04's
  exact alert and rule; terminal state `FINISHED` with two `SUCCESS` actions.
  Case `~8224768` linked the alert and rule.
- **B07** — MCP added observable `~8171760`, type `ip`, value
  `172.20.1.30`. TheHive UI launched `TechVaultScenarioContext`; Cortex job
  `uQdNvKABaJpUmtdtv4Pc` completed `Success`. Reopening the case in the
  strict-TLS browser showed its `Analysis report` and the scenario-context
  result `TechVault:ScenarioAttacker="1"`.
- **B08** — Canonical `https://misp.techvault.local/` authenticated with
  valid TLS and showed `APTL Lab - Known Threat Actors` event #1 with
  `172.20.4.30`. MCP returned `ip-src`, event id `1`, attribute id `1`.
- **B09–B12** — Target-backed MCP red, Wazuh, indexer, SOAR, threat-intel,
  and network calls returned HTTP 200 or a successful target command. The
  Wazuh/indexer query used `00:51:30–40Z`; the network query used
  `00:52:00–10Z` and found signature `1000010`.
- **B13** — Full MCP protocol call to shipped `mcp-reverse` returned
  `{"outcome":"expected-unavailable","operation":"reverse_run_command"}`;
  B01 inventory had no reverse target.
- **B14** — Manifest identifies TechVault, backend `aptl`, package `5.5.0`,
  pack `techvault` `0.1.0`, B01's Suricata container and B02's passed live
  gate. Export root
  `sha256:141cf828bbdc7d1ec084b1fd565cacffe3f481799155b9ced6e2e81f40659a6e`,
  15 members; `verify-bundle` returned `OK: bundle verified`. This is an
  **unsealed startup bundle**: no #444 seal or
  `provenance/run-provenance.json` is claimed.
- **B15** — `Lab stopped successfully.` and
  `Project 'aptl': no containers, networks, or volumes remain.` The two
  path-B browser trust entries were then removed.

## Release decision

Both installation paths passed all 18 required rows against the immutable
`254bc40f` head and artifact hashes above. All 37 PR checks passed, including
the full Python coverage suite, cross-platform smoke checks, SonarCloud's
new-issue gate, and clean-install lab boot/teardown. The code PR is mergeable
but remains a draft. Human evidence review and release sign-off are still
required; this document does not authorize merging or publishing.
