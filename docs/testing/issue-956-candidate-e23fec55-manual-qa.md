# Issue 956 candidate manual QA: 2026-09-20

This is an operator-assisted execution record for the procedure in
[`smoke-test-plan.md`](smoke-test-plan.md). It tests candidate commit
`e23fec55fef3e0088ec3dd1e922c71cd335b5862`; it is not a release approval.
No release PR was open at the time of this run, so the release decision remains
**BLOCK** even if both installation paths pass. A release PR whose head or
artifacts differ from this candidate requires both paths to be repeated.
The procedure calls for a person to execute and sign off the manual gate;
this automation-assisted run does not replace that human approval.

## Candidate and environment

| Field | Value |
| --- | --- |
| Release version | `5.5.0` |
| Release PR / tested head | No release PR; `e23fec55fef3e0088ec3dd1e922c71cd335b5862` on `956-manual-qa-repair` |
| Wheel / SHA-256 | `aptl_labs-5.5.0-py3-none-any.whl` / `9affea44c6f886ee172ac680d33aba4ea8d259de9ec3a9d9dabb1d47a787429d` |
| Sdist / SHA-256 | `aptl_labs-5.5.0.tar.gz` / `2cdcb24366cf8dbf6544b84933b9db97eb719b702d18d8772256aa40e76256c4` |
| RAES pack | `techvault` `0.1.0`, set digest `sha256:db98a9daa62a092a0c6b001217027d7f4ad489889e95d01050e77f148e8ef29b` |
| Host | Ubuntu 24.04, x86_64; Python 3.12.3; Docker Engine 29.5.0; Compose 5.1.3 |
| Distribution project | `/tmp/aptl-956-manualqa.YGfzGd/repair5-a-project` (new `aptl lab init` directory; exact wheel installed in a separate new venv) |
| Source checkout | `/tmp/aptl-956-manualqa.YGfzGd/repair5-b-source` (fresh GitHub clone, detached at tested head; `pip install -e '.[dev]'` in a new venv) |
| Operator | Automation-assisted candidate rehearsal using the shipped CLI, MCP protocol driver, and strict-TLS Chromium UI sessions; human release sign-off pending |
| QA time zone | Europe/Berlin (UTC+02:00); event times below are UTC |
| QA start / finish | 2026-09-20 00:14:23–00:55:38 CEST (from first run id to final candidate/hash check) |

Only bounded, credential-free observations are reproduced here. The source
screenshots, browser profiles, lab-generated configuration, and raw run bundle
were kept in the local QA workspace, **not** attached or published; they require
separate review and redaction before external distribution. Evidence IDs below
refer to the command/result excerpts in this document, not to a claim that
unredacted local files are safe to publish. The local QA workspace is
ephemeral, so these excerpts are the durable release-review evidence.
The operator named above performed every row. Event-level UTC timestamps
appear in the numbered excerpts. For UI and command-only observations, the
path-A work was captured on 2026-09-20 from 00:14 to 00:33 CEST and path B
from 00:36 to 00:55 CEST; the browser capture times were A: Wazuh 00:27,
TheHive from 00:28 to 00:29, MISP 00:29; B: Wazuh from 00:49 to 00:50,
TheHive 00:52, MISP 00:53.

## Path A: candidate wheel

Start run: `run_20260919T221423Z`. Its 28-container project was
`aptl-wd6bf2dbd460e`. The exact installed version was `aptl 5.5.0`.

| ID | Result | Actual observation | Evidence |
| --- | --- | --- | --- |
| QA-START | PASS | `aptl lab start` exited 0, reported “Lab is ready”; JSON inventory contained 28 running containers, no MCP endpoint container; `aptl runs list` showed the canonical run. | A01 |
| QA-LIVE | PASS | Same run passed all nine RAES live-gate checks. | A02 |
| QA-WAZUH | PASS | Strict-TLS Chromium login at `https://wazuh.dashboard:443` showed 8 active agents and 1,095 recent alerts; Threat Hunting loaded. | A03 |
| QA-DETECT | PASS | MCP `kali_run_command` sent SQLi from `172.20.1.30`, received HTTP 200, and Wazuh indexed rule `302010` on the webapp agent. | A04 |
| QA-SURICATA | PASS | Sensor namespace request returned HTTP 200; Suricata signature `1000010` was forwarded as Wazuh rule `303020`. | A05 |
| QA-SOAR | PASS | Seeded Shuffle workflow executed the exact A04 alert and finished with two successful actions; downstream TheHive case linked the alert. | A06 |
| QA-CASE | PASS | TheHive case retained alert relationship; source-IP observable was added; strict-TLS UI launched `TechVaultScenarioContext`; Cortex job succeeded and UI report appeared. | A07 |
| QA-MISP | PASS | Strict-TLS browser on authored `https://misp.techvault.local` showed seeded event #1 and indicator; MCP read back exact attribute #1. | A08 |
| QA-MCP-RED | PASS | `kali_info` responded and `kali_run_command whoami` returned `kali` from realized target. | A09 |
| QA-MCP-WAZUH | PASS | `wazuh_query_alerts` retrieved exact A04 alert and rule `302010`. | A10 |
| QA-MCP-INDEXER | PASS | Time-bounded `indexer_query` retrieved exact A04 document. | A11 |
| QA-MCP-SOAR | PASS | MCP listed the seeded workflow and the real-alert execution, including its terminal state. | A06 |
| QA-MCP-CASE | PASS | MCP listed the linked case and added its source-IP observable. | A07 |
| QA-MCP-TI | PASS | MCP found `ip-src` `172.20.4.30`, event #1, attribute #1. | A08 |
| QA-MCP-NET | PASS | Time-bounded `network_query_ids_alerts` found Wazuh rule `303020` with signature `1000010`. | A12 |
| QA-MCP-REVERSE | PASS | Production protocol call returned structured `expected-unavailable`; the scenario intentionally has no reverse target. | A13 |
| QA-ARCHIVE | PASS | Canonical run shown; exported 15-member bundle; independent verification succeeded. Export is explicitly unsealed and missing run-provenance (not misrepresented as a sealed release artifact). | A14 |
| QA-TEARDOWN | PASS | `aptl lab stop -v -y` exited 0, then the project-scoped teardown assertion reported no remaining containers, networks, or volumes. | A15 |

### Path-A bounded observations

- **A01**: CLI: `Lab is ready.`; `aptl runs list`:
  `run_20260919T221423Z techvault.sdl.yaml 2026-09-19T22:23:35`.
  `qa-start-status.json` held 28 entries, all with status `Up ...` and none
  named `aptl-mcp-endpoints`. Its Wazuh publication was
  `127.0.0.1:443->5601/tcp`; MISP's security-network address was
  `172.20.0.134`. The plain-text `aptl lab status` form was not separately
  captured; the complete JSON inventory was.
- **A02**: Scenario verification reported `scenario=techvault backend=aptl
  plugin=techvault from aptl-labs==5.5.0: PASSED`; all nine listed checks,
  including defensive-stack readiness and runtime containment, were `passed`.
- **A03**: Chromium (certificate validation enabled) after login:
  `Active (8)`, `Disconnected (0)`, `1,049` low alerts; Threat Hunting
  displayed `1,095` total alerts in the last 24 hours.
- **A04**: MCP action 2026-09-19T22:27:35–37Z: target
  `172.20.1.30`, exit `0`, HTTP `200`; index hit
  `JpfIu6ABi5eqXjMPYcjG` at `22:27:37.516Z`, rule `302010`, agent
  `techvault-webapp-agent`.
- **A05**: Sensor request at `22:27:58Z`, HTTP `200`; Suricata alert
  `22:27:58.983466+0000`, flow `1967697202781802`, source
  `172.20.1.128`, destination `172.20.1.20`, signature `1000010`;
  Wazuh hit `KZfIu6ABi5eqXjMPnMhU` at `22:27:59.896Z`, rule `303020`,
  agent `techvault-suricata-agent`.
- **A06**: Workflow `ecc3b203-ecf6-43ce-bf09-2ae2deef6486`, execution
  `fbe73a1b-37f1-4f2a-9b94-d6396e85dedd`: input alert A04 and rule
  `302010`; execution `FINISHED`, two `SUCCESS` action results. Case
  `~4042752` description contained the exact alert ID and rule.
- **A07**: MCP returned observable `~4046848`, type `ip`, value
  `172.20.1.30`; TheHive UI case #1 launched analyzer
  `TechVaultScenarioContext`. Cortex job `AjrJu6ABDMOPgKvxk-uv` was
  `Success` for that IP; UI showed `Analysis report` and
  `TechVault:ScenarioAttacker="1"`.
- **A08**: Browser authenticated at canonical MISP origin and showed
  `Event #1` with seeded name `APTL Lab - Known Threat Actors` and
  `172.20.4.30`. MCP `threatintel_search_iocs` returned `ip-src`, value
  `172.20.4.30`, event id `1`, attribute id `1`.
- **A09**: `kali_info` responded with target metadata; `whoami` was a
  successful MCP command, exit `0`, identity `kali`. MCP-side sessions were
  written under configured `runs/run_20260919T221423Z/mcp-side/sessions/`.
- **A10**: `wazuh_query_alerts`: HTTP `200`, document
  `JpfIu6ABi5eqXjMPYcjG`, rule `302010`.
- **A11**: `indexer_query` bounded to `22:27:30–22:28:00Z`: HTTP `200`,
  same document and rule. The request used an ID filter and timestamp range.
- **A12**: `network_query_ids_alerts` bounded to
  `22:27:55–22:28:05Z`: HTTP `200`, document
  `KZfIu6ABi5eqXjMPnMhU`, rule `303020`, signature `1000010`.
- **A13**: Complete MCP initialize/list/call to shipped `mcp-reverse`
  returned `{"outcome":"expected-unavailable","operation":"reverse_run_command"}`;
  no reverse container was in A01 inventory.
- **A14**: `aptl runs show` identified TechVault, backend `aptl`,
  package `5.5.0`, pack `techvault` `0.1.0`, and A01/A02 run artifacts.
  Bundle root `sha256:4d3b86e7fc2ed4d999b239b4ff51d0080f0267d74ae6ebb4b919ed0ec74a6c8d`,
  15 members; `verify-bundle` returned `OK: bundle verified` and
  `seal: unsealed`. Limitations: no #444 seal and no
  `provenance/run-provenance.json`.
- **A15**: `Lab stopped successfully.`; project-scoped assertion:
  `Project 'aptl': no containers, networks, or volumes remain.` Both
  path-A browser CA trust entries were then removed.

## Path B: exact source commit

Start run: `run_20260919T223603Z`. Its 28-container project was
`aptl-wf802fdb528c7`. The clean checkout was detached at the exact candidate
commit, and the editable installation reported `aptl 5.5.0`.

| ID | Result | Actual observation | Evidence |
| --- | --- | --- | --- |
| QA-START | PASS | Startup exited 0; plain and JSON status views showed 28 running containers and no MCP endpoint container; runs list showed the new canonical run. | B01 |
| QA-LIVE | PASS | Correctly activated source venv passed all nine live-gate checks against the same startup run. An earlier invalid shell invocation is disclosed below. | B02 |
| QA-WAZUH | PASS | Strict-TLS Chromium login showed 8 active agents and 1,097 recent alerts; Threat Hunting loaded. | B03 |
| QA-DETECT | PASS | MCP SQLi from realized Kali returned HTTP 200; new Wazuh alert had rule `302010`. | B04 |
| QA-SURICATA | PASS | Separate sensor namespace request returned HTTP 200; Suricata signature `1000010` arrived in Wazuh as rule `303020`. | B05 |
| QA-SOAR | PASS | Source-path Shuffle workflow executed B04's actual alert, finished with two successful actions, and created a linked TheHive case. | B06 |
| QA-CASE | PASS | Case retained alert linkage; source-IP observable added; TheHive UI launched `TechVaultScenarioContext`; Cortex job and UI report succeeded. | B07 |
| QA-MISP | PASS | Strict-TLS browser at canonical MISP origin showed seeded event #1 and indicator; MCP read back attribute #1. | B08 |
| QA-MCP-RED | PASS | `kali_info` responded and `kali_run_command whoami` returned `kali` from realized target. | B09 |
| QA-MCP-WAZUH | PASS | `wazuh_query_alerts` retrieved B04 alert and rule `302010`. | B10 |
| QA-MCP-INDEXER | PASS | Time-bounded `indexer_query` retrieved the same B04 document. | B11 |
| QA-MCP-SOAR | PASS | MCP listed the seeded workflow and real-alert execution in terminal successful state. | B06 |
| QA-MCP-CASE | PASS | MCP listed linked case and wrote its source-IP observable. | B07 |
| QA-MCP-TI | PASS | MCP found seeded `ip-src` `172.20.4.30`, event #1, attribute #1. | B08 |
| QA-MCP-NET | PASS | Time-bounded `network_query_ids_alerts` found B05 rule `303020`, signature `1000010`. | B12 |
| QA-MCP-REVERSE | PASS | Production MCP protocol call returned structured `expected-unavailable` for intentionally omitted target. | B13 |
| QA-ARCHIVE | PASS | Canonical run was shown; exported 15-member bundle verified independently, with unsealed/missing-run-provenance limitations disclosed. | B14 |
| QA-TEARDOWN | PASS | Scoped stop exited 0 and project-scoped assertion found no remaining containers, networks, or volumes. | B15 |

### Path-B bounded observations

- **B01**: `Lab is ready.`; plain status said `Lab is running` and listed
  all 28 project containers as `running`. JSON inventory contained 28
  entries; `aptl runs list` returned
  `run_20260919T223603Z techvault.sdl.yaml 2026-09-19T22:45:11`.
  Wazuh published on loopback port 443; the MISP security-network address
  was `172.20.0.134`. No `aptl-mcp-endpoints` was inventoried.
- **B02**: Scenario verification reported `scenario=techvault backend=aptl
  plugin=techvault from aptl-labs==5.5.0: PASSED`; all nine listed checks
  passed, including readiness and runtime containment. Before this valid
  invocation, an attempt used `.venv/bin/aptl` by absolute path without
  activating the venv. It exited 1 at `static_prerequisite` because the
  companion `raes` CLI was not on `PATH`. `raes` was present in `.venv/bin`;
  rerunning with that directory on `PATH` produced the above pass against
  the same startup run. This was an operator invocation error, not a passing
  check or a product defect.
- **B03**: Strict-TLS Chromium after login: `Active (8)`,
  `Disconnected (0)`; Threat Hunting displayed `1,097` recent alerts.
- **B04**: MCP action 2026-09-19T22:50:25–27Z: target
  `172.20.1.30`, exit `0`, HTTP `200`; Wazuh hit
  `_h_du6ABiDKYBLsqUDGT` at `22:50:27.386Z`, rule `302010`, agent
  `techvault-webapp-agent`.
- **B05**: Sensor request at `22:50:55Z`, HTTP `200`; Suricata alert
  `22:50:55.345220+0000`, flow `2040975874541685`, source
  `172.20.1.128`, destination `172.20.1.20`, signature `1000010`;
  Wazuh hit `AR_du6ABiDKYBLsqsjI4` at `22:50:56.102Z`, rule
  `303020`, agent `techvault-suricata-agent`.
- **B06**: Workflow `f7143505-c14b-4d82-b6b9-8142c4a94631`,
  execution `4e463d44-1de6-49d4-8bb5-8206d548c5af`: input contained
  exact B04 alert and rule `302010`; execution `FINISHED` with two
  `SUCCESS` actions. Case `~4218944` linked the exact alert and rule.
- **B07**: MCP returned observable `~4120728`, type `ip`, value
  `172.20.1.30`; strict-TLS TheHive case UI launched
  `TechVaultScenarioContext`. Cortex job `Mfbeu6ABPxFiCaN-yrzU` was
  `Success`; the UI showed `Analysis report` and
  `TechVault:ScenarioAttacker="1"`.
- **B08**: Browser authenticated at
  `https://misp.techvault.local/` and showed seeded event #1 with
  `APTL Lab - Known Threat Actors` and `172.20.4.30`.
  `threatintel_search_iocs` returned `ip-src` `172.20.4.30`, event id
  `1`, attribute id `1`.
- **B09**: `kali_info` returned target metadata; `whoami` succeeded,
  exit `0`, identity `kali`. MCP-side session records were under
  `runs/run_20260919T223603Z/mcp-side/sessions/`, not the legacy store.
- **B10**: `wazuh_query_alerts`: HTTP `200`, document
  `_h_du6ABiDKYBLsqUDGT`, rule `302010`.
- **B11**: `indexer_query` bounded to `22:50:20–22:50:35Z`: HTTP
  `200`, same document and rule, using an ID filter and timestamp range.
- **B12**: `network_query_ids_alerts` bounded to
  `22:50:50–22:51:05Z`: HTTP `200`, document
  `AR_du6ABiDKYBLsqsjI4`, rule `303020`, signature `1000010`.
- **B13**: Full MCP initialize/list/call to shipped `mcp-reverse`
  returned `{"outcome":"expected-unavailable","operation":"reverse_run_command"}`;
  B01 inventory had no reverse target.
- **B14**: `aptl runs show` identified TechVault, backend `aptl`,
  package `5.5.0`, pack `techvault` `0.1.0`, and B01/B02 artifacts.
  Bundle root `sha256:c13d96bde75b307e3ec7a0f7bae3dd704de45c9fae678ea0950457b22c4e7dc5`,
  15 members; `verify-bundle` returned `OK: bundle verified`,
  `seal: unsealed`. Limitations: no #444 seal and no
  `provenance/run-provenance.json`.
- **B15**: `Lab stopped successfully.`; project-scoped assertion:
  `Project 'aptl': no containers, networks, or volumes remain.` Both
  path-B browser CA trust entries were then removed.

## Release decision

| Field | Decision |
| --- | --- |
| Path A | 18/18 candidate checks passed, with the A01 plain-status capture deviation disclosed above |
| Path B | 18/18 candidate checks passed after correcting the disclosed venv invocation error |
| Open candidate functional failures | None observed in the two clean paths |
| Evidence review/redaction | Bounded excerpts in this record reviewed; raw local screenshots, profiles, configs, and bundles are not approved for publication |
| Release PR / approver | Not yet identified; no human manual-QA approval recorded |
| Release decision | **BLOCK** until a release PR identifies this same immutable head and artifact pair and a human operator completes the required manual gate; rerun both paths if the head or artifacts change |

No release PR was merged or release package published from this QA run.
