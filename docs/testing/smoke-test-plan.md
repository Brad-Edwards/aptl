# Release Candidate Manual QA

This is the single release-blocking, hands-on QA procedure for APTL. A person
must execute it against both the candidate distribution and a clean source
checkout before the release PR is merged. Container health, automated tests,
and a previous release's results are useful prerequisites, but they do not
satisfy any row in this manual.

Every row is blocking. Record `PASS` or `FAIL`; `SKIP`, an empty result, and
"not applicable" are not passing outcomes. Stop the release on a failure,
repair it, build a new candidate, and repeat both paths from clean state.

## Candidate and environment record

Create one record for the release and fill every field before testing:

| Field | Recorded value |
| --- | --- |
| Release version | |
| Release PR and head commit | |
| Candidate wheel filename and SHA-256 | |
| Candidate sdist filename and SHA-256 | |
| RAES env-pack id, version, and set digest | |
| OS and version | |
| CPU architecture | |
| Python version | |
| Docker Engine version | |
| Docker Compose version | |
| Distribution-path project directory | |
| Source-path checkout directory | |
| Evidence location | |
| Primary operator | |
| QA start and finish times, including time zone | |

The release PR head must be clean and immutable while QA runs. From that exact
commit, build and identify the candidate artifacts:

```bash
git status --porcelain
git rev-parse HEAD
python -m build
sha256sum dist/*
```

Record both artifact hashes. The distribution-path test installs the exact
wheel; the sdist is its recorded companion release artifact. If the commit or
either artifact changes, the record is invalid and both paths must be rerun.

Use a dedicated Docker host or prove the selected project has no prior
resources. Do not use a daemon-wide prune. Each path ends with the scoped
teardown proof before the next path begins.

## Install path A: candidate distribution

Use an empty directory and a new virtual environment. Do not import lab assets
from a source checkout.

```bash
python3 -m venv qa-candidate-venv
source qa-candidate-venv/bin/activate
pip install /absolute/path/to/aptl_labs-X.Y.Z-py3-none-any.whl
aptl --version
aptl lab init qa-candidate-lab
cd qa-candidate-lab
```

Record the installed version and wheel identity in the path-A evidence. The
initialized directory is the project directory for every path-A action below.

## Install path B: exact source commit

Use a second, clean checkout at the same recorded release-PR commit. Do not
reuse the distribution-path project, virtual environment, generated files, or
Docker volumes.

```bash
git clone https://github.com/Brad-Edwards/aptl.git qa-source
cd qa-source
git checkout --detach <recorded-release-pr-head-commit>
git status --porcelain
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
aptl --version
```

The clean checkout itself is the project directory for every path-B action.

## Evidence rules

For each action, capture the minimum output or screenshot that proves the
expected observation. Give every file a stable reference and put that reference
in the result table. A timestamp and a written assertion without the underlying
observation are insufficient.

Review and redact evidence before attaching or publishing it. Never capture or
publish `.env`, browser storage, cookies, authorization headers, API tokens,
private keys, full generated configuration, unreviewed logs, or planted
credentials. A private archive or restrictive file mode does not replace
redaction. Preserve useful identifiers such as the candidate hash, run id,
container name, alert id, rule id, case id, execution id, and analyzer job id.

## Required actions

Execute `QA-START` through `QA-TEARDOWN` in order for path A, complete the
path-A results table, then repeat the whole sequence from clean state for path
B. Do not copy an observation from one path to the other.

### QA-START: Complete startup and project inventory

Run:

```bash
aptl lab start
aptl lab status
aptl runs list | tee qa-start-runs.txt
```

Expected: start exits zero and reports readiness; status accounts for every
project-owned container and none is `created`, `exited`, `dead`, or otherwise
non-running. No `aptl-mcp-endpoints` container exists. The runs listing
contains the canonical run created by this exact start, backed by its root
`manifest.json`. Record that full run id as the path's startup run id. Capture
the final start result, complete status inventory, and runs listing. A start
failure is a valid diagnostic, not a pass.

### QA-LIVE: RAES live validation

Run against the already-running lab and add live-gate evidence to the canonical
startup run recorded by `QA-START`:

```bash
aptl lab validate-live --skip-clean-boot --run-id <path-startup-run-id>
```

Expected: the command exits zero and every live-gate check passes, including
defensive-stack readiness and declared/observed container parity. Capture the
rendered verdict and confirm that it names the same run id recorded by
`QA-START`.

### QA-WAZUH: Dashboard, agents, and events

Open the Wazuh dashboard at `https://localhost:443` and log in using the
generated credential referenced by `aptl lab info`. In the UI, inspect agent
status and recent indexed events.

Expected: the dashboard is usable, the scenario's agents are enrolled and
reporting, and recent events are visible in the indexer. Capture the agent view
and a bounded recent-event view without credentials or session data.

### QA-DETECT: Attack and expected Wazuh rule

Open a Kali shell with `aptl container shell aptl-kali`. Send a SQL-injection
request to the realized TechVault portal:

```bash
curl -sf 'http://172.20.1.20:8080/login?username=admin%27%20UNION%20SELECT%201,2,3--&password=x'
```

In Wazuh, find the resulting alert within the test time window.

Expected: the alert is attributable to this action and the expected custom
Wazuh rule is `302010` (SQL injection). Capture the action time, source, alert
id, rule id, description, and event time.

### QA-SURICATA: Network rule reaches the SIEM

Use the same SQL-injection traffic, or repeat it while recording a new time.
Inspect Suricata evidence and then locate the corresponding event in Wazuh.

Expected: Suricata reports `APTL SQL Injection Attempt - UNION SELECT` with
signature id `1000010`, and its event reaches Wazuh as a Suricata/web-attack
event (normally rule `303020`). Capture both sides with a shared timestamp,
flow, or alert identifier.

### QA-SOAR: Real-alert Shuffle playbook

In Shuffle, create or inspect a playbook that accepts the exact alert produced
by `QA-DETECT` and performs an observable downstream action, such as creating or
updating its TheHive case. Run it with that alert's real id, source, and rule
data (not a dummy or synthetic smoke payload), and monitor it to completion.

Expected: the execution reaches `FINISHED`, its input can be tied to the real
Wazuh alert, and the downstream action is visible. Capture the workflow id,
execution id, input alert id, terminal state, and downstream object id.

### QA-CASE: TheHive case and Cortex analyzer

In TheHive, create or open the case produced from the `QA-DETECT` alert, add a
relevant observable such as the recorded source IP, and run an available Cortex
analyzer on it.

Expected: the case retains the alert relationship, the observable is present,
and the analyzer job completes with a visible result. Capture the case id,
alert id, observable type/value, analyzer name, job id, and terminal result.

### QA-MISP: Seeded threat intelligence and round trip

Open MISP at `https://localhost:8443`, confirm the expected seeded TechVault
content is present, then add a harmless release-QA indicator in a dedicated QA
event or select a seeded indicator. Retrieve the same indicator through a
second supported surface, preferably `mcp-threatintel` in `QA-MCP-TI`.

Expected: MISP is usable and seeded, and the exact indicator can be pushed or
pulled and found again. Capture event and attribute ids plus the redacted
round-trip result; never capture the API key.

### QA-MCP-RED: `mcp-red`

From an MCP client using the generated configuration, invoke `kali_info`, then
use `kali_run_command` for a harmless real command such as `whoami`.

Expected: the server responds from the realized Kali target and the command
returns target output. Capture the tool names, target identity, and bounded
result.

### QA-MCP-WAZUH: `mcp-wazuh`

Use `wazuh_query_alerts` to retrieve the exact `QA-DETECT` alert.

Expected: the live Wazuh target returns the matching alert and rule `302010`.
Capture the tool name, query bounds, alert id, and rule id.

### QA-MCP-INDEXER: `mcp-indexer`

Use `indexer_query` with a time-bounded query for the recorded alert or rule.

Expected: the live indexer returns the expected document. Capture the tool
name, index pattern, query bounds, and matching document id.

### QA-MCP-SOAR: `mcp-soar`

Use the SOAR tools to list/get the real-alert workflow and retrieve or execute
the `QA-SOAR` run with the recorded real alert data.

Expected: the live Shuffle target returns the same workflow and a terminal
successful execution. Capture the tool names, workflow id, execution id, alert
id, and terminal state.

### QA-MCP-CASE: `mcp-casemgmt`

Use the case-management tools to list the `QA-CASE` case and, if needed, add a
second harmless observable to prove a target-backed write.

Expected: the live TheHive target returns the case and reflects the operation.
Capture the tool names, case id, and bounded result.

### QA-MCP-TI: `mcp-threatintel`

Use `threatintel_search_iocs` or `threatintel_correlate_observable` for the
exact indicator selected in `QA-MISP`.

Expected: the live MISP target returns that indicator and event context.
Capture the tool name, indicator type/value, event id, and bounded result.

### QA-MCP-NET: `mcp-network`

Use `network_query_ids_alerts` or `network_query_web_attacks` for the bounded
`QA-SURICATA` time window.

Expected: the live network/Wazuh target returns the Suricata event with the
expected signature. Capture the tool name, time bounds, signature id, and
matching result.

### QA-MCP-REVERSE: `mcp-reverse`

Attempt the reverse MCP check on every path. If the exact candidate scenario
realizes the reverse target, call `reverse_info` and `reverse_run_command` for a
harmless real operation such as `which r2`.

If the selected scenario deliberately omits the reverse target, attempt the
client connection/tool call with the shipped server and production MCP protocol
driver. Run this from the initialized project directory after `aptl lab start`:

```bash
set -o pipefail
python - <<'PY' | tee qa-mcp-reverse.txt
import json
from pathlib import Path

from aptl.validation.mcp_protocol import McpProtocolError, call_mcp_tool

try:
    result = call_mcp_tool(
        ["node", "mcp/mcp-reverse/build/index.js"],
        "reverse_run_command",
        {"command": "which r2"},
        cwd=Path.cwd(),
        timeout_seconds=30,
    )
except McpProtocolError as exc:
    raise SystemExit(f"FAIL: reverse MCP protocol did not complete: {exc}")

content = result.get("content")
if not isinstance(content, list) or len(content) != 1:
    raise SystemExit("FAIL: reverse_run_command returned malformed content")
text = content[0].get("text") if isinstance(content[0], dict) else None
try:
    payload = json.loads(text) if isinstance(text, str) else None
except json.JSONDecodeError:
    payload = None
if not isinstance(payload, dict) or payload.get("success") is not False:
    raise SystemExit("FAIL: reverse_run_command did not prove target unavailability")
print(json.dumps({"outcome": "expected-unavailable", "operation": "reverse_run_command"}))
PY
```

This performs MCP `initialize`, `tools/list`, and `tools/call` against the built
`mcp-reverse` artifact; it is not a declaration-only check. Record the command's
zero exit and bounded `expected-unavailable` result. Cite both the scenario
declaration and `aptl lab status` inventory proving that the target was
intentionally not realized. A missing Node runtime, server artifact, registered
`reverse_run_command` tool, complete protocol response, or structured target
failure makes the command fail.

Expected: a realized target returns real target output; an intentionally
omitted target produces the declared, inventory-backed tested-negative result.
An unexpectedly missing target or an unattempted check is a failure, not a
skip.

### QA-ARCHIVE: Run evidence and integrity

Use the canonical startup run id recorded by `QA-START` and reused by
`QA-LIVE`:

```bash
aptl runs list
aptl runs show <run-id>
aptl runs export-bundle <run-id> --output-dir qa-evidence
aptl runs verify-bundle qa-evidence/<run-id>.evidence-bundle.tar
```

Expected: the run exists; its manifest identifies the expected scenario,
backend, package version, pack/runtime evidence, and captured runtime; export
succeeds; and independent bundle verification passes. The separate candidate
and environment record remains authoritative for the release-PR commit and
wheel/sdist hashes: compare its installed version and path-specific startup run
id with this manifest, without claiming that the manifest stores artifact
hashes it does not contain. Also compare at least one claimed container and one
live-gate evidence item with earlier observations. Capture the run id, bundle
root identity, member count, verification verdict, cross-record comparison,
and the two inspected claims.

### QA-TEARDOWN: Scoped removal

Run:

```bash
aptl lab stop -v -y
python scripts/ci/assert_project_teardown.py .
```

Expected: both commands exit zero and the checked project owns no remaining
containers, networks, or volumes. Capture the project-scoped proof. Do not use
`docker system prune`, broad deletion, or an `aptl-*` name search as evidence.
The `-y` flag confirms only this documented project-scoped volume removal; it
does not widen the cleanup scope.

## Path A results: Candidate distribution

| ID | Result (`PASS`/`FAIL`) | Actual observation | Evidence reference | Operator | Timestamp |
| --- | --- | --- | --- | --- | --- |
| QA-START | | | | | |
| QA-LIVE | | | | | |
| QA-WAZUH | | | | | |
| QA-DETECT | | | | | |
| QA-SURICATA | | | | | |
| QA-SOAR | | | | | |
| QA-CASE | | | | | |
| QA-MISP | | | | | |
| QA-MCP-RED | | | | | |
| QA-MCP-WAZUH | | | | | |
| QA-MCP-INDEXER | | | | | |
| QA-MCP-SOAR | | | | | |
| QA-MCP-CASE | | | | | |
| QA-MCP-TI | | | | | |
| QA-MCP-NET | | | | | |
| QA-MCP-REVERSE | | | | | |
| QA-ARCHIVE | | | | | |
| QA-TEARDOWN | | | | | |

## Path B results: Exact source commit

| ID | Result (`PASS`/`FAIL`) | Actual observation | Evidence reference | Operator | Timestamp |
| --- | --- | --- | --- | --- | --- |
| QA-START | | | | | |
| QA-LIVE | | | | | |
| QA-WAZUH | | | | | |
| QA-DETECT | | | | | |
| QA-SURICATA | | | | | |
| QA-SOAR | | | | | |
| QA-CASE | | | | | |
| QA-MISP | | | | | |
| QA-MCP-RED | | | | | |
| QA-MCP-WAZUH | | | | | |
| QA-MCP-INDEXER | | | | | |
| QA-MCP-SOAR | | | | | |
| QA-MCP-CASE | | | | | |
| QA-MCP-TI | | | | | |
| QA-MCP-NET | | | | | |
| QA-MCP-REVERSE | | | | | |
| QA-ARCHIVE | | | | | |
| QA-TEARDOWN | | | | | |

## Release decision

Record the final decision in or from the release PR:

| Field | Recorded value |
| --- | --- |
| Path A result | |
| Path B result | |
| Open failures | |
| Evidence review/redaction completed by | |
| QA record URL or immutable reference | |
| Release decision (`PASS` or `BLOCK`) | |
| Approver and timestamp | |

`PASS` requires all 36 path-specific rows to pass and the evidence review to be
complete. Any other state is `BLOCK`; do not merge the release PR.
