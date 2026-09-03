# Participant Workbench

The participant workbench is the guest-side profile boundary for the
browser, installed coding-agent adapter, and APTL MCP servers. It is used only
inside the sealed appliance defined by [ADR-049](../adrs/adr-049-sealed-disposable-lab-appliance.md).
It is not a developer-host launch mode, an operator console, or a replacement
for the appliance's network enforcement.

## Profiles

The workbench accepts only three closed profiles:

| Profile | MCP servers | Browser references |
| --- | --- | --- |
| `red` | `aptl-red` | APTL guide and Kali desktop |
| `guided-blue` | `aptl-indexer`, `aptl-wazuh` | APTL guide and Wazuh |
| `blue` | `aptl-indexer`, `aptl-wazuh`, `aptl-network`, `aptl-threatintel`, `aptl-casemgmt`, `aptl-soar` | APTL guide, Wazuh, TheHive, MISP, and Shuffle |

A profile is a launch compartment, not a UI visibility toggle. A purple
exercise stops the preceding agent/MCP runtime, destroys its session-local
credentials and generated configuration, and then launches the next profile.
It must never keep both capability sets in one process environment or config
directory.

The runtime verifies the exact `tools/list` inventory immediately after each
profile launch. The red profile is limited to `kali_info`, `kali_run_command`,
`kali_interactive_session`, `kali_background_session`, `kali_session_command`,
`kali_list_sessions`, `kali_close_session`, `kali_get_session_output`, and
`kali_close_all_sessions`. The guided-blue variation admits only the published
indexer and Wazuh inventories for the bounded profile in issue #820. The full
blue profile adds network, threat-intelligence, case-management, and SOAR. An
added, removed, or cross-profile tool fails the launch rather than being
hidden from the user interface.

## Launch contract

`aptl.workbench` renders a private, standard Claude Code `.mcp.json` for the
selected profile. Each stdio entry uses the fixed Node executable, an absolute
released MCP artifact, the canonical guest `APTL_STATE_DIR`, and only that
server's `${CREDENTIAL_ALIAS}` placeholders. The client expands those
placeholders from a management-only lease; credential values, model
authentication, participant-supplied URLs, command strings, Docker targets,
and operator configuration never enter the file.

The production adapter supports the installed Claude Code CLI. It validates
the executable's ownership and mode, performs a real MCP initialize plus
`tools/list` probe for every configured server, and invokes one non-persistent
request with fixed no-shell arguments. Bare mode, strict MCP config, disabled
built-in tools, disabled slash commands and browser integration, an exact MCP
tool allowlist, bounded input/output/time, and process-group timeout cleanup
keep the agent inside the selected MCP surface. Participant messages are sent
on stdin, never in process arguments.

Every workbench MCP child receives `APTL_MCP_DISABLE_DOTENV=1`.
`aptl-mcp-common` therefore uses only the selected child environment instead
of searching the payload hierarchy for a developer `.env`. Normal
developer-local MCP launches retain their existing dotenv behavior.

The workbench browser app is intentionally a separate FastAPI assembly. It
requires an appliance-provided participant session authorizer on every route
and offers profile selection, fixed same-origin bookmarks, bounded agent
messages, and profile close. Its CSP admits only its hash-pinned script and
same-origin connections. It does not mount the existing operator API,
terminal, lifecycle, Docker, kill, configuration-mutation, or raw-evidence
routes.

Agent-turn records contain the profile, existing scenario trace ID, sizes, and
request/response hashes, not prompt or response content. MCP processes read
the same `trace-context.json` through `APTL_STATE_DIR`, preserving the existing
OTel, MCP-side PTY, and red activity-capture correlation paths.

## ADR-049 reconciliation

| Control | This component changes or proves | Canonical incumbent | Evidence in this change | Remaining appliance proof |
| --- | --- | --- | --- | --- |
| APP-004 participant/operator separation | A dedicated participant FastAPI route assembly with authentication on status, selection, messaging, and teardown; no operator, Docker, terminal, kill, config, or raw-evidence routes | ADR-039/040 request/session patterns and the existing management-only operator API | Unit/framework integration in `tests/test_participant_workbench.py` | #822/#824 listener, Host, origin, CSRF, and live participant-to-operator denial |
| APP-005 agent, MCP, and credential placement | Standard strict MCP config; real inventory probe; minimal configured credential binding; dotenv suppression; fixed bounded Claude Code invocation with built-in tools disabled | Released MCP artifacts, `.mcp.json.example`, `loadLabConfig()`, `createMCPServer()`, shared placeholder checks | Python unit/process integration plus `aptl-mcp-common` vitest | #823 guest-management process identity/package; #822 egress and off-Kali reachability proof |
| APP-008 evidence and capture boundary | Agent lifecycle hashes use `RunStorageBackend`; every MCP child receives the active `ScenarioSession` state path and therefore the existing trace context | `ScenarioSession`, `RunStorageBackend`, MCP `runs.ts`, telemetry, ADR-041/042 capture layout | Unit/process integration in the workbench tests | #823 management-owned mounts and #822/#824 live capture/export/no-host-sync proof |

APP-003, APP-006, APP-007, APP-009, and APP-010 are consumed constraints, not
proof claims from this component. APP-001 and APP-002 are also payload/seat
proofs owned by the appliance build and host contract. Issue #821 must remain
open until #822, #823, and #824 supply the live/static evidence named above.

## Delivery responsibilities

The workbench is a runnable guest component, not the whole appliance. The
appliance payload/build (#823), internal zones and egress rules (#822), and
host kiosk/reset lifecycle (#824) supply its deployment boundary. Those layers
must deny cross-profile filesystem/process and network visibility, prove the
agent and MCP processes are off the physical host and Kali, and keep
model/service credentials out of participant and Kali compartments before the
combined delivery is called supported.
