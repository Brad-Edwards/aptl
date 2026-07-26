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

`aptl.workbench` renders a private, generated, credential-free descriptor for
the selected profile. It contains only the released MCP artifact reference,
the required credential alias, the current scenario trace ID, and the profile
policy version. Credential values, model authentication, URLs supplied by a
participant, command strings, Docker targets, and operator configuration are
not accepted by this contract.

The installed-agent adapter is the narrow seam shared with issue #557. It
receives the sealed profile launch and owns the selected agent plus MCP process
set in the appliance management compartment. The adapter must use the current
run/trace identity for its MCP and evidence paths and must complete ordered
shutdown before the credential broker removes session state.

The workbench browser app is intentionally a separate FastAPI assembly. It
requires an appliance-provided participant session authorizer and offers only
the selected profile's bookmarks and MCP inventory plus profile selection. It
does not mount the existing operator API, terminal, lifecycle, Docker, kill,
configuration-mutation, or raw-evidence routes.

## Delivery responsibilities

The workbench is a reusable guest component. The appliance payload/build
(#823), internal zones and egress rules (#822), and host kiosk/reset lifecycle
(#824) supply its deployment boundary. Those layers must verify the profile's
real MCP `tools/list` inventories, deny cross-profile filesystem/process and
network visibility, and keep model/service credentials out of participant and
Kali compartments before this component is exposed to participants.
