# Interactive Console

The console is a local, browser-based workbench for *exploring* APTL
interactively: you drive red and blue AI chat sessions side by side, control
exactly which MCP servers each session can reach, and share findings between
sessions through named scratchpads.

It is part of the optional web UI and is reached at
[http://localhost:5173/console](http://localhost:5173/console) (dev) once both
the API and frontend are running.

## Concepts

| Concept | What it is |
|---|---|
| **Session** | An isolated chat with its own transcript, MCP allowlist, and scratchpad bindings. Sessions **never share message history** — that is the red/blue separation. |
| **Role** | `red`, `blue`, or `purple`. A role sets the *default* MCP servers and the session's colour, but you can override the allowlist freely (e.g. give a purple session both Kali and Wazuh). |
| **MCP allowlist** | The exact set of MCP servers a session may use this turn. Toggle servers in the **MCP access** panel; the agent only ever sees the tools you enable. |
| **Scratchpad** | A shared, named document — the console's shared-memory primitive. Attach a scratchpad to any number of sessions and they can all read and write it, letting red hand a finding to blue without sharing a chat. |

## Running it

```bash
pip install -e ".[web]"          # API server
aptl web serve                   # terminal 1
cd web && npm install && npm run dev   # terminal 2
```

Open `http://localhost:5173/console`. Create a red and a blue session from the
sidebar, toggle MCP servers per session, and add a scratchpad to share notes.

## Demo mode vs. live agent

The console works out of the box with **no API key** in *demo mode*: replies
are scripted, but the session's tools execute for real. Use the slash commands
in the composer:

- `/help` — list commands
- `/tools` — show the tools available to this session
- `/run <tool> <json-args>` — execute a tool, e.g.
  `/run scratchpad_write {"name": "findings", "content": "creds: admin/admin"}`

This means you can exercise scratchpad sharing (and, once the MCP servers are
built, real MCP calls) before wiring up a model.

To turn on a **live Claude agent** that calls these tools for you:

```bash
pip install -e ".[console]"      # installs anthropic + the MCP client SDK
export ANTHROPIC_API_KEY=sk-...
# optional: override the model (defaults to claude-sonnet-4-6)
export APTL_CONSOLE_MODEL=claude-sonnet-4-6
aptl web serve
```

The console auto-detects the key and the `anthropic` package and switches the
header from *demo mode* to *live*.

## MCP access and availability

The console reads the same `.mcp.json` an external AI client would use (set
`APTL_MCP_CONFIG` to point elsewhere). Each server is auto-tagged by role
(Kali → red, Wazuh/MISP/TheHive/Shuffle → blue, reverse-engineering → purple,
network → neutral); override per-entry with an `"aptlRole"` key. A server shown
as **offline** has no built entrypoint — run `./mcp/build-all-mcps.sh`.

For a live agent to actually reach an MCP server, the `mcp` Python SDK must be
installed (the `[console]` extra) and the server must be built. Otherwise the
session still runs; it just notes which servers were unreachable.

## Where state lives

Sessions and scratchpads persist to `<project>/.aptl/console/state.json`
(already git-ignored). Deleting that file resets the console.

## Security note

Like the rest of the web UI, the console is localhost-only and unauthenticated.
The API needs the host Docker socket and can drive real penetration-testing
tools through the MCP servers — **do not expose it to untrusted networks.**
