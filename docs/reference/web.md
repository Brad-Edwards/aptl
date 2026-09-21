# Web Interface Reference

The APTL web interface is the local operator control plane for one lab project.
It is separate from the intentionally vulnerable target web application and
from third-party SOC interfaces such as the Wazuh Dashboard. Discover every
realized URL with `aptl lab info`.

## Supported Delivery

The supported direct command is:

```shell
aptl web serve
```

It serves the built single-page application and FastAPI control plane from one
origin. The command prints a one-time login URL. Open that private URL in the
operator's browser; the server exchanges it for the two-part browser session.
Do not paste the URL into chat, logs, issues, or another user's browser.

The command requires the Python `web` extra and built frontend assets. A source
or initialized lab project can build the frontend with its locked Node package
metadata. The Compose `web` profile supplies the other supported delivery: a
static UI container and an API container behind one same-origin proxy. Use only
a web surface realized by the selected scenario or an explicitly started local
development setup.

## Serve Defaults

| Setting | Default | Supported behavior |
| --- | --- | --- |
| Bind address | `127.0.0.1` | Keeps the operator control plane on loopback. |
| Port | `8400` | Serves the single-origin UI and API when available. |
| Browser login | one-time URL | Exchanges a terminal-visible launch token for a two-part session. |
| Workers | `1` | Keeps the in-process session and terminal-ticket stores consistent. |

Use `aptl web serve --help` for the exact options in the installed release.
`--api-only` is for the split Compose delivery behind its static UI proxy; it
does not provide a browser interface by itself.

## Operator Surfaces

| Browser route | Supported behavior |
| --- | --- |
| `/` | Lab readiness, lifecycle controls, realized containers, and scenario entry points. |
| `/scenarios/<id>` | Details for a scenario returned by the validated catalog API. |
| `/terminal/<container>` | A terminal for a server-approved realized container after confirmation. |
| `/config` | A redacted, read-only projection of non-secret project and web status. |

The UI can start, stop, and emergency-kill the local lab through the same typed
core boundaries as the CLI. Destructive controls remain explicit. The browser
does not receive the API bearer token, and v1 does not persist terminal input,
terminal output, or operator notes.

## Supported API Surface

These routes support the shipped UI. They are not an unauthenticated public
automation API. Except for the one-time login exchange, HTTP routes require the
web control-plane authentication boundary; mutating browser requests also pass
the same-origin gate.

| Method and path | Purpose |
| --- | --- |
| `GET /api/health` | Authenticated API liveness. |
| `GET /api/auth/login` | One-time launch-token exchange and browser-session bootstrap. |
| `GET /api/lab/status` | Current running, error, and container state. |
| `POST /api/lab/start` | Start the selected project scenario. |
| `POST /api/lab/stop` | Stop the project, with an explicit volume-removal choice. |
| `GET /api/lab/events` | Server-sent lifecycle updates. |
| `POST /api/lab/kill` | Emergency project process or container termination. |
| `GET /api/config` | Redacted non-secret configuration projection. |
| `GET /api/scenarios` | Validated scenario summaries. |
| `GET /api/scenarios/{scenario_id}` | One validated scenario summary. |
| `GET /api/terminal/ticket` | Short-lived ticket for an allowed terminal target. |
| `WEBSOCKET /api/terminal/ws/{container}` | Bounded terminal session for a server-approved container. |

Use the browser interface rather than calling these routes directly unless you
are developing or testing the web client against the typed API contracts.

## Safe Exposure

Loopback is the default and recommended operator boundary. For access from
another device, keep the APTL server on loopback and place a same-host TLS proxy
in front of it. Set the browser-facing public origin and allowed host exactly as
described by `aptl web serve --help`. Do not expose the control plane through a
plain non-loopback bind, rely on CORS as authorization, disable TLS validation,
or put API tokens in URLs.

For design rationale and contributor contracts, see the
[web GUI specification](../specs/web-gui-design.md) and
[authentication ADR](../adrs/adr-039-web-control-plane-authentication.md).
