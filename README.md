[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=Brad-Edwards_aptl&token=4dd88be3421d6d030a4615b86ac8ab0e3c9eb4d3)](https://sonarcloud.io/summary/new_code?id=Brad-Edwards_aptl)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Brad-Edwards/aptl/badge)](https://scorecard.dev/viewer/?uri=github.com/Brad-Edwards/aptl)

🎤 **Accepted to [Black Hat USA Arsenal 2026](https://blackhat.com/us-26/arsenal/schedule/#aptl-advanced-purple-team-labs-52322), [SecTor Arsenal 2026](https://blackhat.com/sector/arsenal/schedule/index.html#aptl-advanced-purple-team-labs-54785), and SecTor 2026 Briefings.**

# APTL—Advanced Purple Team Lab

APTL is a local purple-team lab where human operators and AI agents exercise
red- and blue-team workflows against an intentionally vulnerable enterprise
range. Scenario documents select and realize the target, attacker, and SOC
topology; the CLI owns validation, startup, readiness, access discovery,
teardown, and run records.

Use cases include autonomous cyber-operations research, purple-team training,
and AI threat-actor assessment.

## Status And Safety

**Active development. Not for production. Not hardened.** APTL gives AI agents
penetration-testing tools and starts intentionally vulnerable services. Use a
dedicated, rebuildable host, keep unrelated credentials and workloads
elsewhere, control the surrounding network, and operate only on systems you are
authorized to test.

For stronger host and cross-seat isolation on Linux/KVM, use a disposable
[`aptl seat`](docs/reference/appliance-seat-launcher.md). A VM boundary reduces
risk but does not eliminate it; keep the host kernel and hypervisor current.

## Quick Start

Install the released CLI and materialize its bundled lab assets. No source
checkout is required:

```shell
pipx install aptl-labs
aptl lab init my-lab
cd my-lab
aptl lab start --scenario techvault
```

Startup validates the selected scenario, creates private project state,
realizes the topology, waits for required readiness checks, and reports a
structured outcome. Inspect the runtime-derived state and access information:

```shell
aptl lab status
aptl lab info
aptl container list
```

URLs, host ports, available containers, usernames, and credential locations
belong to the realized project. Use `aptl lab info`; do not rely on static
values copied from documentation.

At the end of the session:

```shell
aptl lab stop      # preserve project volumes
aptl lab stop -v   # confirm and destroy project volume data
```

Read the [first-lab guide](docs/getting-started/quick-start.md) for scenario
selection, safe activity, result inspection, troubleshooting, and teardown.

## Requirements

- Python 3.11 or newer and [pipx](https://pipx.pypa.io/)
- Docker Engine or Docker Desktop with Compose and Buildx
- OpenSSH client with `ssh-keygen` on `PATH`
- Node.js 20 or newer and npm for MCP artifact builds
- 20GB or more of free disk space
- Sufficient Docker memory for the selected scenario; the full acquired
  TechVault stack needs more than 20GB

See [Prerequisites](docs/getting-started/prerequisites.md) for platform-specific
setup and verification.

## Supported Interfaces

- [CLI](docs/reference/cli.md) is the primary lab control plane.
- [MCP servers](docs/reference/mcp.md) give authorized agents scenario-aware
  red- and blue-team tools through generated private client configuration.
- [Web interface](docs/reference/web.md) provides a loopback-first local
  operator UI and typed API.

The APTL operator UI, vulnerable target applications, and third-party SOC
interfaces are separate surfaces. The selected scenario determines which ones
exist.

## Scenarios

The APTL startup catalog exposes the scenario selections supported by the
installed release. Reusable environment-pack definitions and authoring support
live in the companion [OpenRAE/env-packs](https://github.com/OpenRAE/env-packs)
repository; APTL owns admission, realization, readiness, and operation of the
selected scenario in the local lab.

## Documentation

The published site is the canonical user manual:

- [Documentation home](https://brad-edwards.github.io/aptl/)
- [Installation](docs/getting-started/installation.md)
- [Run your first lab](docs/getting-started/quick-start.md)
- [Troubleshooting](docs/troubleshooting/index.md)
- [Architecture and historical records](docs/architecture/index.md)
- [OpenSSF Best Practices assessment](docs/security/openssf-best-practices.md)

The README is the GitHub and package-index gateway, not a second copy of the
manual.

## Project Links

- [Get support](https://github.com/Brad-Edwards/aptl/blob/dev/SUPPORT.md)
- [Contribute](https://github.com/Brad-Edwards/aptl/blob/dev/CONTRIBUTING.md)
- [Report a vulnerability privately](https://github.com/Brad-Edwards/aptl/security/advisories/new)
- [Review the OpenSSF Best Practices assessment](docs/security/openssf-best-practices.md)

Do not report suspected vulnerabilities through a public issue. The
[security policy](SECURITY.md) describes scope and the private fallback contact
path.

## Ethics And Disclaimer

APTL uses commodity services and standard security tooling. AI agents get Kali
access; this public repository does not add red-team enhancements to their
latent capabilities. You are responsible for following all applicable laws and
for obtaining authorization before testing a system.

The repository contains intentional test credentials used only by lab
fixtures. They are not production secrets. Runtime control-plane credentials
are generated into private project files and must not be committed or shared.

## License

MIT
