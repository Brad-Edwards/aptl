# APTL—Advanced Purple Team Lab

APTL is a local purple-team lab where human operators and AI agents exercise
red- and blue-team workflows against an intentionally vulnerable enterprise
range. The released Python package supplies the CLI and materializes the lab
assets; Docker runs the selected scenario on your chosen engine.

!!! warning "Use a dedicated, rebuildable environment"

    APTL starts vulnerable services and gives agent tooling access to
    penetration-testing capabilities. Use a dedicated host or the stronger
    disposable [appliance seat](reference/appliance-seat-launcher.md), keep
    unrelated credentials elsewhere, and use APTL only on systems you are
    authorized to test.

## Run Your First Lab

Follow these tasks in order. The path uses the released package and does not
require a source checkout or an architecture record.

1. [Check prerequisites](getting-started/prerequisites.md) for Docker, Python,
   host resources, and the required command-line tools.
2. [Install APTL](getting-started/installation.md) with pipx and create a lab
   project from the assets in the release.
3. [Choose a scenario](getting-started/quick-start.md#choose-a-scenario) from
   the catalog provided by the installed environment pack.
4. [Start and verify the lab](getting-started/quick-start.md#start-and-verify-the-lab)
   through the CLI readiness checks.
5. [Inspect the running lab](getting-started/quick-start.md#inspect-the-running-lab)
   for realized containers, URLs, remapped ports, usernames, and credential
   locations.
6. [Generate safe test activity](getting-started/quick-start.md#generate-safe-test-activity)
   inside the authorized range.
7. [Inspect results](getting-started/quick-start.md#inspect-results) in the
   realized services and APTL run records.
8. [Troubleshoot](troubleshooting/index.md) with project-scoped diagnostics and
   recovery steps.
9. [Stop or reset the lab](getting-started/quick-start.md#stop-or-reset-the-lab)
   when the session ends.

The shortest installation and start sequence is:

```shell
pipx install aptl-labs
aptl lab init my-lab
cd my-lab
aptl lab start --scenario techvault
```

Startup creates project-local runtime files, validates the selected scenario,
realizes its topology, waits for required services, and prints a structured
result. A running container alone does not mean the lab is ready.

## Supported Interfaces

- [CLI reference](reference/cli.md): lab lifecycle, configuration, containers,
  runs, web, appliance, and participant-seat commands.
- [MCP reference](reference/mcp.md): generated client configuration, server
  availability, fully qualified tools, and credential handling.
- [Web reference](reference/web.md): the local operator UI, its supported API,
  one-time login flow, and safe exposure boundary.

The operator UI, intentionally vulnerable target applications, and SOC product
interfaces are different surfaces. Use `aptl lab info` to discover the URLs
that exist for the current scenario rather than relying on fixed ports.

## Help And Project Policies

- [Get support](https://github.com/Brad-Edwards/aptl/blob/dev/SUPPORT.md) for a
  reproducible problem or focused usage question.
- [Contribute](https://github.com/Brad-Edwards/aptl/blob/dev/CONTRIBUTING.md) a
  fix or improvement against the `dev` branch.
- [Report a vulnerability privately](https://github.com/Brad-Edwards/aptl/security/advisories/new).
  Do not disclose suspected vulnerabilities in a public issue.

## Design And Historical Records

The task guides above are sufficient to operate a first lab. For implementation
context, see the [architecture overview](architecture/index.md),
[architecture decisions](adrs/README.md), [scenario authoring boundary](sdl/index.md),
and [release qualification plan](testing/smoke-test-plan.md). These records
remain available without sitting in the first-time path.
