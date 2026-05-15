# Security Policy

## Reporting a Vulnerability

Do not report suspected vulnerabilities through public GitHub issues.

Use GitHub private vulnerability reporting for this repository if it is
available. If private reporting is not available, contact the maintainer
privately through the contact path listed on Brad Edwards' GitHub profile.

Include enough detail to reproduce and assess the issue:

- affected package, command, container, MCP server, scenario, or document
- affected version, commit, or branch
- reproduction steps
- expected and actual behavior
- impact
- proof of concept, logs, packet captures, or screenshots, if available

## Scope

Security reports are most useful for issues in:

- APTL CLI behavior
- MCP server behavior
- web UI and API behavior
- scenario parsing, compilation, and execution
- run archives, telemetry export, and secret redaction boundaries
- Docker Compose, container images, mounted configuration, and generated files
- lab network isolation and host exposure
- repository automation that handles untrusted input

APTL intentionally includes vulnerable services, test credentials,
penetration-testing tools, and unsafe lab targets. Reports are useful when the
issue crosses an intended lab boundary, exposes host or operator data, leaks
control-plane secrets, weakens isolation, or makes documented safety
assumptions false.

## Response Expectations

Reports are reviewed as time permits, with priority given to reproducible
issues that affect current code, host safety, control-plane secrets, published
packages, or documented workflows.

Please avoid publishing exploit details until there has been reasonable time to
triage and prepare a fix or mitigation.
