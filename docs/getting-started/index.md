# Lab Guide

This guide takes a first-time operator from the released package to a running,
inspectable lab and then through project-scoped teardown.

1. [Check the prerequisites](prerequisites.md).
2. [Install the released package](installation.md) and initialize a project.
3. [Run the lab](quick-start.md): choose a scenario, start it, inspect the
   realized services, generate safe activity, inspect results, and stop it.
4. Use the [troubleshooting guide](../troubleshooting/index.md) when startup or
   a service reports a problem.

The lab project created by `aptl lab init` is the working directory for normal
commands. It contains the released Compose assets and project configuration;
it is not a source checkout. Keep its generated `.env`, `.mcp.json`, `.aptl/`,
keys, and run artifacts private.

APTL runs intentionally vulnerable systems. Review the
[execution-boundary choice](quick-start.md#choose-the-execution-boundary) before
starting it on a host that contains other workloads or credentials.
