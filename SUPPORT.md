# Support

APTL is community supported and maintained on a best-effort basis.

## Where to Ask

- Use GitHub issues for reproducible bugs, documentation problems, and focused
  feature requests.
- Use GitHub discussions if they are enabled for design questions or broader
  usage questions.
- For security issues, do not open a public issue. See [SECURITY.md](SECURITY.md).

## What to Include

For a bug report, include:

- repository commit or package version
- operating system, Python version, Docker version, and Docker Compose version
- command or API call used
- relevant scenario, profile, or configuration file
- expected result
- actual result and error output
- whether the lab was started from a clean state with `aptl lab stop -v`

For MCP server or agent-integration issues, include:

- MCP server name
- client used to run the tool
- tool call and sanitized arguments
- sanitized tool response, logs, or trace output
- whether the lab containers were healthy at the time

For scenario or lab-topology proposals, include:

- the training, research, or validation problem
- the current workaround, if any
- affected containers, networks, services, scenarios, or MCP tools
- safety and isolation considerations
- examples of expected telemetry or agent behavior

## Maintenance Expectations

Issues and pull requests are handled as time permits. Well-scoped reports with
runnable examples are the easiest to review.

There is no commercial support channel for this repository.
