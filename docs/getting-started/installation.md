# Installation

The supported first-time path installs the released package in an isolated
pipx environment. Check the [prerequisites](prerequisites.md) first.

## Install The Released Package

Install pipx through your operating system or the
[official pipx instructions](https://pipx.pypa.io/stable/installation/), then
install APTL:

```shell
pipx install aptl-labs
aptl --version
```

`aptl-labs` requires Python 3.11 or newer. On macOS, if pipx is bound to the
Command Line Tools Python 3.9, ask pipx to fetch a supported interpreter:

```shell
pipx install --python 3.12 --fetch-missing-python aptl-labs
```

pipx keeps the CLI outside the system Python environment, avoiding the PEP 668
system-`pip` restriction on current Debian, Ubuntu, and WSL2 hosts.

## Create A Lab Project

Materialize the released lab assets into a new project directory:

```shell
aptl lab init my-lab
cd my-lab
```

The wheel includes the Compose topology, configuration templates, container
build contexts, MCP sources, and web sources. The installed environment-pack
distribution supplies released scenarios. You do not need to clone the source
repository.

`aptl lab init` creates the durable project files. The first `aptl lab start`
creates private runtime state such as `.env`, `.mcp.json`, keys, and `.aptl/`
artifacts. Do not publish or attach those files to support reports.

Continue with [Run your first lab](quick-start.md).

## Upgrade

Upgrade the isolated installation, then initialize a new project when you want
the complete asset set from the new release:

```shell
pipx upgrade aptl-labs
aptl lab init my-new-lab
```

Do not copy generated credentials or state between project directories.

## Source Install For Contributors

A source checkout is a development path, not a prerequisite for operating the
released lab. Contributors should follow the repository's
[development setup](https://github.com/Brad-Edwards/aptl/blob/dev/CONTRIBUTING.md#development-setup),
which creates a virtual environment and uses an editable install.
