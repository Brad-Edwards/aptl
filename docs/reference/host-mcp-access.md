# Host CLI access to an acquired full lab

Host Claude Code and Codex use OpenSSH to carry MCP stdio to a fixed guest
`aptl mcp-access dispatch` command. The user's provider login stays in the host
client account. The transport enrolls a separate Ed25519 public key; it does
not copy provider authentication to the guest. MCP execution, service keys,
capture, artifact access and Docker authority remain in guest management.

## Guest enrollment

Start the canonical packaged full lab with normal `aptl lab start`. An operator
then runs `aptl mcp-access prepare-guest --request REQUEST.json --output-dir DIR`.
The selected environment pack is recorded by exact identity and digest; a later
pack switch invalidates the grant. The TechVault participant-study copy uses
the same enrollment path as TechVault.
`DIR` must be new and absolute. The typed request contains:

- `owner_id`, `seat_id`, `instance_id`, positive `generation`;
- separate `guest_endpoint` and `outer_endpoint` objects, each with a loopback
  `address` and TCP `port`;
- absolute `project_dir`, `management_home`, `docker_socket`, `node_executable`,
  `aptl_executable`, `host_key` and `host_public_key` paths;
- the dedicated SSH `username`, with `/bin/sh` and a management-owned home;
- `keys`, each with a unique `grant_id`, Ed25519 `public_key`, `profile` (`red`
  or `blue`) and timezone-aware `expires_at` no more than 24 hours away;
- `delivery: rootful-integration` for controlled local software integration, or
  `delivery: appliance` with `appliance` paths to the verified launch descriptor,
  release/qualification public keys and fresh runtime boundary observation.

Enrollment proves the full live workload and capture before writing private
`binding.json`, `access.json`, individual grant records, `authorized_keys` and
`sshd_config`. The dedicated listener uses only that generated configuration;
do not append these keys to a general login account. The downstream supervisor
owns user/key creation, listener startup, file ownership and outer port mapping.
The account must be valid for public-key login with `UsePAM no`; a locked
account is rejected by OpenSSH before key authorization. Disable password
login through the generated policy and a non-password account record. Keep
authorized-key paths and their ancestors free of group/other write access.
The dispatcher runs as a trusted guest service identity with the selected
backend's management access; participants receive no general login to it.

The listener permits public-key authentication and a forced selector only:
`aptl-mcp-v1 INSTANCE GENERATION SERVER`. It denies PTYs, forwarding, agent
forwarding, passwords, environment injection, user rc files, SFTP and arbitrary
commands. Guest management paths and backend argv are never participant inputs.

## Host configuration

Obtain the access record, your public grant record, and the SSH host public key
through the authenticated seat-management channel. Verify the host-key SHA256
fingerprint independently. Then, from a private project directory:

```bash
aptl mcp-access configure \
  --access-record /absolute/access.json --grant /absolute/caller.grant.json \
  --host-public-key /absolute/ssh_host_ed25519_key.pub \
  --expected-host-key 'SHA256:VERIFIED_FINGERPRINT' \
  --identity-file /absolute/host_transport_key --username aptl-mcp \
  --owner-id alice --seat-id seat-1 --instance-id instance-1 \
  --project-dir /absolute/project --client claude
```

Use `--client codex` for `.codex/config.toml`; Claude uses `.mcp.json`. Follow the
client's native project trust and MCP approval flow. Provider login remains the
normal client login. The generated entries use a private per-generation known
hosts file, `StrictHostKeyChecking=yes`, no agent, no multiplexing and `-F /dev/null`.

Manual settings survive regeneration. Ownership metadata records the exact
managed entries; conflicting edits, duplicate JSON keys, stale generations,
changed host pins without a new generation, or another owner's instance fail
without overwriting the config. A locked write-ahead journal recovers an
interrupted publication. `.aptl` and `.codex` state directories must be owned by
the caller and mode 0700. The target config becomes mode 0600.

## Discovery, authority and lifecycle

`aptl.seat-access/v1` contains owner/seat/instance/generation, guest boot and
Docker daemon IDs, project, full 64-hex container IDs, installed pack identity,
distinct guest/outer endpoints, host-key fingerprint, UTC observation time and
lifecycle state. It contains no secrets and grants no authority. Host setup
requires `ready` and an observation at most 120 seconds old.

The guest binding and enrolled key establish authority. Each operation rechecks
caller identity, expiry/revocation, role, unchanged runtime identity and required
capture. Appliance delivery additionally checks the signed host-MCP contract and
boundary evidence at most five seconds old. A changed endpoint or reset needs a
new generation, regenerated enrollment and refreshed host configuration.
`aptl mcp-access refresh --binding PATH --output PATH` refreshes discovery only;
`aptl mcp-access revoke --binding PATH --grant-id ID` revokes active and future
connections. Refresh cannot extend a grant.

Concurrent MCP servers share the guest lifecycle observation lock. These reads
exclude start/reset mutations, and an active lifecycle mutation rejects access.

The relay verifies the exact canonical tool inventory before returning MCP
initialization. It supports tool listing/calls, ping and lifecycle notifications;
resources, prompts, sampling and server-initiated requests are denied. Limits:
1 MiB frames, eight queued requests, 120-second calls, 300-second idle timeout,
one-hour connection lifetime, 64 MiB output and one process per instance/server.
Revocation closes the connection and terminates its process group. Strict remote
SSH teardown must acknowledge closure; otherwise a private taint blocks reuse
until operator recovery creates a clean generation. Do not remove a taint as a
substitute for proving remote cleanup.

Tool schemas retain their JSON Schema structure. Terminal session handles
remain available to the caller for subsequent commands and closure; API login
sessions, service credentials and secret-shaped command output stay redacted.

## Software integration checks

After building the MCP packages, run:

```bash
pytest tests/test_mcp_transport_processes.py tests/test_mcp_payload_processes.py -m integration -q
```

These checks start an ordinary-user OpenSSH listener on an allocated loopback
port. They exercise the production dispatcher and relay with built MCP
processes, including red-role discovery, a blue-role indexer query against a
controlled HTTPS service, revocation, runtime identity mismatch and the browser
WebSocket route. Deployment and capture observations are fixtures. The checks
do not access Docker, alter host limits or qualify a deployed lab.

The payload tests initialize all eight MCP servers from archived and extracted
build outputs after removing their temporary source tree. Flattened common-library
packages retain their own dependencies so runtime imports remain self-contained.
The tests supply a fresh public CA after extraction for services that require
runtime trust material; they make no service calls.

The checks workflow runs this suite after building the MCP packages. The
clean-install job uses the smaller scenario to cover package materialization
and the install/start/teardown lifecycle. Full TechVault tests are triggered
manually during related development. They are intentionally separate from
routine CI because running the full lab on every change is too costly.

Client-driven checks used Claude Code 2.1.274 and Codex 0.154.0 to invoke
`kali_info` through the generated SSH entries. Both returned the built backend's
`target_name: Kali Linux` and `ssh_user: kali`. Codex also exercised its native
app-server MCP call interface. Headless Codex requires explicit approval for the
selected MCP tool; this check approved only `kali_info` for that invocation.
Provider authentication stayed in the host client account. These checks prove
client/transport interoperability, not command execution in a booted guest.

## Appliance-seat integration

`aptl seat start` now carries this contract through the real VM management
channel. The launcher publishes a nonce-bound enrollment request in the
read-only launch share, accepts the guest response only on the private
generation-specific socket, persists the owner-only access bundle, and writes
the selected Claude and Codex configurations. Stop and failed start invalidate
the generation; reset destroys the overlay, rotates instance/generation state,
and requires new client material. Calls made with stale files therefore fail
instead of silently reaching a replacement seat.

Production qualification invokes a read-only tool through both native client
configurations, proves revocation after stop, resets the seat, and records the
current guest/container identities. The two-seat machine-A drill and distinct
machine-B drill remain separately signed evidence; neither unit protocol tests
nor two VMs on one machine substitute for that evidence.
