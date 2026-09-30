# Issue #1178: VM desktop diagnostic

This records an earlier diagnostic image. Its HTTPS-only proxy was removed
after the owner selected ordinary outbound access with no default seat filter;
see [ADR-061](../adrs/adr-061-gateless-vm-seat-access.md). The network results
below describe that earlier image, not the current seat design.

These checks ran on one Linux KVM host on 2026-09-30. They used a local,
uncommitted diagnostic bake. This is functional evidence for the implementation,
not a signed release or APP-3 multi-machine qualification.

## Guest and desktop

The 128 GiB virtual disk passed `qemu-img check`; its file was 9,777,315,840
bytes, below the GHCR single-layer limit. The first boot loaded the offline OCI
closure, started the full lab, and sent a complete guest observation over the
readiness channel. The desktop account's first-boot smoke ran real
`kali_run_command id` and `wazuh_query_alerts` MCP calls before that readiness
response. The guest observed one expected Docker authority holder.

The host entered only its own rootless QEMU network namespace to check the
Guacamole gateway. The gateway returned HTTP 200 and a prompt-free Guacamole
session opened the XFCE desktop with Epiphany and RED/BLUE terminal tabs. The
same mapped port was unreachable from the ordinary host network; another local
Unix account could not enter the seat's namespace. Both existing heron user
VMs were left running and unchanged.

## Provider network

The diagnostic VM was restarted with QEMU `restrict=on` and one guest-only
HTTPS proxy forward. An XFCE terminal inside the VM ran an HTTPS CONNECT to
`api.anthropic.com`: the tunnel returned 200 and the API returned its expected
unauthenticated 404 response. Claude Code 2.1.285 then reached its normal
login-method screen. No provider account was used and no credential was baked.
The proxy's targeted tests reject local and private destinations, non-HTTPS
methods, and other ports; its Unix socket was owner-only.

The guest reboot was stopped after the provider check, before a second full lab
readiness run. Its disposable overlay was removed after QEMU exited. The
first-boot observation and browser captures are retained locally under
`build/seat-1178-reviewfix-live/`; they are not release artifacts.
