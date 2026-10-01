# ADR-061: Browser Desktop for VM Seats

## Status

accepted

Owner decision for issue #1178 on 2026-09-30. This supersedes the VM-seat browser UI and host-MCP entry decisions in ADR-059 and ADR-060. Their signed image, per-user VM, capacity, and host-containment decisions remain in force.

## Context

The earlier seat image booted a headless Ubuntu guest. Its participant port served an APTL web control panel and terminal, while an expiring SSH-carried host MCP grant linked agents on the physical host to the guest. The operator's August seats instead gave each participant an XFCE desktop with a browser and red/blue Claude terminals, reached through Apache Guacamole. The operator selected that desktop experience for the nested `aptl seat` VM and retired the APTL web control panel as a participant interface. Extra APTL login and grant steps obstruct experimentation.

## Decision

A new seat image boots XFCE and xrdp inside its own guest. Apache Guacamole and guacd run from digest-pinned images loaded from the signed offline archive. A private PostgreSQL database holds one RDP connection. An internal nginx proxy supplies the fixed Guacamole header identity; the participant opens the gateway through `aptl seat open-kiosk` without a Guacamole password prompt or an APTL launch token. Guacamole's session mechanism and the xrdp password are generated inside the disposable overlay and are never copied to the golden disk. The proxy replaces any client-supplied identity header. Only the proxy is published through QEMU's per-user network namespace; Guacamole, guacd, PostgreSQL, and xrdp have no separate host port mapping. Scenario applications retain their own native authentication.

The guest desktop autostarts a browser and red/blue terminal tabs. The signed image includes the Claude executable and built MCP servers. Agent/provider sign-in belongs to the participant inside the guest and is not baked into the image. The terminals use the guest's lab services and the current run's guest configuration; no host MCP enrollment, caller grant, generated host client files, or access virtio channel is created for the new image.

The signed boundary policy advances generation and declares one `participant` TCP publication at guest loopback port 8080. Host-side port allocation may choose a different loopback outer port. QEMU runs inside a rootless network namespace owned by the launching Unix account. The launcher enters that namespace to observe its listener, verify Guacamole readiness, and open the participant browser. Other host accounts cannot enter the namespace, and the gateway port is unreachable from the ordinary host network. The launcher keeps exact policy-to-mapping validation, private 9p launch share, KVM resource admission, forbidden-reachability probe, fresh guest boundary observation, and a fatal readiness gate. Status checks current gateway availability separately from saved lifecycle state and QEMU PID. Old image digests remain sticky and keep their old signed contract; existing overlays are neither migrated nor reset.

The seat launcher does not impose default outbound network controls. Rootless
`slirp4netns` gives QEMU's private namespace an outbound route, and QEMU's
user-mode NAT has no egress restriction or HTTPS-only proxy. Guest traffic is
subject to the host network and scenario rules; operators may apply their own
event-specific controls. Network services exposed by the physical host can be
reached from the guest. The VM boundary does not share host files or Docker.
Optional outbound controls are tracked in
[issue #1182](https://github.com/Brad-Edwards/aptl/issues/1182).

The bake reuses the canonical offline package and OCI image closures, golden-state scan, build record, qualification path, and GHCR/Cosign publication. The image may be promoted only after a clean build, real-VM desktop/lab and host-boundary checks, signed candidate publication, and anonymous acquisition/boot. No source change may silently change an already selected disk or a live user's overlay.

## Consequences

The participant has one browser path into the VM desktop and can reopen it without an APTL token or expiring grant. The guest account is a deliberate local authority inside the disposable VM, including its guest Docker daemon. The physical host contributes no Docker socket or writable share. The network namespace separates local Unix accounts without adding participant authentication; processes running as the same Unix account can open that account's seat. A remote participant first enters their assigned host account, then runs `aptl seat open-kiosk` there.

The Guacamole stack requires a generated, overlay-private database and xrdp secret even though no participant credential is entered at the gateway. The older APTL web control path no longer starts in new seat guests and is not their participant interface.
