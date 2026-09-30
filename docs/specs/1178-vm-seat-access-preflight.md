# Issue #1178: VM seat desktop preflight

The operator chose the August XFCE/xrdp desktop through browser-based Guacamole. This decision supersedes the initial architecture preflight's assumption that the APTL web control panel would remain the guest UI. ADR-061 records the current contract. This note identifies implementation checks; it is not qualification evidence.

## Guest entry and boundary

- The signed VM-only boundary policy has one participant Guacamole publication. The launch descriptor binds its exact digest and the launcher maps it to a loopback port inside the launching user's rootless network namespace. Other local host users cannot reach or enter that namespace. No recovery API or host MCP listener is published for the new image.
- Guacamole's header identity comes only from the internal nginx proxy; it overwrites an inbound identity header. PostgreSQL, guacd, Guacamole, and xrdp have no physical-host publication. Database and xrdp credentials are generated in each overlay, never in the golden image, process argv, a browser URL, or host-client configuration.
- Keep the guest-owned Docker daemon, read-only launch share, fixed QEMU argv, owner-private seat persistence, KVM admission, live host listener and negative reachability probes, fresh guest observation, and signed image trust. Existing selected digests and overlays remain untouched.
- The desktop account can use guest services and guest Docker. First boot hands that account the live lab's private MCP inputs and verifies red and blue tool calls before marking the run ready. Agent/provider authentication takes place inside that VM. The host MCP enrollment, expiring grant, and dedicated access channel have no role in a new seat.
- A QEMU guest forward connects a single proxy address to a private Unix socket owned by the seat launcher. The proxy permits HTTPS CONNECT to public DNS destinations on port 443 for Claude sign-in and browsing; local and private addresses, IP literals, and other methods or ports are refused. Guest direct outbound traffic remains blocked by `restrict=on`.

## Runtime and release checks

- The guest first-boot unit loads only its offline signed image archive, starts the desktop gateway, starts the full lab, and publishes readiness on the private virtio channel. The host enters only the tracked VM's user namespace to check the actual Guacamole page and prompt-free session path. Saved `ready` and a live QEMU PID alone do not establish current gateway health.
- Changed signed-document readers reject duplicate JSON keys with the existing strict parser. The new policy generation must not reinterpret old signed policy bytes; newer CLIs either honor an old image's published contract or refuse without altering its state.
- The existing standalone qualification script disables actual first boot. Real KVM checks must launch the baked guest through `aptl seat`, inspect the XFCE/Guacamole connection and lab services, test browser reopening and restart, and check host protection. Two test seats on one host do not meet APP-3's independent-machine qualification by themselves.
- A clean committed source revision, image/config digests, accepted qualification, signed immutable GHCR candidate, anonymous acquisition and fresh boot precede promotion of `:latest`. APP-3 remains ACTIVE until its complete evidence and identity bindings are verified.

The abandoned APTL web control panel is not started in the new guest. Its non-VM source path is separate from the desktop delivery and should not be mistaken for participant access. Scenario-level service authentication, such as Wazuh's, remains scenario content.
