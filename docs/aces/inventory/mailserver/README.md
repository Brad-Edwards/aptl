# Mailserver Steady-State Inventory

This directory is the SCN-010 / issue #335 inventory bundle for the TechVault
`mailserver` container. It applies the ACES-owned asset inventory methodology to
the realized `aptl-mailserver` container and uses the completed webapp,
fileshare, and workstation inventories as the granularity bar.

This capture is non-destructive. It used the already-running local `aptl`
project on 2026-05-28, started only the mail profile service, and did not run
`aptl lab stop -v && aptl lab start`. The mounted
`containers/mailserver/setup.sh` script was executed manually after container
start because the upstream docker-mailserver image waited for accounts and did
not auto-run the mounted script. Treat this bundle as a frozen observation of
that local steady state, not as clean-lab rebuild proof.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-mailserver` |
| Compose service | `mailserver` |
| TechVault profile | `mail` |
| Source class | `upstream-image-plus-mounted-provisioner` |
| Image | `ghcr.io/docker-mailserver/docker-mailserver:latest` |
| Image digest | `ghcr.io/docker-mailserver/docker-mailserver@sha256:af51b15dd3fc72153c0e90eb7692bb5e3a463212d87959a80fa7aa89b617d44a` |
| OCI version / revision | `v15.1.0` / `060bf9a47443382fb7e37f30d6ab9709b4b8aeab` |
| Runtime OS | Debian GNU/Linux 12 (bookworm) |
| Runtime command | `/usr/bin/dumb-init -- supervisord -c /etc/supervisor/supervisord.conf` |
| Reachable participant ports | TCP 25, 143, 465, 587 |
| Host-published ports | TCP 25, 143, 587, 993 |
| Notable realization caveat | TCP 993 is host-published but refused; TCP 465 is reachable but implicit TLS probe fails. |
| Network identity | `dmz-net` IPv4 `172.20.1.21`; `internal-net` IPv4 `172.20.2.26` |
| Mail components | docker-mailserver `v15.1.0`, Postfix 3.7.11, Dovecot 2.3.19.1, amavis 2.13.0, OpenDKIM 2.11.0, OpenDMARC 1.4.2 |
| Mail domain | `techvault.local` |
| Mailboxes | 10 fixture mailboxes under `/var/mail/techvault.local` |
| Package inventory | 395 dpkg packages |
| Trivy vulnerability findings | 1415 total: {'critical': 33, 'high': 192, 'low': 724, 'medium': 414, 'unknown': 52} |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Compose service intent and upstream image identity are recorded. | `evidence/compose-service.mailserver.json`, `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/docker-buildx-imagetools.image.txt`, `evidence/docker-buildx-imagetools.image.raw.json` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-dmz.json`, `evidence/docker-network.aptl-internal.json`, `evidence/docker-volume.mailserver-data.json`, `evidence/docker-volume.mailserver-state.json`, `evidence/docker-volume.mailserver-logs.json`, `evidence/docker-top.txt`, `evidence/docker-logs.mailserver.txt`, `evidence/runtime-baseline.txt` |
| Mail logical state is recorded. | `evidence/mailserver-state.txt`, `evidence/participant-discovery.kali.txt`, `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt` |
| OS packages and SBOM component inventories are recorded. | `evidence/os-packages.txt`, `evidence/language-manifests.txt`, `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/syft-sbom.cyclonedx.json.gz` |
| Patch state is machine-readable. | `evidence/trivy-vulnerability-counts.json`, `evidence/trivy-vulnerability-list.json` |
| osquery table attempts are recorded. | `evidence/osquery-apt-sources.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-processes.json`, `evidence/osquery-programs.json` |
| Evidence files have integrity checksums. | `evidence/evidence-sha256sums.txt` |
| Captured facts are mapped to current ACES surfaces. | `mapping-ledger.yaml` |

## Capture Findings

- The runtime image is the upstream docker-mailserver `v15.1.0` image at
  `ghcr.io/docker-mailserver/docker-mailserver@sha256:af51b15dd3fc72153c0e90eb7692bb5e3a463212d87959a80fa7aa89b617d44a`. The APTL repo contributes the Compose service and mounted
  mailbox-provisioning script, not the upstream Dockerfile.
- The service runs under `dumb-init` and `supervisord`; load-bearing child
  programs include Postfix, Dovecot, amavis, OpenDKIM, OpenDMARC, cron, rsyslog,
  and update/check helper processes.
- The mail domain is `techvault.local`; ten fixture mailboxes are provisioned by
  `setup email add`. Raw mailbox credentials are not represented in SDL or
  evidence beyond source fixture classification.
- Participant-vantage probes from `aptl-kali` reached SMTP/25,
  submission/587, IMAP/143, and TCP/465. The 465 implicit TLS probe failed with
  `wrong version number`, so the SDL records that listener as SMTP-family
  plaintext on the `smtps`-named service rather than as working implicit TLS.
- TCP/993 is host-published by Docker but refused at the participant vantage;
  it is encoded as a published-port realization fact, not as an active
  `Node.services` listener or `runtime.mail_services` listener.
- SMTP/25 advertised `PIPELINING`, `SIZE 10240000`, `ETRN`,
  `ENHANCEDSTATUSCODES`, `8BITMIME`, and `CHUNKING`. Submission/587 additionally
  advertised `AUTH PLAIN LOGIN`, `DSN`, and `AUTH=PLAIN LOGIN`.
- Dovecot IMAP/143 advertised `IMAP4rev1`, `SASL-IR`, `LOGIN-REFERRALS`, `ID`,
  `ENABLE`, `IDLE`, `LITERAL+`, `AUTH=PLAIN`, and `AUTH=LOGIN`.
- `postqueue -p` reported an empty queue at the snapshot point. Queue contents
  are dynamic and are encoded as a queue-shape fact, not as stable messages.
- `setup alias list` reported that `postfix-virtual.cf` does not exist; aliases
  are therefore encoded as an empty runtime alias set for this snapshot.
- Two upstream Docker-history shell fragments use braced shell parameter syntax
  such as `${EC}`. ACES treats `${...}` as SDL variable syntax during
  instantiation, so the SDL build-history strings use shell-equivalent `$EC` /
  `$?` spelling. The raw byte-exact Docker history is preserved in
  `evidence/docker-history.image.txt` and `evidence/docker-history.image.jsonl`.
- Trivy captured 1415 vulnerability findings at scan time. Vulnerability
  evidence is time-sensitive to the Trivy database and advisory feeds.

## ACES Mapping Result

Current ACES SDL, including ACES issue #420 / ADR-038, can encode the
catalogued mailserver facts: node identity, upstream image provenance,
transport listeners, host-published ports, runtime mounts, container host
configuration, process/environment/capability policy, filesystem inventory,
local identity database, package and vulnerability inventory, typed mail-service
components, listeners, domain, mailbox store, mailboxes, queue shape, settings,
and mail-access relationships.

No known ACES expressivity gap remains for the catalogued mailserver
steady-state inventory facts in this ledger. The capture does not assert a full
root filesystem catalogue, byte-identical rebuildability, attack-induced state
changes, or a destructive clean-lab reset.

Run:

```bash
uv run aptl aces-inventory validate docs/aces/inventory/mailserver
uv run aptl aces-inventory gaps docs/aces/inventory/mailserver
```

## Known Limits

- The evidence came from a running lab plus non-destructive mail profile start,
  not a destructive fresh reset.
- The mounted setup script was manually executed before capture to realize the
  authored mailbox state.
- The capture does not prove byte-identical rebuildability or full root
  filesystem equivalence.
- Vulnerability results are time-sensitive to the Trivy database and advisory
  feeds.
- osquery `installed_applications` and `programs` were unavailable in the Linux
  osquery table registry used by the digest-pinned osquery 4.9.0 scanner image.
- The capture does not assert attack-induced state changes, later
  operator-driven runtime modifications, or stable message-by-message queue
  contents.
