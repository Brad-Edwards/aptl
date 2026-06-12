# AD Steady-State Inventory

This directory is the SCN-010 / issue #332 inventory bundle for the TechVault
`ad` container. It applies the ACES-owned asset inventory methodology
documented in
<https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/asset-inventory-methodology.md>
to the realized `aptl-ad` Samba Active Directory Domain Controller.

The capture used a fresh local lab on 2026-05-23 after
`uv run aptl lab stop -v -y && uv run aptl lab start --skip-seed` completed and
`aptl-ad` reached healthy steady state. Treat this as a frozen post-start
steady-state artifact for the observed lab instance, not as byte-identical
rebuild proof.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-ad` |
| Compose service | `ad` |
| TechVault profile | `enterprise` |
| Source class | `custom-build` |
| Source package | `containers/ad/` plus `containers/_wazuh-agent/` |
| Image tag | `aptl-ad:latest` |
| Image digest | `aptl-ad@sha256:e52bc1094b3058452faaf4d88b11712c41b67029d85f88cbdae1f7475bbcf957` |
| Runtime OS | Ubuntu 22.04.5 LTS |
| Samba version | 4.15.13-Ubuntu |
| Runtime command | `/usr/bin/python3 /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf` |
| Domain | `TECHVAULT` / `TECHVAULT.LOCAL` (`techvault.local`) |
| Listener set | DNS, Kerberos, RPC, NetBIOS, LDAP, SMB, LDAPS, Global Catalog |
| Network identity | `aptl_aptl-internal` IPv4 `172.20.2.10` |
| Data volumes | `aptl_ad_data:/var/lib/samba`, `aptl_ad_logs:/var/log/samba` |
| Privileged runtime surface | `CAP_SYS_ADMIN` and `CAP_NET_ADMIN` |
| Supervised programs | `samba`, `rsyslog`, in-process Wazuh agent |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt` |
| Docker Compose service intent is represented by the Compose service slice. | `evidence/compose-service.ad.json` |
| Custom image identity, config, and layers are recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt` |
| Source package inputs are checksum-addressable. | `evidence/source-checksums.txt` |
| Realized runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-internal.json`, `evidence/docker-volume.ad-data.json`, `evidence/docker-volume.ad-logs.json`, `evidence/docker-top.txt`, `evidence/runtime-baseline.txt` |
| OS packages and language/tool manifests visible in the image are recorded. | `evidence/os-packages.txt`, `evidence/language-manifests.txt` |
| Patch state is machine-readable. | `evidence/trivy-vulnerabilities.json.gz`, `evidence/trivy-vulnerability-counts.json`, `evidence/trivy-vulnerability-list.json` |
| Catalogued Samba, supervisor, Wazuh, flag, and generated runtime paths are hashable. | `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt` |
| Evidence files have integrity checksums. | `evidence/evidence-sha256sums.txt` |
| Captured facts are mapped to current ACES surfaces or explicit claim boundaries. | `mapping-ledger.yaml` |

## Capture Findings

- The runtime image is a first-party custom build from
  `containers/ad/Dockerfile`, with Wazuh agent support copied from
  `containers/_wazuh-agent/`.
- The image uses Ubuntu 22.04 and Samba 4.15.13-Ubuntu. The observed local image
  digest is the reproducibility anchor for this capture.
- Samba provisions the `techvault.local` forest/domain at Windows 2008 R2
  functional level, with account lockout threshold 10, duration 30 minutes,
  and reset-after 15 minutes.
- The domain contains 15 users and 45 groups at capture time. Scenario users,
  service accounts, SPNs, high-risk group memberships, and password policy are
  recorded in the runtime baseline and encoded in the SDL under
  `nodes.techvault.ad.runtime.identity_authorities` without raw passwords.
- The service exposes DNS, Kerberos, RPC, NetBIOS, LDAP, SMB, LDAPS, Global
  Catalog, and dynamic RPC listener surfaces inside the internal network. No
  host ports are published.
- The named volumes `aptl_ad_data` and `aptl_ad_logs` are mounted at
  `/var/lib/samba` and `/var/log/samba`; the SDL also records the full
  observed runtime mount table, including container backend and pseudo-filesystem
  mounts.
- PID 1 is `supervisord`, supervising Samba, rsyslog, and the in-process Wazuh
  agent. The Wazuh agent tails Samba logs and registers as `aptl-ad-agent`.
- The SDL encodes the full committed `getent passwd` and `getent group`
  local identity snapshot, all checksum-backed filesystem entries, and all
  catalogued filesystem-tree paths for this frozen capture.
- The `jessica.williams` account is present in the captured user list and
  remains tied to the weak-password scenario account. The committed evidence
  does not include a non-empty `samba-tool user show` block for that user and
  does not list Sales, VPN-Users, or Domain Users membership for that user.
  Although the provisioning script contains intended add-member commands for
  that account, the SDL follows the realized steady-state runtime evidence for
  membership claims, so those memberships are not asserted.
- Trivy 0.70.0 reported 140 package vulnerability findings at scan time:
  65 medium and 75 low.
- Scenario target secrets in Docker/Compose and runtime evidence are retained
  verbatim. The AD administrator password and generated flag/token contents are
  committed as TechVault scenario content.

## ACES Mapping Result

Current ACES SDL encodes the AD node identity, custom image pin, build recipe,
source inputs, image layers, network attachment, service exposure, healthcheck
status and health logs, full observed runtime mount table, committed filesystem
inventory with metadata and digests, container host/security configuration,
process set, runtime environment, capabilities, restart/resource policy,
package and scanner inventory summaries, local Linux identity database, Samba
domain logical state through the ACES `runtime.identity_authorities` surface,
scenario weakness IDs, content entries, domain and host-local account records,
and relationships to DNS forwarding and Wazuh telemetry.

Brad-Edwards/aces#401 added the provider-neutral identity-authority surface
that this bundle now uses for the TECHVAULT domain authority, directory users,
groups, OUs, service accounts, service principals, password/lockout policy, and
membership facts. AD-native subject attributes captured in committed evidence
are represented as first-class identity-authority attributes where they are
non-secret facts, including object GUID/SID, account-control, primary-group,
last-logon, admin-count, and creation-time values. `pwdLastSet` stays in the
evidence bundle but is not encoded as an SDL attribute because the current SDL
identity attribute model does not carry that AD-specific field. No known ACES
expressivity gap remains for the encoded, claim-bounded AD steady-state
inventory facts in this ledger. Samba private database content, Kerberos key
material, and Wazuh `client.keys` remain represented by observable
path/metadata/checksum shape where useful; AD administrator and generated flag
scenario values are captured verbatim.

Run:

```bash
aptl aces-inventory validate docs/aces/inventory/ad
aptl aces-inventory gaps docs/aces/inventory/ad
```

## Known Limits

- The inventory is a frozen steady-state observation, not byte-identical
  rebuild proof.
- Generated Samba databases, Kerberos keys, Wazuh enrollment material, and CTF
  flag files can change on a fresh reprovision. Checksums are snapshot facts.
- AD administrator and generated flag/token values are committed as scenario
  content; other generated service databases and key stores are represented by
  path, metadata, and checksum evidence in this bundle.
- Vulnerability results are time-sensitive to the Trivy database and advisory
  feeds.
- The capture does not assert attack-induced state changes or later
  operator-driven runtime modifications.
