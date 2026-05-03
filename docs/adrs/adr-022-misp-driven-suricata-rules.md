# ADR-022: MISP-driven Suricata rules via a tag-graduated sync service

## Status

accepted

## Date

2026-05-03

## Context

[Issue #250](https://github.com/Brad-Edwards/aptl/issues/250) closes the gap
between two existing SOC components that did not previously talk to each
other: MISP holds threat intelligence (IPs, domains, URLs, file hashes),
and Suricata is the network IDS in the data path, but Suricata's ruleset
was entirely operator-authored — IOCs added to MISP by blue (or by future
threat-intel feeds) never reached the wire. Real OSS-SOC stacks always have
this loop: SOC analyst (or upstream feed) adds an indicator to the canonical
intel platform, automation pushes it to enforcement points, traffic matching
it gets actioned within minutes. The lab needs the same loop so blue's
threat-intel work composes with detection on the wire.

Two adjacent decisions constrain the design:

- **[ADR-019](adr-019-suricata-ids-only-prevention-via-wazuh-ar.md)** —
  Suricata stays IDS-only. Packet-level prevention is delivered by Wazuh
  active-response. Anything this design produces must therefore be `alert`
  rules; `drop`/`reject` rules from this pipeline would have no effect under
  the lab's current Docker network model and would mislead blue about what
  the lab actually enforces.
- **[ADR-008](adr-008-soc-stack-integration.md)** — MISP is the canonical
  IOC store and the SOC stack's intel hub. The new sync component does not
  fork or duplicate that role; it consumes MISP and emits Suricata rules,
  nothing more.

## Decision

Ship a small, single-purpose Python service `aptl-misp-suricata-sync`
under the `soc` compose profile. Architecture and invariants:

1. **Tag-graduated enforcement.** The service polls MISP's
   `POST /attributes/restSearch` filtered by a configurable tag
   (`IOC_TAG_FILTER`, default `aptl:enforce`). MISP attributes without
   the tag are intel only; tagging them is the explicit graduation step
   that promotes an indicator to detection. Default lab posture is the
   service running with zero tagged IOCs — blue's job per iteration is to
   populate intel and graduate it.
2. **Alert-only rules per ADR-019.** The translator hard-codes `alert`
   as the rule action across every IOC type. Any future "drop" semantics
   would require a follow-up ADR overriding ADR-019; the translator's
   `test_action_is_always_alert_never_drop` is the regression guard.
3. **Dedicated rule file.** Generated rules go to
   `/etc/suricata/rules/misp/misp-iocs.rules`, mounted via a host-side
   bind mount of `./config/suricata/rules/misp/` shared between the
   Suricata container and the sync service. The repo ships a seed
   `misp-iocs.rules` plus empty `misp-{md5,sha1,sha256}.list` files so
   Suricata can load the configured rule paths cleanly on the very first
   `aptl lab start`, before the sync service has had a chance to write.
   The bind mount also avoids the named-volume initialization race where
   Suricata starts ahead of the sync service and finds the rule path
   missing. The operator-authored `local.rules` is never touched. The
   two files are concatenated by Suricata at runtime via the
   `rule-files:` list in `config/suricata/suricata.yaml`. Mixing them
   was rejected: it would conflate hand-written and intel-driven rules
   in `git blame`, in run archives, and in any operator inspection.
4. **Deterministic SID allocation.** SID is computed as
   `SID_BASE + (zlib.crc32(f"{type}|{value}") & 0x7FFFFFF)`. CRC32 over a
   stable composite key gives a deterministic, content-addressable SID
   that does not shift when other IOCs are added or removed (the failure
   mode of "list-position" allocation). On the rare collision the
   translator drops the second occurrence and logs a warning; emitting two
   rules with the same SID would be a Suricata startup error. `SID_BASE`
   defaults to `2_000_000`, well clear of the operator's hand-written
   range (current max `1000091` in `local.rules`) and well clear of ET
   Open's reserved 2.x ranges.
5. **Idempotent file writes.** `RuleFileWriter.write_if_changed` reads
   the existing file (if any), compares to the would-be content, and
   only writes — atomically via `<path>.tmp` + `Path.replace` — on
   change. The rule-file header carries the MISP URL, tag filter,
   `sid_base`, and IOC count but **no timestamp** — adding a fresh
   timestamp every render would always invalidate the equality check
   and trigger a Suricata reload every interval even when the IOC set
   is unchanged. The same idempotent writer also produces the
   per-type hash list sidecars; reload only triggers if any of the rule
   file or any list file actually changed.
6. **Live reload via the unix-command socket.** `suricata.yaml` enables
   the unix-command interface at
   `/var/run/suricata/suricata-command.socket`. The sync service mounts
   the same `suricata_command_socket` named volume and speaks the
   handshake-then-`reload-rules` JSON protocol directly (~30 lines in
   `suricata_reloader.py`). This avoids dragging the `suricata` apt
   package onto the sync container just for `suricatasc`. The container
   restart that would otherwise be needed to load new rules is avoided —
   important for an interval-driven service.
7. **MISP-down preservation.** If MISP is unreachable or returns
   malformed data, the loop logs and exits the tick without writing to
   disk. The previous rule file stays in place, so a transient MISP
   outage does not collapse Suricata's intel-driven detection.
8. **Hash-content escaping.** Bytes outside `[A-Za-z0-9._-/?=&]` are
   hex-escaped via Suricata's `|XX|` notation in any `content:` value.
   The threat model is a poisoned upstream MISP feed (or a hostile
   contributor to a public feed), not a hostile lab operator — but the
   escape cost is zero and the test
   `test_rejects_quote_or_semicolon_in_value_via_escape` is the
   regression guard.

9. **Validation at the IOC boundary.** IPs are validated via
   :mod:`ipaddress` before being spliced into rule headers (a malformed
   value would render an unparseable rule and break Suricata reload);
   hashes are validated for hex format and per-type length (md5=32,
   sha1=40, sha256=64) before being written to a list file (bad data
   would make the entire hash list unloadable). Invalid IOCs are
   skipped with a warning rather than poisoning the output.

10. **URL parsing via stdlib.** ``urllib.parse.urlparse`` handles
    credentials, ports, fragments, query strings, IPv6 hosts, and
    schemeless inputs correctly — none of which a hand-rolled splitter
    gets right. Hosts are lowercased and stripped of userinfo / port;
    path includes the query string when present so URL IOCs that vary
    by query parameter still match.

11. **Anchored domain / host matching.** ``dns.query`` and ``http.host``
    matches use the ``dotprefix`` modifier so an IOC for ``bad.com``
    matches ``bad.com`` and ``sub.bad.com`` but not ``notbad.com``.
    Without ``dotprefix`` the ``content:`` directive is a substring
    match and produces avoidable false positives on every domain
    sharing a suffix with the IOC.

12. **Reload retry on failure.** ``SyncRunner`` carries a
    ``reload_pending`` flag across ticks. If a Suricata reload fails
    (socket not yet ready on first start, transient signal failure),
    the next tick retries the reload even when the rule file is
    unchanged, so transient reload failures cannot leave generated
    rules permanently inactive.

13. **Transactional file ordering.** Per-type hash list files
    (``misp-<type>.list``) are written *before* ``misp-iocs.rules`` on
    each tick. Suricata's hash rules reference the list files; writing
    them first means the rule file's references are always resolved
    against fresh content, never stale.

14. **MISP envelope drift preservation.** ``MispClient`` returns
    ``None`` for both transport failures *and* malformed envelope
    structures (missing ``response`` key, non-list ``Attribute``,
    etc.), and only returns ``[]`` for a structurally valid empty IOC
    set. Treating drift as ``[]`` would wipe the rule file on API
    changes; treating it as ``None`` preserves the last-known-good
    file.

### Translator IOC matrix

| MISP type      | Generated rule shape                                                                       |
| -------------- | ------------------------------------------------------------------------------------------ |
| `ip-src`       | `alert ip <ioc> any -> any any (...)` — matches source IP                                  |
| `ip-dst`       | `alert ip any any -> <ioc> any (...)` — matches destination IP                             |
| `domain`/`hostname` | `alert dns ... dns.query; content:"<escaped>"; nocase`                                |
| `url`          | `alert http ... http.host; content:"<host>"; nocase[; http.uri; content:"<path>"; nocase]` |
| `sha256`/`sha1`/`md5` | one rule per type, referencing a sidecar list file: `... file.data; filesha256:/etc/suricata/rules/misp/misp-sha256.list; ...` |
| anything else  | skipped with a warning log                                                                 |

Hash IOCs are aggregated rather than rendered one-rule-per-IOC because
Suricata's `filemd5` / `filesha1` / `filesha256` keywords take a *file
of hashes* as their argument, not an inline digest. The translator
therefore emits one rule per non-empty hash type and writes the digests
themselves to `misp-<type>.list` files alongside the rule file. This is
both syntactically correct (the inline-content form Suricata would
reject) and operationally efficient (one reload regardless of how many
hashes ship).

URLs match `http.host` for the host component and `http.uri` only when
the path is non-trivial; host-only URLs do not emit a `content:"/"` URI
match (which would broadly false-positive against ordinary traffic).

### Service shape

The service is the lab's first long-running Python daemon. Layout under
`src/aptl/services/misp_suricata_sync/` is intentionally narrow so the
package can serve as a template for future services:

- `config.py` — Pydantic v2 `ServiceConfig.from_env()` mirroring
  `aptl.api.deps`'s env-then-validate pattern (no `pydantic-settings`).
- `models.py` — `MispAttribute` DTO + `RenderedRule`.
- `misp_client.py` — curl-subprocess client matching
  `aptl.core.collectors._curl_json` semantics: never raises, returns
  `None` on failure, never logs the API key.
- `translator.py` — pure: `IocTranslator.translate(...) -> list[RenderedRule]`,
  plus `render_rules_file(...)` that adds the file header.
- `rule_writer.py` — atomic, idempotent `write_if_changed`.
- `suricata_reloader.py` — unix-command socket client.
- `main.py` — `run_once`, `run_loop`, `main`. SIGTERM/SIGINT-aware.

The container is `python:3.11-slim` + `curl` + the aptl wheel installed
via `pip install .` (no extras, no PyMISP, no suricatasc). Console
script `aptl-misp-suricata-sync` is the entrypoint.

## Consequences

### Positive

- Closes the MISP→detection loop without touching ADR-019's IDS-only
  posture. Blue's threat-intel work via `aptl-threatintel` MCP now has
  a visible effect on the wire within one sync interval.
- Stable SIDs mean Suricata's reload is a no-op when MISP is quiet.
- Tag-graduated enforcement gives blue a deliberate "promote to detect"
  step instead of every MISP indicator silently becoming a rule.
- Sync service is stateless across restarts (CRC32 SID is a function of
  IOC content, not insertion order), so container restarts don't
  resequence rules and don't trigger spurious Suricata reloads.
- The service container is small (`python:3.11-slim` + curl + the aptl
  wheel) and short — the entire service is < 400 LOC of Python.

### Negative

- The lab now has a unix-command socket on the Suricata container.
  Modest attack surface: it's bound to a unix socket on a private
  Docker volume, not exposed on any network. Only the sync service
  container mounts the same volume.
- Every IOC matches Suricata's IDS-only posture — `alert`, not `drop`.
  Blue cannot author MISP IOCs that *block* traffic. Real prevention
  remains the Wazuh AR path (#248/#249). This ADR makes that boundary
  explicit so blue doesn't expect MISP-driven blocking.
- The service is the lab's first Python daemon, so the supervisord /
  in-process pattern that exists for Wazuh agents does not apply. New
  service is a single foreground process under restart=unless-stopped.

### Risks

- **Rule churn from a noisy upstream MISP feed.** If a feed graduates
  thousands of IOCs in a short window, Suricata will reload often.
  Mitigation: the `aptl:enforce` tag is opt-in per indicator. Lab
  default is empty. Future work could batch reloads.
- **Tag misuse.** If the wrong tag is applied to a high-traffic IOC
  (`tlp:white` instead of `aptl:enforce`, etc.), a flood of false
  positives is possible. Mitigation: the tag is documented in this ADR
  and in the README; the default config is `aptl:enforce`, not
  `tlp:white`, specifically so generic TLP tags don't graduate IOCs by
  accident.
- **Suricata socket protocol drift.** The handshake currently uses
  `version: 0.2`. If upstream Suricata bumps the protocol, the
  reloader's `_send_command` will report `return: NOK` and we fall
  back to "skip reload, log warning" — the rule file still updates on
  disk, and a Suricata container restart still picks it up. Detection
  degrades to "rules apply on next restart," which is acceptable until
  the protocol bump is addressed.

## Verification

- 52 pytest unit tests cover translator (per-type rendering, ADR-019
  alert-only invariant, deterministic SID, collision behavior, content
  escaping), rule writer (atomicity, idempotency, no-truncate-on-error),
  reloader (handshake, reload command, missing-socket failure mode),
  MISP client (auth header, tag filter, malformed-response tolerance,
  no-API-key-in-logs invariant), config (validators), and the sync
  loop (skip-on-fetch-error, skip-on-no-change).
- E2E lab recipe: `aptl lab stop -v && aptl lab start --profiles soc`,
  submit an IOC via the `aptl-threatintel` MCP with the `aptl:enforce`
  tag, wait one sync interval, then
  `docker exec aptl-suricata cat /etc/suricata/rules/misp/misp-iocs.rules`
  to confirm the rule landed and check `suricata_logs/eve.json` for
  alerts on matching traffic.

## Related

- [ADR-008](adr-008-soc-stack-integration.md) — MISP and Suricata
  selection rationale.
- [ADR-019](adr-019-suricata-ids-only-prevention-via-wazuh-ar.md) —
  Suricata IDS-only constraint.
- [#247](https://github.com/Brad-Edwards/aptl/issues/247) — closed in
  ADR-019; informs why this design produces `alert` rules only.
- [#248](https://github.com/Brad-Edwards/aptl/issues/248) /
  [#249](https://github.com/Brad-Edwards/aptl/issues/249) — host-side
  enforcement (Wazuh AR). Companion to this ADR's network-side
  detection path.
- [#250](https://github.com/Brad-Edwards/aptl/issues/250) — implements
  this ADR.
