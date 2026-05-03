# ADR-024: Orchestrator-side purple-team continuity carve-out

## Status

accepted

## Date

2026-05-03

## Context

[ADR-021](adr-021-active-response-whitelist-via-wrapper.md) shipped the **in-band** kali-IP carve-out: the standalone `aptl-firewall-drop` AR script consults `/var/ossec/etc/lists/active-response-whitelist` before applying any `iptables -I` and short-circuits when the source IP is whitelisted. That defends against the most common wedge — blue authoring a Wazuh AR rule that fires `firewall-drop` against any kali traffic and ending the loop after iteration 1.

Three classes of bypass slip past the in-band defense:

1. **Custom AR scripts.** Blue can author their own active-response binary that calls `iptables` directly without consulting the whitelist. The wrapper protects only the canonical command; nothing in Wazuh forces blue to use it.
2. **Manager-side raw commands.** Wazuh `<command>` blocks accept arbitrary shell argv. A blue-authored command that calls `iptables` from the manager (or from another path) inside an in-process agent's namespace bypasses the whitelist entirely.
3. **Manual researcher mistakes.** A researcher debugging blue's tradecraft might `docker exec aptl-webapp iptables -I INPUT -s 172.20.4.30 -j DROP` and forget to undo it. Subsequent iterations look broken without an obvious cause.

In every case, the symptom is the same: a target's `iptables -L INPUT` ends up with a `-A INPUT -s <kali_ip> -j DROP|REJECT` rule that has no port, protocol, payload, or behavior qualifier. That rule wedges the loop.

We need an **out-of-band complement** to ADR-021: an orchestrator-side audit that inspects each target's iptables between iterations, detects blanket kali source-IP drops regardless of how they got installed, removes them, and records each removal in the run archive so the researcher can audit what was undone.

## Decision

Implement the audit as a callable Python module — `aptl.core.continuity` — plus a thin CLI command — `aptl lab continuity-audit` — that researchers invoke between iterations. The module exposes the same `audit_and_revert` entry point that the future SDL runtime engine's orchestration domain (RTE-001) will call as a post-iteration hook when iteration is wired up.

The audit is **stateless and idempotent**:

- For each target container, run `iptables -S INPUT` via `backend.container_exec` (the canonical helper from ADR-023; argv only, no shell strings).
- Parse each `-A INPUT …` line into `(chain, source, action, qualifiers)`.
- A rule is in scope (revertable) iff *all four* hold:
  1. Chain is `INPUT` (FORWARD/OUTPUT bans don't wedge red→target ingress).
  2. Action is `DROP` or `REJECT` (the audit only undoes blocks).
  3. Source IP normalizes to one of the kali IPs in the whitelist file (`/32` and bare-IP forms equivalent; `/24` and other masks are out of scope).
  4. **No other matchers exist** — no `-p`, `-m`, `--dport`, `-i`, `-o`, `--state`, `--reject-with`, or any other option flag. Granular rules with any qualifier are valid blue tradecraft and stay.
- For each in-scope rule, run `iptables -D <delete_args>` via the same backend; record a `KaliCarveOutEvent` (`REVERTED` or `REVERT_FAILED` with error) to the run's `continuity-events.jsonl` if a `LocalRunStore` and `run_id` are provided.

Re-running the audit on a clean tree returns no events and writes nothing — codex's "post-iteration audits must be idempotent" guardrail (`docs/sdl/runtime-architecture.md`).

The kali source-IP set is loaded from `config/wazuh_cluster/etc/lists/active-response-whitelist` — the same file ADR-021 uses. Single source of truth; no IP literals duplicated in continuity code or tests.

### Relationship to ADR-021

| Layer | Mechanism | Scope | Failure mode covered |
|---|---|---|---|
| In-band (ADR-021) | `aptl-firewall-drop` consults whitelist on `add` | AR invocations of the canonical wrapper | Blue authors a rule against the canonical AR command |
| Out-of-band (this ADR) | `audit_and_revert` walks iptables per-target | Any rule that exists, regardless of how installed | Bypasses (custom AR scripts, raw manager commands, manual mistakes) |

The two layers are **complementary**, not redundant. ADR-021 is preventive (refuses the action at install time); this ADR is corrective (reverts the action after the fact). Both can fail without the other catching it (custom AR script bypasses ADR-021; researcher invoking the audit before iteration completes misses a rule installed mid-iter and re-installed by automation).

### Why not a step in `orchestrate_lab_start`

`orchestrate_lab_start` boots the lab once. The carve-out runs *between iterations*, which is an orchestration-domain concern, not a lab-lifecycle one (codex's `docs/sdl/runtime-architecture.md` RTE-001 guardrails make this explicit). When the SDL runtime engine implements iteration, it will own the post-iteration hook; until then, researchers invoke the audit manually via the CLI command. No pre-run snapshot is needed because the audit is stateless — current iptables state is all the input it needs.

### Why detect only blanket source-IP DROP

Granular rules are valid blue tradecraft. A `-A INPUT -s 172.20.4.30 -p tcp --dport 22 -j DROP` is exactly the kind of behavior-scoped hardening this lab wants to encourage — blue noticed kali brute-forcing SSH and locked that single port, leaving every other service reachable. A `-A INPUT -s 172.20.4.30 -j DROP` is the wedge. The qualifier emptiness check is the line.

`/24` (and other non-`/32`) source masks are out of scope — they're a different decision class (subnet ban) and indicate the defender intentionally banned a network segment. ADR scope creep avoided.

REJECT counts the same as DROP because both block traffic; the wedge symptom is identical to the loop.

### Why we don't infer mode

Codex's preflight guardrail (`docs/sdl/runtime-architecture.md`): *"runtime behavior must not infer purple mode from filenames, legacy fixtures, agents present, or CLI defaults."* The SDL `Scenario` model has no `mode` field; the legacy `scenarios/*.yaml` `mode:` keys do not validate. A half-baked gate would either silently default to "purple" (and become indistinguishable from "always-on") or read `mode:` from raw YAML (and violate the no-infer rule).

The cleaner design is to run the audit **unconditionally**, because every shipped APTL scenario is purple-team by design — APTL is the purple-team lab. We do not *read* `mode` from anywhere; the audit always runs. When SDL adds an authoritative `mode` field (issue #263), the audit gains a `scenario.mode == PURPLE` gate at the same call site, with `red` and `blue` runs explicitly skipped (so a defender's source-IP ban remains valid in non-purple modes). That migration is mechanically small — one `if scenario.mode == PURPLE` check at the runtime call site — and intentionally deferred to #263 so this ADR is not blocked on schema work.

## Consequences

### Pros

- **Catches every bypass class** ADR-021 cannot reach (custom AR scripts, manager-side raw commands, researcher mistakes).
- **Stateless, idempotent, no-op on clean tree.** Safe to re-run; safe to invoke at any iteration boundary.
- **Granular rules preserved.** Blue's behavior-scoped, port-scoped, payload-scoped tradecraft is never undone.
- **Single source of truth for kali IPs** — ADR-021's whitelist file. No IP literals scattered across the codebase.
- **Drop-in reuse for the SDL runtime engine** — the same `audit_and_revert` function is the post-iteration hook the engine calls when iteration is wired up. No CLI dependency.
- **Observable.** Every reversion produces a structured `KaliCarveOutEvent` in `continuity-events.jsonl` plus a stdout summary; the researcher can audit exactly what the orchestrator undid.

### Cons

- **Researchers running custom scenarios** where they explicitly want a kali ban to stick (e.g., emulating a real-pentest defensive win) must avoid invoking `aptl lab continuity-audit`. The CLI is opt-in for now; #263 adds the formal mode gate so this scenario becomes correct-by-default.
- **`/24` subnet bans pass through.** A defender who puts `iptables -I INPUT -s 172.20.4.0/24 -j DROP` wedges the loop and the audit doesn't catch it. Out of scope by design (different decision class); revisit if research workflows expose the case.
- **Race with mid-iteration re-installs.** If automation re-installs a wedge rule after the audit runs but before the next iteration starts, the audit doesn't help. Audit cadence is a researcher choice; the in-band ADR-021 defense covers the AR re-install path.
- **Scope is INPUT only.** A defender's `OUTPUT` or `FORWARD` rule on a target that affects kali ingress through a side channel isn't covered. INPUT is the wedge surface for the standard topology; revisit if topology changes.

## Alternatives considered

- **Snapshot-and-diff.** Pre-iteration capture of every target's iptables, post-iteration compare, revert anything new. Rejected: more state to manage, no win in coverage (any blanket-kali-drop rule is suspicious regardless of when it was installed; a clean tree can't *ratify* a coarse rule), and codex's idempotence guardrail prefers stateless audits.
- **In-band-only (no out-of-band audit).** Rejected: leaves the bypass classes uncovered. ADR-021 is necessary but not sufficient.
- **Wait for SDL `mode` (#263) before shipping.** Rejected: the audit is useful unconditionally today (APTL is always purple); blocking on #263 leaves the lab vulnerable to wedges right now. The mode-gate retrofit is a one-line change at the call site.

## References

- [ADR-021](adr-021-active-response-whitelist-via-wrapper.md) — in-band carve-out (the complement)
- [ADR-019](adr-019-suricata-ids-only-prevention-via-wazuh-ar.md) — why Wazuh AR is the prevention layer
- [ADR-020](adr-020-wazuh-agents-in-process-vs-sidecar.md) — in-process agents (precondition for iptables enforcement)
- [ADR-023](adr-023-container-interaction-in-deployment-backend.md) — `backend.container_exec` is the canonical command-execution boundary
- Issue [#252](https://github.com/Brad-Edwards/aptl/issues/252) — orchestrator-side continuity carve-out
- Issue [#263](https://github.com/Brad-Edwards/aptl/issues/263) — formal SDL `mode` field
