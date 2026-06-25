# TechVault curated live validation gate

This gate live-proves the small curated ACES startup variants from
[curated variants](../sdl/techvault-curated-variants.md). The
[static validation gate](techvault-static-validation-gate.md) and
[`tests/test_techvault_curated_variants.py`](https://github.com/Brad-Edwards/aptl/blob/main/tests/test_techvault_curated_variants.py)
already prove each variant parses, compiles, and realizes to a bounded Compose
profile set without starting Docker. This gate goes one step further: it boots
each variant through APTL's public start path and proves the running containers
and networks match the variant's ACES-realized reduced surface, not the full
TechVault range.

It implements the live half of issue #535 (SCN-010K) and follows the boundary
set by the [curated live validation preflight](techvault-curated-live-validation-preflight.md).
The full TechVault [live validation gate](techvault-live-validation-gate.md)
(PR #520) is a separate, unchanged, full-surface proof. The curated gate does
not replace it: the full gate validates the complete operational range including
the SOC stack, Kali reachability, and Suricata telemetry, while the curated gate
validates that an intentionally reduced scenario boots only its declared surface.

## What the gate checks

The model-derived half lives in `aptl.validation.curated_live_proof`. It composes
the existing canonical authorities rather than re-modelling them:

- `expected_reduced_matrix()` runs the same no-start ACES selection path as
  `selected_profiles_for_scenario()` (parse, plan, `interpret_provisioning_plan`,
  `select_backend_profiles`), then keys the expected steady-state Compose
  services and networks to the selected profile set through the shared
  `ComposeProfileIndex`. It records the selected profiles, the realized ACES node
  names, the expected services, and the expected networks.
- `compare_to_snapshot()` compares that matrix to a captured `RangeSnapshot`
  (`aptl lab status --json`). Passing means every expected service has a running
  container, no unexpected steady-state container is present, and the network set
  matches. Each gap becomes one structured diagnostic naming the layer that
  broke, never raw Docker or CLI text.

The expected surface is the set of steady-state services the selected profiles
activate, not only the declared ACES nodes. `docker compose --profile <p>`
activates every service in a profile, so a variant that selects `wazuh` boots the
Wazuh dashboard even when its SDL declares only the manager and indexer. The
matrix records both the ACES `realized_nodes` (the modelling authority) and the
`expected_services` (the boot truth), and the comparison uses the latter.

## Matched configuration per variant

A curated variant selects a subset of the enabled Compose profiles. To boot only
its reduced surface through the public path, the operator config enables exactly
that variant's container profiles. The always-on `otel` core needs no flag.

| Catalog id | `aptl.json` containers enabled | Selected profiles |
|---|---|---|
| `techvault-observability-core` | none | `otel` |
| `techvault-defensive-min` | `wazuh` | `wazuh`, `otel` |
| `techvault-enterprise-web` | `enterprise`, `wazuh` | `enterprise`, `wazuh`, `otel` |
| `techvault-attacker-target` | `kali`, `victim`, `wazuh` | `kali`, `victim`, `wazuh`, `otel` |

## Recorded results

All four variants were booted on 2026-06-24 (UTC) on a single Docker host through
`aptl lab start --scenario <catalog-id> --skip-seed`, captured with
`aptl lab status --json`, and compared with `compare_to_snapshot()`. Every variant
reached the `Lab is ready.` outcome (`StartupOutcome.READY`) and matched its
reduced surface exactly.

| Catalog id | Date (UTC) | Readiness | Boot | Containers | Networks | Verdict |
|---|---|---|---|---|---|---|
| `techvault-observability-core` | 2026-06-24 | Lab is ready. | 51s | 3 | 1 | PASS |
| `techvault-defensive-min` | 2026-06-24 | Lab is ready. | 90s | 6 | 3 | PASS |
| `techvault-enterprise-web` | 2026-06-24 | Lab is ready. | 99s | 10 | 3 | PASS |
| `techvault-attacker-target` | 2026-06-24 | Lab is ready. | 97s | 9 | 4 | PASS |

The booted containers and networks for each run equal the ACES-realized selected
profile surface:

- `techvault-observability-core`: `aptl-grafana-otel`, `aptl-otel-collector`,
  `aptl-tempo` on `aptl_aptl-security`.
- `techvault-defensive-min`: the OTEL core plus `aptl-wazuh-manager`,
  `aptl-wazuh-indexer`, `aptl-wazuh-dashboard` on the security, DMZ, and internal
  networks.
- `techvault-enterprise-web`: the OTEL core, the Wazuh core, and the enterprise
  tier (`aptl-webapp`, `aptl-db`, `aptl-ad`, `aptl-workstation`), with no SOC
  surface.
- `techvault-attacker-target`: the OTEL core, the Wazuh core, `aptl-kali`,
  `aptl-kali-capture`, and `aptl-victim`, with the red-team network added.

## Evidence

Per-variant evidence is committed under
`docs/aces/techvault-curated-live-validation-gate/<catalog-id>/`:

- `result.json`: the matched config, exact command, readiness outcome, boot
  duration, selected profiles, realized nodes, expected and actual services and
  networks, the verdict, and any diagnostics.
- `snapshot.json`: the captured `RangeSnapshot` trimmed to container and network
  surface (`summarize_snapshot()`). The source snapshot is redacted by
  `capture_snapshot()` (ADR-029); no secrets are recorded.

## Reproducing the proof

The boot is destructive (it runs `aptl lab stop -v`) and takes minutes. It
targets maintainers and a documented CI runner, not fast CI or pre-commit. The
fast unit suite that covers the matrix and comparison runs without a lab:

```bash
pytest tests/test_curated_live_proof.py
```

Reproduce one variant's recorded live boot with the committed driver, which sets
the matched config, boots through the public path, captures, compares, writes the
evidence, tears the lab down, and restores `aptl.json`:

```bash
docs/aces/techvault-curated-live-validation-gate/run-curated-live-proof.sh techvault-defensive-min
```

The manual equivalent, for one variant, is to enable that variant's container
profiles in `aptl.json`, then:

```bash
aptl lab start --scenario techvault-defensive-min --skip-seed
aptl lab status --json
aptl lab stop -v -y
```

## Known limitations

- The proof boots with `--skip-seed`. The SOC seed step keys off the global
  `config.containers.soc` flag rather than the scenario's selected profiles, so a
  reduced variant booted with `soc` enabled would attempt to seed SOC tools that
  the variant never started. A reduced variant uses a matched config (so `soc` is
  not enabled) and `--skip-seed`. Scoping the seed step to the selected profiles,
  like the post-start readiness checks already are, is a candidate follow-up,
  outside the scope of this proof.
- The full live gate's realization check (`check_provisioning_realization`)
  asserts the selected profiles equal `public_start_profiles(config)`, so a
  reduced variant only satisfies it under its matched config. Reduced variants are
  therefore proven by this curated gate, not by the full TechVault live gate.
- Variants that omit `kali` or the SOC stack are intentionally not subject to the
  full gate's Kali reachability and Suricata telemetry probes. Their absence is
  part of the reduced surface, not an ambiguous startup failure.
