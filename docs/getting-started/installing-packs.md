# Install a scenario pack and its adapter

LilRAE does not contain the scenarios it runs. A scenario has two parts, and you
install each one:

1. **The pack.** A RAES environment pack holds the scenario content: the SDL
   document, assets, detection content, and seed data. TechVault is a pack.
2. **The adapter.** A Python package that provides the scenario-specific
   behavior for the pack's identity: serving, capture, startup, runtime
   parameters, verification, and participant smoke plans. The generic
   materializer in `src/aptl` does not branch on scenario names. The adapter
   supplies all scenario-specific behavior through entry points.

You must install both. The pack without its adapter realizes generically, but
its scenario-specific startup, verification, and capture do not run.

## Install the pack

The default scenario source is `env-pack`. LilRAE resolves the pack from the
installed `raes-env-packs` distribution by identity. It reads
`resources/packs/<identity>/sdl/<identity>.sdl.yaml`, stages the pack into
private project state, and validates it with the env-packs gates before use.

Install the distribution that carries the pack:

```shell
pip install "raes-env-packs==6.2.0"
```

TechVault ships in `raes-env-packs` as two packs: `techvault` (the environment)
and `techvault-participant-study` (the environment plus authored red and blue
participants).

A third-party pack that is not in `raes-env-packs` ships in its own
distribution. Install that distribution the same way. The pack directory name
must equal the pack's declared identity.

## Install the adapter

The adapter registers entry points in these groups, keyed by the pack identity:

| Entry-point group | Purpose |
| --- | --- |
| `aptl.pack_backend_interactions` | Serving provider |
| `aptl.scenario_capture` | Capture provider |
| `aptl.scenario_startup` | Startup provider |
| `aptl.scenario_runtime_parameters` | Runtime parameters |
| `aptl.scenario_planning_compatibility` | Planning compatibility |
| `aptl.scenario_verifiers` | Verifier |
| `aptl.evidence_payload` | Evidence collectors |
| `aptl.participant_mcp_smoke_plans` | Participant MCP smoke plans |

The TechVault adapter is `aptl_techvault`. It ships inside the `aptl-labs`
(LilRAE) distribution, so a LilRAE install already has it. You do not install it
separately.

A third-party pack supplies its own adapter distribution. Install it with pip.
Its entry points must name the pack's identity (for example `mypack.aptl`).
After install, confirm the entry points resolve:

```shell
python -c "from importlib.metadata import entry_points as e; print([ep.name for ep in e(group='aptl.scenario_startup')])"
```

## Select the pack

The active scenario is an operator decision. It lives in `aptl.json`:

```json
{
  "scenario": {
    "source": "env-pack",
    "identity": "techvault"
  }
}
```

- `source: env-pack` resolves the pack from the installed distribution by
  identity. This is the default.
- `identity` names the pack. The default identity is `techvault`.

The backend never switches the scenario at runtime. You select it before
`aptl lab start`.

## Verify and run

List the configured pack. The catalog projects the pack named in `aptl.json`:

```shell
aptl lab scenarios
```

The command prints the identity, version, status, digest, and description. Start
the lab:

```shell
aptl lab start
```

`aptl lab start` uses the configured identity. The `--scenario` option selects
another identity, but only one that the catalog already lists. The catalog lists
the configured pack, so `--scenario` cannot select a pack that `aptl.json` does
not configure. To run a different pack, set `scenario.identity` in `aptl.json`.

## Troubleshooting

- **`Unknown scenario id '<x>'. Available scenarios: <y>`**. The identity is
  not the configured pack. Set `scenario.identity` to `<x>` in `aptl.json`, then
  run `aptl lab scenarios` to confirm the catalog lists it.
- **`env-pack source not found for '<x>'`**. The pack distribution is not
  installed, or the pack directory name does not match the identity. Install the
  distribution that carries `resources/packs/<x>/`.
- **The lab realizes, but scenario-specific startup or verification does not
  run**. The adapter is missing. Install the adapter distribution and confirm
  its entry points name the pack identity.
