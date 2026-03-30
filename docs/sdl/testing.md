# SDL Testing

## Test Suites

### Unit Tests (standard run)

```bash
pytest tests/test_sdl_models.py tests/test_sdl_validator.py \
       tests/test_sdl_parser.py -v
```

Tests structural validation (Pydantic models), semantic validation (cross-reference checks), and parser behavior (normalization, shorthands, SDL-only format boundary).
The unit suites also cover OCR-derived duration grammar, entity fact maps, and `${var}` placeholder handling across supported scalar/reference fields.

### Stress Tests (standard run)

```bash
pytest tests/test_sdl_stress.py tests/test_sdl_realworld.py -v
```

19 scenarios from 8 platforms testing expressiveness boundaries:

- **test_sdl_stress.py** — Scenarios 1-13: OCR, CybORG, CALDERA, Atomic Red Team, CyRIS, KYPO, HTB, Enterprise AD, Cloud Hybrid, Exchange+data, CybORG+agents, AD+trust+federation
- **test_sdl_realworld.py** — Scenarios 14-19: Incalmo Equifax, NICE Challenge 17, CCDC Burnsodyne, HTB Offshore-style, Metasploitable 2, Locked Shields IT/OT/SCADA

Objective coverage is exercised in the stress suites as well: the agent-heavy CybORG-derived scenarios and exercise-heavy scenarios now include declarative `objectives` so the section is tested against realistic combinations of agents, scoring, orchestration, and team structure rather than only unit tests.

Each scenario is tested for:
1. Parse + validate success
2. Infrastructure cross-reference integrity
3. Non-trivial content (at least 1 VM)

### Fuzz Tests (manual trigger only)

```bash
pytest tests/test_sdl_fuzz.py -m fuzz -v
```

Property-based testing using [Hypothesis](https://hypothesis.readthedocs.io/). Generates ~1,050 random inputs per run across 6 fuzz strategies:

| Test | Strategy | Examples |
|------|----------|----------|
| `test_valid_sdl_never_crashes` | Structurally plausible SDL scenarios | 200 |
| `test_arbitrary_text_never_crashes` | Completely random text | 500 |
| `test_extra_fields_rejected_cleanly` | Scenarios with unknown fields | 50 |
| `test_fuzz_service_ports` | Random port/protocol/name combos | 100 |
| `test_fuzz_vulnerability_class_validation` | Random CWE class strings | 100 |
| `test_fuzz_feature_dependency_cycles` | Random dependency graphs | 100 |

The invariant: the parser **never** raises an unhandled exception. Every input either produces a valid `Scenario` or raises `SDLParseError`/`SDLValidationError`.

Fuzz tests are excluded from the standard `pytest` run via the `fuzz` marker. They take ~70 seconds.

### Full Suite

```bash
# Standard tests (excludes fuzz)
pytest tests/ -v

# Everything including fuzz
pytest tests/ -m '' -v
```

### Example Scenarios

The `examples/` directory now contains curated large SDL files that are
meant to be reusable starting points rather than inline test-only
fixtures. They are loaded directly from disk by `tests/test_scenarios.py`
so they stay valid as real SDL artifacts:

- `aptl-lab-topology.sdl.yaml`
- `hospital-ransomware-surgery-day.sdl.yaml`
- `satcom-release-poisoning.sdl.yaml`
- `port-authority-surge-response.sdl.yaml`

The up-front design briefs for the new complex examples live in
[`docs/sdl/complex-scenarios.md`](complex-scenarios.md), and the running
authoring issue log lives in
[`docs/sdl/complex-scenario-authoring-notes.md`](complex-scenario-authoring-notes.md).

## Adding New Scenarios

To test a new scenario topology, add a YAML string constant to `test_sdl_stress.py` or `test_sdl_realworld.py` and add it to the `SCENARIOS` list. The parametrized tests will automatically pick it up.

The scenario should exercise specific SDL features you want to validate. Include comments noting what aspect is being tested.
