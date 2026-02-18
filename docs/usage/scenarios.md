# Scenarios

APTL includes a scenario engine for structured red team, blue team, and purple team exercises. Scenarios define objectives, scoring, hints, and automated evaluation.

## Running a Scenario

```bash
aptl scenario list              # List available scenarios
aptl scenario show <name>       # View scenario details
aptl scenario start <name>      # Start a scenario
aptl scenario status            # Check active scenario progress
aptl scenario evaluate          # Score objectives (auto-checks wazuh_alert and command_output types)
aptl scenario hint <objective>  # Get a hint (costs points)
aptl scenario complete <id>     # Manually mark an objective complete
aptl scenario stop              # End the active scenario
```

## Available Scenarios

Scenario files are YAML files in the `scenarios/` directory.

**recon-nmap-scan** — Beginner, red team. Perform network reconnaissance with Nmap against the victim machine. Discover services, identify versions, capture a flag.

**detect-brute-force** — Intermediate, purple team. Execute an SSH brute force attack from Kali, then detect it using Wazuh alerts and identify the attacker IP.

## Scenario Structure

Each scenario YAML defines:

- **metadata** — Name, description, difficulty (`beginner`/`intermediate`/`advanced`/`expert`), estimated time, MITRE ATT&CK mapping
- **mode** — `red`, `blue`, or `purple`
- **containers** — Which profiles must be running (`kali`, `victim`, `wazuh`, etc.)
- **preconditions** — Setup steps run before the scenario starts (place files, execute commands)
- **objectives** — Tasks to complete, organized by team (red/blue)
- **scoring** — Points per objective, time bonuses, passing score

## Objective Types

| Type | Evaluation |
|------|-----------|
| `manual` | User marks complete with `aptl scenario complete <id>` |
| `wazuh_alert` | Auto-checked by querying Wazuh for matching alerts |
| `command_output` | Auto-checked by running a command and verifying output contains expected strings |
| `file_exists` | Auto-checked by verifying a file exists in a container |

`aptl scenario evaluate` runs all auto-checkable objectives.

## Hints

Each objective can have progressive hints at increasing levels. Using a hint deducts a point penalty from that objective's score. Request hints with:

```bash
aptl scenario hint <objective_id>
```

## Scoring

- Each objective has a point value
- Time bonuses are available if the scenario is completed quickly (configurable decay)
- A passing score threshold is defined per scenario
- `aptl scenario evaluate` outputs the current score and whether the passing threshold is met

## Writing Scenarios

Scenario YAML files go in `scenarios/`. The schema is defined by Pydantic models in `src/aptl/core/scenarios.py`. Validate a scenario file with:

```bash
aptl scenario validate path/to/scenario.yaml
```

Refer to the existing scenario files (`scenarios/recon-nmap-scan.yaml`, `scenarios/detect-brute-force.yaml`) as working examples.
