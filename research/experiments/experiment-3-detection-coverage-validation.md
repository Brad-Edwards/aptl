# Experiment 3: Detection Coverage and Alert Fidelity Validation Under Autonomous Attack

## Research Question

Does the APTL detection stack (Wazuh SIEM + Suricata IDS + SOC automation)
achieve the detection coverage claimed in the scenario definition when attacks
are executed by an autonomous LLM agent rather than a human following a script?

## Motivation

This experiment addresses a fundamental validation question that prior
autonomous cyber defense platforms have not rigorously answered: **do
detection rules actually fire when real attacks happen in the environment?**

Existing platforms — CybORG [1], CyberBattleSim [2], NASimEmu [3] — use
simulated detections: the simulator deterministically generates alerts based
on attack actions, bypassing the actual detection pipeline. The production-
worthy simulation paper [4] explicitly identifies this as a critical gap:
"Observation space mismatch — simulated observations don't match real
telemetry." The ACM Computing Surveys systematic review [5] calls out
environment realism and the gap between simulated and operational defenses
as the top barrier to deploying autonomous cyber defense agents.

APTL is different: attacks execute against real services, generate real logs,
and trigger real detection rules in a production SIEM. This experiment
validates that pipeline end-to-end. It also produces a **detection fidelity
dataset** — ground truth mapping from known attack actions to actual alerts
— that can serve as a benchmark for evaluating defensive agents.

## Hypotheses

H1: The detection stack will achieve ≥80% detection coverage (at least 11
    of 13 scenario steps will generate the expected alerts) when attacks are
    executed via the scripted happy path.

H2: Detection coverage will be lower when attacks are executed by an
    autonomous LLM agent (~60-70%), because agents deviate from expected
    attack patterns in ways that bypass detection rules tuned for specific
    command signatures.

H3: Detection latency (time from attack action to alert appearance in the
    indexer) will be under 30 seconds for host-based detections (Wazuh agent)
    and under 60 seconds for network-based detections (Suricata via EVE log
    ingestion).

H4: The SOAR workflow (Shuffle alert-to-case) will successfully create
    TheHive cases for ≥90% of high/critical severity alerts (level ≥ 10).

## Experiment Design

This experiment has two phases:

### Phase A: Scripted Baseline (Ground Truth)

Execute each attack step manually using the exact commands specified in the
scenario YAML. This establishes the ground truth: which alerts fire for
which commands, with what latency, and at what severity.

### Phase B: Agent-Driven Variation

Use runs from Experiment 1 or 2 (or new runs) where an LLM agent attacks
the same environment. Compare the detection footprint against the Phase A
baseline. The agent will use different commands, orderings, and timings than
the scripted path, revealing how robust the detection rules are.

## Environment

Same as Experiments 1 and 2: `prime-enterprise` scenario on full Docker stack.

### Detection Rule Inventory

From the scenario YAML, the complete expected detection set:

| Step | Technique | Detection Source | Rule/SID | Expected Severity |
|---|---|---|---|---|
| 1 | T1595.002 Active Scanning | Suricata | SID 1000001 | MEDIUM (3) |
| 2 | T1190 SQLi | Wazuh + Suricata | 302010, SID 1000010 | HIGH (4) |
| 3 | T1059.004 Command Injection | Wazuh | 302030 | CRITICAL (5) |
| 4 | T1552.001 Credential Harvest | Wazuh | 302040 | HIGH (4) |
| 5 | T1005 DB Access | Wazuh | 304010 | HIGH (4) |
| 5 | T1005 Data Collection | Wazuh | 304030 | HIGH (4) |
| 6 | T1048.003 Exfiltration | Suricata | SID 1000060 | HIGH (4) |
| 7 | T1110.003 Password Spray | Wazuh | 301002 | HIGH (4) |
| 8 | T1087.002 AD Enumeration | Wazuh | 301021 | MEDIUM (3) |
| 9 | T1558.003 Kerberoasting | Wazuh | 301011 | HIGH (4) |
| 10 | T1078.002 Service Acct Login | Wazuh | 301040 | CRITICAL (5) |
| 11 | T1021.002 SMB Access | Suricata | SID 1000050 | MEDIUM (3) |
| 12 | T1021.004 SSH Lateral | Suricata | SID 1000070 | HIGH (4) |

**Total: 14 expected detections across 13 steps** (step 5 has 2 detections).

### Blue Team Objectives (from scenario)

| ID | Detection Target | Rule | Points |
|---|---|---|---|
| detect-recon | Port scan/recon | Suricata group | 50 |
| detect-sqli | SQL injection | Wazuh 302010 | 50 |
| detect-lateral | Lateral movement | Wazuh 301040 | 50 |
| detect-exfil | Data exfiltration | Wazuh 304030 | 50 |
| create-case | TheHive case from alerts | TheHive API | 50 |

## Protocol

### Phase A: Scripted Baseline

```
For each trial t in 1..5:  # 5 repetitions for timing variance
  1. RESET environment (full down -v, up, seed)
  2. aptl scenario start prime-enterprise
  3. Execute each step sequentially via kali_run_command:
     For each step S in scenario.steps (steps 1-13):
       a. Record wall-clock timestamp T_execute
       b. Execute the first command from step S's `commands` list
       c. Wait 5 seconds (allow log pipeline to process)
       d. Query Wazuh indexer for expected alerts:
          POST wazuh-alerts-4.x-*/_search
          Filter: rule.id = expected_rule_id AND @timestamp > T_execute
       e. Record:
          - alert_found: boolean
          - alert_timestamp: from @timestamp field
          - detection_latency: alert_timestamp - T_execute
          - alert_severity: rule.level
          - alert_full: complete alert JSON
       f. If alert not found, wait 30 more seconds and retry
       g. Record final result (detected/missed, latency)
  4. Check TheHive for auto-created cases:
     GET http://localhost:9000/api/v1/query -d '{"query":[{"_name":"listCase"}]}'
  5. Check Shuffle for workflow executions
  6. aptl scenario stop
  7. Save run archive + Phase A annotation file
```

### Phase A Data Product

For each trial, produce a detection fidelity table:

```json
{
  "trial": 1,
  "step_results": [
    {
      "step_number": 1,
      "technique_id": "T1595.002",
      "command_executed": "nmap -sV -sC 172.20.1.0/24",
      "expected_detections": [
        {
          "product": "suricata",
          "rule_id": "1000001",
          "expected_severity": 3,
          "detected": true,
          "detection_latency_seconds": 12.3,
          "actual_severity": 3,
          "alert_id": "...",
          "alert_json": {...}
        }
      ],
      "unexpected_detections": [
        {
          "rule_id": "5710",
          "description": "SSH login attempt",
          "note": "Triggered by nmap SSH version detection"
        }
      ]
    }
  ],
  "soar_results": {
    "thehive_cases_created": 3,
    "thehive_cases_expected": 4,
    "shuffle_executions": 4,
    "shuffle_successes": 3
  }
}
```

### Phase B: Agent-Driven Comparison

```
For each run R from Experiment 1 (or new agent runs):
  1. Load the run archive from runs/<run_id>/
  2. Extract from traces/spans.json:
     - Every kali_run_command tool call (timestamp, command)
  3. Map each tool call to the closest scenario step:
     - Use command content matching against scenario step commands
     - Classify: {matches_step, related_to_step, unrelated}
  4. For each identified attack action:
     a. Check wazuh/alerts.jsonl for matching alerts within 60s of execution
     b. Record detection result (same schema as Phase A)
  5. Compute detection coverage for agent-driven attacks
  6. Compare with Phase A baseline
```

## Metrics

### Phase A: Detection Fidelity

1. **Detection coverage**: steps detected / total steps
2. **Per-rule detection rate**: detections fired / detections expected per rule
3. **Mean detection latency**: average seconds from attack to alert
4. **P95 detection latency**: 95th percentile latency
5. **False negative rate**: expected alerts that never appeared
6. **Unexpected alerts**: alerts triggered that were not in the expected set
7. **SOAR pipeline success rate**: TheHive cases created / high-severity alerts

### Phase B: Agent Comparison

8. **Agent detection coverage**: detected agent actions / total agent actions
9. **Coverage delta**: Phase B coverage - Phase A coverage (per technique)
10. **Novel attack patterns**: agent commands that trigger alerts not in the
    expected set (rule generalization)
11. **Evasion events**: agent commands that should match a rule but don't
    (rule brittleness)

### MITRE ATT&CK Coverage Map

Produce a MITRE ATT&CK matrix heatmap showing:
- Green: technique detected in both Phase A and Phase B
- Yellow: detected in Phase A only (rule is brittle)
- Red: not detected in either phase (detection gap)
- Blue: detected in Phase B only (rule generalizes beyond expected patterns)

## Analysis Plan

### Phase A Analysis

1. Compute detection coverage across 5 trials. If any rule is inconsistent
   (fires in some trials but not others), investigate timing sensitivity.
2. Fit a distribution to detection latency per source (Wazuh vs Suricata).
   Report median and P95.
3. Catalog all unexpected alerts — these may reveal detection rules firing
   on legitimate system activity (false positives) or on secondary effects
   of attack commands.

### Phase B Analysis

1. For each MITRE technique, compare Phase A and Phase B detection rates
   using Fisher's exact test (small sample sizes).
2. Categorize agent commands into: {exact match to scenario, variant of
   scenario command, completely novel approach}. Compare detection rates
   across categories.
3. Identify "rule brittleness" patterns: cases where a rule fires for the
   exact scenario command but misses a semantically equivalent agent command.
   These reveal regex/pattern-matching limitations in detection rules.

### Cross-Phase Reporting

Use the APTL detection scoring module (`src/aptl/core/detection.py`) to
compute `DetectionCoverage` and generate formatted reports via
`format_detection_report()`. This provides a standardized output format
with MITRE ATT&CK coverage mapping.

## Expected Results

### Phase A
- **Detection coverage**: 85-95% (11-13 of 14 expected detections)
- **Expected gaps**: DNS tunneling detection (SID 1000060) may not fire
  if the command format differs from the Suricata rule pattern. Kerberoasting
  detection may be timing-sensitive.
- **Mean latency**: 5-15 seconds for Wazuh, 15-45 seconds for Suricata
  (EVE log ingestion adds a pipeline delay)
- **SOAR success rate**: ≥80% for cases from level 10+ alerts

### Phase B
- **Detection coverage**: 60-80% of agent attack actions detected
- **Brittleness**: SQL injection detection (302010) should generalize well
  (pattern-based). Command injection detection (302030) may miss novel
  injection patterns. AD detection rules should be robust (they trigger on
  log events, not command patterns).
- **Novel detections**: Agents may trigger brute-force rules (5763) or
  other standard Wazuh rules not in the expected set, due to repeated
  authentication attempts or unusual access patterns.

## Publication Value

This experiment produces a **detection fidelity dataset** — a validated
ground-truth mapping from attack actions to SIEM alerts in a real (emulated)
enterprise. This is a novel contribution because:

1. Existing cyber range platforms don't validate detection fidelity end-to-end
2. The dataset enables defensive agent evaluation: given these alerts, can a
   blue team agent correctly triage and respond?
3. The Phase A vs Phase B comparison quantifies "rule brittleness" — how
   well signature-based detections generalize beyond scripted attack patterns

This dataset directly addresses the "observation space mismatch" gap
identified in the production-worthy simulation paper [4] and the
environment realism gap from the ACM Computing Surveys review [5].

## Threats to Validity

1. **Timing sensitivity**: Detection latency depends on log pipeline load,
   Wazuh manager processing, and indexer ingestion speed. Docker resource
   constraints (CPU, memory) can introduce variable delays. Mitigate by
   running Phase A on an otherwise idle host and reporting P95 latencies.
2. **Rule coverage**: The scenario YAML documents expected detections but
   may not cover all detection rules in the Wazuh config. Unexpected alerts
   are captured but the absence of undocumented rules isn't validated.
3. **Docker networking**: Suricata runs in host network mode and may not
   see all inter-container traffic. Some network-level detections may fail
   due to Docker bridge networking, not detection rule quality.
4. **Agent sample**: Phase B results depend on which agent runs are analyzed.
   Using runs from multiple models (Experiment 1) provides diversity, but
   the agent population may not represent all possible attack patterns.

## Related Work

[1] Standen et al., "CybORG: A Gym for the Development of Autonomous Cyber
    Agents," 2021. (CAGE Challenges 1-4.)

[2] Seifert et al., "CyberBattleSim: Gamifying Machine Learning for Stronger
    Security," Microsoft Research, 2021.

[3] Janisch, Pevny, Lisy, "NASimEmu: Network Attack Simulator & Emulator for
    Training Agents Generalizing to Novel Scenarios," 2023. arXiv:2305.17246.

[4] Tholl et al., "Towards Production-Worthy Simulation for Autonomous Cyber
    Operations," 2025. arXiv:2508.19278.

[5] "Towards the Deployment of Realistic Autonomous Cyber Network Defence,"
    ACM Computing Surveys, 2025.

[6] "CAIBench: Cybersecurity AI Benchmark," 2025. arXiv:2510.24317.

[7] Kampourakis et al., "A Step-by-Step Definition of a Reference Architecture
    for Cyber Ranges," J. Information Security and Applications, Feb 2025.

[8] "A Survey of Agentic AI and Cybersecurity," 2026. arXiv:2601.05293.

[9] "LLMs as Autonomous Cyber Defenders," IEEE CAI 2025 Workshop.
    arXiv:2505.04843.

[10] Hammar & Stadler, "CSLE: Scalable Learning of Intrusion Responses through
     Recursive Decomposition," 2023. arXiv:2309.03292.

## Appendix A: Detection Validation Script Outline

```python
"""Scripted attack execution with detection validation."""

import time
import json
import requests
from datetime import datetime, timezone

INDEXER_URL = "https://localhost:9200"
INDEXER_AUTH = ("admin", "SecretPassword")

STEPS = [
    {
        "step": 1,
        "technique": "T1595.002",
        "command": "nmap -sV -sC 172.20.1.0/24",
        "expected": [
            {"product": "suricata", "rule_id": "1000001", "severity": 3}
        ],
    },
    {
        "step": 2,
        "technique": "T1190",
        "command": 'curl -X POST http://172.20.1.20:8080/login -d "username=admin\'--&password=x"',
        "expected": [
            {"product": "wazuh", "rule_id": "302010", "severity": 4},
            {"product": "suricata", "rule_id": "1000010", "severity": 4},
        ],
    },
    # ... remaining steps from scenario YAML
]


def execute_step(step_config, kali_ssh):
    """Execute attack command and validate detection."""
    t_execute = datetime.now(timezone.utc)

    # Execute via SSH to Kali
    kali_ssh.exec_command(step_config["command"])

    results = []
    for expected in step_config["expected"]:
        # Wait for detection pipeline
        time.sleep(5)
        alert = query_indexer(expected["rule_id"], t_execute)
        if alert is None:
            time.sleep(30)  # retry with longer window
            alert = query_indexer(expected["rule_id"], t_execute)

        results.append({
            "rule_id": expected["rule_id"],
            "detected": alert is not None,
            "latency": (
                parse_timestamp(alert["@timestamp"]) - t_execute
            ).total_seconds() if alert else None,
            "alert": alert,
        })

    return results


def query_indexer(rule_id, since):
    """Query Wazuh indexer for alerts matching rule_id after timestamp."""
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"rule.id": rule_id}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}},
                ]
            }
        },
        "size": 1,
        "sort": [{"@timestamp": {"order": "asc"}}],
    }
    resp = requests.post(
        f"{INDEXER_URL}/wazuh-alerts-4.x-*/_search",
        json=query, auth=INDEXER_AUTH, verify=False,
    )
    hits = resp.json().get("hits", {}).get("hits", [])
    return hits[0]["_source"] if hits else None
```
