# Workshop Playbook

A facilitator guide for an introductory, hands-on cyber workshop built on
APTL's `guided-purple` participant profile. The audience is undergraduate and
graduate computer-science students with little or no prior security
background. Students run the bounded TechVault attack-detect-investigate loop
and drive it with their own AI agent over MCP. The guided portion (sections 1
to 10) runs about 60 minutes, followed by bounded open play (section 11).

The times below are estimates for a beginner cohort, not measurements from a
live group. The companion [Lab Walkthrough](walkthrough.md) gives the exact
commands and agent prompts for every hands-on step.

## Before you start

For an appliance release produced by issue #823, staging and qualification
happen before delivery. Students use only its participant surface. For a
developer preview, complete the prerequisites in the
[Lab Walkthrough](walkthrough.md), start the `techvault-attacker-target`
scenario with the profile config, confirm health, and register exactly the
three profile MCP servers. Facilitators can use management access for support,
but management commands are not part of participant acceptance.

If students cannot run Docker locally, use the
[Emergency Workshop Rollout Runbook](emergency-rollout.md) to prepare a
short-lived legacy developer-host fleet. That is an unqualified contingency,
not the sealed participant appliance or hosted-seat contract. Tear down its
cloud resources immediately after the event.

## 1. Intro (about 5 min)

Set the frame and the hook.

- Introduce yourself and the plan: a whirlwind tour of security by doing it.
- The hook: in the next hour you attack a company, then catch yourself doing it.
- Safety: this is an isolated range. `aptl lab stop -v` performs the clean
  inner reset measured by this profile; an appliance release may additionally
  offer disposable-seat replacement.
- The agenda in one line: range, agents, attacks, defense, do both, purple.

## 2. Cyber ranges (about 5 min)

Explain what a range is, why they exist, and what you learn from one.

- What it is: a safe, real, resettable replica of an environment, with real
  tools and a real (fake) company called TechVault, kept isolated.
- Why it exists: you cannot practice attacks or defense on production, so a
  range gives real repetitions at no risk.
- What you learn: which attacks are noisy versus quiet, whether detections
  work, and how analysts (and now agents) actually operate.
- Show `aptl lab status` and name the parts: a monitored victim, Wazuh, and an
  attacker box.

## 3. Agents in cyber (about 5 min)

AI agents can now operate security tools, and that is what students do today.

- Security work means driving tools such as scanners, exploit frameworks, and
  SIEM queries. Agents can drive those same tools.
- MCP is the interface. It exposes real tools to an agent as callable
  functions.
- Today students drive both sides, attack and defense, with one agent. That is
  the whole idea of agentic purple.

## 4. The kill chain (about 5 min)

Attacks are a sequence, and defenders try to catch each step.

- Walk the chain plainly: reconnaissance, then gaining access, then acting on
  the objective such as stealing data or moving laterally.
- Each step leaves traces that the defensive side can detect.
- Preview: students generate failed authentication attempts against TechVault,
  then go find the traces.

## 5. Offensive tools (about 5 min)

Meet the attacker's toolbox on the Kali box before using it.

- Kali is the red-team host. The required profile uses its standard shell and
  SSH tooling to generate a bounded, noisy authentication attack.
- The agent reaches these through the `kali_run_command` MCP tool, which runs
  real commands on Kali and returns the output.
- Kali reaches the monitored victim through the TechVault internal network.

## 6. Attack, hands-on (about 12 min)

Students first prove the real Kali backend, then generate one bounded attack.
Let students phrase the prompts their own way.

Backend prompt:

> Use the Kali tool to run `id`.

Expect `uid=1000(kali)`.

Attack prompt:

> From Kali, make several failed SSH login attempts with made-up usernames
> against the monitored victim.

The failed authentication attempts are deliberately noisy and produce Wazuh
rule 5710 alerts.

Narrate as students go. Ask which kill-chain step the action maps to and why it
is loud.

Facilitator watch-fors: if an agent refuses, remind it that this is an
authorized lab and rephrase the request as a security exercise. If an agent
cannot see the tools, check the `.mcp.json` file and the working directory.

## 7. Cyber defense (about 4 min)

The defender's job, and where it happens.

- The blue side follows a loop: monitor, detect, investigate, respond. That
  work happens in the SOC.
- Detection turns raw activity, such as a login or a packet, into an alert
  someone can act on.
- Everything the students just did left evidence, which they find next.

## 8. Defensive tools (about 5 min)

Meet the TechVault SOC and what each tool does.

- Wazuh is the SIEM and host-based detection layer. Its agent on the victim
  feeds alerts to the manager and indexer.
- The agent reaches the same alert through the `indexer_query` and
  `wazuh_query_alerts` MCP tools.
- The Wazuh dashboard supplies the required human view. The supported
  participant appliance projects that capability through its participant
  route rather than exposing the operator control plane.
- OpenTelemetry, Tempo, and Grafana are required supporting services and are
  included in the resource budget, but they are not additional participant
  investigation tools.

## 9. Investigate, hands-on (about 12 min)

Students drive their agent to find and explain the alerts their own attacks
created.

Find-it prompt:

> Query the SOC (Wazuh) for alerts caused by our activity against TechVault in
> the last few minutes. What fired, and from where?

Expect an SSH authentication alert sourced from Kali.

Explain-it prompt:

> Pull the details of the top alert and explain in plain English what it
> detected.

Human view: open the participant Wazuh dashboard projection and find the same
rule 5710 event.

Debrief: you attacked, the SOC saw it, and your agent investigated. That is the
loop.

## 10. Purple teaming (about 4 min)

Name what the students just did, and why it matters.

- Red (attack) plus blue (defend) run as one loop, which is purple. Driving
  both with an agent makes it agentic purple.
- Why it matters: this is how detections get tested, how analysts train, and
  how the field evaluates whether AI agents can do real security work.

## 11. Play (open)

Let students explore within the bounded profile.

- Vary the SSH usernames or timing and compare the alerts.
- Try a different action against the victim and check whether Wazuh sees it.
- Ask your agent to summarize every alert it caused, ranked by severity.
- Two-person purple: one student drives red, one drives blue, and they race the
  loop.

SMB enumeration, web SQL injection, MISP, TheHive, Cortex, Shuffle, and
Suricata exercises belong to the full `techvault-operational` research stack.
They are optional follow-on material, not a fallback required to complete this
profile.
