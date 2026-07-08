# Workshop Playbook

A facilitator guide for an introductory, hands-on cyber workshop built on APTL
and the full TechVault range. The audience is undergraduate and graduate
computer-science students with little or no prior security background. Students
run their own lab and drive it with their own AI agent over MCP. The guided
portion (sections 1 to 10) runs about 60 minutes, followed by open play
(section 11).

The times below are estimates for a beginner cohort, not measurements from a
live group. The companion [Lab Walkthrough](walkthrough.md) gives the exact
commands and agent prompts for every hands-on step.

## Before you start

Students, beforehand: boot the lab with `aptl lab start`, confirm health with
`aptl lab status`, and wire the agent to the lab's MCP servers. Facilitator:
bring your own lab up and open the dashboards on the projector.

## 1. Intro (about 5 min)

Set the frame and the hook.

- Introduce yourself and the plan: a whirlwind tour of security by doing it.
- The hook: in the next hour you attack a company, then catch yourself doing it.
- Safety: this is an isolated range on your own machine. Nothing leaves it, and
  you can break it and reset with `aptl lab stop -v`.
- The agenda in one line: range, agents, attacks, defense, do both, purple.

## 2. Cyber ranges (about 5 min)

Explain what a range is, why they exist, and what you learn from one.

- What it is: a safe, real, resettable replica of an environment, with real
  tools and a real (fake) company called TechVault, kept isolated.
- Why it exists: you cannot practice attacks or defense on production, so a
  range gives real repetitions at no risk.
- What you learn: which attacks are noisy versus quiet, whether detections
  work, and how analysts (and now agents) actually operate.
- Show `aptl lab status` and name the parts: an enterprise, a SOC, and an
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
- Preview: students run reconnaissance and an access step against TechVault,
  then go find the traces.

## 5. Offensive tools (about 5 min)

Meet the attacker's toolbox on the Kali box before using it.

- Kali is the red-team host, loaded with real tools: `nmap` for reconnaissance,
  `smbclient` for file shares, `curl` and web tooling for web attacks, and
  `msfconsole` for exploitation.
- The agent reaches these through the `kali_run_command` MCP tool, which runs
  real commands on Kali and returns the output.
- Kali sits on the TechVault networks, so it can reach the internal and DMZ
  hosts.

## 6. Attack, hands-on (about 12 min)

Students drive their agent through reconnaissance and one attack. Let students
phrase the prompts their own way. The examples below are starting points, and
all are verified to work.

Reconnaissance prompt:

> Use the Kali tools to scan the TechVault internal network and list the hosts
> and open services you find.

Expect the domain controller (ports 445 and 53), the database (port 5432), the
file server (port 445), the victim host (port 22), and the web application.

Then pick an attack, any or all of these:

- File share: connect to the file server `files.techvault.local` anonymously
  and list its shares.
- Web application: probe the TechVault web application for SQL injection.
- Victim: attempt an SSH brute-force against the victim host, which is
  deliberately noisy.

Narrate as students go. Ask which kill-chain step each action maps to, and
which actions are loud.

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

- Wazuh is the SIEM and host-based detection layer. Agents on hosts feed
  alerts.
- Suricata is network intrusion detection and watches traffic.
- MISP is threat intelligence and tracks known-bad indicators.
- TheHive and Cortex provide case management and automated analysis of
  observables.
- Shuffle is the SOAR layer and automates response.
- The agent reaches these through MCP tools as well, such as `indexer_query`
  for Wazuh alerts. The dashboards give the human view, and Wazuh serves its
  dashboard on `https://localhost:443`.

## 9. Investigate, hands-on (about 12 min)

Students drive their agent to find and explain the alerts their own attacks
created.

Find-it prompt:

> Query the SOC (Wazuh) for alerts caused by our activity against TechVault in
> the last few minutes. What fired, and from where?

Expect an SSH-brute alert sourced from the Kali IP address and a SQL-injection
alert.

Explain-it prompt:

> Pull the details of the top alert and explain in plain English what it
> detected.

Human view: open the Wazuh dashboard and find the same events. As a stretch
goal, check MISP for known-bad indicators and open a case in TheHive.

Debrief: you attacked, the SOC saw it, and your agent investigated. That is the
loop.

## 10. Purple teaming (about 4 min)

Name what the students just did, and why it matters.

- Red (attack) plus blue (defend) run as one loop, which is purple. Driving
  both with an agent makes it agentic purple.
- Why it matters: this is how detections get tested, how analysts train, and
  how the field evaluates whether AI agents can do real security work.

## 11. Play (open)

Let students loose on the full lab.

- Try a different attack and check whether the SOC catches it.
- Try to do something the SOC misses, then discuss why coverage has gaps.
- Ask your agent to summarize every alert it caused, ranked by severity.
- Two-person purple: one student drives red, one drives blue, and they race the
  loop.
