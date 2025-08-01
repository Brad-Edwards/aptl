# Automatic Logging on Kali Red Team Box

This document summarizes the plan for moving from manual logging functions to automatic logging of commands, access events, and network connections on the Kali red team container.

## 1. Current Manual Logging
- The container entrypoint appends a `source ~/redteam_logging.sh` line to `.bashrc` so operators can use the `log_redteam_*` functions.
- These functions (`log_redteam_command`, `log_redteam_network`, `log_redteam_auth`) require the operator or AI agent to call them explicitly.

## 2. Goal
Automatically record all shell commands, logins, logouts, and network connections, forwarding them to the SIEM red team index, while leaving the existing simulation scripts unchanged.

## 3. Proposed Steps

### a. Shell Command Logging
- Add a `PROMPT_COMMAND` or `trap DEBUG` hook in `.bashrc` to capture each command before execution.
- Example snippet:
  ```bash
  export PROMPT_COMMAND='RETCODE=$?; CMD=$(history 1 | sed "s/^ *[0-9]* //"); \
  logger -t redteam-autolog "REDTEAM_LOG RedTeamActivity=auto_command \
  RedTeamCommand=\"$CMD\" ExitStatus=$RETCODE RedTeamUser=$(whoami) \
  RedTeamHost=$(hostname)"'
  ```
- This logs every interactive command via `logger` with the same `REDTEAM_LOG` prefix.

### b. Capture Access Logs
- Enable `auditd` or extended SSH logging to track logins and authentication attempts.
- Forward `/var/log/auth.log` entries with a `REDTEAM_LOG RedTeamActivity=access` prefix via `rsyslog`.

### c. Log Network Connections
- Use `auditd`, `iptables`, or `conntrack` hooks to log outbound connections.
- Send summaries to the SIEM using `logger -t redteam-network-auto` with the `REDTEAM_LOG` prefix.

### d. SIEM Integration
- Existing `rsyslog` config already forwards messages containing `REDTEAM_LOG` to the red team index.
- Ensure all automatic logs include this prefix for correct routing.

### e. Testing
- After deployment, run simple commands and verify they appear in the SIEM.
- Confirm login events and network connections are also logged automatically.

## 4. Expected Outcome
- Every shell command is logged without manual function calls.
- Access and network events are automatically captured.
- Manual logging scripts remain available for structured events.

