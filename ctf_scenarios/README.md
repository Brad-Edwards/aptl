# APTL CTF Scenarios

This directory contains CTF scenarios designed for red team MCP agent training and blue team investigation practice.

## Quick Reference

| Difficulty | Scenario | Description | Time | Flags |
|------------|----------|-------------|------|-------|
| **Basic** | | | | |
| 1/10 | [Web Flag Hunt](basic/web_flag_hunt/) | Simple web reconnaissance and directory traversal | 10-15 min | 1 |
| 1/10 | [FTP Anonymous Access](basic/ftp_anonymous_access/) | FTP server misconfiguration and data exfiltration | 5-10 min | 2 |
| 2/10 | [SSH Brute Force](basic/ssh_brute_force/) | Classic SSH brute force with weak credentials | 5-10 min | 1 |
| 2/10 | [Telnet Weak Auth](basic/telnet_weak_auth/) | Legacy Telnet service with clear-text authentication | 5-10 min | 2 |
| **Intermediate** | | | | |
| 5/10 | [SQL Injection](intermediate/sql_injection/) | Web app SQL injection and database enumeration | 20-30 min | 2 |
| 6/10 | [Privilege Escalation](intermediate/privilege_escalation/) | Linux sudo/SUID privilege escalation vectors | 15-25 min | 2 |
| **Hard** | | | | |
| 8/10 | [Buffer Overflow](hard/buffer_overflow/) | Stack-based buffer overflow exploitation | 45-60 min | 1 |
| 9/10 | [Multi-Stage Attack](hard/multi_stage_attack/) | Complete APT-style attack chain simulation | 60-90 min | 4 |

## Usage

Each scenario includes three scripts:
- `setup.sh` - Deploy the vulnerable environment
- `cleanup.sh` - Remove all traces and restore clean state  
- `reset.sh` - Quick cleanup and redeploy for next round

```bash
# Basic usage
cd basic/web_flag_hunt
./setup.sh       # Deploy scenario
# ... perform red team testing ...
./cleanup.sh     # Clean up when done

# Quick reset between rounds
./reset.sh       # Cleanup and redeploy in one command
```

## Training Progression

**Recommended learning path:**
1. Start with **basic** scenarios to learn fundamental techniques
2. Progress to **intermediate** for technical analysis skills
3. Tackle **hard** scenarios for advanced exploitation and attack chaining

## Blue Team Integration

All scenarios generate realistic logs for:
- Apache access logs (web attacks)
- Authentication logs (SSH attacks) 
- System logs (privilege escalation)
- Database logs (SQL injection)

Perfect for SIEM rule development and incident response training.

## Red Team MCP Integration

Scenarios are designed for automated red team MCP agent training:
- Progressive difficulty for systematic skill development
- Compatible with standard penetration testing tools
- Repeatable and automatable deployment
- Comprehensive documentation for AI agent learning

## Configuration

See `scenarios.json` for detailed metadata including:
- Attack vectors and skills tested
- Required services and dependencies
- Difficulty ratings and time estimates
- Integration capabilities

## Security Notes

⚠️ **WARNING**: These scenarios contain deliberately vulnerable configurations
- Deploy only in isolated lab environments
- Never use on production systems
- All vulnerabilities are for educational purposes only