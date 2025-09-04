# Behavioral Analysis Demo Design

## Demo: Anti-Cheat Manual Review

**Repository**: https://github.com/ignaciofq/CS-GO-cheating-calculator

**Dataset**: players_stats.xlsx (included in repo)
- 1,622 CS:GO player profiles
- Stats: K/D, headshot %, accuracy, win rate, MVP %
- Labels: VAC ban status

**Demo Flow**:
1. Present player profiles flagged by "automated anti-cheat system"
2. LLM reviews stats and identifies suspicious patterns
3. LLM ranks players by cheating likelihood with explanations
4. Reveal actual VAC ban status

**Real-World Mapping**:
- Anti-cheat systems (EAC, BattlEye, Vanguard) flag accounts for manual review
- Human analysts review flagged accounts to make ban decisions
- Analysts must provide reasoning for ban appeals