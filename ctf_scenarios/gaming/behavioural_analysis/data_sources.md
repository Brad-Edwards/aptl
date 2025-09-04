# Behavioral Analysis Data Sources

Public datasets for LLM agent analysis of game telemetry - demonstrating how AI can analyze suspicious behavior like a human analyst would.

## Primary Recommendation: Mixed Telemetry for Analysis

### 1. **CS:GO Professional Matches Dataset (Kaggle)**
- **URL**: https://www.kaggle.com/datasets/mateusdmachado/csgo-professional-matches
- **Size**: 25K+ professional matches (Nov 2015 - Mar 2020)
- **Content**: 
  - Results.csv: Map scores and team rankings
  - Picks.csv: Team map picks/vetos
  - Economy.csv: Round start equipment values  
  - Players.csv: Individual player performance stats
- **For LLM Analysis**: Feed match stats to agent, ask it to identify suspicious patterns
- **Demo Value**: Shows agent recognizing legitimate high-skill play vs anomalies

### 2. **CS:GO Cheating Dataset (Kaggle)**
- **URL**: https://www.kaggle.com/datasets/emstatsl/csgo-cheating-dataset
- **Published**: March 2022
- **Content**: Viewangles of cheaters and legit players
- **For LLM Analysis**: Present viewangle data, have agent identify inhuman patterns
- **Demo Value**: Agent explains WHY certain patterns are suspicious (snapping, perfect tracking)

## Alternative Options

### 3. **Counter-Strike 2 Telemetry Dataset**
- **URL**: https://www.kaggle.com/datasets/billpureskillgg/cs2-2023-11-23
- **Size**: 50GB telemetry from 1,300 matches (83 billion data points)
- **Content**: Comprehensive telemetry including positions, angles, actions
- **Use Case**: Deep behavioral analysis with full game state
- **Note**: Very large dataset, may be overkill for demo

### 4. **CS:GO Competitive Matchmaking Damage Data**
- **URL**: https://www.kaggle.com/datasets/skihikingkevin/csgo-matchmaking-damage
- **Content**: 410k+ rounds with damage/grenade statistics
- **Use Case**: Analyzing damage patterns, impossible damage scenarios
- **Why Good for Demo**: Shows wallhack detection via impossible pre-fires

## Cheat Detection Research Datasets

### 5. **vh42720's CS:GO Cheater Detection**
- **URL**: https://github.com/vh42720/csgo_cheater_detection
- **Content**: ML project using VACBanned.com and VAClist.net data
- **Features**: Player lifetime stats + VAC ban status
- **Use Case**: Training classifier on known cheater profiles
- **Limitation**: VAC bans aren't CS:GO specific

### 6. **CS-GO Cheating Calculator Dataset**
- **URL**: https://github.com/ignaciofq/CS-GO-cheating-calculator
- **Size**: 1,622 player profiles
- **Content**: 
  - 1,300 experienced players from Tracker.gg
  - 1,200 banned players from VACList
  - Steam64 IDs with stats and VAC status
- **Use Case**: Statistical analysis of cheater vs legit profiles

## PUBG Telemetry (Alternative Game)

### 7. **PUBG API Telemetry Access**
- **Documentation**: https://github.com/pubg/api-documentation-content
- **Analysis Tools**: https://github.com/JinhaoLiu/PUBGAnalysis
- **Content**: Real-time match telemetry via official API
- **Features**: Player positions, actions, kills, damage events
- **Limitation**: 14-day data retention, requires API key
- **Why Consider**: Shows cross-game applicability of techniques

## Data Quality Notes

### Known Limitations:
- VAC ban datasets can't confirm bans are CS:GO specific
- Some "clean" players may be undetected cheaters
- Professional match data lacks confirmed cheater examples
- Most datasets focus on blatant cheats, not subtle ones

### For Demo Success:
1. **Use CS:GO Pro Matches** as baseline for legitimate high-skill play
2. **Combine with Cheating Dataset** for known cheater patterns
3. **Focus on clear distinctions**: Inhuman reaction times, impossible pre-fires, statistical anomalies
4. **Acknowledge limitations**: Show false positive on pro player to demonstrate real-world challenges

## Quick Start for Demo

```bash
# Download primary datasets
# 1. CS:GO Professional Matches
wget https://www.kaggle.com/datasets/mateusdmachado/csgo-professional-matches/download

# 2. CS:GO Cheating Dataset  
wget https://www.kaggle.com/datasets/emstatsl/csgo-cheating-dataset/download
```

These datasets provide real data that the audience will recognize, avoiding the "academic toy problem" feeling while demonstrating practical AI capabilities for behavioral analysis.