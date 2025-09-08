#!/usr/bin/env python3
"""
Comprehensive analysis of cheaters dataset for behavioral analysis demo.
Outputs results directly to markdown file.
"""

import numpy as np
import sys
import os

def analyze_cheaters_dataset():
    """Analyze the cheaters dataset and generate comprehensive statistics"""
    
    # Load cheaters data
    cheaters = np.load('/home/atomik/src/aptl/ctf_scenarios/gaming/behavioural_analysis/data/cheaters/cheaters.npy')
    
    # Prepare output
    output_lines = []
    output_lines.append("# Cheaters Dataset Analysis\n")
    
    # Dataset Overview
    output_lines.append("## Dataset Overview")
    output_lines.append(f"- **Total Players**: {cheaters.shape[0]:,}")
    output_lines.append(f"- **Data Structure**: ({cheaters.shape[0]:,} players × {cheaters.shape[1]} engagements × {cheaters.shape[2]} timesteps × {cheaters.shape[3]} variables)")
    output_lines.append(f"- **Memory Usage**: {cheaters.nbytes / (1024**3):.2f} GB")
    output_lines.append(f"- **Data Type**: {cheaters.dtype}")
    output_lines.append("- **Temporal Coverage**: 6 seconds per engagement (5 seconds before kill + 1 second after)\n")
    
    # Variables
    output_lines.append("## Variables Analyzed")
    output_lines.append("1. **AttackerDeltaYaw**: Player's horizontal mouse movement (degrees)")
    output_lines.append("2. **AttackerDeltaPitch**: Player's vertical mouse movement (degrees)")
    output_lines.append("3. **CrosshairToVictimYaw**: Horizontal distance from crosshair to victim (degrees)")  
    output_lines.append("4. **CrosshairToVictimPitch**: Vertical distance from crosshair to victim (degrees)")
    output_lines.append("5. **Firing**: Binary indicator (0 = not shooting, 1 = shooting)\n")
    
    # Extract the 5 variables
    attacker_yaw = cheaters[:, :, :, 0]      
    attacker_pitch = cheaters[:, :, :, 1]    
    crosshair_yaw = cheaters[:, :, :, 2]     
    crosshair_pitch = cheaters[:, :, :, 3]   
    firing = cheaters[:, :, :, 4]            
    
    # Core Statistical Summary
    output_lines.append("## Core Statistical Summary\n")
    
    # Data Ranges
    output_lines.append("### Data Ranges")
    output_lines.append("| Variable | Minimum | Maximum | Range |")
    output_lines.append("|----------|---------|---------|-------|")
    output_lines.append(f"| AttackerDeltaYaw | {attacker_yaw.min():.3f}° | {attacker_yaw.max():.3f}° | ~{attacker_yaw.max() - attacker_yaw.min():.0f}° |")
    output_lines.append(f"| AttackerDeltaPitch | {attacker_pitch.min():.3f}° | {attacker_pitch.max():.3f}° | ~{attacker_pitch.max() - attacker_pitch.min():.0f}° |")
    output_lines.append(f"| CrosshairToVictimYaw | {crosshair_yaw.min():.3f}° | {crosshair_yaw.max():.3f}° | {crosshair_yaw.max() - crosshair_yaw.min():.0f}° |")
    output_lines.append(f"| CrosshairToVictimPitch | {crosshair_pitch.min():.3f}° | {crosshair_pitch.max():.3f}° | ~{crosshair_pitch.max() - crosshair_pitch.min():.0f}° |")
    output_lines.append("| Firing | 0.0 | 1.0 | Binary |\n")
    
    # Firing Behavior
    total_firing_events = np.sum(firing)
    total_possible_events = cheaters.shape[0] * cheaters.shape[1] * cheaters.shape[2]
    firing_rate = total_firing_events / total_possible_events
    player_total_shots = np.sum(firing, axis=(1,2))
    engagement_shots = np.sum(firing, axis=2)
    shots_per_engagement = engagement_shots[engagement_shots > 0]
    
    output_lines.append("### Firing Behavior Patterns\n")
    output_lines.append("#### Overall Firing Statistics")
    output_lines.append(f"- **Total Firing Events**: {int(total_firing_events):,} shots across all players")
    output_lines.append(f"- **Overall Firing Rate**: {firing_rate:.4%} (firing in ~1 of every {1/firing_rate:.0f} timesteps)")
    output_lines.append(f"- **Shots per Player**: {player_total_shots.min():.0f} to {player_total_shots.max():.0f} (Mean: {player_total_shots.mean():.1f}, Std: {player_total_shots.std():.1f})")
    output_lines.append(f"- **Zero-Shot Players**: {np.sum(player_total_shots == 0)}\n")
    
    output_lines.append("#### Engagement-Level Analysis")
    engagements_with_shots = np.sum(engagement_shots > 0)
    total_engagements = cheaters.shape[0] * cheaters.shape[1]
    output_lines.append(f"- **Engagements with Shots**: {engagements_with_shots:,} of {total_engagements:,} ({engagements_with_shots/total_engagements:.1%})")
    output_lines.append(f"- **Shots per Engagement**: {shots_per_engagement.min():.0f} to {shots_per_engagement.max():.0f} shots (Mean: {shots_per_engagement.mean():.1f} when shots fired)\n")
    
    # Movement Patterns
    output_lines.append("## Movement Patterns\n")
    output_lines.append("### Attacker Movement (Mouse/Camera Control)\n")
    
    output_lines.append("#### Horizontal Movement (Yaw)")
    output_lines.append(f"- **Mean**: {attacker_yaw.mean():.3f}° (nearly centered)")
    output_lines.append(f"- **Standard Deviation**: {attacker_yaw.std():.3f}°")
    output_lines.append("- **Distribution**:")
    output_lines.append(f"  - 25th percentile: {np.percentile(attacker_yaw, 25):.3f}°")
    output_lines.append(f"  - 75th percentile: {np.percentile(attacker_yaw, 75):.3f}°")
    output_lines.append(f"  - 99th percentile: {np.percentile(attacker_yaw, 99):.3f}°\n")
    
    output_lines.append("#### Vertical Movement (Pitch)")
    output_lines.append(f"- **Mean**: {attacker_pitch.mean():.3f}° ({'slight upward bias' if attacker_pitch.mean() > 0 else 'slight downward bias'})")
    output_lines.append(f"- **Standard Deviation**: {attacker_pitch.std():.3f}°")
    output_lines.append("- **Distribution**:")
    output_lines.append(f"  - 25th percentile: {np.percentile(attacker_pitch, 25):.3f}°")
    output_lines.append(f"  - 75th percentile: {np.percentile(attacker_pitch, 75):.3f}°")
    output_lines.append(f"  - 99th percentile: {np.percentile(attacker_pitch, 99):.3f}°\n")
    
    # Crosshair Accuracy Analysis
    output_lines.append("## Crosshair Accuracy Analysis\n")
    output_lines.append("### Overall Crosshair Distance from Target\n")
    
    output_lines.append("#### All Timesteps")
    output_lines.append("| Metric | Yaw | Pitch |")
    output_lines.append("|--------|-----|-------|")
    output_lines.append(f"| Mean | {crosshair_yaw.mean():.3f}° | {crosshair_pitch.mean():.3f}° |")
    output_lines.append(f"| Std Dev | {crosshair_yaw.std():.3f}° | {crosshair_pitch.std():.3f}° |")
    output_lines.append(f"| Absolute Mean | {np.abs(crosshair_yaw).mean():.3f}° | {np.abs(crosshair_pitch).mean():.3f}° |")
    output_lines.append(f"| 95th Percentile (abs) | {np.percentile(np.abs(crosshair_yaw), 95):.3f}° | {np.percentile(np.abs(crosshair_pitch), 95):.3f}° |\n")
    
    # Accuracy at firing
    firing_mask = firing > 0
    firing_yaw = crosshair_yaw[firing_mask]
    firing_pitch = crosshair_pitch[firing_mask]
    firing_distance = np.sqrt(firing_yaw**2 + firing_pitch**2)
    
    output_lines.append("#### At Moment of Firing")
    output_lines.append("| Metric | Yaw | Pitch | Combined Distance |")
    output_lines.append("|--------|-----|-------|------------------|")
    output_lines.append(f"| Absolute Mean | {np.abs(firing_yaw).mean():.3f}° | {np.abs(firing_pitch).mean():.3f}° | {firing_distance.mean():.3f}° |")
    output_lines.append(f"| Standard Deviation | {firing_yaw.std():.3f}° | {firing_pitch.std():.3f}° | {firing_distance.std():.3f}° |")
    output_lines.append(f"| 25th Percentile | {np.percentile(np.abs(firing_yaw), 25):.3f}° | {np.percentile(np.abs(firing_pitch), 25):.3f}° | {np.percentile(firing_distance, 25):.3f}° |")
    output_lines.append(f"| 50th Percentile (Median) | - | - | {np.percentile(firing_distance, 50):.3f}° |")
    output_lines.append(f"| 75th Percentile | {np.percentile(np.abs(firing_yaw), 75):.3f}° | {np.percentile(np.abs(firing_pitch), 75):.3f}° | {np.percentile(firing_distance, 75):.3f}° |")
    output_lines.append(f"| 95th Percentile | {np.percentile(np.abs(firing_yaw), 95):.3f}° | {np.percentile(np.abs(firing_pitch), 95):.3f}° | {np.percentile(firing_distance, 95):.3f}° |")
    output_lines.append(f"| 99th Percentile | - | - | {np.percentile(firing_distance, 99):.3f}° |\n")
    
    # Perfect Shot Analysis
    perfect_1deg = np.sum(firing_distance < 1.0)
    perfect_2deg = np.sum(firing_distance < 2.0)
    perfect_5deg = np.sum(firing_distance < 5.0)
    total_shots = len(firing_distance)
    
    output_lines.append("### \"Perfect Shot\" Analysis")
    output_lines.append("When firing, cheaters achieved:")
    output_lines.append(f"- **Within 1°**: {perfect_1deg:,} shots ({perfect_1deg/total_shots:.2%})")
    output_lines.append(f"- **Within 2°**: {perfect_2deg:,} shots ({perfect_2deg/total_shots:.2%})")
    output_lines.append(f"- **Within 5°**: {perfect_5deg:,} shots ({perfect_5deg/total_shots:.2%})\n")
    
    # Individual Player Variance
    player_accuracies = []
    player_consistencies = []
    
    for player_idx in range(cheaters.shape[0]):
        player_firing_mask = firing[player_idx] > 0
        if np.any(player_firing_mask):
            player_firing_yaw = crosshair_yaw[player_idx][player_firing_mask]
            player_firing_pitch = crosshair_pitch[player_idx][player_firing_mask]
            if len(player_firing_yaw) > 0:
                player_distance = np.sqrt(player_firing_yaw**2 + player_firing_pitch**2)
                player_accuracies.append(player_distance.mean())
                if len(player_distance) > 3:
                    player_consistencies.append(player_distance.std())
    
    player_accuracies = np.array(player_accuracies)
    player_consistencies = np.array(player_consistencies)
    
    output_lines.append("## Individual Player Variance\n")
    output_lines.append("### Player-Level Accuracy (Mean Crosshair Distance)")
    output_lines.append(f"- **Population Mean**: {player_accuracies.mean():.3f}°")
    output_lines.append(f"- **Population Std Dev**: {player_accuracies.std():.3f}°")
    output_lines.append("- **Distribution**:")
    output_lines.append(f"  - 25th percentile: {np.percentile(player_accuracies, 25):.3f}°")
    output_lines.append(f"  - 75th percentile: {np.percentile(player_accuracies, 75):.3f}°")
    output_lines.append(f"  - 95th percentile: {np.percentile(player_accuracies, 95):.3f}°")
    output_lines.append(f"  - Min: {player_accuracies.min():.3f}°, Max: {player_accuracies.max():.3f}°\n")
    
    output_lines.append("### Player-Level Consistency (Std Dev of Accuracy)")
    output_lines.append(f"- **Population Mean**: {player_consistencies.mean():.3f}°")
    output_lines.append(f"- **Population Std Dev**: {player_consistencies.std():.3f}°")
    output_lines.append("- **Distribution**:")
    output_lines.append(f"  - 25th percentile: {np.percentile(player_consistencies, 25):.3f}°")
    output_lines.append(f"  - 75th percentile: {np.percentile(player_consistencies, 75):.3f}°")
    output_lines.append(f"  - 95th percentile: {np.percentile(player_consistencies, 95):.3f}°")
    output_lines.append(f"  - Min: {player_consistencies.min():.3f}°, Max: {player_consistencies.max():.3f}°\n")
    
    # Temporal Patterns
    pre_shot_window = slice(0, 160)
    during_shot_window = slice(160, 192)
    pre_shot_yaw = crosshair_yaw[:, :, pre_shot_window]
    during_shot_yaw = crosshair_yaw[:, :, during_shot_window]
    
    output_lines.append("## Temporal Patterns\n")
    output_lines.append("### Pre-Engagement vs During-Engagement")
    output_lines.append(f"- **Pre-Engagement** (5 seconds): {np.abs(pre_shot_yaw).mean():.3f}° mean absolute yaw distance")
    output_lines.append(f"- **During Engagement** (1 second): {np.abs(during_shot_yaw).mean():.3f}° mean absolute yaw distance\n")
    
    # Movement leading to shots
    shot_timesteps = np.where(firing > 0)
    pre_shot_movements = []
    
    for i in range(min(10000, len(shot_timesteps[0]))):
        player_idx, eng_idx, time_idx = shot_timesteps[0][i], shot_timesteps[1][i], shot_timesteps[2][i]
        if time_idx >= 10:
            yaw_before = crosshair_yaw[player_idx, eng_idx, time_idx-10:time_idx]
            pitch_before = crosshair_pitch[player_idx, eng_idx, time_idx-10:time_idx]
            yaw_movement = np.abs(np.diff(yaw_before)).sum()
            pitch_movement = np.abs(np.diff(pitch_before)).sum()
            pre_shot_movements.append([yaw_movement, pitch_movement])
    
    pre_shot_movements = np.array(pre_shot_movements)
    
    output_lines.append("### Movement Leading to Shots")
    output_lines.append("In the 10 timesteps immediately before firing:")
    output_lines.append(f"- **Yaw Movement**: {pre_shot_movements[:, 0].mean():.3f}° ± {pre_shot_movements[:, 0].std():.3f}° total movement")
    output_lines.append(f"- **Pitch Movement**: {pre_shot_movements[:, 1].mean():.3f}° ± {pre_shot_movements[:, 1].std():.3f}° total movement\n")
    
    # Suspicious Pattern Analysis
    suspiciously_accurate_players = np.sum(player_accuracies < 3.0)
    suspiciously_consistent_players = np.sum(player_consistencies < 5.0)
    
    # Perfect shot rate analysis
    perfect_shot_rates = []
    for player_idx in range(cheaters.shape[0]):
        player_firing_mask = firing[player_idx] > 0
        if np.any(player_firing_mask):
            player_firing_yaw = crosshair_yaw[player_idx][player_firing_mask]
            player_firing_pitch = crosshair_pitch[player_idx][player_firing_mask]
            player_distance = np.sqrt(player_firing_yaw**2 + player_firing_pitch**2)
            perfect_shots = np.sum(player_distance < 1.0)
            total_player_shots = len(player_distance)
            perfect_rate = perfect_shots / total_player_shots if total_player_shots > 0 else 0
            perfect_shot_rates.append(perfect_rate)
    
    perfect_shot_rates = np.array(perfect_shot_rates)
    high_perfect_rate_players = np.sum(perfect_shot_rates > 0.30)
    
    output_lines.append("## Suspicious Pattern Analysis\n")
    output_lines.append("### Players with Potentially Automated Behavior")
    output_lines.append(f"- **Extremely Accurate** (avg <3°): {suspiciously_accurate_players} ({suspiciously_accurate_players/len(player_accuracies):.1%})")
    output_lines.append(f"- **Extremely Consistent** (std <5°): {suspiciously_consistent_players} ({suspiciously_consistent_players/len(player_consistencies):.1%})")
    output_lines.append(f"- **High Perfect Shot Rate** (>30%): {high_perfect_rate_players} ({high_perfect_rate_players/len(perfect_shot_rates):.1%})\n")
    
    output_lines.append("### Perfect Shot Rate Distribution")
    output_lines.append(f"- **Mean**: {perfect_shot_rates.mean():.3%}, **Std**: {perfect_shot_rates.std():.3%}")
    output_lines.append("- **Percentiles**:")
    output_lines.append(f"  - 25th: {np.percentile(perfect_shot_rates, 25):.3%}")
    output_lines.append(f"  - 75th: {np.percentile(perfect_shot_rates, 75):.3%}")
    output_lines.append(f"  - 95th: {np.percentile(perfect_shot_rates, 95):.3%}")
    output_lines.append(f"  - Maximum: {perfect_shot_rates.max():.3%}\n")
    
    # Data Quality Assessment
    extreme_yaw = np.sum(np.abs(crosshair_yaw) > 150)
    extreme_pitch = np.sum(np.abs(crosshair_pitch) > 80) 
    total_datapoints = crosshair_yaw.size
    zero_yaw = np.sum(crosshair_yaw == 0)
    zero_pitch = np.sum(crosshair_pitch == 0)
    very_precise_yaw = np.sum((np.abs(crosshair_yaw) < 0.01) & (firing > 0))
    very_precise_pitch = np.sum((np.abs(crosshair_pitch) < 0.01) & (firing > 0))
    
    output_lines.append("## Data Quality Assessment\n")
    output_lines.append("### Potential Anomalies")
    output_lines.append(f"- **Extreme Yaw Values (>150°)**: {extreme_yaw:,} ({extreme_yaw/total_datapoints:.4%} of all datapoints)")
    output_lines.append(f"- **Extreme Pitch Values (>80°)**: {extreme_pitch:,} ({extreme_pitch/total_datapoints:.4%} of all datapoints)")
    output_lines.append("- **Exact Zero Values**:")
    output_lines.append(f"  - Yaw: {zero_yaw:,} ({zero_yaw/total_datapoints:.4%})")
    output_lines.append(f"  - Pitch: {zero_pitch:,} ({zero_pitch/total_datapoints:.4%})")
    output_lines.append("- **Extremely Precise Shots (<0.01°)**:")
    output_lines.append(f"  - Yaw: {very_precise_yaw:,} ({very_precise_yaw/total_shots:.4%} of shots)")
    output_lines.append(f"  - Pitch: {very_precise_pitch:,} ({very_precise_pitch/total_shots:.4%} of shots)\n")
    
    # Comparison implications
    output_lines.append("## Key Findings\n")
    output_lines.append("### Notable Patterns in Cheater Data")
    output_lines.append(f"1. **Accuracy Distribution**: {len(player_accuracies)} cheaters show mean accuracy from {player_accuracies.min():.1f}° to {player_accuracies.max():.1f}°")
    output_lines.append(f"2. **Perfect Shots**: {perfect_1deg/total_shots:.1%} of shots within 1° vs {perfect_5deg/total_shots:.1%} within 5°")
    output_lines.append(f"3. **Consistency Range**: Std deviation from {player_consistencies.min():.1f}° to {player_consistencies.max():.1f}°")
    output_lines.append(f"4. **Suspicious Subset**: {suspiciously_accurate_players} extremely accurate, {suspiciously_consistent_players} extremely consistent players")
    output_lines.append(f"5. **High-Performance Outliers**: {high_perfect_rate_players} players with >30% perfect shot rates\n")
    
    output_lines.append("### Data Quality")
    output_lines.append(f"**Assessment**: Low rate of extreme values ({extreme_yaw/total_datapoints:.2%} extreme yaw, {extreme_pitch/total_datapoints:.2%} extreme pitch) and exact zeros ({zero_yaw/total_datapoints:.2%} yaw, {zero_pitch/total_datapoints:.2%} pitch) suggests reasonable data quality. Presence of extremely precise shots ({very_precise_yaw/total_shots:.3%} yaw, {very_precise_pitch/total_shots:.3%} pitch) may indicate detection signatures.\n")
    
    output_lines.append("**Note**: This analysis presents empirical observations from the dataset without validation against domain expertise or published literature. Thresholds and patterns identified should be considered preliminary findings requiring further validation.")
    
    return "\n".join(output_lines)

if __name__ == "__main__":
    print("Analyzing cheaters dataset...")
    analysis_content = analyze_cheaters_dataset()
    
    output_file = '/home/atomik/src/aptl/ctf_scenarios/gaming/behavioural_analysis/notes/cheaters_analysis.md'
    with open(output_file, 'w') as f:
        f.write(analysis_content)
    
    print(f"Analysis complete. Results saved to: {output_file}")