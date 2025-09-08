#!/usr/bin/env python3
"""
Generic descriptive statistics analysis for CS:GO behavioral datasets.
Usage: python3 analyze_dataset.py <numpy_file_path> <output_markdown_path> <dataset_name>
"""

import numpy as np
import sys
import os

def analyze_dataset(numpy_file_path, dataset_name="Dataset"):
    """Analyze any CS:GO behavioral dataset and generate comprehensive statistics"""
    
    if not os.path.exists(numpy_file_path):
        raise FileNotFoundError(f"Dataset file not found: {numpy_file_path}")
    
    # Load data
    data = np.load(numpy_file_path)
    
    # Prepare output
    output_lines = []
    output_lines.append(f"# {dataset_name} Analysis\n")
    
    # Dataset Overview
    output_lines.append("## Dataset Overview")
    output_lines.append(f"- **Total Players**: {data.shape[0]:,}")
    output_lines.append(f"- **Data Structure**: ({data.shape[0]:,} players × {data.shape[1]} engagements × {data.shape[2]} timesteps × {data.shape[3]} variables)")
    output_lines.append(f"- **Memory Usage**: {data.nbytes / (1024**3):.2f} GB")
    output_lines.append(f"- **Data Type**: {data.dtype}")
    output_lines.append("- **Temporal Coverage**: 6 seconds per engagement (5 seconds before kill + 1 second after)\n")
    
    # Variables
    output_lines.append("## Variables")
    output_lines.append("1. **AttackerDeltaYaw**: Player's horizontal mouse movement (degrees)")
    output_lines.append("2. **AttackerDeltaPitch**: Player's vertical mouse movement (degrees)")
    output_lines.append("3. **CrosshairToVictimYaw**: Horizontal distance from crosshair to victim (degrees)")  
    output_lines.append("4. **CrosshairToVictimPitch**: Vertical distance from crosshair to victim (degrees)")
    output_lines.append("5. **Firing**: Binary indicator (0 = not shooting, 1 = shooting)\n")
    
    # Extract the 5 variables
    attacker_yaw = data[:, :, :, 0]      
    attacker_pitch = data[:, :, :, 1]    
    crosshair_yaw = data[:, :, :, 2]     
    crosshair_pitch = data[:, :, :, 3]   
    firing = data[:, :, :, 4]            
    
    # Core Statistical Summary
    output_lines.append("## Data Ranges\n")
    output_lines.append("| Variable | Minimum | Maximum | Range |")
    output_lines.append("|----------|---------|---------|-------|")
    output_lines.append(f"| AttackerDeltaYaw | {attacker_yaw.min():.3f}° | {attacker_yaw.max():.3f}° | ~{attacker_yaw.max() - attacker_yaw.min():.0f}° |")
    output_lines.append(f"| AttackerDeltaPitch | {attacker_pitch.min():.3f}° | {attacker_pitch.max():.3f}° | ~{attacker_pitch.max() - attacker_pitch.min():.0f}° |")
    output_lines.append(f"| CrosshairToVictimYaw | {crosshair_yaw.min():.3f}° | {crosshair_yaw.max():.3f}° | {crosshair_yaw.max() - crosshair_yaw.min():.0f}° |")
    output_lines.append(f"| CrosshairToVictimPitch | {crosshair_pitch.min():.3f}° | {crosshair_pitch.max():.3f}° | ~{crosshair_pitch.max() - crosshair_pitch.min():.0f}° |")
    output_lines.append("| Firing | 0.0 | 1.0 | Binary |\n")
    
    # Firing Behavior Statistics
    total_firing_events = np.sum(firing)
    total_possible_events = data.shape[0] * data.shape[1] * data.shape[2]
    firing_rate = total_firing_events / total_possible_events
    player_total_shots = np.sum(firing, axis=(1,2))
    engagement_shots = np.sum(firing, axis=2)
    shots_per_engagement = engagement_shots[engagement_shots > 0]
    engagements_with_shots = np.sum(engagement_shots > 0)
    total_engagements = data.shape[0] * data.shape[1]
    
    output_lines.append("## Firing Behavior\n")
    output_lines.append(f"- **Total Firing Events**: {int(total_firing_events):,} shots across all players")
    output_lines.append(f"- **Overall Firing Rate**: {firing_rate:.4%} (firing in ~1 of every {1/firing_rate:.0f} timesteps)")
    output_lines.append(f"- **Shots per Player**: {player_total_shots.min():.0f} to {player_total_shots.max():.0f} (Mean: {player_total_shots.mean():.1f}, Std: {player_total_shots.std():.1f})")
    output_lines.append(f"- **Zero-Shot Players**: {np.sum(player_total_shots == 0)}")
    output_lines.append(f"- **Engagements with Shots**: {engagements_with_shots:,} of {total_engagements:,} ({engagements_with_shots/total_engagements:.1%})")
    output_lines.append(f"- **Shots per Engagement** (when shots fired): {shots_per_engagement.min():.0f} to {shots_per_engagement.max():.0f} (Mean: {shots_per_engagement.mean():.1f})\n")
    
    # Movement Patterns
    output_lines.append("## Movement Patterns\n")
    output_lines.append("### Attacker Movement (Mouse/Camera Control)\n")
    
    output_lines.append("**Horizontal Movement (Yaw)**")
    output_lines.append(f"- Mean: {attacker_yaw.mean():.3f}°, Std: {attacker_yaw.std():.3f}°")
    output_lines.append(f"- Percentiles: 25th={np.percentile(attacker_yaw, 25):.3f}°, 75th={np.percentile(attacker_yaw, 75):.3f}°, 99th={np.percentile(attacker_yaw, 99):.3f}°\n")
    
    output_lines.append("**Vertical Movement (Pitch)**")
    output_lines.append(f"- Mean: {attacker_pitch.mean():.3f}°, Std: {attacker_pitch.std():.3f}°")
    output_lines.append(f"- Percentiles: 25th={np.percentile(attacker_pitch, 25):.3f}°, 75th={np.percentile(attacker_pitch, 75):.3f}°, 99th={np.percentile(attacker_pitch, 99):.3f}°\n")
    
    # Crosshair Accuracy - All timesteps
    output_lines.append("## Crosshair Accuracy\n")
    output_lines.append("### All Timesteps\n")
    output_lines.append("| Metric | Yaw | Pitch |")
    output_lines.append("|--------|-----|-------|")
    output_lines.append(f"| Mean | {crosshair_yaw.mean():.3f}° | {crosshair_pitch.mean():.3f}° |")
    output_lines.append(f"| Std Dev | {crosshair_yaw.std():.3f}° | {crosshair_pitch.std():.3f}° |")
    output_lines.append(f"| Absolute Mean | {np.abs(crosshair_yaw).mean():.3f}° | {np.abs(crosshair_pitch).mean():.3f}° |")
    output_lines.append(f"| 25th Percentile (abs) | {np.percentile(np.abs(crosshair_yaw), 25):.3f}° | {np.percentile(np.abs(crosshair_pitch), 25):.3f}° |")
    output_lines.append(f"| 75th Percentile (abs) | {np.percentile(np.abs(crosshair_yaw), 75):.3f}° | {np.percentile(np.abs(crosshair_pitch), 75):.3f}° |")
    output_lines.append(f"| 95th Percentile (abs) | {np.percentile(np.abs(crosshair_yaw), 95):.3f}° | {np.percentile(np.abs(crosshair_pitch), 95):.3f}° |\n")
    
    # Crosshair Accuracy - At moment of firing
    firing_mask = firing > 0
    if np.any(firing_mask):
        firing_yaw = crosshair_yaw[firing_mask]
        firing_pitch = crosshair_pitch[firing_mask]
        firing_distance = np.sqrt(firing_yaw**2 + firing_pitch**2)
        
        output_lines.append("### At Moment of Firing\n")
        output_lines.append("| Metric | Yaw | Pitch | Combined Distance |")
        output_lines.append("|--------|-----|-------|------------------|")
        output_lines.append(f"| Absolute Mean | {np.abs(firing_yaw).mean():.3f}° | {np.abs(firing_pitch).mean():.3f}° | {firing_distance.mean():.3f}° |")
        output_lines.append(f"| Standard Deviation | {firing_yaw.std():.3f}° | {firing_pitch.std():.3f}° | {firing_distance.std():.3f}° |")
        output_lines.append(f"| 25th Percentile | {np.percentile(np.abs(firing_yaw), 25):.3f}° | {np.percentile(np.abs(firing_pitch), 25):.3f}° | {np.percentile(firing_distance, 25):.3f}° |")
        output_lines.append(f"| 50th Percentile | {np.percentile(np.abs(firing_yaw), 50):.3f}° | {np.percentile(np.abs(firing_pitch), 50):.3f}° | {np.percentile(firing_distance, 50):.3f}° |")
        output_lines.append(f"| 75th Percentile | {np.percentile(np.abs(firing_yaw), 75):.3f}° | {np.percentile(np.abs(firing_pitch), 75):.3f}° | {np.percentile(firing_distance, 75):.3f}° |")
        output_lines.append(f"| 95th Percentile | {np.percentile(np.abs(firing_yaw), 95):.3f}° | {np.percentile(np.abs(firing_pitch), 95):.3f}° | {np.percentile(firing_distance, 95):.3f}° |")
        output_lines.append(f"| 99th Percentile | {np.percentile(np.abs(firing_yaw), 99):.3f}° | {np.percentile(np.abs(firing_pitch), 99):.3f}° | {np.percentile(firing_distance, 99):.3f}° |\n")
        
        # Perfect Shot Analysis
        perfect_1deg = np.sum(firing_distance < 1.0)
        perfect_2deg = np.sum(firing_distance < 2.0)
        perfect_5deg = np.sum(firing_distance < 5.0)
        total_shots = len(firing_distance)
        
        output_lines.append("### 'Perfect Shot' Analysis\n")
        output_lines.append(f"- **Within 1°**: {perfect_1deg:,} shots ({perfect_1deg/total_shots:.2%})")
        output_lines.append(f"- **Within 2°**: {perfect_2deg:,} shots ({perfect_2deg/total_shots:.2%})")
        output_lines.append(f"- **Within 5°**: {perfect_5deg:,} shots ({perfect_5deg/total_shots:.2%})\n")
    
    # Individual Player Variance
    player_accuracies = []
    player_consistencies = []
    
    for player_idx in range(data.shape[0]):
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
    
    output_lines.append("## Individual Player Statistics\n")
    output_lines.append("### Player-Level Accuracy (Mean Crosshair Distance)\n")
    output_lines.append(f"- **Population Mean**: {player_accuracies.mean():.3f}°")
    output_lines.append(f"- **Population Std Dev**: {player_accuracies.std():.3f}°")
    output_lines.append(f"- **Range**: {player_accuracies.min():.3f}° to {player_accuracies.max():.3f}°")
    output_lines.append(f"- **Percentiles**: 25th={np.percentile(player_accuracies, 25):.3f}°, 75th={np.percentile(player_accuracies, 75):.3f}°, 95th={np.percentile(player_accuracies, 95):.3f}°\n")
    
    output_lines.append("### Player-Level Consistency (Std Dev of Accuracy)\n")
    output_lines.append(f"- **Population Mean**: {player_consistencies.mean():.3f}°")
    output_lines.append(f"- **Population Std Dev**: {player_consistencies.std():.3f}°")
    output_lines.append(f"- **Range**: {player_consistencies.min():.3f}° to {player_consistencies.max():.3f}°")
    output_lines.append(f"- **Percentiles**: 25th={np.percentile(player_consistencies, 25):.3f}°, 75th={np.percentile(player_consistencies, 75):.3f}°, 95th={np.percentile(player_consistencies, 95):.3f}°\n")
    
    # Temporal Patterns
    pre_shot_window = slice(0, 160)
    during_shot_window = slice(160, 192)
    pre_shot_yaw = crosshair_yaw[:, :, pre_shot_window]
    during_shot_yaw = crosshair_yaw[:, :, during_shot_window]
    
    output_lines.append("## Temporal Patterns\n")
    output_lines.append(f"- **Pre-Engagement** (5 seconds): {np.abs(pre_shot_yaw).mean():.3f}° mean absolute yaw")
    output_lines.append(f"- **During Engagement** (1 second): {np.abs(during_shot_yaw).mean():.3f}° mean absolute yaw\n")
    
    # Movement leading to shots
    shot_timesteps = np.where(firing > 0)
    if len(shot_timesteps[0]) > 100:
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
        output_lines.append("### Movement in 10 Timesteps Before Firing\n")
        output_lines.append(f"- **Yaw Movement**: {pre_shot_movements[:, 0].mean():.3f}° ± {pre_shot_movements[:, 0].std():.3f}°")
        output_lines.append(f"- **Pitch Movement**: {pre_shot_movements[:, 1].mean():.3f}° ± {pre_shot_movements[:, 1].std():.3f}°\n")
    
    # Data Quality
    extreme_yaw = np.sum(np.abs(crosshair_yaw) > 150)
    extreme_pitch = np.sum(np.abs(crosshair_pitch) > 80)
    total_datapoints = crosshair_yaw.size
    zero_yaw = np.sum(crosshair_yaw == 0)
    zero_pitch = np.sum(crosshair_pitch == 0)
    
    output_lines.append("## Data Quality\n")
    output_lines.append(f"- **Extreme Values**: {extreme_yaw:,} yaw >150° ({extreme_yaw/total_datapoints:.4%}), {extreme_pitch:,} pitch >80° ({extreme_pitch/total_datapoints:.4%})")
    output_lines.append(f"- **Exact Zeros**: {zero_yaw:,} yaw ({zero_yaw/total_datapoints:.4%}), {zero_pitch:,} pitch ({zero_pitch/total_datapoints:.4%})")
    
    if np.any(firing_mask):
        very_precise_yaw = np.sum((np.abs(crosshair_yaw) < 0.01) & (firing > 0))
        very_precise_pitch = np.sum((np.abs(crosshair_pitch) < 0.01) & (firing > 0))
        output_lines.append(f"- **Extremely Precise Shots** (<0.01°): {very_precise_yaw:,} yaw ({very_precise_yaw/total_shots:.4%}), {very_precise_pitch:,} pitch ({very_precise_pitch/total_shots:.4%})")
    
    return "\n".join(output_lines)

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 analyze_dataset.py <numpy_file_path> <output_markdown_path> <dataset_name>")
        print("Example: python3 analyze_dataset.py data/legit/legit.npy legit_analysis.md 'Legitimate Players'")
        sys.exit(1)
    
    numpy_file_path = sys.argv[1]
    output_file_path = sys.argv[2]
    dataset_name = sys.argv[3]
    
    print(f"Analyzing {dataset_name} dataset...")
    
    try:
        analysis_content = analyze_dataset(numpy_file_path, dataset_name)
        
        with open(output_file_path, 'w') as f:
            f.write(analysis_content)
        
        print(f"Analysis complete. Results saved to: {output_file_path}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()