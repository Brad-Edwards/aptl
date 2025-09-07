#!/usr/bin/env python3
"""
Machine Learning analysis to identify what actually differentiates legitimate players from cheaters.
Uses proper feature engineering and classification techniques.
"""

import numpy as np
import pandas as pd
import sys
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from xgboost import XGBClassifier
import matplotlib.pyplot as plt
import seaborn as sns

def extract_engagement_features(data, labels, dataset_name):
    """Extract per-engagement features to detect wallhack/aimbot signatures"""
    
    print(f"Extracting engagement features for {dataset_name}...")
    
    features = []
    engagement_labels = []
    
    for player_idx in range(data.shape[0]):
        player_data = data[player_idx]  # 30 engagements x 192 timesteps x 5 variables
        
        for eng in range(30):  # Process each engagement separately
            engagement = player_data[eng, :, :]  # 192 timesteps x 5 variables
            
            # Extract variables
            attacker_delta_yaw = engagement[:, 0]
            attacker_delta_pitch = engagement[:, 1]
            crosshair_to_victim_yaw = engagement[:, 2]
            crosshair_to_victim_pitch = engagement[:, 3]
            firing = engagement[:, 4]
            
            # Skip engagements with no shots
            if not np.any(firing > 0):
                continue
            
            # Calculate crosshair-to-victim distance over time
            victim_distances = np.sqrt(crosshair_to_victim_yaw**2 + crosshair_to_victim_pitch**2)
            
            # Find first shot time
            shot_times = np.where(firing > 0)[0]
            if len(shot_times) == 0:
                continue
            first_shot_time = shot_times[0]
            
            # 1. WALLHACK SIGNATURES - tracking behavior before shot
            
            # 5s, 3s, 1s tracking windows before shot
            windows = [160, 96, 32]  # ~5s, 3s, 1s (assuming 32 ticks/sec)
            tracking_features = []
            
            for window in windows:
                start_tick = max(0, first_shot_time - window)
                window_distances = victim_distances[start_tick:first_shot_time]
                
                if len(window_distances) > 0:
                    avg_distance = np.mean(window_distances)
                    std_distance = np.std(window_distances)
                    tracking_features.extend([avg_distance, std_distance])
                else:
                    tracking_features.extend([0, 0])
            
            # 2. AIMBOT SIGNATURES - movement efficiency
            
            # Movement-to-accuracy ratios at different intervals
            movement_efficiency = []
            intervals = [10, 5, 2]  # ticks before shot
            
            for interval in intervals:
                start_tick = max(0, first_shot_time - interval)
                
                # Total movement in this interval
                yaw_movement = np.sum(np.abs(attacker_delta_yaw[start_tick:first_shot_time]))
                pitch_movement = np.sum(np.abs(attacker_delta_pitch[start_tick:first_shot_time]))
                total_movement = yaw_movement + pitch_movement
                
                # Accuracy improvement over interval
                if start_tick < first_shot_time:
                    initial_distance = victim_distances[start_tick]
                    final_distance = victim_distances[first_shot_time-1] if first_shot_time > 0 else initial_distance
                    accuracy_improvement = max(0, initial_distance - final_distance)
                    
                    # Movement efficiency: how much accuracy per unit movement
                    if total_movement > 0:
                        efficiency = accuracy_improvement / total_movement
                    else:
                        efficiency = 0
                else:
                    efficiency = 0
                    
                movement_efficiency.append(efficiency)
            
            # 3. SHOT PRECISION
            shot_accuracy = victim_distances[first_shot_time] if first_shot_time < len(victim_distances) else 999
            
            # 4. PRE-SHOT SNAP DETECTION
            # Large movements in final ticks before shot
            snap_movement = 0
            if first_shot_time >= 3:
                final_yaw_movement = np.sum(np.abs(attacker_delta_yaw[first_shot_time-3:first_shot_time]))
                final_pitch_movement = np.sum(np.abs(attacker_delta_pitch[first_shot_time-3:first_shot_time]))
                snap_movement = final_yaw_movement + final_pitch_movement
            
            # 5. RAW DATA FEATURES - basic statistics on the raw variables
            
            # Basic stats on crosshair-to-victim distances
            cv_mean = np.mean(victim_distances)
            cv_std = np.std(victim_distances)
            cv_min = np.min(victim_distances)
            cv_max = np.max(victim_distances)
            
            # Basic stats on attacker movements  
            yaw_movement_total = np.sum(np.abs(attacker_delta_yaw))
            pitch_movement_total = np.sum(np.abs(attacker_delta_pitch))
            yaw_movement_std = np.std(attacker_delta_yaw)
            pitch_movement_std = np.std(attacker_delta_pitch)
            
            # Shot timing
            total_shots = np.sum(firing)
            
            # Compile feature vector
            feature_vector = (
                tracking_features +  # 6 features: avg/std distance for 5s, 3s, 1s windows
                movement_efficiency +  # 3 features: efficiency at 10, 5, 2 tick intervals
                [shot_accuracy, snap_movement] +  # 2 features: final shot accuracy and snap movement
                [cv_mean, cv_std, cv_min, cv_max] +  # 4 raw crosshair-victim features
                [yaw_movement_total, pitch_movement_total, yaw_movement_std, pitch_movement_std] +  # 4 raw movement features
                [total_shots]  # 1 raw firing feature
            )
            
            features.append(feature_vector)
            engagement_labels.append(labels)  # Same label as player
    
    feature_names = [
        'track_5s_avg', 'track_5s_std',
        'track_3s_avg', 'track_3s_std', 
        'track_1s_avg', 'track_1s_std',
        'movement_eff_10t', 'movement_eff_5t', 'movement_eff_2t',
        'shot_accuracy', 'snap_movement',
        'cv_mean', 'cv_std', 'cv_min', 'cv_max',
        'yaw_movement_total', 'pitch_movement_total', 'yaw_movement_std', 'pitch_movement_std',
        'total_shots'
    ]
    
    return np.array(features), np.array(engagement_labels), feature_names

def run_ml_analysis(models_to_run="rf", test_size=0.2):
    """Run comprehensive ML analysis to find differentiating patterns"""
    
    print("Loading datasets...")
    legit_data = np.load('data/legit/legit.npy')
    cheat_data = np.load('data/cheaters/cheaters.npy')
    
    print(f"Legit data shape: {legit_data.shape}")
    print(f"Cheat data shape: {cheat_data.shape}")
    
    # Extract features for both datasets  
    legit_features, legit_labels, feature_names = extract_engagement_features(legit_data, 0, "Legitimate Players")
    cheat_features, cheat_labels, _ = extract_engagement_features(cheat_data, 1, "Cheaters")
    
    # Combine datasets
    X = np.vstack([legit_features, cheat_features])
    y = np.hstack([legit_labels, cheat_labels])
    
    print(f"Combined dataset: {X.shape} features, {y.shape} labels")
    print(f"Feature names: {feature_names}")
    
    # Remove any NaN or infinite values
    valid_mask = np.isfinite(X).all(axis=1)
    X = X[valid_mask]
    y = y[valid_mask]
    
    print(f"After cleaning: {X.shape} samples")
    print(f"Class distribution: {np.bincount(y)} (0=legit, 1=cheat)")
    
    results = []
    results.append("# Machine Learning Classification Analysis\n")
    results.append(f"## Dataset Summary")
    results.append(f"- **Total Samples**: {len(X):,}")
    results.append(f"- **Features**: {len(feature_names)}")
    results.append(f"- **Legitimate Players**: {np.sum(y == 0):,}")
    results.append(f"- **Cheaters**: {np.sum(y == 1):,}")
    results.append("")
    
    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=test_size, random_state=42, stratify=y)
    
    
    feature_importance = []  # Initialize for later use
    
    # Random Forest Classification
    if 'r' in models_to_run:
        results.append("## Random Forest Classification\n")
        rf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
        rf.fit(X_train, y_train)
        
        
        # Test set performance
        y_pred = rf.predict(X_test)
        results.append("### Test Set Performance")
        results.append("```")
        results.append(classification_report(y_test, y_pred, target_names=['Legitimate', 'Cheater']))
        results.append("```")
        results.append("")
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        results.append("### Confusion Matrix")
        results.append("|          | Predicted Legit | Predicted Cheat |")
        results.append("|----------|-----------------|-----------------|")
        results.append(f"| **Actual Legit** | {cm[0,0]} | {cm[0,1]} |")
        results.append(f"| **Actual Cheat** | {cm[1,0]} | {cm[1,1]} |")
        results.append("")
    
    # 3. Logistic Regression for interpretability
    if 'l' in models_to_run:
        results.append("## Logistic Regression Analysis\n")
        lr = LogisticRegression(random_state=42, class_weight='balanced', max_iter=1000)
        lr.fit(X_train, y_train)
        
    
    # 4. XGBoost Classification
    if 'x' in models_to_run:
        results.append("## XGBoost Classification\n")
        xgb = XGBClassifier(
            scale_pos_weight=5,  # Handle 5:1 class imbalance
            random_state=42,
            eval_metric='logloss',
            verbosity=0
        )
        xgb.fit(X_train, y_train)
        
        
        # Test set performance
        y_pred_xgb = xgb.predict(X_test)
        results.append("### Test Set Performance")
        results.append("```")
        results.append(classification_report(y_test, y_pred_xgb, target_names=['Legitimate', 'Cheater']))
        results.append("```")
        results.append("")
        
        # Confusion Matrix
        cm_xgb = confusion_matrix(y_test, y_pred_xgb)
        results.append("### Confusion Matrix")
        results.append("|          | Predicted Legit | Predicted Cheat |")
        results.append("|----------|-----------------|-----------------|")
        results.append(f"| **Actual Legit** | {cm_xgb[0,0]} | {cm_xgb[0,1]} |")
        results.append(f"| **Actual Cheat** | {cm_xgb[1,0]} | {cm_xgb[1,1]} |")
        results.append("")
    
    
    return "\n".join(results)

def main():
    # Parse command line arguments
    models_to_run = "rf"  # default: random forest only
    test_size = 0.2  # default: 80/20 split
    output_file = 'notes/ml_classification_analysis.md'
    
    for arg in sys.argv[1:]:
        if arg.startswith('-'):
            models_to_run = arg[1:]  # remove the - prefix
        elif arg.replace('.', '').isdigit():
            test_size = float(arg)
        else:
            output_file = arg
    
    print(f"Starting ML Classification Analysis with models: {models_to_run}, test_size: {test_size}")
    analysis_results = run_ml_analysis(models_to_run, test_size)
    
    with open(output_file, 'w') as f:
        f.write(analysis_results)
    
    print(f"Analysis complete. Results saved to: {output_file}")

if __name__ == "__main__":
    main()