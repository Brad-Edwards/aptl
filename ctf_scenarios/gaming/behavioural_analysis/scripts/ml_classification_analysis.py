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

def extract_features(data, labels, dataset_name):
    """Extract behavioral features from CS:GO engagement data"""
    
    print(f"Extracting features for {dataset_name}...")
    
    features = []
    player_labels = []
    
    for player_idx in range(data.shape[0]):
        player_data = data[player_idx]  # 30 engagements x 192 timesteps x 5 variables
        
        # Extract variables: AttackerDeltaYaw, AttackerDeltaPitch, CrosshairToVictimYaw, CrosshairToVictimPitch, Firing
        attacker_delta_yaw = player_data[:, :, 0]
        attacker_delta_pitch = player_data[:, :, 1]
        crosshair_to_victim_yaw = player_data[:, :, 2]
        crosshair_to_victim_pitch = player_data[:, :, 3]
        firing = player_data[:, :, 4]
        
        # Find all shots across all engagements
        shot_mask = firing > 0
        if not np.any(shot_mask):
            continue
        
        # 1. Shot accuracy - distance from crosshair to victim when firing
        shot_distances = np.sqrt(
            crosshair_to_victim_yaw[shot_mask]**2 + 
            crosshair_to_victim_pitch[shot_mask]**2
        )
        
        mean_shot_accuracy = np.mean(shot_distances)
        std_shot_accuracy = np.std(shot_distances)
        min_shot_accuracy = np.min(shot_distances)
        perfect_shots = np.mean(shot_distances < 1.0)  # Very close to target
        
        # 2. Pre-shot aim adjustment patterns
        pre_shot_adjustments_yaw = []
        pre_shot_adjustments_pitch = []
        
        for eng in range(30):
            for t in range(160, 192):  # Only look in the 1-second after part where shots likely occur
                if firing[eng, t] > 0:  # Shot fired
                    # Look at aim adjustments in 10 ticks before shot (if available)
                    start_tick = max(0, t-10)
                    yaw_adjustment = np.sum(np.abs(attacker_delta_yaw[eng, start_tick:t]))
                    pitch_adjustment = np.sum(np.abs(attacker_delta_pitch[eng, start_tick:t]))
                    pre_shot_adjustments_yaw.append(yaw_adjustment)
                    pre_shot_adjustments_pitch.append(pitch_adjustment)
        
        if pre_shot_adjustments_yaw:
            mean_pre_shot_yaw_adj = np.mean(pre_shot_adjustments_yaw)
            mean_pre_shot_pitch_adj = np.mean(pre_shot_adjustments_pitch)
        else:
            mean_pre_shot_yaw_adj = mean_pre_shot_pitch_adj = 0
        
        # 3. Tracking behavior - how crosshair distance to victim changes over time
        tracking_consistency = []
        for eng in range(30):
            victim_distances = np.sqrt(
                crosshair_to_victim_yaw[eng, :]**2 + 
                crosshair_to_victim_pitch[eng, :]**2
            )
            tracking_consistency.append(np.std(victim_distances))
        
        mean_tracking_consistency = np.mean(tracking_consistency)
        
        # 4. Firing patterns
        shots_per_engagement = np.sum(firing, axis=1)  # Sum over timesteps for each engagement
        mean_shots_per_engagement = np.mean(shots_per_engagement)
        std_shots_per_engagement = np.std(shots_per_engagement)
        
        # 5. Reaction timing - when in the engagement do shots occur
        first_shot_times = []
        for eng in range(30):
            shot_times = np.where(firing[eng, :] > 0)[0]
            if len(shot_times) > 0:
                first_shot_times.append(shot_times[0])  # First shot time in this engagement
        
        if first_shot_times:
            mean_reaction_time = np.mean(first_shot_times)
            std_reaction_time = np.std(first_shot_times)
        else:
            mean_reaction_time = std_reaction_time = 0
            
        # Compile feature vector
        feature_vector = [
            mean_shot_accuracy,
            std_shot_accuracy,
            min_shot_accuracy,
            perfect_shots,
            mean_pre_shot_yaw_adj,
            mean_pre_shot_pitch_adj,
            mean_tracking_consistency,
            mean_shots_per_engagement,
            std_shots_per_engagement,
            mean_reaction_time,
            std_reaction_time
        ]
        
        features.append(feature_vector)
        player_labels.append(labels)
    
    feature_names = [
        'mean_shot_accuracy',
        'std_shot_accuracy', 
        'min_shot_accuracy',
        'perfect_shots',
        'mean_pre_shot_yaw_adj',
        'mean_pre_shot_pitch_adj',
        'mean_tracking_consistency',
        'mean_shots_per_engagement',
        'std_shots_per_engagement', 
        'mean_reaction_time',
        'std_reaction_time'
    ]
    
    return np.array(features), np.array(player_labels), feature_names

def run_ml_analysis(models_to_run="rf", test_size=0.2):
    """Run comprehensive ML analysis to find differentiating patterns"""
    
    print("Loading datasets...")
    legit_data = np.load('data/legit/legit.npy')
    cheat_data = np.load('data/cheaters/cheaters.npy')
    
    print(f"Legit data shape: {legit_data.shape}")
    print(f"Cheat data shape: {cheat_data.shape}")
    
    # Extract features for both datasets
    legit_features, legit_labels, feature_names = extract_features(legit_data, 0, "Legitimate Players")
    cheat_features, cheat_labels, _ = extract_features(cheat_data, 1, "Cheaters")
    
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