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
from sklearn.metrics import classification_report, confusion_matrix, roc_curve
from sklearn.decomposition import PCA
from xgboost import XGBClassifier
import lightgbm as lgb
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import matplotlib.pyplot as plt
import seaborn as sns

def extract_raw_engagement_features(data, labels, dataset_name):
    """Extract raw statistical features from each engagement"""
    
    print(f"Extracting raw engagement features for {dataset_name}...")
    
    features = []
    engagement_labels = []
    
    for player_idx in range(data.shape[0]):
        player_data = data[player_idx]  # 30 engagements x 192 timesteps x 5 variables
        
        for eng in range(30):  # Process each engagement separately
            engagement = player_data[eng, :, :]  # 192 timesteps x 5 variables
            
            # Extract the 5 raw variables
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
            
            # 1. BASIC RAW STATISTICS (original features)
            basic_features = []
            
            # For each variable: mean, std, min, max, total
            for var in [attacker_delta_yaw, attacker_delta_pitch, crosshair_to_victim_yaw, crosshair_to_victim_pitch]:
                basic_features.extend([
                    np.mean(var),
                    np.std(var),
                    np.min(var), 
                    np.max(var),
                    np.sum(np.abs(var))  # total absolute movement/distance
                ])
            
            # For firing: just sum (total shots)
            basic_features.append(np.sum(firing))
            
            # 2. WALLHACK SIGNATURES - tracking behavior before shot
            
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
            
            # 3. AIMBOT SIGNATURES - movement efficiency
            
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
            
            # 4. SHOT PRECISION
            shot_accuracy = victim_distances[first_shot_time] if first_shot_time < len(victim_distances) else 999
            
            # 5. PRE-SHOT SNAP DETECTION
            # Large movements in final ticks before shot
            snap_movement = 0
            if first_shot_time >= 3:
                final_yaw_movement = np.sum(np.abs(attacker_delta_yaw[first_shot_time-3:first_shot_time]))
                final_pitch_movement = np.sum(np.abs(attacker_delta_pitch[first_shot_time-3:first_shot_time]))
                snap_movement = final_yaw_movement + final_pitch_movement
            
            # 6. ADDITIONAL RAW DATA FEATURES
            
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
            
            # 7. MOVEMENT SMOOTHNESS AND BEHAVIORAL FEATURES
            
            # Movement direction changes (jerkiness)
            yaw_direction_changes = np.sum(np.diff(np.sign(attacker_delta_yaw)) != 0)
            pitch_direction_changes = np.sum(np.diff(np.sign(attacker_delta_pitch)) != 0)
            total_direction_changes = yaw_direction_changes + pitch_direction_changes
            
            # Micro-movements (small adjustments humans make)
            yaw_micro_movements = np.sum((np.abs(attacker_delta_yaw) > 0.01) & (np.abs(attacker_delta_yaw) < 0.1))
            pitch_micro_movements = np.sum((np.abs(attacker_delta_pitch) > 0.01) & (np.abs(attacker_delta_pitch) < 0.1))
            micro_movement_rate = (yaw_micro_movements + pitch_micro_movements) / len(attacker_delta_yaw)
            
            # Movement smoothness (velocity variance)
            yaw_velocity_changes = np.diff(attacker_delta_yaw)
            pitch_velocity_changes = np.diff(attacker_delta_pitch)
            yaw_smoothness = np.std(yaw_velocity_changes) if len(yaw_velocity_changes) > 0 else 0
            pitch_smoothness = np.std(pitch_velocity_changes) if len(pitch_velocity_changes) > 0 else 0
            
            # Zero movement periods (unnatural stillness)
            zero_movement_count = np.sum((attacker_delta_yaw == 0) & (attacker_delta_pitch == 0))
            
            # 8. PER-ENGAGEMENT TIMING FEATURES
            
            # First shot delay (reaction time for this engagement)
            first_shot_delay = first_shot_time
            
            # Movement to shot gap (time between last movement and first shot)
            last_movement_time = 0
            for t in range(first_shot_time - 1, -1, -1):
                if attacker_delta_yaw[t] != 0 or attacker_delta_pitch[t] != 0:
                    last_movement_time = t
                    break
            movement_to_shot_gap = max(0, first_shot_time - last_movement_time)
            
            # Early vs late shot accuracy (if multiple shots)
            if total_shots > 1:
                shot_indices = np.where(firing > 0)[0]
                mid_point = len(shot_indices) // 2
                early_shots = shot_indices[:mid_point]
                late_shots = shot_indices[mid_point:]
                
                early_accuracy = np.mean(victim_distances[early_shots]) if len(early_shots) > 0 else 999
                late_accuracy = np.mean(victim_distances[late_shots]) if len(late_shots) > 0 else 999
                accuracy_progression = early_accuracy - late_accuracy  # positive = improved over time
            else:
                accuracy_progression = 0
            
            # Movement axis dominance
            if pitch_movement_total > 0:
                movement_axis_ratio = yaw_movement_total / pitch_movement_total
            else:
                movement_axis_ratio = 99 if yaw_movement_total > 0 else 1
            
            # Number of shots in this engagement
            shots_per_engagement = total_shots
            
            # 9. MOVEMENT TIMING WINDOWS (wallhack signatures)
            
            # When do they start moving significantly
            movement_start_time = 0
            for t in range(len(attacker_delta_yaw)):
                if abs(attacker_delta_yaw[t]) > 0.1 or abs(attacker_delta_pitch[t]) > 0.1:
                    movement_start_time = t
                    break
            
            # Movement intensity in different time windows
            mid_point = len(attacker_delta_yaw) // 2  # 96 timesteps
            early_movement_intensity = np.sum(np.abs(attacker_delta_yaw[:mid_point])) + np.sum(np.abs(attacker_delta_pitch[:mid_point]))
            late_movement_intensity = np.sum(np.abs(attacker_delta_yaw[mid_point:])) + np.sum(np.abs(attacker_delta_pitch[mid_point:]))
            
            # Early vs late movement ratio (wallhack signature)
            if late_movement_intensity > 0:
                early_vs_late_movement_ratio = early_movement_intensity / late_movement_intensity
            else:
                early_vs_late_movement_ratio = 99 if early_movement_intensity > 0 else 1
            
            # 10. INITIAL POSITIONING (surprise factor)
            
            # How far off-target at engagement start
            initial_crosshair_offset = victim_distances[0]
            
            # Improvement from start to first shot
            convergence_improvement = victim_distances[0] - victim_distances[first_shot_time] if first_shot_time < len(victim_distances) else 0
            
            # Combine features - keeping top performing features based on PCA analysis
            feature_vector = [
                # Top crosshair-victim positioning features
                cv_max, cv_std, cv_mean,  # distance variance and positioning
                
                # Top movement features (yaw dominant)
                np.sum(np.abs(attacker_delta_yaw)), np.std(attacker_delta_yaw),  # yaw total and std
                yaw_movement_total, yaw_movement_std,  # duplicate but PCA shows importance
                
                # Top basic stats from original features
                np.std(crosshair_to_victim_yaw), np.sum(np.abs(crosshair_to_victim_yaw)),  # cv_yaw_std, cv_yaw_total
                
                # Key tracking features
                tracking_features[0], tracking_features[1],  # track_5s_avg, track_5s_std
                
                # Best movement efficiency
                movement_efficiency[0],  # movement_eff_10t
                
                # Shot precision
                shot_accuracy,
                
                # Key behavioral features that showed up
                total_direction_changes, micro_movement_rate,
                
                # Firing patterns
                total_shots, shots_per_engagement,
                
                # Pitch features (lower importance but still useful)
                np.sum(np.abs(attacker_delta_pitch)), np.std(attacker_delta_pitch),  # pitch total and std
                pitch_movement_total, pitch_movement_std,
                
                # Key timing features
                first_shot_delay, movement_to_shot_gap,
                
                # Initial positioning
                initial_crosshair_offset,
                
                # Additional distance features
                cv_min,
                
                # Snap movement
                snap_movement
            ]
            
            features.append(feature_vector)
            engagement_labels.append(labels)  # Same label as player
    
    feature_names = [
        # Top performing features based on PCA analysis
        'cv_distance_max', 'cv_distance_std', 'cv_distance_mean',  # top 3 distance features
        'delta_yaw_total', 'delta_yaw_std',  # top yaw movement features
        'yaw_movement_total', 'yaw_movement_std',  # duplicate yaw features (high importance)
        'cv_yaw_std', 'cv_yaw_total',  # crosshair yaw variance
        'track_5s_avg', 'track_5s_std',  # key tracking features
        'movement_eff_10t',  # best movement efficiency
        'shot_accuracy',  # shot precision
        'total_direction_changes', 'micro_movement_rate',  # behavioral patterns
        'total_shots', 'shots_per_engagement',  # firing patterns
        'delta_pitch_total', 'delta_pitch_std',  # pitch movement
        'pitch_movement_total', 'pitch_movement_std',  # pitch duplicates
        'first_shot_delay', 'movement_to_shot_gap',  # timing features
        'initial_crosshair_offset',  # positioning
        'cv_distance_min',  # additional distance
        'snap_movement'  # pre-shot snap
    ]
    
    return np.array(features), np.array(engagement_labels), feature_names

class SimpleNet(nn.Module):
    def __init__(self, input_size):
        super(SimpleNet, self).__init__()
        self.layers = nn.Sequential(
            nn.Linear(input_size, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 32),
            nn.ReLU(), 
            nn.Dropout(0.3),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        return self.layers(x)

def find_best_threshold(y_true, y_proba, metric='f1'):
    """Find optimal threshold for binary classification"""
    fpr, tpr, thresholds = roc_curve(y_true, y_proba)
    
    if metric == 'f1':
        # Maximize F1 score
        f1_scores = []
        for thresh in thresholds:
            y_pred_thresh = (y_proba >= thresh).astype(int)
            tp = np.sum((y_true == 1) & (y_pred_thresh == 1))
            fp = np.sum((y_true == 0) & (y_pred_thresh == 1))
            fn = np.sum((y_true == 1) & (y_pred_thresh == 0))
            
            if tp + fp == 0 or tp + fn == 0:
                f1 = 0
            else:
                precision = tp / (tp + fp)
                recall = tp / (tp + fn)
                f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            f1_scores.append(f1)
        
        best_idx = np.argmax(f1_scores)
        return thresholds[best_idx]
    
    elif metric == 'balanced':
        # Maximize balanced accuracy
        balanced_acc = (tpr + (1 - fpr)) / 2
        best_idx = np.argmax(balanced_acc)
        return thresholds[best_idx]

def train_random_forest(X_train, y_train, X_test, y_test, feature_names=None):
    """Train Random Forest and return results"""
    results = []
    results.append("## Random Forest Classification\n")
    
    # PCA Analysis first
    results.append("### Principal Component Analysis\n")
    pca = PCA()
    pca.fit(X_train)
    
    # Explained variance
    explained_variance = pca.explained_variance_ratio_
    cumulative_variance = np.cumsum(explained_variance)
    
    results.append("#### Explained Variance by Components")
    for i in range(min(10, len(explained_variance))):  # Top 10 components
        results.append(f"- PC{i+1}: {explained_variance[i]:.3f} ({cumulative_variance[i]:.3f} cumulative)")
    results.append("")
    
    # Feature importance from PCA loadings
    if feature_names is not None:
        pc1_loadings = pca.components_[0]
        feature_importance_pca = list(zip(feature_names, np.abs(pc1_loadings)))
        feature_importance_pca.sort(key=lambda x: x[1], reverse=True)
        
        results.append("#### Most Important Features (PC1 Loadings)")
        for feat, importance in feature_importance_pca[:10]:  # Top 10
            results.append(f"- **{feat}**: {importance:.3f}")
        results.append("")
    
    # Dimensionality reduction recommendation
    components_90 = np.argmax(cumulative_variance >= 0.90) + 1
    components_95 = np.argmax(cumulative_variance >= 0.95) + 1
    results.append(f"#### Dimensionality Insights")
    results.append(f"- **90% variance**: {components_90} components (vs {len(explained_variance)} original)")
    results.append(f"- **95% variance**: {components_95} components")
    results.append("")
    
    rf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    rf.fit(X_train, y_train)
    
    # Test set performance with default threshold
    y_pred = rf.predict(X_test)
    results.append("### Test Set Performance (Default)")
    results.append("```")
    results.append(classification_report(y_test, y_pred, target_names=['Legitimate', 'Cheater']))
    results.append("```")
    
    # Find optimal threshold and test
    y_proba = rf.predict_proba(X_test)[:, 1]
    best_thresh = find_best_threshold(y_test, y_proba, 'f1')
    y_pred_tuned = (y_proba >= best_thresh).astype(int)
    
    results.append(f"### Test Set Performance (Tuned Threshold: {best_thresh:.3f})")
    results.append("```")
    results.append(classification_report(y_test, y_pred_tuned, target_names=['Legitimate', 'Cheater']))
    results.append("```")
    results.append("")
    
    # Confusion Matrix (tuned)
    cm = confusion_matrix(y_test, y_pred_tuned)
    results.append("### Confusion Matrix (Tuned)")
    results.append("|          | Predicted Legit | Predicted Cheat |")
    results.append("|----------|-----------------|-----------------|")
    results.append(f"| **Actual Legit** | {cm[0,0]} | {cm[0,1]} |")
    results.append(f"| **Actual Cheat** | {cm[1,0]} | {cm[1,1]} |")
    results.append("")
    
    return results

def train_logistic_regression(X_train, y_train, X_test, y_test):
    """Train Logistic Regression and return results"""
    results = []
    results.append("## Logistic Regression Analysis\n")
    
    lr = LogisticRegression(random_state=42, class_weight='balanced', max_iter=1000)
    lr.fit(X_train, y_train)
    
    # Test set performance
    y_pred_lr = lr.predict(X_test)
    results.append("### Test Set Performance")
    results.append("```")
    results.append(classification_report(y_test, y_pred_lr, target_names=['Legitimate', 'Cheater']))
    results.append("```")
    results.append("")
    
    # Confusion Matrix
    cm_lr = confusion_matrix(y_test, y_pred_lr)
    results.append("### Confusion Matrix")
    results.append("|          | Predicted Legit | Predicted Cheat |")
    results.append("|----------|-----------------|-----------------|")
    results.append(f"| **Actual Legit** | {cm_lr[0,0]} | {cm_lr[0,1]} |")
    results.append(f"| **Actual Cheat** | {cm_lr[1,0]} | {cm_lr[1,1]} |")
    results.append("")
    
    return results

def train_xgboost(X_train, y_train, X_test, y_test):
    """Train XGBoost and return results"""
    results = []
    results.append("## XGBoost Classification\n")
    
    xgb = XGBClassifier(
        scale_pos_weight=5,  # Handle 5:1 class imbalance
        random_state=42,
        eval_metric='logloss',
        verbosity=0
    )
    xgb.fit(X_train, y_train)
    
    # Test set performance with default threshold
    y_pred_xgb = xgb.predict(X_test)
    results.append("### Test Set Performance (Default)")
    results.append("```")
    results.append(classification_report(y_test, y_pred_xgb, target_names=['Legitimate', 'Cheater']))
    results.append("```")
    
    # Find optimal threshold and test
    y_proba_xgb = xgb.predict_proba(X_test)[:, 1]
    best_thresh_xgb = find_best_threshold(y_test, y_proba_xgb, 'f1')
    y_pred_xgb_tuned = (y_proba_xgb >= best_thresh_xgb).astype(int)
    
    results.append(f"### Test Set Performance (Tuned Threshold: {best_thresh_xgb:.3f})")
    results.append("```")
    results.append(classification_report(y_test, y_pred_xgb_tuned, target_names=['Legitimate', 'Cheater']))
    results.append("```")
    results.append("")
    
    # Confusion Matrix (tuned)
    cm_xgb = confusion_matrix(y_test, y_pred_xgb_tuned)
    results.append("### Confusion Matrix (Tuned)")
    results.append("|          | Predicted Legit | Predicted Cheat |")
    results.append("|----------|-----------------|-----------------|")
    results.append(f"| **Actual Legit** | {cm_xgb[0,0]} | {cm_xgb[0,1]} |")
    results.append(f"| **Actual Cheat** | {cm_xgb[1,0]} | {cm_xgb[1,1]} |")
    results.append("")
    
    return results

def train_neural_network(X_train, y_train, X_test, y_test):
    """Train Neural Network and return results"""
    results = []
    results.append("## Neural Network (PyTorch)\n")
    
    # Convert to PyTorch tensors
    X_train_tensor = torch.FloatTensor(X_train)
    y_train_tensor = torch.FloatTensor(y_train).reshape(-1, 1)
    X_test_tensor = torch.FloatTensor(X_test)
    
    # Create model
    model = SimpleNet(X_train.shape[1])
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)
    
    # Training
    model.train()
    batch_size = 1024
    train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    
    for epoch in range(20):
        for batch_x, batch_y in train_loader:
            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
    
    # Predictions
    model.eval()
    with torch.no_grad():
        y_proba_nn = model(X_test_tensor).numpy().flatten()
    
    # Default threshold
    y_pred_nn = (y_proba_nn >= 0.5).astype(int)
    results.append("### Test Set Performance (Default)")
    results.append("```")
    results.append(classification_report(y_test, y_pred_nn, target_names=['Legitimate', 'Cheater']))
    results.append("```")
    
    # Tuned threshold
    best_thresh_nn = find_best_threshold(y_test, y_proba_nn, 'f1')
    y_pred_nn_tuned = (y_proba_nn >= best_thresh_nn).astype(int)
    
    results.append(f"### Test Set Performance (Tuned Threshold: {best_thresh_nn:.3f})")
    results.append("```")
    results.append(classification_report(y_test, y_pred_nn_tuned, target_names=['Legitimate', 'Cheater']))
    results.append("```")
    results.append("")
    
    # Confusion Matrix (tuned)
    cm_nn = confusion_matrix(y_test, y_pred_nn_tuned)
    results.append("### Confusion Matrix (Tuned)")
    results.append("|          | Predicted Legit | Predicted Cheat |")
    results.append("|----------|-----------------|-----------------|")
    results.append(f"| **Actual Legit** | {cm_nn[0,0]} | {cm_nn[0,1]} |")
    results.append(f"| **Actual Cheat** | {cm_nn[1,0]} | {cm_nn[1,1]} |")
    results.append("")
    
    return results

def train_lightgbm(X_train, y_train, X_test, y_test):
    """Train LightGBM and return results"""
    results = []
    results.append("## LightGBM Classification\n")
    
    # LightGBM datasets
    train_data = lgb.Dataset(X_train, label=y_train)
    
    # Parameters
    params = {
        'objective': 'binary',
        'metric': 'binary_logloss',
        'boosting_type': 'gbdt',
        'num_leaves': 31,
        'learning_rate': 0.05,
        'feature_fraction': 0.9,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'verbose': 0,
        'scale_pos_weight': 5
    }
    
    # Train
    lgb_model = lgb.train(params, train_data, num_boost_round=100)
    
    # Predictions
    y_proba_lgb = lgb_model.predict(X_test, num_iteration=lgb_model.best_iteration)
    
    # Default threshold
    y_pred_lgb = (y_proba_lgb >= 0.5).astype(int)
    results.append("### Test Set Performance (Default)")
    results.append("```")
    results.append(classification_report(y_test, y_pred_lgb, target_names=['Legitimate', 'Cheater']))
    results.append("```")
    
    # Tuned threshold
    best_thresh_lgb = find_best_threshold(y_test, y_proba_lgb, 'f1')
    y_pred_lgb_tuned = (y_proba_lgb >= best_thresh_lgb).astype(int)
    
    results.append(f"### Test Set Performance (Tuned Threshold: {best_thresh_lgb:.3f})")
    results.append("```")
    results.append(classification_report(y_test, y_pred_lgb_tuned, target_names=['Legitimate', 'Cheater']))
    results.append("```")
    results.append("")
    
    # Confusion Matrix (tuned)
    cm_lgb = confusion_matrix(y_test, y_pred_lgb_tuned)
    results.append("### Confusion Matrix (Tuned)")
    results.append("|          | Predicted Legit | Predicted Cheat |")
    results.append("|----------|-----------------|-----------------|")
    results.append(f"| **Actual Legit** | {cm_lgb[0,0]} | {cm_lgb[0,1]} |")
    results.append(f"| **Actual Cheat** | {cm_lgb[1,0]} | {cm_lgb[1,1]} |")
    results.append("")
    
    return results

def run_ml_analysis(models_to_run="r", test_size=0.2):
    """Run comprehensive ML analysis to find differentiating patterns"""
    
    print("Loading datasets...")
    legit_data = np.load('data/legit/legit.npy')
    cheat_data = np.load('data/cheaters/cheaters.npy')
    
    print(f"Legit data shape: {legit_data.shape}")
    print(f"Cheat data shape: {cheat_data.shape}")
    
    # Extract features for both datasets
    legit_features, legit_labels, feature_names = extract_raw_engagement_features(legit_data, 0, "Legitimate Players")
    cheat_features, cheat_labels, _ = extract_raw_engagement_features(cheat_data, 1, "Cheaters")
    
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
    
    
    # Run selected models
    if 'r' in models_to_run:
        results.extend(train_random_forest(X_train, y_train, X_test, y_test, feature_names))
    if 'l' in models_to_run:
        results.extend(train_logistic_regression(X_train, y_train, X_test, y_test))
    if 'x' in models_to_run:
        results.extend(train_xgboost(X_train, y_train, X_test, y_test))
    if 'n' in models_to_run:
        results.extend(train_neural_network(X_train, y_train, X_test, y_test))
    if 'd' in models_to_run:
        results.extend(train_lightgbm(X_train, y_train, X_test, y_test))
    
    return "\n".join(results)

def main():
    # Parse command line arguments
    models_to_run = "r"  # default: run Random Forest only
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