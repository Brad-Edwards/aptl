#!/usr/bin/env python3
"""
Demo Cases for Anti-Cheat Behavioral Analysis

Based on CS:GO Cheating Dataset analysis, these cases represent realistic
scenarios an anti-cheat analyst might encounter during appeal investigations.
"""

import numpy as np
import json
from datetime import datetime, timedelta

# Load the datasets
CHEATERS = np.load('/home/atomik/src/aptl/ctf_scenarios/gaming/behavioural_analysis/data/cheaters/cheaters.npy')
LEGIT = np.load('/home/atomik/src/aptl/ctf_scenarios/gaming/behavioural_analysis/data/legit/legit.npy')

def analyze_player_patterns(player_data):
    """Extract key behavioral metrics from player data"""
    
    # Extract components
    attacker_yaw = player_data[:, :, 0]      # AttackerDeltaYaw
    attacker_pitch = player_data[:, :, 1]    # AttackerDeltaPitch  
    crosshair_yaw = player_data[:, :, 2]     # CrosshairToVictimYaw
    crosshair_pitch = player_data[:, :, 3]   # CrosshairToVictimPitch
    firing = player_data[:, :, 4]            # Firing (0 or 1)
    
    # Calculate metrics
    total_shots = int(np.sum(firing))
    avg_crosshair_accuracy_yaw = float(np.mean(np.abs(crosshair_yaw[firing > 0]))) if total_shots > 0 else 0
    avg_crosshair_accuracy_pitch = float(np.mean(np.abs(crosshair_pitch[firing > 0]))) if total_shots > 0 else 0
    
    # Detect potential snaps (sudden crosshair movements before firing)
    snap_count = 0
    for eng in range(player_data.shape[0]):
        for t in range(3, player_data.shape[1]):
            if firing[eng, t] == 1 and t > 5:
                yaw_change = abs(crosshair_yaw[eng, t] - crosshair_yaw[eng, t-3])
                pitch_change = abs(crosshair_pitch[eng, t] - crosshair_pitch[eng, t-3])
                if yaw_change > 15 or pitch_change > 8:
                    snap_count += 1
    
    # Movement consistency (lower is more robotic)
    movement_variance = float(np.var(attacker_yaw)) + float(np.var(attacker_pitch))
    
    return {
        "total_shots": total_shots,
        "avg_crosshair_accuracy_yaw": round(avg_crosshair_accuracy_yaw, 3),
        "avg_crosshair_accuracy_pitch": round(avg_crosshair_accuracy_pitch, 3),
        "snap_shots_detected": snap_count,
        "movement_variance": round(movement_variance, 3),
        "engagements_analyzed": int(player_data.shape[0])
    }

# Define our demo cases
DEMO_CASES = [
    {
        "case_id": "CASE_001_OBVIOUS_CHEATER",
        "player_id": "steam_76561198400",
        "dataset_index": 400,
        "dataset_type": "cheater",
        "ground_truth": "CHEATER",
        "description": "Obvious aimbot with extreme snapping patterns",
        "expected_verdict": "UPHOLD_BAN"
    },
    {
        "case_id": "CASE_002_SUBTLE_CHEATER", 
        "player_id": "steam_76561198191",
        "dataset_index": 1913,
        "dataset_type": "cheater",
        "ground_truth": "CHEATER",
        "description": "Subtle aimbot with humanized movements",
        "expected_verdict": "UPHOLD_BAN"
    },
    {
        "case_id": "CASE_003_FALSE_POSITIVE",
        "player_id": "steam_76561198059",
        "dataset_index": 59,
        "dataset_type": "legit",
        "ground_truth": "LEGIT_HIGH_SKILL",
        "description": "High-skill player with aggressive playstyle",
        "expected_verdict": "OVERTURN_BAN"
    },
    {
        "case_id": "CASE_004_NORMAL_PLAYER",
        "player_id": "steam_76561198000",
        "dataset_index": 0,
        "dataset_type": "legit",
        "ground_truth": "LEGIT_NORMAL",
        "description": "Average player incorrectly flagged",
        "expected_verdict": "OVERTURN_BAN"
    }
]

def generate_eos_sanction(case):
    """Generate realistic EOS Sanctions API response"""
    base_time = datetime(2024, 1, 15, 14, 30, 22)
    
    return {
        "productUserId": case["player_id"],
        "referenceId": f"sanction_{case['case_id'].lower()}",
        "timestamp": base_time.isoformat() + "Z",
        "action": "CHEAT_DETECTION",
        "justification": "Automated anti-cheat detection - aimbot signature",
        "source": "easy-anti-cheat",
        "trustedPartner": "EAC",
        "automated": True,
        "pending": False,
        "metadata": {
            "detection_type": "aimbot",
            "confidence": "high" if "CHEATER" in case["case_id"] else "medium"
        },
        "status": "Active"
    }

def generate_appeal(case):
    """Generate realistic player appeal"""
    appeals = {
        "CASE_001_OBVIOUS_CHEATER": {
            "reason": 1,  # "Incorrect sanction"
            "appeal_text": "This is completely wrong! I never cheated. I've been playing CS:GO for 8 years and just have good aim. I recently switched to 240Hz monitor and new gaming mouse (Logitech G Pro X) which improved my performance. Please review the ban.",
            "submitted_evidence": ["receipt_monitor_240hz.pdf", "logitech_purchase_receipt.pdf"],
            "hardware_upgrade_date": "2024-01-14"
        },
        "CASE_002_SUBTLE_CHEATER": {
            "reason": 2,  # "Compromised account"  
            "appeal_text": "My account was hacked last month. I noticed suspicious activity and changed my password on January 10th. The cheating must have happened during the breach. I can provide evidence of the password reset and Steam Guard alerts.",
            "submitted_evidence": ["steam_guard_alerts.png", "password_reset_email.pdf"],
            "compromise_reported_date": "2024-01-10"
        },
        "CASE_003_FALSE_POSITIVE": {
            "reason": 1,  # "Incorrect sanction"
            "appeal_text": "I'm a competitive player (ESEA Rank A+) and this is clearly a false positive. I've been practicing aim_botz daily for months and recently improved my sensitivity settings. My playstyle is aggressive but completely legitimate. Check my ESEA profile and match history.",
            "submitted_evidence": ["esea_profile_screenshot.png", "training_routine_video.mp4"],
            "esea_profile": "https://play.esea.net/users/2845792"
        },
        "CASE_004_NORMAL_PLAYER": {
            "reason": 3,  # "Unfair punishment"
            "appeal_text": "I'm just a casual player who got lucky in a few matches. My overall stats are average and I've never used any cheats. This ban is ruining my experience with friends. Please reconsider.",
            "submitted_evidence": ["steam_profile_hours.png"],
            "steam_hours": 847
        }
    }
    
    return appeals[case["case_id"]]

def generate_account_metadata(case):
    """Generate synthetic account metadata"""
    base_date = datetime(2021, 3, 15)
    
    metadata = {
        "steam_id": case["player_id"],
        "account_created": base_date.isoformat(),
        "total_hours_csgo": 1200 + (case["dataset_index"] * 2),
        "last_hardware_change": None,
        "recent_ip_changes": [],
        "friends_with_banned_players": 0,
        "vac_bans_other_games": 0,
        "game_bans": 0,
        "account_value_usd": 250 + (case["dataset_index"] * 0.5)
    }
    
    # Add case-specific details
    if case["case_id"] == "CASE_001_OBVIOUS_CHEATER":
        metadata.update({
            "last_hardware_change": "2024-01-14T10:30:00Z",
            "recent_ip_changes": [
                {"date": "2024-01-14", "new_location": "Same City", "reason": "ISP_ROTATION"}
            ]
        })
    elif case["case_id"] == "CASE_002_SUBTLE_CHEATER":
        metadata.update({
            "recent_ip_changes": [
                {"date": "2024-01-08", "new_location": "Different Country", "reason": "VPN_DETECTED"},
                {"date": "2024-01-10", "new_location": "Original Location", "reason": "NORMAL"}
            ],
            "password_changes": [
                {"date": "2024-01-10T15:22:00Z", "initiated_by": "user"}
            ]
        })
    elif case["case_id"] == "CASE_003_FALSE_POSITIVE":
        metadata.update({
            "total_hours_csgo": 3247,
            "esea_premium": True,
            "faceit_elo": 2156,
            "friends_with_banned_players": 0,
            "account_value_usd": 1250
        })
        
    return metadata

def export_demo_cases():
    """Export all demo cases with data"""
    cases_data = []
    
    for case in DEMO_CASES:
        # Get behavioral data
        if case["dataset_type"] == "cheater":
            player_data = CHEATERS[case["dataset_index"]]
        else:
            player_data = LEGIT[case["dataset_index"]]
            
        behavioral_analysis = analyze_player_patterns(player_data)
        
        case_data = {
            "case_info": case,
            "eos_sanction": generate_eos_sanction(case),
            "player_appeal": generate_appeal(case),
            "account_metadata": generate_account_metadata(case),
            "behavioral_data": behavioral_analysis,
            "raw_viewangle_data": {
                "description": "30 engagements with 192 timesteps each (5 seconds before, 1 second after)",
                "shape": list(player_data.shape),
                "sample_engagement_0": {
                    "attacker_yaw_range": [float(player_data[0, :, 0].min()), float(player_data[0, :, 0].max())],
                    "crosshair_accuracy": float(np.mean(np.abs(player_data[0, :, 2:4])))
                }
            }
        }
        
        cases_data.append(case_data)
    
    return cases_data

if __name__ == "__main__":
    print("Generating demo cases for Anti-Cheat Behavioral Analysis...")
    
    cases = export_demo_cases()
    
    # Save to JSON for easy loading
    with open('/home/atomik/src/aptl/ctf_scenarios/gaming/behavioural_analysis/demo_cases.json', 'w') as f:
        json.dump(cases, f, indent=2)
    
    print(f"Generated {len(cases)} demo cases:")
    for case in cases:
        info = case["case_info"]
        behavioral = case["behavioral_data"]
        print(f"- {info['case_id']}: {info['description']}")
        print(f"  Shots fired: {behavioral['total_shots']}, Snaps: {behavioral['snap_shots_detected']}")
        print(f"  Expected verdict: {info['expected_verdict']}")
        print()