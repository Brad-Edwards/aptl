#!/usr/bin/env python3
"""
Download CS:GO Pro Players Dataset from Kaggle.
Usage: python3 download_pro_players.py
"""

import kagglehub
import os
import sys

def download_pro_players_dataset():
    """Download the CS:GO Pro Players dataset from Kaggle"""
    
    try:
        print("Downloading CS:GO Pro Players dataset...")
        
        # Download latest version
        path = kagglehub.dataset_download("naumanaarif/csgo-pro-players-dataset")
        
        print(f"Path to dataset files: {path}")
        
        # List downloaded files
        if os.path.exists(path):
            files = os.listdir(path)
            print(f"\nDownloaded files:")
            for file in files:
                file_path = os.path.join(path, file)
                if os.path.isfile(file_path):
                    size = os.path.getsize(file_path)
                    print(f"  - {file} ({size / (1024**2):.2f} MB)")
        
        # Copy to our data directory
        target_dir = "/home/atomik/src/aptl/ctf_scenarios/gaming/behavioural_analysis/data/pro_players"
        os.makedirs(target_dir, exist_ok=True)
        
        import shutil
        for file in os.listdir(path):
            src = os.path.join(path, file)
            dst = os.path.join(target_dir, file)
            if os.path.isfile(src):
                shutil.copy2(src, dst)
                print(f"Copied {file} to {target_dir}")
        
        return target_dir
        
    except Exception as e:
        print(f"Error downloading dataset: {e}")
        sys.exit(1)

if __name__ == "__main__":
    dataset_path = download_pro_players_dataset()
    print(f"\nDataset ready at: {dataset_path}")