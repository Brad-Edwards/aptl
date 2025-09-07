#!/usr/bin/env python3
"""
Generic descriptive statistics analysis for CSV datasets.
Usage: python3 analyze_csv_dataset.py <csv_file_path> <output_markdown_path> <dataset_name>
"""

import pandas as pd
import numpy as np
import sys
import os

def analyze_csv_dataset(csv_file_path, dataset_name="Dataset"):
    """Analyze any CSV dataset and generate comprehensive statistics"""
    
    if not os.path.exists(csv_file_path):
        raise FileNotFoundError(f"Dataset file not found: {csv_file_path}")
    
    # Load data
    df = pd.read_csv(csv_file_path)
    
    # Prepare output
    output_lines = []
    output_lines.append(f"# {dataset_name} Analysis\n")
    
    # Dataset Overview
    output_lines.append("## Dataset Overview")
    output_lines.append(f"- **Total Records**: {len(df):,}")
    output_lines.append(f"- **Total Columns**: {len(df.columns)}")
    output_lines.append(f"- **Memory Usage**: {df.memory_usage(deep=True).sum() / (1024**2):.2f} MB")
    output_lines.append(f"- **Data Types**: {df.dtypes.value_counts().to_dict()}\n")
    
    # Column Information
    output_lines.append("## Columns")
    for i, col in enumerate(df.columns, 1):
        output_lines.append(f"{i}. **{col}**: {df[col].dtype}")
    output_lines.append("")
    
    # Basic Statistics for Numeric Columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    
    if len(numeric_cols) > 0:
        output_lines.append("## Numeric Column Statistics\n")
        
        # Summary table
        output_lines.append("### Summary Statistics\n")
        output_lines.append("| Column | Count | Mean | Std | Min | 25% | 50% | 75% | Max |")
        output_lines.append("|--------|--------|------|-----|-----|-----|-----|-----|-----|")
        
        for col in numeric_cols:
            stats = df[col].describe()
            output_lines.append(f"| {col} | {stats['count']:.0f} | {stats['mean']:.3f} | {stats['std']:.3f} | {stats['min']:.3f} | {stats['25%']:.3f} | {stats['50%']:.3f} | {stats['75%']:.3f} | {stats['max']:.3f} |")
        
        output_lines.append("")
        
        # Missing values
        missing_counts = df[numeric_cols].isnull().sum()
        missing_counts = missing_counts[missing_counts > 0]
        
        if len(missing_counts) > 0:
            output_lines.append("### Missing Values\n")
            for col, count in missing_counts.items():
                pct = (count / len(df)) * 100
                output_lines.append(f"- **{col}**: {count:,} missing ({pct:.2f}%)")
            output_lines.append("")
    
    # Text/Categorical Columns
    text_cols = df.select_dtypes(include=['object', 'string']).columns
    
    if len(text_cols) > 0:
        output_lines.append("## Categorical Column Analysis\n")
        
        for col in text_cols:
            unique_count = df[col].nunique()
            total_count = len(df[col])
            missing_count = df[col].isnull().sum()
            
            output_lines.append(f"### {col}")
            output_lines.append(f"- **Unique Values**: {unique_count:,}")
            output_lines.append(f"- **Missing Values**: {missing_count:,} ({(missing_count/total_count)*100:.2f}%)")
            
            # Show top values if reasonable number
            if unique_count <= 20 and unique_count > 0:
                value_counts = df[col].value_counts().head(10)
                output_lines.append("- **Top Values**:")
                for value, count in value_counts.items():
                    pct = (count / total_count) * 100
                    output_lines.append(f"  - {value}: {count:,} ({pct:.1f}%)")
            elif unique_count > 20:
                output_lines.append(f"- **Sample Values**: {list(df[col].dropna().unique()[:10])}")
            
            output_lines.append("")
    
    # Key Performance Metrics (if this looks like gaming data)
    gaming_indicators = ['kills', 'deaths', 'headshot', 'rating', 'damage', 'rounds']
    gaming_cols = [col for col in df.columns if any(indicator in col.lower() for indicator in gaming_indicators)]
    
    if len(gaming_cols) > 0:
        output_lines.append("## Gaming Performance Metrics\n")
        
        for col in gaming_cols[:10]:  # Limit to first 10 gaming-related columns
            if col in numeric_cols:
                values = df[col].dropna()
                if len(values) > 0:
                    output_lines.append(f"### {col}")
                    output_lines.append(f"- **Range**: {values.min():.3f} to {values.max():.3f}")
                    output_lines.append(f"- **Mean ± Std**: {values.mean():.3f} ± {values.std():.3f}")
                    output_lines.append(f"- **Percentiles**: P10={values.quantile(0.1):.3f}, P90={values.quantile(0.9):.3f}, P99={values.quantile(0.99):.3f}")
                    
                    # Identify potential outliers
                    q1 = values.quantile(0.25)
                    q3 = values.quantile(0.75)
                    iqr = q3 - q1
                    outlier_threshold_low = q1 - 1.5 * iqr
                    outlier_threshold_high = q3 + 1.5 * iqr
                    outliers = values[(values < outlier_threshold_low) | (values > outlier_threshold_high)]
                    
                    if len(outliers) > 0:
                        output_lines.append(f"- **Potential Outliers**: {len(outliers)} values outside [{outlier_threshold_low:.3f}, {outlier_threshold_high:.3f}]")
                    
                    output_lines.append("")
    
    # Correlations for numeric data
    if len(numeric_cols) > 1:
        output_lines.append("## Correlation Analysis\n")
        
        corr_matrix = df[numeric_cols].corr()
        
        # Find highest correlations (excluding self-correlations)
        corr_pairs = []
        for i in range(len(corr_matrix.columns)):
            for j in range(i+1, len(corr_matrix.columns)):
                col1 = corr_matrix.columns[i]
                col2 = corr_matrix.columns[j]
                corr_val = corr_matrix.iloc[i, j]
                if not pd.isna(corr_val):
                    corr_pairs.append((abs(corr_val), col1, col2, corr_val))
        
        # Sort by absolute correlation value
        corr_pairs.sort(reverse=True)
        
        output_lines.append("### Strongest Correlations\n")
        for abs_corr, col1, col2, corr_val in corr_pairs[:10]:  # Top 10 correlations
            direction = "positive" if corr_val > 0 else "negative"
            output_lines.append(f"- **{col1}** ↔ **{col2}**: {corr_val:.3f} ({direction})")
        
        output_lines.append("")
    
    # Data Quality Assessment
    output_lines.append("## Data Quality Assessment\n")
    
    total_cells = len(df) * len(df.columns)
    total_missing = df.isnull().sum().sum()
    completeness = ((total_cells - total_missing) / total_cells) * 100
    
    output_lines.append(f"- **Data Completeness**: {completeness:.2f}% ({total_missing:,} missing values out of {total_cells:,} total)")
    
    # Check for duplicates
    duplicate_rows = df.duplicated().sum()
    output_lines.append(f"- **Duplicate Rows**: {duplicate_rows:,} ({(duplicate_rows/len(df))*100:.2f}%)")
    
    # Check for potential data issues
    if len(numeric_cols) > 0:
        negative_values = {}
        zero_values = {}
        
        for col in numeric_cols:
            neg_count = (df[col] < 0).sum()
            zero_count = (df[col] == 0).sum()
            
            if neg_count > 0:
                negative_values[col] = neg_count
            if zero_count > 0:
                zero_values[col] = zero_count
        
        if negative_values:
            output_lines.append("- **Negative Values Found**:")
            for col, count in negative_values.items():
                output_lines.append(f"  - {col}: {count:,} negative values")
        
        if zero_values:
            output_lines.append("- **Zero Values**:")
            for col, count in list(zero_values.items())[:5]:  # Show first 5
                pct = (count / len(df)) * 100
                output_lines.append(f"  - {col}: {count:,} zeros ({pct:.1f}%)")
    
    output_lines.append("")
    
    # Sample Data
    output_lines.append("## Sample Data\n")
    output_lines.append("First 3 rows:\n")
    output_lines.append("```")
    output_lines.append(df.head(3).to_string())
    output_lines.append("```")
    
    return "\n".join(output_lines)

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 analyze_csv_dataset.py <csv_file_path> <output_markdown_path> <dataset_name>")
        print("Example: python3 analyze_csv_dataset.py data/players.csv players_analysis.md 'Professional Players'")
        sys.exit(1)
    
    csv_file_path = sys.argv[1]
    output_file_path = sys.argv[2] 
    dataset_name = sys.argv[3]
    
    print(f"Analyzing {dataset_name} dataset...")
    
    try:
        analysis_content = analyze_csv_dataset(csv_file_path, dataset_name)
        
        with open(output_file_path, 'w') as f:
            f.write(analysis_content)
        
        print(f"Analysis complete. Results saved to: {output_file_path}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()