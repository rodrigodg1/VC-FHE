#!/usr/bin/env python3
"""
Threshold Decryption Overhead Visualization Script

Analyzes and visualizes threshold decryption metrics from experiment_results.csv,
focusing on the impact of network delay on overhead components.

Generates plots in threshold_plots/ directory:
1. Network delay vs share collection time (linearity verification)
2. Overhead breakdown by delay value
3. Total overhead across dataset sizes and delays
4. Reconstruction time consistency check
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path

# Configuration
CSV_FILE = "experiment_results.csv"
OUTPUT_DIR = Path("threshold_plots")
OUTPUT_DIR.mkdir(exist_ok=True)

# Plot styling
sns.set_style("whitegrid")
sns.set_palette("husl")
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 11

def load_data():
    """Load and filter threshold-enabled experiments."""
    print(f"📊 Loading data from {CSV_FILE}...")
    df = pd.read_csv(CSV_FILE)
    
    # Filter for threshold-enabled runs only
    # Handle both boolean True and string 'true'/'True'
    if df['threshold_enabled'].dtype == 'object':
        # CSV has string values like 'true'/'false'
        df_threshold = df[df['threshold_enabled'].str.lower() == 'true'].copy()
    else:
        # CSV has actual boolean values
        df_threshold = df[df['threshold_enabled'] == True].copy()
    
    print(f"   Total rows: {len(df)}")
    print(f"   Threshold-enabled rows: {len(df_threshold)}")
    
    if len(df_threshold) > 0:
        print(f"   Network delays tested: {sorted(df_threshold['threshold_network_delay_ms'].unique())}")
        print(f"   Dataset sizes tested: {sorted(df_threshold['dataset_size'].unique())}")
    
    return df_threshold

def plot_delay_vs_collection_time(df):
    """
    Plot 1: Network Delay vs Share Collection Time
    
    Verifies linearity: collection time = t × delay per share
    Expected: should be approximately linear with slope = threshold_t
    """
    print("\n📈 Generating Plot 1: Network Delay vs Share Collection Time...")
    
    # Group by delay and calculate mean collection time
    delay_stats = df.groupby('threshold_network_delay_ms').agg({
        'threshold_share_collection_ms': ['mean', 'std'],
        'threshold_t': 'first'
    }).reset_index()
    
    delay_stats.columns = ['delay_ms', 'collection_mean', 'collection_std', 'threshold_t']
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Plot actual measurements
    ax.errorbar(delay_stats['delay_ms'], delay_stats['collection_mean'],
                yerr=delay_stats['collection_std'], 
                fmt='o-', linewidth=2, markersize=8, capsize=5,
                label='Measured Collection Time')
    
    # Plot theoretical line (t × delay)
    t_value = delay_stats['threshold_t'].iloc[0]
    theoretical = delay_stats['delay_ms'] * t_value
    ax.plot(delay_stats['delay_ms'], theoretical, 
            '--', linewidth=2, alpha=0.7, color='red',
            label=f'Theoretical (t={t_value} × delay)')
    
    ax.set_xlabel('Network Delay per Share (ms)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Share Collection Time (ms)', fontsize=12, fontweight='bold')
    ax.set_title('Network Delay vs Share Collection Time\n(Linearity Verification)', 
                 fontsize=14, fontweight='bold')
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    
    # Add annotations
    for _, row in delay_stats.iterrows():
        ax.annotate(f"{row['collection_mean']:.1f}ms", 
                   xy=(row['delay_ms'], row['collection_mean']),
                   xytext=(5, 5), textcoords='offset points',
                   fontsize=9, alpha=0.7)
    
    plt.tight_layout()
    output_path = OUTPUT_DIR / "01_delay_vs_collection_time.pdf"
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"   ✅ Saved: {output_path}")
    plt.close()

def plot_overhead_breakdown(df):
    """
    Plot 2: Overhead Component Breakdown by Network Delay
    
    Stacked bar chart showing:
    - Share generation time (one-time setup cost)
    - Share collection time (network overhead)
    - Reconstruction time (computational overhead)
    """
    print("\n📈 Generating Plot 2: Overhead Breakdown by Network Delay...")
    
    # Group by delay and calculate mean for each component
    breakdown = df.groupby('threshold_network_delay_ms').agg({
        'threshold_share_generation_ms': 'mean',
        'threshold_share_collection_ms': 'mean',
        'threshold_reconstruction_ms': 'mean'
    }).reset_index()
    
    fig, ax = plt.subplots(figsize=(10, 7))
    
    x = np.arange(len(breakdown))
    width = 0.6
    
    # Stacked bars
    p1 = ax.bar(x, breakdown['threshold_share_generation_ms'], width,
                label='Share Generation (Setup)', color='#3498db')
    p2 = ax.bar(x, breakdown['threshold_share_collection_ms'], width,
                bottom=breakdown['threshold_share_generation_ms'],
                label='Share Collection (Network)', color='#e74c3c')
    p3 = ax.bar(x, breakdown['threshold_reconstruction_ms'], width,
                bottom=breakdown['threshold_share_generation_ms'] + 
                       breakdown['threshold_share_collection_ms'],
                label='Reconstruction (Computation)', color='#2ecc71')
    
    ax.set_xlabel('Network Delay per Share (ms)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Time (ms)', fontsize=12, fontweight='bold')
    ax.set_title('Threshold Overhead Component Breakdown\n(Mean Across All Experiments)', 
                 fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(breakdown['threshold_network_delay_ms'].astype(int))
    ax.legend(fontsize=11, loc='upper left')
    ax.grid(True, alpha=0.3, axis='y')
    
    # Add total annotations on top of bars
    for i, (idx, row) in enumerate(breakdown.iterrows()):
        total = (row['threshold_share_generation_ms'] + 
                row['threshold_share_collection_ms'] + 
                row['threshold_reconstruction_ms'])
        ax.text(i, total + 5, f'{total:.1f}ms', 
               ha='center', va='bottom', fontweight='bold', fontsize=10)
    
    plt.tight_layout()
    output_path = OUTPUT_DIR / "02_overhead_breakdown.pdf"
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"   ✅ Saved: {output_path}")
    plt.close()


def plot_computational_overhead_detail(df):
    """
    Plot 5: Computational Overhead Detail (Separate Scale)
    
    Creates two separate plots:
    - Plot 5a: Share Generation Time (using _us column)
    - Plot 5b: Reconstruction + Decryption Time (combined)
    """
    print("\n📈 Generating Plot 5: Computational Overhead Detail...")
    
    # Group by delay and calculate mean for computational components
    # Note: threshold_share_generation_us is already in microseconds!
    breakdown = df.groupby('threshold_network_delay_ms').agg({
        'threshold_share_generation_us': 'mean',  # Already in microseconds
        'threshold_reconstruction_ms': 'mean',
        'threshold_decryption_ms': 'mean'
    }).reset_index()
    
    x = np.arange(len(breakdown))
    delays = breakdown['threshold_network_delay_ms'].astype(int).tolist()
    
    # --- Plot 5a: Share Generation Time ---
    fig1, ax1 = plt.subplots(figsize=(8, 5))
    
    values_gen = breakdown['threshold_share_generation_us']  # Already in μs
    bars1 = ax1.bar(x, values_gen, color='#3498db', width=0.5)
    ax1.set_xlabel('Network Delay per Share (ms)', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Time (μs)', fontsize=12, fontweight='bold')
    ax1.set_title('Share Generation Time\n(Polynomial Evaluation for Secret Sharing)', fontsize=13, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(delays)
    ax1.grid(True, alpha=0.3, axis='y')
    
    # Add value labels
    for i, v in enumerate(values_gen):
        ax1.text(i, v + 0.5, f'{v:.1f}μs', ha='center', va='bottom', fontsize=11, fontweight='bold')
    
    plt.tight_layout()
    output_path_a = OUTPUT_DIR / "05a_share_generation.pdf"
    plt.savefig(output_path_a, dpi=300, bbox_inches='tight')
    print(f"   ✅ Saved: {output_path_a}")
    plt.close()
    
    # --- Plot 5b: Reconstruction + Decryption Time (Combined) ---
    fig2, ax2 = plt.subplots(figsize=(10, 5))
    
    width = 0.35
    values_recon = breakdown['threshold_reconstruction_ms'] * 1000  # Convert to μs
    values_decrypt = breakdown['threshold_decryption_ms'] * 1000  # Convert to μs
    
    bars_recon = ax2.bar(x - width/2, values_recon, width, 
                         label='Reconstruction (Lagrange Interpolation)', color='#2ecc71')
    bars_decrypt = ax2.bar(x + width/2, values_decrypt, width,
                           label='Decryption (Final Result)', color='#9b59b6')
    
    ax2.set_xlabel('Network Delay per Share (ms)', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Time (μs)', fontsize=12, fontweight='bold')
    ax2.set_title('Reconstruction and Decryption Time\n(Computational Overhead)', fontsize=13, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(delays)
    ax2.legend(fontsize=11)
    ax2.grid(True, alpha=0.3, axis='y')
    
    # Add value labels
    for i, v in enumerate(values_recon):
        ax2.text(i - width/2, v + 0.5, f'{v:.1f}μs', ha='center', va='bottom', fontsize=10)
    for i, v in enumerate(values_decrypt):
        ax2.text(i + width/2, v + 0.5, f'{v:.1f}μs', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    output_path_b = OUTPUT_DIR / "05b_reconstruction_decryption.pdf"
    plt.savefig(output_path_b, dpi=300, bbox_inches='tight')
    print(f"   ✅ Saved: {output_path_b}")
    plt.close()

def plot_delay_and_size_heatmap(df):
    """
    Plot 3: Total Overhead Heatmap (Delay × Dataset Size)
    
    Shows how total threshold overhead varies with both:
    - Network delay (x-axis)
    - Dataset size (y-axis)
    """
    print("\n📈 Generating Plot 3: Delay × Size Heatmap...")
    
    # Pivot table for heatmap
    pivot = df.pivot_table(
        values='threshold_total_overhead_ms',
        index='dataset_size',
        columns='threshold_network_delay_ms',
        aggfunc='mean'
    )
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    sns.heatmap(pivot, annot=True, fmt='.1f', cmap='YlOrRd', 
                cbar_kws={'label': 'Total Overhead (ms)'},
                linewidths=0.5, ax=ax)
    
    ax.set_xlabel('Network Delay per Share (ms)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Dataset Size (N)', fontsize=12, fontweight='bold')
    ax.set_title('Total Threshold Overhead: Network Delay × Dataset Size\n(Mean Overhead in ms)', 
                 fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    output_path = OUTPUT_DIR / "03_delay_size_heatmap.pdf"
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"   ✅ Saved: {output_path}")
    plt.close()

def plot_reconstruction_consistency(df):
    """
    Plot 4: Reconstruction Time Consistency Check
    
    Verifies that reconstruction time is:
    - Independent of network delay
    - Independent of dataset size
    - Consistent around O(t²) complexity
    """
    print("\n📈 Generating Plot 4: Reconstruction Time Consistency...")
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    
    # Subplot 1: Reconstruction time vs Network Delay
    delay_recon = df.groupby('threshold_network_delay_ms').agg({
        'threshold_reconstruction_ms': ['mean', 'std']
    }).reset_index()
    delay_recon.columns = ['delay_ms', 'recon_mean', 'recon_std']
    
    ax1.errorbar(delay_recon['delay_ms'], delay_recon['recon_mean'],
                 yerr=delay_recon['recon_std'], 
                 fmt='o-', linewidth=2, markersize=8, capsize=5,
                 color='#9b59b6')
    ax1.axhline(y=delay_recon['recon_mean'].mean(), color='red', 
                linestyle='--', alpha=0.7, linewidth=2,
                label=f"Mean: {delay_recon['recon_mean'].mean():.2f}ms")
    ax1.set_xlabel('Network Delay (ms)', fontsize=11, fontweight='bold')
    ax1.set_ylabel('Reconstruction Time (ms)', fontsize=11, fontweight='bold')
    ax1.set_title('Reconstruction Time vs Network Delay\n(Should be Independent)', fontsize=12, fontweight='bold')
    ax1.legend(fontsize=10)
    ax1.grid(True, alpha=0.3)
    
    # Subplot 2: Reconstruction time vs Dataset Size
    size_recon = df.groupby('dataset_size').agg({
        'threshold_reconstruction_ms': ['mean', 'std']
    }).reset_index()
    size_recon.columns = ['size', 'recon_mean', 'recon_std']
    
    ax2.errorbar(size_recon['size'], size_recon['recon_mean'],
                 yerr=size_recon['recon_std'], 
                 fmt='o-', linewidth=2, markersize=8, capsize=5,
                 color='#e67e22')
    ax2.axhline(y=size_recon['recon_mean'].mean(), color='red', 
                linestyle='--', alpha=0.7, linewidth=2,
                label=f"Mean: {size_recon['recon_mean'].mean():.2f}ms")
    ax2.set_xlabel('Dataset Size (N)', fontsize=11, fontweight='bold')
    ax2.set_ylabel('Reconstruction Time (ms)', fontsize=11, fontweight='bold')
    ax2.set_title('Reconstruction Time vs Dataset Size\n(Should be Independent)', fontsize=12, fontweight='bold')
    ax2.legend(fontsize=10)
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    output_path = OUTPUT_DIR / "04_reconstruction_consistency.pdf"
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"   ✅ Saved: {output_path}")
    plt.close()

def generate_summary_statistics(df):
    """Generate and save summary statistics table."""
    print("\n📊 Generating Summary Statistics...")
    
    summary = df.groupby('threshold_network_delay_ms').agg({
        'threshold_share_generation_ms': ['mean', 'std'],
        'threshold_share_collection_ms': ['mean', 'std'],
        'threshold_reconstruction_ms': ['mean', 'std'],
        'threshold_total_overhead_ms': ['mean', 'std']
    }).round(2)
    
    summary_path = OUTPUT_DIR / "summary_statistics.csv"
    summary.to_csv(summary_path)
    print(f"   ✅ Saved: {summary_path}")
    
    print("\n" + "="*70)
    print("SUMMARY STATISTICS (by Network Delay)")
    print("="*70)
    print(summary)
    print("="*70)

def main():
    """Main execution function."""
    print("="*70)
    print("THRESHOLD DECRYPTION OVERHEAD VISUALIZATION")
    print("="*70)
    
    # Load data
    df = load_data()
    
    if len(df) == 0:
        print("\n❌ No threshold-enabled data found in CSV!")
        print("   Make sure to run simulation with --enable-threshold flag.")
        return
    
    # Generate all plots
    plot_delay_vs_collection_time(df)
    plot_overhead_breakdown(df)
    plot_computational_overhead_detail(df)
    plot_delay_and_size_heatmap(df)
    plot_reconstruction_consistency(df)
    
    # Generate summary statistics
    generate_summary_statistics(df)
    
    print("\n" + "="*70)
    print(f"✅ ALL PLOTS GENERATED SUCCESSFULLY")
    print(f"📁 Output directory: {OUTPUT_DIR.absolute()}")
    print("="*70)
    
    # List all generated files
    print("\nGenerated files:")
    for file in sorted(OUTPUT_DIR.glob("*")):
        print(f"   • {file.name}")

if __name__ == "__main__":
    main()
