import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
from matplotlib.patches import Patch

AGGREGATION_COLOR = '#3F5BF6'
AGGREGATION_HATCH_EDGE = '#DCE3FF'
VERIFICATION_GRAY = '#8C8C8C'
NEUTRAL_ERRORBAR = '#4D4D4D'

def remove_outliers_grouped(df, column, group_col='dataset_size'):
    """Removes outliers from a DataFrame based on IQR per group."""
    def filter_outliers(group):
        if group.empty: return group
        Q1 = group[column].quantile(0.25)
        Q3 = group[column].quantile(0.75)
        IQR = Q3 - Q1
        lower_bound = Q1 - 1.5 * IQR
        upper_bound = Q3 + 1.5 * IQR
        return group[(group[column] >= lower_bound) & (group[column] <= upper_bound)]
    
    return df.groupby(group_col, group_keys=False).apply(filter_outliers)

def add_labels_above_bars(ax, values, stds=None, fmt='{:.2f}', fontsize=18, pad_frac=0.02, top_margin_frac=0.04):
    """Place value labels above the error bars instead of on top of the bars."""
    if stds is None:
        stds = [0.0] * len(values)

    y_min, y_max = ax.get_ylim()
    pad = (y_max - y_min) * pad_frac if y_max > y_min else 0.05
    required_top = y_max

    for patch, value, std in zip(ax.patches, values, stds):
        if pd.isna(value):
            continue
        std = 0.0 if pd.isna(std) else float(std)
        x = patch.get_x() + patch.get_width() / 2.0
        y = float(value) + std + pad
        ax.text(x, y, fmt.format(value), ha='center', va='bottom', fontsize=fontsize)
        required_top = max(required_top, y + pad)

    required_top += (required_top - y_min) * top_margin_frac if required_top > y_min else top_margin_frac
    if required_top > y_max:
        ax.set_ylim(y_min, required_top)

def add_labels_above_grouped_bars(ax, stats, x_order, hue_order, fmt='{:.2f}', fontsize=18, pad_frac=0.02, top_margin_frac=0.04):
    """Place grouped-bar labels above their standard-deviation error bars."""
    y_min, y_max = ax.get_ylim()
    pad = (y_max - y_min) * pad_frac if y_max > y_min else 0.05
    required_top = y_max
    bar_containers = [container for container in ax.containers if hasattr(container, 'patches')]

    for container, hue_name in zip(bar_containers, hue_order):
        if hue_name not in stats.index.get_level_values(0):
            continue
        series = stats.loc[hue_name].reindex(x_order)
        for patch, (_, row) in zip(container.patches, series.iterrows()):
            value = row['mean']
            if pd.isna(value):
                continue
            std = 0.0 if pd.isna(row['std']) else float(row['std'])
            x = patch.get_x() + patch.get_width() / 2.0
            y = float(value) + std + pad
            ax.text(x, y, fmt.format(value), ha='center', va='bottom', fontsize=fontsize)
            required_top = max(required_top, y + pad)

    required_top += (required_top - y_min) * top_margin_frac if required_top > y_min else top_margin_frac
    if required_top > y_max:
        ax.set_ylim(y_min, required_top)

def style_bar_patches(patches, facecolor, edgecolor=None, hatch=None, linewidth=1.2):
    """Apply a consistent facecolor/hatch style to a sequence of bar patches."""
    edgecolor = edgecolor or facecolor
    for patch in patches:
        patch.set_facecolor(facecolor)
        patch.set_edgecolor(edgecolor)
        patch.set_linewidth(linewidth)
        if hatch:
            patch.set_hatch(hatch)

def style_errorbar_lines(ax, color=NEUTRAL_ERRORBAR, linewidth=1.5):
    """Standardize error-bar styling after seaborn barplot generation."""
    for line in ax.lines:
        line.set_color(color)
        line.set_linewidth(linewidth)

def build_custom_legend(ax, entries, fontsize=18, loc='upper left'):
    """Replace seaborn's auto legend with a custom legend."""
    handles = [
        Patch(
            facecolor=entry['facecolor'],
            edgecolor=entry.get('edgecolor', entry['facecolor']),
            hatch=entry.get('hatch', ''),
            linewidth=entry.get('linewidth', 1.2),
            label=entry['label'],
        )
        for entry in entries
    ]
    existing_legend = ax.get_legend()
    if existing_legend is not None:
        existing_legend.remove()
    ax.legend(handles=handles, title='', fontsize=fontsize, loc=loc)

def analyze_and_plot(csv_file='experiment_results.csv', output_dir='plots'):
    if not os.path.exists(csv_file):
        print(f"Error: {csv_file} not found.")
        return

    try:
        # Read columns directly from file header (CSV structure has evolved with threshold metrics)
        df = pd.read_csv(csv_file)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Use a professional, academic-standard palette
    # Use distinct colors and patterns for the comparison
    current_palette = "colorblind" 


    # Increase font size
    # Increase font size for all plots globally
    sns.set_theme(style="whitegrid") # Ensure style is consistent
    plt.rcParams.update({
        'font.family': 'serif',
        'font.size': 18,
        'axes.titlesize': 18,     # Title
        'axes.labelsize': 18,     # Axis Labels
        'xtick.labelsize': 18,    # Ticks
        'ytick.labelsize': 18,
        'legend.fontsize': 18,
        'figure.titlesize': 20,
        # 'axes.labelweight': 'bold', # Bold Axis Labels
        # 'axes.titleweight': 'bold', # Bold Titles
        # 'font.weight': 'bold',    # REMOVED to keep legends normal weight
    })

    # Convert ms to seconds
    ms_columns = [col for col in df.columns if col.endswith('_ms')]
    for col in ms_columns:
        df[col] = pd.to_numeric(df[col], errors='coerce') # Ensure numeric
        new_col = col.replace('_ms', '_s')
        df[new_col] = df[col] / 1000.0
    
    # Ensure other columns are numeric
    numeric_cols = ['verification_tx_s', 'gas_used', 'tx_size_bytes', 'aggregated_signature_size_bytes', 'dataset_size']
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    # Drop rows with NaN in critical columns (likely repeated headers or malformed lines)
    df.dropna(subset=['dataset_size'], inplace=True)

    # Tracking convention for this script:
    # 1. "df" always refers to the raw experiment_results.csv dataset after type coercion.
    # 2. Numeric summaries exported for the implementation are computed from raw "df".
    # 3. Some boxplots use outlier-filtered views only for visualization readability; those
    #    filtered subsets are not the source of the summary table values copied into the experiment.
    #    explicitly says so.

    
    # --- Plot 1: Setup and Encryption (Combined Subplots) ---
    # Tracking: diagnostic stage-1 figure saved to stage_1_plot_scalability_setup_encrypt.pdf.
    # outlier-filtered data used in this visualization.
    fig1, axes1 = plt.subplots(1, 2, figsize=(14, 6))
    
    # Remove outliers for Setup
    df_setup = remove_outliers_grouped(df, 'setup_s')
    # Plot as a single aggregated category
    sns.boxplot(y=df_setup['setup_s'], ax=axes1[0], color=sns.color_palette(current_palette)[0], width=0.4)
    axes1[0].set_title('Key Generation Latency\n(TFHE + LHS)')
    axes1[0].set_ylabel('Time (s)')
    # Set explicit x-axis label and tick for the single aggregated box
    axes1[0].set_xlabel('Experiment Configuration')
    axes1[0].set_xticks([]) # Remove tick marks to just show label, or use a descriptive tick if preferred.
    # Actually, user wants "legend of x-axis" fixed. Let's provide a generic label.
    axes1[0].set_xticks([0])
    axes1[0].set_xticklabels(['Independent of $N$'])
    axes1[0].grid(True, axis='y')
    
    # Encryption & Signing Time
    df_enc = remove_outliers_grouped(df, 'encrypt_sign_s')
    sns.boxplot(x='dataset_size', y='encrypt_sign_s', data=df_enc, ax=axes1[1], hue='dataset_size', palette=current_palette, legend=False)
    axes1[1].set_title('Data Encryption and LHS\nSignature Generation Latency')
    axes1[1].set_xlabel('Number of Rating Inputs ($N$)')
    axes1[1].set_ylabel('Time (s)')
    axes1[1].grid(True, axis='y')
    
    plt.tight_layout()
    output_path_1 = os.path.join(output_dir, 'stage_1_plot_scalability_setup_encrypt.pdf')
    plt.savefig(output_path_1)
    print(f"Saved Setup & Encryption plot to {output_path_1}")
    plt.close(fig1)

    # --- Plot 2: Aggregation ---
    # Tracking: diagnostic aggregation boxplot. Evaluation prose and results_summary.md use raw
    # group means/stds from df, while this figure uses an outlier-filtered copy for display.
    plt.figure(figsize=(8, 6))
    df_agg = remove_outliers_grouped(df, 'fhe_sign_aggregation_s')
    sns.boxplot(x='dataset_size', y='fhe_sign_aggregation_s', data=df_agg, hue='dataset_size', palette=current_palette, legend=False)
    plt.title('')
    plt.xlabel('Number of Rating Inputs ($N$)')
    plt.ylabel('Time (s)')
    plt.grid(True, axis='y')
    
    plt.tight_layout()
    output_path_2 = os.path.join(output_dir, 'stage_2_plot_scalability_aggregation.pdf')
    plt.savefig(output_path_2)
    print(f"Saved Aggregation plot to {output_path_2}")
    plt.close()

    # --- Plot 2b: Aggregation (Faceted Boxplots) ---
    # Tracking: auxiliary faceted version of the aggregation plot for inspection only.
    # Create a faceted plot where each dataset_size has its own subplot
    # Using sharex=False so each subplot has its own x-axis setup if needed, 
    # but here x-axis is just a single category per subplot so it's fine.
    # col_wrap controls how many columns before wrapping to next row.
    g = sns.catplot(
        data=df_agg, 
        x='dataset_size', 
        y='fhe_sign_aggregation_s', 
        col='dataset_size', 
        kind='box', 
        col_wrap=5, 
        height=4, 
        aspect=0.8, 
        sharex=False,
        sharey=False,
        palette=current_palette
    )
    
    # Adjust titles and labels
    g.set_titles("") # Remove title for each subplot as requested
    g.set_axis_labels("N", "Time (s)") # Set x-axis label to N
    
    # Add a global title
    g.fig.suptitle('', y=1.02)
    
    output_path_2_faceted = os.path.join(output_dir, 'stage_2_plot_scalability_aggregation_faceted.pdf')
    g.savefig(output_path_2_faceted)
    print(f"Saved Aggregation Faceted plot to {output_path_2_faceted}")
    plt.close(g.fig)

    # Division Plot Removed


    # --- Plot 4: On-Chain Verification Time ---
    # Tracking: diagnostic verification boxplot. Evaluation text uses the raw per-N means/stds
    # computed later in the script and in results_summary.md.
    plt.figure(figsize=(8, 6))
    df_ver = remove_outliers_grouped(df, 'verification_tx_s')
    sns.boxplot(x='dataset_size', y='verification_tx_s', data=df_ver, hue='dataset_size', palette=current_palette, legend=False)
    plt.title('On-Chain Verification Latency')
    plt.xlabel('Number of Rating Inputs ($N$)')
    plt.ylabel('Time (s)')
    plt.grid(True, axis='y')
    
    plt.tight_layout()
    output_path_4 = os.path.join(output_dir, 'stage_4_plot_scalability_verification.pdf')
    plt.savefig(output_path_4)
    print(f"Saved On-Chain Verification plot to {output_path_4}")
    plt.close()

    # --- Plot 5: Transaction Size vs On-Chain Verification Time ---
    # Tracking: diagnostic correlation analysis between calldata size and verification latency.
    # This is not directly copied into the current evaluation tables, but it is used to sanity-check
    # the O(1) verification claim when tx_size_bytes varies slightly across runs.
    if 'tx_size_bytes' in df.columns:
        plt.figure(figsize=(10, 6))
        
        # Calculate Correlation
        corr = df['tx_size_bytes'].corr(df['verification_tx_s'])
        
        # Scatter plot by dataset size
        sns.scatterplot(x='tx_size_bytes', y='verification_tx_s', data=df, hue='dataset_size', palette=current_palette, s=100)
        
        # Add a global linear regression line (Trend)
        # scatter=False prevents duplicating the points, color='black' makes it distinct
        sns.regplot(x='tx_size_bytes', y='verification_tx_s', data=df, scatter=False, color='black', line_kws={"linestyle": "--", "alpha": 0.7})

        plt.title(f'On-Chain Verification Latency vs. Transaction Size\n(Correlation r = {corr:.4f})')
        plt.xlabel('Transaction Size (Bytes)')
        plt.ylabel('Verification Time (s)')
        plt.grid(True)
        
        plt.tight_layout()
        output_path_tx = os.path.join(output_dir, 'plot_tx_size_vs_verification.pdf')
        plt.savefig(output_path_tx)
        print(f"Saved Tx Size vs Verification plot to {output_path_tx}")
        plt.close()

    # --- Plot 5b: Box Plot of Verification Time vs Tx Size (Grouped by N) ---
    # Tracking: secondary diagnostic plot to expose the small tx-size variation per dataset_size.
    # User requested grouping by dataset size but KEEPING transaction size visible
    if 'tx_size_bytes' in df.columns:
        plt.figure(figsize=(10, 6))
        
        # 1. Calculate mean size per group (rounding to nearest byte)
        # This handles the slight variance (630 vs 633) by picking the representative size
        size_map = df.groupby('dataset_size')['tx_size_bytes'].mean().round(0).astype(int)
        
        # 2. Create a new label column: "~632 Bytes (N=10)"
        def get_label(row):
            n = row['dataset_size']
            bytes_val = size_map.get(n, 0)
            return f"~{bytes_val} Bytes\n(N={n})"
            
        df['Tx Group Label'] = df.apply(get_label, axis=1)
        
        # 3. Determine clearer order for the x-axis
        unique_sizes = sorted(df['dataset_size'].unique())
        order_labels = [f"~{size_map[n]} Bytes\n(N={n})" for n in unique_sizes]

        sns.boxplot(x='Tx Group Label', y='verification_tx_s', data=df, order=order_labels, hue='dataset_size', palette=current_palette, legend=False)
        
        plt.title('')
        plt.xlabel('Transaction Size Group (Bytes)')
        plt.ylabel('Verification Time (s)')
        plt.grid(True, axis='y')
        
        plt.tight_layout()
        output_path_tx_box = os.path.join(output_dir, 'plot_tx_size_vs_verification_box.pdf')
        plt.savefig(output_path_tx_box)
        print(f"Saved Tx Size vs Verification Box plot to {output_path_tx_box}")
        plt.close()
    else:
        print("Skipping Transaction Size plot (column not found in CSV)")

    # --- Plot 6: Combined Stage Execution Time (Total without Division) ---
    # Tracking: overview figure combining setup, encryption/signing, and aggregation means.
    # Useful for internal sanity checks; not directly referenced by the current evaluation text.
    # Calculate averages per dataset size
    avg_df = df.select_dtypes(include='number').groupby('dataset_size', as_index=False).mean()
    
    # Calculate Total Time (Setup + Enc + Aggregation)
    avg_df['Total Execution'] = avg_df['setup_s'] + avg_df['encrypt_sign_s'] + avg_df['fhe_sign_aggregation_s']
    
    plt.figure(figsize=(10, 6))
    
    # Plot individual stages
    sns.lineplot(x='dataset_size', y='setup_s', data=avg_df, marker='o', label='Setup (KeyGen)')
    sns.lineplot(x='dataset_size', y='encrypt_sign_s', data=avg_df, marker='o', label='Encryption & Signing')
    sns.lineplot(x='dataset_size', y='fhe_sign_aggregation_s', data=avg_df, marker='o', label='Aggregation')
    
    # Plot Total
    sns.lineplot(x='dataset_size', y='Total Execution', data=avg_df, marker='s', linewidth=2.5, label='Total Execution (No Division)')

    plt.title('Comparasion of Execution Time Across Stages')
    plt.xlabel('Number of Rating Inputs ($N$)')
    plt.ylabel('Avg. Time (s)')
    plt.grid(True)
    plt.legend()
    
    plt.tight_layout()
    output_path_combined = os.path.join(output_dir, 'plot_combined_execution_time.pdf')
    plt.savefig(output_path_combined)
    print(f"Saved Combined Execution plot to {output_path_combined}")
    plt.close()

    # --- Plot 7: Combined Boxplot for All Stages (excluding Division) ---
    # Tracking: distribution-level overview across stages. This is diagnostic and not used as the
    # source for any implementation table values.
    # Melt the dataframe to long format for easier plotting with hue
    df_long = pd.melt(df, 
                      id_vars=['dataset_size'], 
                      value_vars=['setup_s', 'encrypt_sign_s', 'fhe_sign_aggregation_s', 'verification_tx_s'],
                      var_name='Stage', 
                      value_name='Time (s)')
    
    # Rename stages for better readability
    stage_mapping = {
        'setup_s': 'Setup',
        'encrypt_sign_s': 'Encrypt & Sign',
        'fhe_sign_aggregation_s': 'Aggregation',
        'verification_tx_s': 'On-Chain Verif.'
    }
    df_long['Stage'] = df_long['Stage'].map(stage_mapping)

    # Remove outliers for the combined plot (grouped by Stage AND dataset_size)
    def remove_outliers_combined(group):
        Q1 = group['Time (s)'].quantile(0.25)
        Q3 = group['Time (s)'].quantile(0.75)
        IQR = Q3 - Q1
        lower_bound = Q1 - 1.5 * IQR
        upper_bound = Q3 + 1.5 * IQR
        return group[(group['Time (s)'] >= lower_bound) & (group['Time (s)'] <= upper_bound)]

    df_long_clean = df_long.groupby(['dataset_size', 'Stage'], group_keys=False).apply(remove_outliers_combined)

    plt.figure(figsize=(12, 8))
    sns.boxplot(x='dataset_size', y='Time (s)', hue='Stage', data=df_long_clean, palette=current_palette)
    
    plt.title('Execution Time Distribution by Stage')
    plt.xlabel('Number of Rating Inputs ($N$)')
    plt.ylabel('Time (s)')
    plt.grid(True, axis='y')
    plt.legend(title='Stage')
    
    plt.tight_layout()
    output_path_combined_box = os.path.join(output_dir, 'plot_combined_stages_boxplot.pdf')
    plt.savefig(output_path_combined_box)
    print(f"Saved Combined Stages Boxplot to {output_path_combined_box}")
    plt.close()

    # --- Plot 4: Gas Cost Dashboard (2x2) ---
    # Tracking: gas dashboard for exploratory analysis. The implementation gas table uses the raw
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    
    df_gas = remove_outliers_grouped(df, 'gas_used')
    
    # Constants for Cost Estimation
    GAS_PRICE_GWEI = 30
    ETH_PRICE_USD = 3000
    CONVERSION_FACTOR = GAS_PRICE_GWEI * 1e-9 * ETH_PRICE_USD

    # 1. Top-Left: Linear Trend (Line Plot)
    # Shows the O(N) relationship clearly
    sns.lineplot(x='dataset_size', y='gas_used', data=df, ax=axes[0, 0], marker='o', color=sns.color_palette(current_palette)[0], linewidth=2.5)
    axes[0, 0].set_title('Gas Usage Trend (Linear Scaling)')
    axes[0, 0].set_xlabel('Number of Ratings (N)')
    axes[0, 0].set_ylabel('Gas Used')
    axes[0, 0].grid(True)
    
    # 2. Top-Right: Estimated Cost in USD (Bar Chart)
    # Clear economic view without mixing units
    df_mean_gas = df.groupby('dataset_size')['gas_used'].mean().reset_index()
    df_mean_gas['usd_cost'] = df_mean_gas['gas_used'] * CONVERSION_FACTOR
    
    bars = sns.barplot(x='dataset_size', y='usd_cost', data=df_mean_gas, ax=axes[0, 1], palette=current_palette)
    axes[0, 1].set_title(f'Estimated Transaction Cost (USD)\n@ {GAS_PRICE_GWEI} Gwei, ${ETH_PRICE_USD}/ETH')
    axes[0, 1].set_xlabel('Number of Ratings (N)')
    axes[0, 1].set_ylabel('Cost (USD)')
    axes[0, 1].grid(True, axis='y')
    
    # Add value labels on bars
    for container in bars.containers:
        bars.bar_label(container, fmt='$%.2f', padding=3)

    # 3. Bottom-Left: Distribution (Box Plot)
    # Shows stability/variance of gas usage
    sns.boxplot(x='dataset_size', y='gas_used', data=df_gas, hue='dataset_size', palette="Set3", ax=axes[1, 0], legend=False)
    axes[1, 0].set_title('Gas Usage Distribution')
    axes[1, 0].set_xlabel('Number of Ratings (N)')
    axes[1, 0].set_ylabel('Gas Used')
    axes[1, 0].grid(True, axis='y')
    
    # 4. Bottom-Right: Marginal Gas Cost per Item (Derived)
    # Calculates (Gas / N) to show efficiency
    # Note: This includes fixed base cost, so it typically decays towards the marginal cost
    df_gas_per_item = df.copy()
    df_gas_per_item['gas_per_item'] = df_gas_per_item['gas_used'] / df_gas_per_item['dataset_size']
    
    sns.lineplot(x='dataset_size', y='gas_per_item', data=df_gas_per_item, ax=axes[1, 1], marker='s', color=sns.color_palette(current_palette)[1], linewidth=2.5)
    axes[1, 1].set_title('Amortized Gas Cost per Item')
    axes[1, 1].set_xlabel('Number of Ratings (N)')
    axes[1, 1].set_ylabel('Gas / Item')
    axes[1, 1].grid(True)
    
    # Add a reference line for the marginal cost (~960) if desired, or just let the trend show it
    # axes[1, 1].axhline(y=960, color='r', linestyle='--', label='Approx. Marginal Cost (~960)')
    # axes[1, 1].legend()

    plt.tight_layout()
    output_path_dashboard = os.path.join(output_dir, 'plot_gas_cost_dashboard.pdf')
    plt.savefig(output_path_dashboard)
    print(f"Saved Gas Cost Dashboard to {output_path_dashboard}")
    plt.close()

    # --- Plot 4b: Stacked Bar Chart (Aggregation vs Verification) ---
    # Tracking: diagnostic stacked view showing that aggregation dominates verification.
    # This view shows: off-chain calculation depends on data while verification time varies very short
    plt.figure(figsize=(10, 6))
    
    # Calculate means for the stacked chart
    stacked_df = df.groupby('dataset_size')[['fhe_sign_aggregation_s', 'verification_tx_s']].mean().reset_index()
    
    # Create bottom bars (Aggregation)
    p1 = plt.bar(stacked_df['dataset_size'].astype(str), stacked_df['fhe_sign_aggregation_s'], label='Off-Chain Aggregation', color=sns.color_palette(current_palette)[0], width=0.5)
    
    # Create top bars (Verification), stacked on top of Aggregation
    # Note: We stack verification on top, or side-by-side. 
    # User requested stacked: "stacked bar chart with stage 2 and stage 4"
    p2 = plt.bar(stacked_df['dataset_size'].astype(str), stacked_df['verification_tx_s'], bottom=stacked_df['fhe_sign_aggregation_s'], label='On-Chain Verification', color=sns.color_palette(current_palette)[1], width=0.5)
    
    plt.title('Comparison: Off-Chain Aggregation vs On-Chain Verification')
    plt.xlabel('Number of Rating Inputs ($N$)')
    plt.ylabel('Time (s)')
    plt.legend()
    plt.grid(True, axis='y')
    
    plt.tight_layout()
    output_path_stacked = os.path.join(output_dir, 'plot_stacked_aggregation_verification.pdf')
    plt.savefig(output_path_stacked)
    print(f"Saved Stacked Aggregation vs Verification plot to {output_path_stacked}")
    plt.close()

    # --- Plot 4c: Box Plot Comparison (Aggregation vs Verification) ---
    # Tracking: diagnostic distribution comparison between stage 2 and stage 4.
    plt.figure(figsize=(10, 6))
    
    # Prepare data for box plot
    df_box_compare = pd.melt(df, 
                             id_vars=['dataset_size'], 
                             value_vars=['fhe_sign_aggregation_s', 'verification_tx_s'],
                             var_name='Type', 
                             value_name='Time (s)')
    
    # Rename for legend
    type_mapping = {
        'fhe_sign_aggregation_s': 'Off-Chain Aggregation',
        'verification_tx_s': 'On-Chain Verification'
    }
    df_box_compare['Type'] = df_box_compare['Type'].map(type_mapping)
    
    sns.boxplot(x='dataset_size', y='Time (s)', hue='Type', data=df_box_compare, palette=current_palette)
    
    plt.title('Performance Comparison: Off-Chain vs On-Chain')
    plt.xlabel('Number of Rating Inputs ($N$)')
    plt.ylabel('Time (s)')
    plt.grid(True, axis='y')
    plt.legend(title='Operation Type')
    
    plt.tight_layout()
    output_path_box_compare = os.path.join(output_dir, 'plot_boxplot_aggregation_vs_verification.pdf')
    plt.savefig(output_path_box_compare)
    print(f"Saved Box Plot Comparison to {output_path_box_compare}")
    plt.close()

    # --- Plot 4d: Comparison Dashboard (2x2) ---
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    
    # Data Prep
    df_mean = df.groupby('dataset_size')[['fhe_sign_aggregation_s', 'verification_tx_s']].mean().reset_index()
    type_map = {'fhe_sign_aggregation_s': 'Aggregation', 'verification_tx_s': 'Verification'}
    
    # 1. Grouped Bar
    df_melt_mean = pd.melt(df_mean, id_vars=['dataset_size'], var_name='Type', value_name='Time (s)')
    df_melt_mean['Type'] = df_melt_mean['Type'].map(type_map)
    sns.barplot(x='dataset_size', y='Time (s)', hue='Type', data=df_melt_mean, ax=axes[0, 0], palette=current_palette)
    axes[0, 0].set_title('Average Execution Time (Grouped)')
    axes[0, 0].set_xlabel('N')
    axes[0, 0].grid(True, axis='y')
    
    # 2. Line Plot
    sns.lineplot(x='dataset_size', y='fhe_sign_aggregation_s', data=df, ax=axes[0, 1], marker='o', label='Aggregation')
    sns.lineplot(x='dataset_size', y='verification_tx_s', data=df, ax=axes[0, 1], marker='s', label='Verification')
    axes[0, 1].set_title('Scaling Trend: Linear vs Constant')
    axes[0, 1].set_xlabel('N')
    axes[0, 1].set_ylabel('Time (s)')
    axes[0, 1].grid(True)
    
    # 3. Stacked Bar
    axes[1, 0].bar(df_mean['dataset_size'].astype(str), df_mean['fhe_sign_aggregation_s'], label='Aggregation', color=sns.color_palette(current_palette)[0], width=0.5)
    axes[1, 0].bar(df_mean['dataset_size'].astype(str), df_mean['verification_tx_s'], bottom=df_mean['fhe_sign_aggregation_s'], label='Verification', color=sns.color_palette(current_palette)[1], width=0.5)
    axes[1, 0].set_title('Composition: Aggregation + Verification')
    axes[1, 0].set_xlabel('N')
    axes[1, 0].set_ylabel('Time (s)')
    axes[1, 0].legend()
    axes[1, 0].grid(True, axis='y')
    
    # 4. Box Plot
    df_box_full = pd.melt(df, id_vars=['dataset_size'], value_vars=['fhe_sign_aggregation_s', 'verification_tx_s'], var_name='Type', value_name='Time (s)')
    df_box_full['Type'] = df_box_full['Type'].map(type_map)
    sns.boxplot(x='dataset_size', y='Time (s)', hue='Type', data=df_box_full, ax=axes[1, 1], palette=current_palette)
    axes[1, 1].set_title('Distribution Comparison')
    axes[1, 1].set_xlabel('N')
    axes[1, 1].grid(True, axis='y')
    
    plt.tight_layout()
    output_path_dashboard = os.path.join(output_dir, 'plot_comparison_dashboard.pdf')
    plt.savefig(output_path_dashboard)
    print(f"Saved Comparison Dashboard to {output_path_dashboard}")
    plt.close()

    # --- Plot 4e: Grouped Bar Chart (Standalone) ---
    # fig:comparison_agg_ver (plot_grouped_bar_aggregation_verification.pdf).
    # Means and error bars are computed from the raw dataframe, so this figure should align with
    # the raw summary tables below.
    plt.figure(figsize=(10, 6))
    
    # Use full dataframe 'df' to allow Seaborn to calculate error bars
    type_map_standalone = {'fhe_sign_aggregation_s': 'FHE Computation and Sign. Aggregation', 'verification_tx_s': 'On-Chain Commit Time'}
    comparison_hue_order = [type_map_standalone[key] for key in ['fhe_sign_aggregation_s', 'verification_tx_s']]
    comparison_palette = {
        type_map_standalone['fhe_sign_aggregation_s']: AGGREGATION_COLOR,
        type_map_standalone['verification_tx_s']: VERIFICATION_GRAY,
    }
    
    # Melt the full dataframe
    df_melt_full = pd.melt(df, id_vars=['dataset_size'], value_vars=['fhe_sign_aggregation_s', 'verification_tx_s'], var_name='Type', value_name='Time (s)')
    df_melt_full['Type'] = df_melt_full['Type'].map(type_map_standalone)
    
    ax = sns.barplot(
        x='dataset_size', 
        y='Time (s)', 
        hue='Type', 
        data=df_melt_full, 
        palette=comparison_palette,
        hue_order=comparison_hue_order,
        errorbar='sd',  # Standard Deviation error bars
        capsize=0.1     # Error bar caps
    )

    grouped_stats = df_melt_full.groupby(['Type', 'dataset_size'])['Time (s)'].agg(['mean', 'std'])
    x_order = sorted(df_melt_full['dataset_size'].unique())
    hue_order = comparison_hue_order
    grouped_containers = [container for container in ax.containers if hasattr(container, 'patches')]
    if len(grouped_containers) >= 2:
        style_bar_patches(grouped_containers[0].patches, AGGREGATION_COLOR, edgecolor=AGGREGATION_HATCH_EDGE, hatch='///', linewidth=1.2)
        style_bar_patches(grouped_containers[1].patches, VERIFICATION_GRAY, edgecolor=VERIFICATION_GRAY, linewidth=0.9)
    style_errorbar_lines(ax)
    add_labels_above_grouped_bars(ax, grouped_stats, x_order, hue_order, fontsize=18, pad_frac=0.025, top_margin_frac=0.05)

    plt.title('')
    plt.xlabel('Number of Rating Inputs ($N$)', fontsize=18)
    plt.ylabel('Time (s)', fontsize=18)
    plt.xticks(fontsize=18)
    plt.yticks(fontsize=18)
    plt.grid(True, axis='y')
    build_custom_legend(
        ax,
        [
            {
                'label': type_map_standalone['fhe_sign_aggregation_s'],
                'facecolor': AGGREGATION_COLOR,
                'edgecolor': AGGREGATION_HATCH_EDGE,
                'hatch': '///',
                'linewidth': 1.2,
            },
            {
                'label': type_map_standalone['verification_tx_s'],
                'facecolor': VERIFICATION_GRAY,
                'edgecolor': VERIFICATION_GRAY,
                'linewidth': 0.9,
            },
        ],
        fontsize=18,
        loc='upper left'
    )
    
    plt.tight_layout()
    output_path_grouped = os.path.join(output_dir, 'plot_grouped_bar_aggregation_verification.pdf')
    plt.savefig(output_path_grouped)
    print(f"Saved Standalone Grouped Bar Chart to {output_path_grouped}")
    plt.close()

    # --- Plot 4f: Direct verify() Call Time (Standalone) ---
    # Tracking: companion figure for the new verification_call_ms metric added to
    # experiment_results.csv. This plot is meant to sit next to
    # plot_grouped_bar_aggregation_verification.pdf in the experiment, separating the
    # contract's direct verify() path from the end-to-end transaction lifecycle.
    if 'verification_call_ms' in df.columns and df['verification_call_ms'].notna().any():
        plt.figure(figsize=(10, 6))

        df_verify_call = df.dropna(subset=['verification_call_ms']).copy()
        ax = sns.barplot(
            x='dataset_size',
            y='verification_call_ms',
            data=df_verify_call,
            color=VERIFICATION_GRAY,
            errorbar='sd',
            capsize=0.1
        )

        verify_call_stats = df_verify_call.groupby('dataset_size')['verification_call_ms'].agg(['mean', 'std']).reindex(sorted(df_verify_call['dataset_size'].unique()))
        style_bar_patches(ax.patches, VERIFICATION_GRAY, edgecolor=VERIFICATION_GRAY, linewidth=0.9)
        style_errorbar_lines(ax)
        add_labels_above_bars(ax, verify_call_stats['mean'].tolist(), verify_call_stats['std'].tolist(), fontsize=18, pad_frac=0.03, top_margin_frac=0.08)

        plt.title('')
        plt.xlabel('Number of Rating Inputs ($N$)', fontsize=18)
        plt.ylabel('Direct verify() Time (ms)', fontsize=18)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.grid(True, axis='y')

        plt.tight_layout()
        output_path_verify_call = os.path.join(output_dir, 'plot_bar_verification_call_ms.pdf')
        plt.savefig(output_path_verify_call)
        print(f"Saved Direct verify() Bar Chart to {output_path_verify_call}")
        plt.close()

        # Tracking: experiment-ready composite figure pairing the direct verify() latency view with the
        # aggregation-vs-commit chart. This is the figure to place next to or instead of the
        # standalone commit-time plot in the implementation.
        subplot_title_fontsize = 28
        axis_label_fontsize = 30
        tick_label_fontsize = 26
        legend_fontsize = 22
        value_label_fontsize = 24

        fig, axes = plt.subplots(1, 2, figsize=(20.5, 7.5), gridspec_kw={'width_ratios': [1.08, 1.55]})

        ax_left = sns.barplot(
            x='dataset_size',
            y='verification_call_ms',
            data=df_verify_call,
            color=VERIFICATION_GRAY,
            errorbar='sd',
            capsize=0.1,
            ax=axes[0]
        )
        style_bar_patches(ax_left.patches, VERIFICATION_GRAY, edgecolor=VERIFICATION_GRAY, linewidth=0.9)
        style_errorbar_lines(ax_left)
        add_labels_above_bars(
            ax_left,
            verify_call_stats['mean'].tolist(),
            verify_call_stats['std'].tolist(),
            fontsize=value_label_fontsize,
            pad_frac=0.05,
            top_margin_frac=0.14
        )
        axes[0].set_title('(a) Verification process:\nRHS reconstruction + BN254 pairing', fontsize=subplot_title_fontsize, pad=16)
        axes[0].set_xlabel('Number of Rating Inputs ($N$)', fontsize=axis_label_fontsize)
        axes[0].set_ylabel('Time (ms)', fontsize=axis_label_fontsize)
        axes[0].tick_params(axis='both', labelsize=tick_label_fontsize)
        axes[0].grid(True, axis='y')

        ax_right = sns.barplot(
            x='dataset_size',
            y='Time (s)',
            hue='Type',
            data=df_melt_full,
            palette=comparison_palette,
            hue_order=comparison_hue_order,
            errorbar='sd',
            capsize=0.1,
            ax=axes[1]
        )
        right_containers = [container for container in ax_right.containers if hasattr(container, 'patches')]
        if len(right_containers) >= 2:
            style_bar_patches(right_containers[0].patches, AGGREGATION_COLOR, edgecolor=AGGREGATION_HATCH_EDGE, hatch='///', linewidth=1.2)
            style_bar_patches(right_containers[1].patches, VERIFICATION_GRAY, edgecolor=VERIFICATION_GRAY, linewidth=0.9)
        style_errorbar_lines(ax_right)
        add_labels_above_grouped_bars(
            ax_right,
            grouped_stats,
            x_order,
            hue_order,
            fontsize=value_label_fontsize,
            pad_frac=0.035,
            top_margin_frac=0.10
        )
        axes[1].set_title('(b) Aggregation vs Commit Time', fontsize=subplot_title_fontsize, pad=16)
        axes[1].set_xlabel('Number of Rating Inputs ($N$)', fontsize=axis_label_fontsize)
        axes[1].set_ylabel('Time (s)', fontsize=axis_label_fontsize)
        axes[1].tick_params(axis='both', labelsize=tick_label_fontsize)
        axes[1].grid(True, axis='y')
        build_custom_legend(
            axes[1],
            [
                {
                    'label': type_map_standalone['fhe_sign_aggregation_s'],
                    'facecolor': AGGREGATION_COLOR,
                    'edgecolor': AGGREGATION_HATCH_EDGE,
                    'hatch': '///',
                    'linewidth': 1.2,
                },
                {
                    'label': type_map_standalone['verification_tx_s'],
                    'facecolor': VERIFICATION_GRAY,
                    'edgecolor': VERIFICATION_GRAY,
                    'linewidth': 0.9,
                },
            ],
            fontsize=legend_fontsize,
            loc='upper left'
        )

        fig.subplots_adjust(top=0.90, wspace=0.26)
        plt.tight_layout(rect=[0.005, 0.01, 0.995, 0.96])
        output_path_subplot = os.path.join(output_dir, 'plot_subplots_aggregation_commit_direct_verify.pdf')
        plt.savefig(output_path_subplot, bbox_inches='tight', pad_inches=0.03)
        print(f"Saved Combined Subplot Figure to {output_path_subplot}")
        plt.close(fig)
    else:
        print("Skipping direct verify() plot ('verification_call_ms' column missing)")



    # --- Generate Statistics for Setup and Encryption ---
    # Tracking: descriptive summary for stage-1 metrics. This is terminal-only output but it is
    print("\n--- Statistics for Setup and Encryption ---")
    stats_cols = ['setup_s', 'encrypt_sign_s']
    # Group by dataset_size and calculate describe
    stats = df.groupby('dataset_size')[stats_cols].describe()
    
    # Print in a format easy to read for table construction
    # We want Mean, Std, Min, Max for each
    print(stats.to_string())

    print("\n--- Statistics for Single Signing Time and Signature Size ---")
    if 'single_signing_time_ms' in df.columns and 'single_signature_size_bytes' in df.columns:
         # Tracking: auxiliary metrics for discussion/cross-checking. These are not currently
         single_stats_cols = ['single_signing_time_ms', 'single_signature_size_bytes']
         # These are constant or near-constant, but let's see stats across all runs
         print(df[single_stats_cols].describe().to_string())
    else:
        print("Columns for single metrics not found.")

    print("\n--- Statistics for On-Chain Verification and Transaction Size ---")
    # Tracking: raw grouped describe() output supporting the verification-time and tx-size claims
    # in the BN254 evaluation subsection.
    stats_cols_verif = ['verification_tx_s', 'tx_size_bytes']
    stats_verif = df.groupby('dataset_size')[stats_cols_verif].describe()
    print(stats_verif.to_string())

    if 'verification_call_ms' in df.columns and df['verification_call_ms'].notna().any():
        print("\n--- Statistics for Direct verify() Call Time ---")
        # Tracking: raw grouped statistics for the direct contract verify() benchmark, excluding
        # transaction submission/mining/receipt overhead.
        stats_verify_call = df.groupby('dataset_size')['verification_call_ms'].describe()
        print(stats_verify_call.to_string())

    if 'tx_size_bytes' in df.columns:
        corr_val = df['tx_size_bytes'].corr(df['verification_tx_s'])
        print(f"\n[Correlation Analysis] Transaction Size vs. Verification Time: r = {corr_val:.4f}")

    print("\n--- Statistics for Aggregated Signature Size ---")
    if 'aggregated_signature_size_bytes' in df.columns:
        # Tracking: confirms the constant aggregated-signature footprint cited in the implementation.
        print(df[['aggregated_signature_size_bytes']].groupby(df['dataset_size']).describe())
    else:
        print("Column 'aggregated_signature_size_bytes' not found.")

    # Formatted output for easier Summary Table construction
    print("\n--- Summary Table Data Helper (Values in ms) ---")
    
    # Global setup statistic used by the evaluation table for "Key Generation (TFHE + LHS)".
    # This is intentionally aggregated over the full CSV, not grouped by dataset_size,
    # because the setup/key-generation phase is treated as independent of N in the experiment.
    setup_global_mean = df['setup_ms'].mean()
    setup_global_std = df['setup_ms'].std()
    print(f"Key Generation (TFHE + LHS) [Aggregated] | Mean: {setup_global_mean:.4f} | Std: {setup_global_std:.4f}")
    
    print("-" * 60)
    print("Dataset Size | Encrypt Mean (ms) | Encrypt Std | Aggregation Mean (ms) | Aggregation Std")
    for size, group in df.groupby('dataset_size'):
        # Tracking: these per-N encryption and aggregation values are the raw numbers to compare
        enc_mean = group['encrypt_sign_ms'].mean()
        enc_std = group['encrypt_sign_ms'].std()
        agg_mean = group['fhe_sign_aggregation_ms'].mean()
        agg_std = group['fhe_sign_aggregation_ms'].std()
        print(f"{size:<12} | {enc_mean:<17.4f} | {enc_std:<11.4f} | {agg_mean:<21.4f} | {agg_std:<15.4f}")

    print("\n--- Additional Metrics for Table (Single Item) ---")
    if 'single_signing_time_ms' in df.columns:
        single_sign_mean = df['single_signing_time_ms'].mean()
        single_sign_std = df['single_signing_time_ms'].std()
        print(f"Single Signing Time (ms) | Mean: {single_sign_mean:.4f} | Std: {single_sign_std:.4f}")
    
    if 'single_signature_size_bytes' in df.columns:
        # Size shouldn't vary, so max is fine
        sig_size = df['single_signature_size_bytes'].max()
        print(f"Single Signature Size: {sig_size} bytes")

    print("\n--- On-Chain Verification Table Data (Values in Seconds) ---")
    print("Dataset Size | Verification Mean (s) | Verification Std (s) | Tx Size Mean (Bytes)")
    for size, group in df.groupby('dataset_size'):
        # Tracking: raw verification figures supporting the O(1) runtime discussion and the gas/tx
        # table cross-check in the implementation.
        ver_mean = group['verification_tx_s'].mean()
        ver_std = group['verification_tx_s'].std()
        tx_mean = group['tx_size_bytes'].mean()
        print(f"{size:<12} | {ver_mean:<21.4f} | {ver_std:<20.4f} | {tx_mean:<20.0f}")

    if 'verification_call_ms' in df.columns and df['verification_call_ms'].notna().any():
        print("\n--- Direct verify() Table Data (Values in ms) ---")
        print("Dataset Size | verify() Mean (ms) | verify() Std (ms)")
        for size, group in df.groupby('dataset_size'):
            group_verify_call = group.dropna(subset=['verification_call_ms'])
            if group_verify_call.empty:
                continue
            verify_call_mean = group_verify_call['verification_call_ms'].mean()
            verify_call_std = group_verify_call['verification_call_ms'].std()
            print(f"{size:<12} | {verify_call_mean:<18.4f} | {verify_call_std:<16.4f}")

    print("\n--- Aggregation Table Data (Values in Seconds) ---")
    print("Dataset Size | Aggregation Mean (s) | Aggregation Std (s)")
    for size, group in df.groupby('dataset_size'):
        # Tracking: raw aggregation values used in the evaluation text and the comparison figure.
        agg_mean_s = group['fhe_sign_aggregation_s'].mean()
        agg_std_s = group['fhe_sign_aggregation_s'].std()
        print(f"{size:<12} | {agg_mean_s:<20.4f} | {agg_std_s:<19.4f}")

    # --- Plot 8: Game Theoretic Utility Analysis (Economic Dynamics) ---
    if 'operator_utility' in df.columns and 'stage_index' in df.columns:
        plt.figure(figsize=(12, 6))
        
        # We want to plot Utility over Stage Index for different runs/behaviors
        # Filter for relevant columns
        df_eco = df[['run_id', 'scenario_desc', 'stage_index', 'operator_utility', 'cheated', 'detected']].copy()
        
        # For plotting, we might have many runs. Let's pick representative ones if there are too many,
        # or plot all with hue='scenario_desc'.
        # To make it readable, let's plot unique lines for each (Scenario + Behavior) combination.
        # But 'behavior' (cheating prob) isn't explicitly a column in the CSV (it's in command args).
        # We can infer behavior: Honest (never cheated), or Malicious.
        
        # create a 'Run Type' label
        def get_run_type(group):
            if group['cheated'].sum() > 0:
                if group['detected'].sum() > 0:
                    return "Malicious (Detected)"
                else:
                    return "Malicious (Undetected)"
            return "Honest"

        # Groups by run_id to determine type
        run_types = df_eco.groupby('run_id').apply(get_run_type)
        df_eco['Run Type'] = df_eco['run_id'].map(run_types)
        
        # Combine Scenario + Run Type for Legend
        df_eco['Legend'] = df_eco['scenario_desc'] + "\n" + df_eco['Run Type']

        sns.lineplot(
            data=df_eco, 
            x='stage_index', 
            y='operator_utility', 
            hue='Legend', 
            style='Legend',
            markers=True, 
            dashes=False,
            linewidth=2.5,
            palette="bright"
        )
        
        plt.title('Operator Economic Utility Over Stages (Game Theory Analysis)')
        plt.xlabel('Stage Index (Time)')
        plt.ylabel('Accumulated Utility ($ = Gain - Slash)')
        plt.axhline(0, color='black', linewidth=1, linestyle='--') # Baseline
        plt.grid(True)
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        
        plt.tight_layout()
        output_path_eco = os.path.join(output_dir, 'plot_game_theory_utility.pdf')
        plt.savefig(output_path_eco)
        print(f"Saved Game Theory Utility plot to {output_path_eco}")
        plt.close()
    else:
        print("Skipping Game Theory Utility plot ('operator_utility' column missing)")

    # --- Deployment Costs Analysis ---
    deployment_csv = 'deployment_costs.csv'
    if os.path.exists(deployment_csv):
        try:
            df_deploy = pd.read_csv(deployment_csv)
            print("\n--- Smart Contract Deployment Costs ---")
            
            # Constants for Cost Estimation
            GAS_PRICE_GWEI = 30
            ETH_PRICE_USD = 3000
            CONVERSION_FACTOR = GAS_PRICE_GWEI * 1e-9 * ETH_PRICE_USD

            # Group by dataset_size
            # Tracking: these grouped means are the deployment-gas values later exported as
            deploy_stats = df_deploy.groupby('dataset_size')['deployment_gas_used'].agg(['mean', 'std']).reset_index()
            deploy_tx_sizes = None
            if 'deployment_tx_size_bytes' in df_deploy.columns:
                deploy_tx_sizes = df_deploy.groupby('dataset_size')['deployment_tx_size_bytes'].mean()
            
            header = "Dataset Size | Avg. Gas | Std. Dev | Avg. Cost (USD)"
            if deploy_tx_sizes is not None:
                header += " | Tx Size (Bytes)"
            print(header)
            print("-" * 80)
            for _, row in deploy_stats.iterrows():
                size = int(row['dataset_size'])
                avg_gas = row['mean']
                std_gas = row['std'] if not pd.isna(row['std']) else 0.0
                cost_usd = avg_gas * CONVERSION_FACTOR
                if deploy_tx_sizes is not None:
                    tx_size = deploy_tx_sizes.get(size, 0.0)
                    print(f"{size:<12} | {avg_gas:<8.0f} | {std_gas:<8.0f} | ${cost_usd:.2f} | {tx_size:.0f}")
                else:
                    print(f"{size:<12} | {avg_gas:<8.0f} | {std_gas:<8.0f} | ${cost_usd:.2f}")

        except Exception as e:
            print(f"Error analyzing deployment costs: {e}")
    else:
        print(f"\nWarning: {deployment_csv} not found.")

    # --- Transaction Gas Costs Analysis ---
    # Tracking: verification gas means below are the raw source for the verification rows of
    if 'gas_used' in df.columns:
        print("\n--- Transaction Execution Costs (Verification) ---")
        tx_stats = df.groupby('dataset_size')['gas_used'].agg(['mean', 'std']).reset_index()
        
        print("Dataset Size | Avg. Gas | Std. Dev | Avg. Cost (USD)")
        print("-" * 65)
        for _, row in tx_stats.iterrows():
            size = int(row['dataset_size'])
            avg_gas = row['mean']
            std_gas = row['std'] if not pd.isna(row['std']) else 0.0
            cost_usd = avg_gas * CONVERSION_FACTOR
            print(f"{size:<12} | {avg_gas:<8.0f} | {std_gas:<8.0f} | ${cost_usd:.2f}")

    # Tracking: results_summary.md is the file-level audit artifact used to compare the evaluation
    # against the generated analysis without rerunning the full visual inspection.
    generate_markdown_report(df, df_deploy if 'df_deploy' in dir() else None, output_dir)
    
    print("\nAnalysis Complete.")


def generate_markdown_report(df, df_deploy, output_dir):
    """Generate a markdown file with all statistical tables for quick verification."""
    
    report_path = os.path.join(output_dir, 'results_summary.md')
    
    # Constants
    GAS_PRICE_GWEI = 30
    ETH_PRICE_USD = 3000
    CONVERSION_FACTOR = GAS_PRICE_GWEI * 1e-9 * ETH_PRICE_USD
    
    with open(report_path, 'w') as f:
        f.write("# Simulation Results Summary\n\n")
        
        f.write("## Table: Setup, Encryption and Signing Phase Time\n")
        
        # Same global setup statistic exported to plots/results_summary.md and mirrored in
        setup_mean = df['setup_ms'].mean()
        setup_std = df['setup_ms'].std()
        
        f.write("| Operation Phase | Mean (ms) | Std. Dev. (ms) |\n")
        f.write("|-----------------|-----------|----------------|\n")
        f.write(f"| **Key Generation (TFHE + LHS)** | **{setup_mean:.2f}** | **{setup_std:.2f}** |\n\n")
        
        f.write("| N | Encrypt & Sign Mean (ms) | Std. Dev. (ms) |\n")
        f.write("|---|--------------------------|----------------|\n")
        for size in sorted(df['dataset_size'].unique()):
            group = df[df['dataset_size'] == size]
            # Per-N values used for the "Encryption & Signing" rows in the evaluation table.
            enc_mean = group['encrypt_sign_ms'].mean()
            enc_std = group['encrypt_sign_ms'].std()
            f.write(f"| {size} | {enc_mean:.2f} | {enc_std:.2f} |\n")
        f.write("\n")
        
        # --- Table 2: Aggregation Time ---
        # Tracking: these rows back the aggregation numbers cited in the BN254 evaluation prose.
        f.write("## Table: Aggregation Phase Time\n")
        f.write("*Values shown in Figure `fig:comparison_agg_ver`*\n\n")
        
        f.write("| N | Aggregation Mean (s) | Std. Dev. (s) |\n")
        f.write("|---|----------------------|---------------|\n")
        for size in sorted(df['dataset_size'].unique()):
            group = df[df['dataset_size'] == size]
            # Per-N raw aggregation means/stds mirrored in the evaluation discussion of stage 2.
            agg_mean = group['fhe_sign_aggregation_ms'].mean() / 1000.0
            agg_std = group['fhe_sign_aggregation_ms'].std() / 1000.0
            f.write(f"| {size} | {agg_mean:.2f} | {agg_std:.4f} |\n")
        f.write("\n")
        
        # --- Table 3: On-Chain Verification Time ---
        # Tracking: these rows back the verification-runtime claims in the BN254 evaluation prose.
        f.write("## Table: On-Chain Verification Time\n")
        f.write("*Values shown in Figure `fig:comparison_agg_ver`*\n\n")
        
        f.write("| N | Verification Mean (s) | Std. Dev. (s) |\n")
        f.write("|---|----------------------|---------------|\n")
        for size in sorted(df['dataset_size'].unique()):
            group = df[df['dataset_size'] == size]
            # Per-N raw verification means/stds mirrored in the evaluation comparison figure text.
            ver_mean = group['verification_tx_s'].mean()
            ver_std = group['verification_tx_s'].std()
            f.write(f"| {size} | {ver_mean:.4f} | {ver_std:.4f} |\n")
        f.write("\n")

        if 'verification_call_ms' in df.columns and df['verification_call_ms'].notna().any():
            # --- Table 3b: Direct verify() Call Time ---
            # Tracking: companion table for the direct verify() eth_call benchmark. This excludes
            # transaction lifecycle overhead and supports the new standalone figure.
            f.write("## Table: Direct verify() Call Time\n")
            f.write("*Companion values for `plot_bar_verification_call_ms.pdf`*\n\n")

            f.write("| N | verify() Mean (ms) | Std. Dev. (ms) |\n")
            f.write("|---|--------------------|----------------|\n")
            for size in sorted(df['dataset_size'].unique()):
                group = df[df['dataset_size'] == size].dropna(subset=['verification_call_ms'])
                if group.empty:
                    continue
                verify_call_mean = group['verification_call_ms'].mean()
                verify_call_std = group['verification_call_ms'].std()
                f.write(f"| {size} | {verify_call_mean:.4f} | {verify_call_std:.4f} |\n")
            f.write("\n")

        f.write("## Table: Smart Contract Gas Costs\n")
        
        f.write("| Operation | Gas Used (Units) | Tx Size (Bytes) |\n")
        f.write("|-----------|------------------|----------------|\n")
        
        # Deployment costs
        if df_deploy is not None:
            # Deployment rows come from deployment_costs.csv, not experiment_results.csv.
            deploy_stats = df_deploy.groupby('dataset_size')['deployment_gas_used'].mean()
            deploy_tx_sizes = df_deploy.groupby('dataset_size')['deployment_tx_size_bytes'].mean() if 'deployment_tx_size_bytes' in df_deploy.columns else None
            for size, mean_gas in deploy_stats.items():
                tx_size = "-" if deploy_tx_sizes is None else f"{deploy_tx_sizes.get(size, 0):.0f}"
                f.write(f"| Contract Deployment (N={size}) | {mean_gas:,.0f} | {tx_size} |\n")
        
        # Verification costs
        if 'gas_used' in df.columns:
            # Verification rows come from experiment_results.csv grouped by dataset_size.
            verif_stats = df.groupby('dataset_size')['gas_used'].mean()
            verif_tx_sizes = df.groupby('dataset_size')['tx_size_bytes'].mean() if 'tx_size_bytes' in df.columns else None
            for size, mean_gas in verif_stats.items():
                tx_size = "-" if verif_tx_sizes is None else f"{verif_tx_sizes.get(size, 0):.0f}"
                f.write(f"| Verification (N={size}) | {mean_gas:,.0f} | {tx_size} |\n")
        f.write("\n")
        
        # --- Summary for quick copy-paste ---
        # Tracking: compact block to compare evaluation prose against one file without scanning all
        # tables or plots.
        f.write("## Quick Reference Values\n\n")
        f.write("```\n")
        f.write(f"Key Generation: {setup_mean:.2f} ms (±{setup_std:.2f})\n")
        for size in sorted(df['dataset_size'].unique()):
            group = df[df['dataset_size'] == size]
            f.write(f"\nN={size}:\n")
            f.write(f"  Encrypt & Sign: {group['encrypt_sign_ms'].mean():.2f} ms\n")
            f.write(f"  Aggregation: {group['fhe_sign_aggregation_ms'].mean()/1000:.2f} s\n")
            f.write(f"  Verification: {group['verification_tx_s'].mean():.4f} s\n")
            if 'verification_call_ms' in group.columns and group['verification_call_ms'].notna().any():
                f.write(f"  Direct verify(): {group['verification_call_ms'].mean():.4f} ms\n")
            f.write(f"  Gas Used: {group['gas_used'].mean():,.0f}\n")
        f.write("```\n")
    
    print(f"\nSaved Markdown summary to {report_path}")


if __name__ == "__main__":
    analyze_and_plot()
