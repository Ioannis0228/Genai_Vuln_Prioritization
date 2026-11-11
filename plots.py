from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

CONFIG_GROUPS = {
    "main": [
        "cvss",
        "epss",
        "cvss_epss",
        "fusion",
    ],
    "ablations": [
        "sbom_ablation",
        "epss_ablation",
        "kev_ablation",
        "fusion",
    ],
}

def load_all_results(csv_dir: str | Path) -> pd.DataFrame:
    """Load per-SBOM evaluation CSV files into a unified DataFrame."""
    csv_dir = Path(csv_dir)
    files = sorted(csv_dir.glob("evaluation_results_*.csv"))

    if not files:
        raise FileNotFoundError(f"No evaluation CSV files found in {csv_dir}")

    frames = []
    for filepath in files:
        df = pd.read_csv(filepath)
        df["sbom_id"] = filepath.stem.replace("evaluation_results_", "")
        frames.append(df)

    results = pd.concat(frames, ignore_index=True)

    numeric_columns = [
        "k",
        "recall",
        "ndcg",
        "median_time_to_surface",
        "mean_time_to_surface",
        "surface_rate",
        "daily_churn",
        "weekly_churn",
        "surfaced_count",
        "never_surfaced_count",
        "not_relevant_due_to_vex_count",
        "kev_added_outside_snapshot_window",
        "tts_total_count",
    ]

    for column in numeric_columns:
        if column in results.columns:
            results[column] = pd.to_numeric(results[column], errors="coerce")

    return results

def aggregate_results(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate per-SBOM results across configurations and K values."""
    grouped = df.groupby(["config_type", "k"], dropna=False)

    results = grouped.agg(
        recall=("recall", "mean"),
        ndcg=("ndcg", "mean"),
        surfaced_count=("surfaced_count", "sum"),
        never_surfaced_count=("never_surfaced_count", "sum"),
        historical_kev_count=("kev_added_outside_snapshot_window", "sum"),
        vex_excluded_count=("not_relevant_due_to_vex_count", "sum"),
        daily_churn=("daily_churn", "mean"),
        weekly_churn=("weekly_churn", "mean"),
        valid_recall_sboms=("recall", "count"),
        valid_ndcg_sboms=("ndcg", "count"),
        sbom_count=("sbom_id", "nunique"),
    ).reset_index()

    # Total eligible TTS population
    results["tts_eligible_count"] = (
        results["surfaced_count"] + results["never_surfaced_count"]
    )

    # Surface rate over eligible population
    results["surface_rate"] = (
        results["surfaced_count"]
        / results["tts_eligible_count"].replace(0, np.nan)
    )

    # Weighted mean TTS across all surfaced findings
    tts_weighted = (
        df.assign(
            weighted_tts=df["mean_time_to_surface"] * df["surfaced_count"]
        )
        .groupby(["config_type", "k"])
        .agg(
            weighted_tts_sum=("weighted_tts", "sum"),
            surfaced_sum=("surfaced_count", "sum"),
        )
        .reset_index()
    )

    results = results.merge(tts_weighted, on=["config_type", "k"])
    results["mean_time_to_surface"] = (
        results["weighted_tts_sum"]
        / results["surfaced_sum"].replace(0, np.nan)
    )

    return results.drop(columns=["weighted_tts_sum", "surfaced_sum"])

def plot_1x2_figure(
    df: pd.DataFrame,
    metrics: list[tuple[str, str, str]],
    figure_name: str,
    family_name: str,
    config_types: list[str],
    output_dir: str | Path,
):
    """Generate a clean 1x2 subplot figure for a pair of metrics."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    data = df[df["config_type"].isin(config_types)].copy()
    if data.empty:
        return

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5), sharex=True)

    line_styles = ["-", "--", "-.", ":"]
    markers = ["o", "s", "^", "D", "v"]

    for ax, (metric, title, ylabel) in zip(axes, metrics):
        for i, (config_type, group) in enumerate(data.groupby("config_type")):
            group = group.sort_values("k")
            ax.plot(
                group["k"],
                group[metric],
                marker=markers[i % len(markers)],
                linewidth=2,
                linestyle=line_styles[i % len(line_styles)],
                label=config_type,
            )
        ax.set_title(title, fontsize=11, fontweight="bold")
        ax.set_xlabel("K", fontsize=10)
        ax.set_ylabel(ylabel, fontsize=10)
        ax.grid(True, linestyle="--", alpha=0.4)
        ax.set_xticks(sorted(data["k"].unique()))

    # Single top legend centered above subplots
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.05),
        ncol=min(len(config_types), 4),
        frameon=True,
    )

    fig.tight_layout()
    fig.savefig(output_dir / f"{family_name}_{figure_name}.pdf", dpi=300, bbox_inches="tight")
    fig.savefig(output_dir / f"{family_name}_{figure_name}.png", dpi=300, bbox_inches="tight")
    plt.close(fig)

def create_tts_explanation_table(
    df: pd.DataFrame, config_types: list[str], selected_k=(5, 10, 20)
) -> pd.DataFrame:
    """Create a dedicated TTS Breakdown & Diagnostics Table to explain TTS mechanics."""
    columns = [
        "config_type",
        "k",
        "mean_time_to_surface",
        "surface_rate",
        "surfaced_count",
        "never_surfaced_count",
        "tts_eligible_count",
        "historical_kev_count",
        "vex_excluded_count",
    ]

    table = df[
        df["config_type"].isin(config_types) & df["k"].isin(selected_k)
    ][columns].copy()

    # Convert counts to integer types for clean presentation
    count_cols = [
        "surfaced_count",
        "never_surfaced_count",
        "tts_eligible_count",
        "historical_kev_count",
        "vex_excluded_count",
    ]
    table[count_cols] = table[count_cols].fillna(0).astype(int)

    return table.sort_values(["config_type", "k"])


def export_tts_table(
    df: pd.DataFrame,
    name: str,
    output_dir: str | Path = "plots2/tables",
    caption: str = None,
    label: str = None,
) -> pd.DataFrame:
    """Export the TTS Diagnostic Table to CSV, LaTeX, and a formatted PNG image."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    table = df.copy()

    # Define clean column display labels
    column_rename_map = {
        "config_type": "Configuration",
        "k": "K",
        "mean_time_to_surface": "Mean TTS (Days)",
        "surface_rate": "Surface Rate",
        "surfaced_count": "Surfaced (N_surf)",
        "never_surfaced_count": "Missed (N_miss)",
        "tts_eligible_count": "Eligible (N_elig)",
        "historical_kev_count": "Historical KEVs",
        "vex_excluded_count": "VEX Excluded",
    }
    display_table = table.rename(columns=column_rename_map)

    # 1. Save CSV
    display_table.to_csv(output_dir / f"{name}.csv", index=False, float_format="%.3f")

    # 2. Save Formatted PNG Table Preview
    cell_text = []
    for row in display_table.itertuples(index=False):
        row_text = []
        for val in row:
            if pd.isna(val):
                row_text.append("N/A")
            elif isinstance(val, (float, np.floating)):
                row_text.append(f"{val:.3f}")
            else:
                row_text.append(str(val))
        cell_text.append(row_text)

    fig, ax = plt.subplots(
        figsize=(
            max(12, len(display_table.columns) * 1.5),
            max(2, len(display_table) * 0.45 + 1),
        )
    )
    ax.axis("off")

    mpl_table = ax.table(
        cellText=cell_text,
        colLabels=list(display_table.columns),
        cellLoc="center",
        loc="center",
    )

    mpl_table.auto_set_font_size(False)
    mpl_table.set_fontsize(8.5)
    mpl_table.scale(1, 1.6)

    # Styling header and rows
    for (row, col), cell in mpl_table.get_celld().items():
        if row == 0:
            cell.set_text_props(weight="bold", color="white")
            cell.set_facecolor("#2c3e50")
        else:
            cell.set_facecolor("#ecf0f1" if row % 2 == 0 else "white")

    fig.tight_layout()
    fig.savefig(output_dir / f"{name}.png", dpi=300, bbox_inches="tight")
    plt.close(fig)

    return display_table

if __name__ == "__main__":
    # 1. Load results
    raw_results = load_all_results("results/metrics/")
    mean_results = aggregate_results(raw_results)
    output_dir = Path("plots")
    output_dir.mkdir(exist_ok=True)
    mean_results.to_csv(output_dir / "aggregated_results.csv", index=False, float_format="%.3f")

    # 2. Generate 1x2 plot figures (Accuracy, Surfacing, Churn)
    plot_pairs = {
        "accuracy": [
            ("recall", "Recall@K", "Score"),
            ("ndcg", "NDCG@K", "Score"),
        ],
        "surfacing": [
            ("mean_time_to_surface", "Mean Time to Surface (Days)", "Days"),
            ("surface_rate", "Surface Rate@K", "Rate"),
        ],
        "churn": [
            ("daily_churn", "Daily Churn@K", "Volatility"),
            ("weekly_churn", "Weekly Churn@K", "Volatility"),
        ],
    }

    for family, config_types in CONFIG_GROUPS.items():
        family_dir = output_dir / family
        for fig_name, metrics in plot_pairs.items():
            plot_1x2_figure(
                df=mean_results,
                metrics=metrics,
                figure_name=fig_name,
                family_name=family,
                config_types=config_types,
                output_dir=family_dir,
            )

    # 3. Generate TTS Diagnostic Tables (Main + Ablations)
    for family, config_types in CONFIG_GROUPS.items():
        tts_table = create_tts_explanation_table(mean_results, config_types)
        export_tts_table(
            tts_table,
            name=f"{family}_tts_explanation_table",
            output_dir=output_dir / "tables",
            caption=f"TTS Diagnostic Breakdown for {family.title()} Methods",
            label=f"tab:{family}_tts_breakdown",
        )