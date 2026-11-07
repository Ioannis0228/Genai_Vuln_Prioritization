from evaluation import mean_recall_at_k, mean_ndcg_at_k, time_to_surface_all, summarize_time_to_surface, mean_churn
from config import config

def evaluate_config(config_type, queue_snapshots, kev_snapshots, kev_added_dates, vex_statements, sbom_findings_set):
    """Evaluate a single configuration type across multiple queue snapshots.

    Args:
        config_type (str): Name of the configuration type being evaluated.
        queue_snapshots (list): List of queue snapshots, each containing a list of findings.
        kev_snapshots (dict): Dictionary mapping snapshot dates to sets of KEV CVEs.
        kev_added_dates (dict): Dictionary mapping KEV CVEs to their added dates.
        vex_statements (dict): Dictionary mapping finding IDs to their VEX status history.
        sbom_findings_set (set): Set of tuples containing (CVE ID, PURL) for findings in the SBOM.
    Returns:
        list: A list of dictionaries containing evaluation metrics for each k value.
    """

    results = []

    for k in config.k_values:

        mean_recall = mean_recall_at_k(queue_snapshots, kev_snapshots, k, vex_statements, sbom_findings_set)

        mean_ndcg = mean_ndcg_at_k(queue_snapshots, kev_snapshots, k, vex_statements, sbom_findings_set)

        tts = time_to_surface_all(kev_added_dates, queue_snapshots, k, vex_statements, sbom_findings_set)

        tts_summary = summarize_time_to_surface(tts)

        churn = mean_churn(queue_snapshots, k)

        # Snapshots must be daily, so we can take every 7th snapshot for weekly churn evaluation
        weekly_snapshots = queue_snapshots[::7]  # Take every 7th snapshot for weekly evaluation
        weekly_churn = mean_churn(weekly_snapshots, k)

        results.append({
            "config_type": config_type,
            "k": k,
            "recall": f'{mean_recall:.3f}' if mean_recall is not None else "N/A",
            "ndcg": f'{mean_ndcg:.3f}' if mean_ndcg is not None else "N/A",
            "median_time_to_surface":
                f'{tts_summary["median_tts_days"]:.3f}' if tts_summary["median_tts_days"] is not None else "N/A",
            "mean_time_to_surface":
                f'{tts_summary["mean_tts_days"]:.3f}' if tts_summary["mean_tts_days"] is not None else "N/A",
            "surface_rate":
                f' {tts_summary["surface_rate"]:.3f}' if tts_summary["surface_rate"] is not None else "N/A",
            "daily_churn":
                f'{churn:.3f}' if churn is not None else "N/A",
            "weekly_churn":
                f'{weekly_churn:.3f}' if weekly_churn is not None else "N/A",

            "surfaced_count": tts_summary["surfaced_count"],
            "never_surfaced_count": tts_summary["never_surfaced_count"],
            "not_relevant_due_to_vex_count": tts_summary["not_relevant_due_to_vex_count"],
            "kev_added_outside_snapshot_window": tts_summary["kev_added_outside_snapshot_window"],
            "tts_total_count": tts_summary["total_count"],
        })

    return results



def evaluate_all_configs(config_types_queues, kev_snapshots, kev_added_dates, vex_statements, sbom_findings_set):
    """Evaluate all configuration types across multiple queue snapshots."""

    all_results = []

    for config_type, queue_snapshots in config_types_queues.items():

        results = evaluate_config(
            config_type=config_type,
            queue_snapshots=queue_snapshots,
            kev_snapshots=kev_snapshots,
            kev_added_dates=kev_added_dates,
            vex_statements=vex_statements,
            sbom_findings_set=sbom_findings_set
        )

        all_results.extend(results)

    return all_results