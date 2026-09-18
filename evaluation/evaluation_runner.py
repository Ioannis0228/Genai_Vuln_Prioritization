from evaluation import mean_recall_at_k, mean_ndcg_at_k, time_to_surface_all, summarize_time_to_surface, mean_churn
from config import config

def evaluate_algorithm(algorithm_name, queue_snapshots, kev_snapshots, kev_added_dates, vex_statements):
    """Evaluate a single algorithm across multiple queue snapshots.

    Args:
        algorithm_name (str): Name of the algorithm being evaluated.
        queue_snapshots (list): List of queue snapshots, each containing a list of findings.
        kev_snapshots (dict): Dictionary mapping snapshot dates to sets of KEV CVEs.
        kev_added_dates (dict): Dictionary mapping KEV CVEs to their added dates.
        vex_statements (dict): Dictionary mapping finding IDs to their VEX status history.
    
    Returns:
        list: A list of dictionaries containing evaluation metrics for each k value.
    """

    results = []

    for k in config.k_values:

        mean_recall = mean_recall_at_k(queue_snapshots, kev_snapshots, k, vex_statements)

        mean_ndcg = mean_ndcg_at_k(queue_snapshots, kev_snapshots, k, vex_statements)

        tts = time_to_surface_all(kev_added_dates, queue_snapshots, k, vex_statements)

        tts_summary = summarize_time_to_surface(tts)

        churn = mean_churn(queue_snapshots, k)

        results.append({
            "algorithm": algorithm_name,
            "k": k,
            "recall": f'{mean_recall:.3f}',
            "ndcg": f'{mean_ndcg:.3f}',
            "median_time_to_surface":
                f'{tts_summary["median_tts_days"]:.3f}' if tts_summary["median_tts_days"] is not None else "N/A",
            "mean_time_to_surface":
                f'{tts_summary["mean_tts_days"]:.3f}' if tts_summary["mean_tts_days"] is not None else "N/A",
            "surface_rate":
                tts_summary["surface_rate"],
            "mean_churn":
                f'{churn:.3f}'
        })

    return results


def evaluate_all_algorithms(algorithm_queues, kev_snapshots, kev_added_dates, vex_statements):
    """Evaluate all algorithms across multiple queue snapshots."""

    all_results = []

    for algorithm_name, queue_snapshots in algorithm_queues.items():

        results = evaluate_algorithm(
            algorithm_name=algorithm_name,
            queue_snapshots=queue_snapshots,
            kev_snapshots=kev_snapshots,
            kev_added_dates=kev_added_dates,
            vex_statements=vex_statements
        )

        all_results.extend(results)

    return all_results