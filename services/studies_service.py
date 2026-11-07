from database import save_queue_snapshots
from evaluation.ablation_studies import sbom_ablation, epss_kev_ablation
from services.sbom_service import get_all_sboms


def run_ablation_studies(dates: list):
    """
    Run the ablation studies for the specified SBOM and snapshot date.

    Args:
        dates (list): The dates for retrieving the appropriate snapshots.

    Returns:
        dict: A dictionary containing the results of the ablation studies.
    """

    sboms = get_all_sboms()

    results = {}
    for date in dates:
        # SBOM ablation study creates a single queue across all SBOMs
        sbom_ablation_results = sbom_ablation(snapshot_date=date)

        for sbom_id, _ in sboms:
            results[sbom_id] = {
                "sbom_ablation": sbom_ablation_results,
                **epss_kev_ablation(sbom_id=sbom_id, snapshot_date=date)
            }

        save_queue_snapshots(results, date)

    return results