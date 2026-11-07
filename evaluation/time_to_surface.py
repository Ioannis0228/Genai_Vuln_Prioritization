""" Module for calculating the time it takes for a finding to surface in the queue after its CVE has been added as a KEV. """

from datetime import datetime
from typing import Optional, Dict, List
from statistics import mean, median

from evaluation import get_vex_status_at_date


def time_to_surface(item: tuple, queue_snapshots, kev_date: datetime.date, k: int, vex_statements) -> Dict[str, Optional[int]]:
    """
    Calculate the time (in days) it takes for a finding to surface in the queue after, the CVE of that finding being added as a KEV.

    Args:
        item (tuple): A tuple representing the finding, containing its cve_id and purl.
        queue_snapshots (list): A list of queue snapshots, each containing a snapshot date and a dictionary of findings.
        kev_date (datetime.date): The date when the CVE was added as a KEV
        k (int): The number of top items to consider for determining if the finding has surfaced.
        vex_statements (Dict): A dictionary mapping finding IDs to their VEX status history.

    Returns:
        Dict[str, Optional[int]]: A dictionary containing the finding ID, status, and days to surface (if applicable).
    """

    if kev_date is None or k <= 0:
        raise ValueError("KEV added date must be provided and k must be greater than 0.")

    snapshots = sorted(queue_snapshots, key=lambda x: x["snapshot_date"])

    def result(status: str, days: Optional[int] = None):
        return {
            "item": item,
            "status": status,
            "days_to_surface": days
        }

    # If the KEV was added before the first snapshot, we can't calculate the time to surface, as we don't have any data before that snapshot. 
    if kev_date < snapshots[0]["snapshot_date"]:
        return result("KEV_added_before_first_snapshot")

    # If the KEV was added after the last snapshot, we cant calculate the time to surface, as we don't have any data after that snapshot.
    if kev_date > snapshots[-1]["snapshot_date"]:
        return result("KEV_added_after_last_snapshot")

    # If KEV was added in snapshot window, we need to check subsequent snapshots to see if it surfaced.
    for snapshot in snapshots:

        if snapshot["snapshot_date"] < kev_date:
            continue

        status = get_vex_status_at_date(
            cve_id=item[0],
            purl=item[1],
            snapshot_date=snapshot["snapshot_date"],
            vex_history=vex_statements
        )

        if status in ['not_affected', 'fixed']:
            return result("Not_relevant_due_to_vex")

        top_k = snapshot["findings"][:k]

        if item in top_k:
            return result("Surfaced", (snapshot["snapshot_date"] - kev_date).days)

    return result("Never_surfaced")



def time_to_surface_all(kev_added_dates: Dict[str, str], queue_snapshots, k: int, vex_statements, sbom_findings_set) -> List[Dict[str, Optional[int]]]:
    """
    Calculate the time to surface for all findings in the queue snapshots based on their KEV added dates.
    
    Args:
        kev_added_dates (Dict[str, str]): A dictionary mapping KEV CVEs to their added dates.
        queue_snapshots (list): A list of queue snapshots, each containing a snapshot date and a dictionary of findings.
        k (int): The number of top items to consider for determining if the finding has surfaced.
        vex_statements (Dict): A dictionary mapping finding IDs to their VEX status history.
    
    Returns:
        List[Dict[str, Optional[int]]]: A list of dictionaries containing the finding ID, status, and days to surface (if applicable) for each finding.
    """

    results = []

    unique_items = dict.fromkeys(item for snapshot in queue_snapshots for item in snapshot["findings"] if item in sbom_findings_set)

    for item in unique_items:
        cve_id, _ = item
        kev_date = kev_added_dates.get(cve_id)

        if kev_date is None:
            continue 

        results.append(time_to_surface(
            item=item,
            queue_snapshots=queue_snapshots,
            kev_date=kev_date,
            k=k,
            vex_statements=vex_statements
        ))

    return results

def summarize_time_to_surface(results: list[Dict[str, any]]) -> dict:
    """
    Summarize the time to surface results by calculating the median and mean days to surface, as well as the surface rate.

    Args:
        results (list[Dict[str, any]]): A list of dictionaries containing the finding ID, status, and days to surface (if applicable) for each finding.

    Returns:
        dict: A summary dictionary containing the mean and median days to surface, surfaced count, 
        KEV added outside snapshot window count, never surfaced count, not relevant due to VEX count,
        total count, and surface rate.
    """

    total = sum(r["status"] in ["Surfaced", "Never_surfaced"] for r in results)

    surfaced_days = [
        result["days_to_surface"]
        for result in results
        if result["days_to_surface"] is not None and result["status"] == "Surfaced"
    ]

    kev_outside_snapshot_window = sum(
        result["status"] == "KEV_added_before_first_snapshot" or result["status"] == "KEV_added_after_last_snapshot"
        for result in results
    )

    never_surfaced_count = sum(
        result["status"] == "Never_surfaced"
        for result in results
    )

    not_relevant_due_to_vex_count = sum(
        result["status"] == "Not_relevant_due_to_vex"
        for result in results
    )


    surfaced_count = len(surfaced_days)

    return {
        "mean_tts_days": (
            mean(surfaced_days)
            if surfaced_days
            else None
        ),

        "median_tts_days": (
            median(surfaced_days)
            if surfaced_days
            else None
        ),

        "surfaced_count": surfaced_count,

        "kev_added_outside_snapshot_window": (
           kev_outside_snapshot_window
        ),

        "never_surfaced_count": (
            never_surfaced_count
        ),

        "not_relevant_due_to_vex_count": (
            not_relevant_due_to_vex_count 
        ),

        "total_count": total,

        "surface_rate": (
            surfaced_count / total
            if total > 0
            else None
        ),
    }