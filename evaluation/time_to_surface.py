""" Module for calculating the time it takes for a finding to surface in the queue after its CVE has been added as a KEV. """

from datetime import datetime
from typing import Optional, Dict, List
from statistics import mean, median

from evaluation import get_vex_status_at_date


def time_to_surface(finding: Dict, queue_snapshots, kev_date: datetime.date, k: int, vex_statements) -> Dict[str, Optional[int]]:
    """
    Calculate the time (in days) it takes for a finding to surface in the queue after, the CVE of that finding being added as a KEV.

    Args:
        finding (Dict): A dictionary representing the finding, containing its ID and CVE.
        queue_snapshots (list): A list of queue snapshots, each containing a snapshot date and a dictionary of findings.
        kev_date (datetime.date): The date when the CVE was added as a KEV
        k (int): The number of top items to consider for determining if the finding has surfaced.
        vex_statements (Dict): A dictionary mapping finding IDs to their VEX status history.

    Returns:
        Dict[str, Optional[int]]: A dictionary containing the finding ID, status, and days to surface (if applicable).
    """

    if kev_date is None or k <= 0:
        raise ValueError("KEV added date must be provided and k must be greater than 0.")

    snapshots = sorted(queue_snapshots, key=lambda x: x['snapshot_date'])

    # If the KEV was added before the first snapshot, we can't calculate the time to surface, as we don't have any data before that snapshot. 
    if kev_date < snapshots[0]['snapshot_date']:
        return {
            "finding_id": list(finding.keys())[0],
            "status": "KEV_added_before_first_snapshot",
            "days_to_surface": None
        }

    # If the KEV was added after the last snapshot, we cant calculate the time to surface, as we don't have any data after that snapshot.
    if kev_date > snapshots[-1]['snapshot_date']:
        return {
            "finding_id": list(finding.keys())[0],
            "status": "KEV_added_after_last_snapshot",
            "days_to_surface": None
        }

    # If KEV was added in snapshot window, we need to check subsequent snapshots to see if it surfaced.
    for snapshot in snapshots:

        if snapshot['snapshot_date'] < kev_date:
            continue

        status = get_vex_status_at_date(
            finding_id=list(finding.keys())[0],
            snapshot_date=snapshot['snapshot_date'],
            vex_history=vex_statements
        )

        if status in ['not_affected', 'fixed']:

            return {
                "finding_id": list(finding.keys())[0],
                "status": "Not_relevant_due_to_vex",
                "days_to_surface": None
            }

        top_k = list(snapshot['findings'].keys())[:k]

        if list(finding.keys())[0] in top_k:
            return {
                "finding_id": list(finding.keys())[0],
                "status": "Surfaced",
                "days_to_surface": (snapshot['snapshot_date'] - kev_date).days
            }

    return {
        "finding_id": list(finding.keys())[0],
        "status": "Never_surfaced",
        "days_to_surface": None
    }




def time_to_surface_all(kev_added_dates: Dict[str, str], queue_snapshots, k: int, vex_statements) -> List[Dict[str, Optional[int]]]:
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

    for kev_cve, added_date in kev_added_dates.items():

        finding = {id: cve for snapshot in queue_snapshots for id, cve in snapshot['findings'].items() if cve == kev_cve}

        if not finding:
            continue  # Skip if the finding is not present in any snapshot

        results.append(time_to_surface(
            finding=finding,
            queue_snapshots=queue_snapshots,
            kev_date=added_date,
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

    total = len(results)

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
            else 0.0
        ),
    }