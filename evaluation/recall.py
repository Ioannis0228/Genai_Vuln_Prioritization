"""
This module provides a function to calculate the recall at k for a given queue of findings and a set of KEV CVEs.
Recall at k is defined as the proportion of relevant items (KEV CVEs) that are
retrieved in the top k items of the queue.
"""

from typing import Optional, Set
from evaluation import get_relevant_items


def recall_at_k(items: list, relevant_items: Set[str], k: int)-> float:
    """Calculate finding-level Recall@K.
    
    Args:
        items: Ordered items.
        relevant_items: IDs of relevant items.
        k: Number of top-ranked items to consider.

    Returns:
        float: Recall@K, i.e. the proportion of relevant items appearing
        in the top K positions.
    """

    if not relevant_items or k <= 0:
        return 0.0

    top_k = items[:k]

    hits = sum(1 for item in top_k if item in relevant_items)

    return hits / len(relevant_items)

def mean_recall_at_k(queue_snapshots, kev_snapshots, k: int, vex_statements, sbom_findings_set)-> Optional[float]:
    """Calculate the mean recall at k across multiple queue snapshots.
    
    Args:
        queue_snapshots (list): List of queue snapshots, each containing a list of findings.
        kev_snapshots (dict): Dictionary mapping snapshot dates to sets of KEV CVEs.
        k (int): The number of top items to consider for recall calculation.
        vex_statements (dict): Dictionary mapping (cve_id, finding_id) to VEX status.
        sbom_findings_set (set): Set of findings present in the SBOM.

    Returns:
        float: The mean recall at k value across all snapshots.
    """

    values = []

    for snapshot in queue_snapshots:

        relevant_items = get_relevant_items(snapshot, kev_snapshots, vex_statements, sbom_findings_set)
        if not relevant_items:
            continue  # Skip this snapshot if there are no relevant items

        values.append(recall_at_k(snapshot["findings"], relevant_items, k))

    return sum(values) / len(values) if values else None