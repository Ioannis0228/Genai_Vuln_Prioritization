"""
This module provides a function to calculate the recall at k for a given queue of findings and a set of KEV CVEs.
Recall at k is defined as the proportion of relevant items (KEV CVEs) that are
retrieved in the top k items of the queue.
"""

from typing import Set, Dict
from evaluation import get_relevant_findings


def recall_at_k(findings: Dict, relevant_findings_ids: Set[str], k: int)-> float:
    """Calculate finding-level Recall@K.
    
    Args:
        findings: Ordered findings with CVEs.
        relevant_findings_ids: IDs of relevant findings.
        k: Number of top-ranked findings to consider.

    Returns:
        float: Recall@K, i.e. the proportion of relevant findings appearing
        in the top K positions.
    """

    if not relevant_findings_ids or k <= 0:
        return 0.0

    top_k = list(findings.keys())[:k]

    hits = sum(1 for finding in top_k if finding in relevant_findings_ids)

    return hits / len(relevant_findings_ids)

def mean_recall_at_k(queue_snapshots, kev_snapshots, k: int, vex_statements)-> float:
    """Calculate the mean recall at k across multiple queue snapshots.
    
    Args:
        queue_snapshots (list): List of queue snapshots, each containing a list of findings.
        kev_snapshots (dict): Dictionary mapping snapshot dates to sets of KEV CVEs.
        k (int): The number of top items to consider for recall calculation.

    Returns:
        float: The mean recall at k value across all snapshots.
    """

    values = []

    for snapshot in queue_snapshots:

        relevant_findings_ids = get_relevant_findings(snapshot, kev_snapshots, vex_statements)

        values.append(recall_at_k(snapshot['findings'], relevant_findings_ids, k))

    return sum(values) / len(values) if values else 0.0