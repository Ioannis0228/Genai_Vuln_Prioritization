""" 
This module contains functions to calculate the Normalized Discounted Cumulative Gain (NDCG)
at k for a given queue of findings and a set of relevant CVEs.
"""

import math
from typing import Optional, Set

from evaluation import get_relevant_items


def dcg_at_k(items: list, relevant_items: Set[str], k: int) -> float:
    """Calculate the Discounted Cumulative Gain (DCG) at k for a queue of findings and a set of relevant findings.

    Args:
        items (list): Ordered list of findings.
        relevant_items (Set[str]): Set of relevant findings.
        k (int): The number of top items to consider for DCG calculation.

    Returns:
        float: DCG@K value.
    """

    if not relevant_items or k <= 0:
        return 0.0

    top_k = items[:k]

    dcg = 0.0

    for rank, finding_id in enumerate(top_k, start=1):

        if finding_id in relevant_items:
            dcg += 1 / math.log2(rank + 1)

    return dcg

def idcg_at_k(relevant_items: Set[str], k: int) -> float:
    """
    Calculate the Ideal Discounted Cumulative Gain (IDCG) at k for a given set of relevant findings.
    The IDCG is the maximum possible DCG for a given set of relevant items.

    Args:
        relevant_items (Set[str]): Set of relevant findings.
        k (int): The number of top items to consider for IDCG calculation.

    Returns:
        float: IDCG@K value.
    """

    if not relevant_items or k <= 0:
        return 0.0
    
    ideal_relevant = min(len(relevant_items), k)

    idcg = 0.0

    for rank in range(1, ideal_relevant + 1):
        idcg += 1 / math.log2(rank + 1)

    return idcg

def ndcg_at_k(items: list, relevant_items: Set[str], k: int) -> float:
    """ Calculate the Normilized Discounted Cumulative Gain at k (NDCG@K) for ordered findings and a set of relevant findings.

    Relevance is binary: a finding is either relevant (its CVE is in KEV) or not. The NDCG@K is the ratio of DCG@K to IDCG@K

    Args:
        items (list): Ordered list of findings.
        relevant_items (Set[str]): Set of relevant findings.
        k (int): The number of top items to consider for NDCG calculation.

    Returns:
        float: NDCG@K value.

    """

    if not relevant_items or k <= 0:
        return 0.0

    dcg = dcg_at_k(items, relevant_items, k)
    idcg = idcg_at_k(relevant_items, k)

    if idcg == 0:
        return 0.0

    return dcg / idcg

def mean_ndcg_at_k(queue_snapshots, kev_snapshots, k: int, vex_statements, sbom_findings_set) -> Optional[float]:
    """Calculate the mean NDCG at k across multiple queue snapshots.

    Args:
        queue_snapshots (list): List of queue snapshots, each containing a list of findings.
        kev_snapshots (dict): Dictionary mapping snapshot dates to sets of KEV CVEs.
        k (int): The number of top items to consider for NDCG calculation.
        vex_statements (dict): Dictionary mapping (cve_id, finding_id) to VEX status.
        sbom_findings_set (set): Set of findings present in the SBOM.

    Returns:
        float: The mean NDCG at k value across all snapshots.
    """

    values = []

    for snapshot in queue_snapshots:

        relevant_items = get_relevant_items(snapshot, kev_snapshots, vex_statements, sbom_findings_set)
        if not relevant_items:
            continue  # Skip this snapshot if there are no relevant items

        values.append(ndcg_at_k(snapshot["findings"], relevant_items, k))

    return sum(values) / len(values) if values else None