""" 
This module contains functions to calculate the Normalized Discounted Cumulative Gain (NDCG)
at k for a given queue of findings and a set of relevant CVEs.
"""

import math
from typing import Set, Dict

from evaluation import get_relevant_findings


def dcg_at_k(findings: Dict, relevant_findings_ids: Set[str], k: int) -> float:
    """Calculate the Discounted Cumulative Gain (DCG) at k for a queue of findings and a set of relevant findings.

    Args:
        findings (Dict): Ordered dictionary of findings.
        relevant_findings_ids (Set[str]): Set of relevant findings.
        k (int): The number of top items to consider for DCG calculation.

    Returns:
        float: DCG@K value.
    """

    if not relevant_findings_ids or k <= 0:
        return 0.0

    top_k = list(findings.keys())[:k]

    dcg = 0.0

    for rank, finding_id in enumerate(top_k, start=1):

        if finding_id in relevant_findings_ids:
            dcg += 1 / math.log2(rank + 1)

    return dcg

def idcg_at_k(relevant_findings_ids: Set[str], k: int) -> float:
    """
    Calculate the Ideal Discounted Cumulative Gain (IDCG) at k for a given set of relevant findings.
    The IDCG is the maximum possible DCG for a given set of relevant items.
    """

    if not relevant_findings_ids or k <= 0:
        return 0.0
    
    ideal_relevant = min(len(relevant_findings_ids), k)

    idcg = 0.0

    for rank in range(1, ideal_relevant + 1):
        idcg += 1 / math.log2(rank + 1)

    return idcg

def ndcg_at_k(findings: Dict, relevant_findings_ids: Set[str], k: int) -> float:
    """ Calculate the Normilized Discounted Cumulative Gain at k (NDCG@K) for ordered findings and a set of relevant findings.

    Relevance is binary: a finding is either relevant (its CVE is in KEV) or not. The NDCG@K is the ratio of DCG@K to IDCG@K

    Args:
        findings (Dict): Ordered dictionary of findings.
        relevant_findings_ids (Set[str]): Set of relevant findings.
        k (int): The number of top items to consider for NDCG calculation.

    Returns:
        float: NDCG@K value.

    """

    if not relevant_findings_ids or k <= 0:
        return 0.0

    dcg = dcg_at_k(findings, relevant_findings_ids, k)
    idcg = idcg_at_k(relevant_findings_ids, k)

    if idcg == 0:
        return 0.0

    return dcg / idcg

def mean_ndcg_at_k(queue_snapshots, kev_snapshots, k: int, vex_statements) -> float:
    """Calculate the mean NDCG at k across multiple queue snapshots.

    Args:
        queue_snapshots (list): List of queue snapshots, each containing a list of findings.
        kev_snapshots (dict): Dictionary mapping snapshot dates to sets of KEV CVEs.
        k (int): The number of top items to consider for NDCG calculation.

    Returns:
        float: The mean NDCG at k value across all snapshots.
    """

    values = []

    for snapshot in queue_snapshots:

        relevant_findings_ids = get_relevant_findings(snapshot, kev_snapshots, vex_statements)

        values.append(ndcg_at_k(snapshot['findings'], relevant_findings_ids, k))

    return sum(values) / len(values) if values else 0.0