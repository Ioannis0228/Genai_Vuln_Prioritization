""" Module for calculating the stability of a finding queue over time. """


def queue_churn(previous_queue, current_queue, k: int) -> float:
    """Calculate the churn between two finding queues at k.
    
    Churn is defined as the proportion of findings in the top k of the previous queue
    that are not present in the top k of the current queue.

    Args:
        previous_queue (dict): Ordered dictionary of findings from the previous snapshot.
        current_queue (dict): Ordered dictionary of findings from the current snapshot.
        k (int): The number of top items to consider for churn calculation.

    Returns:
        float: Churn value, ranging from 0.0 (no churn) to 1.0 (complete churn).
    """

    if k <= 0:
        return None
    
    previous = set(previous_queue[:k])
    current = set(current_queue[:k])

    overlap = len(previous.intersection(current))

    return 1 - (overlap / k)

def calculate_churn(queue_snapshots, k: int) -> list:
    """Calculate churn values for a series of queue snapshots at k.
    
    Args:
        queue_snapshots (list): List of queue snapshots, each containing a list of findings.
        k (int): The number of top items to consider for churn calculation.

    Returns:
        list: A list of churn values for each pair of consecutive snapshots.
    """

    snapshots = sorted(queue_snapshots, key=lambda x: x["snapshot_date"])

    churn_values = []

    for previous, current in zip(snapshots,snapshots[1:]):
        if len(previous["findings"])>=k and len(current["findings"])>=k:
            value = queue_churn(previous["findings"], current["findings"], k)
            if value is not None:
                churn_values.append(value)

    return churn_values

def mean_churn(queue_snapshots, k: int) -> float:
    """
    Calculate the mean churn across multiple queue snapshots at k.
    
    Args:
        queue_snapshots (list): List of queue snapshots, each containing a list of findings.
        k (int): The number of top items to consider for churn calculation.

    Returns:
        float: The mean churn value across all pairs of consecutive snapshots.
    """

    values = calculate_churn(queue_snapshots, k)

    return (sum(values) / len(values)
        if values
        else None
    )