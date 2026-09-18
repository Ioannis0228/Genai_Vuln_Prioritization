from collections import defaultdict
from typing import Dict, List, Set, Optional


def build_vex_history(vex_rows) -> Dict[int, List[dict]]:
    """Build chronological VEX history for each finding."""

    vex_history = defaultdict(list)

    for cve_id, finding_id, status, timestamp in vex_rows:
        vex_history[finding_id].append({
            "cve_id": cve_id,
            "status": status,
            "timestamp": timestamp,
        })

    for finding_id in vex_history:
        vex_history[finding_id].sort(
            key=lambda row: row["timestamp"]
        )

    return dict(vex_history)

def get_vex_status_at_date(finding_id, snapshot_date, vex_history: Dict[int, List[dict]]) -> Optional[str]:
    """Return the latest VEX status known at snapshot_date."""

    statements = vex_history.get(finding_id, [])

    latest_status = None

    for statement in statements:
        if statement["timestamp"].date() <= snapshot_date:
            latest_status = statement["status"]
        else:
            break

    return latest_status

def is_relevance(cve_id, snapshot_date, kev_by_date, vex_status) -> bool:
    """ Check if a finding is relevant based on KEV and VEX rules. 
    Returns:
        bool: True if the finding is relevant, False otherwise.
    """

    kev_cves = kev_by_date.get(snapshot_date)

    if cve_id not in kev_cves:
        return False

    # If the VEX status is 'not_affected' or 'fixed', the finding is not relevant.
    # If the VEX status is None or any other value, the finding is considered relevant.
    if vex_status in ['not_affected', 'fixed']:
        return False

    return True



def get_relevant_findings(snapshot: Dict, kev_by_date: Dict[str, set], vex_statements: Dict[tuple, str]) -> Set[str]:
    """ Get the set of relevant findings based on KEV and VEX rules.

    Args:
        snapshot (Dict): Ordered dictionary of findings.
        kev_by_date (Dict[str, set]): Dictionary mapping snapshot dates to sets of KEV CVEs.
        vex_statements (Dict[tuple, str]): Dictionary mapping (cve_id, finding_id) to VEX status.

    Returns:
        Set[str]: Set of relevant finding IDs.
    """

    relevant_findings_ids = set()

    for finding_id, cve_id in snapshot['findings'].items():
        snapshot_date = snapshot.get('snapshot_date')
        vex_status = get_vex_status_at_date(finding_id, snapshot_date, vex_statements)

        if is_relevance(cve_id=cve_id, snapshot_date=snapshot_date, kev_by_date=kev_by_date, vex_status=vex_status):
            relevant_findings_ids.add(finding_id)

    return relevant_findings_ids