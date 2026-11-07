from collections import defaultdict
from typing import Dict, List, Set, Optional


def build_vex_history(vex_rows) -> Dict[int, List[dict]]:
    """Build chronological VEX history for each finding."""

    vex_history = defaultdict(list)

    for cve_id, purl, status, sbom_id, timestamp in vex_rows:
        key = (cve_id, purl)
        vex_history[key].append({
            "sbom_id": sbom_id,
            "status": status,
            "timestamp": timestamp,
        })

    for key in vex_history:
        vex_history[key].sort(
            key=lambda row: row["timestamp"]
        )

    return dict(vex_history)

def get_vex_status_at_date(cve_id: str, purl: str, snapshot_date, vex_history: Dict[tuple, List[dict]]) -> Optional[str]:
    """Return the latest VEX status known at snapshot_date."""

    statements = vex_history.get((cve_id, purl), [])

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


def get_relevant_items(snapshot: Dict, kev_by_date: Dict[str, set], vex_statements: Dict[tuple, str], sbom_findings_set: Set[tuple]) -> Set[str]:
    """ Get the set of relevant items based on KEV and VEX rules.

    Args:
        snapshot (Dict): Ordered dictionary of findings.
        kev_by_date (Dict[str, set]): Dictionary mapping snapshot dates to sets of KEV CVEs.
        vex_statements (Dict[tuple, str]): Dictionary mapping (cve_id, finding_id) to VEX status.
        sbom_findings_set (Set[tuple]): Set of findings present in the SBOM.

    Returns:
        Set[str]: Set of relevant items.
    """

    relevant_items = set(tuple())

    for (cve_id, purl) in snapshot["findings"]:
        
        if (cve_id, purl) not in sbom_findings_set:
            continue 

        snapshot_date = snapshot.get("snapshot_date")
        vex_status = get_vex_status_at_date(cve_id, purl, snapshot_date, vex_statements)

        if is_relevance(cve_id=cve_id, snapshot_date=snapshot_date, kev_by_date=kev_by_date, vex_status=vex_status):
            relevant_items.add((cve_id, purl))

    return relevant_items