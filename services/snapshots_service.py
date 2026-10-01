""" Service for creating snapshots for all CVEs existing in the database."""

from database import execute_select, Vulnerabilities, SBOM, SessionLocal, save_EPSS_snapshot, save_KEV_snapshot, save_queue_snapshots
from ingestion import fetch_EPSS, fetch_KEV, get_sha_map
from services.prioritization_service import ranking_sbom

def capture_snapshots(dates: list, save_queues: bool = True):
    """Create snapshots of EPSS and KEV data and create prioritization queues for the given dates.

    Args:
        dates (list): List of dates in YYYY-MM-DD format for which to create snapshots.
    """

    # Fetch all CVEs from the Vulnerabilities table
    with SessionLocal() as session:
        cve_rows = execute_select(
            session=session,
            selected_columns=[Vulnerabilities.cve_id],
        )

        sbom_ids_rows = execute_select(
            session=session,
            selected_columns=[SBOM.id],
        )

    cve_ids = [row[0] for row in cve_rows]
    sbom_ids = [row[0] for row in sbom_ids_rows]

    kev_sha_map = get_sha_map(dates)

    for date in dates:
        # Create EPSS snapshot for the given date
        epss_snapshot = fetch_EPSS(cve_ids=cve_ids, snapshot_date=date)
        if epss_snapshot:
            save_EPSS_snapshot(epss_snapshot, create_evidence=False)

        # Create KEV snapshot for the given date
        kev_snapshot = fetch_KEV(cve_ids=cve_ids, snapshot_date=date, sha_map=kev_sha_map)
        if kev_snapshot:
            save_KEV_snapshot(kev_snapshot, create_evidence=False)

        if save_queues:
            results = {}
            for sbom_id in sbom_ids:
                results[sbom_id] = ranking_sbom(sbom_id=sbom_id,
                                                snapshot_date=date,
                                                cvss_ranking=True,
                                                epss_ranking=True,
                                                cvss_epss_ranking=True)

            save_queue_snapshots(results, date)