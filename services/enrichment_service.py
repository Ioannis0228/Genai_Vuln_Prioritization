"""Service layer for persisting vulnerability enrichment link data."""

from ingestion import fetch_vulnerability_links
from database import save_vuln_enrichment, get_CVE_ids

def vuln_enrichment(sbom_id: int):
    """Fetch vulnerability enrichment data from the Vulnerability-Lookup in batches and persist it to the database."""

    # Retrieve CVE IDs associated with the given SBOM ID
    CVE_ids = get_CVE_ids(sbom_id)

    print("Starting vulnerability enrichment...", flush=True)

    BUFFER_SIZE = 100
    links_dict = []

    for cve in CVE_ids:
        links_dict.append(fetch_vulnerability_links(cve))

        if len(links_dict) >= BUFFER_SIZE:
            save_vuln_enrichment(links_dict)
            links_dict.clear()

    if links_dict:
        save_vuln_enrichment(links_dict)