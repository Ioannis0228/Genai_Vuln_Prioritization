from ingestion import fetch_vulnerability_links
from database import save_vuln_enrichment

def vuln_enrichment(cve_id):
    print("Starting vulnerability enrichment...", flush=True)

    BUFFER_SIZE = 100
    links_dict = []

    for cve in cve_id:
        links_dict.append(fetch_vulnerability_links(cve))

        if len(links_dict) >= BUFFER_SIZE:
            print(f"Processing enrichment for CVE: {cve}", flush=True)
            save_vuln_enrichment(links_dict)
            links_dict.clear()

    if links_dict:
        save_vuln_enrichment(links_dict)