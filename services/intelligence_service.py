from database import save_CSAF_advisory, save_CVE_CSAF_mapping, save_EPSS_snapshot, save_KEV_snapshot, CSAFadvisories, check_existence
from ingestion import fetch_RedHat_advisory, find_RHSA_id, fetch_EPSS, fetch_KEV


def process_intelligence(CVEs_id):
    save_KEV_snapshot(fetch_KEV())

    print("Fetching EPSS data...", flush=True)
    save_EPSS_snapshot(fetch_EPSS(CVEs_id))

    print("Fetching CSAF advisories...", flush=True)
    csaf_vuln = []

    for cve in CVEs_id:
        RHSA_ids = find_RHSA_id(cve)
        if RHSA_ids:
            for rhsa in RHSA_ids:
                if not check_existence(CSAFadvisories, CSAFadvisories.csaf_id, rhsa):
                    save_CSAF_advisory(cve, fetch_RedHat_advisory(rhsa), rhsa)
                    # print(f"Saved CSAF advisory for {cve} (RHSA: {rhsa})")
                # else:
                    # print(f"CSAF advisory for {cve} (RHSA: {rhsa}) already exists in the database.")       

                csaf_vuln.append({
                    "cve_id": cve,
                    "csaf_id": rhsa
                })

    save_CVE_CSAF_mapping(csaf_vuln)