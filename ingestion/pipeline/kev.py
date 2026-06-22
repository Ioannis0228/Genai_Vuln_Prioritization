"""CISA Known Exploited Vulnerabilities (KEV) catalog fetcher.

This module retrieves the current KEV catalog from CISA's GitHub repository.
The KEV catalog lists CVEs that are known to be actively exploited in the wild.
This information significantly boosts vulnerability priority in the fusion score.
"""

import requests

def fetch_KEV():
    """Fetch the current KEV catalog and normalize it into database-ready rows.
    
    Connects to CISA's official KEV repository and extracts CVE metadata including
    when each CVE was added to the catalog and its brief description.
    
    Returns:
        list: List of dicts with keys: cve_id, catalog_added_date, shortDescription.
              Returns empty list on network failure (resilient fallback).
    """
    
    url = "https://raw.githubusercontent.com/cisagov/kev-data/refs/heads/develop/known_exploited_vulnerabilities.json"
    
    KEV_data = [] 
    try:
        res = requests.get(url, timeout=3)
        vulnerabilities = res.json().get("vulnerabilities", [])
        for vuln in vulnerabilities:
            KEV_data.append({
                "cve_id": vuln.get("cveID"),
                "catalog_added_date": vuln.get("dateAdded"),
                "shortDescription": vuln.get("shortDescription"),
            })

    except Exception:
        print("Error fetching KEV data")
        return []

    return KEV_data