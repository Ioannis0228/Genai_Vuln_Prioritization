"""NVD API integration for fetching CVSS scores.

This module queries the National Vulnerability Database (NIST NVD) for CVSS scoring data.
It prioritizes newer CVSS versions (V4.0 > V3.x > V2.0) and handles network failures gracefully.
"""

import requests

def fetch_nvd_cvss(cve_id):
    """Fetch the best available CVSS score and version for a CVE from NVD.
    
    Prioritizes CVSS versions in order: V4.0 > V3.1 > V3.0 > V2.0.
    Returns None on network errors or if the CVE is not found in NVD.
    
    Args:
        cve_id (str): CVE identifier (e.g., 'CVE-2021-1234').
    
    Returns:
        tuple: (score, version) where score is a float (0-10) and version is a string ('4.0', '3.1', '3.0', '2.0').
               Returns (None, None) on network failure or missing data.
    """
    
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    try:
        res = requests.get(url, timeout=3)
        data = res.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None, None

        metrics = vulns[0]["cve"].get("metrics", {})

        if metrics.get("cvssMetricV4"):
            return metrics["cvssMetricV4"][0]["cvssData"]["baseScore"], "4.0"
        if metrics.get("cvssMetricV31"):
            return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"], "3.1"
        if metrics.get("cvssMetricV30"):
            return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"], "3.0"
        if metrics.get("cvssMetricV2"):
            return metrics["cvssMetricV2"][0]["cvssData"]["baseScore"], "2.0"
        

    except Exception:
        print(f"Error fetching CVSS for {cve_id}")
        return None, None