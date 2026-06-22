"""Red Hat CSAF advisory fetcher and RHSA ID mapper.

This module interfaces with Red Hat's CSAF (Common Security Advisory Format) API to
fetch detailed security advisories. CSAF documents provide vendor-specific remediation
guidance.
"""

import requests

def fetch_RedHat_advisory(RHSA_ID: str) -> dict:
    """Fetch a single Red Hat CSAF advisory document by RHSA identifier.
    
    Args:
        RHSA_ID (str): Red Hat Security Advisory ID (e.g., 'RHSA-2021:1234').
    
    Returns:
        dict: Full CSAF advisory JSON document, or None on network failure.
    """
    
    url = f'https://access.redhat.com/hydra/rest/securitydata/csaf/{RHSA_ID}.json'

    try:
        res = requests.get(url, timeout=10)
        data = res.json()
        return data
    except Exception:
        print(f"Error fetching CSAF advisory for {url}")
        return None

def find_RHSA_id(CVE: str) -> list:
    """Return the Red Hat RHSA identifiers associated with a CVE.
    
    Queries Red Hat's CSAF index to find all RHSA IDs that cover a given CVE.
    This enables fetching detailed vendor guidance for a vulnerability.
    
    Args:
        CVE (str): CVE identifier (e.g., 'CVE-2021-1234').
    
    Returns:
        list: RHSA identifiers (e.g., ['RHSA-2021:1234', 'RHSA-2021:5678']) or empty list if none found.
        
        Empty list also returned on network failure (graceful fallback).
    """
    
    url = f'https://access.redhat.com/hydra/rest/securitydata/csaf.json?cve={CVE}'

    try:
        res = requests.get(url, timeout=10)
        data = res.json()
        if data:
            return [r["RHSA"] for r in data]
        else:
            # print(f"No RHSA found for {CVE}")
            return []
    except Exception:
        print(f"Error searching for RHSA ID for {CVE}")
        return []