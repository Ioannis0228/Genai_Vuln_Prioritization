"""EPSS (Exploit Prediction Scoring System) score fetcher from FIRST.org.

This module queries the FIRST EPSS API to fetch the latest exploitation probability and
percentile scores for a batch of CVEs. It handles URL length limits by chunking requests.
"""

import requests

def fetch_EPSS(cve_list: list, date=None) -> list:
    """Fetch EPSS scores for a list of CVEs and return normalized snapshot rows.
    
    Splits long CVE lists into multiple API requests due to URL length constraints (max ~1950 chars).
    
    Args:
        cve_list (list): CVE identifiers to fetch (e.g., ['CVE-2021-1234', 'CVE-2022-5678']).
        date (str, optional): Date in YYYY-MM-DD format for historical scores (since 2021-04-14).
    
    Returns:
        list: List of dicts with keys: cve_id, epss_score (float 0-1), percentile (float 0-1), score_date.
              Empty list if all requests fail.
    """
    
    # Date in the format YYYY-MM-DD (since April 14, 2021)
    limit = len(cve_list)

    if not cve_list:
        return []
    
    urls = create_epss_url(cve_list)

    if date:
        for i, url in enumerate(urls):
            urls[i] = url + f"&date={date}"
    
    # The EPSS API has a default limit of 100 CVEs per request
    # If we have more than 100 CVEs, we need to set the limit parameter in the URL
    if limit > 100:
        for i, url in enumerate(urls):
            urls[i] = url + f"&limit={limit}"

    EPSS_data = []
    for url in urls:
        try:
            res = requests.get(url, timeout=3)
            data = res.json()
            for item in data.get("data", []):
                EPSS_data.append(
                    {
                        "cve_id": item["cve"],
                        "epss_score": item["epss"],
                        "percentile": item["percentile"],
                        "score_date": item["date"]
                    }
                )
            
        except Exception:
            print("Error fetching EPSS data for URL:", url)
    
    return EPSS_data

def create_epss_url(cve_list: list, max_len=1950) -> list:
    """Split a CVE list into FIRST EPSS API-safe query URLs.
    
    The EPSS API has a maximum URL length of ~2000 characters. This function chunks
    the CVE list into multiple URLs, each with a ?cve=ID1,ID2,ID3... parameter.
    
    Args:
        cve_list (list): CVE identifiers to split.
        max_len (int): Maximum URL parameter length (default 1950 for safety margin).
    
    Returns:
        list: List of complete EPSS API URLs ready for HTTP GET requests.
    """
    
    # EPSS API has a max URL length of 2000 chars, we need to split the CVE list into chunks
    base_url = "https://api.first.org/data/v1/epss"
    prefix = "?cve="
    urls = []
    
    current = prefix

    for cve in cve_list:
        # if first item, no comma
        separator = "" if current == prefix else ","
        addition = separator + cve

        if len(current) + len(addition) > max_len:
            urls.append(base_url+current)
            current = prefix + cve
        else:
            current += addition

    if current != prefix:
        urls.append(base_url+current)

    return urls