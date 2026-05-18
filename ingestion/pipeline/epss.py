import requests

def fetch_EPSS(cve_list, date=None):
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

def create_epss_url(cve_list, max_len=1950):
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