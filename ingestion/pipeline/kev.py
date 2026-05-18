import requests

def fetch_KEV():
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