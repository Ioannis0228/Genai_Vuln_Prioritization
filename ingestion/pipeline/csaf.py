import requests

def fetch_RedHat_advisory(RHSA_ID):
    url = f'https://access.redhat.com/hydra/rest/securitydata/csaf/{RHSA_ID}.json'

    try:
        res = requests.get(url, timeout=10)
        data = res.json()
        return data
    except Exception:
        print(f"Error fetching CSAF advisory for {url}")
        return None

def find_RHSA_id(CVE):
    url = f'https://access.redhat.com/hydra/rest/securitydata/csaf.json?cve={CVE}'

    try:
        res = requests.get(url, timeout=10)
        data = res.json()
        if data:
            return [r["RHSA"] for r in data]
        else:
            print(f"No RHSA found for {CVE}")
            return []
    except Exception:
        print(f"Error searching for RHSA ID for {CVE}")
        return []