"""EPSS (Exploit Prediction Scoring System) score fetcher from FIRST.org.

This module queries the FIRST EPSS API to fetch the latest exploitation probability and
percentile scores for a batch of CVEs. It handles URL length limits by chunking requests.
"""

import io
import csv
import gzip
from  datetime import datetime, date
import requests



def fetch_EPSS(cve_ids: list[str], snapshot_date: date | None = None) -> list[dict]:
    """Fetch EPSS scores for a list of CVEs and return normalized snapshot rows.
    
    Args:
        cve_ids (list[str]): List of CVE identifiers to fetch (e.g., ['CVE-2021-1234', 'CVE-2022-5678']).
        snapshot_date (date, optional): Date for historical scores in format YYYY-MM-DD (after 2021-04-14).
    Returns:
        list[dict]: List of dictionaries containing the fetched EPSS scores.
    """

    if snapshot_date is None:
        url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

    elif snapshot_date < date(2021, 4, 14):
        raise ValueError("EPSS scores are not available for dates before 2021-04-14.")
    
    else:
        url = (f"https://raw.githubusercontent.com/empiricalsec/epss_scores/master/{snapshot_date.year}/epss_scores-{snapshot_date:%Y-%m-%d}.csv.gz")

    results = []

    with requests.get(url, stream=True, timeout=30) as response:
        response.raise_for_status()

        # requests gives us the compressed response stream.
        with gzip.GzipFile(fileobj=response.raw, mode="rb") as gz:
            text = io.TextIOWrapper(gz, encoding="utf-8")

            if snapshot_date is None or snapshot_date >= date(2022, 2, 4): 
                # After 2022-02-04, the EPSS CSV format changed to include a header row with the snapshot date.
                first_line = text.readline().strip()
                if snapshot_date is None:
                    raw_date_part = first_line.split(",")[1]
                    snapshot_date = datetime.strptime(
                        raw_date_part.replace("score_date:", "").split("T")[0].strip(),"%Y-%m-%d"
                    ).date()

            reader = csv.DictReader(text)

            for row in reader:
                if row["cve"] not in cve_ids:
                    continue

                results.append({
                    "cve_id": row["cve"],
                    "epss_score": float(row["epss"]),
                    "percentile": float(row.get("percentile", 0.0)),
                    "score_date": snapshot_date,
                })

    return results