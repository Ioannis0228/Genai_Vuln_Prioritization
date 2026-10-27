"""CISA Known Exploited Vulnerabilities (KEV) catalog fetcher.

This module retrieves the current KEV catalog from CISA's GitHub repository, 
or fetches the catalog as it existed on a specific date by using the commit history of the KEV file.
The KEV catalog lists CVEs that are known to be actively exploited in the wild.
This information significantly boosts vulnerability priority in the fusion score.
"""

import requests
from datetime import datetime, date
from typing import Any

def get_kev_commits(start_date: date, end_date: date) -> list[dict[str, Any]]:
    """Fetch KEV file commit history from GitHub.

    Retrieves all commits that modified the KEV catalog between the
    requested date range.

    GitHub returns a maximum of 100 commits per page, so pagination is
    handled automatically.

    Args:
        start_date: Earliest date we need a snapshot for.
        end_date: Latest date we need a snapshot for.

    Returns:
        List of commit metadata dictionaries.
    """

    commits: list[dict[str, Any]] = []

    page = 1

    while True:
        params = {
            "path": "known_exploited_vulnerabilities.json",
            "until": f"{end_date:%Y-%m-%d}T23:59:59Z",
            "per_page": 100,
            "page": page,
        }

        response = requests.get(
            "https://api.github.com/repos/cisagov/kev-data/commits",
            headers={"Accept": "application/vnd.github+json"},
            params=params,
            timeout=10,
        )

        response.raise_for_status()

        page_commits = response.json()

        if not page_commits:
            break

        commits.extend(page_commits)

        # GitHub returns commits newest -> oldest.
        # Once the oldest commit on this page is before our
        # earliest required date, we have enough history.
        oldest_commit = page_commits[-1]

        oldest_date = datetime.fromisoformat(
            oldest_commit["commit"]["committer"]["date"].replace("Z", "+00:00")
        ).date()

        if oldest_date <= start_date:
            break

        page += 1

    return commits

def build_sha_map(dates: list[date], commits: list[dict[str, Any]]) -> dict[date, str]:
    """Map every requested snapshot date to the appropriate KEV commit SHA.

    For each snapshot date, the selected commit is the latest commit
    to the KEV file that occurred on or before that date.

    Args:
        dates: Snapshot dates to resolve.
        commits: KEV commit history returned by get_kev_commits().

    Returns:
        Dictionary mapping snapshot date -> commit SHA.
    """



    commit_dates = [ 
        {
            "date": datetime.fromisoformat(c["commit"]["committer"]["date"].replace("Z", "+00:00")).date(),
            "sha": c["sha"] 
        }
        for c in commits
    ]

    # GitHub returns newest -> oldest.
    # Convert to oldest -> newest to make the mapping straightforward.
    sorted_commit_dates = sorted(commit_dates, key=lambda item: item["date"])

    sha_map: dict[date, str] = {}

    for snapshot_date in dates:

        selected_sha: str | None = None

        for commit in sorted_commit_dates:
            commit_date = commit["date"]

            if commit_date <= snapshot_date:
                selected_sha = commit["sha"]
            else:
                # Commits are sorted oldest -> newest, so once we've
                # passed the snapshot date we can stop.
                break

        if selected_sha is not None:
            sha_map[snapshot_date] = selected_sha

    return sha_map


def get_sha_map(dates: list[date]) -> dict[date, str]:
    """Get a mapping of snapshot dates to commit SHAs.

    This function fetches the commit history for the KEV data and builds a map
    of each requested snapshot date to the appropriate commit SHA.

    Args:
        dates: Snapshot dates.
    Returns:
        Dictionary mapping snapshot date -> commit SHA.
    """

    commits = get_kev_commits(
        start_date=min(dates),
        end_date=max(dates),
    )
    return build_sha_map(dates, commits)

def fetch_KEV(cve_ids: list[str], snapshot_date: date | None = None, sha_map: dict[date, str] | None = None) -> list[dict]:
    """Fetch the current KEV catalog and normalize it into database-ready rows.
    
    Connects to CISA's official KEV repository and extracts CVE metadata including
    when each CVE was added to the catalog and its brief description.

    Args:
        cve_ids (list[str]): List of CVE IDs to filter the KEV catalog. 
                             Only CVEs present in this list will be returned.
        snapshot_date (date, optional): If provided, fetches the KEV catalog as it existed on this date.
                             The date must be in YYYY-MM-DD format and after 2025-01-27. If None, fetches the latest catalog.
        sha_map (dict[date, str], optional): A mapping of snapshot dates to commit SHAs.
                             This is required if snapshot_date is provided, to determine which commit to fetch.
    
    Returns:
        list: List of dicts with keys: cve_id, catalog_added_date, shortDescription.
              Returns empty list on network failure (resilient fallback).
    """

    cve_ids = set(cve_ids)
    if snapshot_date and snapshot_date < date(2025, 1, 27):
        raise ValueError("The provided date is before the earliest available KEV data.")

    elif snapshot_date and snapshot_date > date.today():
        raise ValueError("The provided date is in the future. Please provide a valid date.")

    elif snapshot_date:
        if sha_map is None:
            raise ValueError("sha_map must be provided when a date is specified.")

        sha = sha_map.get(snapshot_date)

        # Construct the URL to fetch the KEV catalog at that specific commit
        url = f"https://raw.githubusercontent.com/cisagov/kev-data/{sha}/known_exploited_vulnerabilities.json"

    else: 
        url = "https://raw.githubusercontent.com/cisagov/kev-data/refs/heads/develop/known_exploited_vulnerabilities.json"
    
    KEV_data = [] 
    try:
        res = requests.get(url, timeout=3)
        vulnerabilities = res.json().get("vulnerabilities", [])
        for vuln in vulnerabilities:
            if vuln.get("cveID") in cve_ids:
                KEV_data.append({
                    "cve_id": vuln.get("cveID"),
                    "catalog_added_date": vuln.get("dateAdded"),
                    "shortDescription": vuln.get("shortDescription"),
                    "snapshot_date": snapshot_date if snapshot_date else date.today(),
                })

    except Exception:
        print("Error fetching KEV data")
        return []

    return KEV_data