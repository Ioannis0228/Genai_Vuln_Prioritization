"""Helpers that invoke Trivy and extract CVE records from the resulting scan output.

This module acts as a bridge to Trivy, an open-source vulnerability scanner.
It runs Trivy on an SBOM, captures the JSON output, and normalizes the vulnerability
findings into database-ready records with CVSS metadata.
"""

import json
import subprocess

def mapping_cve(SBOM_PATH: str, OUTPUT_PATH: str) -> list:
    """Run Trivy against an SBOM and convert the findings into normalized CVE rows.
    
    Executes: trivy sbom <SBOM_PATH> --format json
    Writes raw output to OUTPUT_PATH for audit/debugging purposes.
    Extracts CVE findings and enriches them with CVSS data from Trivy.
    
    Args:
        SBOM_PATH (str): Path to the CycloneDX SBOM JSON file.
        OUTPUT_PATH (str): Path where the raw Trivy JSON output will be written.
    
    Returns:
        list: List of dicts with keys: purl, cve_id, description, cvss_score, 
              cvss_version, cvss_source, published_date.
    
    Raises:
        Exception: If Trivy returns a non-zero exit code or produces empty output.
    """

    result = subprocess.run(
        ["trivy", "sbom", SBOM_PATH, "--format", "json"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("ERROR:", result.stderr)
        raise Exception("Trivy failed")

    if not result.stdout.strip(): 
        raise Exception("Empty output from Trivy scan")
    data = json.loads(result.stdout)


    with open(OUTPUT_PATH, 'w') as f:
        json.dump(data, f, ensure_ascii=False,sort_keys=True, indent=4)

    component_cve = []
        
    for r in data.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            if not v.get("VulnerabilityID", "").startswith("CVE-"):
                continue

            cvss_score, cvss_version, cvss_source = extract_cvss(v.get("CVSS", {}))

            component_cve.append({
                "purl": v["PkgIdentifier"]["PURL"],
                "cve_id": v["VulnerabilityID"],
                "description": v["Description"],
                "cvss_score": cvss_score,
                "cvss_version": cvss_version,
                "cvss_source": cvss_source,
                "published_date": v.get("PublishedDate")
            })    

    return component_cve
    

def extract_cvss(cvss_dict):
    """Extract the best available CVSS score, version, and source label from Trivy data.
    
    Trivy may report multiple CVSS versions from different sources (nvd, redhat, ghsa).
    This function prioritizes V4.0 > V3.x > V2.0 and returns the first available.
    
    Precedence logic:
    1. Try nvd source first (NVD is most authoritative)
    2. Fall back to redhat or ghsa if NVD not available
    3. Within a source, prioritize V4.0 > V3.1 > V3.0 > V2.0
    
    Args:
        cvss_dict (dict): CVSS data from Trivy output with keys like 'nvd', 'redhat', 'ghsa'.
            May be empty or None.
    
    Returns:
        tuple: (score, version, source_name) where:
            - score is a float (0-10)
            - version is '4.0', '3.1', '3.0', or '2.0'
            - source_name is 'nvd', 'redhat', or 'ghsa'
            - Returns (None, None, None) if no CVSS data is available.
    """
    
    if not cvss_dict:
        return None, None, None

    for name in ["nvd", "redhat", "ghsa"]:
        source_dict = cvss_dict.get(name)
        if source_dict:
            break
    else:
        return None, None, None

    if "V40Score" in source_dict:
        return source_dict["V40Score"], "4.0", name

    if "V3Score" in source_dict:
        if source_dict.get("V3Vector").startswith("CVSS:3.1"):
            version = "3.1"
        elif source_dict.get("V3Vector").startswith("CVSS:3.0"):
            version = "3.0"
        return source_dict["V3Score"], version, name

    if "V2Score" in source_dict:
        return source_dict["V2Score"], "2.0", name

    return None, None, None