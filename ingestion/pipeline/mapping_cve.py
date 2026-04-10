import json
import subprocess

def mapping_cve(SBOM_PATH, OUTPUT_PATH):

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