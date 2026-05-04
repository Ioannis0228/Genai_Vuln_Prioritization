from database import save_sbom, save_components, save_CVEs, save_KEV_snapshot, save_EPSS_snapshot, save_CSAF_advisory, save_CVE_CSAF_mapping, save_Evidence, check_existence, SBOM,CSAFadvisories

from .pipeline.sbom import normalize_component, parse_sbom
from .pipeline.mapping_cve import mapping_cve
from .pipeline.cve import fetch_nvd_cvss
from .pipeline.kev import fetch_KEV
from .pipeline.epss import fetch_EPSS
from .pipeline.csaf import find_RHSA_id,fetch_RedHat_advisory
from .pipeline.evidence import create_Evidence

def run_pipeline(SBOM_PATH, OUTPUT_PATH):

    sbom = parse_sbom(SBOM_PATH)
    if check_existence(SBOM, SBOM.serial_number, str(sbom.serial_number)):
        print(f"SBOM for product {sbom.metadata.component.name} with serial number {sbom.serial_number} already processed. Skipping pipeline execution.")
        return
    
    sbom_id = save_sbom(sbom)
    normalized_components = [normalize_component(c) for c in sbom.components]
    save_components(sbom_id, normalized_components, dependencies=sbom.dependencies)

    print("Starting CVE mapping...", flush=True)
    component_cve = mapping_cve(SBOM_PATH, OUTPUT_PATH)

    save_CVEs(sbom_id, component_cve)

    # Maybe we fetch data if the last update is > 24h, but for now we just fetch and save
    save_KEV_snapshot(fetch_KEV())

    print("Fetching EPSS data...", flush=True)
    CVEs_id = [cve["cve_id"] for cve in component_cve]

    save_EPSS_snapshot(fetch_EPSS(CVEs_id))

    print("Fetching CSAF advisories...", flush=True)
    csaf_vuln = []

    for cve in CVEs_id:
        RHSA_ids = find_RHSA_id(cve)
        if RHSA_ids:
            for rhsa in RHSA_ids:
                if not check_existence(CSAFadvisories, CSAFadvisories.csaf_id, rhsa):
                    save_CSAF_advisory(fetch_RedHat_advisory(rhsa), rhsa)
                    # print(f"Saved CSAF advisory for {cve} (RHSA: {rhsa})")
                # else:
                    # print(f"CSAF advisory for {cve} (RHSA: {rhsa}) already exists in the database.")       

                csaf_vuln.append({
                    "cve_id": cve,
                    "csaf_id": rhsa
                })

    save_CVE_CSAF_mapping(csaf_vuln)

    save_Evidence(*create_Evidence(sbom_id))

    print("Pipeline execution completed successfully.", flush=True)

