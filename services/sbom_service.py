from database import save_sbom, save_components, save_CVEs, check_existence, SBOM
from ingestion import normalize_component, parse_sbom, mapping_cve

def process_sbom(SBOM_PATH, OUTPUT_PATH):
    sbom = parse_sbom(SBOM_PATH)
    
    if check_existence(SBOM, SBOM.serial_number, str(sbom.serial_number)):
        print(f"SBOM for product {sbom.metadata.component.name} with serial number {sbom.serial_number} already processed. Skipping pipeline execution.")
        return None
    
    sbom_id = save_sbom(sbom)
    normalized_components = [normalize_component(c) for c in sbom.components]
    save_components(sbom_id, normalized_components, dependencies=sbom.dependencies)

    print("Starting CVE mapping...", flush=True)
    component_cve = mapping_cve(SBOM_PATH, OUTPUT_PATH)

    save_CVEs(sbom_id, component_cve)

    CVEs_id = [cve["cve_id"] for cve in component_cve]

    return CVEs_id