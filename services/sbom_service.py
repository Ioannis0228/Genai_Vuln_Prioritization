"""Service layer for SBOM ingestion, component normalization, and vulnerability mapping."""

from database import save_sbom, save_components, save_CVEs, check_existence, SBOM, save_finding_evidence_links, SessionLocal, execute_select
from ingestion import normalize_component, parse_sbom, mapping_cve

def process_sbom(SBOM_PATH:str , OUTPUT_PATH:str):
    """Parse an SBOM, persist it, and map the discovered CVEs.
    
    Orchestrates the full SBOM ingest workflow: parse the CycloneDX file, check for duplicates,
    persist the SBOM and its components, run Trivy to discover vulnerabilities, and store findings.
    
    Args:
        SBOM_PATH (str): Path to the input CycloneDX SBOM JSON file.
        OUTPUT_PATH (str): Path where Trivy scan results will be written.
    
    Returns:
        tuple: A tuple containing the SBOM ID and a list of unique CVE IDs discovered, or (None, None) if SBOM already processed.
    """

    sbom = parse_sbom(SBOM_PATH)
    
    if check_existence(SBOM, SBOM.serial_number, str(sbom.serial_number)):
        print(f"SBOM for product {sbom.metadata.component.name} with serial number {sbom.serial_number} already processed. Skipping pipeline execution.")
        return None, None
    
    sbom_id = save_sbom(sbom)
    normalized_components = [normalize_component(c) for c in sbom.components]
    save_components(sbom_id, normalized_components, dependencies=sbom.dependencies)

    print("Starting CVE mapping...", flush=True)
    component_cve = mapping_cve(SBOM_PATH, OUTPUT_PATH)

    save_CVEs(sbom_id, component_cve)

    CVE_ids = [cve["cve_id"] for cve in component_cve]

    save_finding_evidence_links(CVE_ids)

    return sbom_id, CVE_ids

def get_all_sboms():
    """Retrieve all ingested SBOMs from the database."""
    
    with SessionLocal() as session:
        results = execute_select(session=session, 
                                 selected_columns=[SBOM.id, SBOM.product_name],
                                 )

    return results