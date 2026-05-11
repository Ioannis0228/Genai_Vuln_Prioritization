from database import create_tables, save_finding_evidence_links
from services.intelligence_service import process_intelligence
from services.sbom_service import process_sbom
from services.vex_service import process_vex

SBOM_PATH = ['data/juice_bom.json',
             'data/spring_petclinic_sbom.json',
             'data/grafana_sbom.json',
             'data/webgoat_sbom.json']

OUTPUT_PATH = ['data/juice_scan_results.json',
               'data/spring_scan_results.json',
               'data/grafana_scan_results.json',
               'data/webgoat_scan_results.json']

VEX_PATH = ['data/vex_documents/vex_document.json',
            'data/vex_documents/vex_document_2.json']

if __name__ == "__main__":
    create_tables()


    cve_id = set()
    for sbom_path, output_path in zip(SBOM_PATH, OUTPUT_PATH):
        returned_cve_ids = process_sbom(sbom_path, output_path)
        if returned_cve_ids:
            cve_id.update(returned_cve_ids)

    for vex_path in VEX_PATH:
        process_vex(vex_path)
    
    if cve_id:
        process_intelligence(cve_id)
        save_finding_evidence_links(cve_id)