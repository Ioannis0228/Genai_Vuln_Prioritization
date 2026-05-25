from database import create_tables, save_finding_evidence_links, SessionLocal
from database.queries import get_CVEs_id
from services.enrichment_service import vuln_enrichment
from services.intelligence_service import process_intelligence
from services.sbom_service import process_sbom
from services.vex_service import process_vex
from services.prioritization_service import ranking_sbom
from services.dependency_depth import get_component_depths
from prioritization.rank import fusion_rank

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


    # cve_id = set()
    # for sbom_path, output_path in zip(SBOM_PATH, OUTPUT_PATH):
    #     returned_cve_ids = process_sbom(sbom_path, output_path)
    #     if returned_cve_ids:
    #         cve_id.update(returned_cve_ids)

    # for vex_path in VEX_PATH:
    #     process_vex(vex_path)
    
    # # if cve_id:
    #     # process_intelligence(cve_id)
    #     # save_finding_evidence_links(cve_id)
    #     # vuln_enrichment(cve_id)
    ranking_sbom(3, fusion_ranking=True, cvss_ranking=True, epss_ranking=True, cvss_epss_ranking=True)