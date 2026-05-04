from database import create_tables
from ingestion import run_pipeline

SBOM_PATH = ['data/juice_bom.json', 'data/spring_petclinic_sbom.json', 'data/grafana_sbom.json', 'data/webgoat_sbom.json']
OUTPUT_PATH = ['data/juice_scan_results.json', 'data/spring_scan_results.json', 'data/grafana_scan_results.json', 'data/webgoat_scan_results.json']

if __name__ == "__main__":
    create_tables()

    for sbom_path, output_path in zip(SBOM_PATH, OUTPUT_PATH):
        run_pipeline(sbom_path, output_path)
