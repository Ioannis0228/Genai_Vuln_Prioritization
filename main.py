import sys
import shlex
import typer
import readline # Optional: For command history and line editing in the REPL interface
from typing import Annotated

from database import create_tables
from services.enrichment_service import vuln_enrichment
from services.intelligence_service import process_intelligence
from services.sbom_service import process_sbom, get_all_sboms
from services.vex_service import process_vex
from services.prioritization_service import ranking_sbom
from services.genai_service import generate_explanations
from genai import LLMClient

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

# --- Initialize Typer App ---
app = typer.Typer(  name="GenAi Vulnerability Prioritization",
                    add_completion=False,
                    context_settings={"help_option_names": ["-h", "--help"]},
                )

# --- Initialize LLM Client ---
llm_client = LLMClient() 

# --- Typer Commands ---
@app.command(name="list-sboms")
def list_sboms():
    """List all ingested SBOMs in the database."""
    sboms = get_all_sboms()
    if not sboms:
        typer.echo("No SBOMs found in the database.")
        return

    typer.echo(f"{'SBOM ID':<10} {'Product Name':<70}")
    typer.echo("-" * 80)
    for sbom in sboms:
        typer.echo(f"{sbom.id:<10} {sbom.product_name:<70}")


@app.command(name="ingest-sbom")
def ingest_sbom(sbom_path: Annotated[str, typer.Argument(..., help="Path to the CycloneDX SBOM JSON file.")],
                output_path: Annotated[str, typer.Argument(..., help="Path to the output JSON file from Trivy.")]):
    """Parse a software bill of materials (SBOM) JSON file CycloneDX."""
    typer.echo(f"Ingesting SBOM from: {sbom_path}")
    sbom_id, _ = process_sbom(sbom_path, output_path)

    if sbom_id is not None:
        typer.echo(f"SBOM ID: {sbom_id}")
        typer.secho(f"SBOM ingested successfully.", fg=typer.colors.GREEN)
    return sbom_id


@app.command(name="fetch-intel")
def fetch_intel(sbom_id: Annotated[int, typer.Argument(..., help="The database ID of ingested SBOM.")]):
    """
    Fetch threat intelligence for CVEs associated with a specific SBOM ID.
    
    Warning: This may take several minutes depending on the number of CVEs.
    """
    typer.echo(f"Fetching intel for SBOM_id: {sbom_id}...")
    process_intelligence(sbom_id)
    typer.secho(f"Intel fetched and persisted successfully for SBOM_id: {sbom_id}.", fg=typer.colors.GREEN)


@app.command(name="enrichment")
def enrichment(sbom_id: Annotated[int, typer.Argument(..., help="The database ID of ingested SBOM.")]):
    """Enrich vulnerabilities using CIRCL Vulnerability Lookup.

    Warning: This operation may take several minutes for SBOMs containing many CVEs.
    """
    typer.echo(f"Running CIRCL enrichment for SBOM ID: {sbom_id}...")
    vuln_enrichment(sbom_id)
    typer.secho("Enrichment completed.", fg=typer.colors.GREEN)


@app.command(name="ingest-vex")
def ingest_vex(file_path: Annotated[str, typer.Argument(..., help="Path to the Vulnerability Exploitability eXchange (VEX) JSON file.")]):
    """Parse and ingest a Vulnerability Exploitability eXchange (VEX) JSON file."""

    typer.echo(f"Ingesting VEX from: {file_path}")
    process_vex(file_path)
    typer.secho("VEX parsed successfully.", fg=typer.colors.GREEN)


@app.command(name="prioritization")
def prioritization(sbom_id: Annotated[int, typer.Argument(..., help="The database ID of the ingested SBOM.")],
                       cvss_ranking: Annotated[bool, typer.Option("--cvss", help="Enable CVSS-based ranking.")] = False,
                       epss_ranking: Annotated[bool, typer.Option("--epss", help="Enable EPSS-based ranking.")] = False,
                       cvss_epss_ranking: Annotated[bool, typer.Option("--cvss-epss", help="Enable CVSS-EPSS fusion ranking.")] = False,
                       fusion_ranking: Annotated[bool, typer.Option("--fusion/--no-fusion", help="Enable fusion-based ranking.")] = True):

    """Run the vulnerability prioritization pipeline for a given SBOM ID using specified ranking methods."""

    typer.echo(f"Running prioritization for SBOM ID: {sbom_id}...")
    ranking_results = ranking_sbom(sbom_id, cvss_ranking, epss_ranking, cvss_epss_ranking, fusion_ranking)
    typer.secho("Prioritization completed.", fg=typer.colors.GREEN)


@app.command(name="full-pipeline")
def full_pipeline(sbom_path: Annotated[str, typer.Argument(..., help="Path to the CycloneDX SBOM JSON file.")],
                  output_path: Annotated[str, typer.Argument(..., help="Path to the output JSON file from Trivy.")],
                  vex_paths: Annotated[list[str], typer.Option("--vex", help="Paths to VEX JSON files to ingest.")] = [],
                  cvss_ranking: Annotated[bool, typer.Option("--cvss", help="Enable CVSS-based ranking.")] = False,
                  epss_ranking: Annotated[bool, typer.Option("--epss", help="Enable EPSS-based ranking.")] = False,
                  cvss_epss_ranking: Annotated[bool, typer.Option("--cvss-epss", help="Enable CVSS-EPSS fusion ranking.")] = False,
                  fusion_ranking: Annotated[bool, typer.Option("--fusion/--no-fusion", help="Enable fusion-based ranking.")] = True,
                  ):
    
    """
    Run the entire vulnerability prioritization pipeline for a given SBOM path.
    This includes SBOM ingestion, vulnerability enrichment, threat intelligence processing, VEX ingestion, and prioritization based on the specified ranking methods.
    
    - Provide the paths to any VEX files you wish to ingest using the --vex option. Multiple VEX files can be specified by repeating the --vex option.
    - For prioritization, you can enable or disable specific ranking methods using the provided flags. If no ranking methods are specified, fusion-based ranking will be used by default.
    - For skipping prioritization entirely, use the --no-fusion flag and not provide any other ranking flags.
    """

    typer.echo(f"Running full pipeline for SBOM: {sbom_path}...")
    sbom_id, _ = process_sbom(sbom_path, output_path)

    if sbom_id is None:
        typer.secho("SBOM ingestion failed. SBOM already exists or there was an error.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.echo(f"SBOM ID: {sbom_id}")
    typer.secho("SBOM ingested successfully.", fg=typer.colors.GREEN)
    vuln_enrichment(sbom_id=sbom_id)
    process_intelligence(sbom_id=sbom_id)

    for vex_file in vex_paths:
        ingest_vex(vex_file)

    ranking_sbom(sbom_id, cvss_ranking, epss_ranking, cvss_epss_ranking, fusion_ranking)


@app.command(name="genai-explanations")
def genai_explanations(sbom_id: Annotated[int, typer.Argument(..., help="The database ID of the ingested SBOM.")],
              top_k: Annotated[int, typer.Option("--top-k", help="Number of top vulnerabilities to prioritize for GenAI analysis.")] = 5):
    """Run the GenAI explanation generation for a given SBOM ID."""
    typer.echo(f"Running GenAI for SBOM ID: {sbom_id}...")
    generate_explanations(llm_client, sbom_id, top_k)

    typer.secho("GenAI explanation generation completed.", fg=typer.colors.GREEN)


# --- Loop for REPL-like interface ---
@app.command(hidden=True)
def interactive():
    """ Launch an interactive REPL session to keep the Docker container alive and accept sequential commands."""
    typer.echo("\n" + "=" * 60)
    typer.echo(" GenAI Vulnerability Prioritization App Initialized.")
    typer.echo(" Type '--help' or '-h' to see available commands.")
    typer.echo(" Type 'exit' or 'quit' to terminate.")
    typer.echo("=" * 60 + "\n")
    
    while True:
        try:
            user_input = input("gvp\u276F ").strip()
            if user_input.lower() in ["exit", "quit"]:
                break
            if not user_input:
                continue

            # shlex.split automatically handles spaces inside quotes
            args = shlex.split(user_input)
            
            # This feeds the text straight into Typer's parsing engine
            app(args=args, standalone_mode=False)
            
        except Exception as e:
            typer.echo(f"Error: {e}")
        except (KeyboardInterrupt, EOFError):
            break

if __name__ == "__main__":
    # Initialize database schema on first run
    create_tables()

    sys.argv[0] = "" # Clear the script name to avoid confusion in Typer's help output
    # If no flags passed, default to entering the REPL loop
    if len(sys.argv) == 1:
        app(args=["interactive"])
        pass
    else:
        app()