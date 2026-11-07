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
from services.genai_service import generate_explanations, generate_persona_narratives
from services.snapshots_service import capture_snapshots
from services.studies_service import run_ablation_studies
from datetime import datetime, timedelta
from config import config

# --- Initialize Typer App ---
app = typer.Typer(  name="GenAi Vulnerability Prioritization",
                    add_completion=False,
                    context_settings={"help_option_names": ["-h", "--help"]},
                )

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
    typer.echo()


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
def ingest_vex(file_path: Annotated[str, typer.Argument(..., help="Path to the Vulnerability Exploitability eXchange (OpenVEX) JSON file.")]):
    """Parse and ingest a Vulnerability Exploitability eXchange (OpenVEX) JSON file."""

    typer.echo(f"Ingesting VEX from: {file_path}")
    process_vex(file_path)
    typer.secho("VEX parsed successfully.", fg=typer.colors.GREEN)


@app.command(name="prioritization")
def prioritization(sbom_id: Annotated[int, typer.Argument(..., help="The database ID of the ingested SBOM.")],
                       date: Annotated[datetime, typer.Option("-d","--date", help="The date to run the prioritization for. Defaults to today.", formats=["%Y-%m-%d"])] = None,
                       cvss_ranking: Annotated[bool, typer.Option("-c","--cvss", help="Enable CVSS-based ranking.")] = False,
                       epss_ranking: Annotated[bool, typer.Option("-e","--epss", help="Enable EPSS-based ranking.")] = False,
                       cvss_epss_ranking: Annotated[bool, typer.Option("-ce","--cvss-epss", help="Enable CVSS-EPSS fusion ranking.")] = False,
                       fusion_ranking: Annotated[bool, typer.Option("-f/-nf","--fusion/--no-fusion", help="Enable fusion-based ranking.")] = True):

    """Run the vulnerability prioritization pipeline for a given SBOM ID using specified ranking methods."""

    typer.echo(f"Running prioritization for SBOM ID: {sbom_id}...")

    if date is None: 
        date = datetime.now().date()
    else: 
        date = date.date()  # Convert datetime to date

    if date > datetime.now().date():
        typer.secho("Error: The provided date is in the future. Please provide a valid date.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    
    typer.echo(f"Date for prioritization: {date}")
    
    ranking_results = ranking_sbom(sbom_id, date, cvss_ranking, epss_ranking, cvss_epss_ranking, fusion_ranking)

    if cvss_ranking:
        typer.secho("\nCVSS Rankings:", fg=typer.colors.CYAN)
        for rank, item in enumerate(ranking_results["cvss"], start=1):
            typer.secho(f"{rank:<4}",nl=False, fg=typer.colors.CYAN)
            typer.secho(f"| {item['cve_id']:<16}", nl=False, fg=typer.colors.RED)
            typer.echo(f" - Component:",nl=False)
            typer.secho(f" {item['component_purl']:<50}", fg=typer.colors.BRIGHT_MAGENTA)
            typer.secho(f"    | CVSS Score: {item['score']:<4.2f}")
            typer.echo()

    if epss_ranking:
        typer.secho("\nEPSS Rankings:", fg=typer.colors.CYAN)
        for rank, item in enumerate(ranking_results["epss"], start=1):
            typer.secho(f"{rank:<4}", nl=False, fg=typer.colors.CYAN)
            typer.secho(f"| {item['cve_id']:<16}", nl=False, fg=typer.colors.RED)
            typer.echo(f" - Component:", nl=False)
            typer.secho(f" {item['component_purl']:<50}", fg=typer.colors.BRIGHT_MAGENTA)
            typer.echo(f"    | EPSS Score: {item['score']:<3.4f} with Percentile: {item['epss_percentile']:<.4f}")
            typer.echo()

    if cvss_epss_ranking:
        typer.secho("\nCVSS-EPSS Rankings:", fg=typer.colors.CYAN)
        for rank, item in enumerate(ranking_results["cvss_epss"], start=1):
            typer.secho(f"{rank:<4}", nl=False, fg=typer.colors.CYAN)
            typer.secho(f"| {item['cve_id']:<16}", nl=False, fg=typer.colors.RED)
            typer.echo(f"- Component:", nl=False)
            typer.secho(f" {item['component_purl']:<50}", fg=typer.colors.BRIGHT_MAGENTA)
            typer.echo(f"    | Combined score: {item['score']:<5.2f}")
            typer.echo(f"    | CVSS: {item['cvss_score']:<4.2f} | EPSS average: {item['epss_avg']:<3.4f}")
            typer.echo()

    if fusion_ranking:
        typer.secho("\nFusion Rankings:", fg=typer.colors.CYAN)
        for rank, item in enumerate(ranking_results["fusion"], start=1):
            typer.secho(f"{rank:<4}", nl=False, fg=typer.colors.CYAN)
            typer.secho(f"| {item['cve_id']:<16}", nl=False, fg=typer.colors.RED)
            typer.echo(f"- Component:", nl=False)
            typer.secho(f" {item['component_purl']:<50}", fg=typer.colors.BRIGHT_MAGENTA)
            typer.secho(f"    | Priority: {item['priority']:<8} - Fusion Score: {item['score']:<4.2f}")
            typer.secho(f"    | Why ranked:", nl=False, fg=typer.colors.YELLOW)
            typer.echo(f" {item['why-ranked']}".replace("|", "\n"+ " "*17))
            typer.echo()

    typer.secho("Prioritization completed.\n", fg=typer.colors.GREEN)


@app.command(name="full-pipeline")
def full_pipeline(sbom_path: Annotated[str, typer.Argument(..., help="Path to the CycloneDX SBOM JSON file.")],
                  output_path: Annotated[str, typer.Argument(..., help="Path to the output JSON file from Trivy.")],
                  vex_paths: Annotated[list[str], typer.Option("-v","--vex", help="Paths to VEX JSON files to ingest.")] = [],
                  cvss_ranking: Annotated[bool, typer.Option("-c","--cvss", help="Enable CVSS-based ranking.")] = False,
                  epss_ranking: Annotated[bool, typer.Option("-e","--epss", help="Enable EPSS-based ranking.")] = False,
                  cvss_epss_ranking: Annotated[bool, typer.Option("-ce","--cvss-epss", help="Enable CVSS-EPSS fusion ranking.")] = False,
                  fusion_ranking: Annotated[bool, typer.Option("-f/-nf","--fusion/--no-fusion", help="Enable fusion-based ranking.")] = True,
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

    ranking_results = ranking_sbom(sbom_id, datetime.now().date(), cvss_ranking, epss_ranking, cvss_epss_ranking, fusion_ranking)

    if cvss_ranking:
        typer.secho("\nCVSS Rankings:", fg=typer.colors.CYAN)
        for rank, item in enumerate(ranking_results["cvss"], start=1):
            typer.secho(f"{rank:<4}", nl=False, fg=typer.colors.CYAN)
            typer.secho(f"| {item['cve_id']:<16}", nl=False, fg=typer.colors.RED)
            typer.echo(f"    | Component:", nl=False)
            typer.secho(f" {item['component_purl']:<50}", fg=typer.colors.BRIGHT_MAGENTA)
            typer.secho(f"    | CVSS Score: {item['score']:<4.2f}")
        typer.echo()

    if epss_ranking:
        typer.secho("\nEPSS Rankings:", fg=typer.colors.CYAN)
        for rank, item in enumerate(ranking_results["epss"], start=1):
            typer.secho(f"{rank:<4}", nl=False, fg=typer.colors.CYAN)
            typer.secho(f"| {item['cve_id']:<16}", nl=False, fg=typer.colors.RED)
            typer.echo(f"    | Component:", nl=False)
            typer.secho(f" {item['component_purl']:<50}", fg=typer.colors.BRIGHT_MAGENTA)
            typer.echo(f"    | EPSS Score: {item['score']:<3.4f} with Percentile: {item['epss_percentile']:<.4f}")
        typer.echo()

    if cvss_epss_ranking:
        typer.secho("\nCVSS-EPSS Rankings:", fg=typer.colors.CYAN)
        for rank, item in enumerate(ranking_results["cvss_epss"], start=1):
            typer.secho(f"{rank:<4}", nl=False, fg=typer.colors.CYAN)
            typer.secho(f"| {item['cve_id']:<16}", nl=False, fg=typer.colors.RED)
            typer.echo(f"    | Component:", nl=False)
            typer.secho(f" {item['component_purl']:<50}", fg=typer.colors.BRIGHT_MAGENTA)
            typer.secho(f"    | Combined score: {item['score']:<5.2f}")
        typer.echo()

    if fusion_ranking:
        typer.secho("\nFusion Rankings:", fg=typer.colors.CYAN)
        for rank, item in enumerate(ranking_results["fusion"], start=1):
            typer.secho(f"{rank:<4}", nl=False, fg=typer.colors.CYAN)
            typer.secho(f"| {item['cve_id']:<16}", nl=False, fg=typer.colors.RED)
            typer.echo(f"- Component:", nl=False)
            typer.secho(f" {item['component_purl']:<50}", fg=typer.colors.BRIGHT_MAGENTA)
            typer.secho(f"    | Priority: {item['priority']:<8} - Fusion Score: {item['score']:<4.2f} ")
            typer.secho(f"    | Why ranked:", nl=False, fg=typer.colors.YELLOW)
            typer.echo(f"{item['why-ranked']}".replace("|", "\n"+ " "*17))
        typer.echo()

@app.command(name="genai-explanations")
def genai_explanations(sbom_id: Annotated[int, typer.Argument(..., help="The database ID of the ingested SBOM.")],
              date: Annotated[datetime, typer.Option("-d","--date", help="The date to run the GenAI explanations for. Defaults to today.", formats=["%Y-%m-%d"])] = None,
              top_k: Annotated[int, typer.Option("-k","--top-k", help="Number of top items to generate AI explanations for.")] = 5,
              baseline: Annotated[bool, typer.Option("-b","--baseline", help="Use the baseline prompt for GenAI analysis.")] = False,
              verbose: Annotated[bool, typer.Option("-v","--verbose", help="Enable verbose output for printing every explanation.")] = False):
    """Run the GenAI explanation generation for a given SBOM ID.
    
    Warning: Don't run this command for large top_k value because will exceed the token limit of the LLM model. The default top_k is 5. 
    """

    if date is None:
        date = datetime.now().date()
    else:
        date = date.date()  # Convert datetime to date
    
    typer.echo(f"Running GenAI for SBOM ID: {sbom_id} for date: {date}...")
    answer = generate_explanations(sbom_id, top_k, baseline, snapshot_date=date)

    typer.secho("\n"+ "=" * 60, fg=typer.colors.CYAN)
    typer.secho(f" PRODUCT: {answer.Product_Name} (SBOM ID: {answer.SBOM_id})", fg=typer.colors.CYAN, bold=True)
    typer.secho(f" DATE: {date}", fg=typer.colors.CYAN)
    typer.secho(f" TOP {top_k} EXPLANATIONS GENERATED", fg=typer.colors.CYAN)
    typer.secho("=" * 60, fg=typer.colors.CYAN)

    if verbose:
        for i, explanation in enumerate(answer.explanations, start=1):
            typer.secho(f"\nExplanation {i}:", fg=typer.colors.CYAN)
            typer.echo("Vulnerability: ", nl=False)
            typer.secho(f"{explanation.Vulnerability}", fg=typer.colors.RED, bold=True)
            typer.echo("Component PURL: ", nl=False)
            typer.secho(f"{explanation.component_purl}", fg=typer.colors.BRIGHT_MAGENTA)
            typer.echo("Rank: ", nl=False)
            typer.secho(f"{explanation.rank}", fg=typer.colors.YELLOW)
            typer.secho("Why Prioritized Now:", fg=typer.colors.CYAN)
            for claim in explanation.why_prioritized_now:
                typer.echo(f"  - Summary: {claim.summary}")
                typer.secho(f"  - Claim Type: {claim.claim_type}, Value: {claim.value}, Evidence ID: {claim.evidence_id}", dim=True)
            typer.secho("What to Do Next:", fg=typer.colors.CYAN)
            for claim in explanation.what_to_do_next:
                typer.echo(f"  - Summary: {claim.summary}")
                typer.secho(f"  - Claim Type: {claim.claim_type}, Value: {claim.value}, Evidence ID: {claim.evidence_id}", dim=True)
    typer.echo()

    typer.secho("GenAI explanation generation completed.", fg=typer.colors.GREEN)

@app.command(name="genai-persona-narratives")
def genai_persona_narratives(sbom_id: Annotated[int, typer.Argument(..., help="The database ID of the ingested SBOM.")],
                             date: Annotated[datetime, typer.Option("-d","--date", help="The date to run the GenAI explanations for. Defaults to today.", formats=["%Y-%m-%d"])] = None,
                             top_k: Annotated[int, typer.Option("-k","--top-k", help="Number of top items to generate AI explanations for.")] = 5,
                             persona: Annotated[str, typer.Option("-p","--persona", help="The persona to generate narratives for.")] = "developer"):
    """
    Generate persona narratives for the top_k findings in a given SBOM ID.

    Args:
        sbom_id (int): The database ID of the ingested SBOM.
        date (datetime): The date to run the GenAI explanations for. Defaults to today.
        top_k (int): The number of top findings to generate explanations for.
        baseline (bool): Whether to use the baseline prompt.
    """
    persona = persona.lower()
    if persona not in ["developer", "devops", "security_lead"]:
        typer.secho("Invalid persona. Please choose from: developer, devops, security_lead.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if date is None:
        date = datetime.now().date()
    else:
        date = date.date()  # Convert datetime to date

    typer.echo(f"Generating persona narratives for SBOM ID: {sbom_id} for date: {date}...")
    try:
        answer, generated_narratives = generate_persona_narratives(sbom_id=sbom_id, top_k=top_k, snapshot_date=date, persona=persona)
    except FileNotFoundError as e:
        typer.secho(str(e), fg=typer.colors.RED)
        raise typer.Exit(code=1)        

    typer.secho("\n" + "=" * 60, fg=typer.colors.CYAN)
    typer.secho(f" PRODUCT: {answer.Product_Name} (SBOM ID: {answer.SBOM_id})", fg=typer.colors.CYAN, bold=True)
    typer.secho(f" DATE: {date}", fg=typer.colors.CYAN)
    typer.secho(f" TOP {top_k}", fg=typer.colors.CYAN)
    typer.secho(f" SUMMARY FOR {persona.upper()}", fg=typer.colors.CYAN)
    typer.secho("=" * 60, fg=typer.colors.CYAN)

    typer.echo(generated_narratives + "\n")


@app.command(name="capture-snapshots")
def snapshots(start_date: Annotated[datetime, typer.Option("-s", "--start-date", help="Start date for snapshot capture.", formats=["%Y-%m-%d"])] = None,
              end_date: Annotated[datetime, typer.Option("-e", "--end-date", help="End date for snapshot capture.", formats=["%Y-%m-%d"])] = None,
              save_queues: Annotated[bool, typer.Option("-sq/-nsq", "--save-queues/--no-save-queues", help="Save prioritization queues for the snapshots.")] = True,
              create_evidence: Annotated[bool, typer.Option("-ce/-nce", "--create-evidence/--no-create-evidence", help="Create evidence for the snapshots.")] = False):
    """
    Capture snapshots for a given date range and save prioritization queues for each date for evaluation purposes. 

    The snapshots will include EPSS and KEV data for each date.
    Start date is the oldest date and end date is the most recent date.
    If no dates are provided, the default range from the configuration will be used. 
    Create evidence is optional and it will create evidence for later use in the GenAI explanation generation.

    The start date must be after 2025-01-27, and the end date cannot be in the future.
    Warning: This operation may take several minutes depending on the dates, the number of CVEs and SBOMs in the database.
    """

    if start_date is None:
        start_date = config.start_date  # Default to config start date
    else:
        start_date = start_date.date()

    if end_date is None:
        end_date = config.end_date  # Default to config end date
    else:
        end_date = end_date.date()

    if start_date > end_date:
        typer.secho("Error: Start date cannot be after end date.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    if end_date > datetime.now().date():
        typer.secho("Error: End date cannot be in the future.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    dates = [start_date + timedelta(days=i) for i in range((end_date - start_date).days + 1)]

    capture_snapshots(dates=dates, save_queues=save_queues, create_evidence=create_evidence)
    typer.secho(f"Snapshots created for dates from {start_date} to {end_date}.", fg=typer.colors.GREEN)

@app.command(name="ablation-studies")
def ablation_studies(start_date: Annotated[datetime, typer.Option("-s", "--start-date", help="Start date for snapshot capture.", formats=["%Y-%m-%d"])] = None,
                     end_date: Annotated[datetime, typer.Option("-e", "--end-date", help="End date for snapshot capture.", formats=["%Y-%m-%d"])] = None,):
    """Run ablation studies for a given date range and save prioritization queues for each date for evaluation purposes.

    Warning: This operation may take several minutes depending on the dates, the number of CVEs and SBOMs in the database.
    The ablation studies will evaluate the impact of different factors on the prioritization of vulnerabilities.
    We implement three ablation studies: One for the impact of SBOM linkage, one for the impact of EPSS and one on the impact of KEV. 
    """

    if start_date is None:
        start_date = config.start_date  # Default to config start date
    else:
        start_date = start_date.date()

    if end_date is None:
        end_date = config.end_date  # Default to config end date
    else:
        end_date = end_date.date()

    if start_date > end_date:
        typer.secho("Error: Start date cannot be after end date.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    if end_date > datetime.now().date():
        typer.secho("Error: End date cannot be in the future.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    dates = [start_date + timedelta(days=i) for i in range((end_date - start_date).days + 1)]

    run_ablation_studies(dates=dates)
    typer.secho(f"Ablation studies completed for dates from {start_date} to {end_date}.", fg=typer.colors.GREEN)


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