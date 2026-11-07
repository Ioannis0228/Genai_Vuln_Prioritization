from database import SessionLocal, Vulnerabilities, Finding, Components, execute_select, get_latest_snapshots, EPSSsnapshot, KEVsnapshot, VEXstatements, vex_statement_component
from prioritization.rank import fusion_rank
from prioritization.fusion_score import compute_fusion_score
from services.prioritization_service import ranking_sbom
from collections import defaultdict
from datetime import date, datetime


def sbom_ablation(snapshot_date: date):
    """
    Perform ablation study removing the need for a specific SBOM and evaluating prioritization.
    
    Args:
        snapshot_date (str): The date for retrieving the appropriate snapshots in YYYY-MM-DD format.
    
    Returns:
        dict: A dictionary containing the results of the ablation study for each configuration type.
    """

    with SessionLocal() as session:
        # Fetch all findings for the given snapshot date
        Findings = execute_select(
            session=session,
            selected_columns=[Finding.id, Vulnerabilities.cve_id, Vulnerabilities.cvss_score, Components.purl],
            joins=[
                (Finding, Finding.vulnerability_id == Vulnerabilities.id),
                (Components, Components.id == Finding.component_id)
            ],
            where_conditions=[Vulnerabilities.published_date <= snapshot_date]
        )

        cve_ids = list({row[1] for row in Findings})

        EPSS_rows = get_latest_snapshots(
            session=session,
            table=EPSSsnapshot,
            cve_ids=cve_ids,
            date_column=EPSSsnapshot.score_date,
            selected_columns=[EPSSsnapshot.cve_id, EPSSsnapshot.epss_score, EPSSsnapshot.percentile],
            date=snapshot_date
        )

        KEV_rows = get_latest_snapshots(
            session=session,
            table=KEVsnapshot,
            cve_ids=cve_ids,
            date_column=KEVsnapshot.snapshot_date,
            selected_columns=[KEVsnapshot.cve_id],
            date=snapshot_date
        )

        vex_statements = execute_select(
            session=session,
            selected_columns=[Vulnerabilities.cve_id, Components.purl, VEXstatements.status, VEXstatements.justification, VEXstatements.timestamp],
            where_conditions=[VEXstatements.sbom_id.is_(None), Vulnerabilities.cve_id.in_(cve_ids),
                                VEXstatements.timestamp <= datetime.combine(snapshot_date, datetime.max.time())],
            joins=[(Vulnerabilities, VEXstatements.vulnerability == Vulnerabilities.id),
                    (vex_statement_component, VEXstatements.id == vex_statement_component.c.statement_id),
                    (Components, Components.id == vex_statement_component.c.component_id)]
        )

    EPSS_map = {cve: (score, perc) if score is not None and perc is not None else (0.0, 0.0) for cve, score, perc in EPSS_rows}
    KEV_map = {cve: True for (cve,) in KEV_rows}
    VEX_map = {}

    # Build a mapping of the latest VEX statements to CVEs, considering timestamps. The latest timestamp takes precedence over older ones.
    for cve_id, purl, status, justification, timestamp in vex_statements:
        key = (cve_id, purl)
        candidate = {
            "status": status,
            "justification": justification,
            "timestamp": timestamp
        }

        current = VEX_map.get(key)
        if current is None:
            VEX_map[key] = candidate
            continue

        elif timestamp > current["timestamp"]:
            VEX_map[key] = candidate


    grouped_findings = defaultdict(list)
    for finding in Findings:
        finding_id, cve_id, cvss_score, purl = finding

        key = (cve_id, purl)
        if key not in grouped_findings:
            grouped_findings[key] = ([], cvss_score)

        grouped_findings[key][0].append(finding_id)

    processed_findings = [
        (finding_ids, cve_id, cvss_score, purl)
        for (cve_id, purl), (finding_ids, cvss_score) in grouped_findings.items()
    ]

    risk_assessment = []
    for finding_id, cve, CVSS, purl in processed_findings:
        KEV_status = KEV_map.get(cve, False)
        CVSS = CVSS if CVSS is not None else 0.0
        EPSS_prob, EPSS_perc = EPSS_map.get(cve, (0.0, 0.0))
        fusion_score = compute_fusion_score(CVSS_score=CVSS,
                                                EPSS_probability=EPSS_prob,
                                                EPSS_percentile=EPSS_perc,
                                                KEV=KEV_status)

        if KEV_status:
            priority = 'Critical'
            priority_rank = 0
        elif EPSS_perc >= 0.85 or fusion_score >= 7.0:
            priority = 'High'
            priority_rank = 1
        else:
            priority = 'Medium'
            priority_rank = 2

        risk_assessment.append({
            "cve_id": cve,
            "finding_id": finding_id,
            "component_purl": purl,
            "score": fusion_score,
            "priority": priority,
            "priority_rank": priority_rank,
        })
    
    grouped_results = fusion_rank(risk_assessment=risk_assessment, vex_statements=VEX_map)

    ablation_results = []
    for item in grouped_results:
        for finding_id in item["finding_id"]:
            ablation_results.append({
                "cve_id": item["cve_id"],
                "finding_id": finding_id,
                "component_purl": item["component_purl"],
                "score": item["score"],
                "priority": item["priority"],
                "priority_rank": item["priority_rank"],
                "rank": item["rank"]
            })

    return ablation_results

def epss_kev_ablation(sbom_id:int, snapshot_date: date):
    """
    Perform 2 ablation studies removing the EPSS and KEV data and evaluating prioritization.
    
    Args:
        sbom_id (int): The SBOM ID for which to perform the ablation studies.
        snapshot_date (str): The date for retrieving the appropriate snapshots in YYYY-MM-DD format.
    
    Returns:
        dict: A dictionary containing the results of the ablation studies.
    """

    results = {}
    results["epss_ablation"] = ranking_sbom(sbom_id=sbom_id, snapshot_date=snapshot_date, use_epss=False).get("fusion", [])
    results["kev_ablation"] = ranking_sbom(sbom_id=sbom_id, snapshot_date=snapshot_date, use_kev=False).get("fusion", [])

    return results
