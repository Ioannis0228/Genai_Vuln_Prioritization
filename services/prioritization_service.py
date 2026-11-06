"""Service layer for assembling ranking inputs and persisting fusion results."""

from database import SessionLocal, Components, Vulnerabilities, EPSSsnapshot, KEVsnapshot, VEXstatements, Finding, vex_statement_component, execute_select, get_latest_snapshots
from prioritization import compute_fusion_score, cvss_rank, epss_rank, cvss_epss_rank, fusion_rank, explain_fusion
from datetime import date, datetime
from sqlalchemy import or_

def ranking_sbom(sbom_id: int, snapshot_date: date, cvss_ranking=False, epss_ranking=False, cvss_epss_ranking=False, fusion_ranking=True,
                 use_epss=True, use_kev=True)-> dict:
    """Computes the rankings for a given SBOM based on CVSS, EPSS, CVSS+EPSS, and fusion scores. 
    
    Retrieves all findings for an SBOM, fetches their associated CVSS/EPSS/KEV/VEX data,
    computes fusion scores, applies VEX status downgrades, and stores fusion results back to the database.
    
    Args:
        sbom_id (int): Primary key of the SBOM to rank.
        snapshot_date (date): The date for retrieving the appropriate snapshots.
        cvss_ranking (bool): If True, compute and return CVSS-only rankings.
        epss_ranking (bool): If True, compute and return EPSS-only rankings.
        cvss_epss_ranking (bool): If True, compute and return combined CVSS+EPSS rankings.
        fusion_ranking (bool): If True (default), compute fusion scores and persist results.
    
    Returns:
        results (dict): The computed rankings, keyed by ranking type ('cvss', 'epss', 'cvss_epss', 'fusion').
    """

    results = {}
    with SessionLocal() as session:
        
        Findings = execute_select(
            session = session, 
            selected_columns = [Finding.id, Vulnerabilities.cve_id, Vulnerabilities.cvss_score, Components.purl],
            where_conditions = [Finding.sbom_id == sbom_id, Vulnerabilities.published_date <= snapshot_date],
            joins = [(Finding, Finding.vulnerability_id == Vulnerabilities.id), (Components, Components.id == Finding.component_id)]
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
            selected_columns=[Vulnerabilities.cve_id, Components.purl, VEXstatements.status, VEXstatements.justification, VEXstatements.sbom_id, VEXstatements.timestamp],
            where_conditions=[or_(VEXstatements.sbom_id == sbom_id, VEXstatements.sbom_id.is_(None)), Vulnerabilities.cve_id.in_(cve_ids),
                              VEXstatements.timestamp <= datetime.combine(snapshot_date, datetime.max.time())],
            joins=[(Vulnerabilities, VEXstatements.vulnerability == Vulnerabilities.id),
                    (vex_statement_component, VEXstatements.id == vex_statement_component.c.statement_id),
                    (Components, Components.id == vex_statement_component.c.component_id)]
        )

    EPSS_map = {cve: (score, perc) if score is not None and perc is not None else (0.0, 0.0) for cve, score, perc in EPSS_rows}
    KEV_map = {cve: True for (cve,) in KEV_rows}
    VEX_map = {}

    if not use_epss:
        EPSS_map = {}

    if not use_kev:
        KEV_map = {}

    # Build a mapping of the latest VEX statements for each finding, considering SBOM-specific statements and timestamps.
    # An SBOM-specific statement takes precedence over a global statement, and the latest timestamp takes precedence over older ones.
    for cve_id, purl, status, justification, sbom_id, timestamp in vex_statements:
        key = (cve_id, purl)
        candidate = {
            "sbom_id": sbom_id,
            "status": status,
            "justification": justification,
            "timestamp": timestamp
        }

        current = VEX_map.get(key)
        if current is None:
            VEX_map[key] = candidate
            continue

        # SBOM-specific statements take precedence over global statements
        if candidate["sbom_id"] == sbom_id and current["sbom_id"] is None:
            VEX_map[key] = candidate

        elif candidate["sbom_id"] is None and current["sbom_id"] == sbom_id:
            continue

        elif timestamp > current["timestamp"]:
            VEX_map[key] = candidate


    if cvss_ranking:
        results["cvss"] = cvss_rank(Findings)

    if epss_ranking:
        results["epss"] = epss_rank(Findings, EPSS_map)

    if cvss_epss_ranking:
        results["cvss_epss"] = cvss_epss_rank(Findings, EPSS_map)

    risk_assessment = []
    ranked_assessment = []
    if fusion_ranking:
        for finding_id, cve, CVSS, purl in Findings:
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
                'cve_id': cve,
                'finding_id': finding_id,
                'component_purl': purl,
                'score': fusion_score,
                'priority': priority,
                'priority_rank': priority_rank,
                "why-ranked": " | ".join(explain_fusion(KEV=KEV_status,
                                             CVSS_score=CVSS,
                                             EPSS_probability=EPSS_prob,
                                             EPSS_percentile=EPSS_perc,
                                             vex_status=VEX_map.get((cve, purl), {}).get("status")))
            })

        ranked_assessment = fusion_rank(risk_assessment,vex_statements=VEX_map)

        results["fusion"] = ranked_assessment

    return results