"""Service layer for assembling ranking inputs and persisting fusion results."""

from database import SessionLocal, Components, Vulnerabilities, EPSSsnapshot, KEVsnapshot, VEXstatements, Finding, vex_statement_component, get_rows_by_column_in, execute_select, get_latest_snapshots, save_fusion_results
from prioritization import compute_fusion_score, cvss_rank, epss_rank, cvss_epss_rank, fusion_rank, explain_fusion
from sqlalchemy import or_

def ranking_sbom(sbom_id, cvss_ranking=False, epss_ranking=False, cvss_epss_ranking=False, fusion_ranking=True):
    """Build ranking inputs for a single SBOM and persist the resulting fusion scores.
    
    Retrieves all findings for an SBOM, fetches their associated CVSS/EPSS/KEV/VEX data,
    computes fusion scores, applies VEX status downgrades, and stores results back to the database.
    
    Args:
        sbom_id (int): Primary key of the SBOM to rank.
        cvss_ranking (bool): If True, print and return CVSS-only rankings.
        epss_ranking (bool): If True, print and return EPSS-only rankings.
        cvss_epss_ranking (bool): If True, print and return combined CVSS+EPSS rankings.
        fusion_ranking (bool): If True (default), compute fusion scores and persist results.
    
    Returns:
        list: Risk assessment list with dicts containing: cve_id, finding_id, component_purl, 
              fusion_score, priority, priority_rank, why_ranked.
    """
    with SessionLocal() as session:
        
        Findings = execute_select(
            session = session, 
            selected_columns = [Finding.id, Vulnerabilities.cve_id, Components.purl],
            where_conditions = [Finding.sbom_id == sbom_id],
            joins = [(Finding, Finding.vulnerability_id == Vulnerabilities.id), (Components, Components.id == Finding.component_id)]
        )

        cve_ids = list({row[1] for row in Findings})
        
        CVSS_rows = get_rows_by_column_in(
            session=session,
            tables=[Vulnerabilities],
            filter_column=Vulnerabilities.cve_id,
            filter_values=cve_ids,
            selected_columns=[Vulnerabilities.cve_id, Vulnerabilities.cvss_score]
        )

        EPSS_rows = get_latest_snapshots(
            session=session,
            table=EPSSsnapshot,
            cve_ids=cve_ids,
            date_column=EPSSsnapshot.score_date,
            selected_columns=[EPSSsnapshot.cve_id, EPSSsnapshot.epss_score, EPSSsnapshot.percentile]
        )

        KEV_rows = get_latest_snapshots(
            session=session,
            table=KEVsnapshot,
            cve_ids=cve_ids,
            date_column=KEVsnapshot.created_on,
            selected_columns=[KEVsnapshot.cve_id]
        )

        vex_statements = execute_select(
            session=session,
            selected_columns=[Vulnerabilities.cve_id, Components.purl, VEXstatements.status, VEXstatements.justification],
            where_conditions=[or_(VEXstatements.sbom_id == sbom_id, VEXstatements.sbom_id.is_(None)), Vulnerabilities.cve_id.in_(cve_ids)],
            joins=[(VEXstatements, VEXstatements.vulnerability == Vulnerabilities.id),
                   (vex_statement_component, VEXstatements.id == vex_statement_component.c.statement_id),
                   (Components, Components.id == vex_statement_component.c.component_id)]
        )

    CVSS_map = {cve: score if score is not None else 0 for cve, score in CVSS_rows}
    EPSS_map = {cve: (score, perc) if score is not None and perc is not None else (0, 0) for cve, score, perc in EPSS_rows}
    KEV_map = {cve: True for (cve,) in KEV_rows}
    VEX_map = {(cve,purl): (status, justification) if status is not None else (None, None) for cve, purl, status, justification in vex_statements}

    if cvss_ranking:
        cvss_rank(CVSS_map)

    if epss_ranking:
        epss_rank(EPSS_map)

    if cvss_epss_ranking:
        cvss_epss_rank(CVSS_map, EPSS_map)

    risk_assessment = []
    if fusion_ranking:
        for finding_id, cve, purl in Findings:
            KEV_status = KEV_map.get(cve, False)
            CVSS = CVSS_map.get(cve, 0)
            EPSS_prob, EPSS_perc = EPSS_map.get(cve, (0, 0))
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
                'fusion_score': fusion_score,
                'priority': priority,
                'priority_rank': priority_rank,
                "why-ranked": " | ".join(explain_fusion(KEV=KEV_status,
                                             CVSS_score=CVSS,
                                             EPSS_probability=EPSS_prob,
                                             EPSS_percentile=EPSS_perc,
                                             vex_status=VEX_map.get((cve, purl), (None, None))[0]))
            })

        fusion_rank(risk_assessment,vex_statements=VEX_map)

    save_fusion_results(risk_assessment)

    return risk_assessment