"""Ranking helpers for sorting vulnerabilities by CVSS, EPSS, and fusion score.

These functions return ranked finding lists for different scoring models,
enabling side-by-side comparison of different prioritization strategies.
"""

def cvss_rank(findings) -> list:
    """Return a list of findings sorted by CVSS score from highest to lowest.
    
    Args:
        findings (list): List of finding records. [finding_id, cve_id, cvss_score, purl]
    
    Returns:
        list: Sorted list of tuples (CVE_ID, CVSS_score) in descending order.
    """

    ranked_findings = []

    for finding in findings:
        finding_id, cve_id, cvss_score, purl = finding

        ranked_findings.append({
            "finding_id": finding_id,
            "cve_id": cve_id,
            "score": cvss_score or 0,
            "component_purl": purl,
        })

    return sorted(ranked_findings, key=lambda finding: finding["score"], reverse=True)

def epss_rank(findings, epss_map) -> list:
    """Return a list of findings sorted by EPSS score from highest to lowest.
    
    Args:
        findings (list): List of finding records. [finding_id, cve_id, cvss_score, purl]
        epss_map (dict): Mapping of CVE ID to tuple (EPSS_probability, EPSS_percentile).
    
    Returns:
        list: Sorted list of tuples (CVE_ID, (probability, percentile)) in descending order by probability.
    """
    ranked_findings = []

    for finding in findings:
        finding_id, cve_id, _, purl = finding

        epss_score, percentile = epss_map.get(cve_id, (0, 0))

        ranked_findings.append({
            "finding_id": finding_id,
            "cve_id": cve_id,
            "component_purl": purl,
            "score": epss_score,
            "epss_percentile": percentile
        })

    return sorted(ranked_findings, key=lambda finding: finding["score"], reverse=True)        

def cvss_epss_rank(findings, epss_map) -> list:
    """Return a list of findings sorted by a combined CVSS and EPSS score from highest to lowest.
    
    Computes a hybrid score: min(8, CVSS * 0.35 + EPSS_avg * 0.45) and sorts by this combined value.
    
    Args:
        findings (list): List of finding records. [finding_id, cve_id, cvss_score, purl]
        epss_map (dict): Mapping of CVE ID to tuple (EPSS_probability, EPSS_percentile).
    
    Returns:
        list: Sorted list of tuples (CVE_ID, combined_score, CVSS, EPSS_avg) in descending order by combined_score.
    """

    ranked_findings = []

    for finding in findings:
        finding_id, cve_id, cvss_score, purl = finding

        epss_score, percentile = epss_map.get(cve_id, (0, 0))
        epss_avg = (epss_score + percentile) / 2 * 10

        ranked_findings.append({
            "finding_id": finding_id,
            "cve_id": cve_id,
            "cvss_score": cvss_score or 0,
            "component_purl": purl,
            "epss_avg": epss_avg,
            "score": round(min(8, (cvss_score or 0) * 0.35 + epss_avg * 0.45), 2)
        })

    return sorted(ranked_findings, key=lambda finding: finding["score"], reverse=True)
    

def fusion_rank(risk_assessment, vex_statements=None) -> list[dict]:
    """Return a list of findings sorted by fusion score, applying VEX status downgrades.
    
    Args:
        risk_assessment (list): List of risk assessment items.
        vex_statements (dict): VEX statements to consider.

    Returns:
        list: Final ordered list of risk items.
    """
    if vex_statements is None:
        vex_statements = {}

    for items in risk_assessment:
        lookup_key = (items['cve_id'], items['component_purl'])
        
        if lookup_key in vex_statements:
            vex = vex_statements.get(lookup_key, {})

            if not vex or not vex.get("status"):
                continue

            status = vex["status"].lower()
                
            if status.lower() == 'not_affected':
                items['priority'] = 'Informational'
                items['priority_rank'] = 4
            elif status.lower() == 'fixed':
                items['priority'] = 'Low'
                items['priority_rank'] = 3
            elif status.lower() == 'under_investigation':
                pass

    ranked_scores = [
        {**item,"rank":rank} for rank, item in enumerate(
            sorted(risk_assessment, key=lambda x: (x['priority_rank'], -x['score'])),
            start=1)
    ]

    return ranked_scores
