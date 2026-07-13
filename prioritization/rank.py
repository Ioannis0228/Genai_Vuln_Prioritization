"""Ranking helpers for sorting vulnerabilities by CVSS, EPSS, and fusion score.

These functions print and return ranked CVE lists for different scoring models,
enabling side-by-side comparison of different prioritization strategies.
"""

def cvss_rank(scores):
    """Print and return CVSS scores sorted from highest to lowest.
    
    Args:
        scores (dict): Mapping of CVE ID to CVSS score.
    
    Returns:
        list: Sorted list of tuples (CVE_ID, CVSS_score) in descending order.
    """

    ranked_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

    for rank, item in enumerate(ranked_scores, start=1):
        print(f"{rank:<4}| {item[0]:<20} - CVSS Score: {item[1]}")
    return ranked_scores

def epss_rank(scores):
    """Print and return EPSS scores sorted by probability in descending order.
    
    Args:
        scores (dict): Mapping of CVE ID to tuple (EPSS_probability, EPSS_percentile).
    
    Returns:
        list: Sorted list of tuples (CVE_ID, (probability, percentile)) in descending order by probability.
    """
    ranked_scores = sorted(scores.items(), key=lambda x: x[1][0], reverse=True)

    for rank, item in enumerate(ranked_scores, start=1):
        print(f"{rank:<4}| {item[0]:<20} - EPSS Score: {item[1][0]} with Percentile: {item[1][1]}")
    return ranked_scores         

def cvss_epss_rank(CVSS_map, EPSS_map):
    """Combine CVSS and EPSS into a single ordered list for comparison output.
    
    Computes a hybrid score: min(8, CVSS * 0.35 + EPSS_avg * 0.45) and sorts by this combined value.
    
    Args:
        CVSS_map (dict): Mapping of CVE ID to CVSS score.
        EPSS_map (dict): Mapping of CVE ID to tuple (EPSS_probability, EPSS_percentile).
    
    Returns:
        list: Sorted list of tuples (CVE_ID, combined_score, CVSS, EPSS_avg) in descending order by combined_score.
    """
    combined_scores = []

    for cve, cvss_score in CVSS_map.items():
        
        epss_prob, epss_perc = EPSS_map.get(cve, (0, 0))
        epss_avg = (epss_prob + epss_perc) / 2 * 10
        
        combined_factor = round( min(8, cvss_score * 0.35 + epss_avg * 0.45), 2)
        
        combined_scores.append((cve, combined_factor, cvss_score, epss_avg))

    ranked_scores = sorted(combined_scores, key=lambda x: x[1], reverse=True)

    for rank, item in enumerate(ranked_scores, start=1):
        print(f"{rank:<4}| {item[0]:<20} - CVSS: {item[2]:.2f}, EPSS Avg: {item[3]:.2f}, Combined: {item[1]}")
    return ranked_scores
    

def fusion_rank(risk_assessment, vex_statements=None):
    """Adjust priorities using VEX context and print the final ordered risk list."""

    for items in risk_assessment:
        cve_id = items['cve_id']

        if cve_id in vex_statements and vex_statements[cve_id][0] == items['component_purl']:
            status, justification = vex_statements[cve_id][1:]
            if status.lower() == 'not_affected':
                items['priority'] = 'Informational'
                items['priority_rank'] = 4
            elif status.lower() == 'fixed':
                items['priority'] = 'Low'
                items['priority_rank'] = 3
            elif status.lower() == 'under_investigation':
                items['priority'] = 'Medium'
                items['priority_rank'] = 2

    ranked_scores = sorted(risk_assessment, key=lambda x: (x['priority_rank'], -x['fusion_score']))


    for rank, item in enumerate(ranked_scores, start=1):
        print(f"{rank:<4}| {item['cve_id']:<20} - Fusion Score: {item['fusion_score']} - Priority: {item['priority']} - Component: {item['component_purl']}")
        item["rank"] = rank
    return ranked_scores
