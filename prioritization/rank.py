def cvss_rank(scores):
    ranked_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

    for rank, item in enumerate(ranked_scores, start=1):
        print(f"{rank}. {item[0]} - CVSS Score: {item[1]}")
    return ranked_scores

def epss_rank(scores):
    ranked_scores = sorted(scores.items(), key=lambda x: x[1][0], reverse=True)

    for rank, item in enumerate(ranked_scores, start=1):
        print(f"{rank}. {item[0]} - EPSS Score: {item[1][0]} with Percentile: {item[1][1]}")
    return ranked_scores         

def cvss_epss_rank(CVSS_map, EPSS_map):
    combined_scores = []

    for cve, cvss_score in CVSS_map.items():
        
        epss_prob, epss_perc = EPSS_map.get(cve, (0, 0))
        epss_avg = (epss_prob + epss_perc) / 2 * 10
        
        combined_factor = round( min(8, cvss_score * 0.35 + epss_avg * 0.45), 2)
        
        combined_scores.append((cve, combined_factor, cvss_score, epss_avg))

    ranked_scores = sorted(combined_scores, key=lambda x: x[1], reverse=True)

    for rank, item in enumerate(ranked_scores, start=1):
        print(f"{rank}. {item[0]} - CVSS: {item[2]:.2f}, EPSS Avg: {item[3]:.2f}, Combined: {item[1]}")
    return ranked_scores
    

def fusion_rank(scores, vex_statements=None):

    for score_items in scores:
        cve_id = score_items['cve_id']

        if cve_id in vex_statements:
            status, justification = vex_statements[cve_id]
            if status.lower() == 'not_affected':
                score_items['priority'] = 'Informational'
                score_items['priority_rank'] = 4
            elif status.lower() == 'fixed':
                score_items['priority'] = 'Low'
                score_items['priority_rank'] = 3
            elif status.lower() == 'under_investigation':
                score_items['priority'] = 'Medium'
                score_items['priority_rank'] = 2

    ranked_scores = sorted(scores, key=lambda x: (x['priority_rank'], -x['fusion_score']))


    for rank, item in enumerate(ranked_scores, start=1):
        print(f"{rank}. {item['cve_id']} - Fusion Score: {item['fusion_score']} - Priority: {item['priority']}")
    return ranked_scores
