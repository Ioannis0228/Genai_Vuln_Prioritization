def compute_fusion_score(CVSS_score, EPSS_probability, EPSS_percentile, KEV)->float:
    
    EPSS_score = 0.5 * EPSS_probability * 10 + 0.5 * EPSS_percentile * 10
    Score = 0.35 * CVSS_score + 0.45 * EPSS_score

    if KEV:  # If KEV is not empty, it means the CVE is in KEV, so we boost the score
        Final_score = min(10, Score + 2)
    else: 
        Final_score = Score
    
    return round(Final_score,2)