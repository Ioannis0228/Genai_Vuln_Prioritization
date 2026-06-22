"""Fusion score calculation used to blend CVSS, EPSS, and KEV signals.

Weight configuration:
- CVSS: 0.35 (relative importance)
- EPSS: 0.45 (relative importance)
- KEV boost: +2 points when a CVE is in the CISA Known Exploited Vulnerabilities catalog

These weights determine how much each signal contributes to the final 0-10 score.
"""

def compute_fusion_score(CVSS_score: float, EPSS_probability: float, EPSS_percentile: float, KEV: bool) -> float:
    """Compute the final vulnerability score from CVSS, EPSS, and KEV inputs.
    
    Args:
        CVSS_score (float): Base Common Vulnerability Scoring System score (0-10).
        EPSS_probability (float): Probability of exploitation from EPSS (0-1).
        EPSS_percentile (float): Percentile rank of EPSS score (0-1).
        KEV (bool): Whether the CVE is in the CISA Known Exploited Vulnerabilities catalog.
    
    Returns:
        float: Final fusion score rounded to 2 decimal places (0-10, capped at 10).
    """
    
    EPSS_score = 0.5 * EPSS_probability * 10 + 0.5 * EPSS_percentile * 10
    Score = 0.35 * CVSS_score + 0.45 * EPSS_score

    if KEV:  # If KEV is not empty, it means the CVE is in KEV, so we boost the score
        Final_score = min(10, Score + 2)
    else: 
        Final_score = Score
    
    return round(Final_score,2)