"""Human-readable explanations for fusion score components and priority decisions."""

def explain_fusion(KEV: bool, CVSS_score: float, EPSS_probability: float, EPSS_percentile: float, vex_status: str) -> list:
    """Build a list of factors that contributed to the final fusion ranking.
    
    Generates human-readable explanation strings for each scoring component.
    Used to justify why a finding received its final priority in the ranking.
    
    Args:
        KEV (bool): Whether the CVE is in CISA's Known Exploited Vulnerabilities catalog.
        CVSS_score (float): The CVSS base score for the CVE (0-10).
        EPSS_probability (float): The EPSS exploitation probability (0-1).
        EPSS_percentile (float): The EPSS percentile rank (0-1).
        vex_status (str): VEX status like 'not_affected', 'fixed', 'under_investigation', 'affected'.
    
    Returns:
        list: List of human-readable explanation strings describing the ranking factors.
    """

    reasons = []
    if KEV:
        reasons.append("Active Exploitation Identified (CISA KEV Boost Added)")
    if CVSS_score:
        reasons.append(f"CVSS Score: {CVSS_score}")
    if EPSS_percentile:
        reasons.append(f"EPSS Percentile: {EPSS_percentile:.3%}")
    if EPSS_probability:
        reasons.append(f"EPSS Probability: {EPSS_probability:.3%}")

    if vex_status:
        vex_clean = vex_status.strip().lower()
        vex_labels = {
            'not_affected': "VEX Status: 'not_affected', Priority reduced",
            'fixed': "VEX Status: 'fixed', Priority reduced",
            'under_investigation': "VEX Status: 'under_investigation', Priority reduced",
            'affected': "VEX Status: 'affected', No priority change",
        }
        # Fall back to raw status if it's an unmapped custom string
        reasons.append(vex_labels.get(vex_clean, f"VEX Status: '{vex_status}'"))

    return reasons