def explain_fusion(KEV, CVSS_score, EPSS_probability, EPSS_percentile, vex_status):
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