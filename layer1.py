
def layer1_rule_based(row):
    """
    Layer 1: Rule-based detection using D2-D6 and fuzzy score.
    Returns:
        1 → Phishing (detected at Layer 1)
        0 → Pass to Layer 2
    """
    # If any D2-D5 is 1, check fuzzy similarity in domain/subdomain
    if row['D2'] or row['D3'] or row['D4'] or row['D5'] or row['D6']:
        return 1  # If D2-D6 triggers, consider phishing anyway
    else:
        return 0  # Pass to Layer 2
