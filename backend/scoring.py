
def calculate_risk_score(data):
    score = 0
    confidence = 70
    factors = []

    # Tier 1: Basic info
    if data.get('email') and '@' in data['email']:
        score += 5
        factors.append("Valid email format")

    if data.get('postcode'):
        score += 5
        factors.append("Postcode provided")

    if data.get('country'):
        score += 5
        factors.append("Country specified")

    # Tier 2: Verification & work history
    if data.get('idType'):
        score += 15
        factors.append(f"ID type provided: {data['idType']}")

    if data.get('linkedin'):
        score += 10
        factors.append("LinkedIn profile provided")

    if data.get('github'):
        score += 10
        factors.append("GitHub profile provided")

    # Tier 3: Financial history & digital footprint
    if data.get('paymentHistory') == 'Simulated':
        score += 10
        factors.append("Simulated payment history accepted")

    try:
        rep_score = float(data.get('reputationScore', 0)) or 0
    except (ValueError, TypeError):
        rep_score = 0

    if rep_score > 0:
        score += min(rep_score, 10)
        factors.append("Reputation score from social signals")

    # Normalize
    score = min(score, 100)
    confidence = 70 + (score / 10)

    return {
        "score": round(score, 1),
        "confidence": round(confidence, 1),
        "factors": factors
    }
