def detect_phishing(url):
    suspicious_keywords = ["login", "verify", "bank", "secure", "account"]

    score = 0

    if "https" not in url:
        score += 1

    if any(word in url.lower() for word in suspicious_keywords):
        score += 1

    if "-" in url:
        score += 1

    if len(url) > 50:
        score += 1

    if score >= 3:
        return {
            "result": "Phishing ⚠️",
            "why": "This URL contains multiple suspicious patterns commonly used in phishing attacks."
        }
    elif score == 2:
        return {
            "result": "Suspicious ❓",
            "why": "This URL shows some unusual characteristics. Be cautious before interacting."
        }
    else:
        return {
            "result": "Safe ✅",
            "why": "No major phishing indicators detected in this URL."
        }