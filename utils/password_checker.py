def check_password_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if any(char.isdigit() for char in password):
        score += 1
    if any(char.isupper() for char in password):
        score += 1
    if any(char in "!@#$%^&*" for char in password):
        score += 1

    if score <= 1:
        return {
            "level": "Weak ❌",
            "why": "Weak passwords are easy to guess and can be cracked quickly by attackers using brute-force methods.",
            "score": score
        }
    elif score == 2:
        return {
            "level": "Medium ⚠️",
            "why": "Your password has some strength but may still be vulnerable to dictionary or guessing attacks.",
            "score": score
        }
    else:
        return {
            "level": "Strong ✅",
            "why": "Strong passwords are harder to crack and provide better protection against unauthorized access.",
            "score": score
        }