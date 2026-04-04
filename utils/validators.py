import re

def is_valid_password(password):
    if not password or len(password) < 3:
        return False
    return True


def is_valid_url(url):
    # simple URL pattern
    pattern = re.compile(
        r'^(http://|https://)?(www\.)?[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}'
    )
    return re.match(pattern, url) is not None