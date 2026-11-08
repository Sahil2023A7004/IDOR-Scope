"""
Automatically extracts authentication credentials (Bearer tokens OR session cookies)
and builds a user identity profile (emails, usernames, phone numbers, and JWT claims)
from captured user traffic to prove data leaks without manual inspection.
"""

import re
import json
import base64
from collections import Counter

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_PATTERN = re.compile(r"\b\d{9,12}\b")

# High-value personal fields to inspect inside JSON response bodies
IDENTITY_KEYS = {
    "username", "user_name", "login", "handle", "display_name",
    "name", "full_name", "first_name", "last_name", "email",
    "phone", "mobile", "user_id", "account_id", "id"
}


def _safe_b64_decode(payload_str):
    #Decode base64url string with required padding
    rem = len(payload_str) % 4
    if rem > 0:
        payload_str += "=" * (4 - rem)
    try:
        return base64.urlsafe_b64decode(payload_str.encode("utf-8")).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_identity_from_token(token):
    """
    If token is a JWT (header.payload.signature), decode the middle payload
    and extract identity claims (sub, email, username, etc.) without needing a secret key.
    """
    if not token or not isinstance(token, str):
        return set()

    parts = token.split(".")
    if len(parts) != 3:
        return set()

    payload_json = _safe_b64_decode(parts[1])
    try:
        payload = json.loads(payload_json)
    except (json.JSONDecodeError, TypeError):
        return set()

    claims = set()
    for key in ("sub", "email", "username", "preferred_username", "name"):
        val = payload.get(key)
        if val and isinstance(val, (str, int)):
            claims.add(str(val))
    return claims


def extract_auth(requests):
    """
    Auto-detect authentication method. Checks for Bearer token first,
    falls back to session Cookie header.
    Returns: {"type": "bearer"|"cookie", "value": "<credential_string>"} or None
    """
    tokens = []
    cookies = []

    for req in requests:
        headers = req.get("headers", {})

        # Check for Authorization header
        auth = headers.get("authorization", "")
        if auth.startswith("Bearer "):
            tokens.append(auth[len("Bearer "):].strip())

        # Check for Cookie header
        cookie = headers.get("cookie", "")
        if cookie:
            cookies.append(cookie.strip())

    if tokens:
        most_common_token = Counter(tokens).most_common(1)[0][0]
        return {"type": "bearer", "value": most_common_token}

    if cookies:
        most_common_cookie = Counter(cookies).most_common(1)[0][0]
        return {"type": "cookie", "value": most_common_cookie}

    return None


def extract_bearer_token(requests):
    #Backward compatibility helper for original engine calls
    auth = extract_auth(requests)
    if auth and auth["type"] == "bearer":
        return auth["value"]
    return None


def extract_identity_values(requests):
    """
    Scan response bodies for identity values (emails, phone numbers,
    and specific JSON profile keys like username, full_name, user_id).
    """
    found_values = set()

    for req in requests:
        body = req.get("response_body")
        if not body:
            continue

        # Regex scan (text-level)
        for email in EMAIL_PATTERN.findall(body):
            found_values.add(email)
        for phone in PHONE_PATTERN.findall(body):
            found_values.add(phone)

        # JSON key scan (structured profile fields)
        try:
            parsed = json.loads(body)
            _collect_keys_recursive(parsed, found_values)
        except (json.JSONDecodeError, TypeError):
            continue

    return found_values


def _collect_keys_recursive(data, collected_set):
    #Walk nested JSON dictionaries/lists to extract known identity fields
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() in IDENTITY_KEYS and isinstance(v, (str, int)):
                # Ignore generic booleans or empty values
                str_val = str(v).strip()
                if str_val and len(str_val) > 1:
                    collected_set.add(str_val)
            _collect_keys_recursive(v, collected_set)
    elif isinstance(data, list):
        for item in data:
            _collect_keys_recursive(item, collected_set)