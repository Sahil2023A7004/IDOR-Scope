# Automatically finds how each user logs in (Bearer token or Cookie),
# Decodes JWT claims if present, and scans response bodies for personal
# data like emails, usernames, and phone numbers to prove data leaks.

import re
import json
import base64
from collections import Counter

EMAIL = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE = re.compile(r"\b\d{9,12}\b")

PERSONAL_KEYS = {"username", "user_name", "login", "handle", "display_name",
                 "name", "full_name", "first_name", "last_name", "email",
                 "phone", "mobile", "user_id", "account_id", "id"}


def decode_base64(text): #Safely decode base64url with padding fix
    remainder = len(text) % 4
    if remainder > 0:
        text += "=" * (4 - remainder) #Base64 requires length divisible by 4
    try:
        return base64.urlsafe_b64decode(text.encode("utf-8")).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_auth(requests): #Find login method from captured traffic automatically
    tokens = [] #Collect all Bearer tokens seen
    cookies = [] #Collect all Cookie headers seen

    for req in requests: #Loop through every request in the clean list
        headers = req.get("headers", {}) #Get the flat header dictionary

        auth = headers.get("authorization", "") #Check for Authorization header
        if auth.startswith("Bearer "): #If it starts with Bearer it is a token
            tokens.append(auth[len("Bearer "):].strip()) #Strip the word Bearer and save

        cookie = headers.get("cookie", "") #Check for Cookie header
        if cookie: #If cookie exists
            cookies.append(cookie.strip()) #Save it

    if tokens: #If we found Bearer tokens
        winner = Counter(tokens).most_common(1)[0][0] #Pick the most frequently used one
        return {"type": "bearer", "value": winner}

    if cookies: #If no tokens but cookies exist
        winner = Counter(cookies).most_common(1)[0][0] #Pick the most frequently used one
        return {"type": "cookie", "value": winner}

    return None #No auth found at all


def extract_bearer_token(requests): #Backward compatibility for original engine calls
    auth = extract_auth(requests)
    if auth and auth["type"] == "bearer":
        return auth["value"]
    return None


def claims_from_jwt(token): #Decode JWT payload and extract identity claims
    if not token or not isinstance(token, str):
        return set()

    parts = token.split(".") #JWT has 3 parts separated by dots
    if len(parts) != 3: #If it does not have 3 sprate parts, it is not a JWT
        return set()

    payload_text = decode_base64(parts[1]) #Decode the middle segment (payload)
    try:
        payload = json.loads(payload_text) #Parse JSON from decoded text
    except (json.JSONDecodeError, TypeError):
        return set()

    claims = set() #Collect identity values found
    for key in ("sub", "email", "username", "preferred_username", "name"):
        val = payload.get(key) #Check if this claim exists in the payload
        if val and isinstance(val, (str, int)): #If it exists and is a real value
            claims.add(str(val)) #Add it to our identity set
    return claims


def extract_identity_values(requests): #Scan response bodies for personal data
    found = set() #Store identity values

    for req in requests: #Loop through every request
        body = req.get("response_body") #Get the server response text
        if not body: #If empty skip
            continue

        for match in EMAIL.findall(body): #Find all email addresses in response
            found.add(match)
        for match in PHONE.findall(body): #Find all phone numbers in response
            found.add(match)

        try: #Try to parse response as JSON for structured field extraction
            parsed = json.loads(body)
            walk_json(parsed, found) #Walk through nested JSON pulling personal fields
        except (json.JSONDecodeError, TypeError):
            continue

    return found


def walk_json(data, collected): #Recursively walk JSON to find personal field values
    if isinstance(data, dict): #If current level is a dictionary
        for key, val in data.items(): #Check each key value pair
            if key.lower() in PERSONAL_KEYS and isinstance(val, (str, int)):
                text = str(val).strip()
                if text and len(text) > 1: #Skip empty or single char values like "0"
                    collected.add(text) #Add to identity collection
            walk_json(val, collected) #Go deeper into nested structures
    elif isinstance(data, list): #If current level is a list
        for item in data: #Check each item
            walk_json(item, collected) #Go deeper and keep recursively doing it until it meets the required condition


# Libraries Used:
# re (builtin) provides regex patterns to find emails and phone numbers in text
# json (builtin) parses JSON response bodies and JWT payloads
# base64 (builtin) decodes the middle segment of JWT tokens
# Counter (from collections) counts occurrences to find most common token or cookie

# Variables Used:
# tokens: collects every Bearer token string seen across all requests
# cookies: collects every Cookie header string seen across all requests
# winner: is the most frequently used token or cookie (the real session credential)
# found: is the set that accumulates all personal data values (emails phones usernames)
# claims: is the set of identity values extracted from inside a JWT payload
# parsed: is a JSON response body converted from text into Python dictonries and lists

# Working:
# engine.py calls extract auth with the clean request list from har loader
# extract auth loops through every request checking headers for Bearer or Cookie
# The most common credential is returned as a typed dict (type and value)
# engine.py then calls claims from jwt on the token to get user ID email etc from JWT
# engine.py also calls extract identity values which scans all response bodies
# It uses regex to find emails and phones in raw text
# Then parses JSON responses and walks through nested structures
# Looking for keys like username, full name, account id
# All found values are merged into one identity set per user
# This identity set is later used by classifier to prove a leak is real