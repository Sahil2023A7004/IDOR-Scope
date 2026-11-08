#Automatically finds how each user logs in using a Bearer token or Cookie.
#Decodes JWT claims if present and scans response bodies for personal
#data like emails, usernames, and phone numbers to prove data leaks.

import re
import json
import base64
from collections import Counter

EMAIL = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE = re.compile(r"\b\d{9,12}\b")

PERSONAL_KEYS = {
    "username", "user_name", "login", "handle", "display_name",
    "full_name", "first_name", "last_name", "email",
    "phone", "mobile", "user_id", "account_id",
}

MAX_WALK_DEPTH = 30                                                  #Stop recursion at 30 levels deep so huge JSON files never crash RAM


def decode_base64(text):                                             #Decode base64 text safely into readable words
    remainder = len(text) % 4
    if remainder > 0:
        text += "=" * (4 - remainder)                                #Add equals signs at the end so length divides by 4
    try:
        return base64.urlsafe_b64decode(text.encode("utf-8")).decode("utf-8", errors="ignore")
    except Exception:
        return ""                                                    #If decoding fails return an empty string instead of crashing


def extract_auth(requests):                                          #Find the user login credential automatically from traffic
    tokens = []                                                      #List to store all Bearer tokens found
    cookies = []                                                     #List to store all Cookies found

    for req in requests:                                             #Loop through every clean request
        headers = req.get("headers", {})                             #Get the request headers dictionary

        auth = headers.get("authorization", "")                      #Look for the authorization header
        if auth.startswith("Bearer "):                               #Check if it uses a Bearer token
            tokens.append(auth[len("Bearer "):].strip())             #Remove the word Bearer and save the token

        cookie = headers.get("cookie", "")                           #Look for the cookie header
        if cookie:                                                   #Check if a cookie exists
            cookies.append(cookie.strip())                           #Save the cookie string

    if tokens:                                                       #If Bearer tokens were found prefer them first
        winner = Counter(tokens).most_common(1)[0][0]                #Pick the token used most often
        return {"type": "bearer", "value": winner}                   #Return token type and value to RAM

    if cookies:                                                      #If no Bearer token exists use the session cookie
        winner = Counter(cookies).most_common(1)[0][0]               #Pick the cookie used most often
        return {"type": "cookie", "value": winner}                   #Return cookie type and value to RAM

    return None                                                      #If neither exists return None


def extract_bearer_token(requests):                                  #Helper function that returns only a Bearer token string
    auth = extract_auth(requests)
    if auth and auth["type"] == "bearer":
        return auth["value"]
    return None


def claims_from_jwt(token):                                          #Open up a JWT token and pull out user identity info
    if not token or not isinstance(token, str):
        return set()

    parts = token.split(".")                                         #Split token by dots since JWT has 3 parts
    if len(parts) != 3:                                              #If it does not have 3 parts it is not a JWT
        return set()

    payload_text = decode_base64(parts[1])                           #Decode the middle part which holds user data
    try:
        payload = json.loads(payload_text)                           #Convert decoded text into a Python dictionary
    except (json.JSONDecodeError, TypeError):
        return set()

    claims = set()                                                   #Create a set to store unique identity values
    for key in ("sub", "email", "username", "preferred_username", "name"):
        val = payload.get(key)                                       #Check if this field exists inside the JWT
        if val and isinstance(val, (str, int)):
            claims.add(str(val))                                     #Save the value as a string
    return claims                                                    #Return all extracted JWT identity values


def extract_identity_values(requests):                               #Scan server responses for user personal data
    found = set()                                                    #Set to store unique personal values for this user

    for req in requests:                                             #Loop through every captured request
        body = req.get("response_body")                              #Get the response text sent by the server
        if not body:                                                 #If response is empty skip it
            continue

        for match in EMAIL.findall(body):                            #Find any email addresses in the text
            found.add(match)
        for match in PHONE.findall(body):                            #Find any phone numbers in the text
            found.add(match)

        try:
            parsed = json.loads(body)                                #Try to convert response text into a JSON object
            walk_json(parsed, found)                                 #Search inside the JSON for personal fields
        except (json.JSONDecodeError, TypeError):
            continue                                                 #If response is not JSON move to the next request

    return found                                                     #Return all personal values belonging to this user


def walk_json(data, collected, depth=0):                             #Step through nested JSON to grab personal field values
    if depth > MAX_WALK_DEPTH:                                       #Stop if nesting goes deeper than 30 levels
        return
    if isinstance(data, dict):                                       #If current item is a JSON dictionary
        for key, val in data.items():                                #Check every key and value pair
            if key.lower() in PERSONAL_KEYS and isinstance(val, (str, int)):
                text = str(val).strip()
                if text and len(text) > 1:                           #Ignore empty values or single characters like 0
                    collected.add(text)                              #Save the personal value
            walk_json(val, collected, depth + 1)                     #Step deeper into nested objects
    elif isinstance(data, list):                                     #If current item is a JSON list
        for item in data:                                            #Check every item in the list
            walk_json(item, collected, depth + 1)                    #Step deeper into the list item


# re.compile builds a search pattern in RAM to quickly spot emails and phone numbers
# base64.urlsafe b64decode translates encoded JWT text back into readable characters
# Counter counts how many times each token or cookie appears so we pick the active session

# Variables Used:

# PERSONAL KEYS holds specific account field names like username email and account id
# Generic words like id and name are excluded from PERSONAL KEYS so product names do not cause false alerts
# MAX WALK DEPTH limits how deep walk json can go so deeply nested data never crashes Python
# tokens and cookies store all credentials seen across the user traffic
# winner stores the single most frequent credential used by that user
# found and claims store the personal identity strings that belong to the user

# Working:

# engine calls extract auth to find whether the user logs in with a Bearer token or Cookie
# If a JWT Bearer token is found claims from jwt decodes its middle section to grab user IDs and emails
# Next extract identity values scans all response bodies using regex and walk json
# It collects account specific values like emails phone numbers and usernames into a set
# This identity set is passed to classifier so it can tell if User A data leaks into User B responses