#Takes a matched pair from matcher, performs URL surgery to swap the
#resource ID, injects the attacker credentials, forwards real browser
#headers to bypass WAF, fires the request, and returns the raw response.
#This is the automated Burp Suite Repeater of the project.

import json
import requests
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

#Headers that must never be forwarded from HAR captures
#These are connection level controls that break requests if forwarded
SKIP_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "upgrade",
}


def clean_headers(raw_headers):#Remove dangerous headers and normalize to lowercase
    if not raw_headers:#If no headers provided return empty dict
        return {}
    cleaned = {}
    for key, value in raw_headers.items():#Loop through each header
        if key.lower() not in SKIP_HEADERS:#Only keep safe headers
            cleaned[key.lower()] = value#Normalize key to lowercase
    return cleaned


def replace_path_segment(path, target_index, new_value):#Swap one segment in URL path
    parts = path.split("/")#Chop path into segments
    count = -1#Counter for non empty segments only
    for i, segment in enumerate(parts):
        if segment == "":#Skip empty segments from leading slashes
            continue
        count += 1
        if count == target_index:#Found the segment to replace
            parts[i] = new_value#Swap it
            break
    return "/".join(parts)#Glue segments back into a path string


def build_swapped_url(original_url, diff_location, diff_index, diff_key, new_value):#URL surgery
    parsed = urlparse(original_url)#Split URL into components

    if diff_location == "path":#ID is in the path like /api/users/42
        new_path = replace_path_segment(parsed.path, diff_index, new_value)
        return urlunparse(parsed._replace(path=new_path))

    if diff_location == "query":#ID is in query like ?user_id=42
        pairs = parse_qsl(parsed.query)#Get current query pairs
        updated = [(k, new_value) if k == diff_key else (k, v) for k, v in pairs]
        return urlunparse(parsed._replace(query=urlencode(updated)))

    if diff_location == "body":#ID is in request body, URL stays the same
        return original_url

    raise ValueError(f"Unknown diff_location: {diff_location}")


def build_swapped_body(original_body, diff_key, new_value):#Swap one field in JSON body
    if not original_body:#No body to modify
        return None
    try:
        data = json.loads(original_body)#Parse JSON body into dict
        data[diff_key] = new_value#Replace the target field value
        return json.dumps(data)#Convert back to JSON string
    except (json.JSONDecodeError, TypeError):
        return original_body#If not valid JSON return as is


def send_probe(url, auth, method="GET", body=None, original_headers=None):#Fire one HTTP request
    #Step 1: Copy browser headers first so WAF sees real browser fingerprint
    headers = clean_headers(original_headers)

    #Step 2: Set content type if body exists and original headers dont have one
    if body is not None and "content-type" not in headers:
        headers["content-type"] = "application/json"

    #Step 3: Inject test credential LAST so it always overrides the original
    if auth:
        if auth.get("type") == "bearer":
            headers["authorization"] = f"Bearer {auth.get('value')}"
        elif auth.get("type") == "cookie":
            headers["cookie"] = auth.get("value")

    try:
        response = requests.request(method, url, headers=headers, data=body, timeout=10)
        return {"status": response.status_code, "body": response.text, "error": None}
    except requests.RequestException as e:
        return {"status": None, "body": None, "error": str(e)}


def run_pair_probe(match, auth_a, auth_b):#Run both directions of IDOR probe
    #Build swapped URLs
    url_a_to_b = build_swapped_url(#User A credentials aimed at User B resource
        match.request_a["url"], match.diff_location,
        match.diff_index, match.diff_key, match.id_value_b
    )
    url_b_to_a = build_swapped_url(#User B credentials aimed at User A resource
        match.request_b["url"], match.diff_location,
        match.diff_index, match.diff_key, match.id_value_a
    )

    #Build swapped bodies if the ID lives in the request body
    body_a_to_b = match.request_a.get("body")#Default to original body
    body_b_to_a = match.request_b.get("body")
    if match.diff_location == "body":#If ID is in JSON body swap it
        body_a_to_b = build_swapped_body(match.request_a.get("body"), match.diff_key, match.id_value_b)
        body_b_to_a = build_swapped_body(match.request_b.get("body"), match.diff_key, match.id_value_a)

    #Fire both probes with original browser headers for WAF bypass
    response_a_to_b = send_probe(
        url_a_to_b, auth_a, method=match.method,
        body=body_a_to_b, original_headers=match.request_a.get("headers")
    )
    response_b_to_a = send_probe(
        url_b_to_a, auth_b, method=match.method,
        body=body_b_to_a, original_headers=match.request_b.get("headers")
    )

    return {
        "a_credentials_b_resource": {"swapped_url": url_a_to_b, "response": response_a_to_b},
        "b_credentials_a_resource": {"swapped_url": url_b_to_a, "response": response_b_to_a},
    }


# Libraries Used:
# requests sends HTTP requests over TCP socket to target server
# json parses and rebuilds JSON request bodies for body parameter swapping
# urlparse (from urllib.parse) splits URL into components (scheme domain path query)
# urlunparse reassembles URL components back into a full URL string
# urlencode converts query parameter pairs back into a query string
# parse_qsl splits query string like "id=5&page=1" into a list of tuples

# Variables Used:
# SKIP HEADERS is the set of dangerous headers that break requests if forwarded
# parsed holds the URL split into components by urlparse
# headers is the clean header dictionary forwarded from the HAR capture
# auth is the credential dict from token extractor with type (bearer/cookie) and value
# body a to b is the request body with User B ID swapped in for User A to send
# url a to b is the URL with User B resource ID for User A credentials to access

# Working:
# engine.py calls run pair probe with a MatchedPair and both users auth dicts
# For each direction (A to B and B to A):
#   1. build swapped url rewrites the URL replacing the target ID
#   2. If the ID lives in the body build swapped body replaces it in JSON
#   3. send probe assembles the full HTTP request:
#      First copies original browser headers (User Agent Accept etc) for WAF bypass
#      Strips dangerous headers like Host and Content Length
#      Then injects the test credential LAST so it always overrides the original
#      Fires the request and captures the raw response
# Both responses are returned to engine which passes them to classifier