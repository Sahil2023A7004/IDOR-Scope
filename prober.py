#Takes a matched pair from matcher, performs URL surgery to swap the
#resource ID, injects the attacker credentials, forwards real browser
#headers to bypass WAF, fires the request, and returns the raw response.

import json
import requests
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

SKIP_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "upgrade",
}


def clean_headers(raw_headers):                                      #Strip connection headers that would break the outgoing request
    if not raw_headers:                                              #If no headers were passed return an empty dictionary
        return {}
    cleaned = {}
    for key, value in raw_headers.items():                           #Loop through each captured browser header
        if key.lower() not in SKIP_HEADERS:                          #Keep only safe headers
            cleaned[key.lower()] = value                             #Save header with lowercase name in RAM
    return cleaned                                                   #Return the safe header dictionary


def replace_path_segment(path, target_index, new_value):             #Swap one piece of the URL path
    parts = path.split("/")                                          #Split path by slashes
    count = -1                                                       #Counter for real non empty path segments
    for i, segment in enumerate(parts):
        if segment == "":                                            #Skip empty strings created by leading slashes
            continue
        count += 1
        if count == target_index:                                    #Found the exact segment position that holds the ID
            parts[i] = new_value                                     #Replace it with the other user ID
            break
    return "/".join(parts)                                           #Join segments back into a complete URL path


def build_swapped_url(original_url, diff_location, diff_index, diff_key, new_value): #Build the modified test URL
    parsed = urlparse(original_url)                                  #Break full URL into components

    if diff_location == "path":                                      #If the ID is inside the URL path
        new_path = replace_path_segment(parsed.path, diff_index, new_value)
        return urlunparse(parsed._replace(path=new_path))            #Rebuild full URL with the new path

    if diff_location == "query":                                     #If the ID is inside the query string like ?user=42
        pairs = parse_qsl(parsed.query)                              #Break query string into key and value pairs
        updated = [(k, new_value) if k == diff_key else (k, v) for k, v in pairs] #Swap target key value
        return urlunparse(parsed._replace(query=urlencode(updated))) #Rebuild full URL with new query

    if diff_location == "body":                                      #If the ID is inside the JSON body keep the URL unchanged
        return original_url

    raise ValueError(f"Unknown diff_location: {diff_location}")


def build_swapped_body(original_body, diff_key, new_value):          #Swap one field inside a JSON request body
    if not original_body:                                            #If there is no body return None
        return None
    try:
        data = json.loads(original_body)                             #Convert JSON string into a Python dictionary
        data[diff_key] = new_value                                   #Replace the target key with the other user ID
        return json.dumps(data)                                      #Convert dictionary back into a JSON string
    except (json.JSONDecodeError, TypeError):
        return original_body                                         #If body is not valid JSON return it unchanged


def send_probe(url, auth, method="GET", body=None,
               original_headers=None, verify_ssl=True):              #Send one swapped HTTP request to the server
    headers = clean_headers(original_headers)                        #Step 1 Copy safe browser headers so WAF sees a normal browser

    if body is not None and "content-type" not in headers:           #Step 2 Ensure JSON content type if sending a body
        headers["content-type"] = "application/json"

    if auth:                                                         #Step 3 Inject test user credential last so it overwrites the original header
        if auth.get("type") == "bearer":
            headers["authorization"] = f"Bearer {auth.get('value')}" #Add Bearer token
        elif auth.get("type") == "cookie":
            headers["cookie"] = auth.get("value")                    #Add session Cookie

    try:
        response = requests.request(
            method, url, headers=headers, data=body,
            timeout=10, verify=verify_ssl                            #Send request over TCP and check SSL based on flag
        )
        return {"status": response.status_code, "body": response.text, "error": None} #Return response to RAM
    except requests.RequestException as e:
        return {"status": None, "body": None, "error": str(e)}       #If network error happens return error string


def run_pair_probe(match, auth_a, auth_b, verify_ssl=True):          #Test IDOR in both directions for a matched pair
    url_a_to_b = build_swapped_url(                                  #Build URL where User A requests User B resource
        match.request_a["url"], match.diff_location,
        match.diff_index, match.diff_key, match.id_value_b
    )
    url_b_to_a = build_swapped_url(                                  #Build URL where User B requests User A resource
        match.request_b["url"], match.diff_location,
        match.diff_index, match.diff_key, match.id_value_a
    )

    body_a_to_b = match.request_a.get("body")                        #Start with User A original request body
    body_b_to_a = match.request_b.get("body")                        #Start with User B original request body
    if match.diff_location == "body":                                #If the ID is in the body swap the ID inside both JSON bodies
        body_a_to_b = build_swapped_body(match.request_a.get("body"), match.diff_key, match.id_value_b)
        body_b_to_a = build_swapped_body(match.request_b.get("body"), match.diff_key, match.id_value_a)

    response_a_to_b = send_probe(                                    #Fire probe with User A credentials aimed at User B resource
        url_a_to_b, auth_a, method=match.method,
        body=body_a_to_b, original_headers=match.request_a.get("headers"),
        verify_ssl=verify_ssl
    )
    response_b_to_a = send_probe(                                    #Fire probe with User B credentials aimed at User A resource
        url_b_to_a, auth_b, method=match.method,
        body=body_b_to_a, original_headers=match.request_b.get("headers"),
        verify_ssl=verify_ssl
    )

    return {
        "a_credentials_b_resource": {"swapped_url": url_a_to_b, "response": response_a_to_b},
        "b_credentials_a_resource": {"swapped_url": url_b_to_a, "response": response_b_to_a},
    }                                                                #Return both probe results back to engine


# requests.request sends an HTTP packet with any method like GET or POST to the target server
# urlparse and urlunparse break a URL apart to swap the ID and glue it back together cleanly
# urlencode turns a list of query key and value pairs back into a valid URL query string

# Variables Used:

# SKIP HEADERS holds connection level headers like host and content length that must not be copied
# headers holds the cleaned browser headers plus the injected test user login credential
# url a to b holds the modified URL where User B ID is placed into User A request
# body a to b holds the modified JSON payload when the resource ID lives inside the request body
# verify ssl tells requests whether to validate HTTPS certificates or ignore self signed errors

# Working:

# engine calls run pair probe with a MatchedPair and the login credentials for both users
# First build swapped url places User B ID into User A URL and vice versa
# If the ID was inside a JSON payload build swapped body swaps the ID inside the body text
# Next send probe copies the original browser headers removes SKIP HEADERS and writes the test credential last
# Both requests are sent over the network and their status codes and response bodies are returned to engine