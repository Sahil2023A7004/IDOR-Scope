#Engine 2 verifies state changing requests such as delete, update, and post.
#Instead of inspecting response bodies which often return generic success messages,
#this reads the resource state before the test, executes the action request,
#reads the state again after, and compares them to verify if server state changed.

import json
import requests

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

SKIP_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "upgrade",
}

DYNAMIC_KEYS = {
    "timestamp", "ts", "updated_at", "created_at", "modified_at",
    "last_modified", "expires", "expires_at", "ttl",
    "request_id", "trace_id", "correlation_id",
    "server_time", "response_time", "nonce",
}


def clean_headers(raw_headers): #Remove hop by hop headers before forwarding
    if not raw_headers:         #If no headers exist return empty dictionary
        return {}
    cleaned = {}
    for key, value in raw_headers.items():  #Loop through every header pair
        if key.lower() not in SKIP_HEADERS: #Only keep safe browser headers
            cleaned[key.lower()] = value    #Store normalized lowercase header in RAM
    return cleaned                          #Return clean header dictionary


def is_state_changing(method):                        #Check if HTTP method modifies server state
    return method.upper() in STATE_CHANGING_METHODS   #Return True if POST PUT PATCH or DELETE


def stable_body_changed(body_before, body_after):   #Compare responses while ignoring rotating timestamps
    if body_before == body_after:                   #If both strings are identical nothing changed
        return False
    try:
        a = json.loads(body_before or "")          #Convert before text into Python dictionary
        b = json.loads(body_after or "")           #Convert after text into Python dictionary
        if isinstance(a, dict) and isinstance(b, dict):                                #If both are JSON objects
            a_stable = {k: v for k, v in a.items() if k.lower() not in DYNAMIC_KEYS}   #Remove dynamic keys from before
            b_stable = {k: v for k, v in b.items() if k.lower() not in DYNAMIC_KEYS}   #Remove dynamic keys from after
            return a_stable != b_stable                                                #Return True only if real data fields changed
        return a != b                                                                  #Compare JSON lists or simple values directly
    except (json.JSONDecodeError, TypeError, ValueError):
        return body_before != body_after                                    #If not valid JSON fall back to raw text comparison


def read_resource_state(url, auth, original_headers=None, verify_ssl=True): #Read current state of resource
    headers = clean_headers(original_headers)                               #Copy browser headers for standard verification

    if isinstance(auth, dict):                                         #Check auth dictionary format
        if auth.get("type") == "bearer":
            headers["authorization"] = f"Bearer {auth.get('value')}"   #Attach Bearer token
        elif auth.get("type") == "cookie":
            headers["cookie"] = auth.get("value")                      #Attach session cookie
    elif isinstance(auth, str):                                        #Direct token string fallback
        headers["authorization"] = f"Bearer {auth}"

    try:
        response = requests.get(url, headers=headers, timeout=10, verify=verify_ssl)    #Send GET request to target
        return {"status": response.status_code, "body": response.text, "error": None}   #Return snapshot to RAM
    except requests.RequestException as e:
        return {"status": None, "body": None, "error": str(e)}                          #If network fails return error details


def verify_action_swap(read_back_url, owner_auth, send_action_fn,
                       original_headers=None, verify_ssl=True):                            #Verify side effects on target resource
    before = read_resource_state(read_back_url, owner_auth, original_headers, verify_ssl)  #Step 1 Snapshot state before action
    action_result = send_action_fn()#Step 2 Execute the swapped test action
    after = read_resource_state(read_back_url, owner_auth, original_headers, verify_ssl)   #Step 3 Snapshot state after action

    state_changed = (
        before.get("status") != after.get("status")
        or stable_body_changed(before.get("body"), after.get("body"))
    )                                                                                 #Step 4 Check if status code or stable body data changed

    return {
        "before": before,
        "action_result": action_result,
        "after": after,
        "state_changed": state_changed,
    }                                                                                 #Return full verification bundle to engine


# json.loads is an inbuilt function that converts raw text into a Python dictionary in RAM
# requests.get is a function that sends an HTTP GET packet over TCP to read the server resource
# timeout=10 tells requests to abort if the server does not respond within 10 seconds
# verify=verify ssl tells requests whether to check SSL certificates for local or staging servers

# Variables Used:

# DYNAMIC KEYS stores rotating fields like timestamp and request id so they do not cause false alerts
# read back url stores the endpoint address used to check the target resource current state
# owner auth stores the session credential used to legitimately inspect the resource data
# send action fn is the function passed from engine that fires the swapped action request
# before and after store the status and body snapshots taken before and after the action
# state changed stores True if the resource was modified or False if it stayed the same

# Working:

# engine calls verify action swap when it finds a POST PUT PATCH or DELETE endpoint
# First read resource state sends a GET request with owner credentials to save the before snapshot
# Next send action fn fires the swapped request to see if the server allows the action
# Then read resource state sends the same GET request again to save the after snapshot
# stable body changed strips out noisy fields like timestamps and compares the remaining data
# If the status code changed or the clean data changed state changed becomes True
# Otherwise if both snapshots match state changed becomes False and the result is passed to classifier