#Engine 2 verifies state changing requests such as delete, update, and post.
#Instead of inspecting response bodies which often return generic success messages,
#this reads the resource state before the test, executes the action request,
#reads the state again after, and compares them to verify if server state changed.

import requests

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

SKIP_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "upgrade",
}


def clean_headers(raw_headers):#Remove hop by hop headers before forwarding
    if not raw_headers:
        return {}
    cleaned = {}
    for key, value in raw_headers.items():
        if key.lower() not in SKIP_HEADERS:
            cleaned[key.lower()] = value#Store normalized lowercase header
    return cleaned


def is_state_changing(method):#Check if HTTP method modifies server state
    return method.upper() in STATE_CHANGING_METHODS


def read_resource_state(url, auth, original_headers=None):#Read current state of resource
    headers = clean_headers(original_headers)#Copy browser headers for standard verification

    if isinstance(auth, dict):#Check auth dictionary format
        if auth.get("type") == "bearer":
            headers["authorization"] = f"Bearer {auth.get('value')}"
        elif auth.get("type") == "cookie":
            headers["cookie"] = auth.get("value")
    elif isinstance(auth, str):#Direct token string fallback
        headers["authorization"] = f"Bearer {auth}"

    try:
        response = requests.get(url, headers=headers, timeout=10)
        return {"status": response.status_code, "body": response.text, "error": None}
    except requests.RequestException as e:
        return {"status": None, "body": None, "error": str(e)}


def verify_action_swap(read_back_url, owner_auth, send_action_fn, original_headers=None):#Verify side effects
    #Step 1 Snapshot resource state before action is sent
    before = read_resource_state(read_back_url, owner_auth, original_headers)

    #Step 2 Execute the swapped test action
    action_result = send_action_fn()

    #Step 3 Snapshot resource state after action was sent
    after = read_resource_state(read_back_url, owner_auth, original_headers)

    #Step 4 Compare state snapshots
    state_changed = (
        before.get("body") != after.get("body")
        or before.get("status") != after.get("status")
    )

    return {
        "before": before,
        "action_result": action_result,
        "after": after,
        "state_changed": state_changed,
    }


# Libraries Used:

# requests handles sending HTTP GET requests over TCP socket to inspect resource state

# Variables Used:

# read back url is the endpoint used to check the target resource current state
# owner auth is the session credential used to legitimately inspect the data
# send action fn is the callback function that fires the swapped action request
# before is the snapshot dictionary containing status and body before the action
# after is the snapshot dictionary containing status and body after the action
# state changed is a boolean that is true if status code or body text changed

# Working:

# verify action swap handles endpoints using POST PUT PATCH or DELETE
# It takes a snapshot of the resource by sending a GET request with owner credentials
# It then calls send action fn to execute the swapped request
# It reads the resource again using the same GET request
# If the status code or body differs between before and after it confirms a state mutation
# Results are returned to engine which passes them to classify action