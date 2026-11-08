#The automated decision engine for read requests.
#Inspects swapped probe responses and baseline data through a four signal cascade
#to decide if an IDOR vulnerability exists without needing human verification.

import json

LEAK = "confirmed_leak"
DENIED_STATUS = "no_leak_denied_by_status"
DENIED_SHAPE = "no_leak_matches_error_baseline"
CORRECTLY_SCOPED = "no_leak_correctly_scoped"
NO_STATE_CHANGE = "no_leak_state_unchanged"
AMBIGUOUS = "ambiguous_needs_manual_review"
REQUEST_FAILED = "request_failed"

IGNORED_WORDS = {"true", "false", "null", "none", "undefined", "success", "error"}


def try_parse_json(body):                                            #Safely convert response text into a Python object without crashing
    if not body:                                                     #If body is empty return None
        return None
    try:
        return json.loads(body)                                      #Parse JSON text into a dictionary or list in RAM
    except (json.JSONDecodeError, TypeError):
        return None                                                  #If text is HTML or plain text return None


def extract_schema(data, prefix=""):                                 #Build a structural blueprint of keys and data types in a JSON response
    schema = set()                                                   #Set to store field paths and their value types
    if isinstance(data, dict):                                       #If current level is a dictionary step into every key
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            schema |= extract_schema(value, path)                    #Merge child schema into main set
    elif isinstance(data, list):                                     #If current level is a list check the first item shape
        for item in data[:1]:
            schema |= extract_schema(item, prefix + "[]")
    else:                                                            #Reached a final value so record its path and Python type name
        schema.add(f"{prefix}:{type(data).__name__}")
    return schema                                                    #Return the complete blueprint set


def extract_values(data, prefix=""):                                 #Flatten all values inside a JSON object into a simple dictionary
    values = {}
    if isinstance(data, dict):                                       #If dictionary loop through each key
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            values.update(extract_values(value, path))
    elif isinstance(data, list):                                     #If list inspect the first element
        for item in data[:1]:
            values.update(extract_values(item, prefix + "[]"))
    else:                                                            #Save final leaf value under its full dot path
        values[prefix] = data
    return values                                                    #Return flat map of field paths to values


def schema_similarity(schema_a, schema_b):                           #Measure how similar two JSON blueprints are from 0.0 to 1.0
    if not schema_a and not schema_b:
        return 1.0                                                   #Both empty means 100 percent match
    if not schema_a or not schema_b:
        return 0.0                                                   #One empty and one full means 0 percent match
    return len(schema_a & schema_b) / len(schema_a | schema_b)       #Divide shared fields by total unique fields


def build_error_baseline(all_requests):                              #Learn what error responses look like on the target website
    baseline = []
    for req in all_requests:                                         #Loop through all captured traffic
        if req.get("status") in (401, 403, 404):                     #Find requests that the server explicitly denied
            parsed = try_parse_json(req.get("response_body"))
            if parsed is not None:
                baseline.append(extract_schema(parsed))              #Save the JSON blueprint of this error message
    return baseline                                                  #Return list of known error blueprints


def matches_error_baseline(schema, baseline_schemas, threshold=0.7): #Check if a 200 OK response is really an error
    if not baseline_schemas:                                         #Cannot match if no error shapes were learned
        return False
    best_match = max(schema_similarity(schema, b) for b in baseline_schemas) #Find highest similarity score
    return best_match >= threshold                                   #Return True if shape matches a known error by 70 percent or more


def check_provenance(response_text, owner_values):                   #Check if victim personal data appears inside the response
    if not response_text or not owner_values:
        return []
    matches = []
    for val in owner_values:                                         #Check every known personal value belonging to the victim
        val_str = str(val).strip()
        if len(val_str) < 2 or val_str.lower() in IGNORED_WORDS:     #Skip single characters and generic words
            continue
        if val_str in response_text:                                 #Victim personal string was found inside the response body
            matches.append(val_str)
    return matches                                                   #Return list of leaked victim values


def find_personal_fields(credential_owner_body, resource_owner_body): #Find JSON fields that differ between User A and User B
    cred_vals = extract_values(try_parse_json(credential_owner_body) or {})
    owner_vals = extract_values(try_parse_json(resource_owner_body) or {})

    differing_fields = {}
    for path, owner_val in owner_vals.items():                       #Loop through every field in the victim original response
        if path in cred_vals and cred_vals[path] != owner_val:       #Field has different values for User A and User B
            differing_fields[path] = owner_val                       #Save this field and the victim value as a personal marker
    return differing_fields                                          #Return map of user specific fields


def check_field_leak(swapped_body, personal_fields):                 #Check if swapped response contains victim values in personal fields
    swapped_vals = extract_values(try_parse_json(swapped_body) or {})
    leaked = []
    for path, owner_val in personal_fields.items():                  #Check each personal field path
        if swapped_vals.get(path) == owner_val:                      #Swapped response returned the victim exact value
            leaked.append((path, owner_val))
    return leaked                                                    #Return list of leaked field pairs


def classify(swapped_response, baseline_schemas, owner_values,
             owner_own_body=None, credential_owner_own_body=None):   #Run the four signal decision cascade
    if swapped_response.get("error") or swapped_response.get("status") is None: #Check if network request failed
        return {"label": REQUEST_FAILED, "confidence": 0.0,
                "evidence": [f"Network probe failed: {swapped_response.get('error')}"]}

    status = swapped_response["status"]
    body = swapped_response.get("body") or ""

    if status in (401, 403, 404):                                    #Signal 1 Check HTTP status code for explicit denial
        return {"label": DENIED_STATUS, "confidence": 0.95,
                "evidence": [f"Server properly denied request with status {status}"]}

    parsed_body = try_parse_json(body)
    if parsed_body is None:                                          #Response is plain text or HTML instead of JSON
        matched_values = check_provenance(body, owner_values)
        if matched_values:                                           #Found victim personal data in plain text
            return {"label": LEAK, "confidence": 0.8,
                    "evidence": [f"Status {status} non-JSON body contains victim data: {matched_values}"]}
        return {"label": AMBIGUOUS, "confidence": 0.3,
                "evidence": [f"Status {status} non-JSON body with no clear identity match"]}

    response_shape = extract_schema(parsed_body)

    if matches_error_baseline(response_shape, baseline_schemas):     #Signal 2 Check if 200 OK matches disguised error blueprint
        return {"label": DENIED_SHAPE, "confidence": 0.75,
                "evidence": [f"Status {status} but body shape matches known error baseline"]}

    matched_values = check_provenance(body, owner_values)            #Signal 3 Check if victim identity strings appear in body
    if matched_values:
        return {"label": LEAK, "confidence": 0.95,
                "evidence": [f"Status {status} response body exposes victim identity: {matched_values}"]}

    if owner_own_body and credential_owner_own_body:                 #Signal 4 Compare user specific JSON fields
        personal_fields = find_personal_fields(credential_owner_own_body, owner_own_body)
        field_matches = check_field_leak(body, personal_fields)
        if field_matches:                                            #Swapped response returned victim values in personal fields
            return {"label": LEAK, "confidence": 0.9,
                    "evidence": [f"Status {status} response matches victim values in fields: {field_matches}"]}

        if personal_fields:                                          #Check if server ignored swapped ID and served sender own data
            cred_vals = extract_values(try_parse_json(credential_owner_own_body) or {})
            swapped_vals = extract_values(parsed_body)
            still_cred_data = all(swapped_vals.get(p) == cred_vals.get(p) for p in personal_fields)
            if still_cred_data:                                      #Server safely scoped the response to the logged in user
                return {"label": CORRECTLY_SCOPED, "confidence": 0.85,
                        "evidence": [f"Status {status} server ignored swapped ID and served requester own data"]}

    if owner_own_body:                                               #Fallback Check if shape matches victim data without value proof
        owner_parsed = try_parse_json(owner_own_body)
        if owner_parsed is not None:
            similarity = schema_similarity(response_shape, extract_schema(owner_parsed))
            if similarity > 0.8:
                return {"label": AMBIGUOUS, "confidence": 0.5,
                        "evidence": [f"Status {status} shape matches victim response but lacks concrete value proof"]}

    return {"label": AMBIGUOUS, "confidence": 0.4,
            "evidence": [f"Status {status} JSON returned without conclusive leak or denial signal"]}


def classify_action(verification_result):                            #Decide verdict for state changing requests from Engine 2
    before = verification_result.get("before", {})
    after = verification_result.get("after", {})

    if before.get("error") or after.get("error"):                    #Network error happened while reading resource state
        return {"label": REQUEST_FAILED, "confidence": 0.0,
                "evidence": ["Verification failed due to network errors during state read"]}

    if verification_result.get("state_changed"):                     #Victim resource changed after the swapped action
        return {"label": LEAK, "confidence": 0.9,
                "evidence": ["Victim resource state mutated after swapped action request"]}

    return {"label": NO_STATE_CHANGE, "confidence": 0.7,
            "evidence": ["Victim resource state remained unchanged after swapped action request"]}


# json.loads is an inbuilt function that parses raw JSON text into Python dictionaries and lists in RAM
# set operations like & and | calculate shared and total fields between two JSON response blueprints

# Variables Used:

# schema stores the structural blueprint of a JSON response as field paths and data types
# baseline schemas stores the blueprints of known 401 403 and 404 error responses from the site
# owner values holds the set of personal strings like emails and IDs belonging to the victim user
# personal fields holds JSON fields that have different values for User A and User B
# swapped response holds the HTTP status code and text returned when prober sent the swapped request

# Working:

# engine passes every read probe result to classify which runs four checks in order
# Signal 1 checks if the status code is 401 403 or 404 which means the server blocked the request
# Signal 2 compares the response structure against known error shapes to catch 200 OK error messages
# Signal 3 searches the response for victim identity strings including 2 digit IDs emails and usernames
# Signal 4 checks user specific JSON fields to see if they show victim data or the sender own data
# For state changing requests classify action checks the boolean from action verifier to confirm if data mutated