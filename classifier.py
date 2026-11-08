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


def try_parse_json(body):#Safely convert text to JSON without crashing
    if not body:
        return None
    try:
        return json.loads(body)#Parse JSON string into Python dict or list
    except (json.JSONDecodeError, TypeError):
        return None#If invalid text return None instead of crashing


def extract_schema(data, prefix=""):#Create structural blueprint of JSON response
    schema = set()#Store path and data type pairs
    if isinstance(data, dict):#If object step into each key
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            schema |= extract_schema(value, path)#Combine schemas using set union
    elif isinstance(data, list):#If array sample first item shape
        for item in data[:1]:
            schema |= extract_schema(item, prefix + "[]")
    else:#Leaf node record path and data type name
        schema.add(f"{prefix}:{type(data).__name__}")
    return schema#Return complete set of field paths and types


def extract_values(data, prefix=""):#Flatten all values inside JSON into path and value map
    values = {}
    if isinstance(data, dict):#If dictionary traverse each field
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            values.update(extract_values(value, path))
    elif isinstance(data, list):#If list check first item
        for item in data[:1]:
            values.update(extract_values(item, prefix + "[]"))
    else:#Store final value at its field path
        values[prefix] = data
    return values#Return flat dictionary of all values


def schema_similarity(schema_a, schema_b):#Calculate percentage match between two response shapes
    if not schema_a and not schema_b:
        return 1.0#Both empty means identical shape
    if not schema_a or not schema_b:
        return 0.0#One empty and one full means no match
    return len(schema_a & schema_b) / len(schema_a | schema_b)#Jaccard index calculation


def build_error_baseline(all_requests):#Learn what error responses look like on this website
    baseline = []
    for req in all_requests:#Check all recorded requests
        if req.get("status") in (401, 403, 404):#Find explicit refusal codes
            parsed = try_parse_json(req.get("response_body"))
            if parsed is not None:
                baseline.append(extract_schema(parsed))#Save the error shape blueprint
    return baseline#Return list of known error shapes


def matches_error_baseline(schema, baseline_schemas, threshold=0.7):#Check if a 200 OK is a disguised error
    if not baseline_schemas:
        return False#No baseline means cannot match
    best_match = max(schema_similarity(schema, b) for b in baseline_schemas)
    return best_match >= threshold#True if response matches known error blueprint


def check_provenance(response_text, owner_values):#Look for victim personal data in response text
    if not response_text or not owner_values:
        return []
    matches = []
    for val in owner_values:
        val_str = str(val).strip()#Convert numbers or IDs to string
        if len(val_str) < 3 or val_str.lower() in IGNORED_WORDS:#Ignore tiny or generic words
            continue
        if val_str in response_text:#Exact match found in response body
            matches.append(val_str)
    return matches#Return list of leaked victim values


def find_personal_fields(credential_owner_body, resource_owner_body):#Find fields where values differ between users
    cred_vals = extract_values(try_parse_json(credential_owner_body) or {})
    owner_vals = extract_values(try_parse_json(resource_owner_body) or {})

    differing_fields = {}
    for path, owner_val in owner_vals.items():#Check every field belonging to victim
        if path in cred_vals and cred_vals[path] != owner_val:#Values differ between User A and User B
            differing_fields[path] = owner_val#This field is a unique identifier marker
    return differing_fields#Return fields that distinguish victim from attacker


def check_field_leak(swapped_body, personal_fields):#Check if swapped response shows victim data in marker fields
    swapped_vals = extract_values(try_parse_json(swapped_body) or {})
    leaked = []
    for path, owner_val in personal_fields.items():
        if swapped_vals.get(path) == owner_val:#Swapped response contains victim value
            leaked.append((path, owner_val))
    return leaked#Return list of leaked fields and their values


def classify(swapped_response, baseline_schemas, owner_values,
             owner_own_body=None, credential_owner_own_body=None):#Main engine running the four signal cascade
    if swapped_response.get("error") or swapped_response.get("status") is None:
        return {"label": REQUEST_FAILED, "confidence": 0.0,
                "evidence": [f"Network probe failed: {swapped_response.get('error')}"]}

    status = swapped_response["status"]
    body = swapped_response.get("body") or ""

    #Signal 1 Status Code Check
    if status in (401, 403, 404):#Explicit refusal by server
        return {"label": DENIED_STATUS, "confidence": 0.95,
                "evidence": [f"Server properly denied request with status {status}"]}

    parsed_body = try_parse_json(body)
    if parsed_body is None:#Non JSON or plain HTML text response
        matched_values = check_provenance(body, owner_values)
        if matched_values:#Contains victim specific strings
            return {"label": LEAK, "confidence": 0.8,
                    "evidence": [f"Status {status} non JSON body contains victim data: {matched_values}"]}
        return {"label": AMBIGUOUS, "confidence": 0.3,
                "evidence": [f"Status {status} non JSON body with no clear identity match"]}

    response_shape = extract_schema(parsed_body)

    #Signal 2 Disguised Error Check
    if matches_error_baseline(response_shape, baseline_schemas):
        return {"label": DENIED_SHAPE, "confidence": 0.75,
                "evidence": [f"Status {status} but body shape matches known error baseline"]}

    #Signal 3 Direct Value Provenance Check
    matched_values = check_provenance(body, owner_values)
    if matched_values:#Victim email phone username or token claim found in body
        return {"label": LEAK, "confidence": 0.95,
                "evidence": [f"Status {status} response body exposes victim identity: {matched_values}"]}

    #Signal 4 Personal Field Comparison Check
    if owner_own_body and credential_owner_own_body:
        personal_fields = find_personal_fields(credential_owner_own_body, owner_own_body)
        field_matches = check_field_leak(body, personal_fields)
        if field_matches:#Victim value returned in a personal field
            return {"label": LEAK, "confidence": 0.9,
                    "evidence": [f"Status {status} response matches victim values in fields: {field_matches}"]}

        #Check if server safely ignored swapped ID and served credential owner own data
        if personal_fields:
            cred_vals = extract_values(try_parse_json(credential_owner_own_body) or {})
            swapped_vals = extract_values(parsed_body)
            still_cred_data = all(swapped_vals.get(p) == cred_vals.get(p) for p in personal_fields)
            if still_cred_data:#Server safely enforced access control
                return {"label": CORRECTLY_SCOPED, "confidence": 0.85,
                        "evidence": [f"Status {status} server ignored swapped ID and served requester own data"]}

    #Fallback shape matches victim baseline but lacks identity proof
    if owner_own_body:
        owner_parsed = try_parse_json(owner_own_body)
        if owner_parsed is not None:
            similarity = schema_similarity(response_shape, extract_schema(owner_parsed))
            if similarity > 0.8:
                return {"label": AMBIGUOUS, "confidence": 0.5,
                        "evidence": [f"Status {status} shape matches victim response but lacks concrete value proof"]}

    return {"label": AMBIGUOUS, "confidence": 0.4,
            "evidence": [f"Status {status} JSON returned without conclusive leak or denial signal"]}


def classify_action(verification_result):#Verdict engine for action endpoints like delete or update
    before = verification_result.get("before", {})
    after = verification_result.get("after", {})

    if before.get("error") or after.get("error"):
        return {"label": REQUEST_FAILED, "confidence": 0.0,
                "evidence": ["Verification failed due to network errors during state read"]}

    if verification_result.get("state_changed"):#State changed on victim resource
        return {"label": LEAK, "confidence": 0.9,
                "evidence": ["Victim resource state mutated after swapped action request"]}

    return {"label": NO_STATE_CHANGE, "confidence": 0.7,
            "evidence": ["Victim resource state remained unchanged after swapped action request"]}


# Libraries Used:

# json (builtin) parses JSON strings into Python dictionaries and lists safely

# Variables Used:

# body is the raw response text received from the target server
# schema is a set of paths and types representing the structural shape of a response
# baseline is the list of error schemas learned from 401 403 and 404 responses
# owner values is the set of victim emails phones usernames and token claims
# personal fields is a map of fields where User A and User B baselines differ
# swapped response is the result dict returned by prober after firing the swapped request
# verification result is the before and after state comparison dict from action verifier

# Working:

# classify runs every read probe through a four signal decision cascade:
# Signal 1 checks status code where 401 403 and 404 are immediate clean denials
# Signal 2 checks if a 200 OK body has the structural shape of known error responses
# Signal 3 checks if victim identity data like email or phone appears inside the body
# Signal 4 checks if fields that differ between users show the victim value
# If personal fields show the requester own data the verdict is correctly scoped
# classify action evaluates state changing requests by comparing before and after snapshots
# If the victim resource changed state on read back the verdict is confirmed leak