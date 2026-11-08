#Compares User A and User B captured traffic side by side.
#Finds endpoints that look identical except for one value (the resource ID).
#That single differing value is the swap candidate for IDOR testing.
#Checks URL path segments, query parameters, AND JSON request bodies.

import re
import json
from dataclasses import dataclass


@dataclass
class MatchedPair:                                                   #Container that holds everything prober needs to build a swapped request
    request_a: dict                                                  #Full clean request dictionary for User A
    request_b: dict                                                  #Full clean request dictionary for User B
    method: str                                                      #HTTP method like GET POST or DELETE
    path_template: str                                               #The URL path pattern shared by both users
    diff_index: int                                                  #Which path segment differs or -1 if the difference is not in the path
    id_value_a: str                                                  #User A own resource ID value
    id_value_b: str                                                  #User B own resource ID value
    diff_location: str = "path"                                      #Where the ID lives which can be path query or body
    diff_key: str = ""                                               #The key name when the ID lives in query or body


_RE_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_RE_HEX_ID = re.compile(r"^[0-9a-fA-F]{16,}$")                       #Pattern for long hex IDs like MongoDB ObjectIDs
_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")                #Pattern for email addresses used as IDs
_RE_SLUG = re.compile(r"^[a-zA-Z0-9_\-]{3,}$")                       #Pattern for short alphanumeric ID strings


def looks_like_id(value):                                            #Check if a value looks like a real ID and not a normal word
    s = str(value).strip()
    if not s:                                                        #Empty string is not an ID
        return False
    if s.isdigit():                                                  #Pure numbers like 42 or 1005 are standard IDs
        return True
    if _RE_UUID.match(s):                                            #Standard UUID format is a valid ID
        return True
    if _RE_HEX_ID.match(s):                                          #Long hexadecimal string is a valid ID
        return True
    if _RE_EMAIL.match(s):                                           #Email address used as an identifier is a valid ID
        return True
    if _RE_SLUG.match(s) and any(c.isdigit() for c in s):            #Code string with at least one number is an ID
        return True
    return False                                                     #Plain words like settings or profile return False


def split_path(path):                                                #Chop URL path by slashes and ignore empty pieces
    return [segment for segment in path.split("/") if segment != ""]


def path_similarity(path_a, path_b):                                 #Count how many path segments match in the exact same position
    segments_a = split_path(path_a)
    segments_b = split_path(path_b)
    if len(segments_a) != len(segments_b):                           #Different number of segments means different endpoints
        return -1
    return sum(1 for x, y in zip(segments_a, segments_b) if x == y)  #Return total matching segments


def find_path_diff(path_a, path_b):                                  #Find the exact position where two URL paths differ
    segments_a = split_path(path_a)
    segments_b = split_path(path_b)
    diffs = [i for i, (x, y) in enumerate(zip(segments_a, segments_b)) if x != y]
    if len(diffs) != 1:                                              #Only accept if exactly one segment differs
        return None
    return diffs[0]                                                  #Return the index of the single differing path segment


def find_query_diff(query_a, query_b):                               #Find the single query parameter where two requests differ
    if set(query_a.keys()) != set(query_b.keys()):                   #Both requests must have the exact same parameter names
        return None
    diffs = [key for key in query_a if query_a[key] != query_b.get(key)]
    if len(diffs) != 1:                                              #Only accept if exactly one query parameter has a different value
        return None
    return diffs[0]                                                  #Return the name of that differing parameter


def find_body_diff(body_a, body_b):                                  #Find the single JSON body field where two requests differ
    if not body_a or not body_b:                                     #Skip if either request does not have a body
        return None
    try:
        json_a = json.loads(body_a)                                  #Convert User A body into a Python dictionary
        json_b = json.loads(body_b)                                  #Convert User B body into a Python dictionary
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(json_a, dict) or not isinstance(json_b, dict): #Both bodies must be JSON objects
        return None
    if set(json_a.keys()) != set(json_b.keys()):                     #Both bodies must have the exact same keys
        return None

    diffs = [key for key in json_a if str(json_a[key]) != str(json_b.get(key))]
    if len(diffs) != 1:                                              #Only accept if exactly one body field differs
        return None
    return diffs[0]                                                  #Return the key name of the differing field


def find_matches(requests_a, requests_b, min_similarity_ratio=0.6):  #Find all swappable endpoint pairs
    matched_pairs = []                                               #List to store matched pairs
    candidates_b = [r for r in requests_b if 200 <= r.get("status", 0) < 300] #Keep only successful User B requests

    for request_a in requests_a:                                     #Loop through every User A request
        if not (200 <= request_a.get("status", 0) < 300):            #Skip failed User A requests
            continue

        best_match = None                                            #Store the closest matching User B request
        best_score = -1                                              #Track the highest segment match score

        for request_b in candidates_b:                               #Compare against every successful User B request
            if request_a["method"] != request_b["method"]:           #HTTP methods like GET or POST must match
                continue

            score = path_similarity(request_a["path"], request_b["path"])
            if score == -1:                                          #Skip if URL paths have different lengths
                continue

            segment_count = len(split_path(request_a["path"])) or 1
            ratio = score / segment_count                            #Calculate fraction of segments that match

            if ratio >= min_similarity_ratio and score > best_score: #Update best match if score is higher
                best_match = request_b
                best_score = score

        if best_match is None:                                       #If no similar endpoint was found move to next request
            continue

        diff_index = find_path_diff(request_a["path"], best_match["path"]) #Priority 1 Check if ID differs in URL path
        if diff_index is not None:
            segments_a = split_path(request_a["path"])
            segments_b = split_path(best_match["path"])
            val_a = segments_a[diff_index]
            val_b = segments_b[diff_index]
            if looks_like_id(val_a) or looks_like_id(val_b):         #Confirm values look like real IDs not page names
                matched_pairs.append(MatchedPair(
                    request_a=request_a, request_b=best_match,
                    method=request_a["method"], path_template=request_a["path"],
                    diff_index=diff_index,
                    id_value_a=val_a,
                    id_value_b=val_b,
                    diff_location="path",
                ))
            continue

        diff_key = find_query_diff(request_a.get("query", {}), best_match.get("query", {})) #Priority 2 Check query parameters
        if diff_key is not None:
            val_a = request_a["query"][diff_key]
            val_b = best_match["query"][diff_key]
            if looks_like_id(val_a) or looks_like_id(val_b):         #Confirm query values look like real IDs
                matched_pairs.append(MatchedPair(
                    request_a=request_a, request_b=best_match,
                    method=request_a["method"], path_template=request_a["path"],
                    diff_index=-1,
                    id_value_a=val_a,
                    id_value_b=val_b,
                    diff_location="query", diff_key=diff_key,
                ))
            continue

        diff_key = find_body_diff(request_a.get("body"), best_match.get("body")) #Priority 3 Check JSON request body
        if diff_key is not None:
            body_a = json.loads(request_a["body"])
            body_b = json.loads(best_match["body"])
            val_a = str(body_a[diff_key])
            val_b = str(body_b[diff_key])
            if looks_like_id(val_a) or looks_like_id(val_b):         #Confirm body values look like real IDs
                matched_pairs.append(MatchedPair(
                    request_a=request_a, request_b=best_match,
                    method=request_a["method"], path_template=request_a["path"],
                    diff_index=-1,
                    id_value_a=val_a,
                    id_value_b=val_b,
                    diff_location="body", diff_key=diff_key,
                ))

    seen = set()                                                     #Set to track endpoints we have already added
    deduped = []                                                     #List to store unique endpoint pairs without duplicates
    for pair in matched_pairs:                                       #Remove duplicate matches caused by browser page refreshes
        key = (pair.method, pair.path_template, pair.diff_location, pair.diff_key)
        if key not in seen:
            seen.add(key)
            deduped.append(pair)

    return deduped                                                   #Return clean list of unique swap candidates to engine


# dataclass is an inbuilt decorator that builds a clean data container object in RAM
# re.compile builds regex patterns used to check if a string is a UUID hex value or email
# zip pairs up items from two lists side by side so we can compare User A and User B path segments

# Variables Used:

# MatchedPair holds both user requests the HTTP method and the exact location and values of the differing ID
# candidates b holds all User B requests that returned a 200 level success status
# best match holds the User B request whose URL structure is closest to the current User A request
# val a and val b hold the candidate ID values extracted from User A and User B
# seen and deduped remove duplicate endpoint pairs so the tool never probes the same URL twice

# Working:

# engine calls find matches with the clean request lists from User A and User B
# For each successful User A request matcher finds the User B request with the same HTTP method and closest path
# It then checks three places for a single differing value in order: URL path query string and JSON body
# looks like id checks the differing value to make sure it is a real ID like 42 or a UUID and not a word like settings
# Finally duplicate matches are filtered out and the unique MatchedPair objects are returned to engine