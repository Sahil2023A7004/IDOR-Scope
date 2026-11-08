#Compares User A and User B captured traffic side by side.
#Finds endpoints that look identical except for one value (the resource ID).
#That single differing value is the swap candidate for IDOR testing.
#Checks URL path segments, query parameters, AND JSON request bodies.

import json
from dataclasses import dataclass

@dataclass
class MatchedPair: #Container that holds everything prober needs to build a swapped request
    request_a: dict #Full clean request dict from har loader for User A
    request_b: dict #Full clean request dict from har loader for User B
    method: str #HTTP verb (GET, POST, DELETE etc)
    path_template: str #The URL path pattern shared by both users
    diff_index: int #Which path segment differs (-1 if diff is not in path)
    id_value_a: str #User A own resource ID value
    id_value_b: str #User B own resource ID value
    diff_location: str = "path" #Where the ID lives: "path", "query", or "body"
    diff_key: str = "" #The key name if diff is in query or body


def split_path(path): #Seprate URL path into segments ignoring empty strings from slashes i.e "/"
    return [segment for segment in path.split("/") if segment != ""]


def path_similarity(path_a, path_b): #Count how many segments match at the same position
    segments_a = split_path(path_a)
    segments_b = split_path(path_b)
    if len(segments_a) != len(segments_b): #Different lengths means different endpoints
        return -1
    return sum(1 for x, y in zip(segments_a, segments_b) if x == y)


def find_path_diff(path_a, path_b): #Find the single path segment where two paths differ
    segments_a = split_path(path_a)
    segments_b = split_path(path_b)
    diffs = [i for i, (x, y) in enumerate(zip(segments_a, segments_b)) if x != y]
    if len(diffs) != 1: #If zero or more than one segment differs it is ambiguous
        return None
    return diffs[0] #Return the index of the single differing segment


def find_query_diff(query_a, query_b): #Find the single query param where values differ
    if set(query_a.keys()) != set(query_b.keys()): #Keys must match exactly
        return None
    diffs = [key for key in query_a if query_a[key] != query_b.get(key)]
    if len(diffs) != 1: #Exactly one param must differ
        return None
    return diffs[0] #Return the key name of the differing param


def find_body_diff(body_a, body_b): #Find the single JSON body field where values differ
    if not body_a or not body_b: #If either request has no body skip
        return None
    try:
        json_a = json.loads(body_a) #Parse User A body as JSON
        json_b = json.loads(body_b) #Parse User B body as JSON
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(json_a, dict) or not isinstance(json_b, dict): #Must be flat dicts
        return None
    if set(json_a.keys()) != set(json_b.keys()): #Keys must match exactly
        return None

    diffs = [key for key in json_a if str(json_a[key]) != str(json_b.get(key))]
    if len(diffs) != 1: #Exactly one field must differ
        return None
    return diffs[0] #Return the key name of the differing field


def find_matches(requests_a, requests_b, min_similarity_ratio=0.6): #Main matching engine
    matched_pairs = [] #Collection tray for all swap candidates
    candidates_b = [r for r in requests_b if 200 <= r.get("status", 0) < 300] #Only successful responses

    for request_a in requests_a: #Loop through every User A request
        if not (200 <= request_a.get("status", 0) < 300): #Skip failed requests
            continue

        best_match = None #Track the closest matching User B request
        best_score = -1 #Track highest similarity score

        for request_b in candidates_b: #Compare against every User B request
            if request_a["method"] != request_b["method"]: #Must be same HTTP verb
                continue

            score = path_similarity(request_a["path"], request_b["path"])
            if score == -1: #Different path lengths means different endpoints
                continue

            segment_count = len(split_path(request_a["path"])) or 1
            ratio = score / segment_count #What fraction of segments match

            if ratio >= min_similarity_ratio and score > best_score: #Best match so far
                best_match = request_b
                best_score = score

        if best_match is None: #No matching endpoint found for this request
            continue

        #Priority 1: Check if ID differs in URL path segment

        diff_index = find_path_diff(request_a["path"], best_match["path"])
        if diff_index is not None:
            segments_a = split_path(request_a["path"])
            segments_b = split_path(best_match["path"])
            matched_pairs.append(MatchedPair(
                request_a=request_a, request_b=best_match,
                method=request_a["method"], path_template=request_a["path"],
                diff_index=diff_index,
                id_value_a=segments_a[diff_index],
                id_value_b=segments_b[diff_index],
                diff_location="path",
            ))
            continue

        
        #Priority 2: Check if ID differs in query parameter

        diff_key = find_query_diff(request_a.get("query", {}), best_match.get("query", {}))
        if diff_key is not None:
            matched_pairs.append(MatchedPair(
                request_a=request_a, request_b=best_match,
                method=request_a["method"], path_template=request_a["path"],
                diff_index=-1,
                id_value_a=request_a["query"][diff_key],
                id_value_b=best_match["query"][diff_key],
                diff_location="query", diff_key=diff_key,
            ))
            continue

        #Priority 3: Check if ID differs in JSON request body

        diff_key = find_body_diff(request_a.get("body"), best_match.get("body"))
        if diff_key is not None:
            body_a = json.loads(request_a["body"])
            body_b = json.loads(best_match["body"])
            matched_pairs.append(MatchedPair(
                request_a=request_a, request_b=best_match,
                method=request_a["method"], path_template=request_a["path"],
                diff_index=-1,
                id_value_a=str(body_a[diff_key]),
                id_value_b=str(body_b[diff_key]),
                diff_location="body", diff_key=diff_key,
            ))
    return matched_pairs #Hand all swap candidates to engine


# Libraries Used:
# json (builtin) parses JSON request bodies to compare field values between users
# dataclass (from dataclasses) creates a clean container class without boilerplate

# variables used:
# MatchedPair holds everything prober needs in one object:
#   request a and request b (full dicts from har loader)
#   method (GET POST etc)
#   path template (the shared URL pattern)
#   diff index (which path segment has the ID, -1 if not in path)
#   id value a and id value b (the actual ID strings to swap)
#   diff location (where the ID lives: path, query, or body)
#   diff key (the parameter or field name if in query or body)

# Working:
# engine.py calls find matches with clean request lists from both users
# For each User A request it finds the most similar User B request
# Similarity is measured by counting how many URL path segments match
# Once a pair is found it checks three locations for the differing ID:
#  1. URL path segments (e.g. /api/users/42 vs /api/users/99)
#  2. Query parameters (e.g. ?user_id=42 vs ?user_id=99)
#  3. JSON request body (e.g. {"account_id": 42} vs {"account_id": 99})
# If exactly one value differs in any location it becomes a swap candidate
# All candidates are returned as a list of MatchedPair objects
# prober.py then uses each MatchedPair to build and fire the swapped requests