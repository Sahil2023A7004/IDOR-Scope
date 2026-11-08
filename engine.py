#The master orchestrator for IDOR-Scope.
#Takes two HAR files and runs the full automated pipeline end to end:
#1. Load and clean both HAR captures
#2. Match identical endpoints differing by one resource ID
#3. Extract auth credentials, JWT claims, and identity markers
#4. Probe and classify read endpoints with Engine 1
#5. Verify state changing endpoints with Engine 2
#6. Print an aligned console summary table and save a JSON report

import sys
import os
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))       #Make sure Python finds local project files

from har_loader import load_clean, load_har
from matcher import find_matches
from token_extractor import extract_auth, claims_from_jwt, extract_identity_values
from prober import run_pair_probe, build_swapped_url, build_swapped_body, send_probe
from classifier import build_error_baseline, classify, classify_action
from action_verifier import is_state_changing, verify_action_swap


def shorten(text, max_length):                                       #Cut long text and add dots so console table columns stay aligned
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def shorten_auth(auth):                                              #Show only the start and end of a token or cookie for safe printing
    if not auth:
        return "(none)"
    if isinstance(auth, dict):
        auth_type = auth.get("type", "unknown")
        val = auth.get("value", "")
    else:
        auth_type = "bearer"
        val = str(auth)

    if len(val) <= 24:
        return f"[{auth_type}] {val}"
    return f"[{auth_type}] {val[:16]}...{val[-6:]}"


def print_results_table(rows):                                       #Print a clean aligned table of test results in the terminal
    col_widths = {"endpoint": 42, "direction": 20, "status": 8, "verdict": 30, "confidence": 10}

    header = (
        f"{'ENDPOINT':<{col_widths['endpoint']}} "
        f"{'DIRECTION':<{col_widths['direction']}} "
        f"{'STATUS':<{col_widths['status']}} "
        f"{'VERDICT':<{col_widths['verdict']}} "
        f"{'CONFIDENCE':<{col_widths['confidence']}}"
    )
    print(header)
    print("-" * len(header))

    for row in rows:                                                 #Print one formatted line for each test result
        print(
            f"{shorten(row['endpoint'], col_widths['endpoint']):<{col_widths['endpoint']}} "
            f"{row['direction']:<{col_widths['direction']}} "
            f"{str(row['status']):<{col_widths['status']}} "
            f"{row['verdict']:<{col_widths['verdict']}} "
            f"{row['confidence']:<{col_widths['confidence']}.2f}"
        )


def run_read_match(match, auth_a, auth_b, identity_a, identity_b,
                   baseline_schemas, verbose, verify_ssl):           #Run Engine 1 on a read endpoint pair
    endpoint_label = f"{match.method} {match.path_template}"

    if verbose:
        print(f"\n  [verbose] probing (read): {endpoint_label} (diff in {match.diff_location})")

    probe_results = run_pair_probe(match, auth_a, auth_b, verify_ssl=verify_ssl) #Step 1 Send swapped read requests

    if verbose:
        print(f"    A's creds -> B's resource: "
              f"{probe_results['a_credentials_b_resource']['swapped_url']}")
        print(f"    B's creds -> A's resource: "
              f"{probe_results['b_credentials_a_resource']['swapped_url']}")

    verdict_a_to_b = classify(                                       #Step 2 Classify A to B response with 4 signal cascade
        probe_results["a_credentials_b_resource"]["response"],
        baseline_schemas, identity_b,
        owner_own_body=match.request_b.get("response_body"),
        credential_owner_own_body=match.request_a.get("response_body"),
    )
    verdict_b_to_a = classify(                                       #Step 3 Classify B to A response with 4 signal cascade
        probe_results["b_credentials_a_resource"]["response"],
        baseline_schemas, identity_a,
        owner_own_body=match.request_a.get("response_body"),
        credential_owner_own_body=match.request_b.get("response_body"),
    )

    if verbose:
        print(f"    verdict A->B: {verdict_a_to_b['label']} (confidence {verdict_a_to_b['confidence']:.2f})")
        for ev in verdict_a_to_b["evidence"]:
            print(f"      reason: {ev}")
        print(f"    verdict B->A: {verdict_b_to_a['label']} (confidence {verdict_b_to_a['confidence']:.2f})")
        for ev in verdict_b_to_a["evidence"]:
            print(f"      reason: {ev}")

    table_rows = [
        {"endpoint": endpoint_label, "direction": "A creds -> B data",
         "status": probe_results["a_credentials_b_resource"]["response"].get("status"),
         "verdict": verdict_a_to_b["label"], "confidence": verdict_a_to_b["confidence"]},
        {"endpoint": endpoint_label, "direction": "B creds -> A data",
         "status": probe_results["b_credentials_a_resource"]["response"].get("status"),
         "verdict": verdict_b_to_a["label"], "confidence": verdict_b_to_a["confidence"]},
    ]

    report_entry = {
        "type": "read",
        "endpoint": endpoint_label,
        "diff_location": match.diff_location,
        "diff_key": match.diff_key,
        "id_value_a": match.id_value_a,
        "id_value_b": match.id_value_b,
        "a_credentials_b_resource": {
            "swapped_url": probe_results["a_credentials_b_resource"]["swapped_url"],
            "response_status": probe_results["a_credentials_b_resource"]["response"].get("status"),
            "response_body": probe_results["a_credentials_b_resource"]["response"].get("body"),
            "verdict": verdict_a_to_b,
        },
        "b_credentials_a_resource": {
            "swapped_url": probe_results["b_credentials_a_resource"]["swapped_url"],
            "response_status": probe_results["b_credentials_a_resource"]["response"].get("status"),
            "response_body": probe_results["b_credentials_a_resource"]["response"].get("body"),
            "verdict": verdict_b_to_a,
        },
    }

    return table_rows, report_entry                                   #Return summary rows and report entry to main


def run_action_match(match, auth_a, auth_b, verbose, verify_ssl):    #Run Engine 2 on a state changing endpoint pair
    endpoint_label = f"{match.method} {match.path_template}"

    if verbose:
        print(f"\n  [verbose] verifying (action): {endpoint_label} (diff in {match.diff_location})")

    url_a_to_b = build_swapped_url(                                  #Step 1 Build swapped URL for A to B
        match.request_a["url"], match.diff_location,
        match.diff_index, match.diff_key, match.id_value_b
    )
    url_b_to_a = build_swapped_url(                                  #Build swapped URL for B to A
        match.request_b["url"], match.diff_location,
        match.diff_index, match.diff_key, match.id_value_a
    )

    body_a_to_b = match.request_a.get("body")                        #Step 2 Start with original request bodies
    body_b_to_a = match.request_b.get("body")
    if match.diff_location == "body":                                #Swap IDs inside JSON payload if ID lives in body
        body_a_to_b = build_swapped_body(match.request_a.get("body"), match.diff_key, match.id_value_b)
        body_b_to_a = build_swapped_body(match.request_b.get("body"), match.diff_key, match.id_value_a)

    send_a_to_b = lambda: send_probe(                                #Step 3 Prepare callback to fire A to B action
        url_a_to_b, auth_a, method=match.method,
        body=body_a_to_b, original_headers=match.request_a.get("headers"),
        verify_ssl=verify_ssl
    )
    send_b_to_a = lambda: send_probe(                                #Prepare callback to fire B to A action
        url_b_to_a, auth_b, method=match.method,
        body=body_b_to_a, original_headers=match.request_b.get("headers"),
        verify_ssl=verify_ssl
    )

    result_a_to_b = verify_action_swap(                              #Step 4 Snapshot before execute action and snapshot after
        match.request_b["url"], auth_b, send_a_to_b,
        original_headers=match.request_b.get("headers"),
        verify_ssl=verify_ssl
    )
    result_b_to_a = verify_action_swap(                              #Snapshot before execute action and snapshot after for B to A
        match.request_a["url"], auth_a, send_b_to_a,
        original_headers=match.request_a.get("headers"),
        verify_ssl=verify_ssl
    )

    verdict_a_to_b = classify_action(result_a_to_b)                  #Step 5 Classify whether resource state mutated
    verdict_b_to_a = classify_action(result_b_to_a)

    if verbose:
        print(f"    A's creds -> B's resource: state_changed={result_a_to_b['state_changed']}")
        print(f"      verdict: {verdict_a_to_b['label']} (confidence {verdict_a_to_b['confidence']:.2f})")
        for ev in verdict_a_to_b["evidence"]:
            print(f"      reason: {ev}")
        print(f"    B's creds -> A's resource: state_changed={result_b_to_a['state_changed']}")
        print(f"      verdict: {verdict_b_to_a['label']} (confidence {verdict_b_to_a['confidence']:.2f})")
        for ev in verdict_b_to_a["evidence"]:
            print(f"      reason: {ev}")

    table_rows = [
        {"endpoint": endpoint_label, "direction": "A creds -> B action",
         "status": result_a_to_b["action_result"].get("status"),
         "verdict": verdict_a_to_b["label"], "confidence": verdict_a_to_b["confidence"]},
        {"endpoint": endpoint_label, "direction": "B creds -> A action",
         "status": result_b_to_a["action_result"].get("status"),
         "verdict": verdict_b_to_a["label"], "confidence": verdict_b_to_a["confidence"]},
    ]

    report_entry = {
        "type": "action",
        "endpoint": endpoint_label,
        "diff_location": match.diff_location,
        "diff_key": match.diff_key,
        "id_value_a": match.id_value_a,
        "id_value_b": match.id_value_b,
        "a_credentials_b_resource": {**result_a_to_b, "verdict": verdict_a_to_b},
        "b_credentials_a_resource": {**result_b_to_a, "verdict": verdict_b_to_a},
    }

    return table_rows, report_entry                                   #Return summary rows and report entry to main


def main():                                                          #Main program entry point that reads flags and runs all stages
    parser = argparse.ArgumentParser(
        description="IDOR-Scope automated access control leak detection engine"
    )
    parser.add_argument("har_a", help="HAR file for user A (e.g. alice.har)")
    parser.add_argument("har_b", help="HAR file for user B (e.g. bob.har)")
    parser.add_argument("--report", default="findings.json", help="Output JSON report path")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show step-by-step detail.")
    parser.add_argument("--test-actions", action="store_true",
                        help="Also verify state-changing endpoints (POST/PUT/PATCH/DELETE). "
                             "WARNING: this performs the real action (delete/update/etc) "
                             "against your test accounts. Only use on accounts you control.")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL certificate verification. "
                             "Use for targets with self-signed or invalid TLS certs. "
                             "Never use against production systems over untrusted networks.")
    args = parser.parse_args()                                       #Read command line arguments into RAM
    verbose = args.verbose
    verify_ssl = not args.no_verify                                  #Set SSL check to False if user passed --no-verify

    if args.no_verify:
        print("WARNING: SSL certificate verification is disabled (--no-verify).")

    print(f"Loading {args.har_a} and {args.har_b}...")
    all_requests_a = load_har(args.har_a)                            #Load all User A traffic for error baseline learning
    all_requests_b = load_har(args.har_b)                            #Load all User B traffic for error baseline learning
    clean_requests_a = load_clean(args.har_a)                        #Load filtered User A API requests
    clean_requests_b = load_clean(args.har_b)                        #Load filtered User B API requests

    print(f"  User A: {len(all_requests_a)} total, "
          f"{len(all_requests_a) - len(clean_requests_a)} removed as junk, "
          f"{len(clean_requests_a)} remain")
    print(f"  User B: {len(all_requests_b)} total, "
          f"{len(all_requests_b) - len(clean_requests_b)} removed as junk, "
          f"{len(clean_requests_b)} remain")

    auth_a = extract_auth(clean_requests_a)                          #Pull User A login token or cookie
    auth_b = extract_auth(clean_requests_b)                          #Pull User B login token or cookie
    if not auth_a or not auth_b:
        print("ERROR: couldn't find a Bearer token or Cookie session for one or both users.")
        sys.exit(1)

    identity_a = extract_identity_values(clean_requests_a)           #Pull User A personal markers from responses
    identity_b = extract_identity_values(clean_requests_b)           #Pull User B personal markers from responses
    if auth_a.get("type") == "bearer":
        identity_a |= claims_from_jwt(auth_a.get("value"))           #Add decoded JWT claims to User A markers
    if auth_b.get("type") == "bearer":
        identity_b |= claims_from_jwt(auth_b.get("value"))           #Add decoded JWT claims to User B markers

    if verbose:
        print(f"\n  [verbose] user A auth: {shorten_auth(auth_a)}")
        print(f"  [verbose] user B auth: {shorten_auth(auth_b)}")
        print(f"  [verbose] user A identity values found: {identity_a or '(none found)'}")
        print(f"  [verbose] user B identity values found: {identity_b or '(none found)'}")

    baseline_schemas = build_error_baseline(all_requests_a + all_requests_b) #Learn site error shapes
    print(f"\n  Collected {len(baseline_schemas)} known 'denied' response shapes")

    matches = find_matches(clean_requests_a, clean_requests_b)       #Find swappable endpoint pairs
    read_matches = [m for m in matches if not is_state_changing(m.method)]   #Split out safe read endpoints
    action_matches = [m for m in matches if is_state_changing(m.method)]     #Split out state changing endpoints

    print(f"  Found {len(read_matches)} read-type candidate(s), "
          f"{len(action_matches)} action-type candidate(s)\n")

    if not matches:
        print("No swappable candidates found. Try browsing more matching "
              "actions in both sessions and re-capturing.")
        sys.exit(0)

    table_rows = []
    full_report = []

    for match in read_matches:                                       #Test every read candidate using Engine 1
        rows, entry = run_read_match(
            match, auth_a, auth_b, identity_a, identity_b,
            baseline_schemas, verbose, verify_ssl
        )
        table_rows += rows
        full_report.append(entry)

    for match in action_matches:                                     #Test state changing candidates using Engine 2 if flag is enabled
        endpoint_label = f"{match.method} {match.path_template}"
        if not args.test_actions:
            print(f"  [skipped] {endpoint_label} is state-changing - "
                  f"re-run with --test-actions to verify it (this performs "
                  f"the real action against your test accounts)")
            full_report.append({
                "type": "action", "endpoint": endpoint_label,
                "status": "skipped_pending_test_actions_flag",
            })
            continue
        rows, entry = run_action_match(match, auth_a, auth_b, verbose, verify_ssl)
        table_rows += rows
        full_report.append(entry)

    print()
    if table_rows:
        print_results_table(table_rows)                              #Display summary table in console
    else:
        print("(no endpoints were actually tested - action-type candidates "
              "were skipped; re-run with --test-actions)")

    with open(args.report, "w", encoding="utf-8") as f:              #Save full results to JSON report file
        json.dump(full_report, f, indent=2)

    leak_count = sum(1 for row in table_rows if row["verdict"] == "confirmed_leak")
    print(f"\n{len(table_rows)} test(s) run, {leak_count} confirmed leak(s)")
    print(f"Full report saved to {args.report}")


if __name__ == "__main__":
    main()


# argparse.ArgumentParser reads command line inputs like HAR file names and optional flags into RAM
# json.dump writes the final list of test results and evidence into a formatted JSON file on disk
# sys.exit stops the program cleanly if login tokens are missing or no matching endpoints exist

# Variables Used:

# all requests a and all requests b hold raw unfiltered traffic used to learn error shapes
# clean requests a and clean requests b hold noise free API requests used for endpoint matching
# auth a and auth b hold the extracted Bearer token or Cookie for each user
# identity a and identity b hold personal values like emails phones usernames and JWT claims
# read matches and action matches separate safe GET requests from state changing requests
# verify ssl holds True by default or False when the user runs with the --no-verify flag

# Working:

# main reads the two HAR files and calls har loader to strip out static files and trackers
# Next token extractor pulls each user login credential and builds a set of their personal identity values
# classifier scans all 401 403 and 404 responses to learn what error messages look like on the target site
# matcher compares User A and User B traffic to find endpoints that differ by a single ID
# Engine 1 tests read candidates by calling prober to swap IDs and classifier to inspect the responses
# Engine 2 tests state changing candidates when --test-actions is used by checking resource state before and after
# Finally print results table shows a summary in the terminal and json.dump saves the full report to findings.json