#The master orchestrator for IDOR-Scope.
#Takes two HAR files and runs the full automated pipeline end to end:
#1. Load and clean both HAR captures (har_loader.py)
#2. Match identical endpoints differing by one resource ID (matcher.py)
#3. Extract auth credentials, JWT claims, and identity markers (token_extractor.py)
#4. Probe and classify read endpoints with Engine 1 (prober.py, classifier.py)
#5. Verify state changing endpoints with Engine 2 (action_verifier.py, classifier.py)
#6. Print an aligned console summary table and save a JSON report

import sys
import os
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))#Ensure local modules import cleanly

from har_loader import load_clean, load_har
from matcher import find_matches
from token_extractor import extract_auth, claims_from_jwt, extract_identity_values
from prober import run_pair_probe, build_swapped_url, build_swapped_body, send_probe
from classifier import build_error_baseline, classify, classify_action
from action_verifier import is_state_changing, verify_action_swap


def shorten(text, max_length):#Truncate long strings cleanly for table display
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def shorten_auth(auth):#Display auth type and a masked preview of the credential
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


def print_results_table(rows):#Print an aligned summary table of all probe verdicts
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

    for row in rows:#Print each test direction as one formatted row
        print(
            f"{shorten(row['endpoint'], col_widths['endpoint']):<{col_widths['endpoint']}} "
            f"{row['direction']:<{col_widths['direction']}} "
            f"{str(row['status']):<{col_widths['status']}} "
            f"{row['verdict']:<{col_widths['verdict']}} "
            f"{row['confidence']:<{col_widths['confidence']}.2f}"
        )


def run_read_match(match, auth_a, auth_b, identity_a, identity_b, baseline_schemas, verbose):#Engine 1 pipeline
    endpoint_label = f"{match.method} {match.path_template}"

    if verbose:
        print(f"\n  [verbose] probing (read): {endpoint_label} (diff in {match.diff_location})")

    #Step 1 Fire swapped requests in both directions
    probe_results = run_pair_probe(match, auth_a, auth_b)

    if verbose:
        print(f"    A's creds -> B's resource: "
              f"{probe_results['a_credentials_b_resource']['swapped_url']}")
        print(f"    B's creds -> A's resource: "
              f"{probe_results['b_credentials_a_resource']['swapped_url']}")

    #Step 2 Run responses through the four signal classifier cascade
    verdict_a_to_b = classify(
        probe_results["a_credentials_b_resource"]["response"],
        baseline_schemas, identity_b,
        owner_own_body=match.request_b.get("response_body"),
        credential_owner_own_body=match.request_a.get("response_body"),
    )
    verdict_b_to_a = classify(
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

    return table_rows, report_entry


def run_action_match(match, auth_a, auth_b, verbose):#Engine 2 before and after state verification
    endpoint_label = f"{match.method} {match.path_template}"

    if verbose:
        print(f"\n  [verbose] verifying (action): {endpoint_label} (diff in {match.diff_location})")

    #Step 1 Build swapped URLs for both directions
    url_a_to_b = build_swapped_url(
        match.request_a["url"], match.diff_location,
        match.diff_index, match.diff_key, match.id_value_b
    )
    url_b_to_a = build_swapped_url(
        match.request_b["url"], match.diff_location,
        match.diff_index, match.diff_key, match.id_value_a
    )

    #Step 2 Build swapped bodies if the differing ID lives inside the JSON payload
    body_a_to_b = match.request_a.get("body")
    body_b_to_a = match.request_b.get("body")
    if match.diff_location == "body":
        body_a_to_b = build_swapped_body(match.request_a.get("body"), match.diff_key, match.id_value_b)
        body_b_to_a = build_swapped_body(match.request_b.get("body"), match.diff_key, match.id_value_a)

    #Step 3 Prepare callbacks that fire the swapped action with browser headers
    send_a_to_b = lambda: send_probe(
        url_a_to_b, auth_a, method=match.method,
        body=body_a_to_b, original_headers=match.request_a.get("headers")
    )
    send_b_to_a = lambda: send_probe(
        url_b_to_a, auth_b, method=match.method,
        body=body_b_to_a, original_headers=match.request_b.get("headers")
    )

    #Step 4 Snapshot before state, execute action, snapshot after state, and compare
    result_a_to_b = verify_action_swap(
        match.request_b["url"], auth_b, send_a_to_b,
        original_headers=match.request_b.get("headers")
    )
    result_b_to_a = verify_action_swap(
        match.request_a["url"], auth_a, send_b_to_a,
        original_headers=match.request_a.get("headers")
    )

    #Step 5 Classify whether server state mutated
    verdict_a_to_b = classify_action(result_a_to_b)
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

    return table_rows, report_entry


def main():#CLI entry point that coordinates all modules
    parser = argparse.ArgumentParser(description="IDOR-Scope automated access control leak detection engine")
    parser.add_argument("har_a", help="HAR file for user A (e.g. alice.har)")
    parser.add_argument("har_b", help="HAR file for user B (e.g. bob.har)")
    parser.add_argument("--report", default="findings.json", help="Output JSON report path")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Show step-by-step detail.")
    parser.add_argument("--test-actions", action="store_true",
                         help="Also verify state-changing endpoints (POST/PUT/PATCH/DELETE). "
                              "WARNING: this performs the real action (delete/update/etc) "
                              "against your test accounts. Only use on accounts you control.")
    args = parser.parse_args()
    verbose = args.verbose

    print(f"Loading {args.har_a} and {args.har_b}...")
    all_requests_a = load_har(args.har_a)#All traffic for error baseline learning
    all_requests_b = load_har(args.har_b)
    clean_requests_a = load_clean(args.har_a)#Filtered API traffic for matching
    clean_requests_b = load_clean(args.har_b)

    print(f"  User A: {len(all_requests_a)} total, "
          f"{len(all_requests_a) - len(clean_requests_a)} removed as junk, "
          f"{len(clean_requests_a)} remain")
    print(f"  User B: {len(all_requests_b)} total, "
          f"{len(all_requests_b) - len(clean_requests_b)} removed as junk, "
          f"{len(clean_requests_b)} remain")

    #Extract session credentials (Bearer token or Cookie) for both users
    auth_a = extract_auth(clean_requests_a)
    auth_b = extract_auth(clean_requests_b)
    if not auth_a or not auth_b:
        print("ERROR: couldn't find a Bearer token or Cookie session for one or both users.")
        sys.exit(1)

    #Extract personal identity values from responses and merge JWT payload claims
    identity_a = extract_identity_values(clean_requests_a)
    identity_b = extract_identity_values(clean_requests_b)
    if auth_a.get("type") == "bearer":
        identity_a |= claims_from_jwt(auth_a.get("value"))
    if auth_b.get("type") == "bearer":
        identity_b |= claims_from_jwt(auth_b.get("value"))

    if verbose:
        print(f"\n  [verbose] user A auth: {shorten_auth(auth_a)}")
        print(f"  [verbose] user B auth: {shorten_auth(auth_b)}")
        print(f"  [verbose] user A identity values found: {identity_a or '(none found)'}")
        print(f"  [verbose] user B identity values found: {identity_b or '(none found)'}")

    #Build error response shape baselines from 401 403 and 404 responses
    baseline_schemas = build_error_baseline(all_requests_a + all_requests_b)
    print(f"\n  Collected {len(baseline_schemas)} known 'denied' response shapes")

    #Find matched endpoints that differ by a single candidate ID
    matches = find_matches(clean_requests_a, clean_requests_b)
    read_matches = [m for m in matches if not is_state_changing(m.method)]
    action_matches = [m for m in matches if is_state_changing(m.method)]

    print(f"  Found {len(read_matches)} read-type candidate(s), "
          f"{len(action_matches)} action-type candidate(s)\n")

    if not matches:
        print("No swappable candidates found. Try browsing more matching "
              "actions in both sessions and re-capturing.")
        sys.exit(0)

    table_rows = []
    full_report = []

    #Run Engine 1 on all read endpoints
    for match in read_matches:
        rows, entry = run_read_match(
            match, auth_a, auth_b, identity_a, identity_b,
            baseline_schemas, verbose
        )
        table_rows += rows
        full_report.append(entry)

    #Run Engine 2 on state changing endpoints if --test-actions is enabled
    for match in action_matches:
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
        rows, entry = run_action_match(match, auth_a, auth_b, verbose)
        table_rows += rows
        full_report.append(entry)

    print()
    if table_rows:
        print_results_table(table_rows)
    else:
        print("(no endpoints were actually tested - action-type candidates "
              "were skipped; re-run with --test-actions)")

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    leak_count = sum(1 for row in table_rows if row["verdict"] == "confirmed_leak")
    print(f"\n{len(table_rows)} test(s) run, {leak_count} confirmed leak(s)")
    print(f"Full report saved to {args.report}")


if __name__ == "__main__":
    main()


# Libraries Used:

# sys and os (builtin) configure module import paths and handle exit codes
# json (builtin) writes the final findings report to disk in structured JSON format
# argparse (builtin) parses command line flags like --verbose, --report, and --test-actions

# Variables Used:

# all_requests_a / all_requests_b hold unfiltered HAR traffic used to learn error shapes
# clean_requests_a / clean_requests_b hold filtered API requests used for matching and probing
# auth_a / auth_b store extracted session credentials as {"type": "bearer"|"cookie", "value": ...}
# identity_a / identity_b store sets of personal markers (emails, phones, usernames, JWT claims)
# baseline_schemas holds the list of error response shapes learned from 401/403/404 traffic
# read_matches / action_matches separate GET probes (Engine 1) from state-changing probes (Engine 2)
# table_rows / full_report collect console summary rows and detailed JSON output entries

# Working:

# main parses CLI arguments and calls har_loader to build raw and cleaned request lists
# token_extractor pulls each user's Bearer token or Cookie and extracts personal identity markers
# If the credential is a JWT Bearer token claims_from_jwt merges decoded claims into the identity set
# classifier builds an error baseline from all 401 403 and 404 responses across both HAR files
# matcher compares User A and User B traffic to find endpoints differing by a single ID
# Read candidates are sent through run_read_match (Engine 1) which swaps IDs via prober and classifies responses
# State-changing candidates (POST/PUT/PATCH/DELETE) are sent through run_action_match (Engine 2) only if --test-actions is passed
# Finally engine prints an aligned summary table to the terminal and writes full evidence to findings.json