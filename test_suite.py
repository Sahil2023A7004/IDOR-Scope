"""
test_suite.py
Automated test suite verifying IDOR-Scope components and end-to-end execution.
"""

import sys
import os
import json
import base64
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from har_loader import is_junk, parse, load_har, load_clean
from token_extractor import extract_auth, claims_from_jwt, extract_identity_values
from matcher import find_matches, MatchedPair
from prober import build_swapped_url, build_swapped_body, clean_headers, replace_path_segment
from classifier import (
    classify, classify_action, build_error_baseline,
    LEAK, DENIED_STATUS, DENIED_SHAPE, CORRECTLY_SCOPED, NO_STATE_CHANGE
)

TESTS_PASSED = 0
TESTS_FAILED = 0


def check(name, condition, details=""):
    global TESTS_PASSED, TESTS_FAILED
    if condition:
        print(f"  [PASS] {name}")
        TESTS_PASSED += 1
    else:
        print(f"  [FAIL] {name}: {details}")
        TESTS_FAILED += 1


# ==========================================
# 1. Test har_loader.py
# ==========================================
def test_har_loader():
    print("\n--- Testing har_loader.py ---")
    check("is_junk on image", is_junk("https://test.com/logo.PNG"))
    check("is_junk on stylesheet", is_junk("https://test.com/assets/style.css"))
    check("is_junk on analytics", is_junk("https://google-analytics.com/collect"))
    check("is_junk on clean API", not is_junk("https://test.com/api/v1/users/101/profile"))

    # Test dummy HAR parsing
    sample_har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://test.com/api/users/101",
                        "method": "GET",
                        "headers": [{"name": "Authorization", "value": "Bearer token101"}],
                    },
                    "response": {"status": 200, "content": {"text": "{\"user\": 101}"}},
                },
                {
                    "request": {
                        "url": "https://test.com/images/cat.png",
                        "method": "GET",
                        "headers": [],
                    },
                    "response": {"status": 200, "content": {}},
                },
            ]
        }
    }
    with open("temp_test.har", "w", encoding="utf-8") as f:
        json.dump(sample_har, f)

    all_reqs = load_har("temp_test.har")
    clean_reqs = load_clean("temp_test.har")
    check("load_har keeps junk", len(all_reqs) == 2)
    check("load_clean filters junk", len(clean_reqs) == 1)
    check("header normalized to lowercase", "authorization" in clean_reqs[0]["headers"])
    if os.path.exists("temp_test.har"):
        os.remove("temp_test.har")


# ==========================================
# 2. Test token_extractor.py
# ==========================================
def test_token_extractor():
    print("\n--- Testing token_extractor.py ---")
    reqs_bearer = [{"headers": {"authorization": "Bearer secret_token_xyz"}}]
    auth_bearer = extract_auth(reqs_bearer)
    check("extract_auth Bearer type", auth_bearer["type"] == "bearer")
    check("extract_auth Bearer value", auth_bearer["value"] == "secret_token_xyz")

    reqs_cookie = [{"headers": {"cookie": "session_id=sess_abc_123"}}]
    auth_cookie = extract_auth(reqs_cookie)
    check("extract_auth Cookie type", auth_cookie["type"] == "cookie")
    check("extract_auth Cookie value", auth_cookie["value"] == "session_id=sess_abc_123")

    # JWT claim extraction test
    payload = {"sub": "10042", "email": "alice@university.edu", "username": "alice_sec"}
    b64_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    fake_jwt = f"eyJhbGciOiJIUzI1NiJ9.{b64_payload}.fake_signature"
    claims = claims_from_jwt(fake_jwt)
    check("JWT sub claim extracted", "10042" in claims)
    check("JWT email claim extracted", "alice@university.edu" in claims)
    check("JWT username claim extracted", "alice_sec" in claims)

    # Response identity extraction test
    reqs_ident = [
        {"response_body": "Contact alice@test.org or call 9876543210."},
        {"response_body": json.dumps({"display_name": "Alice Wonderland", "id": 10042})},
    ]
    identities = extract_identity_values(reqs_ident)
    check("Email regex extracted", "alice@test.org" in identities)
    check("Phone regex extracted", "9876543210" in identities)
    check("JSON display_name extracted", "Alice Wonderland" in identities)


# ==========================================
# 3. Test matcher.py
# ==========================================
def test_matcher():
    print("\n--- Testing matcher.py ---")
    # URL path parameter diff
    req_a1 = {"method": "GET", "path": "/api/users/101/orders", "url": "http://x/api/users/101/orders", "query": {}, "status": 200}
    req_b1 = {"method": "GET", "path": "/api/users/102/orders", "url": "http://x/api/users/102/orders", "query": {}, "status": 200}
    matches = find_matches([req_a1], [req_b1])
    check("Path ID diff match found", len(matches) == 1)
    if matches:
        check("Diff location is path", matches[0].diff_location == "path")
        check("Diff value A is 101", matches[0].id_value_a == "101")
        check("Diff value B is 102", matches[0].id_value_b == "102")

    # Query parameter diff
    req_a2 = {"method": "GET", "path": "/api/profile", "url": "http://x/api/profile?user_id=101", "query": {"user_id": "101"}, "status": 200}
    req_b2 = {"method": "GET", "path": "/api/profile", "url": "http://x/api/profile?user_id=102", "query": {"user_id": "102"}, "status": 200}
    matches_q = find_matches([req_a2], [req_b2])
    check("Query param diff match found", len(matches_q) == 1)
    if matches_q:
        check("Diff location is query", matches_q[0].diff_location == "query")
        check("Diff key is user_id", matches_q[0].diff_key == "user_id")

    # JSON Body diff (Gap 2)
    req_a3 = {"method": "POST", "path": "/api/account", "url": "http://x/api/account", "query": {}, "body": json.dumps({"account_id": 101}), "status": 200}
    req_b3 = {"method": "POST", "path": "/api/account", "url": "http://x/api/account", "query": {}, "body": json.dumps({"account_id": 102}), "status": 200}
    matches_b = find_matches([req_a3], [req_b3])
    check("JSON body diff match found (Gap 2)", len(matches_b) == 1)
    if matches_b:
        check("Diff location is body", matches_b[0].diff_location == "body")
        check("Diff key is account_id", matches_b[0].diff_key == "account_id")


# ==========================================
# 4. Test prober.py
# ==========================================
def test_prober():
    print("\n--- Testing prober.py ---")
    path_res = replace_path_segment("/api/v1/users/101/data", 3, "202")
    check("replace_path_segment rewrites correctly", path_res == "/api/v1/users/202/data")

    url_path_swap = build_swapped_url("https://site.com/api/users/101", "path", 2, "", "102")
    check("build_swapped_url path", url_path_swap == "https://site.com/api/users/102")

    url_query_swap = build_swapped_url("https://site.com/api/doc?id=101&view=full", "query", -1, "id", "102")
    check("build_swapped_url query", "id=102" in url_query_swap and "view=full" in url_query_swap)

    body_swap = build_swapped_body(json.dumps({"user": "101", "action": "test"}), "user", "102")
    parsed_body = json.loads(body_swap)
    check("build_swapped_body JSON update", parsed_body["user"] == "102" and parsed_body["action"] == "test")

    headers_cleaned = clean_headers({"host": "bad.com", "content-length": "10", "user-agent": "Mozilla/5.0", "cookie": "x=1"})
    check("clean_headers stripped host", "host" not in headers_cleaned)
    check("clean_headers stripped content-length", "content-length" not in headers_cleaned)
    check("clean_headers kept user-agent", "user-agent" in headers_cleaned)


# ==========================================
# 5. Test classifier.py
# ==========================================
def test_classifier():
    print("\n--- Testing classifier.py ---")
    # Signal 1: Status Code Rejection
    res_403 = {"status": 403, "body": "Forbidden"}
    verdict_403 = classify(res_403, [], set())
    check("Signal 1: 403 returns DENIED_STATUS", verdict_403["label"] == DENIED_STATUS)

    # Signal 2: Disguised Error Baseline
    error_sample = [{"status": 403, "response_body": json.dumps({"error": "Unauthorized", "code": 403})}]
    baseline = build_error_baseline(error_sample)
    res_disguised = {"status": 200, "body": json.dumps({"error": "Permission Denied", "code": 999})}
    verdict_shape = classify(res_disguised, baseline, set())
    check("Signal 2: 200 with error schema returns DENIED_SHAPE", verdict_shape["label"] == DENIED_SHAPE)

    # Signal 3: Value Provenance (Direct target leak)
    victim_values = {"bob_secret@target.org", "9876543210"}
    res_leak_val = {"status": 200, "body": json.dumps({"name": "Bob", "email": "bob_secret@target.org"})}
    verdict_leak = classify(res_leak_val, baseline, victim_values)
    check("Signal 3: Response with victim email returns LEAK", verdict_leak["label"] == LEAK)

    # Signal 4: Personal field diff & CORRECTLY_SCOPED
    body_user_a = json.dumps({"name": "Alice", "balance": 500})
    body_user_b = json.dumps({"name": "Bob", "balance": 9999})
    # Server returns Alice's data when asked for Bob's ID -> CORRECTLY_SCOPED
    res_scoped = {"status": 200, "body": json.dumps({"name": "Alice", "balance": 500})}
    verdict_scoped = classify(res_scoped, baseline, set(), owner_own_body=body_user_b, credential_owner_own_body=body_user_a)
    check("Signal 4: Server returned own data -> CORRECTLY_SCOPED", verdict_scoped["label"] == CORRECTLY_SCOPED)

    # Engine 2: Action verifier classification
    verdict_act_leak = classify_action({"before": {"status": 200, "body": "exists"}, "after": {"status": 404, "body": "none"}, "state_changed": True})
    check("Action engine: state_changed True -> LEAK", verdict_act_leak["label"] == LEAK)

    verdict_act_safe = classify_action({"before": {"status": 200, "body": "exists"}, "after": {"status": 200, "body": "exists"}, "state_changed": False})
    check("Action engine: state_changed False -> NO_STATE_CHANGE", verdict_act_safe["label"] == NO_STATE_CHANGE)


# ==========================================
# 6. End-to-End Integration Test with Mock HTTP Server
# ==========================================
class MockTargetHandler(BaseHTTPRequestHandler):
    notes = {"101": "Alice Note", "102": "Bob Private Note"}

    def log_message(self, format, *args):
        return  # Silence server logs

    def do_GET(self):
        auth = self.headers.get("authorization", "")
        if self.path == "/api/users/101":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"id": "101", "email": "alice@site.com", "name": "Alice"}).encode())
        elif self.path == "/api/users/102":
            # Vulnerable IDOR endpoint: returns Bob's data to anyone!
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"id": "102", "email": "bob@site.com", "name": "Bob Private"}).encode())
        elif self.path == "/api/notes/102":
            content = self.notes.get("102", "not found")
            self.send_response(200 if content != "not found" else 404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(content.encode())
        elif self.path == "/api/error_example":
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "forbidden", "code": 403}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        if self.path == "/api/notes/102":
            # Vulnerable Action IDOR: deletes Bob's note regardless of who sends it!
            MockTargetHandler.notes["102"] = "not found"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"message": "deleted"}).encode())
        else:
            self.send_response(404)
            self.end_headers()


def test_end_to_end():
    print("\n--- Testing End-to-End Execution (engine.py against Local Server) ---")
    server = HTTPServer(("127.0.0.1", 8989), MockTargetHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(0.5)

    base_url = "http://127.0.0.1:8989"

    # Create Alice HAR
    alice_har = {
        "log": {
            "entries": [
                {
                    "request": {"url": f"{base_url}/api/users/101", "method": "GET", "headers": [{"name": "Authorization", "value": "Bearer token_alice_123"}]},
                    "response": {"status": 200, "content": {"text": json.dumps({"id": "101", "email": "alice@site.com", "name": "Alice"})}}
                },
                {
                    "request": {"url": f"{base_url}/api/error_example", "method": "GET", "headers": [{"name": "Authorization", "value": "Bearer token_alice_123"}]},
                    "response": {"status": 403, "content": {"text": json.dumps({"error": "forbidden", "code": 403})}}
                },
                {
                    "request": {"url": f"{base_url}/api/notes/101", "method": "DELETE", "headers": [{"name": "Authorization", "value": "Bearer token_alice_123"}]},
                    "response": {"status": 200, "content": {"text": json.dumps({"message": "deleted"})}}
                }
            ]
        }
    }

    # Create Bob HAR
    bob_har = {
        "log": {
            "entries": [
                {
                    "request": {"url": f"{base_url}/api/users/102", "method": "GET", "headers": [{"name": "Authorization", "value": "Bearer token_bob_456"}]},
                    "response": {"status": 200, "content": {"text": json.dumps({"id": "102", "email": "bob@site.com", "name": "Bob Private"})}}
                },
                {
                    "request": {"url": f"{base_url}/api/notes/102", "method": "DELETE", "headers": [{"name": "Authorization", "value": "Bearer token_bob_456"}]},
                    "response": {"status": 200, "content": {"text": json.dumps({"message": "deleted"})}}
                }
            ]
        }
    }

    with open("test_alice.har", "w", encoding="utf-8") as f:
        json.dump(alice_har, f)
    with open("test_bob.har", "w", encoding="utf-8") as f:
        json.dump(bob_har, f)

    # Run engine.py as a subprocess
    import subprocess
    cmd = [sys.executable, "engine.py", "test_alice.har", "test_bob.har", "--test-actions", "--report", "test_findings.json"]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    check("engine.py executed with exit code 0", proc.returncode == 0, proc.stderr)
    check("test_findings.json was created", os.path.exists("test_findings.json"))

    if os.path.exists("test_findings.json"):
        with open("test_findings.json", "r", encoding="utf-8") as f:
            findings = json.load(f)

        read_findings = [f for f in findings if f.get("type") == "read"]
        check("Read endpoint was evaluated", len(read_findings) >= 1)
        if read_findings:
            a_to_b_verdict = read_findings[0]["a_credentials_b_resource"]["verdict"]["label"]
            check("IDOR correctly detected on read endpoint (confirmed_leak)", a_to_b_verdict == "confirmed_leak")

        action_findings = [f for f in findings if f.get("type") == "action"]
        check("Action endpoint was evaluated", len(action_findings) >= 1)
        if action_findings:
            action_verdict = action_findings[0]["a_credentials_b_resource"]["verdict"]["label"]
            check("Action IDOR correctly detected via state change (confirmed_leak)", action_verdict == "confirmed_leak")

    # Clean up test files
    for p in ["test_alice.har", "test_bob.har", "test_findings.json"]:
        if os.path.exists(p):
            os.remove(p)

    server.shutdown()


def main():
    print("========================================")
    print("      IDOR-Scope Verification Suite     ")
    print("========================================")
    test_har_loader()
    test_token_extractor()
    test_matcher()
    test_prober()
    test_classifier()
    test_end_to_end()

    print("\n========================================")
    print(f"Results: {TESTS_PASSED} Passed, {TESTS_FAILED} Failed")
    print("========================================")
    if TESTS_FAILED == 0:
        print("ALL TESTS PASSED! Project is fully functional.")
        sys.exit(0)
    else:
        print("SOME TESTS FAILED. Review errors above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
