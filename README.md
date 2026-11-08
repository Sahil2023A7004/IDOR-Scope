# IDOR-Scope: Automated Broken Access Control Detection Engine

An automated access control audit engine based on the IEEE S&P 2025 paper:
> *"403 Forbidden? Ethically Evaluating Broken Access Control in the Wild"* (VSF Paper)

IDOR-Scope solves the open research problem identified in Section 8.2 of the paper: automating the semantic classification of successful (`200 OK`) responses to determine whether an IDOR (Insecure Direct Object Reference) data leak genuinely occurred, rather than requiring human inspection.

---

## 1. How the Engine Works

```
alice.har  +  bob.har
       │
       ▼
 [har_loader.py]      1. Ingests raw browser archives and strips noise (.png, .css, trackers).
       │
       ▼
[token_extractor.py]  2. Auto-detects auth method (Bearer token OR session Cookie),
       │                 decodes JWT identity claims without a signing key, and
       │                 builds a baseline identity profile (usernames, emails, IDs).
       ▼
  [matcher.py]        3. Aligns corresponding endpoints between users and identifies
       │                 differing parameters in URL paths, query strings, and JSON bodies.
       │
       ├─── GET (Read Endpoints) ──────┐
       │                               ▼
       │                         [prober.py]       4. Replays requests with swapped IDs
       │                               │              forwarding browser headers for WAF bypass.
       │                               ▼
       │                       [classifier.py]     5. Engine 1: Evaluates leaks via a 4-signal
       │                                              cascade (Status → Disguised Error →
       │                                              Value Provenance → Personal Field Diff).
       │
       └─── POST/PUT/DELETE ───────────┐
                                       ▼
                              [action_verifier.py] 6. Engine 2: Verifies state mutation via
                                                      before-and-after resource snapshots.
       │
       ▼
 findings.json  +  Terminal Summary Table
```

---

## 2. Environment & Prerequisites (Kali Linux)

IDOR-Scope requires **Python 3.8+**. It deliberately relies almost entirely on the Python Standard Library (`json`, `urllib`, `re`, `base64`, `dataclasses`, `argparse`), requiring only the `requests` HTTP library.

### Step 1: Install System Dependencies
In your Kali terminal, ensure Python's virtual environment package is installed:
```bash
sudo apt update && sudo apt install -y python3-venv python3-pip
```

### Step 2: Clone or Navigate to the Project Folder
```bash
cd /path/to/idor-scope
```

### Step 3: Create and Activate a Virtual Environment
```bash
# Create the virtual environment named myenv
python3 -m venv myenv

# Activate the virtual environment
source myenv/bin/activate
```
*(Your terminal prompt will now show `(myenv)`).*

### Step 4: Install Required Packages
```bash
pip install requests
```

---

## 3. Gathering Input Data (Capturing HAR Files)

The engine requires two `.har` network archives recorded from two separate test accounts (e.g., User A and User B) performing identical or similar actions on the target application:

1. Open your browser (Firefox, Chromium, or Chrome in Kali).
2. Open **Developer Tools** (`F12` or `Ctrl + Shift + I`) and switch to the **Network** tab.
3. Check the **Preserve log** checkbox.
4. Log in as **User A (Alice)** and browse the application (visit profiles, documents, orders).
5. Right-click anywhere in the Network request list and select **"Save All As HAR"**. Save it as `alice.har`.
6. Log out, or open a private window, and repeat the exact same browsing workflow as **User B (Bob)**. Save this capture as `bob.har`.
7. Move `alice.har` and `bob.har` into your `idor-scope` project folder.

---

## 4. Running the Engine

### A. Run Automated Unit & Integration Tests
Before testing live captures, verify all components are operating correctly:
```bash
python3 test_suite.py
```
*(All 46 unit and mock integration checks should pass).*

### B. Standard Audit (Read Endpoints)
Run the engine against the two captured session files:
```bash
python3 engine.py alice.har bob.har
```

### C. Verbose Mode (Detailed Assessment Trace)
To view real-time decision logging for every evaluated endpoint:
```bash
python3 engine.py alice.har bob.har -v
```

### D. Audit State-Changing Endpoints (POST / PUT / PATCH / DELETE)
> **Warning**: This performs the real action against your test account resources to verify state mutation. Only run this against test accounts you control.
```bash
python3 engine.py alice.har bob.har -v --test-actions
```

### E. Custom Report File
Specify a custom destination for the structured JSON report:
```bash
python3 engine.py alice.har bob.har --report audit_results.json
```

---

## 5. Interpreting Verdict Labels

| Verdict | Meaning |
|---|---|
| `confirmed_leak` | High-confidence finding: Victim private data was returned in the response or server-side resource state was mutated. |
| `no_leak_denied_by_status` | Access control enforced: Server cleanly rejected the probe with HTTP 401, 403, or 404. |
| `no_leak_matches_error_baseline` | Disguised denial: Server returned `200 OK`, but the body structure matched known application error responses. |
| `no_leak_correctly_scoped` | Server returned `200 OK`, but safely served the requester's own data, ignoring the swapped ID parameter. |
| `no_leak_state_unchanged` | Action verified: The server may have returned a success message, but the victim's resource state remained completely untouched. |
| `ambiguous_needs_manual_review` | Valid response structure returned, but without sufficient identity markers to confirm or deny a leak. |
| `request_failed` | Network drop, connection timeout, or host unreachable during test. |

---

## 6. Exiting the Environment

When you have finished testing, deactivate the Python virtual environment:
```bash
deactivate
```

---

## 7. Ethical Scope & Authorization

This tool is strictly intended for **authorized testing in controlled environments**:
* Intentionally vulnerable testbeds (e.g., [OWASP crAPI](https://github.com/OWASP/crAPI), [VAmPI](https://github.com/erev0s/VAmPI)).
* Academic and defensive access control research on accounts owned and controlled by the researcher.
* Authorized penetration testing and security assessments under an explicit Rules of Engagement (RoE).
