# IDOR Scope: Automated Access Control Security Assessment Framework

An automated security assessment engine designed to detect and validate Insecure Direct Object Reference vulnerabilities across modern web applications.

Based on the research paper:
> 403 Forbidden? Ethically Evaluating Broken Access Control in the Wild (IEEE S&P 2025)

---

## Executive Overview

Section 8.2 of the Vulnerability Scan Framework paper explicitly left the semantic interpretation of HTTP 200 OK responses as an open research challenge. Web servers frequently return status 200 OK even when requests are denied, or conversely, return 200 OK with data belonging to other accounts.

IDOR Scope automates this deep semantic verification. By ingesting browser network session recordings from two test accounts, the framework correlates identical endpoints, swaps object identifiers, retransmits requests while preserving browser fingerprinting, and applies an automated dual engine classifier to definitively prove data disclosure and unauthorized state modification.

---

## Architectural Pipeline

```
User A Session  +  User B Session
       │
       ▼
 [ Har Loader ]       1. Ingests network archives and eliminates static asset noise (.png, .css).
       │
       ▼
[ Token Extractor ]   2. Auto detects Bearer tokens or Session Cookies, decodes JWT identity
       │                 claims without private keys, and builds a baseline user profile.
       ▼
   [ Matcher ]        3. Discovers equivalent endpoints and locates differing parameters
       │                 inside URL paths, query parameters, and JSON request bodies.
       │
       ├─── Read Endpoints (GET) ──────┐
       │                               ▼
       │                          [ Prober ]        4. Dispatches swapped requests while
       │                               │               forwarding browser headers for WAF bypass.
       │                               ▼
       │                         [ Classifier ]     5. Engine 1: Evaluates data leaks through
       │                                               a four signal decision cascade.
       │
       └─── Action Endpoints ──────────┐
            (POST, PUT, DELETE)        ▼
                              [ Action Verifier ]   6. Engine 2: Verifies unauthorized mutations
                                                       using pre and post state snapshots.
       │
       ▼
 Structured Findings Report (JSON) + Terminal Summary Table
```

---

## Operating Environment and Prerequisites

The system is tested for Kali Linux, Debian, and Ubuntu environments running Python 3.8 or newer.

The design relies entirely on the Python Standard Library for parsing, data structures, and networking logic, requiring only a single external HTTP library.

### Step 1: Install Operating System Packages
Open terminal and update repository lists:
```bash
sudo apt update && sudo apt install -y python3-venv python3-pip
```

### Step 2: Navigate to Project Directory
```bash
cd /path/to/files
```

### Step 3: Configure Virtual Environment
Create and activate an isolated Python environment:
```bash
python3 -m venv myenv
source myenv/bin/activate
```
The terminal prompt will display (myenv) indicating the environment is active.

### Step 4: Install Dependencies
Install the required HTTP library:
```bash
pip install requests
```

---

## Capturing Input Traffic

The engine operates on two HTTP Archive (HAR) files captured from test accounts you control:

1. Open your browser in Kali (Firefox or Chromium) and open Developer Tools by pressing F12.
2. Select the Network panel and enable the checkbox marked Preserve log.
3. Authenticate as User A (Alice) and perform typical application tasks such as browsing profile data, viewing documents, and checking settings.
4. Right click any entry within the Network log table and click Save All As HAR. Save this file as alice.har.
5. Open an incognito or private window, authenticate as User B (Bob), and execute the same sequence of actions. Save this file as bob.har.
6. Transfer both alice.har and bob.har directly into your project folder.

---

## Execution Procedures

### 1. Verification Test Run
Verify all internal logic and the mock HTTP pipeline before evaluating live targets:
```bash
python3 test-suite.py
```
Expected terminal outcome:
```
Results: 46 Passed, 0 Failed
ALL TESTS PASSED! Project is fully functional.
```

### 2. Standard Read Endpoint Assessment
Evaluates read requests to identify unauthorized data disclosure:
```bash
python3 engine.py alice.har bob.har -v
```

### 3. Comprehensive Assessment (Read and State Actions)
Includes evaluation of state modifying methods (POST, PUT, PATCH, DELETE). Engine 2 verifies whether server state on User B data was mutated by requests originating from User A:
```bash
python3 engine.py alice.har bob.har -v --test-actions
```

### 4. Custom Output Reporting
Outputs full diagnostic logs, swapped parameters, and classification evidence into a designated JSON file:
```bash
python3 engine.py alice.har bob.har -v --test-actions --report report.json
```

---

## Terminal Command Reference

| Command Flag | Description |
|---|---|
| -v or --verbose | Enables granular step by step logging for every tested transaction. |
| --test-actions | Authorizes Engine 2 to evaluate state changing endpoints on test accounts. |
| --report <file> | Designates the destination path for the structured JSON output report. |

---

## Classification Verdict Matrix

| Verdict Label | Assessment Meaning |
|---|---|
| confirmed leak | Proven finding: Victim personal data leaked into the response or server resource state was mutated. |
| no leak denied by status | Enforced control: Server rejected the request using HTTP status 401, 403, or 404. |
| no leak matches error baseline | Disguised denial: Server returned status 200 OK, but the body matched known error blueprints. |
| no leak correctly scoped | Proper tenancy: Server returned 200 OK, but safely served the requester own record, ignoring the swapped ID. |
| no leak state unchanged | Action verified: The server returned a success message, but victim resource state remained unmodified. |
| ambiguous needs manual review | Valid data format returned without definitive proof to confirm or refute a vulnerability. |
| request failed | Network connectivity timeout or connection drop occurred during test execution. |

---

## Exiting the Environment

Upon completion of assessment activities, close the virtual environment:
```bash
deactivate
```

---

## Authorization and Safe Testing Boundaries

This software is developed strictly for educational research, defensive security engineering, and authorized security assessments. Testing must be conducted exclusively against:

- Local purposely vulnerable applications such as OWASP crAPI or VAmPI.
- Accounts and applications explicitly created and owned by the tester.
- Client environments covered by written authorization and clear Rules of Engagement.