"""
Reads a HAR file (exported from browser DevTools) and turns it into a
clean list of request/response dicts in memory. Strips out junk requests
(static assets, trackers) so downstream engines only test real API endpoints.
"""

import json
from urllib.parse import urlparse, parse_qsl

JUNK_KEYWORDS = [
    ".css", ".woff", ".woff2", ".png", ".jpg", ".jpeg", ".svg", ".ico",
    "google", "facebook", "analytics", "gstatic", "hot-update", "favicon",
    "chatbot/genai",
]


def is_junk(url):
    #Return True if URL points to static assets or tracker noise.
    clean_url = url.lower()
    return any(keyword in clean_url for keyword in JUNK_KEYWORDS)


def load_har(path):
    """
    Parse a HAR file, discard static assets/analytics, and return
    a list of clean, standardized request/response dictionaries.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("log", {}).get("entries", [])
    parsed_requests = []

    for entry in entries:
        req = entry.get("request", {})
        res = entry.get("response", {})
        url = req.get("url", "")

        # Skip empty entries or static junk
        if not url or is_junk(url):
            continue

        # URL decomposition for matching the data s/as email etc.
        url_parts = urlparse(url)
        path_part = url_parts.path
        query_part = dict(parse_qsl(url_parts.query))

        # Normalize headers to lowercase to handle HTTP/1.1 and HTTP/2
        headers = {
            h["name"].lower(): h["value"]
            for h in req.get("headers", [])
            if "name" in h and "value" in h
        }

        # Extract request payload (POST/PUT/PATCH)
        request_body = None
        if "postData" in req:
            request_body = req["postData"].get("text")

        # Extract server response content
        response_body = None
        content = res.get("content", {})
        if content.get("text"):
            response_body = content["text"]

        parsed_requests.append({
            "url": url,
            "path": path_part,
            "query": query_part,
            "method": req.get("method", "GET"),
            "headers": headers,
            "body": request_body,
            "status": res.get("status"),
            "response_body": response_body,
        })

    return parsed_requests


def load_clean(path):
    #For backward Compatibility.
    return load_har(path)