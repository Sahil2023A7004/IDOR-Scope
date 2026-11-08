#Opens a browser HAR file and filters out noise like images and trackers.
#Returns clean request and response data for the detection engine.

import json
from urllib.parse import urlparse, parse_qsl

JUNK_EXTENSIONS = {
    ".css", ".woff", ".woff2", ".png", ".jpg", ".jpeg",
    ".svg", ".ico", ".gif", ".webp", ".ttf", ".otf", ".map",
}

JUNK_DOMAINS = {
    "google.com", "google-analytics.com", "googletagmanager.com",
    "analytics.google.com", "ssl.google-analytics.com",
    "facebook.com", "facebook.net", "connect.facebook.net",
    "gstatic.com", "googleapis.com", "doubleclick.net",
    "hotjar.com", "cdn.hotjar.com",
    "segment.io", "cdn.segment.com",
    "amplitude.com", "api.amplitude.com",
    "mixpanel.com", "api.mixpanel.com",
    "fullstory.com", "rs.fullstory.com",
    "intercom.io", "widget.intercom.io",
    "sentry.io", "ingest.sentry.io",
}

JUNK_PATH_PATTERNS = {
    "hot-update",    #Webpack live reload files
    "favicon",       #Browser tab icon requests
    "chatbot/genai", #Internal AI chat widget
}


def is_junk(url):                                                    #Check if URL is static noise or a third party tracker
    url_lower = url.lower()                                          #Convert URL to lowercase for consistent matching
    parsed = urlparse(url_lower)                                     #Split URL into domain and path parts

    for ext in JUNK_EXTENSIONS:                                      #Stage 1 Check if path ends with an image or font extension
        if parsed.path.endswith(ext):
            return True                                              #It is a static file so mark as junk

    domain = parsed.netloc.split(":")[0]                             #Stage 2 Get domain name and remove port number if present
    for junk_domain in JUNK_DOMAINS:                                 #Check if domain belongs to known analytics or ad trackers
        if domain == junk_domain or domain.endswith("." + junk_domain):
            return True                                              #Matches a tracker domain or its subdomain

    for pattern in JUNK_PATH_PATTERNS:                               #Stage 3 Check for noisy keywords inside the URL
        if pattern in url_lower:
            return True                                              #Matches internal background noise

    return False                                                     #Passed all checks so it is a real API request


def parse(path, skip_junk=False):                                    #Read HAR file from disk and build a clean list in RAM
    with open(path, "r", encoding="utf-8") as f:                     #Open the HAR file in read mode
        data = json.load(f)                                          #Convert JSON text into a Python dictionary in RAM

    entries = data.get("log", {}).get("entries", [])                 #Get the list of all recorded HTTP traffic
    clean = []                                                       #Create an empty list to store clean requests

    for entry in entries:                                            #Loop through each recorded HTTP transaction one by one
        req = entry.get("request", {})                               #Get the outgoing request details
        res = entry.get("response", {})                              #Get the incoming response details
        url = req.get("url", "")                                     #Get the full request URL string

        if not url:                                                  #If the URL is empty skip this transaction
            continue
        if skip_junk and is_junk(url):                               #If filtering is enabled and URL is noise skip it
            continue

        parts = urlparse(url)                                        #Split URL into scheme domain path and query
        headers = {}                                                 #Create an empty dictionary to store request headers
        for h in req.get("headers", []):                             #Loop through raw header pairs from the browser
            if "name" in h and "value" in h:                         #Make sure both header name and value exist
                headers[h["name"].lower()] = h["value"]              #Save header with lowercase name

        body = None                                                  #Default to no request body
        if "postData" in req:                                        #Check if the browser sent data in a POST or PUT request
            body = req["postData"].get("text")                       #Save the sent payload text

        response_body = None                                         #Default to no response body
        content = res.get("content", {})                             #Get the response content section
        if content.get("text"):                                      #Check if the server sent back body text
            response_body = content["text"]                          #Save the response text

        clean.append({                                               #Pack all 8 important pieces of data into one dictionary
            "url": url,
            "path": parts.path,
            "query": dict(parse_qsl(parts.query)),
            "method": req.get("method", "GET"),
            "headers": headers,
            "body": body,
            "status": res.get("status"),
            "response_body": response_body,
        })

    return clean                                                     #Return the finished list of requests to RAM


def load_har(path):                                                  #Load all requests including junk to help learn error shapes
    return parse(path, skip_junk=False)


def load_clean(path):                                                #Load only real API requests for matching and testing
    return parse(path, skip_junk=True)


# json.load is an inbuilt function that reads JSON text from a file into a Python dictionary in RAM
# urlparse is an inbuilt function that splits a full web address into smaller pieces like domain and path
# parse qsl is an inbuilt function that turns query text like id=5&page=1 into key and value pairs

# Variables Used:

# JUNK EXTENSIONS stores file endings like png and css that are never API endpoints
# JUNK DOMAINS stores third party tracker domains like google analytics and hotjar
# data holds the entire HAR file content as a Python dictionary in RAM
# entries holds the list of all HTTP transactions captured by the browser
# clean is the list that collects all formatted request dictionaries
# domain holds just the website hostname so path words do not accidentally trigger domain filters

# Working:

# engine calls load har and load clean with the path to a user HAR file
# parse opens the file and loops through every recorded transaction
# When skip junk is True is junk checks file extensions first then the domain name and finally path patterns
# Checking only the domain name for trackers prevents real API paths like /api/google/login from being deleted
# For every valid request parse extracts the URL path query parameters headers body and response
# All clean dictionaries are stored in a list and returned to engine for the next pipeline stage