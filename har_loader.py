#Opens a browser HAR file, filters out junk like images and trackers
#Returns clean request/response data for the detection engine.

import json
from urllib.parse import urlparse, parse_qsl

JUNK = [".css", ".woff", ".woff2", ".png", ".jpg", ".jpeg", ".svg", ".ico",
        "google", "facebook", "analytics", "gstatic", "hot-update", "favicon",
        "chatbot/genai"]

def is_junk(url):#Check if URL points to static assets or tracker noise
    url = url.lower()#Normalize to lowercase so .PNG and .png both match
    return any(keyword in url for keyword in JUNK)#If any junk keyword found return True


def parse(path, skip_junk=False):#Core parser, reads HAR and builds clean list
    with open(path, "r", encoding="utf-8") as f: #Open the file at given path
        data = json.load(f) #Load JSON text into Python dictionary in RAM

    entries = data.get("log", {}).get("entries", []) #Get the list of all HTTP transactions i.e requests and responses
    clean = [] #Empty List to store clean requests

    for entry in entries: #Loop through each transaction one by one
        req = entry.get("request", {}) #Pull the requests
        res = entry.get("response", {}) #Pull the responses
        url = req.get("url", "") #Get the full URL string

        if not url: #If URL is empty skip that URL
            continue
        if skip_junk and is_junk(url): #If junk filtering is on and URL is junk skip it
            continue

        parts = urlparse(url) #Split URL into components (scheme, domain, path, query)
        headers = {} #Empty dictonary to store headers
        for h in req.get("headers", []): #Loop through raw HAR header pairs
            if "name" in h and "value" in h: #Check if both fields i.e name and value exist.
                headers[h["name"].lower()] = h["value"] #Store with lowercase key

        body = None #Default no body
        if "postData" in req: #If browser sent POST/PUT data
            body = req["postData"].get("text") #Extract the payload text

        response_body = None #Default no response body
        content = res.get("content", {}) #Get response content container
        if content.get("text"): #If server actually returned text
            response_body = content["text"] #Store it

        clean.append({ #Bundle all 8 components into one dictionary
            "url": url,
            "path": parts.path,
            "query": dict(parse_qsl(parts.query)),
            "method": req.get("method", "GET"),
            "headers": headers,
            "body": body,
            "status": res.get("status"),
            "response_body": response_body,
        })

    return clean #Return the clean list back to whoever called this function


def load_har(path): #Returns ALL requests including junk, used for error baselines
    return parse(path, skip_junk=False)


def load_clean(path): #Returns only filtered API requests, used for matching and probing
    return parse(path, skip_junk=True)


# Libraries Used:
# json (builtin) reads the .har file which is standard JSON text into Python dicts
# urlparse (from urllib.parse) splits a URL string into path, query, domain etc
# parse_qsl (from urllib.parse) splits query string like "id=5&page=1" into pairs

# Variables Used:
# data: holds the entire HAR file content as a Python dictionary in RAM
# entries: is the list of all HTTP transactions recorded by the browser
# req: is one single HTTP request (method, url, headers, body)
# res: is one single HTTP response (status code, content body)
# clean: is the collection tray that accumulates all filtered request dicts
# headers: is a clean dictionary extracted and built from the HAR header pair list

# Working:
# The main master file "engine.py" calls load_har or load_clean with a file path
# File is opened and parsed into RAM by json.load
# Each transaction is examined one by one in the for loop
# If junk filtering is active and URL matches noise like .png or analytics it is skipped
# Otherwise URL is split, headers are normalized, bodies are extracted
# Everything is bundled into a dictionary and appended to the clean list
# The list is returned to engine.py which passes it to matcher and token extractor

# Two entry points exist because engine.py needs both:
# load_har gives ALL requests to build error response baselines
# load_clean gives only real API endpoints for actual IDOR testing
