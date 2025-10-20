"""
JSLIB - JavaScript Library Detection Module

This module implements robust detection of JavaScript libraries and frameworks
by analyzing JavaScript files loaded on the homepage. It uses pattern matching
with confidence scoring to reduce false positives.
"""

import re
from urllib.parse import urlparse, urljoin
from collections import defaultdict

from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

from bs4 import BeautifulSoup

__TESTLABEL__ = "Test JavaScript library detection"


class JSLIB:
    """
    JSLIB performs JavaScript library detection.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client

        self.response_hp = responses.resp_hp
        self.js_definitions = self.helpers.load_definitions("jslib.json")

        self.detected_libraries = []
        self.analyzed_content = {}

    def run(self):
        """
        Runs the JavaScript library detection process.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        base_url = self.args.url.rstrip("/")
        resp = self.response_hp
        html = resp.text

        js_urls = self._extract_js_urls(html, base_url)
        
        if self.args.verbose:
            ptprint(f"Found {len(js_urls)} JavaScript files", "ADDITIONS", not self.args.json, indent=4, colortext=True)

        for js_url in js_urls:
            self._analyze_js_file(js_url)

        self._analyze_inline_scripts(html)
        self._report()

    def _extract_js_urls(self, html, base_url):
        """
        Extracts all JavaScript file URLs from HTML content.
        """
        soup = BeautifulSoup(html, "html.parser")
        js_urls = set()

        for script in soup.find_all("script", src=True):
            src = script.get("src")
            if src:
                abs_url = urljoin(base_url, src)
                js_urls.add(abs_url)

        for link in soup.find_all("link", {"rel": ["preload", "prefetch"], "as": "script"}):
            href = link.get("href")
            if href:
                abs_url = urljoin(base_url, href)
                js_urls.add(abs_url)

        return list(js_urls)

    def _analyze_inline_scripts(self, html):
        """
        Analyzes inline script tags for library detection.
        """
        soup = BeautifulSoup(html, "html.parser")
        
        for script in soup.find_all("script", src=False):
            if script.string:
                content = script.string
                for lib_def in self.js_definitions:
                    result = self._check_library(content, "inline script", lib_def, is_inline=True)
                    if result:
                        self._add_unique_detection(result)

    def _analyze_js_file(self, js_url):
        """
        Fetches and analyzes a JavaScript file to detect libraries.
        """
        if js_url in self.analyzed_content:
            return

        resp = self.helpers.fetch(js_url, allow_redirects=True)
        
        if resp is None or resp.status_code != 200:
            return

        js_content = resp.text
        self.analyzed_content[js_url] = js_content

        is_bundle = len(js_content) > 500000

        for lib_def in self.js_definitions:
            result = self._check_library(js_content, js_url, lib_def, is_bundle=is_bundle)
            if result:
                self._add_unique_detection(result)

    def _check_library(self, js_content, js_url, lib_def, is_inline=False, is_bundle=False):
        """
        Checks if JavaScript content matches a library signature.
        """
        matched = False
        
        url_pattern = lib_def.get("url_pattern")
        if url_pattern and not is_inline:
            if re.search(url_pattern, js_url, re.IGNORECASE):
                matched = True
        
        signatures = lib_def.get("signatures", [])
        if not matched and signatures:
            for signature in signatures:
                if signature.lower() in js_content.lower():
                    matched = True
                    break
        
        if not matched:
            return None

        probability = lib_def.get("probability", 100)
        
        if is_bundle:
            probability = int(probability * 0.9)

        version = self._detect_version(js_content, lib_def)
        
        result = {
            "technology": lib_def["technology"],
            "category": lib_def.get("category", "JavaScript Library"),
            "url": js_url,
            "probability": probability
        }

        if version:
            result["version"] = version

        return result

    def _detect_version(self, js_content, lib_def):
        """
        Attempts to detect the version of a library from its content.
        """
        version_patterns = lib_def.get("version_patterns", [])
        
        for pattern in version_patterns:
            try:
                search_content = js_content[:5000] if len(js_content) > 5000 else js_content
                match = re.search(pattern, search_content, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else match.group(0)
                    if re.match(r'^\d+(\.\d+)*$', version):
                        return version
            except re.error:
                continue

        return None

    def _add_unique_detection(self, result):
        """
        Adds detection to list, avoiding duplicates and keeping highest confidence version.
        """
        technology = result["technology"]
        version = result.get("version")
        
        # Check for existing detection of same technology
        for i, existing in enumerate(self.detected_libraries):
            if existing["technology"] == technology:
                # If versions match, keep the one with higher probability
                if existing.get("version") == version:
                    if result["probability"] > existing["probability"]:
                        self.detected_libraries[i] = result
                    return
                # If different versions, keep both + make note
                elif version and existing.get("version"):
                    result["note"] = "Multiple versions detected"
                    self.detected_libraries.append(result)
                    return
                # If one has version and other doesn't, prefer the one with version
                elif version and not existing.get("version"):
                    self.detected_libraries[i] = result
                    return
                elif not version and existing.get("version"):
                    return
                # Both without version, keep higher probability
                elif result["probability"] > existing["probability"]:
                    self.detected_libraries[i] = result
                return
        
        self.detected_libraries.append(result)

    def _report(self):
        """
        Reports all detected JavaScript libraries with improved formatting.
        """
        if self.detected_libraries:
            self.detected_libraries.sort(key=lambda x: x["probability"], reverse=True)
            
            for lib in self.detected_libraries:
                technology = lib["technology"]
                version = lib.get("version")
                probability = lib.get("probability", 100)
                url = lib.get("url", "")
                category = lib.get("category", "JavaScript Library")
                note = lib.get("note", "")
                
                storage.add_to_storage(
                    technology=technology,
                    technology_type=category,
                    probability=probability,
                    version=version if version else None
                )


                if self.args.verbose:
                    ptprint(f"Match: {url}", "ADDITIONS", not self.args.json, indent=4, colortext=True)
                
                if version:
                    ptprint(f"{technology} {version} ({category}) ", "VULN", 
                           not self.args.json, indent=4, end=" ")
                else:
                    ptprint(f"{technology} ({category})", "VULN", 
                           not self.args.json, indent=4, end=" ")
                
                ptprint(f"({probability}%)", "ADDITIONS", not self.args.json)
                    
        else:
            ptprint("It was not possible to identify any JavaScript library", "INFO", not self.args.json, indent=4)


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point for running the JSLIB detection."""
    JSLIB(args, ptjsonlib, helpers, http_client, responses).run()