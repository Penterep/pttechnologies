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
from helpers.products import get_product_manager
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
        self.product_manager = get_product_manager()

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

        version = self._detect_version(js_content, lib_def, js_url)
        
        # Get product info from product_id
        product_id = lib_def.get("product_id")
        if not product_id:
            return None  # Skip if no product_id defined
            
        product = self.product_manager.get_product_by_id(product_id)
        if not product:
            return None
        
        products = product.get('products', [])
        technology_name = products[0] if products else product.get("our_name", "Unknown")
        display_name = product.get("our_name", "Unknown")
        category = self.product_manager.get_category_name(product.get("category_id"))
        
        result = {
            "product_id": product_id,
            "technology": technology_name,  # For storage (CVE compatible)
            "display_name": display_name,   # For printing
            "category": category,
            "url": js_url,
            "probability": probability
        }

        if version:
            result["version"] = version

        return result

    def _detect_version(self, js_content, lib_def, js_url=None):
        """
        Attempts to detect the version of a library from its content and URL.
        """
        version_patterns = lib_def.get("version_patterns", [])
        url_pattern = lib_def.get("url_pattern")
        product_id = lib_def.get("product_id")
        
        # Try to extract version from URL if url_pattern contains capture groups
        if js_url and url_pattern:
            try:
                url_match = re.search(url_pattern, js_url, re.IGNORECASE)
                if url_match and url_match.groups():
                    for group in url_match.groups():
                        if group and re.match(r'^\d+(\.\d+)*$', group):
                            return group
            except re.error:
                pass
        
        # For jQuery, search more thoroughly in bundled files
        is_jquery = product_id == 90
                
        for idx, pattern in enumerate(version_patterns):
            try:
                if is_jquery:
                    search_content = js_content
                elif len(js_content) > 100000 and len(pattern) < 100:
                    search_sections = [
                        js_content[:50000],
                        js_content[len(js_content)//3:len(js_content)//3 + 50000],
                        js_content[2*len(js_content)//3:2*len(js_content)//3 + 50000],
                        js_content[-50000:]
                    ]
                    search_content = ''.join(search_sections)
                elif len(js_content) > 50000:
                    search_content = js_content[:30000] + js_content[-30000:]
                else:
                    search_content = js_content
                
                match = re.search(pattern, search_content, re.IGNORECASE | re.MULTILINE)
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
        url = result.get("url", "")
        
        # Check for existing detection of same technology
        for i, existing in enumerate(self.detected_libraries):
            if existing["technology"] == technology:
                # If new result has version and existing doesn't, ALWAYS prefer the one with version
                if version and not existing.get("version"):
                    self.detected_libraries[i] = result
                    return
                # If existing has version and new doesn't, keep existing
                elif not version and existing.get("version"):
                    return
                # If both have versions
                elif version and existing.get("version"):
                    if existing.get("version") == version:
                        # Same version, keep higher probability
                        if result["probability"] > existing["probability"]:
                            self.detected_libraries[i] = result
                        return
                    else:
                        # Different versions, keep both
                        result["note"] = "Multiple versions detected"
                        self.detected_libraries.append(result)
                        return
                # Neither has version, keep higher probability
                else:
                    if result["probability"] > existing["probability"]:
                        self.detected_libraries[i] = result
                    return
        
        # No existing detection found, add as new
        self.detected_libraries.append(result)

    def _report(self):
        """
        Reports all detected JavaScript libraries with improved formatting.
        """
        if self.detected_libraries:
            self.detected_libraries.sort(key=lambda x: x["probability"], reverse=True)
            
            for lib in self.detected_libraries:
                technology = lib["technology"]  # For storage (CVE compatible)
                display_name = lib.get("display_name", technology)  # For printing
                version = lib.get("version")
                product_id = lib.get("product_id")
                probability = lib.get("probability", 100)
                url = lib.get("url", "")
                category = lib.get("category", "JavaScript Library")
                note = lib.get("note", "")
                
                # Get vendor from product if product_id is available
                vendor = None
                if product_id:
                    product = self.product_manager.get_product_by_id(product_id)
                    if product:
                        vendor = product.get('vendor')
                
                storage.add_to_storage(
                    technology=technology,
                    technology_type=category,
                    probability=probability,
                    version=version if version else None,
                    product_id=product_id,
                    vendor=vendor
                )


                if self.args.verbose:
                    ptprint(f"Match: {url}", "ADDITIONS", not self.args.json, indent=4, colortext=True)
                
                if version:
                    ptprint(f"{display_name} {version} ({category}) ", "VULN", 
                           not self.args.json, indent=4, end=" ")
                else:
                    ptprint(f"{display_name} ({category})", "VULN", 
                           not self.args.json, indent=4, end=" ")
                
                ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True)
                    
        else:
            ptprint("It was not possible to identify any JavaScript library", "INFO", not self.args.json, indent=4)


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point for running the JSLIB detection."""
    JSLIB(args, ptjsonlib, helpers, http_client, responses).run()