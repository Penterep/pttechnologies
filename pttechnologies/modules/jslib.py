"""
JSLIB - JavaScript Library Detection Module

This module implements robust detection of JavaScript libraries and frameworks
by analyzing JavaScript files loaded on the homepage. It uses pattern matching
with confidence scoring to reduce false positives.
"""

import re
from urllib.parse import urljoin

from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager
from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

from bs4 import BeautifulSoup

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

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
        wapp_js_definitions = self.helpers.load_definitions("jslib_from_wappalyzer.json")
        if isinstance(wapp_js_definitions, list):
            self.js_definitions.extend(wapp_js_definitions)
        self.browser_js_definitions = self.helpers.load_definitions("jsbrowser_from_wappalyzer.json")

        self.detected_libraries = []
        self.analyzed_content = {}

    def _resolve_wappalyzer_version(self, version_template, value_regex, value):
        """
        Resolve Wappalyzer-style version templates using regex capture groups.
        """
        if not version_template:
            return None

        try:
            regex = re.compile(value_regex, re.IGNORECASE) if value_regex else None
        except re.error:
            return None

        match = regex.search(value) if regex else None
        resolved = version_template

        if match:
            groups = [match.group(0)] + list(match.groups())
            for index, group in enumerate(groups):
                group_val = group or ""
                resolved = resolved.replace(f"\\{index}", group_val)
        else:
            # If no regex exists or no match, template cannot be resolved meaningfully.
            return None

        resolved = resolved.strip()
        return resolved[:64] if resolved else None

    def _version_quality(self, version):
        """
        Higher quality means more specific semantic-like version.
        Example: 2.1.5 > 2
        """
        if not version:
            return 0
        return max(1, version.count(".") + 1)

    def _source_priority(self, result):
        """
        Prefer runtime/browser matches over static ones when quality is similar.
        """
        method = result.get("match_method")
        if method == "browser_js":
            return 3
        if method in {"url_pattern", "inline_pattern"}:
            return 2
        return 1

    def _result_score(self, result):
        return (
            int(result.get("probability", 0)),
            self._version_quality(result.get("version")),
            self._source_priority(result),
        )

    def _is_version_context_valid(self, product_id, pattern, content, match_start, match_end):
        """
        Guard against cross-library generic version captures in bundled files.
        """
        if "@version" not in pattern.lower():
            return True

        context_start = max(0, match_start - 180)
        context_end = min(len(content), match_end + 180)
        context = content[context_start:context_end].lower()

        required_keywords = {
            101: ["bootstrap"],      # Bootstrap
            102: ["popper"],         # Popper.js
            92: ["underscore"],      # Underscore.js
            93: ["lodash"],          # Lodash
        }

        keywords = required_keywords.get(product_id)
        if not keywords:
            return True

        return any(keyword in context for keyword in keywords)

    def run(self):
        """
        Runs the JavaScript library detection process.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        base_url = self.args.url.rstrip("/")
        base_path = getattr(self.args, 'base_path', '') or ''
        # Construct full base URL with path for resolving relative URLs from HTML
        full_base_url = urljoin(base_url, base_path) if base_path else base_url
        resp = self.response_hp
        html = resp.text

        js_urls = self._extract_js_urls(html, full_base_url)


        for js_url in js_urls:
            self._analyze_js_file(js_url)

        self._analyze_inline_scripts(html)
        if HAS_PLAYWRIGHT:
            self._analyze_with_browser(full_base_url)
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
        match_method = None
        match_detail = None
        
        url_pattern = lib_def.get("url_pattern")
        if url_pattern and not is_inline:
            try:
                url_match = re.search(url_pattern, js_url, re.IGNORECASE)
                if url_match:
                    matched = True
                    match_method = "url_pattern"
                    match_detail = url_match.group(0)[:120]
            except re.error:
                return None
        
        signatures = lib_def.get("signatures", [])
        if not matched and signatures:
            for signature in signatures:
                if signature.lower() in js_content.lower():
                    matched = True
                    match_method = "signature"
                    match_detail = signature
                    break

        inline_patterns = lib_def.get("inline_patterns", [])
        if is_inline and not matched and inline_patterns:
            for inline_pattern in inline_patterns:
                try:
                    inline_match = re.search(inline_pattern, js_content, re.IGNORECASE | re.MULTILINE)
                    if inline_match:
                        matched = True
                        match_method = "inline_pattern"
                        match_detail = inline_match.group(0)[:120]
                        break
                except re.error:
                    continue
        
        if not matched:
            return None

        version = self._detect_version(js_content, lib_def, js_url)

        # Large bundled assets are noisy for plain substring signatures.
        # Keep signature-only bundle matches only when a concrete version is found.
        if is_bundle and match_method == "signature" and not version:
            return None

        probability = lib_def.get("probability", 100)
        
        if is_bundle:
            probability = int(probability * 0.9)
        
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
            "probability": probability,
            "match_method": match_method,
            "match_detail": match_detail
        }

        if version:
            result["version"] = version

        return result

    def _analyze_with_browser(self, target_url):
        """
        Use Playwright to detect runtime JavaScript globals from Wappalyzer's js chains.
        """
        if not isinstance(self.browser_js_definitions, list) or not self.browser_js_definitions:
            return

        # Browser detection can fail in restricted environments; keep static detection unaffected.
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
                page.wait_for_timeout(1000)

                runtime_hits = page.evaluate(
                    """
                    (definitions) => {
                      const results = []
                      const normalizePath = (chain) => chain.replace(/\\[([^\\]]+)\\]/g, '.$1')

                      definitions.forEach((definition) => {
                        const productId = definition.product_id
                        const chains = definition.chains || []

                        chains.forEach((chainDef) => {
                          const chain = chainDef.chain
                          const methods = normalizePath(chain).split('.').filter(Boolean)
                          let value = window
                          let exists = true

                          for (const method of methods) {
                            if (
                              value &&
                              value instanceof Object &&
                              Object.prototype.hasOwnProperty.call(value, method)
                            ) {
                              const descriptor = Object.getOwnPropertyDescriptor(value, method) || {}
                              if (descriptor.get) {
                                exists = false
                                break
                              }
                              value = value[method]
                            } else {
                              exists = false
                              break
                            }
                          }

                          if (exists) {
                            let scalarValue = value
                            if (typeof scalarValue !== 'string' && typeof scalarValue !== 'number') {
                              scalarValue = String(!!scalarValue)
                            } else {
                              scalarValue = String(scalarValue)
                            }
                            results.push({
                              product_id: productId,
                              chain: chain,
                              value: scalarValue,
                              value_regex: chainDef.value_regex || '',
                              version_template: chainDef.version_template || '',
                              confidence: chainDef.confidence || 100
                            })
                          }
                        })
                      })

                      return results
                    }
                    """,
                    self.browser_js_definitions,
                )

                browser.close()
        except Exception:
            return

        for hit in runtime_hits:
            product_id = hit.get("product_id")
            if not product_id:
                continue

            product = self.product_manager.get_product_by_id(product_id)
            if not product:
                continue

            products = product.get("products", [])
            technology_name = products[0] if products else product.get("our_name", "Unknown")
            display_name = product.get("our_name", "Unknown")
            category = self.product_manager.get_category_name(product.get("category_id"))

            version = None
            value = str(hit.get("value", ""))
            value_regex = hit.get("value_regex") or ""
            version_template = hit.get("version_template") or ""
            confidence = hit.get("confidence", 100)

            # Match value exactly as Wappalyzer js patterns intend.
            if value_regex:
                try:
                    if not re.search(value_regex, value, re.IGNORECASE | re.MULTILINE):
                        continue
                except re.error:
                    continue

            version = self._resolve_wappalyzer_version(version_template, value_regex, value)

            result = {
                "product_id": product_id,
                "technology": technology_name,
                "display_name": display_name,
                "category": category,
                "url": f"browser:{hit.get('chain', '')}",
                "probability": confidence if isinstance(confidence, int) else 100,
                "match_method": "browser_js",
                "match_detail": f"chain={hit.get('chain', '')}, value={value[:80]}",
            }
            if version:
                result["version"] = version

            self._add_unique_detection(result)

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
                    if not self._is_version_context_valid(
                        product_id=product_id,
                        pattern=pattern,
                        content=search_content,
                        match_start=match.start(),
                        match_end=match.end(),
                    ):
                        continue

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
        product_id = result.get("product_id")
        
        # Check for existing detection of same technology
        for i, existing in enumerate(self.detected_libraries):
            if existing.get("product_id") == product_id:
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
                        if self._result_score(result) > self._result_score(existing):
                            self.detected_libraries[i] = result
                        return
                    else:
                        # Different versions for same product: prefer better scored result
                        # (probability, version specificity, source priority).
                        if self._result_score(result) > self._result_score(existing):
                            result["note"] = f"Alternative version seen: {existing.get('version')}"
                            self.detected_libraries[i] = result
                        else:
                            existing["note"] = f"Alternative version seen: {version}"
                        return
                # Neither has version, keep higher probability
                else:
                    if self._result_score(result) > self._result_score(existing):
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
                match_method = lib.get("match_method")
                match_detail = lib.get("match_detail")
                
                storage.add_to_storage(
                    technology=technology,
                    technology_type=category,\
                    vulnerability="PTV-WEB-INFO-TECNT",
                    probability=probability,
                    version=version if version else None,
                    product_id=product_id
                )


                if self.args.verbose:
                    ptprint(f"Source: {url}", "ADDITIONS", not self.args.json, indent=4, colortext=True)
                    if match_method:
                        detail = f" ({match_detail})" if match_detail else ""
                        ptprint(f"Match: {match_method}{detail}", "ADDITIONS", not self.args.json, indent=8, colortext=True)
                    if note:
                        ptprint(f"Note: {note}", "ADDITIONS", not self.args.json, indent=8, colortext=True)
                
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