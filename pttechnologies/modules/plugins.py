"""
PLUGINS - Plugin Detection Module (Enhanced Version Priority)

This module implements detection of plugins (primarily WordPress plugins)
by analyzing HTML content from the homepage. It extracts all URLs containing
'/plugins/' pattern, identifies plugin names, and attempts to detect versions
with proper priority: readme.txt > HTML comments > URL parameters.

Classes:
    PLUGINS: Main detector class.

Functions:
    run: Entry point to execute the detection.

Usage:
    PLUGINS(args, ptjsonlib, helpers, http_client, responses).run()

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

__TESTLABEL__ = "Test plugin detection"


class PLUGINS:
    """
    PLUGINS performs plugin detection and version identification.

    This class analyzes HTML content to find plugin references, extract
    plugin names, and detect versions with proper priority:
    1. readme.txt (most reliable)
    2. HTML comments
    3. URL parameters (least reliable)
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.product_manager = get_product_manager()

        self.response_hp = responses.resp_hp

        self.plugin_definitions = self.helpers.load_definitions("plugins.json")
        self.detected_plugins = {}

    def run(self):
        """
        Runs the plugin detection process.

        Uses a pre-fetched homepage response to find all plugin references,
        extract plugin names, and attempt version detection.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        base_url = self.args.url.rstrip("/")
        resp = self.response_hp
        html = resp.text

        plugin_urls = self._extract_plugin_urls(html, base_url)
        
        if self.args.verbose:
            ptprint(f"Found {len(plugin_urls)} plugin references", "ADDITIONS", not self.args.json, indent=4, colortext=True)

        for plugin_url in plugin_urls:
            self._analyze_plugin(plugin_url, base_url, html)

        self._report()

    def _extract_plugin_urls(self, html, base_url):
        """
        Extracts all URLs containing '/plugins/' pattern from HTML content.

        Args:
            html (str): HTML content of the page.
            base_url (str): Base URL for resolving relative links.

        Returns:
            set: Set of unique plugin URLs.
        """
        plugin_urls = set()
        
        soup = BeautifulSoup(html, "html.parser")
        
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc
        
        tags_attrs = [
            ("script", "src"),
            ("link", "href"),
            ("img", "src"),
            ("a", "href"),
            ("iframe", "src")
        ]
        
        for tag, attr in tags_attrs:
            for element in soup.find_all(tag):
                url = element.get(attr)
                if url and "/plugins/" in url:
                    abs_url = urljoin(base_url, url)
                    parsed_url = urlparse(abs_url)
                    
                    if parsed_url.netloc == base_domain or parsed_url.netloc == "":
                        plugin_urls.add(abs_url)
        
        inline_pattern = r'["\']([^"\']*?/plugins/[^"\']*?)["\']'
        matches = re.findall(inline_pattern, html)
        for match in matches:
            abs_url = urljoin(base_url, match)
            parsed_url = urlparse(abs_url)
            
            if parsed_url.netloc == base_domain or parsed_url.netloc == "":
                plugin_urls.add(abs_url)
        
        return plugin_urls

    def _analyze_plugin(self, plugin_url, base_url, html):
        """
        Analyzes a plugin URL to extract plugin name and detect version.
        
        Version detection priority:
        1. readme.txt (most reliable)
        2. HTML comments
        3. URL parameters (least reliable)

        Args:
            plugin_url (str): URL containing plugin reference.
            base_url (str): Base URL of the website.
            html (str): Full HTML content for pattern matching.
        """
        plugin_match = re.search(r'/plugins/([^/]+)', plugin_url)
        
        if not plugin_match:
            return
        
        plugin_name = plugin_match.group(1)
        
        if plugin_name in self.detected_plugins:
            return
        
        plugin_def = self._get_plugin_definition(plugin_name)
        
        version = None
        match_text = None
        version_source = None
        
        # PRIORITY 1: Check readme.txt first (most reliable)
        readme_result = self._get_version_from_readme(plugin_name, base_url, plugin_def)
        if readme_result:
            version, match_text = readme_result
            version_source = "readme.txt"

        # PRIORITY 2: Check HTML comments (reliable)
        if not version and plugin_def and "version_patterns" in plugin_def:
            result = self._extract_version_from_html(html, plugin_def)
            if result:
                version, match_text = result
                version_source = "HTML"

        # PRIORITY 3: Check URL (least reliable)
        if not version:
            version_in_url = self._extract_version_from_url(plugin_url)
            if version_in_url:
                version = version_in_url
                match_text = plugin_url
                version_source = "URL"
        
        # Get product_id from plugin definition
        product_id = None
        if plugin_def:
            product_id = plugin_def.get("product_id")
        
        # Get display_name from ProductManager if product_id exists
        display_name = plugin_name
        if product_id:
            product = self.product_manager.get_product_by_id(product_id)
            if product:
                display_name = product.get("our_name", plugin_name)
        
        self.detected_plugins[plugin_name] = {
            "name": plugin_name,
            "display_name": display_name,
            "product_id": product_id,
            "version": version,
            "url": plugin_url,
            "match_text": match_text,
            "version_source": version_source
        }

    def _get_plugin_definition(self, plugin_name):
        """
        Retrieves plugin definition from loaded definitions.

        Args:
            plugin_name (str): Name of the plugin.

        Returns:
            dict or None: Plugin definition if found, otherwise None.
        """
        for plugin_def in self.plugin_definitions:
            if plugin_def["name"] == plugin_name:
                return plugin_def
            
            url_patterns = plugin_def.get("url_patterns", [])
            if plugin_name in url_patterns:
                return plugin_def
        
        return None

    def _extract_version_from_html(self, html, plugin_def):
        """
        Extracts version from HTML content using regex patterns from plugin definition.

        Args:
            html (str): Full HTML content.
            plugin_def (dict): Plugin definition containing version_patterns.

        Returns:
            tuple or None: (version_string, matched_text) if found, otherwise None.
        """
        version_patterns = plugin_def.get("version_patterns", [])
        
        for pattern_def in version_patterns:
            pattern_type = pattern_def.get("type", "html_comment")
            regex = pattern_def.get("regex")
            
            if not regex:
                continue
            
            try:
                compiled_regex = re.compile(regex, re.IGNORECASE)
                match = compiled_regex.search(html)
                
                if match:
                    version = match.group(1)
                    match_start = match.start()
                    match_end = match.end()
                    
                    if pattern_type == "html_comment":
                        comment_start = html.rfind("<!--", max(0, match_start - 200), match_start)
                        comment_end = html.find("-->", match_end, min(len(html), match_end + 200))
                        
                        if comment_start != -1 and comment_end != -1:
                            matched_text = html[comment_start:comment_end + 3].strip()
                        else:
                            matched_text = match.group(0)
                    else:
                        matched_text = match.group(0)
                    
                    return (version, matched_text)
            except re.error as e:
                if self.args.verbose:
                    ptprint(f"Invalid regex pattern: {regex} - {e}", "ERROR", not self.args.json, indent=8)
                continue
        
        return None

    def _extract_version_from_url(self, url):
        """
        Attempts to extract version number from URL.

        Args:
            url (str): Plugin URL.

        Returns:
            str or None: Version string if found, otherwise None.
        """
        # Common version patterns in URLs:
        # - /plugin-name/1.2.3/
        # - /plugin-name.1.2.3.js
        # - /plugin-name-1.2.3/
        # - ?ver=1.2.3
        
        ver_param = re.search(r'[?&]ver=([0-9]+\.[0-9]+(?:\.[0-9]+)*?)(?:[&\s]|$)', url)
        if ver_param:
            return ver_param.group(1)
        
        version_patterns = [
            r'/([0-9]+\.[0-9]+(?:\.[0-9]+)*?)/',
            r'\.([0-9]+\.[0-9]+(?:\.[0-9]+)*?)\.(?:js|css|min\.js|min\.css)',
            r'-([0-9]+\.[0-9]+(?:\.[0-9]+)*?)/',
            r'-([0-9]+\.[0-9]+(?:\.[0-9]+)*?)\.(?:js|css|min\.js|min\.css)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        
        return None

    def _get_version_from_readme(self, plugin_name, base_url, plugin_def=None):
        """
        Attempts to fetch and parse readme.txt file for version.

        Args:
            plugin_name (str): Name of the plugin.
            base_url (str): Base URL of the website.
            plugin_def (dict): Plugin definition with custom readme paths.

        Returns:
            tuple or None: (version, readme_url) if found, otherwise None.
        """
        readme_paths = []
        
        if plugin_def and "readme_paths" in plugin_def:
            readme_paths.extend(plugin_def["readme_paths"])
        
        readme_paths.extend([
            f"/wp-content/plugins/{plugin_name}/readme.txt",
            f"/plugins/{plugin_name}/readme.txt",
            f"/wp-content/plugins/{plugin_name}/README.txt",
            f"/plugins/{plugin_name}/README.txt"
        ])
        
        seen = set()
        unique_paths = []
        for path in readme_paths:
            if path not in seen:
                seen.add(path)
                unique_paths.append(path)
        
        for path in unique_paths:
            readme_url = urljoin(base_url, path)
            
            resp = self.helpers.fetch(readme_url, allow_redirects=True)
            
            if resp and resp.status_code == 200:
                version = self._parse_readme_version(resp.text)
                if version:
                    return (version, readme_url)
        
        return None

    def _parse_readme_version(self, readme_content):
        """
        Parses readme.txt content to extract version information.

        Args:
            readme_content (str): Content of readme.txt file.

        Returns:
            str or None: Version string if found, otherwise None.
        """
        # Common patterns in WordPress readme.txt files:
        # Stable tag: 1.2.3
        # Version: 1.2.3
        
        patterns = [
            r'Stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)*)',
            r'Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)*)',
            r'stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)*)',
            r'version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)*)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, readme_content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None

    def _report(self):
        """
        Reports all detected plugins via ptjsonlib and prints output.
        """
        if self.detected_plugins:
            for plugin_name, plugin_info in self.detected_plugins.items():
                display_name = plugin_info.get("display_name", plugin_name)
                product_id = plugin_info.get("product_id")
                version = plugin_info.get("version")
                url = plugin_info.get("url")
                match_text = plugin_info.get("match_text")
                version_source = plugin_info.get("version_source")
                
                probability = 100
                
                # Get category from ProductManager if product_id exists
                if product_id:
                    product = self.product_manager.get_product_by_id(product_id)
                    if product:
                        category_name = self.product_manager.get_category_name(product.get("category_id"))
                    else:
                        category_name = "Plugin"
                else:
                    category_name = "Plugin"
                
                storage.add_to_storage(
                    technology=display_name,
                    technology_type=category_name,
                    vulnerability="PTV-WEB-INFO-PLUGIN",
                    probability=probability,
                    version=version if version else None,
                    product_id=product_id
                )
                
                if self.args.verbose:
                    match_to_print = match_text if match_text else url
                    ptprint(f"Match: {match_to_print}", "ADDITIONS", not self.args.json, indent=4, colortext=True)
                    
                    if version and version_source:
                        ptprint(f"Version found in {version_source}: {version}", 
                               "ADDITIONS", not self.args.json, indent=4, colortext=True)

                if version:
                    ptprint(f"Identified plugin: {display_name} {version}", "VULN", 
                           not self.args.json, indent=4, end=" ")
                else:
                    ptprint(f"Identified plugin: {display_name}", "VULN", 
                           not self.args.json, indent=4, end=" ")
                
                ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True)
        else:
            ptprint("It was not possible to identify any plugins", "INFO", 
                   not self.args.json, indent=4)


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point for running the PLUGINS detection."""
    PLUGINS(args, ptjsonlib, helpers, http_client, responses).run()
