"""
DEFPAGE - Default Server Welcome Page Detection Module

This module analyzes default welcome pages served by web servers when accessing
IP addresses directly. Different web servers and operating systems have distinct
default pages that can reveal technology information.

The module tests both HTTP and HTTPS protocols, as servers may be configured
differently for each protocol. It uses regular expressions to identify technologies
and versions from the content of default pages.

Includes:
- DEFPAGE class to perform default page analysis and classification.
- run() function as an entry point to execute the test.

Usage:
    DEFPAGE(args, ptjsonlib, helpers, http_client, responses).run()
"""

import re
import socket
import ssl
from urllib.parse import urlparse
from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager

from typing import List, Dict, Any, Optional, Tuple
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Test default server welcome pages for technology identification"


class DEFPAGE:
    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        """Initialize the DEFPAGE test with provided components and load page definitions."""
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.product_manager = get_product_manager()

        self.http_resp = responses.http_resp
        self.https_resp = responses.https_resp

        self.definitions = self.helpers.load_definitions("defpage.json")
        self.target_ip = self._extract_ip_from_url(args.url)
        self.detected_technologies = []
        self.default_page_reachable = False

    def _extract_ip_from_url(self, url: str) -> Optional[str]:
        """
        Extract IP address from URL or resolve hostname to IP.
        
        Args:
            url: Target URL
            
        Returns:
            IP address string or None if unable to resolve
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc.split(':')[0]
        
        try:
            socket.inet_aton(hostname)
            return hostname
        except socket.error:
            pass
        
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def _test_invalid_host_header(self, protocol: str) -> Optional[object]:
        """
        Test server response with invalid Host header.
        
        Tests if server returns the same page when accessing with invalid Host header.
        
        Args:
            protocol: 'http' or 'https'
            
        Returns:
            Response object or None if request failed
        """
        base_url = f"{protocol}://{self.target_ip}"
        
        try:            
            response = self.helpers._raw_request(base_url, "/", extra_headers={"Host": "%"})
            
            if response:                
                return response
            
        except Exception as e:
            return None
        return None

    def _compare_responses(self, resp1: object, resp2: object, protocol: str) -> Dict[str, Any]:
        """
        Compare two responses to check if they are the same.
        
        Args:
            resp1: First response object (IP access)
            resp2: Second response object (invalid Host header)
            protocol: Protocol used
            
        Returns:
            Dictionary with comparison results
        """
        result = {
            'same_status': False,
            'same_content': False,
            'responses_match': False,
            'status1': None,
            'status2': None
            }
        
        if not resp1 or not resp2:
            return result
        
        status1 = getattr(resp1, 'status', None) or getattr(resp1, 'status_code', None)
        status2 = getattr(resp2, 'status', None) or getattr(resp2, 'status_code', None)
        
        result['status1'] = status1
        result['status2'] = status2
        result['same_status'] = (status1 == status2)
        
        content1 = getattr(resp1, 'text', '') or ''
        content2 = getattr(resp2, 'text', '') or ''
        
        if content1 and content2:
            result['same_content'] = (content1 == content2)
        
        result['responses_match'] = result['same_status'] and result['same_content']
        return result

    def run(self) -> None:
        """
        Execute the DEFPAGE test logic.
        
        Tests both HTTP and HTTPS protocols on the target IP address,
        retrieves default pages, and analyzes them for technology signatures.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        if self.args.verbose:
            ptprint(f"Testing default pages on IP: {self.target_ip}", "ADDITIONS", not self.args.json, indent=4, colortext=True)

        protocols = ['http', 'https']
        
        for protocol in protocols:
            self._test_protocol(protocol)

        self._report_findings()

    def _test_protocol(self, protocol: str) -> None:
        """
        Test default page for a specific protocol.
        
        Args:
            protocol: 'http' or 'https'
        """

        url = f"{protocol}://{self.target_ip}/"
        
        if self.args.verbose:
            ptprint(f"Testing {protocol.upper()} protocol", "ADDITIONS", not self.args.json, indent=4, colortext=True)
        
        if protocol == 'http':
            response = self.http_resp
        else:
            response = self.https_resp
        
        if response is None:
            if self.args.verbose:
                ptprint("No response received", "ADDITIONS", not self.args.json, indent=8, colortext=True)
            return
        
        if not hasattr(response, 'text'):
            if self.args.verbose:
                ptprint(f"Response object has no text attribute for {protocol.upper()}", "ADDITIONS", not self.args.json, indent=8, colortext=True)
            return
            
        content = response.text
        status_code = getattr(response, 'status_code', 0)

        if status_code == 200 or status_code == 403:
            if self.args.verbose:
                self._debug_output(content, protocol, response, url)

            self.default_page_reachable = True
            
            invalid_host_response = self._test_invalid_host_header(protocol)
            
            if invalid_host_response:
                invalid_status_code = getattr(invalid_host_response, 'status', 0) or getattr(invalid_host_response, 'status_code', 0)
                
                if invalid_status_code == 200 or invalid_status_code == 403:
                    comparison = self._compare_responses(response, invalid_host_response, protocol)
                                        
                    # If responses are different, analyze both
                    if not comparison['responses_match']:
                        if self.args.verbose:
                            ptprint("Responses differ - analyzing both pages", "ADDITIONS", not self.args.json, indent=8, colortext=True)
                        
                        technologies = self._analyze_page_content(content, protocol, response)
                        self._process_detected_technologies(technologies, protocol, url, "IP access")
                        
                        invalid_content = getattr(invalid_host_response, 'text', '')
                        if invalid_content:
                            invalid_technologies = self._analyze_page_content(invalid_content, protocol, invalid_host_response)
                            self._process_detected_technologies(invalid_technologies, protocol, url, "invalid Host header")
                    else:
                        if self.args.verbose:
                            ptprint("Responses match - analyzing once", "ADDITIONS", not self.args.json, indent=8, colortext=True)
                        
                        #If responses are the same, analyze once
                        technologies = self._analyze_page_content(content, protocol, response)
                        self._process_detected_technologies(technologies, protocol, url, "both methods")
                else:
                    #If Invalid Host response has different status code, analyze only original
                    if self.args.verbose:
                        ptprint(f"Invalid Host header returned HTTP {invalid_status_code} - skipping analysis", "ADDITIONS", not self.args.json, indent=8, colortext=True)
                    
                    technologies = self._analyze_page_content(content, protocol, response)
                    self._process_detected_technologies(technologies, protocol, url, "IP access")
            else:
                technologies = self._analyze_page_content(content, protocol, response)
                self._process_detected_technologies(technologies, protocol, url, "IP access")
                
        else:
            if self.args.verbose:
                ptprint(f"Default page of server is not reachable (HTTP {status_code})", "ADDITIONS", not self.args.json, indent=8, colortext=True)

    def _process_detected_technologies(self, technologies: List[Dict[str, Any]], protocol: str, url: str, access_method: str) -> None:
        """
        Process and report detected technologies.
        
        Args:
            technologies: List of detected technologies
            protocol: Protocol used
            url: URL tested
            access_method: How the page was accessed (e.g., "IP access", "invalid Host header")
        """
        if technologies:
            if self.args.verbose:
                ptprint(f"Technologies detected ({access_method}):", "ADDITIONS", not self.args.json, indent=8, colortext=True)

            for tech in technologies:
                tech['protocol'] = protocol
                tech['url'] = url
                tech['access_method'] = access_method
                self.detected_technologies.append(tech)
                
                version_text = f" {tech['version']}" if tech.get('version') else ""
                category_text = f" ({tech['category']})"
                
                if self.args.verbose:
                    ptprint(f"{tech['technology']}{version_text}{category_text}", 
                    "ADDITIONS", not self.args.json, indent=12, colortext=True, end="")

                    source_location = tech.get('source_location', 'content')
                    ptprint(f" <- Matched: {tech.get('matched_text', 'N/A')}", 
                        "ADDITIONS", not self.args.json, colortext=True)
        else:
            if self.args.verbose:
                ptprint(f"No technologies detected ({access_method})", "ADDITIONS", not self.args.json, indent=8, colortext=True)

    def _debug_output(self, content: str, protocol: str, response: object, url: str) -> None:
        """
        Debug output shown when the -vv flag is used.

        Args:
            content: HTML content of the page.
            protocol: Protocol used (e.g., HTTP, HTTPS).
            response: Response object returned by the request.
            url: Requested URL address.
        """

        title = self._extract_title(content)
        if title:
            ptprint(f"HTML Title: {title}", "ADDITIONS", not self.args.json, indent=8, colortext=True)
        else:
            ptprint("HTML Title: Not found or empty", "ADDITIONS", not self.args.json, indent=8, colortext=True)
                
        method_info = self._determine_method(response, content, url)
        ptprint(f"Method: {method_info}", "ADDITIONS", not self.args.json, indent=8, colortext=True)
        
        ptprint("", "", not self.args.json)

    def _extract_title(self, content: str) -> Optional[str]:
        """
        Extracts the contents of the HTML <title> element.

        Args:
            content: HTML content.

        Returns:
            The title text or None if not found.
        """
        
        title_pattern = r'<title[^>]*>(.*?)</title>'
        match = re.search(title_pattern, content, re.IGNORECASE | re.DOTALL)
        
        if match:
            title = match.group(1).strip()
            title = re.sub(r'<[^>]+>', '', title)
            title = re.sub(r'\s+', ' ', title)
            return title if title else None
        
        return None

    def _determine_method(self, response: object, content: str, url: str) -> str:
        """
        Determines how the default page was delivered.

        Args:
            response: Response object.
            content: HTML content.
            url: Requested URL.

        Returns:
            Human-readable description of the delivery method.
        """
        status_code = getattr(response, 'status_code', 0)
        
        if hasattr(response, 'history') and response.history:
            return f"HTTP Redirect (final status: {status_code})"
        
        if status_code == 200:
            if self._is_index_page(content):
                return "Default index page (200) (GET method)"
            elif self._is_server_generated(content):
                return "Server-generated default page (200) (GET method)"
            else:
                return "Static default page (200) (GET method)"
        elif status_code == 403:
            return "Access forbidden - directory listing disabled (403)(GET method)"
        elif status_code == 404:
            return "Not found - custom 404 page (GET method)"
        elif status_code in [301, 302, 303, 307, 308]:
            return f"HTTP Redirect ({status_code}) (GET method)"
        else:
            return f"HTTP {status_code} response (GET method)"

    def _is_index_page(self, content: str) -> bool:
        """Checks whether the content looks like a typical index page."""
        index_indicators = [
            r'index\.html?',
            r'welcome\s+to',
            r'default\s+page',
            r'home\s+page',
            r'directory\s+listing'
        ]
        
        for pattern in index_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _is_server_generated(self, content: str) -> bool:
        """Checks whether the page appears to be server-generated."""
        server_indicators = [
            r'apache.*server',
            r'nginx.*server',
            r'iis.*server',
            r'server\s+information',
            r'web\s+server\s+is\s+running'
        ]
        
        for pattern in server_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _analyze_page_content(self, content: str, protocol: str, response: object = None) -> List[Dict[str, Any]]:
        """
        Analyze page content and headers against known default page patterns.
        
        Args:
            content: HTML content of the page
            protocol: Protocol used ('http' or 'https')
            response: HTTP response object containing headers
            
        Returns:
            List of detected technologies (deduplicated by technology name)
        """
        detected = []
        seen_technologies = set()
        
        if not self.definitions:
            return detected

        patterns = self.definitions.get('patterns', [])
        
        headers_dict = {}
        if response and hasattr(response, 'headers'):
            headers_dict = dict(response.headers)
        
        for pattern_def in patterns:
            match_result = self._match_pattern(content, pattern_def, 'content')
            
            if match_result:
                tech_key = match_result.get('technology', match_result.get('name', 'Unknown')).lower()
                
                if tech_key not in seen_technologies:
                    # Call submodule if specified in pattern definition
                    if pattern_def.get("submodule"):
                        match_result = self._call_submodule(match_result, pattern_def["submodule"], response, content)
                    
                    # Determine version range based on technology
                    match_result = self._determine_version_range(match_result, content)
                    
                    detected.append(match_result)
                    seen_technologies.add(tech_key)
        
        return detected

    def _match_pattern(self, content: str, pattern_def: Dict[str, Any], source_type: str = 'content') -> Optional[Dict[str, Any]]:
        """
        Match content against a specific pattern definition.
        
        Args:
            content: Page content to analyze
            pattern_def: Pattern definition from JSON
            source_type: 'content' or 'headers'
            
        Returns:
            Technology information if matched, None otherwise
        """
        pattern = pattern_def.get('pattern', '')
        if not pattern:
            return None
            
        flags = pattern_def.get('flags', 'i')
        
        re_flags = 0
        if 'i' in flags.lower():
            re_flags |= re.IGNORECASE
        if 'm' in flags.lower():
            re_flags |= re.MULTILINE
        if 's' in flags.lower():
            re_flags |= re.DOTALL
        
        try:
            match = re.search(pattern, content, re_flags)
        except re.error as e:
            return None
        
        if not match:
            return None
        
        # Get product information from product_id
        product_id = pattern_def.get('product_id')
        if product_id:
            product = self.product_manager.get_product_by_id(product_id)
            if product:
                technology_name = product.get('our_name', 'Unknown')
                category_id = product.get('category_id')
                category = self.product_manager.get_category_by_id(category_id)
                category_name = category.get('name', 'Other') if category else 'Other'
            else:
                # Fallback if product not found
                technology_name = pattern_def.get('name', 'Unknown')
                category_name = 'Other'
        else:
            # Backward compatibility with old format
            technology_name = pattern_def.get('technology', pattern_def.get('name', 'Unknown'))
            category_name = pattern_def.get('category', 'Other')
            
        result = {
            'name': pattern_def.get('name', 'Unknown'),
            'category': category_name,
            'technology': technology_name,
            'product_id': product_id,
            'version': None,
            'matched_text': match.group(0)[:100] + ('...' if len(match.group(0)) > 100 else ''),
            'source_location': source_type
        }
        
        version = None
        version_pattern = pattern_def.get('version_pattern')
        if version_pattern:
            try:
                version_match = re.search(version_pattern, content, re_flags)
                if version_match:
                    version = version_match.group(1) if version_match.groups() else version_match.group(0)
            except re.error:
                pass
        elif match.groups():
            version = match.group(1)
        
        if version:
            version_transform = pattern_def.get('version_transform')
            if version_transform == 'iis_legacy':
                version = self._transform_iis_legacy_version(version)
            
            result['version'] = version
        
        return result

    def _determine_version_range(self, tech_info: Dict[str, Any], content: str) -> Dict[str, Any]:
        """
        Determine version range for detected technology based on structural characteristics.
        Uses rules defined in JSON configuration file.
        
        Args:
            tech_info: Technology information dictionary
            content: Page content
            
        Returns:
            Enhanced technology information with version range
        """
        technology = tech_info.get('technology', '').lower()
        
        version_detection = self.definitions.get('version_detection', {})
        
        matched_tech_key = None
        for tech_key, tech_data in version_detection.items():
            aliases = tech_data.get('technology_aliases', [])
            for alias in aliases:
                if alias.lower() in technology:
                    matched_tech_key = tech_key
                    break
            if matched_tech_key:
                break
        
        if not matched_tech_key:
            return tech_info
        
        return self._apply_version_rules(tech_info, content, version_detection[matched_tech_key])

    def _apply_version_rules(self, tech_info: Dict[str, Any], content: str, rules: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply version detection rules from JSON configuration.
        
        Args:
            tech_info: Technology information dictionary
            content: Page content
            rules: Version detection rules for specific technology
            
        Returns:
            Enhanced technology information with version range
        """
        # Use product_id from version_detection rules if available
        if 'product_id' in rules and 'product_id' not in tech_info:
            tech_info['product_id'] = rules['product_id']
        
        ranges = rules.get('ranges', [])
        best_match = None
        best_score = 0
        best_confidence = 'low'
        
        for range_def in ranges:
            indicators = range_def.get('indicators', [])
            required_matches = range_def.get('required_matches', 1)
            specific_indicator = range_def.get('specific_indicator')
            confidence = range_def.get('confidence', 'low')
            
            score = 0
            for pattern in indicators:
                try:
                    if re.search(pattern, content, re.I | re.S):
                        score += 1
                except re.error as e:
                    if self.args.verbose:
                        ptprint(f"Invalid regex pattern in version detection: {pattern} - {e}", 
                            "INFO", not self.args.json, indent=8)
                    continue
            
            specific_ok = True
            if specific_indicator:
                try:
                    specific_ok = bool(re.search(specific_indicator, content, re.I | re.S))
                except re.error as e:
                    if self.args.verbose:
                        ptprint(f"Invalid specific indicator regex: {specific_indicator} - {e}", 
                            "INFO", not self.args.json, indent=8)
                    specific_ok = False
            
            if score >= required_matches and specific_ok:
                if score > best_score or (score == best_score and self._compare_confidence(confidence, best_confidence) > 0):
                    best_score = score
                    best_match = range_def
                    best_confidence = confidence
        
        if best_match:
            version_range_info = {
                'min_version': best_match.get('min_version'),
                'max_version': best_match.get('max_version'),
                'confidence': best_confidence
            }
            
            tech_info['version_range'] = version_range_info
        
        return tech_info

    def _compare_confidence(self, conf1: str, conf2: str) -> int:
        """
        Compare two confidence levels.
        
        Args:
            conf1: First confidence level ('low', 'medium', 'high')
            conf2: Second confidence level ('low', 'medium', 'high')
            
        Returns:
            1 if conf1 > conf2, -1 if conf1 < conf2, 0 if equal
        """
        confidence_order = {'low': 0, 'medium': 1, 'high': 2}
        level1 = confidence_order.get(conf1.lower(), 0)
        level2 = confidence_order.get(conf2.lower(), 0)
        
        if level1 > level2:
            return 1
        elif level1 < level2:
            return -1
        else:
            return 0


    def _format_version_range(self, min_version: Optional[str], max_version: Optional[str]) -> str:
        """
        Format version range for display.
        
        Args:
            min_version: Minimum version
            max_version: Maximum version
            
        Returns:
            Formatted version range string
        """
        if min_version and max_version:
            return f"{min_version} - {max_version}"
        elif min_version:
            return f"{min_version}+"
        elif max_version:
            return f"< {max_version}"
        else:
            return "unknown"

    def _call_submodule(self, tech_info: Dict[str, Any], submodule_name: str, response: object, content: str) -> Dict[str, Any]:
        """
        Calls specified submodule for enhanced technology detection.

        Args:
            tech_info (dict): Technology information dictionary.
            submodule_name (str): Name of the submodule to call.
            response (object): HTTP response object.
            content (str): Page content.

        Returns:
            dict: Enhanced technology information.
        """
        try:
            submodule = __import__(f"modules.submodules.{submodule_name}", fromlist=[submodule_name])
            
            if hasattr(submodule, "analyze"):
                enhanced_tech_info = tech_info.copy()
                enhanced_tech_info['response'] = response
                enhanced_tech_info['content'] = content
                
                enhanced_info = submodule.analyze(enhanced_tech_info, self.args, self.helpers)
                tech_info.update(enhanced_info)
                                    
        except ImportError as e:
            if self.args.verbose:
                ptprint(f"Submodule {submodule_name} not found: {str(e)}", "ADDITIONS", not self.args.json, indent=8, colortext=True)
        except Exception as e:
            if self.args.verbose:
                ptprint(f"Error in submodule {submodule_name}: {str(e)}", "ADDITIONS", not self.args.json, indent=8, colortext=True)
        
        return tech_info

    def _transform_iis_legacy_version(self, version: str) -> str:
        """
        Transform IIS legacy version format (e.g., '85' -> '8.5', '75' -> '7.5').
        
        Args:
            version: Original version string
            
        Returns:
            Transformed version string
        """
        if version.isdigit() and len(version) == 2:
            num = int(version)
            if 19 <= num <= 99:
                return f"{version[0]}.{version[1]}"
        
        return version

    def _report_findings(self) -> None:
        """
        Report summary of all detected technologies and store them (avoiding duplicates).
        """
        if not self.detected_technologies:
            if self.default_page_reachable:
                ptprint("No default page technologies identified", "INFO", not self.args.json, indent=4)
            else:
                ptprint("Default page of server is not reachable", "INFO", not self.args.json, indent=4)
            return
        
        tech_summary = {}
        for tech in self.detected_technologies:
            tech_name = tech.get('technology', 'Unknown')
            version = tech.get('version', '')
            protocol = tech.get('protocol', 'unknown')
            probability = tech.get('probability', 100)
            
            key = f"{tech_name}_{version}" if version else tech_name
            
            if key not in tech_summary:
                tech_summary[key] = {
                    'name': tech_name,
                    'version': version,
                    'category': tech.get('category', 'unknown'),
                    'protocols': [],
                    'source_locations': set(),
                    'additional_info': tech.get('additional_info', []),
                    'version_range': tech.get('version_range', {}),
                    'product_id': tech.get('product_id')
                }
            
            tech_summary[key]['protocols'].append(protocol.upper())
            tech_summary[key]['source_locations'].add(tech.get('source_location', 'content'))
            
            # Merge additional_info from submodules
            if tech.get('additional_info'):
                existing_info = tech_summary[key]['additional_info']
                for info in tech['additional_info']:
                    if info not in existing_info:
                        existing_info.append(info)
         
        for tech_info in tech_summary.values():
            protocols_text = "/".join(sorted(set(tech_info['protocols'])))
            category_text = f" ({tech_info['category']})"
            
            ptprint(f"{tech_info['name']}{category_text}", "VULN", not self.args.json, indent=4, end=" ")
            ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True)

            if tech_info['version']:
                ptprint(f"Version: {tech_info['version']}", "INFO", not self.args.json, indent=12)
            elif tech_info.get('version_range'):
                version_range = tech_info['version_range']
                range_text = self._format_version_range(
                    version_range.get('min_version'),
                    version_range.get('max_version')
                )
                ptprint(f"Version range: {range_text}", "INFO", not self.args.json, indent=8)
            
                
            # Report additional info from submodules and version ranges
            if tech_info.get("additional_info"):
                for info in tech_info["additional_info"]:
                    ptprint(f"{info}", "VULN", not self.args.json, indent=8)

        for tech_info in tech_summary.values():
            self._store_unique_technology(tech_info)

    def _store_unique_technology(self, tech_info: Dict[str, Any]) -> None:
        """
        Store detected technology in the storage system (once per unique technology).
        
        Args:
            tech_info: Aggregated technology information from all protocols
        """
        tech_name = tech_info['name']
        version = tech_info['version']
        tech_type = tech_info['category']
        probability = 100
        product_id = tech_info.get('product_id')

        version_range = tech_info.get('version_range', {})
        if version_range:
            version_min = version_range.get('min_version')
            version_max = version_range.get('max_version')
        else:
            version_min = None
            version_max = None
        
        # Get product info for vendor and CVE details URL
        vendor = None
        cve_details_url = None
        if product_id:
            product = self.product_manager.get_product_by_id(product_id)
            if product:
                vendor = product.get('vendor')
                cve_details_url = product.get('cve_details_url')
            
        protocols_text = "/".join(sorted(set(tech_info['protocols'])))
        source_locations = sorted(tech_info['source_locations'])
        
        description = f"Default {protocols_text} page: {tech_name}"
        if version:
            description += f" {version}"
        
        version_range = tech_info.get('version_range', {})
        if version_range.get('min_version') or version_range.get('max_version'):
            range_text = self._format_version_range(
                version_range.get('min_version'),
                version_range.get('max_version')
            )
            description += f" (range: {range_text})"
        
        description += f" (detected from {', '.join(source_locations)})"
        
        storage.add_to_storage(
            technology=tech_name,
            version=version if version else None,
            version_min=version_min,
            version_max=version_max,
            technology_type=tech_type,
            probability=probability,
            description=description,
            product_id=product_id,
            vendor=vendor,
            cve_details_url=cve_details_url
        )


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the DEFPAGE test."""
    DEFPAGE(args, ptjsonlib, helpers, http_client, responses).run()