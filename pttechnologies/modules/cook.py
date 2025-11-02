"""
Module for identifying technologies from HTTP cookies.

Analyzes Set-Cookie headers to detect web technologies, frameworks,
and platforms based on cookie names and values using predefined patterns.
"""

import re
from ptlibs.ptprinthelper import ptprint
from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager

__TESTLABEL__ = "Test for cookie-based technology identification"


class COOK:
    """
    Cookie analyzer for technology detection.
    
    Processes Set-Cookie headers to identify web technologies, frameworks,
    programming languages, and platforms based on cookie name and value patterns.
    """
    
    def __init__(self, args, ptjsonlib, helpers, http_client, responses: StoredResponses):
        """
        Initialize the cookie analyzer.
        
        Args:
            args: Command line arguments and configuration settings.
            ptjsonlib: JSON processing library instance.
            helpers: Helper utilities for loading configuration files.
            http_client: HTTP client instance.
            responses: Container with pre-fetched responses.
        """
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.product_manager = get_product_manager()
        
        self.response_hp = responses.resp_hp
        self.response_404 = responses.resp_404
        self.raw_response_400 = responses.raw_resp_400
        
        self.definitions = self.helpers.load_definitions("cook.json")
        self.detected_technologies = set()
    
    def run(self):
        """
        Main entry point for cookie analysis.
        
        Extracts cookies from all available responses and analyzes them
        for technology identification patterns.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        
        all_cookies = self._collect_all_cookies()
        
        if not all_cookies:
            ptprint("No cookies found in responses", "INFO", not self.args.json, indent=4)
            return
        
        #if self.args.verbose:
        #    ptprint(f"Found {len(all_cookies)} unique cookies to analyze", "INFO", not self.args.json, indent=4)
        
        technologies_found = self._analyze_cookies(all_cookies)
        
        if not technologies_found:
            ptprint("No technologies identified from cookies", "INFO", not self.args.json, indent=4)
    
    def _collect_all_cookies(self):
        """
        Collect all cookies from available responses.
        
        Returns:
            dict: Dictionary of cookie names to their values and raw headers.
        """
        all_cookies = {}
        
        if self.response_hp:
            cookies = self._extract_cookies_from_response(self.response_hp)
            all_cookies.update(cookies)
        
        if self.response_404:
            cookies = self._extract_cookies_from_response(self.response_404)
            all_cookies.update(cookies)
        
        if self.raw_response_400:
            cookies = self._extract_cookies_from_raw_response(self.raw_response_400)
            all_cookies.update(cookies)
        
        return all_cookies
    
    def _extract_cookies_from_response(self, response):
        """
        Extract cookies from a standard response object.
        
        Args:
            response: HTTP response object with headers.
            
        Returns:
            dict: Dictionary of cookie names to their values and raw headers.
        """
        cookies = {}
        
        if not response or not hasattr(response, 'headers'):
            return cookies
        
        set_cookie_headers = []
        
        if hasattr(response, 'raw') and hasattr(response.raw, 'headers'):
            for header_name, header_value in response.raw.headers.items():
                if header_name.lower() == 'set-cookie':
                    set_cookie_headers.append(header_value)

        elif hasattr(response, 'headers'):
            for header_name, header_value in response.headers.items():
                if header_name.lower() == 'set-cookie':
                    if isinstance(header_value, list):
                        set_cookie_headers.extend(header_value)
                    else:
                        set_cookie_headers.append(header_value)
        
        for cookie_header in set_cookie_headers:
            parsed = self._parse_cookie_header(cookie_header)
            cookies.update(parsed)
        
        if hasattr(response, 'cookies'):
            for cookie in response.cookies:
                if cookie.name not in cookies:
                    cookies[cookie.name] = {
                        'value': cookie.value,
                        'raw': f"{cookie.name}={cookie.value}"
                    }
        
        return cookies
    
    def _extract_cookies_from_raw_response(self, raw_response):
        """
        Extract cookies from a raw response object.
        
        Args:
            raw_response: Raw HTTP response object.
            
        Returns:
            dict: Dictionary of cookie names to their values.
        """
        cookies = {}
        
        if not raw_response:
            return cookies
        
        if hasattr(raw_response, 'headers'):
            headers = raw_response.headers
        elif hasattr(raw_response, 'raw') and hasattr(raw_response.raw, 'headers'):
            headers = raw_response.raw.headers
        else:
            return cookies
        
        for header_name, header_value in headers.items():
            if header_name.lower() == 'set-cookie':
                parsed = self._parse_cookie_header(header_value)
                cookies.update(parsed)
        
        return cookies
    
    def _parse_cookie_header(self, cookie_header):
        """
        Parse a Set-Cookie header string.
        
        Args:
            cookie_header: Raw Set-Cookie header value.
            
        Returns:
            dict: Parsed cookie information.
        """
        cookies = {}
        
        if '=' in cookie_header:
            parts = cookie_header.split(';')[0].split('=', 1)
            if len(parts) == 2:
                name = parts[0].strip()
                value = parts[1].strip()
                cookies[name] = {
                    'value': value,
                    'raw': cookie_header
                }
        
        return cookies
    
    def _analyze_cookies(self, cookies):
        """
        Analyze cookies against defined patterns.
        
        Args:
            cookies: Dictionary of cookie names to their information.
            
        Returns:
            int: Number of technologies found.
        """
        technologies_found = 0
        
        for cookie_name, cookie_info in cookies.items():
            cookie_value = cookie_info.get('value', '')
            
            for pattern in self.definitions:
                if self._match_cookie_pattern(cookie_name, cookie_value, pattern):
                    self._process_match(cookie_name, cookie_value, pattern, cookie_info)
                    technologies_found += 1
                    break
        
        return technologies_found
    
    def _match_cookie_pattern(self, cookie_name, cookie_value, pattern):
        """
        Check if a cookie matches a pattern definition.
        
        Args:
            cookie_name: Name of the cookie.
            cookie_value: Value of the cookie.
            pattern: Pattern definition dictionary.
            
        Returns:
            bool: True if the cookie matches the pattern.
        """
        name_regex = pattern.get("name_regex")
        if name_regex:
            if not re.match(name_regex, cookie_name, re.IGNORECASE):
                return False
        
        value_regex = pattern.get("value_regex")
        if value_regex and cookie_value:
            if not re.match(value_regex, cookie_value, re.IGNORECASE):
                return False
        
        return True
    
    def _process_match(self, cookie_name, cookie_value, pattern, cookie_info):
        """
        Process a successful pattern match and store results.
        
        Args:
            cookie_name: Name of the cookie that matched.
            cookie_value: Value of the cookie.
            pattern: Pattern definition that matched.
            cookie_info: Full cookie information.
        """
        # Get product info from product_id
        product_id = pattern.get("product_id")
        if not product_id:
            return  # Skip if no product_id defined
        
        product = self.product_manager.get_product_by_id(product_id)
        if not product:
            return
        
        technology = product.get("our_name", "Unknown")
        technology_type = self.product_manager.get_category_name(product.get("category_id"))
        
        description = pattern.get("description", "")
        probability = pattern.get("probability", 100)
        
        tech_key = f"{product_id}:{technology_type}"
        
        if tech_key in self.detected_technologies:
            return
        
        self.detected_technologies.add(tech_key)
        
        storage_description = f"Cookie '{cookie_name}'"
        if description:
            storage_description += f": {description}"
        
        storage.add_to_storage(
            technology=technology,
            technology_type=technology_type,
            description=storage_description,
            probability=probability,
            product_id=product_id
        )
        
        self._display_result(technology, technology_type, cookie_name, cookie_value, description, probability)
    
    def _display_result(self, technology, technology_type, cookie_name, cookie_value, description, probability):
        """
        Display the identified technology result.
        
        Args:
            technology: Technology name.
            technology_type: Type of technology.
            cookie_name: Cookie name that provided the detection.
            cookie_value: Cookie value.
            description: Description of the cookie's purpose.
        """
        type_display = self._format_type_display(technology_type)
        main_message = f"{technology} ({type_display})"
        
        detail_parts = [f"<- Cookie '{cookie_name}'"]
        
        if self.args.verbose and cookie_value:
            display_value = cookie_value[:30] + "..." if len(cookie_value) > 30 else cookie_value
            detail_parts.append(f" = '{display_value}'")
        
        if self.args.verbose and description:
            detail_parts.append(f" : {description}")
        
        detail_message = "".join(detail_parts)
        
        ptprint(main_message, "VULN", not self.args.json, end=" ", indent=4)
        ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True, end="")
        if self.args.verbose:
            ptprint(f" {detail_message}", "ADDITIONS", not self.args.json, colortext=True)
        else:
            ptprint(" ")
    
    def _format_type_display(self, technology_type):
        """
        Format technology type for display.
        
        Args:
            technology_type: Technology type string.
            
        Returns:
            str: Human-readable type string.
        """
        display_mapping = {
            "WebApp": "WebApp",
            "FrontendFramework": "Frontend Framework",
            "BackendFramework": "Backend Framework",
            "Interpret": "Programming Language",
            "LoadBalancer": "Load Balancer",
            "OAuth2Server": "OAuth2 Server",
            "CDN": "CDN",
            "CloudPlatform": "Cloud Platform",
            "Analytics": "Analytics",
            "WebServer": "Web Server"
        }
        return display_mapping.get(technology_type, technology_type)


def run(args, ptjsonlib, helpers, http_client, responses: StoredResponses):
    """Entry point for running the Cookie detection."""
    COOK(args, ptjsonlib, helpers, http_client, responses).run()