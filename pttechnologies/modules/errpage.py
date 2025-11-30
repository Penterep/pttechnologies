"""
ERRPAGE - Error Page Technology Detection Module

This module analyzes error pages served by web servers by deliberately triggering
various HTTP error conditions. Different web servers and technologies have distinct
error page formats that can reveal technology information.

The module tests multiple error conditions including 404 Not Found, 400 Bad Request,
414 URI Too Long, 403 Forbidden, and malformed HTTP requests. It uses regular
expressions to identify technologies and versions from error page content.

Includes:
- ERRPAGE class to perform error page analysis and classification.
- run() function as an entry point to execute the test.

Usage:
    ERRPAGE(args, ptjsonlib, helpers, http_client, responses).run()
"""

import re
from typing import List, Dict, Any, Optional
from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Test error pages for technology identification"


class ERRPAGE:
    TRIGGER_MAP = {
        "404 Not Found": "resp_404",
        "400 Bad Request (percent)": "raw_resp_400", 
        "414 URI Too Long": "long_resp",
        "403 Forbidden (.ht)": "/.ht",
        "403 Forbidden (.htaccess)": "/.htaccess",
        "400 Invalid Header": {"path": "/", "headers": {"Accept": ""}},
        "Invalid HTTP method": "http_invalid_method",
        "400 Invalid Protocol": "http_invalid_protocol",
        "505 Invalid HTTP Version": "http_invalid_version"
    }

    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        """Initialize the ERRPAGE test with provided components and load error page definitions."""
        self.args = args
        self.helpers = helpers
        self.product_manager = get_product_manager()
        self.response_404 = responses.resp_404
        self.raw_response_400 = responses.raw_resp_400
        self.long_response = responses.long_resp
        self.http_invalid_method = responses.http_invalid_method
        self.http_invalid_protocol = responses.http_invalid_protocol
        self.http_invalid_version = responses.http_invalid_version
        self.errpage_definitions = self.helpers.load_definitions("errpage.json")
        self.patterns = self.errpage_definitions.get('patterns', []) if self.errpage_definitions else []
        self.base_url = args.url.rstrip('/')
        self.detected_technologies = []

    def run(self) -> None:
        """
        Execute the ERRPAGE test logic.
        
        Tests various error conditions to trigger different error pages,
        then analyzes the responses for technology signatures.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        if not self.patterns:
            ptprint("No error page definitions loaded from errpage.json or defpage.json", "INFO", not self.args.json, indent=4)
            return

        for trigger_name, trigger_config in self.TRIGGER_MAP.items():
            self._test_error_trigger(trigger_name, trigger_config)

        self._report_findings()
    
    def _test_error_trigger(self, trigger_name: str, trigger_config: Any) -> None:
        """
        Test a single error trigger.
        
        Args:
            trigger_name: Name of the error trigger being tested
            trigger_config: Configuration for the specific trigger
        """
        try:
            response = self._get_response(trigger_config)
            if response is None:
                return
                
            content = getattr(response, 'text', getattr(response, 'body', ''))
            if not content:
                return
                    
            technologies = self._analyze_error_content(content, trigger_name)
            
            for tech in technologies:
                tech['trigger'] = trigger_name
                tech['status_code'] = getattr(response, 'status_code', getattr(response, 'status', 0))
                tech['url'] = getattr(response, 'url', self.base_url)
                self.detected_technologies.append(tech)
                        
        except Exception as e:
            if self.args.verbose:
                ptprint(f"Error testing trigger {trigger_name}: {str(e)}", "ADDITIONS", not self.args.json, indent=8, colortext=True)

    def _get_response(self, trigger_config: Any) -> Optional[object]:
        """
        Get response based on trigger configuration.
        
        Args:
            trigger_config: Configuration specifying how to trigger the error
            
        Returns:
            Response object or None if unable to get response
        """
        if isinstance(trigger_config, str):
            if trigger_config == "resp_404":
                return self.response_404
            elif trigger_config == "raw_resp_400":
                return self.raw_response_400
            elif trigger_config == "long_resp":
                return self.long_response
            elif trigger_config == "http_invalid_method":
                return self.http_invalid_method
            elif trigger_config == "http_invalid_protocol":
                return self.http_invalid_protocol
            elif trigger_config == "http_invalid_version":
                return self.http_invalid_version
            elif trigger_config.startswith('/'):
                return self.helpers.fetch(self.base_url + trigger_config)
        
        elif isinstance(trigger_config, dict):
                return self.helpers._raw_request(
                    self.base_url, 
                    trigger_config.get("path", "/"),
                    extra_headers=trigger_config.get("headers", {})
                )
        
        return None

    def _analyze_error_content(self, content: str, trigger_name: str) -> List[Dict[str, Any]]:
        """
        Analyze error page content against known error page patterns.
        
        Args:
            content: HTML content of the error page
            trigger_name: Name of the trigger that generated this error
            
        Returns:
            List of detected technologies (deduplicated by technology name)
        """
        detected = []
        seen_technologies = set()
        
        if not self.patterns:
            return detected

        for pattern_def in self.patterns:
            match_result = self._match_pattern(content, pattern_def)
            if match_result:
                # Handle both single result and list of results (from extract_tech)
                results_list = match_result if isinstance(match_result, list) else [match_result]
                
                for result in results_list:
                    tech_key = result.get('technology', result.get('name', 'Unknown')).lower()
                    
                    if tech_key not in seen_technologies:
                        result['trigger_name'] = trigger_name
                        result['source'] = pattern_def.get('source', 'unknown')
                        detected.append(result)
                        seen_technologies.add(tech_key)
        
        return detected

    def _parse_footer_content(self, footer_text: str) -> List[Dict[str, Optional[str]]]:
        """
        Parse footer/error page content to extract all technologies.
        Uses the same comprehensive parsing logic as HDRVAL's Server header parsing.
        
        Examples:
        - "Apache/2.2.14 (Unix) mod_ssl/2.2.14 OpenSSL/0.9.8g PHP/5.2.11 with Suhosin-Patch"
        - "nginx/1.18.0"
        - "Microsoft-IIS/10.0"
        
        Args:
            footer_text: Footer/error page text content to parse.
            
        Returns:
            List of technology dictionaries with 'name' and 'version' keys.
        """
        technologies = []
        
        blacklist = {'with', 'Server', 'at', 'port'}
        
        compound_servers = ["Google Frontend", "Microsoft-HTTPAPI", "Apache Tomcat"]
        for compound in compound_servers:
            if compound.lower() in footer_text.lower():
                pattern = f"{re.escape(compound)}(?:/([\\w\\.-]+))?"
                match = re.search(pattern, footer_text, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.group(1) else None
                    technologies.append({'name': compound, 'version': version})
                    footer_text = re.sub(pattern, '', footer_text, flags=re.IGNORECASE).strip()
        
        footer_text = re.sub(r'Server\s+at\s+[^\s]+', '', footer_text, flags=re.IGNORECASE)
        footer_text = re.sub(r'port\s+\d+', '', footer_text, flags=re.IGNORECASE)
        
        parts = footer_text.split()

        for part in parts:
            part = part.strip()
            if not part:
                continue

            if part.lower() in blacklist:
                continue

            os_match = re.search(r'\(([^)]+)\)', part)
            if os_match:
                os_content = os_match.group(1).strip()
                if os_content not in ['codeit', '@RELEASE@']:
                    main_part = re.sub(r'\([^)]*\)', '', part).strip()
                    if main_part:
                        version_match = re.match(r'^([^/]+)/([^/\s]+)', main_part)
                        if version_match:
                            name = version_match.group(1)
                            version = version_match.group(2)
                            technologies.append({'name': name, 'version': version})
                        else:
                            if re.match(r'^[A-Za-z][A-Za-z0-9\-_]*', main_part):
                                technologies.append({'name': main_part, 'version': None})

                    technologies.append({'name': os_content, 'version': None})
            else:
                version_match = re.match(r'^([^/]+)/([^/\s]+)', part)
                if version_match:
                    name = version_match.group(1)
                    version = version_match.group(2)
                    technologies.append({'name': name, 'version': version})
                else:
                    if re.match(r'^[A-Za-z][A-Za-z0-9\-_]*$', part) and part.lower() not in blacklist:
                        if len(part) > 2:
                            technologies.append({'name': part, 'version': None})
        
        return technologies

    def _match_pattern(self, content: str, pattern_def: Dict[str, Any]) -> Optional[Any]:
        """
        Match content against a specific pattern definition.
        
        Args:
            content: Page content to analyze
            pattern_def: Pattern definition from JSON
            
        Returns:
            Technology information if matched (single dict or list of dicts), None otherwise.
            Returns a list when extract_tech is used to parse multiple technologies from footer.
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
            if self.args.verbose:
                ptprint(f"Invalid regex pattern in definitions: {e}", "ADDITIONS", not self.args.json, indent=8,colortext=True)
            return None
        
        if not match:
            return None
        
        # Get product info from product_id
        product_id = pattern_def.get('product_id')
        if not product_id:
            return None  # Skip if no product_id defined
        
        product = self.product_manager.get_product_by_id(product_id)
        if not product:
            return None
        
        technology_name = product.get('our_name', 'Unknown')
        category_name = self.product_manager.get_category_name(product.get('category_id'))
                    
        result = {
            'name': pattern_def.get('name', 'Unknown'),
            'category': category_name,
            'technology': technology_name,
            'product_id': product_id,
            'version': None,
            'matched_text': match.group(0)[:100] + ('...' if len(match.group(0)) > 100 else ''),
            'pattern_used': pattern 
        }
        
        version_pattern = pattern_def.get('version_pattern')
        if version_pattern:
            try:
                version_match = re.search(version_pattern, content, re_flags)
                if version_match:
                    result['version'] = version_match.group(1) if version_match.groups() else version_match.group(0)
            except re.error:
                pass
        elif match.groups():
            result['version'] = match.group(1)

        if pattern_def.get('extract_tech') and match.groups():
            footer_text = match.group(1)
            parsed_techs = self._parse_footer_content(footer_text)
            
            if parsed_techs:
                hdrval_definitions = self.helpers.load_definitions("hdrval.json")
                definitions = hdrval_definitions.get('definitions', hdrval_definitions)
                if isinstance(definitions, list):
                    definition_list = definitions
                else:
                    definition_list = [v for k, v in definitions.items() if k != 'headers']
                
                results = []
                for tech in parsed_techs:
                    tech_result = {
                        'name': tech['name'],
                        'category': None,
                        'technology': tech['name'],
                        'product_id': None,
                        'version': tech.get('version'),
                        'matched_text': match.group(0)[:100] + ('...' if len(match.group(0)) > 100 else ''),
                        'pattern_used': pattern
                    }
                    
                    tech_name_lower = tech['name'].lower()
                    
                    classified = False
                    for definition in definition_list:
                        if isinstance(definition, dict) and 'content' in definition:
                            if definition['content'].lower() == tech_name_lower:
                                product_id = definition.get('product_id')
                                if product_id:
                                    product = self.product_manager.get_product_by_id(product_id)
                                    if product:
                                        tech_result['technology'] = product.get('our_name', tech['name'])
                                        tech_result['category'] = self.product_manager.get_category_name(product.get('category_id'))
                                        tech_result['product_id'] = product_id
                                        tech_result['probability'] = definition.get('probability', 100)
                                        classified = True
                                        break
                    
                    if not classified:
                        tech_to_product_id = {
                            'apache': 10,
                            'nginx': 11,
                            'iis': 12,
                            'microsoft-iis': 12,
                            'tomcat': 20,
                            'apache tomcat': 20,
                            'jetty': 21,
                            'litespeed': 13,
                            'openresty': 170,
                            'ibm_http_server': 171,
                            'ibm http server': 171
                        }
                        
                        tech_lower = tech_name_lower.replace(' ', '_')
                        if tech_lower in tech_to_product_id:
                            product_id = tech_to_product_id[tech_lower]
                            product = self.product_manager.get_product_by_id(product_id)
                            if product:
                                tech_result['technology'] = product.get('our_name', tech['name'])
                                tech_result['category'] = self.product_manager.get_category_name(product.get('category_id'))
                                tech_result['product_id'] = product_id
                    
                    if not tech_result.get('probability'):
                        tech_result['probability'] = 100
                    
                    results.append(tech_result)
                
                return results if results else None
        
        return result

    def _report_findings(self) -> None:
        """
        Report detected technologies and store them.
        """
        if not self.detected_technologies:
            ptprint("No error page technologies identified", "INFO", not self.args.json, indent=4)
            return

        unique_techs = {}
        for tech in self.detected_technologies:
            tech_key = tech.get('technology', 'Unknown').lower()
            if tech_key not in unique_techs:
                unique_techs[tech_key] = tech

        for tech in unique_techs.values():
            version_text = f" {tech['version']}" if tech.get('version') else ""
            category_text = f" ({tech['category']})" if tech.get('category') else " (Unknown)"
            probability = tech.get("probability", 100)
            
            # First print verbose details
            if self.args.verbose:
                ptprint(f"Detected via: {tech.get('trigger_name', 'unknown')} [HTTP {tech.get('status_code', '?')}]", 
                       "ADDITIONS", not self.args.json, indent=4, colortext=True)
                if tech.get('pattern_used'):
                    ptprint(f"Pattern: {tech.get('pattern_used')[:100]}{'...' if len(tech.get('pattern_used', '')) > 100 else ''}", 
                           "ADDITIONS", not self.args.json, indent=4, colortext=True)
                if tech.get('matched_text'):
                    ptprint(f"Match: '{tech.get('matched_text')}'", 
                           "ADDITIONS", not self.args.json, indent=4, colortext=True)
            
            # Then print the technology
            ptprint(f"{tech['technology']}{version_text}{category_text}", 
                   "VULN", not self.args.json, indent=4, end=" ")
            ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True)

        for tech in unique_techs.values():
            self._store_technology(tech)

    def _store_technology(self, tech: Dict[str, Any]) -> None:
        """
        Store detected technology in the storage system.
        
        Args:
            tech: Detected technology information
        """
        tech_name = tech.get('technology', tech.get('name', 'Unknown'))
        version = tech.get('version')
        tech_type = tech.get('category')
        product_id = tech.get('product_id')
        probability = tech.get('probability', 100)
        trigger_name = tech.get('trigger_name', 'unknown')
        status_code = tech.get('status_code')
        
        description = f"Error page ({trigger_name}): {tech_name}"
        if version:
            description += f" {version}"
        if status_code:
            description += f" [HTTP {status_code}]"
        
        # Get vendor from product if product_id is available
        vendor = None
        if product_id:
            product = self.product_manager.get_product_by_id(product_id)
            if product:
                vendor = product.get('vendor')
        
        storage.add_to_storage(
            technology=tech_name,
            version=version,
            technology_type=tech_type,
            probability=probability,
            description=description,
            product_id=product_id,
            vendor=vendor
        )


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the ERRPAGE test."""
    ERRPAGE(args, ptjsonlib, helpers, http_client, responses).run()