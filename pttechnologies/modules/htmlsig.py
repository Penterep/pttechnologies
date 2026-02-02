"""
Module for identifying technologies from HTML signatures.

Analyzes HTML code from the homepage to detect web technologies, frameworks,
and CMS platforms based on HTML patterns extracted from Wappalyzer.
Uses pre-fetched homepage response for efficiency.
"""

import re
from ptlibs.ptprinthelper import ptprint
from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager

__TESTLABEL__ = "Test for HTML-based technology identification"


class HTML:
    """
    HTML analyzer for technology detection.
    
    Processes HTML content to identify web technologies, frameworks,
    and content management systems based on HTML signature patterns.
    Uses already fetched homepage response for analysis.
    
    Attributes:
        args: Command line arguments and configuration.
        ptjsonlib: JSON processing library.
        helpers: Helper utilities for loading definitions.
        wapp_definitions: Loaded HTML patterns from html_from_wappalyzer.json.
        response_hp: Pre-fetched homepage response.
        product_manager: Product manager for retrieving product information.
    """
    
    def __init__(self, args, ptjsonlib, helpers, http_client, responses: StoredResponses):
        """
        Initialize the HTML analyzer.
        
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
        
        self.wapp_definitions = self.helpers.load_definitions("html_from_wappalyzer.json")
    
    def run(self):
        """
        Main entry point for HTML analysis.
        
        Extracts HTML content from the pre-fetched homepage response
        and analyzes it for technology identification patterns.
        
        Returns:
            None
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        
        if not self.response_hp:
            ptprint("No homepage response available", "INFO", not self.args.json, indent=4)
            return
        
        html_content = self.response_hp.text
        
        if not html_content:
            ptprint("No HTML content found", "INFO", not self.args.json, indent=4)
            return
        
        technologies_found = self._analyze_html(html_content)
        
        if not technologies_found:
            ptprint("No technologies identified from HTML signatures", "INFO", not self.args.json, indent=4)
    
    def _analyze_html(self, html_content):
        """
        Analyze HTML content against known patterns.
        
        Args:
            html_content: Raw HTML content string.
            
        Returns:
            int: Number of technologies found.
        """
        technologies_found = 0
        detected_products = set()
        
        if not self.wapp_definitions:
            return 0
        
        for product_def in self.wapp_definitions:
            product_id = product_def.get("product_id")
            patterns = product_def.get("patterns", [])
            
            if not product_id or not patterns:
                continue
            
            if product_id in detected_products:
                continue
            
            for pattern in patterns:
                match_result = self._check_pattern(html_content, pattern, product_id)
                
                if match_result:
                    self._process_match(match_result)
                    detected_products.add(product_id)
                    technologies_found += 1
                    break
        
        return technologies_found
    
    def _check_pattern(self, html_content, pattern, product_id):
        """
        Check if HTML content matches a pattern.
        
        Args:
            html_content: HTML content to analyze.
            pattern: Pattern definition dictionary.
            product_id: ID of the product being checked.
            
        Returns:
            dict: Match result with technology info, or None if no match.
        """
        regex = pattern.get("regex")
        version_group = pattern.get("version_group")
        probability = pattern.get("probability", 100)
        
        if not regex:
            return None
        
        try:
            match = re.search(regex, html_content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            
            if not match:
                return None
            
            product = self.product_manager.get_product_by_id(product_id)
            if not product:
                return None
            
            products = product.get('products', [])
            if products and products[0] is not None:
                technology = products[0]
            else:
                technology = product.get("our_name", "Unknown")
            
            display_name = product.get("our_name", "Unknown")
            technology_type = self.product_manager.get_category_name(product.get("category_id"))
            
            version = None
            if version_group and match.groups() and len(match.groups()) >= version_group:
                version_str = match.group(version_group)
                if version_str:
                    version_str = version_str.strip()
                    if re.match(r'^[\d.]+', version_str):
                        version = version_str
            
            matched_text = match.group(0)
            if len(matched_text) > 100:
                matched_text = matched_text[:100] + "..."
            
            return {
                'product_id': product_id,
                'technology': technology,
                'display_name': display_name,
                'technology_type': technology_type,
                'version': version,
                'probability': probability,
                'matched_text': matched_text
            }
            
        except re.error as e:
            if self.args.verbose:
                ptprint(f"Invalid regex pattern: {regex[:50]}... - {e}", "WARNING", not self.args.json, indent=8)
            return None
        except Exception as e:
            if self.args.verbose:
                ptprint(f"Error checking pattern: {e}", "WARNING", not self.args.json, indent=8)
            return None
    
    def _process_match(self, match_result):
        """
        Process a successful pattern match and store results.
        
        Args:
            match_result: Dictionary containing match information.
            
        Returns:
            None
        """
        technology = match_result['technology']
        display_name = match_result['display_name']
        technology_type = match_result['technology_type']
        version = match_result.get('version')
        probability = match_result['probability']
        product_id = match_result['product_id']
        matched_text = match_result.get('matched_text', '')
        
        description = self._create_description(matched_text)
        
        storage.add_to_storage(
            technology=technology,
            version=version,
            technology_type=technology_type,
            probability=probability,
            description=description,
            product_id=product_id
        )
        
        self._display_result(display_name, version, technology_type, matched_text, probability)
    
    def _create_description(self, matched_text):
        """
        Create a description for the identified technology.
        
        Args:
            matched_text: The HTML snippet that matched.
            
        Returns:
            str: Formatted description string.
        """
        display_text = matched_text[:80] + "..." if len(matched_text) > 80 else matched_text
        return f"HTML signature: {display_text}"
    
    def _display_result(self, technology, version, technology_type, matched_text, probability):
        """
        Display the identified technology result.
        
        Args:
            technology: Technology name.
            version: Technology version or None.
            technology_type: Type of technology.
            matched_text: The HTML snippet that matched.
            probability: Detection probability.
            
        Returns:
            None
        """
        tech_display = technology
        if version:
            tech_display += f" {version}"
        
        type_display = self._format_type_display(technology_type)
        main_message = f"{tech_display} ({type_display})"
        
        detail_text = matched_text[:50] + "..." if len(matched_text) > 50 else matched_text
        detail_message = f"<- HTML: {detail_text}"
        
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
            "Operating System": "OS",
            "E-commerce": "Ecommerce"
        }
        return display_mapping.get(technology_type, technology_type)


def run(args, ptjsonlib, helpers, http_client, responses: StoredResponses):
    """Entry point for running the HTML signature detection."""
    HTML(args, ptjsonlib, helpers, http_client, responses).run()
