"""
SOURCES - Technology Detection Module

This module implements detection of web technologies based on the presence
of specific files on the target web server. It performs dictionary attacks
to identify common technology-specific files and resources.

Classes:
    SOURCES: Main detector class.

Functions:
    run: Entry point to execute the detection.

Usage:
    SOURCES(args, ptjsonlib, helpers, http_client, responses).run()
"""

import json
import os
import re
from urllib.parse import urlparse, urljoin

from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager
from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Test technology detection via specific file presence"


class SOURCES:
    """
    SOURCES performs technology detection based on specific file presence.

    This class is responsible for identifying web technologies by checking
    for the presence of characteristic files and resources on the target server.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.product_manager = get_product_manager()
        self.response_hp = responses.resp_hp
        self.nonexist_status = responses.resp_404
        self.tech_definitions = self.helpers.load_definitions("sources.json")

    def run(self):
        """
        Runs the technology detection process.

        Performs dictionary attack to identify technologies based on
        specific file presence, then reports the results.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        if self.nonexist_status is not None:
            if self.nonexist_status.status_code == 200:
                ptprint("It is not possible to run this module because non exist pages are returned with status code 200", "INFO", not self.args.json, indent=4)
                return

        base_url = self.args.url.rstrip("/")
        
        detected_technologies = self._dictionary_attack(base_url)
        
        if detected_technologies:
            for tech in detected_technologies:
                self._report(tech)
        else:
            ptprint("No specific technology files were found", "INFO", not self.args.json, indent=4)

    def _dictionary_attack(self, base_url):
        """
        Attempts to detect technologies by checking for specific files.

        Args:
            base_url (str): Base URL to test.

        Returns:
            list: List of detected technology dictionaries with metadata.
        """
        detected = []
        
        for tech_entry in self.tech_definitions:
            file_variants = tech_entry.get("files", [tech_entry.get("file", "")])
            if isinstance(file_variants, str):
                file_variants = [file_variants]
            
            for file_path in file_variants:
                if not file_path:
                    continue
                    
                test_url = f"{base_url}/{file_path}"
                resp = self._check_file_presence(test_url)
                
                if resp:
                    # Get product info from product_id
                    product_id = tech_entry.get("product_id")
                    if not product_id:
                        continue  # Skip if no product_id defined
                    
                    # For Drupal (product_id 71), verify CHANGELOG.txt content
                    if product_id == 71 and file_path == "CHANGELOG.txt":
                        if not self._verify_drupal_changelog(resp):
                            continue  # Skip if content verification fails
                    
                    probability = self._determine_probability(resp.status_code)
                    
                    product = self.product_manager.get_product_by_id(product_id)
                    if not product:
                        continue
                    
                    products = product.get('products', [])
                    technology_name = products[0] if products else product.get("our_name", "Unknown")
                    display_name = product.get("our_name", "Unknown")
                    category_name = self.product_manager.get_category_name(product.get("category_id"))
                    
                    tech_info = {
                        "product_id": product_id,
                        "technology": technology_name,  # For storage (CVE compatible)
                        "display_name": display_name,   # For printing
                        "category": category_name,
                        "file_path": file_path,
                        "url": test_url,
                        "probability": probability,
                        "status_code": resp.status_code,
                        "response": resp,
                        "submodule": tech_entry.get("submodule")
                    }
                    
                    if tech_entry.get("submodule"):
                        tech_info = self._call_submodule(tech_info, tech_entry["submodule"])
                    
                    detected.append(tech_info)
                    break
        
        return detected

    def _check_file_presence(self, test_url):
        """
        Checks if a specific file exists on the server.

        Args:
            test_url (str): URL to test.

        Returns:
            Response object or None: HTTP response if file exists, None otherwise.
        """
        try:
            resp = self.helpers.fetch(test_url)
            if resp.status_code in [200, 403]:
                return resp
                
        except Exception as e:
            if self.args.verbose:
                ptprint(f"Error checking {test_url}: {str(e)}", "ADDITIONS", not self.args.json, indent=6, colortext=True)
        
        return None

    def _verify_drupal_changelog(self, resp):
        """
        Verifies that CHANGELOG.txt content is actually from Drupal.

        Drupal CHANGELOG.txt has a specific format:
        - Version entries start with "Drupal X.Y.Z" or "Drupal X.Y" followed by date
        - Format: "Drupal 3.0.1, 2001-10-15" or similar
        - Contains separator lines with dashes

        Args:
            resp: HTTP response object containing the file content.

        Returns:
            bool: True if content appears to be from Drupal, False otherwise.
        """
        try:
            content = resp.text
            if not content:
                return False
            
            # Check for Drupal version format: "Drupal X.Y.Z" or "Drupal X.Y" followed by date
            # Pattern matches: "Drupal" followed by version number (X.Y.Z or X.Y) and optional date
            # Examples: "Drupal 3.0.1, 2001-10-15", "Drupal 7.0", "Drupal 8.2.0"
            drupal_version_pattern = r'Drupal\s+\d+\.\d+(?:\.\d+)?(?:\s*,\s*\d{4}-\d{2}-\d{2})?'
            
            if re.search(drupal_version_pattern, content, re.IGNORECASE):
                return True
            
            return False
        except Exception as e:
            if self.args.verbose:
                ptprint(f"Error verifying Drupal CHANGELOG.txt content: {str(e)}", "ADDITIONS", not self.args.json, indent=6, colortext=True)
            return False

    def _determine_probability(self, status_code):
        """
        Determines probability level based on HTTP status code.

        Args:
            status_code (int): HTTP status code.

        Returns:
            int: probability percentage.
        """
        if status_code == 200:
            return 100
        elif status_code == 403:
            return 80
        else:
            return 50

    def _call_submodule(self, tech_info, submodule_name):
        """
        Calls specified submodule for enhanced technology detection.

        Args:
            tech_info (dict): Technology information dictionary.
            submodule_name (str): Name of the submodule to call.

        Returns:
            dict: Enhanced technology information.
        """
        try:
            submodule = __import__(f"modules.submodules.{submodule_name}", fromlist=[submodule_name])
   
            
            if hasattr(submodule, "analyze"):
                enhanced_info = submodule.analyze(tech_info, self.args, self.helpers)
                tech_info.update(enhanced_info)
                                    
        except ImportError as e:
            if self.args.verbose:
                ptprint(f"Submodule {submodule_name} not found: {str(e)}", "ADDITIONS", not self.args.json, indent=6, colortext=True)
        except Exception as e:
            if self.args.verbose:
                ptprint(f"Error in submodule {submodule_name}: {str(e)}", "ADDITIONS", not self.args.json, indent=6, colortext=True)
        
        return tech_info

    def _report(self, tech_info):
        """
        Reports the detected technology via ptjsonlib and prints output.

        Args:
            tech_info (dict): Detected technology information.
        """
        technology = tech_info["technology"]  # For storage (CVE compatible)
        display_name = tech_info.get("display_name", technology)  # For printing
        category = tech_info["category"]
        product_id = tech_info.get("product_id")
        probability = tech_info.get("probability", 50)
        test_url = tech_info["url"]
        status_code = tech_info["status_code"]
        
        if self.args.verbose:
            status_msg = f"Found: {test_url} [{status_code}]"
            ptprint(status_msg, "ADDITIONS", not self.args.json, indent=4, colortext=True)
        
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
            product_id=product_id,
            vendor=vendor
        )
                
        ptprint(f"{display_name} ({category})", "VULN", not self.args.json, indent=4, end=" ")
        ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True)

        if tech_info.get("additional_info"):
            apache_version_items = []
            apache_modules = []
            php_version_items = []
            php_extensions = []
            other_items = []
            
            for info in tech_info["additional_info"]:
                lines = info.split('\n')
                if lines:
                    first_line = lines[0]
                    first_line_stripped = first_line.strip()
                    if first_line.startswith("    "):
                        if product_id == 10:
                            apache_modules.append(info)
                        elif product_id == 30:
                            php_extensions.append(info)
                        else:
                            other_items.append(info)
                    elif "Apache" in first_line_stripped and product_id == 10:
                        apache_version_items.append(info)
                    elif "PHP" in first_line_stripped and product_id == 30:
                        php_version_items.append(info)
                    else:
                        other_items.append(info)
            
            sorted_additional_info = apache_version_items + apache_modules + php_version_items + php_extensions + other_items
            
            for info in sorted_additional_info:
                lines = info.split('\n')
                if lines:
                    first_line = lines[0]
                    is_indented = first_line.startswith("    ")
                    display_line = first_line[4:].strip() if is_indented else first_line.strip()
                    indent_level = 12 if is_indented else 8
                    
                    if self.args.verbose and len(lines) > 1:
                        for detail_line in lines[1:]:
                            if detail_line.strip():
                                ptprint(f"{detail_line.strip()}", "ADDITIONS", not self.args.json, indent=4, colortext=True)
                    
                    last_space_idx = display_line.rfind(' ')
                    if last_space_idx != -1:
                        tech_part = display_line[:last_space_idx]
                        prob_part = display_line[last_space_idx:]

                        ptprint(f"{tech_part}", "VULN", not self.args.json, indent=indent_level, end="")
                        ptprint(f"{prob_part}", "ADDITIONS", not self.args.json, colortext=True)

                    else:
                        ptprint(f"{display_line}", "VULN", not self.args.json, indent=indent_level)


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point for running the SOURCES detection."""
    SOURCES(args, ptjsonlib, helpers, http_client, responses).run()