"""
DOCS - Documentation Files Detection Module

This module implements detection of documentation and informational files
on the target web server. It performs dictionary attacks to identify common
documentation files like readme, version, changelog, etc.

Classes:
    DOCS: Main detector class.

Functions:
    run: Entry point to execute the detection.

Usage:
    DOCS(args, ptjsonlib, helpers, http_client, responses).run()
"""

import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin

from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager
from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Test presence of documentation files"


class DOCS:
    """
    DOCS performs documentation files detection.

    This class is responsible for identifying documentation and informational
    files like readme, version, changelog, license, install, etc.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.product_manager = get_product_manager()
        self.response_hp = responses.resp_hp
        self.nonexist_status = responses.resp_404
        self.doc_definitions = self.helpers.load_definitions("docs.json")
        self._detected_lock = threading.Lock()

    def run(self):
        """
        Runs the documentation files detection process.

        Performs dictionary attack to identify documentation files,
        then reports the results.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        if self.nonexist_status is not None:
            if self.nonexist_status.status_code == 200:
                ptprint("It is not possible to run this module because non exist pages are returned with status code 200", "INFO", not self.args.json, indent=4)
                return

        base_url = self.args.url.rstrip("/")
        base_path = getattr(self.args, 'base_path', '') or ''
        
        detected_files = self._dictionary_attack(base_url, base_path)
        
        if detected_files:
            for doc_file in detected_files:
                self._report(doc_file)
                # Analyze content for technology patterns
                self._analyze_doc_content(doc_file)
        else:
            ptprint("No documentation files were found", "INFO", not self.args.json, indent=4)

    def _is_case_insensitive(self) -> Optional[bool]:
        """
        Checks if the server is case-insensitive (Windows) based on OSCS results.
        Only considers results from OSCS module (vulnerability="PTV-WEB-INFO-OSSEN").
        
        Returns:
            True if Windows (case-insensitive), False if Linux (case-sensitive), None if unknown
        """
        # Check storage for OSCS results (vulnerability="PTV-WEB-INFO-OSSEN")
        all_records = storage.get_all_records()
        for record in all_records:
            # Only check records from OSCS module
            if record.get("vulnerability") == "PTV-WEB-INFO-OSSEN":
                if record.get("product_id") == 6:
                    return True  # Windows detected - case-insensitive
                elif record.get("product_id") == 167:
                    return False  # Linux detected - case-sensitive
        
        return None  # Unknown - test all variants

    def _prepare_file_list(self, base_url: str, base_path: str, is_case_insensitive: Optional[bool]) -> List[tuple]:
        """
        Prepares list of files to test based on case sensitivity.
        
        Args:
            base_url: Base URL to test
            base_path: Base path to append test strings after
            is_case_insensitive: True if Windows, False if Linux, None if unknown
            
        Returns:
            List of tuples: (test_url, file_name, doc_entry_index)
        """
        files_to_test = []
        files_list = self.doc_definitions.get("files", []) if isinstance(self.doc_definitions, dict) else []
        
        for doc_entry_idx, doc_entry in enumerate(files_list):
            # Handle new array format or old dict format for backward compatibility
            if isinstance(doc_entry, list):
                file_variants = doc_entry
            elif isinstance(doc_entry, dict):
                file_variants = doc_entry.get("files", [doc_entry.get("file", "")])
            else:
                file_variants = []
            
            if isinstance(file_variants, str):
                file_variants = [file_variants]
            
            # If case-insensitive (Windows), only test lowercase variant
            if is_case_insensitive is True:
                # Find first lowercase variant or use first variant
                test_variant = None
                for variant in file_variants:
                    if variant and variant.islower():
                        test_variant = variant
                        break
                if not test_variant and file_variants:
                    test_variant = file_variants[0].lower() if file_variants[0] else None
                
                if test_variant:
                    # Construct path: base_path/test_variant
                    test_path = f"{base_path}/{test_variant}" if base_path else f"/{test_variant}"
                    test_url = urljoin(base_url, test_path)
                    files_to_test.append((test_url, test_variant, doc_entry_idx))
            else:
                # Case-sensitive or unknown - test all variants
                for file_path in file_variants:
                    if not file_path:
                        continue
                    # Construct path: base_path/file_path
                    test_path = f"{base_path}/{file_path}" if base_path else f"/{file_path}"
                    test_url = urljoin(base_url, test_path)
                    files_to_test.append((test_url, file_path, doc_entry_idx))
        
        return files_to_test

    def _dictionary_attack(self, base_url, base_path):
        """
        Attempts to detect documentation files by checking for specific files.
        Uses parallel processing with ThreadPoolExecutor for faster scanning.

        Args:
            base_url (str): Base URL to test.
            base_path (str): Base path to append test strings after.

        Returns:
            list: List of detected documentation files with metadata.
        """
        # Check case sensitivity from OSCS results
        is_case_insensitive = self._is_case_insensitive()
        
        # Prepare file list based on case sensitivity
        files_to_test = self._prepare_file_list(base_url, base_path, is_case_insensitive)
        
        if not files_to_test:
            return []
        
        detected = []
        found_entries = set()  # Track which doc_entry indices we've found files for
        
        # Use ThreadPoolExecutor for parallel processing
        max_workers = self.args.threads if hasattr(self.args, 'threads') else 10
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_info = {
                executor.submit(self._check_file_presence, test_url): (test_url, file_name, doc_entry_idx)
                for test_url, file_name, doc_entry_idx in files_to_test
            }
            
            # Process completed tasks
            for future in as_completed(future_to_info):
                test_url, file_name, doc_entry_idx = future_to_info[future]
                
                # Skip if we already found a file for this doc_entry
                if doc_entry_idx in found_entries:
                    continue
                
                try:
                    resp = future.result()
                    if resp:
                        doc_info = {
                            "file_name": file_name,
                            "url": test_url,
                            "status_code": resp.status_code,
                            "response": resp
                        }
                        
                        # Thread-safe append
                        with self._detected_lock:
                            detected.append(doc_info)
                            found_entries.add(doc_entry_idx)
                        
                        # Cancel remaining futures for this doc_entry (if possible)
                        # Note: We can't easily cancel futures, but we skip them in the loop above
                except Exception as e:
                    if self.args.verbose:
                        ptprint(f"Error checking {test_url}: {str(e)}", "ADDITIONS", not self.args.json, indent=6, colortext=True)
        
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
            if resp is not None and resp.status_code in [200, 403]:
                return resp
                
        except Exception as e:
            if self.args.verbose:
                ptprint(f"Error checking {test_url}: {str(e)}", "ADDITIONS", not self.args.json, indent=6, colortext=True)
        
        return None

    def _report(self, doc_info):
        """
        Reports the detected documentation file.

        Args:
            doc_info (dict): Detected documentation file information.
        """
        file_name = doc_info["file_name"]
        test_url = doc_info["url"]
        status_code = doc_info["status_code"]
        
        if self.args.verbose:
            status_msg = f"Found: {test_url} [{status_code}]"
            ptprint(status_msg, "ADDITIONS", not self.args.json, indent=4, colortext=True)
        
        ptprint(f"{file_name}", "VULN", not self.args.json, indent=4)

    def _analyze_doc_content(self, doc_info):
        """
        Analyzes the content of a documentation file to detect technologies.

        Args:
            doc_info (dict): Detected documentation file information.
        """
        try:
            resp = doc_info.get("response")
            if not resp or not hasattr(resp, 'text'):
                return
            
            content = resp.text
            if not content:
                return
            
            patterns = self.doc_definitions.get("patterns", []) if isinstance(self.doc_definitions, dict) else []
            detected_technologies = []
            seen_technologies = set()
            
            for pattern_def in patterns:
                match_result = self._match_pattern(content, pattern_def)
                
                if match_result:
                    tech_key = match_result.get('technology', match_result.get('name', 'Unknown')).lower()
                    
                    if tech_key not in seen_technologies:
                        detected_technologies.append(match_result)
                        seen_technologies.add(tech_key)
            
            # Store detected technologies
            for tech in detected_technologies:
                technology = tech.get('technology')
                display_name = tech.get('display_name', tech.get('name', 'Unknown'))
                technology_type = tech.get('category')  # This is the category name from product manager
                product_id = tech.get('product_id')
                version = tech.get('version')
                probability = tech.get('probability', 100)
                
                # Only store technologies with product_id (skip generic ones like HLS, DASH)
                if product_id:
                    storage.add_to_storage(
                        technology=technology,
                        technology_type=technology_type,
                        product_id=product_id,
                        version=version,
                        probability=probability
                    )
                
                version_str = f" {version}" if version else ""
                category_str = f" ({technology_type})" if technology_type else ""
                ptprint(f"{display_name}{version_str}{category_str}", "VULN", not self.args.json, indent=8, end=" ")
                ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True)
                    
        except Exception as e:
            if self.args.verbose:
                ptprint(f"Error analyzing doc content: {str(e)}", "ADDITIONS", not self.args.json, indent=6, colortext=True)

    def _match_pattern(self, content: str, pattern_def: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Match content against a specific pattern definition.
        
        Args:
            content: Page content to analyze
            pattern_def: Pattern definition from JSON
            
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
            if self.args.verbose:
                ptprint(f"Invalid regex pattern in definitions: {e}", "ADDITIONS", not self.args.json, indent=8, colortext=True)
            return None
        
        if not match:
            return None
        
        # Get product info from product_id (skip if product_id is null)
        product_id = pattern_def.get('product_id')
        if product_id is None:
            # Technology without product_id (like HLS, DASH)
            return {
                'name': pattern_def.get('name', 'Unknown'),
                'technology': pattern_def.get('name', 'Unknown').lower(),
                'display_name': pattern_def.get('name', 'Unknown'),
                'category': None,
                'product_id': None,
                'version': None,
                'probability': pattern_def.get('probability', 100),
                'matched_text': match.group(0)[:100] + ('...' if len(match.group(0)) > 100 else '')
            }
        
        product = self.product_manager.get_product_by_id(product_id)
        if not product:
            return None
        
        products = product.get('products', [])
        technology_name = products[0] if products else product.get('our_name', 'Unknown')
        display_name = product.get('our_name', 'Unknown')
        category_name = self.product_manager.get_category_name(product.get('category_id'))
        
        result = {
            'name': pattern_def.get('name', 'Unknown'),
            'category': category_name,
            'technology': technology_name,
            'display_name': display_name,
            'product_id': product_id,
            'version': None,
            'probability': pattern_def.get('probability', 100),
            'matched_text': match.group(0)[:100] + ('...' if len(match.group(0)) > 100 else '')
        }
        
        # Extract version if version_pattern is defined
        version_pattern = pattern_def.get('version_pattern')
        if version_pattern:
            try:
                version_match = re.search(version_pattern, content, re_flags)
                if version_match and version_match.lastindex:
                    # Find the first non-None group (handles alternation patterns)
                    for i in range(1, version_match.lastindex + 1):
                        version = version_match.group(i)
                        if version:
                            result['version'] = version
                            break
            except re.error:
                pass
        
        return result


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point for running the DOCS detection."""
    DOCS(args, ptjsonlib, helpers, http_client, responses).run()

