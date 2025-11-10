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
        
        detected_files = self._dictionary_attack(base_url)
        
        if detected_files:
            for doc_file in detected_files:
                self._report(doc_file)
        else:
            ptprint("No documentation files were found", "INFO", not self.args.json, indent=4)

    def _dictionary_attack(self, base_url):
        """
        Attempts to detect documentation files by checking for specific files.

        Args:
            base_url (str): Base URL to test.

        Returns:
            list: List of detected documentation files with metadata.
        """
        detected = []
        
        for doc_entry in self.doc_definitions:
            file_variants = doc_entry.get("files", [doc_entry.get("file", "")])
            if isinstance(file_variants, str):
                file_variants = [file_variants]
            
            for file_path in file_variants:
                if not file_path:
                    continue
                    
                test_url = f"{base_url}/{file_path}"
                resp = self._check_file_presence(test_url)
                
                if resp:                    
                    doc_info = {
                        "file_name": file_path,
                        "url": test_url,
                        "status_code": resp.status_code,
                        "response": resp
                    }
                    
                    detected.append(doc_info)
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


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point for running the DOCS detection."""
    DOCS(args, ptjsonlib, helpers, http_client, responses).run()

