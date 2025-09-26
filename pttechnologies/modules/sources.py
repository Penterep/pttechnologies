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
from urllib.parse import urlparse, urljoin

from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
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
                    probability = self._determine_probability(resp.status_code)
                    
                    tech_info = {
                        "technology": tech_entry.get("technology", "Unknown"),
                        "category": tech_entry.get("category", "Unknown"),
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
                enhanced_info = submodule.analyze(tech_info, self.args)
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
        technology = tech_info["technology"]
        category = tech_info["category"]
        probability = tech_info["probability"]
        test_url = tech_info["url"]
        status_code = tech_info["status_code"]
        
        if self.args.verbose:
            status_msg = f"Found: {test_url} [{status_code}]"
            ptprint(status_msg, "ADDITIONS", not self.args.json, indent=4, colortext=True)
        
        storage.add_to_storage(
            technology=technology, 
            technology_type=category, 
            probability=probability
        )
                
        ptprint(f"{technology} ({category})", "VULN", not self.args.json, indent=4)

        if tech_info.get("additional_info"):
            for info in tech_info["additional_info"]:
                ptprint(f"{info}", "INFO", not self.args.json, indent=6)


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point for running the SOURCES detection."""
    SOURCES(args, ptjsonlib, helpers, http_client, responses).run()