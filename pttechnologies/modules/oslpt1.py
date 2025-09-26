"""
OSLPT1 - Operating System Detection via LPT1 Path

This module implements a simple OS detection technique based on the response
differences for requests to /LPP1 and /LPT1 paths. If the HTTP status codes
differ, it assumes the target OS is Windows, otherwise Unix/Linux.

Classes:
    OSLPT1: Main class performing the detection.

Functions:
    run: Entry point to execute the detection.

Usage:
    OSLPT1(args, ptjsonlib, helpers, http_client, responses).run()

"""
import re

from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Test OS detection via LPT1 path"


class OSLPT1:
    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client

        # Unpack stored responses
        self.response_hp = responses.resp_hp
        self.response_404 = responses.resp_404

    def _extract_title(self, html_content: str) -> str:
        """
        Extracts the <title> tag content from HTML response.
        
        Args:
            html_content: HTML string to parse
            
        Returns:
            Title content or empty string if not found
        """
        if not html_content:
            return ""
        
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()
        return ""

    def _responses_differ(self, response1, response2) -> bool:
        """
        Compares two responses to determine if they differ significantly.
        
        Checks:
        - Status codes
        - Title tags
        
        Args:
            response1: First HTTP response
            response2: Second HTTP response
            
        Returns:
            True if responses differ, False otherwise
        """
        if response1.status_code != response2.status_code:
            if self.args.verbose:
                ptprint(f"Status code difference: {response1.status_code} vs {response2.status_code}", "ADDITIONS", not self.args.json, indent=4, colortext=True)
            return True
        
        title1 = self._extract_title(response1.text)
        title2 = self._extract_title(response2.text)
        
        if title1 != title2:
            if self.args.verbose:
                ptprint(f"Title difference detected: '{title1}' vs '{title2}'", "ADDITIONS", not self.args.json, indent=4, colortext=True)
            return True
        
        return False

    def run(self):
        """
        Executes the OS detection by comparing HTTP responses to /LPP1 and /LPT1.

        If the status codes differ, assumes Windows OS; otherwise Unix/Linux.
        Reports the result using ptjsonlib and prints output.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        response1 = self.helpers.fetch(self.args.url + "/LPP1")
        response2 = self.helpers.fetch(self.args.url + "/LPT1")

        if response1 is None or response2 is None:
            ptprint("Connection error occurred", "INFO", not self.args.json, indent=4)
            return

        result = self._responses_differ(response1, response2)

        if result:
            storage.add_to_storage(technology="Windows", technology_type="Os", vulnerability="PTV-WEB-INFO-OSLNK")
            ptprint(f"Identified OS: Windows", "VULN", not self.args.json, indent=4)
        else:
            storage.add_to_storage(technology="Linux", technology_type="Os", vulnerability="PTV-WEB-INFO-OSLNK")
            ptprint(f"Identified OS: Unix / Linux", "VULN", not self.args.json, indent=4)

def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point for running the OSLPT1 OS detection."""
    OSLPT1(args, ptjsonlib, helpers, http_client, responses).run()