"""
PLLNG - Programming Language Detection Module

This module implements detection of web programming languages
based on file extensions found in linked resources or
by checking common filenames on the target web server.

It uses HTTP requests and HTML parsing to infer the backend
language and reports findings via ptjsonlib.

Classes:
    PLLNG: Main detector class.

Functions:
    run: Entry point to execute the detection.

Usage:
    PLLNG(args, ptjsonlib, helpers, http_client, responses).run()

"""

import json
import os
from urllib.parse import urlparse, urljoin

from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

from bs4 import BeautifulSoup

__TESTLABEL__ = "Test programming language detection via file extensions"


class PLLNG:
    """
    PLLNG performs language detection or processing tasks related to language.

    This class is responsible for detecting or handling language-specific logic
    within the application. It may interact with text data, perform analysis,
    or manage language resources.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client

        # Unpack stored responses
        self.response_hp = responses.resp_hp
        self.response_404 = responses.resp_404

        self.extensions = self.helpers.load_definitions("pllng.json")

    def run(self):
        """
        Runs the programming language detection process.

        Uses a pre-fetched homepage response.
        Detects programming language by examining linked resources or, if that fails,
        by dictionary attack, then reports the result.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        base_url = self.args.url.rstrip("/")
        resp = self.response_hp
        html = resp.text
        result = self._find_language_by_link(html, base_url)

        if not result:
            result = self._dictionary_attack(base_url)

        self._report(result)

    def _find_language_by_link(self, html, base_url):
        """
        Parses HTML to detect programming language by examining resource URLs.

        Args:
            html (str): HTML content of the base URL.
            base_url (str): Base URL for resolving relative links.

        Returns:
            dict or None: Extension metadata if detected, otherwise None.
        """
        soup = BeautifulSoup(html, "html.parser")
        netloc = urlparse(base_url).netloc

        tag_attrs = [
            ("a", "href"),
            ("link", "href"),
            ("script", "src"),
            ("img", "src"),
            ("form", "action")
        ]

        for tag, attr in tag_attrs:
            for element in soup.find_all(tag):
                url = element.get(attr)
                if not url:
                    continue
                abs_url = urljoin(base_url, url)
                parsed = urlparse(abs_url)

                if parsed.netloc == "" or parsed.netloc == netloc:
                    for ext_entry in self.extensions:
                        ext = ext_entry["extension"]
                        if abs_url.lower().endswith(f".{ext}"):
                            if self.args.verbose:
                                ptprint(f"Match: {abs_url}", "ADDITIONS", not self.args.json, indent=4, colortext=True)
                            return ext_entry
        return None

    def _dictionary_attack(self, base_url):
        """
        Attempts to detect programming language by checking common filenames with known extensions.

        Args:
            base_url (str): Base URL to test.

        Returns:
            dict or None: Extension metadata if a matching file is found, otherwise None.
        """
        candidates = ["index", "default"]
        for name in candidates:
            for ext_entry in self.extensions:
                ext = ext_entry["extension"]
                test_url = f"{base_url}/{name}.{ext}"
                resp = self.helpers.fetch(test_url, allow_redirects=True)
                if resp is not None:
                    if resp.status_code == 200:
                        if self.args.verbose:
                            ptprint(f"Match: {test_url}", "ADDITIONS", not self.args.json, indent=4, colortext=True)
                        return ext_entry
        return None

    def _report(self, result):
        """
        Reports the detected programming language via ptjsonlib and prints output.

        Args:
            result (dict or None): Detected extension metadata or None if detection failed.
        """
        if result:
            language = result["technology"]
            ext = result["extension"].capitalize()
            storage.add_to_storage(technology=language, technology_type="Interpret", vulnerability="PTV-WEB-INFO-LNGEX")
            ptprint(f"Identified language: {language}", "VULN", not self.args.json, indent=4)
        else:
            ptprint(f"It was not possible to identify the programming language", "INFO", not self.args.json, indent=4)

def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point for running the PLLNG detection."""
    PLLNG(args, ptjsonlib, helpers, http_client, responses).run()