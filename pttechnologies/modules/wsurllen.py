"""
Test web server identification via URL length behavior.

This module implements a test that probes how a web server responds to
HTTP requests with varying URL lengths. By analyzing the pattern of
HTTP status codes returned for different URL lengths, it attempts to
identify the underlying web server technology based on predefined
response signatures loaded from a JSON definitions file.

Includes:
- WSURLLEN class to perform the URL length behavior test.
- run() function as an entry point to execute the test.

Usage:
    WSURLLEN(args, ptjsonlib, helpers, http_client, responses).run()
"""

from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint

from helpers.stored_responses import StoredResponses
from helpers.result_storage import storage

import json
import os

__TESTLABEL__ = "Test URL length behavior to identify web server"


class WSURLLEN:
    """
    Class to test how a web server reacts to various URL lengths and
    identify the web server technology based on response patterns.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client

        # Unpack stored responses
        self.response_hp = responses.resp_hp
        self.response_404 = responses.resp_404

        self.lengths = [1000, 5000, 6000, 7000, 8000, 9000, 10000, 15000, 20000]
        self.definitions = self.helpers.load_definitions("wsurllen.json")

    def run(self) -> None:
        """
        Executes the URL length test for the current context.

        This method performs the URL length analysis based on the configured inputs
        (e.g., collected requests or target domain). It processes the data, evaluates
        the results (e.g., detecting anomalies or violations), and then either prints
        the results to the console, stores them for further processing, or both.

        Intended to be the main entry point for executing the URL length test logic.
        """

        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        base_url = self.args.url.rstrip("/")
        statuses = []

        blocked_long_url = False
        for l in self.lengths:
            path = "/" + ("a" * l)
            full_url = base_url + path

            try:
                response = self.helpers.fetch(full_url)

                if response is None:
                    status = "None"
                    blocked_long_url = True

                else:
                    if hasattr(response, 'status_code'):
                        status = str(response.status_code)
                    else:
                        status = "Unknown"
                        blocked_long_url = True

            except Exception as e:
                status = f"Error: {str(e)}"
                blocked_long_url = True
            
            statuses.append(status)

        if self.args.verbose:
            ptprint("Server responses:", "ADDITIONS", not self.args.json,indent=4, colortext=True)
            for l, s in zip(self.lengths, statuses):
                ptprint(f"{l}\tchars [{s}]", "ADDITIONS", not self.args.json,indent=8, colortext=True)

        if blocked_long_url:
            ptprint("Long URL are blocked", "INFO", not self.args.json,indent=4)

        server = self._identify_server(statuses)
        if server:
            ptprint(f"Identified WS: {server}", "VULN", not self.args.json, indent=4)
            storage.add_to_storage(technology=server, technology_type="WebServer", vulnerability="PTV-WEB-INFO-WSURL", probability=20)
        else:
            ptprint("No matching web server identified from URL length behavior", "INFO", not self.args.json, indent=4)

    def _identify_server(self, observed_statuses: list):
        """
        Match observed response pattern against known server definitions.

        Args:
            observed_statuses: List of HTTP status codes for each tested URL length.

        Returns:
            Detected server name if match is found, otherwise None.
        """
        for entry in self.definitions:
            if entry.get("statuses") == observed_statuses:
                return entry.get("technology")
        return None


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the WSURLLEN test."""
    WSURLLEN(args, ptjsonlib, helpers, http_client, responses).run()