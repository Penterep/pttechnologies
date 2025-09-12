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

    def run(self):
        """
        Executes the OS detection by comparing HTTP responses to /LPP1 and /LPT1.

        If the status codes differ, assumes Windows OS; otherwise Unix/Linux.
        Reports the result using ptjsonlib and prints output.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        response1 = self.helpers.fetch(self.args.url + "/LPP1")
        response2 = self.helpers.fetch(self.args.url + "/LPT1")

        if response1.status_code != response2.status_code:
            storage.add_to_storage(technology="Windows", technology_type="Os", vulnerability="PTV-WEB-INFO-OSLNK")
            ptprint(f"Identified OS: Windows", "VULN", not self.args.json, indent=4)
        else:
            storage.add_to_storage(technology="Linux", technology_type="Os", vulnerability="PTV-WEB-INFO-OSLNK")
            ptprint(f"Identified OS: Unix / Linux", "VULN", not self.args.json, indent=4)

def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point for running the OSLPT1 OS detection."""
    OSLPT1(args, ptjsonlib, helpers, http_client, responses).run()