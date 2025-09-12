'''
PROTO - Protocol Behavior Detection Module

This module analyzes web server behavior when receiving invalid HTTP requests:
- Invalid protocol (GET / FOO/1.1)
- Invalid HTTP version (GET / HTTP/9.8)  
- Invalid HTTP method (FOO / HTTP/1.1)

Different web servers respond differently to these malformed requests,
allowing for server fingerprinting based on error responses.
'''

from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Test protocol behavior for technology identification"


class PROTO:
    TRIGGER_MAP = {
        "Invalid HTTP method": {"request_line": "FOO / HTTP/1.1"},
        "Invalid Protocol": {"request_line": "GET / FOO/1.1"},
        "Invalid HTTP Version": {"request_line": "GET / HTTP/9.8"}
    }

    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.definitions = self.helpers.load_definitions("proto.json")
        self.base_url = args.url.rstrip('/')

    def run(self) -> None:
        """
        Executes the protocol behavior test for the current context.
        
        This method performs the protocol behavior analysis by sending invalid
        HTTP requests and analyzing the response patterns to identify the web server.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        statuses = []

        for trigger_name, trigger_config in self.TRIGGER_MAP.items():
            status = self._get_response(trigger_config)
            statuses.append(status)

        if self.args.verbose:
            ptprint("Server responses:", "ADDITIONS", not self.args.json, indent=4, colortext=True)
            for trigger_name, status in zip(self.TRIGGER_MAP.keys(), statuses):
                ptprint(f"{trigger_name}\t[{status}]", "ADDITIONS", not self.args.json, indent=8, colortext=True)

        server = self._identify_server(statuses)
        if server:
            ptprint(f"Identified WS: {server}", "VULN", not self.args.json, indent=4)
            storage.add_to_storage(technology=server, technology_type="WebServer", vulnerability="PTV-WEB-INFO-PROTO", probability=20)
        else:
            ptprint("No matching web server identified from protocol behavior", "INFO", not self.args.json, indent=4)

    def _get_response(self, trigger_config: dict) -> str:
        """
        Send a custom HTTP request with malformed request line and return status code.
        
        Args:
            trigger_config: Configuration containing custom request line
            
        Returns:
            HTTP status code as string, or "None" if request failed
        """
        try:
            response = self.helpers._raw_request(
                self.base_url,
                '/',
                custom_request_line=trigger_config.get("request_line")
            )
            
            if response is None:
                return "None"
            
            if hasattr(response, 'status'):
                return str(response.status)
            if hasattr(response, 'status_code'):
                return str(response.status_code)
            else:
                return "Unknown"
                
        except Exception as e:
            return "Error"

    def _identify_server(self, observed_statuses: list) -> str:
        """
        Match observed response pattern against known server definitions.

        Args:
            observed_statuses: List of HTTP status codes for each tested protocol behavior.

        Returns:
            Detected server name if match is found, otherwise None.
        """
        if not self.definitions:
            return None

            
        for entry in self.definitions:
            if entry.get("statuses") == observed_statuses:
                return entry.get("technology")
        return None


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the PROTO test."""
    PROTO(args, ptjsonlib, helpers, http_client, responses).run()