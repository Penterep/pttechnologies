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
from helpers.products import get_product_manager
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
        self.product_manager = get_product_manager()
        self.definitions = self.helpers.load_definitions("proto.json")
        self.base_url = args.url.rstrip('/')
        self.base_path = getattr(args, 'base_path', '') or ''

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

        server, display_name, probability, product_id = self._identify_server(statuses)
        if server:
            ptprint(f"Identified WS: {display_name}", "VULN", not self.args.json, indent=4, end=" ")
            ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True)
            
            # Get vendor from product if product_id is available
            vendor = None
            if product_id:
                product = self.product_manager.get_product_by_id(product_id)
                if product:
                    vendor = product.get('vendor')
            
            storage.add_to_storage(
                technology=server, 
                technology_type="Web Server", 
                vulnerability="PTV-WEB-INFO-PROTO", 
                probability=probability,
                product_id=product_id,
                vendor=vendor
            )
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
            # Use base_path for the request path
            request_path = f"{self.base_path}/" if self.base_path else "/"
            response = self.helpers._raw_request(
                self.base_url,
                request_path,
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

    def _identify_server(self, observed_statuses: list) -> tuple:
        """
        Match observed response pattern against known server definitions.

        Args:
            observed_statuses: List of HTTP status codes for each tested protocol behavior.

        Returns:
            Tuple of (technology_name, display_name, probability, product_id) if match found, otherwise (None, None, None, None).
        """
        if not self.definitions:
            return None, None, None, None

            
        for entry in self.definitions:
            if entry.get("statuses") == observed_statuses:
                # Get product info from product_id
                product_id = entry.get("product_id")
                if not product_id:
                    continue
                
                product = self.product_manager.get_product_by_id(product_id)
                if not product:
                    continue
                
                products = product.get('products', [])
                technology_name = products[0] if products else product.get("our_name", "Unknown")
                display_name = product.get("our_name", "Unknown")
                probability = entry.get("probability", 20)
                
                return technology_name, display_name, probability, product_id
        return None, None, None, None


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the PROTO test."""
    PROTO(args, ptjsonlib, helpers, http_client, responses).run()