"""
WSRPO - Web-Server Response Position-Order Detection Module

This module implements a test that identifies the web server technology
by analyzing the order of HTTP response headers in a 400 Bad Request response.

Includes:
- WSRPO class to perform the response-header order detection.
- run() function as an entry point to execute the test.

Usage:
    WSRPO(args, ptjsonlib, helpers, http_client, responses).run()

"""

from typing import List, Tuple
from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager

from ptlibs.http.raw_http_client import RawHttpResponse
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Test response-header order"
WANTED = {b"server", b"date", b"content-type", b"content-length"}


class WSRPO:
    """
    Class to detect web server technology by analyzing the order
    of response headers returned in a 400 Bad Request HTTP response.

    The detection is based on predefined header order definitions loaded
    from a JSON file. It extracts the order of selected headers for matching.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        """Initialize the WSRPO test with necessary components."""
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.product_manager = get_product_manager()

        # Unpack stored responses
        self.response_hp = responses.resp_hp
        self.response_404 = responses.resp_404
        self.raw_response_400 = responses.raw_resp_400

        self.definitions = self.helpers.load_definitions("wsrpo.json")

    def run(self) -> None:
        """
        Execute the response header order detection test.

        Analyzes the order of certain HTTP headers in a pre-obtained 400 Bad Request response.
        If a known header order is matched, it identifies the web server.

        Prints test progress and results depending on verbosity and output mode.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        if self.raw_response_400 is None:
            ptprint("Could not induce 400 Bad Request", "INFO", not self.args.json,indent=4)
            return

        raw_headers = self._read_raw_headers(self.raw_response_400)
        order = self._extract_order(raw_headers)
        result = self._match_order(order)

        if getattr(self.args, "verbose", False) and raw_headers:
            self._print_verbose(raw_headers)

        if result:
            technology, probability, product_id = result
            self._report(technology, probability, product_id)
        else:
            ptprint("Web-server could not be identified by header order", "INFO", not self.args.json,indent=4)

    @staticmethod
    def _read_raw_headers(resp: RawHttpResponse) -> List[Tuple[bytes, bytes]]:
        """
        Extract raw response headers from an RawHttpResponse object.

        Args:
            resp: RawHttpResponse object.

        Returns:
            List of tuples (header_name_bytes, header_value_bytes).
        """
        if hasattr(resp.msg, "raw_headers"):
            return list(resp.msg.raw_headers)
        return [(k.encode(), v.encode()) for k, v in resp.msg.items()]

    @staticmethod
    def _extract_order(raw: List[Tuple[bytes, bytes]]) -> List[str]:
        """
        Extract the order of wanted headers from raw headers list.

        Args:
            raw: List of (header_name_bytes, header_value_bytes).

        Returns:
            List of header names (strings) in lowercase and in order, filtered by WANTED set.
        """
        return [n.lower().decode() for n, _ in raw if n.lower() in WANTED]

    def _match_order(self, order: List[str] | None) -> tuple | None:
        """
        Match observed header order against known definitions.

        Allows the 'server' header to be missing. All other headers in the definition
        must be present and in correct order.

        Args:
            order: List of observed header names (lowercase strings).

        Returns:
            Tuple of (technology_name, probability, product_id) if matched, or None if no match.
        """
        if not order:
            return None

        for d in self.definitions:
            ref = d.get("order", [])

            required_headers = [h for h in ref if h != "server"]
            optional_headers = ["server"] if "server" in ref else []

            if not all(h in order for h in required_headers):
                continue

            order_filtered = [h for h in order if h in required_headers or h in optional_headers]

            expected_sequence = [h for h in ref if h in order_filtered]

            if order_filtered == expected_sequence:
                # Get product info from product_id
                product_id = d.get("product_id")
                if not product_id:
                    continue
                
                product = self.product_manager.get_product_by_id(product_id)
                if not product:
                    continue
                
                technology_name = product.get("our_name", "Unknown")
                probability = d.get("probability", 20)
                
                return technology_name, probability, product_id
        return None

    def _print_verbose(self, raw: List[Tuple[bytes, bytes]]):
        """
        Print detailed raw headers for verbose output.

        Args:
            raw: List of (header_name_bytes, header_value_bytes).
        """
        ptprint("Server responses:", "ADDITIONS", True, indent=4, colortext=True)
        for n, v in raw:
            ptprint(f"{n.decode(errors='replace')}: "
                    f"{v.decode(errors='replace')}", "ADDITIONS", True, indent=8, colortext=True)

    def _report(self, tech: str, probability: int, product_id: int):
        """
        Report the identified web server technology and record it.

        Args:
            tech: The identified technology string.
            probability: Probability percentage.
            product_id: Product ID from products.json.
        """
        if tech:
            storage.add_to_storage(
                technology=tech, 
                technology_type="Web Server", 
                vulnerability="PTV-WEB-INFO-WSRPO", 
                probability=probability,
                product_id=product_id
            )
            ptprint(f"Identified WS: {tech}", "VULN", not self.args.json, indent=4, end=" ")
            ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True)

def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the WSRPO test."""
    WSRPO(args, ptjsonlib, helpers, http_client, responses).run()