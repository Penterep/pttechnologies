"""
Test web server identification via cookie length behavior.

This module implements a test that probes how a web server responds to
HTTP requests with varying cookie header lengths. By analyzing the pattern of
HTTP status codes returned for different cookie sizes, it attempts to
identify the underlying web server technology based on predefined
response signatures loaded from a JSON definitions file.

Includes:
- COOKLEN class to perform the cookie length behavior test.
- run() function as an entry point to execute the test.

Usage:
    COOKLEN(args, ptjsonlib, helpers, http_client, responses).run()
"""

from urllib.parse import urlparse

from ptlibs.ptprinthelper import ptprint
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager
from helpers.result_storage import storage

__TESTLABEL__ = "Test cookie length behavior to identify web server"


class COOKLEN:
    """
    Class to test how a web server reacts to various cookie header lengths and
    identify the web server technology based on response patterns.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.product_manager = get_product_manager()

        # Unpack stored responses
        self.response_hp = responses.resp_hp
        self.response_404 = responses.resp_404

        # Cookie Length Thresholds for Web Server Fingerprinting
        # =====================================================
        # 8183:  Nginx/LiteSpeed boundary    (Nginx: 200 → LiteSpeed: 400)
        # 8183:  Apache/Nginx boundary    (Apache: 200 → Nginx: 400)
        # 8183:  LiteSpeed/Nginx boundary (LiteSpeed: 200 → Nginx: 400) 
        # 16220: Apache/LiteSpeed boundary (Apache: 400 → LiteSpeed: 200)
        # 16230: LiteSpeed/Microsoft-HTTPAPI boundary (LiteSpeed: 400 → HTTPAPI: 200)
        self.lengths = [8180, 8182, 8183, 16220 , 16230, 32000, 48000, 64000, 140000]
        self.definitions = self.helpers.load_definitions("cooklen.json")

    def run(self) -> None:
        """
        Executes the cookie length test for the current context.

        This method performs the cookie length analysis by sending requests with
        increasingly large cookie headers. It evaluates the server responses
        and attempts to identify the web server technology based on response patterns.
        """

        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        base_url = self.args.url.rstrip("/")
        base_path = getattr(self.args, 'base_path', '') or ''
        statuses = []

        for length in self.lengths:
            cookie_value = "a" * max(1, length - 11)
            
            headers = dict(getattr(self.args, "headers", {}) or {})
            headers['Cookie'] = f'testcookie={cookie_value}'
            
            # Construct URL: base_url + base_path + "/"
            from urllib.parse import urljoin
            if base_path:
                test_path = f"{base_path}/"
            else:
                test_path = "/"
            test_url = urljoin(base_url, test_path)
            
            try:
                response = self.http_client.send_request(
                    url=test_url,
                    method="GET",
                    headers=headers,
                    allow_redirects=False,
                    timeout=self.args.timeout
                )
                status = str(response.status_code)
                statuses.append(status)
                
            except Exception as e:
                statuses.append("CONN_ERROR")

        if self.args.verbose:
            ptprint("Server responses:", "ADDITIONS", not self.args.json, indent=4, colortext=True)
            for length, status in zip(self.lengths, statuses):
                ptprint(f"{length}\t chars [{status}]", "ADDITIONS", not self.args.json, indent=8, colortext=True)

        server, probability, product_id = self._identify_server_exact(statuses)
        if server:
            ptprint(f"Identified WS: {server}", "VULN", not self.args.json, indent=4, end=" ")
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
                probability=probability,
                product_id=product_id,
                vendor=vendor
            )
        else:
            ptprint("No matching web server identified from cookie length behavior", "INFO", not self.args.json, indent=4)

    def _identify_server_exact(self, observed_statuses: list):
        """
        Match observed response pattern against known server definitions.
        Only returns match if there's 100% exact pattern match for high confidence.

        Args:
            observed_statuses: List of HTTP status codes for each tested cookie length.

        Returns:
            Tuple of (technology_name, probability, product_id) if exact match found, otherwise (None, None, None).
        """
        if not self.definitions:
            return None, None, None
            
        for entry in self.definitions:
            if entry.get("statuses") == observed_statuses:
                # Get product info from product_id
                product_id = entry.get("product_id")
                if not product_id:
                    continue
                
                product = self.product_manager.get_product_by_id(product_id)
                if not product:
                    continue
                
                technology_name = product.get("our_name", "Unknown")
                probability = entry.get("probability", 100)
                
                return technology_name, probability, product_id
        
        return None, None, None


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the COOKLEN test."""
    COOKLEN(args, ptjsonlib, helpers, http_client, responses).run()