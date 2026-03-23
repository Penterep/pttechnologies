"""
Test web server identification via total header length behavior.

This module implements a test that probes how a web server responds to
HTTP requests with varying total header lengths. By analyzing the pattern of
HTTP status codes returned for different total header sizes, it attempts to
identify the underlying web server technology based on predefined
response signatures loaded from a JSON definitions file.

Note: This module tests the total length of all headers combined, as servers
behave differently based on the sum of all headers rather than individual
header lengths.

Includes:
- HDRLEN class to perform the header length behavior test.
- run() function as an entry point to execute the test.

Usage:
    HDRLEN(args, ptjsonlib, helpers, http_client, responses).run()
"""

from urllib.parse import urlparse

from ptlibs.ptprinthelper import ptprint
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager
from helpers.result_storage import storage

__TESTLABEL__ = "Test total header length behavior to identify web server"


class HDRLEN:
    """
    Class to test how a web server reacts to various total header lengths and
    identify the web server technology based on response patterns.
    
    Tests are performed by sending requests with varying total header lengths.
    Servers behave differently based on the sum of all headers, which allows
    for web server identification.
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

        # Header Length Thresholds for Web Server Fingerprinting
        # =====================================================
        # 8183:  Nginx/LiteSpeed boundary    (Nginx: 200 → LiteSpeed: 400)
        # 8183:  Apache/Nginx boundary    (Apache: 200 → Nginx: 400)
        # 8183:  LiteSpeed/Nginx boundary (LiteSpeed: 200 → Nginx: 400) 
        # 16215: Apache/LiteSpeed boundary (Apache: 400 → LiteSpeed: 200)
        # 16230: LiteSpeed/Microsoft-HTTPAPI boundary (LiteSpeed: 400 → HTTPAPI: 200)
        self.lengths = [8180, 8182, 8312, 16215 , 16230, 32000, 48000, 64000, 140000]
        self.definitions = self.helpers.load_definitions("hdrlen.json")

    def _measure_base_header_length(self, test_url: str) -> int:
        """
        Measure the exact total header length of a real PreparedRequest.
        
        Builds a request with the same headers that will actually be sent
        (args.headers merged with a minimal cookie), then measures each header
        using "Header-Name: value\\r\\n" format, and adds the Host header
        which requests appends at the TCP level.
        
        Returns:
            Exact total header length in characters with minimal cookie "testcookie=a".
        """
        import requests as req_lib

        # Build merged headers exactly as run() will build them for each request
        base_headers = dict(getattr(self.args, 'headers', {}) or {})
        base_headers.pop('cookie', None)
        base_headers.pop('Cookie', None)
        base_headers['Cookie'] = 'testcookie=a'  # minimal 1-char cookie for measurement

        # Use PreparedRequest to let requests resolve ALL auto-headers
        # (User-Agent, Accept-Encoding, Accept, Connection) for this exact environment
        prepared = req_lib.Session().prepare_request(
            req_lib.Request('GET', test_url, headers=base_headers)
        )

        # Sum all headers in "Name: value\r\n" format
        total = sum(len(k) + 2 + len(v) + 2 for k, v in prepared.headers.items())

        # Host is added by requests at the TCP level, not in prepared.headers
        host_value = urlparse(test_url).netloc or urlparse(test_url).hostname or ''
        if host_value:
            total += len("Host: ") + len(host_value) + 2  # "Host: value\r\n"

        return total

    def run(self) -> None:
        """
        Executes the header length test for the current context.

        This method performs the header length analysis by sending requests with
        increasingly large total header lengths. It evaluates 
        the server responses and attempts to identify the web server technology 
        based on response patterns to different total header sizes.
        """

        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        base_url = self.args.url.rstrip("/")
        base_path = getattr(self.args, 'base_path', '') or ''
        statuses = []

        # Construct test URL first
        from urllib.parse import urljoin
        if base_path:
            test_path = f"{base_path}/"
        else:
            test_path = "/"
        test_url = urljoin(base_url, test_path)
        
        # Measure exact base header length using a real PreparedRequest.
        # base includes all headers (args.headers + requests auto-headers + Host)
        # with a minimal 1-char cookie value "testcookie=a".
        base_header_length = self._measure_base_header_length(test_url)

        # For target total L:
        #   base_header_length already contains 1 'a' in cookie
        #   → len(value) = L - base_header_length + 1
        for length in self.lengths:
            # Number of 'a's needed so that total header length == length exactly
            cookie_value_length = max(1, length - base_header_length + 1)
            cookie_value = "a" * cookie_value_length

            # Merge args.headers with Cookie so requests sends the exact same
            # headers that were measured in _measure_base_header_length
            base_hdrs = dict(getattr(self.args, 'headers', {}) or {})
            base_hdrs.pop('cookie', None)
            base_hdrs.pop('Cookie', None)
            base_hdrs['Cookie'] = f'testcookie={cookie_value}'

            try:
                response = self.http_client.send_request(
                    url=test_url,
                    method="GET",
                    headers=base_hdrs,
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
            product = self.product_manager.get_product_by_id(product_id)
            if product:
                display_name = product.get("our_name", "Unknown")
                ptprint(f"Identified WS: {display_name}", "VULN", not self.args.json, indent=4, end=" ")
                ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True)
                
                storage.add_to_storage(
                    technology=server, 
                    technology_type="Web Server",
                    vulnerability="PTV-WEB-INFO-WSRHL", 
                    probability=probability,
                    product_id=product_id
                )
        else:
            ptprint("No matching web server identified from header length behavior", "INFO", not self.args.json, indent=4)

    def _identify_server_exact(self, observed_statuses: list):
        """
        Match observed response pattern against known server definitions.
        Only returns match if there's 100% exact pattern match for high confidence.

        Args:
            observed_statuses: List of HTTP status codes for each tested header length.

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
                products = product.get("products", [])
                # If products[0] is null, use our_name for storage
                if products and products[0] is not None:
                    technology_name = products[0]
                else:
                    technology_name = product.get("our_name")
                probability = entry.get("probability", 100)
                
                return technology_name, probability, product_id
        
        return None, None, None


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the HDRLEN test."""
    HDRLEN(args, ptjsonlib, helpers, http_client, responses).run()
