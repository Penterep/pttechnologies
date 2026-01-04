"""
Test Apache Web Server detection via differential access to .ht* files.

This module provides a test that attempts to detect an Apache web server by
sending HTTP requests to `.hh` and `.ht` paths on the target URL and comparing
their responses. Apache servers typically restrict access to `.ht*` files
using `.htaccess` rules, so differing response status codes can reveal
the presence of Apache.

Contains:
- WSHT class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    WSHT(args, ptjsonlib, helpers, http_client, responses).run()
"""
import requests

from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager
from urllib.parse import urljoin

from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint


__TESTLABEL__ = "Test Apache detection via .ht access rule"

class WSHT:
    """
    Detects Apache Web Server using differential behavior of .ht* file access.

    This class attempts to identify an Apache web server by probing URLs that differ
    only in the presence of `.ht` (which is typically restricted by Apache's default `.htaccess` rules).
    A discrepancy in response codes may indicate Apache or a similar server using such rules.
    """

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
        Executes the Apache detection test.

        Sends two HTTP GET requests to the server:
        - One with a non-restricted `.hh` path
        - One with a potentially restricted `.ht` path

        If the status codes differ, it is likely the server uses `.htaccess`-like rules,
        commonly associated with Apache. If Apache is detected, a vulnerability and a property
        indicating the server type are added to the JSON result.
        """

        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        try:
            base_path = getattr(self.args, 'base_path', '') or ''
            # Construct paths: base_path/.hh and base_path/.ht
            if base_path:
                path1 = f"{base_path}/.hh"
                path2 = f"{base_path}/.ht"
            else:
                path1 = "/.hh"
                path2 = "/.ht"
            url1 = urljoin(self.args.url, path1)
            url2 = urljoin(self.args.url, path2)
            
            response1 = self.http_client.send_request(url=url1, method="GET", headers=self.args.headers, allow_redirects=False, timeout=None)
            response2 = self.http_client.send_request(url=url2, method="GET", headers=self.args.headers, allow_redirects=False, timeout=None)

            if response1 is None or response2 is None:
                ptprint("Connection error occurred", "INFO", not self.args.json, indent=4)
                return
                
            if response1.status_code != response2.status_code:
                probability = 100
                product_manager = get_product_manager()
                # Apache (product_id: 10)
                product = product_manager.get_product_by_id(10)
                if product:
                    products = product.get('products', [])
                    technology_name = products[0] if products else product.get('our_name', 'Apache')
                    display_name = product.get('our_name', 'Apache')
                    category_name = product_manager.get_category_name(product.get('category_id'))
                    vendor = product.get('vendor')
                    storage.add_to_storage(technology=technology_name, technology_type=category_name, vulnerability="PTV-WEB-INFO-WSHT", probability=probability, vendor=vendor)
                    ptprint(f"Identified WS: {display_name}", "VULN", not self.args.json, indent=4, end=" ")
                    ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True)
            else:
                ptprint(f"It is not possible to identify the web server, but it does not seem to be Apache", "INFO", not self.args.json, indent=4)
        
        except requests.exceptions.RequestException as e:
            ptprint("Connection error occurred", "INFO", not self.args.json, indent=4)

def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the WSHT (Web Server .htaccess Test)."""
    WSHT(args, ptjsonlib, helpers, http_client, responses).run()