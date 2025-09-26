"""
Test OS detection via Case Sensitivity.

This module implements a test that detects the underlying operating system (Windows vs Unix/Linux)
based on the case sensitivity of static resource URLs. It does so by:

1) Attempting to find a static resource (favicon or first referenced asset).
2) Requesting the resource with original case and altered case (upper/lower).
3) Comparing responses to infer case sensitivity of the server's file system,
   which correlates with the OS type.

Provides the OSCS class for running the test and a run() entry point function.

Usage:
    OSCS(args, ptjsonlib, helpers, http_client, responses).run()
"""

import os
import re
from urllib.parse import urlparse, urlunparse, urljoin

from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses

from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint
from ptlibs.http.http_client import HttpClient


__TESTLABEL__ = "Test OS detection via Case Sensitivity"

class OSCS:
    """
    OSCS implements an OS detection test based on case sensitivity of static resources.

    It tries to detect whether the underlying server OS is Windows (case-insensitive)
    or Unix/Linux (case-sensitive) by comparing responses to differently cased resource URLs.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client

        # Unpack stored responses
        self.response_hp = responses.resp_hp
        self.response_404 = responses.resp_404

    def run(self) -> None:
        """
        Execute the OS detection test using case sensitivity of static resources.

        1) Locate a static resource (favicon or first referenced asset).
        2) Compare responses for lowercase and uppercase resource URLs.
        3) Report whether the server is case-insensitive (Windows) or case-sensitive (Unix/Linux).
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        resource = self._find_static_resource()
        if not resource:
            ptprint("No static source found for test", "INFO", not self.args.json, indent=4)
            return

        resource_url, lower_resp, ct_lower = resource
        upper_url      = self._make_alt_case_url(resource_url)

        if resource_url == upper_url:
            upper_resp, ct_upper = lower_resp, ct_lower
        else:
            upper_resp, ct_upper = self._fetch(upper_url)

        self._report(lower_resp, ct_lower, upper_resp, ct_upper)

    def _find_static_resource(self):
        """
        Locate a static resource to test:
        1) Try '/favicon.ico'.
        2) If not found, download the homepage HTML and search for the first
           reference to a static asset (.js, .css, .png, .jpg, .jpeg, .gif, .ico).

        Returns:
            tuple or None: (full URL (str), response (requests.Response), content_type (str))
            if a resource is found, else None.
        """
        base = self.args.url.rstrip('/')
        parsed_base = urlparse(base)

        favicon = base + '/favicon.ico'
        resp, ct = self._fetch(favicon)

        if resp is not None:
            if resp.status_code in (301, 302):
                ptprint(f"Redirect detected to {resp.headers.get('Location')}", "INFO", not self.args.json, indent=4)
                return None
            elif resp.status_code == 200:
                return favicon, resp, ct

        resp_home, _ = self._fetch(base + '/')

        if resp_home is not None:
            if resp_home.status_code in (301, 302):
                ptprint(f"Redirect to ghhgj {resp_home.headers.get('Location')}","INFO", not self.args.json, indent=4)
                return None
            elif resp_home.status_code != 200:
                ptprint(f"Homepage returned {resp_home.status_code}","INFO", not self.args.json, indent=4)
                return None
        else:
            ptprint("Connection error occurred", "INFO", not self.args.json, indent=4)
            return None


        html = resp_home.text or ''
        for match in re.finditer(
            r'(?:href|src)=["\']([^"\']+\.(?:js|css|png|jpg|jpeg|gif|ico))["\']',
            html,
            re.IGNORECASE,
        ):
            candidate_url = urljoin(base + '/', match.group(1))
            if urlparse(candidate_url).netloc != parsed_base.netloc:
                continue

            r, ct = self._fetch(candidate_url)
            if r is not None:
                if r.status_code == 200:
                    return candidate_url, r, ct
        return None

    def _fetch(self, url: str) -> tuple:
        """
        Send a GET request to the specified URL and return the response and its content type.

        Args:
            url (str): The URL to request.

        Returns:
            tuple: (response object, content type string).
        """
        resp = self.helpers.fetch(url)
        
        if resp is not None:
            return resp, resp.headers.get('Content-Type', '')
        else:
            return None, ''


    def _make_alt_case_url(self, resource_url: str) -> str:
        """
        Flip the case of the filename in a URL.

        - If it has any lowercase letters → make it ALL UPPER.
        - Else → make it all lower.

        Directory, query, and fragment stay the same; extra slashes are trimmed.

        Args:
            resource_url (str): Original URL.

        Returns:
            str: URL with filename in opposite case.
        """
        parsed = urlparse(resource_url)
        dirname, filename = os.path.split(parsed.path)

        if any(c.islower() for c in filename):
            new_name = filename.upper()
        else:
            new_name = filename.lower()

        dirname = dirname.rstrip('/')
        new_path = f"/{new_name}" if dirname == "" else f"{dirname}/{new_name}"
        return urlunparse(parsed._replace(path=new_path))

    def _report(self, r1, ct1, r2, ct2) -> None:
        """
        Compare the lowercase and uppercase responses and report the OS type.

        If both status code and content type match, the server is case-insensitive (Windows).
        Otherwise, it is case-sensitive (Unix/Linux).

        This method also records the vulnerability code and OS property in the JSON.
        """
        if r1 is not None and r2 is not None:
            if r1.status_code == r2.status_code and ct1 == ct2:
                storage.add_to_storage(technology="Windows", technology_type="Os", vulnerability="PTV-WEB-INFO-OSSEN")
                ptprint("Identified OS: Windows", "VULN", not self.args.json, indent = 4)
            else:
                storage.add_to_storage(technology="Linux", technology_type="Os", vulnerability="PTV-WEB-INFO-OSSEN")
                ptprint("Identified OS: Unix / Linux", "VULN", not self.args.json, indent = 4)
        else:
            ptprint("Connection error occurred", "INFO", not self.args.json, indent=4)


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point for running the OSCS module."""
    OSCS(args, ptjsonlib, helpers, http_client, responses).run()