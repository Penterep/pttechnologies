#!/usr/bin/python3
"""
Copyright (c) 2025 Penterep Security s.r.o.

pttechnologies - Testing tool for identifying technologies used by web applications

pttechnologies is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pttechnologies is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pttechnologies.  If not, see <https://www.gnu.org/licenses/>.
"""

import socket
import argparse
import importlib
import os
import threading
import sys; sys.path.append(__file__.rsplit("/", 1)[0])

from io import StringIO
from types import ModuleType
from urllib.parse import urlparse, urlunparse, urljoin
from typing import Optional

from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint, print_banner, help_print
from ptlibs.threads import ptthreads, printlock
from ptlibs.http.http_client import HttpClient

from helpers._thread_local_stdout import ThreadLocalStdout
from helpers.stored_responses import StoredResponses
from helpers.predict import Predict
from helpers.summary import Summary
from helpers.helpers import Helpers

from helpers.result_storage import storage

from _version import __version__

import requests

class PtTechnologies:
    def __init__(self, args):
        self.ptjsonlib   = ptjsonlib.PtJsonLib()
        self.ptthreads   = ptthreads.PtThreads()
        self.args        = args
        self._lock       = threading.Lock()
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)
        self.helpers     = Helpers(args=self.args, ptjsonlib=self.ptjsonlib, http_client=self.http_client)
        self.target_ip = self._extract_ip_from_url(args.url)
        self.stored_responses = self._fetch_initial_responses()

        # Activate ThreadLocalStdout stdout proxy
        self.thread_local_stdout = ThreadLocalStdout(sys.stdout)
        self.thread_local_stdout.activate()

    def run(self) -> None:
        """Main method"""
        tests = self.args.tests or _get_all_available_modules()
        self.ptthreads.threads(tests, self.run_single_module, self.args.threads)

        Predict(args=self.args, ptjsonlib=self.ptjsonlib, helpers=self.helpers).run()
        Summary(args=self.args, ptjsonlib=self.ptjsonlib).run()

    def run_single_module(self, module_name: str) -> None:
        """
        Safely loads and executes a specified module's `run()` function.

        The method locates the module file in the "modules" directory, imports it dynamically,
        and executes its `run()` method with provided arguments and a shared `ptjsonlib` object.
        It also redirects stdout/stderr to a thread-local buffer for isolated output capture.

        If the module or its `run()` method is missing, or if an error occurs during execution,
        it logs appropriate messages to the user.

        Args:
            module_name (str): The name of the module (without `.py` extension) to execute.
        """
        try:
            with self._lock:
                module = _import_module_from_path(module_name)

            if hasattr(module, "run") and callable(module.run):
                buffer = StringIO()
                self.thread_local_stdout.set_thread_buffer(buffer)
                try:
                    module.run(
                        args=self.args,
                        ptjsonlib=self.ptjsonlib,
                        helpers=self.helpers,
                        http_client=self.http_client,
                        responses=self.stored_responses
                    )

                except Exception as e:
                    ptprint(f"{module_name.upper()}: {e}", "ERROR", not self.args.json)
                    error = e
                else:
                    error = None
                finally:
                    self.thread_local_stdout.clear_thread_buffer()
                    with self._lock:
                        ptprint(buffer.getvalue(), "TEXT", not self.args.json, end="\n")
            else:
                ptprint(f"Module '{module_name}' does not have 'run' function", "WARNING", not self.args.json)

        except FileNotFoundError as e:
            ptprint(f"Module '{module_name}' not found", "ERROR", not self.args.json)
        except Exception as e:
            ptprint(f"Error running module '{module_name}': {e}", "ERROR", not self.args.json)

    def _extract_ip_from_url(self, url: str) -> Optional[str]:
        """
        Extract IP address from URL or resolve hostname to IP.
        
        Args:
            url: Target URL
            
        Returns:
            IP address string or None if unable to resolve
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc.split(':')[0]
        
        try:
            socket.inet_aton(hostname)
            return hostname
        except socket.error:
            pass
        
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def _fetch_initial_responses(self) -> StoredResponses:
        """
        Sends initial HTTP requests to gather key baseline responses and stores them for reuse.

        Performs three requests:
        1. A GET request to the homepage URL (self.args.url), without following redirects.
        If the response is a redirect (3xx) or a non-200 status, the script exits early.
        2. A GET request to a deliberately non-existent URL to obtain a known 404 response.
        3. A low-level/raw request to provoke a 400-like response, useful for fingerprinting or error detection.
        4. A GET request to the `/favicon.ico` path to detect any load-balancer or CDN server variation.
        5. A GET request to an over-long URL (e.g., 5000 'a' characters) to trigger a 400 Bad Request.

        The collected responses are stored together in a `StoredResponses` dataclass instance,
        containing:
          - `resp_hp`:     homepage response (Response)
          - `resp_404`:   404 baseline response (Response)
          - `raw_resp_400`: raw 400-like response (RawHttpResponse | None)
          - `resp_favicon`: favicon.ico response (Response | None)
          - `long_resp`:    long-URL 400 response (Response | None)

        Returns:
            StoredResponses: A dataclass instance with all baseline responses.
        Raises:
            Exits the script via self.ptjsonlib.end_error() if any of the requests fail
            or return unexpected status codes.
        """
        try:
            # Send request to home page
            resp_hp = self.http_client.send_request(url=self.args.url, method="GET", headers=self.args.headers, allow_redirects=False)
            # Handle non 200 statuses
            if resp_hp.status_code != 200:
                redirect_url = resp_hp.headers.get('Location', 'unknown')
                ptprint(f"Redirect detected: {resp_hp.status_code} -> {redirect_url}\n", "INFO", not self.args.json, colortext=True)   
                if redirect_url and redirect_url != 'unknown':
                    if redirect_url.startswith('/'):
                        redirect_url = urljoin(self.args.url, redirect_url)
                    resp_hp = self.http_client.send_request(url=redirect_url, method="GET", headers=self.args.headers, allow_redirects=False)

            # Send request to nonexistent page
            resp_404 = self.http_client.send_request(url=f"{self.args.url}/this-page-does-not-exist-xyz123", method="GET", headers=self.args.headers, allow_redirects=False)

            # Send raw request to raise 400 status code
            raw_resp_400 = self.helpers._get_bad_request_response(self.args.url)

            # Send request to URL with favicon.ico path
            url_favicon = urljoin(self.args.url, '/favicon.ico')
            resp_favicon = self.http_client.send_request(url_favicon, method="GET", headers=self.args.headers, allow_redirects=False)

            # Send request with an over-long URL (5000 'a' characters)
            long_path = '/' + ('a' * 5000)
            long_url = urljoin(self.args.url, long_path)
            long_resp = self.helpers._raw_request(long_url, '/')

            #Get IP responses from HTTP and HTTPS
            http_url = f"http://{self.target_ip}/"
            http_resp = self.helpers.fetch(http_url)

            https_url = f"https://{self.target_ip}/"
            https_resp = self.helpers.fetch(https_url)

            #Send request with invalid request line
            http_invalid_method = self.helpers._raw_request( self.args.url.rstrip('/'), '/', custom_request_line="FOO / HTTP/9.8")
            http_invalid_protocol = self.helpers._raw_request( self.args.url.rstrip('/'), '/', custom_request_line="GET / FOO/1.1")
            http_invalid_version = self.helpers._raw_request( self.args.url.rstrip('/'), '/', custom_request_line="GET / HTTP/9.8")

            # Create and store the responses container
            self.stored_responses = StoredResponses(
                resp_hp=resp_hp,
                resp_404=resp_404,
                raw_resp_400=raw_resp_400,
                resp_favicon=resp_favicon,
                long_resp=long_resp,
                http_resp = http_resp,
                https_resp = https_resp,
                http_invalid_method = http_invalid_method,
                http_invalid_protocol = http_invalid_protocol,
                http_invalid_version = http_invalid_version
            )

            return self.stored_responses

        except requests.exceptions.RequestException as e:
            self.ptjsonlib.end_error(f"Error retrieving initial responses:", details=e, condition=self.args.json)

def _import_module_from_path(module_name: str) -> ModuleType:
    """
    Dynamically imports a Python module from a given file path.

    This method uses `importlib` to load a module from a specific file location.
    The module is then registered in `sys.modules` under the provided name.

    Args:
        module_name (str): Name under which to register the module.

    Returns:
        ModuleType: The loaded Python module object.

    Raises:
        ImportError: If the module cannot be found or loaded.
    """
    module_path = os.path.join(os.path.dirname(__file__), "modules", f"{module_name}.py")

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None:
        raise ImportError(f"Cannot find spec for {module_name} at {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

def _get_all_available_modules() -> list:
    """
    Returns a list of available Python module names from the 'modules' directory.

    Modules must:
    - Not start with an underscore
    - Have a '.py' extension
    """
    modules_folder = os.path.join(os.path.dirname(__file__), "modules")
    available_modules = [
        f.rsplit(".py", 1)[0]
        for f in sorted(os.listdir(modules_folder))
        if f.endswith(".py") and not f.startswith("_")
    ]
    return available_modules

def get_help():
    """
    Generate structured help content for the CLI tool.

    This function dynamically builds a list of help sections including general
    description, usage, examples, and available options. The list of tests (modules)
    is generated at runtime by scanning the 'modules' directory and reading each module's
    optional '__TESTLABEL__' attribute to describe it.

    Returns:
        list: A list of dictionaries, where each dictionary represents a section of help
              content (e.g., description, usage, options). The 'options' section includes
              available command-line flags and dynamically discovered test modules.
    """

    # Build dynamic help from available modules
    def _get_available_modules_help() -> list:
        rows = []
        available_modules = _get_all_available_modules()
        modules_folder = os.path.join(os.path.dirname(__file__), "modules")
        for module in available_modules:
            mod = _import_module_from_path(module)
            label = getattr(mod, "__TESTLABEL__", f"Test for {module.upper()}")
            row = ["", "", f" {module.upper()}", label]
            rows.append(row)
        return sorted(rows, key=lambda x: x[2])

    return [
        {"description": ["Penterep template script"]},
        {"usage": ["pttechnologies <options>"]},
        {"usage_example": [
            "pttechnologies -u https://www.example.com",
        ]},
        {"options": [
            ["-u",  "--url",                    "<url>",            "Connect to URL"],
            ["-ts", "--tests",                  "<test>",     "Specify one or more tests to perform:"],
            *_get_available_modules_help(),
            ["", "", "", ""],
            ["-p",  "--proxy",                  "<proxy>",          "Set proxy (e.g. http://127.0.0.1:8080)"],
            ["-T",  "--timeout",                "<miliseconds>",    "Set timeout (default 10)"],
            ["-t",  "--threads",                "<threads>",        "Set thread count (default 10)"],
            ["-c",  "--cookie",                 "<cookie>",         "Set cookie"],
            ["-a",  "--user-agent",             "<a>",              "Set User-Agent header"],
            ["-H",  "--headers",                "<header:value>",   "Set custom header(s)"],
            ["-r",  "--redirects",              "",                 "Follow redirects (default False)"],
            ["-C",  "--cache",                  "",                 "Cache HTTP communication"],
            ["-vv",  "--verbose",               "",                 "Enable verbose mode"],
            ["-v",  "--version",                "",                 "Show script version and exit"],
            ["-h",  "--help",                   "",                 "Show this help message and exit"],
            ["-j",  "--json",                   "",                 "Output in JSON format"],
        ]
        }]

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help="False", description=f"{SCRIPTNAME} <options>")
    parser.add_argument("-u",  "--url",            type=str, required=True)
    parser.add_argument("-ts",  "--tests",         type=lambda s: s.lower(), nargs="+")
    parser.add_argument("-p",  "--proxy",          type=str)
    parser.add_argument("-T",  "--timeout",        type=int, default=10)
    parser.add_argument("-t",  "--threads",        type=int, default=10)
    parser.add_argument("-a",  "--user-agent",     type=str, default="Penterep Tools")
    parser.add_argument("-c",  "--cookie",         type=str)
    parser.add_argument("-H",  "--headers",        type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-r",  "--redirects",      action="store_true")
    parser.add_argument("-vv",  "--verbose",       action="store_true")
    parser.add_argument("-C",  "--cache",          action="store_true")
    parser.add_argument("-j",  "--json",           action="store_true")
    parser.add_argument("-v",  "--version",        action='version', version=f'{SCRIPTNAME} {__version__}')

    parser.add_argument("--socket-address",          type=str, default=None)
    parser.add_argument("--socket-port",             type=str, default=None)
    parser.add_argument("--process-ident",           type=str, default=None)

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprint(help_print(get_help(), SCRIPTNAME, __version__))
        sys.exit(0)

    args = parser.parse_args()
    args.url = urlunparse(urlparse(args.url)._replace(path='', params='', query='', fragment=''))
    args.headers = ptnethelper.get_request_headers(args)
    args.proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else {}

    print_banner(SCRIPTNAME, __version__, args.json, 0)
    return args

def main():
    global SCRIPTNAME
    SCRIPTNAME = os.path.splitext(os.path.basename(__file__))[0]
    requests.packages.urllib3.disable_warnings()
    args = parse_args()
    script = PtTechnologies(args)
    script.run()

if __name__ == "__main__":
    main()