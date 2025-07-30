"""
HDRVAL - HTTP Header Technology Fingerprinting Module

This module implements a test to analyze specific HTTP response headers and identify
technologies or software used by the target web server (e.g., frameworks, CMS, programming languages).

It examines headers such as `Server`, `X-Powered-By`, and `X-Generator`, parses their values,
and attempts to classify the extracted technology information using a definitions file (`hdrval.json`).

Includes:
- HDRVAL class to perform header parsing and classification.
- run() function as an entry point to execute the test.

Usage:
    HDRVAL(args, ptjsonlib, helpers, http_client, resp_hp, resp_404).run()
"""

import re
import uuid
import ssl
from helpers.stored_responses import StoredResponses

from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Test for the content of HTTP response headers"


class HDRVAL:
    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        """Initialize the HDRVAL test with provided components and load header definitions."""
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client

        # Unpack stored responses
        self.response_hp = responses.resp_hp
        self.response_404 = responses.resp_404
        self.raw_response_400 = responses.raw_resp_400

        self.definitions = self.helpers.load_definitions("hdrval.json")

        self.target_headers = self.definitions.get("headers", [
            "Server", "X-Powered-By", "X-Generator", "X-AspNet-Version", "X-AspNetMvc-Version"
        ])

    def run(self) -> None:
        """
        Execute the HDRVAL test logic.

        Analyzes the headers from the HTTP response (200) and raw HTTP response (400),
        combines them, parses their content to extract
        technologies, classifies known ones based on definitions, and reports the results.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        headers_200 = self._get_response_headers(self.response_hp)

        response_400 = self.raw_response_400
        headers_400 = self._get_response_headers(response_400) if response_400 else {}

        combined_headers = self._combine_headers(headers_200, headers_400)

        if not combined_headers:
            ptprint("No headers available for analysis", "INFO", not self.args.json, indent=4)
            return

        headers_found = {}
        header_sources = {}

        for header_name in self.target_headers:
            header_value = self._get_header_value(combined_headers, header_name)
            if header_value:
                headers_found[header_name] = header_value['value']
                header_sources[header_name] = header_value['sources']

        if not headers_found:
            ptprint("No relevant headers found", "INFO", not self.args.json, indent=4)
            return

        found_technologies = []
        unclassified_technologies = []

        for header_name, header_value in headers_found.items():
            technologies = self._parse_header_value(header_value, header_name)
            sources = header_sources[header_name]

            for tech in technologies:
                classified = self._classify_technology(tech, header_value, header_name)
                if classified:
                    classified['header'] = header_name
                    classified['sources'] = sources
                    found_technologies.append(classified)
                else:
                    unclassified_technologies.append({
                        'name': tech['name'],
                        'version': tech['version'],
                        'header': header_name,
                        'full_header': header_value,
                        'sources': sources
                    })

        self._report(found_technologies, unclassified_technologies, headers_found, header_sources)

    def _get_response_headers(self, response) -> Dict[str, str]:
        """
        Extract and normalize headers from an HTTP response object.

        Supports multiple response formats (e.g., with .headers, .msg, or .getheaders).

        Args:
            response: HTTP response object.

        Returns:
            Dictionary of headers with lowercase keys.
        """
        if not response:
            return {}

        headers = {}

        if hasattr(response, 'headers'):
            if hasattr(response.headers, 'items'):
                headers = {k.lower(): v for k, v in response.headers.items()}
            else:
                for header_name, header_value in response.headers:
                    headers[header_name.lower()] = header_value
        elif hasattr(response, 'msg') and hasattr(response.msg, 'items'):
            headers = {k.lower(): v for k, v in response.msg.items()}
        elif hasattr(response, 'getheaders'):
            for header_name, header_value in response.getheaders():
                headers[header_name.lower()] = header_value

        if hasattr(response, 'msg') and hasattr(response.msg, 'keys'):
            for key in response.msg.keys():
                if key.lower() not in headers:
                    headers[key.lower()] = response.msg[key]

        return headers

    def _combine_headers(self, headers_200: Dict[str, str], headers_400: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """
        Combine headers from 200 and 400 responses, keeping track of sources.

        Args:
            headers_200: Headers from 200 response.
            headers_400: Headers from 400 response.

        Returns:
            Dictionary with header names as keys and dictionaries containing 'value' and 'sources' as values.
        """
        combined = {}
        server_headers = [header.lower() for header in self.target_headers]

        for header_name, header_value in headers_200.items():
            combined[header_name] = {
                'value': header_value,
                'sources': ['200']
            }

        for header_name, header_value in headers_400.items():
            if header_name in combined:
                if combined[header_name]['value'] != header_value:
                    if header_name.lower() in server_headers:
                        combined[header_name] = {
                            'value': f"{combined[header_name]['value']} | {header_value}",
                            'sources': ['200', '400']
                        }
                    else:
                        combined[header_name]['sources'].append('400')
            else:
                combined[header_name] = {
                    'value': header_value,
                    'sources': ['400']
                }

        return combined

    def _get_header_value(self, headers: Dict[str, Dict[str, Any]], header_name: str) -> Optional[Dict[str, Any]]:
        """
        Safely retrieve a specific header value and sources (case-insensitive).

        Args:
            headers: Dictionary of combined response headers.
            header_name: Name of the header to retrieve.

        Returns:
            Dictionary with 'value' and 'sources' keys, or None if not present.
        """
        return headers.get(header_name.lower())

    def _parse_header_value(self, header_value: str, header_name: str) -> List[Dict[str, Optional[str]]]:
        """
        Parse a header value based on its type (Server, X-Powered-By, etc.).

        Args:
            header_value: Raw header value.
            header_name: Name of the header.

        Returns:
            A list of dictionaries containing 'name' and 'version' of detected technologies.
        """
        technologies = []

        if header_name.lower() == "server":
            technologies.extend(self._parse_server_header(header_value))
        elif header_name.lower() in ["x-powered-by", "x-generator"]:
            technologies.extend(self._parse_powered_by_header(header_value))
        elif header_name.lower() == "x-aspnet-version":
            technologies.extend(self._parse_aspnet_version_header(header_value))
        elif header_name.lower() == "x-aspnetmvc-version":
            technologies.extend(self._parse_aspnetmvc_version_header(header_value))
        else:
            technologies.extend(self._parse_generic_header(header_value))

        return technologies

    def _parse_server_header(self, header_value: str) -> List[Dict[str, Optional[str]]]:
        """
        Parse Server header which can contain multiple technologies.

        Examples:
        - "Apache/2.4.54 (Debian) PHP/5.6.40-0+deb8u9 OpenSSL/1.1.1n"
        - "nginx/1.18.0"
        - "nginx"
        - "Microsoft-IIS/10.0"

        Args:
            header_value: Server header value.

        Returns:
            List of technology dictionaries.
        """
        technologies = []
        parts = header_value.split()

        for part in parts:
            part = part.strip()
            if not part:
                continue

            os_match = re.search(r'\(([^)]+)\)', part)
            if os_match:
                os_content = os_match.group(1).strip()
                if os_content not in ['codeit', '@RELEASE@']:
                    # Process the main part first (e.g., "Apache/2.4.54" from "Apache/2.4.54(Ubuntu)")
                    main_part = re.sub(r'\([^)]*\)', '', part).strip()
                    if main_part:
                        version_match = re.match(r'^([^/]+)/([^/\s]+)', main_part)
                        if version_match:
                            name = version_match.group(1)
                            version = version_match.group(2)
                            technologies.append({'name': name, 'version': version})
                        else:
                            if re.match(r'^[A-Za-z][A-Za-z0-9\-_]*$', main_part):
                                technologies.append({'name': main_part, 'version': None})

                    # Then add the OS
                    technologies.append({'name': os_content, 'version': None})
            else:
                # Regular name/version pattern (e.g., "PHP/8.1.2", "OpenSSL/1.1.1n")
                version_match = re.match(r'^([^/]+)/([^/\s]+)', part)
                if version_match:
                    name = version_match.group(1)
                    version = version_match.group(2)
                    technologies.append({'name': name, 'version': version})
                else:
                    # Just the technology name without version (e.g., "nginx")
                    if re.match(r'^[A-Za-z][A-Za-z0-9\-_]*$', part):
                        technologies.append({'name': part, 'version': None})
        return technologies

    def _parse_powered_by_header(self, header_value: str) -> List[Dict[str, Optional[str]]]:
        """
        Parse X-Powered-By or X-Generator headers.

        Examples:
        - "PHP/8.3.8"
        - "Nette Framework 3"
        - "Drupal 9 (https://www.drupal.org)"
        - "ASP.NET"
        - "Express"
        - "IS VUT; www.vut.cz/cvis"

        Args:
            header_value: Header value.

        Returns:
            List of technology dictionaries.
        """
        technologies = []

        cleaned_value = re.sub(r'\(.*?\)', '', header_value).strip()

        parts = re.split(r'[,;]', cleaned_value)

        for part in parts:
            part = part.strip()
            if not part:
                continue

            if part.startswith('http://') or part.startswith('https://') or part.startswith('www.'):
                continue

            # Look for name/version pattern (e.g., "PHP/8.3.8")
            version_match = re.match(r'^([^/\s]+)/([^/\s]+)', part)
            if version_match:
                name = version_match.group(1)
                version = version_match.group(2)
                technologies.append({'name': name, 'version': version})
            else:
                # Look for "Name Version" pattern (e.g., "Nette Framework 3")
                name_version_match = re.match(r'^([A-Za-z][A-Za-z0-9\-_\s\.]*?)\s+([0-9][0-9\.\-]*)', part)
                if name_version_match:
                    name = name_version_match.group(1).strip()
                    version = name_version_match.group(2).strip()
                    technologies.append({'name': name, 'version': version})
                else:
                    # Just the technology name (e.g., "ASP.NET", "Express", "IS VUT")
                    if re.match(r'^[A-Za-z][A-Za-z0-9\-_\s\.]*$', part):
                        technologies.append({'name': part, 'version': None})

        return technologies

    def _parse_aspnet_version_header(self, header_value: str) -> List[Dict[str, Optional[str]]]:
        """
        Parse X-AspNet-Version header.

        Examples:
        - "4.0.30319"
        - "2.0.50727"

        Args:
            header_value: Header value.

        Returns:
            List of technology dictionaries with ASP.NET Framework name and version.
        """
        technologies = []
        
        # Clean and validate the version
        version = header_value.strip()
        if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+.*', version):
            technologies.append({
                'name': 'ASP.NET Framework',
                'version': version
            })
        
        return technologies

    def _parse_aspnetmvc_version_header(self, header_value: str) -> List[Dict[str, Optional[str]]]:
        """
        Parse X-AspNetMvc-Version header.

        Examples:
        - "5.2"
        - "4.0"
        - "3.0"

        Args:
            header_value: Header value.

        Returns:
            List of technology dictionaries with ASP.NET MVC name and version.
        """
        technologies = []
        
        version = header_value.strip()
        if re.match(r'^[0-9]+\.[0-9]+.*', version):
            technologies.append({
                'name': 'ASP.NET MVC',
                'version': version
            })
        
        return technologies

    def _parse_generic_header(self, header_value: str) -> List[Dict[str, Optional[str]]]:
        """
        Generic parser for other header types.

        Args:
            header_value: Header value.

        Returns:
            List of technology dictionaries.
        """
        technologies = []

        version_match = re.match(r'^([^/]+)/([^/\s]+)', header_value)
        if version_match:
            name = version_match.group(1)
            version = version_match.group(2)
            technologies.append({'name': name, 'version': version})
        else:
            technologies.append({'name': header_value, 'version': None})

        return technologies

    def _classify_technology(self, technology: Dict[str, Optional[str]], full_header: str,
                           header_name: str) -> Optional[Dict[str, Any]]:
        """
        Classify a technology based on definitions.

        Args:
            technology: Dictionary with 'name' and 'version' keys.
            full_header: Full header value for description.
            header_name: Name of the header.

        Returns:
            Classified technology dictionary or None if not found in definitions.
        """
        tech_name = technology['name'].lower()

        # Special handling for ASP.NET technologies
        if tech_name == 'asp.net framework':
            return {
                'category': 'framework',
                'technology': 'ASP.NET Framework',
                'name': 'ASP.NET Framework',
                'version': technology['version'],
                'description': f"{header_name}: {full_header}"
            }
        elif tech_name == 'asp.net mvc':
            return {
                'category': 'framework',
                'technology': 'ASP.NET MVC',
                'name': 'ASP.NET MVC',
                'version': technology['version'],
                'description': f"{header_name}: {full_header}"
            }

        definitions = self.definitions.get('definitions', self.definitions)
        if isinstance(definitions, list):
            definition_list = definitions
        else:
            definition_list = [v for k, v in definitions.items() if k != 'headers']

        for definition in definition_list:
            if isinstance(definition, dict) and 'content' in definition:
                if definition['content'].lower() == tech_name:
                    return {
                        'category': definition.get('category', 'unknown'),
                        'technology': definition.get('technology', technology['name']),
                        'name': technology['name'],
                        'version': technology['version'],
                        'description': f"{header_name}: {full_header}"
                    }

        return None

    def _add_software_node(self, tech: Dict[str, Any], is_classified: bool) -> None:
        """
        Add a software node to the ptjsonlib model.

        Args:
            tech: Parsed or classified technology.
            is_classified: Whether the technology was matched against known definitions.
        """
        node_key = str(uuid.uuid4())

        category_mapping = {
            'prgLanguage': 'swPrgLanguage',
            'webServer': 'swWebServer',
            'webServerModule': 'swWebServerModule',
            'framework': 'swFramework',
            'cms': 'swCms',
            'operatingSystem': 'swOperatingSystem'
        }

        sw_type = None
        if is_classified and tech.get('category') != 'unknown':
            sw_type = category_mapping.get(tech['category'])

        version = tech.get('version') if tech.get('version') else None

        if is_classified:
            description = tech.get('description')
            # Use the proper technology name from classification
            name = tech.get('technology', tech['name'])
        else:
            header_name = tech.get('header', 'Unknown')
            full_header = tech.get('full_header', tech['name'])
            description = f"{header_name}: {full_header}"
            name = tech['name']

        properties = {}

        if sw_type:
            properties["type"] = sw_type
        properties["name"] = name
        if version:
            properties["version"] = version
        properties["description"] = description

        node = {
            "type": "sw",
            "key": node_key,
            "parent": None,
            "parentType": None,
            "properties": properties,
            "vulnerabilities": []
        }

        self.ptjsonlib.add_node(node)

    def _report(self, found_technologies: List[Dict[str, Any]], unclassified_technologies: List[Dict[str, Any]],
               headers_found: Dict[str, str], header_sources: Dict[str, List[str]]) -> None:
        """
        Output the results of the header analysis and update the JSON data model.

        Args:
            found_technologies: List of technologies successfully classified.
            unclassified_technologies: List of technologies that were not matched.
            headers_found: Dictionary of headers that were present in the response.
            header_sources: Dictionary mapping header names to list of response sources.
        """
        if not found_technologies and not unclassified_technologies:
            ptprint("No technologies identified in headers", "INFO", not self.args.json, indent=4)
            return

        technologies_by_header = {}

        for tech in found_technologies:
            header_name = tech.get('header', 'Server')
            if header_name not in technologies_by_header:
                technologies_by_header[header_name] = []
            technologies_by_header[header_name].append((tech, True))

        for tech in unclassified_technologies:
            header_name = tech.get('header', 'Server')
            if header_name not in technologies_by_header:
                technologies_by_header[header_name] = []
            technologies_by_header[header_name].append((tech, False))

        for header_name in headers_found.keys():
            if header_name in technologies_by_header:
                ptprint(f"{header_name} header", "INFO", not self.args.json, indent=4)

                if self.args.verbose:
                    header_value = headers_found.get(header_name, '')
                    ptprint(f"{header_name}: {header_value}", "TEXT", not self.args.json, indent=10)

                for tech, is_classified in technologies_by_header[header_name]:
                    category_text = ""
                    if is_classified and 'category' in tech:
                        category_map = {
                            'prgLanguage': 'Programming language',
                            'webServer': 'Web server',
                            'webServerModule': 'Web server module',
                            'framework': 'Framework',
                            'cms': 'CMS',
                            'operatingSystem': 'Operating system'
                        }
                        category_text = f" ({category_map.get(tech['category'], tech['category'])})"
                    elif not is_classified:
                        category_text = " (unknown)"

                    version_text = f" {tech['version']}" if tech.get('version') else ""
                    tech_name = tech.get('technology', tech['name'])

                    ptprint(f"{tech_name}{version_text}{category_text}", "VULN", not self.args.json, indent=10)

        if found_technologies or unclassified_technologies:
            self.ptjsonlib.add_vulnerability("PTV-WEB-INFO-OSSEN")

        for tech, is_classified in [
            *( (t, True) for t in found_technologies ),
            *( (t, False) for t in unclassified_technologies )
        ]:
            self._add_software_node(tech, is_classified)


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the HDRVAL test."""
    HDRVAL(args, ptjsonlib, helpers, http_client, responses).run()