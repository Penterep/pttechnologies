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
from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses

from typing import List, Dict, Any, Optional
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
        self.response_favicon = responses.resp_favicon
        self.long_response = responses.long_resp
        self.http_resp = responses.http_resp
        self.https_resp = responses.https_resp
        self.http_invalid_method = responses.http_invalid_method
        self.http_invalid_protocol = responses.http_invalid_protocol
        self.http_invalid_version = responses.http_invalid_version

        self.definitions = self.helpers.load_definitions("hdrval.json")

        self.target_headers = self.definitions.get("headers", [
            "Server", "X-Powered-By", "X-Generator", "X-AspNet-Version", "X-AspNetMvc-Version"
        ])

    def run(self) -> None:
        """
        Execute the HDRVAL test logic.

        Analyzes headers from multiple HTTP responses (200, 400, favicon, long),
        combines them with source tracking, parses their content to extract
        technologies, classifies known ones based on definitions, and reports the results
        with specific source information for each technology.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        headers_200 = self._get_response_headers(self.response_hp)
        headers_400 = self._get_response_headers(self.raw_response_400) if self.raw_response_400 else {}
        headers_favicon = self._get_response_headers(self.response_favicon)
        headers_long = self._get_response_headers(self.long_response)
        headers_http = self._get_response_headers(self.http_resp)if self.http_resp is not None else {}
        headers_https = self._get_response_headers(self.https_resp)if self.https_resp is not None else {}
        headers_http_IM = self._get_response_headers(self.http_invalid_method)if self.http_invalid_method is not None else {}
        headers_http_IP = self._get_response_headers(self.http_invalid_protocol)if self.http_invalid_protocol is not None else {}
        headers_http_IV = self._get_response_headers(self.http_invalid_version)if self.http_invalid_version is not None else {}

        combined_headers = self._combine_headers({
            '200': headers_200,
            '400': headers_400,
            'favicon': headers_favicon,
            'long': headers_long,
            'HTTP': headers_http,
            'HTTPS': headers_https,
            'invalid_method': headers_http_IM,
            'invalid_protocol': headers_http_IP,
            'invalid_version': headers_http_IV,
        })

        if not combined_headers:
            ptprint("No headers available for analysis", "INFO", not self.args.json, indent=4)
            return

        headers_found = {}

        for header_name in self.target_headers:
            header_value = self._get_header_value(combined_headers, header_name)
            if header_value:
                headers_found[header_name] = header_value['value']

        if not headers_found:
            ptprint("No relevant headers found", "INFO", not self.args.json, indent=4)
            return

        found_technologies = []
        unclassified_technologies = []

        for header_name in self.target_headers:
            header_data = combined_headers.get(header_name.lower())
            if not header_data:
                continue

            for tech_data in header_data.get('technologies', []):
                tech = {
                    'name': tech_data['name'],
                    'version': tech_data['version']
                }
                classified = self._classify_technology(tech, headers_found[header_name], header_name)
                if classified:
                    classified['header'] = header_name
                    classified['tech_sources'] = tech_data['sources']
                    classified['tech_values'] = tech_data['source_values']
                    found_technologies.append(classified)
                else:
                    unclassified_technologies.append({
                        'name': tech['name'],
                        'version': tech['version'],
                        'header': header_name,
                        'tech_sources': tech_data['sources'],
                        'tech_values': tech_data['source_values']
                    })

        self._report(found_technologies, unclassified_technologies, headers_found, combined_headers)

    def _get_response_headers(self, response) -> Dict[str, str]:
        """
        Extract and normalize headers from an HTTP response object

        Args:
            response: HTTP response object.

        Returns:
            Dictionary of headers with lowercase keys.
        """
        headers = {}
        
        if response is not None and hasattr(response, 'headers'):
            headers = {k.lower(): v for k, v in dict(response.headers).items()}
        
            return headers

    def _combine_headers(self, source_headers: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, Any]]:
        """
        Combine headers from multiple sources with enhanced conflict resolution.

        Args:
            source_headers: Dictionary mapping source names to their headers

        Returns:
            Dictionary with header names as keys and dictionaries containing:
            - 'value': Combined header value (multiple values joined with ' | ')
            - 'sources': List of sources where this header was found
            - 'values_by_source': Mapping of source to specific value
            - 'unique_values': List of unique values found across all sources
            - 'technologies': List of parsed technologies with their sources and extracted values
        """
        combined = {}
        tech_detection_headers = [header.lower() for header in self.target_headers]

        for source_name, headers in source_headers.items():
            if not headers:
                continue

            for header_name, header_value in headers.items():
                header_lower = header_name.lower()
                if header_lower not in combined:
                    combined[header_lower] = {
                        'value': header_value,
                        'sources': [source_name],
                        'values_by_source': {source_name: header_value},
                        'unique_values': [header_value]
                    }
                else:
                    existing_data = combined[header_lower]
                    existing_data['values_by_source'][source_name] = header_value

                    if source_name not in existing_data['sources']:
                        existing_data['sources'].append(source_name)

                    if header_value not in existing_data['unique_values']:
                        existing_data['unique_values'].append(header_value)

                        if header_lower in tech_detection_headers:
                            existing_data['value'] = ' | '.join(existing_data['unique_values'])
                            
        for header_name, header_data in combined.items():
            if header_name in [h.lower() for h in self.target_headers]:
                technology_sources = {}  # tech_key -> list of sources
                
                # Parse technologies from each source value
                for source, value in header_data['values_by_source'].items():
                    technologies = self._parse_header_value(value, header_name)
                    
                    for tech in technologies:
                        tech_key = f"{tech['name']}:{tech.get('version', '')}"
                        if tech_key not in technology_sources:
                            technology_sources[tech_key] = {
                                'name': tech['name'],
                                'version': tech.get('version'),
                                'sources': [],
                                'values': {}
                            }
                        
                        if source not in technology_sources[tech_key]['sources']:
                            technology_sources[tech_key]['sources'].append(source)
                        
                        # Store the extracted value for this tech from this source
                        extracted = self._extract_technology_from_header(
                            tech['name'].lower(), tech.get('version'), value
                        )
                        technology_sources[tech_key]['values'][source] = extracted
                
                # Convert to list format
                header_data['technologies'] = [
                    {
                        'name': data['name'],
                        'version': data['version'],
                        'sources': data['sources'],
                        'source_values': data['values']
                    }
                    for data in technology_sources.values()
                ]
        return combined

    def _extract_technology_from_header(self, tech_name: str, version: Optional[str], header_value: str) -> str:
        """
        Extract the specific part of header value that contains the technology.
        
        Args:
            tech_name: Name of the technology (lowercase)
            version: Version of the technology
            header_value: Full header value
            
        Returns:
            Extracted technology string from header
        """
        # Try to find name/version pattern first
        if version:
            pattern = f"{re.escape(tech_name)}/{re.escape(version)}"
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                return match.group(0)
        
        # Look for technology name with any version
        pattern = f"{re.escape(tech_name)}(?:/[\\w\\.-]+)?"
        match = re.search(pattern, header_value, re.IGNORECASE)
        if match:
            return match.group(0)
        
        # Fallback - find the technology name in the string
        parts = header_value.split()
        for part in parts:
            if tech_name.lower() in part.lower():
                return part
        
        # Last fallback
        return f"{tech_name}/{version}" if version else tech_name

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
        elif header_name.lower() == "x-azure-ref":
            technologies.append({'name': 'x-azure-ref', 'version': None})
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
        - "Google Frontend"

        Args:
            header_value: Server header value.

        Returns:
            List of technology dictionaries.
        """
        technologies = []
        
        # Check for known compound names that shouldn't be split
        compound_servers = ["Google Frontend", "Microsoft-HTTPAPI", "Apache Tomcat"]
        for compound in compound_servers:
            if compound.lower() in header_value.lower():
                # Extract version if present
                pattern = f"{re.escape(compound)}(?:/([\\w\\.-]+))?"
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.group(1) else None
                    technologies.append({'name': compound, 'version': version})
                    # Remove this compound from further processing
                    header_value = re.sub(pattern, '', header_value, flags=re.IGNORECASE).strip()
        
        # Now process the remaining parts normally
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
                            if re.match(r'^[A-Za-z][A-Za-z0-9\-_]*', main_part):
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
                    if re.match(r'^[A-Za-z][A-Za-z0-9\-_]*', part):
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
                    if re.match(r'^[A-Za-z][A-Za-z0-9\-_\s]*$', part):
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
                        'category': definition.get('category', 'Unknown'),
                        'technology': definition.get('technology', technology['name']),
                        'name': technology['name'],
                        'version': technology['version'],
                        'description': f"{header_name}: {full_header}"
                    }

        return None

    def _store_technology(self, tech: Dict[str, Any], is_classified: bool) -> None:
        """
        Store detected technology in the storage system.
        
        Args:
            tech: Parsed or classified technology data
            is_classified: Whether the technology was matched against known definitions
        """
        
        if is_classified and tech.get('category') != 'Unknown':
            tech_type = tech['category']
        else:
            tech_type = None
        
        tech_name = tech.get('technology', tech['name'])
        version = tech.get('version')
        
        header_name = tech.get('header', 'Unknown')
        tech_values = tech.get('tech_values', {})
        tech_sources = tech.get('tech_sources', [])
        
        if tech_values and tech_sources:
            first_source = tech_sources[0]
            extracted_value = tech_values.get(first_source, tech_name)
            source_descriptions = [self._get_source_description(source) for source in tech_sources]
            sources_text = ', '.join(source_descriptions)
            description = f"{header_name}: {extracted_value} [{sources_text}]"
        else:
            description = f"{header_name}: {tech_name}"
        
        storage.add_to_storage(
            technology=tech_name,
            version=version,
            technology_type=tech_type,
            vulnerability="PTV-WEB-INFO-SRVHDR",
            description=description
        )

    def _get_source_description(self, source: str) -> str:
        """Map source names to their descriptive labels with status codes."""
        
        sc_http = getattr(self.http_resp, 'status_code', 0)
        sc_https = getattr(self.https_resp, 'status_code', 0)
        sc_im = getattr(self.http_invalid_method, 'status_code', 0)
        sc_ip = getattr(self.http_invalid_protocol, 'status_code', 0)
        sc_iv = getattr(self.http_invalid_version, 'status_code', 0)

        source_map = {
            '200': '200 HP',
            '400': '400 %', 
            'favicon': '200 FAVICON',
            'long': '400 LONGURL',
            'HTTP': f"{sc_http} HTTP",
            'HTTPS': f"{sc_https} HTTPS",
            'invalid_method': f"{sc_http} invalid method",
            'invalid_protocol': f"{sc_http} invalid protocol",
            'invalid_version': f"{sc_http} invalid version"

        }
        return source_map.get(source, source.upper())

    def _report(self, found_technologies: List[Dict[str, Any]], unclassified_technologies: List[Dict[str, Any]],
               headers_found: Dict[str, str], combined_headers: Dict[str, Dict[str, Any]]) -> None:
        """
        Output the results of the header analysis and update the JSON data model.

        Shows grouped header values when using verbose mode (-vv), displaying each
        unique header value with all sources where it was found.

        Args:
            found_technologies: List of technologies successfully classified.
            unclassified_technologies: List of technologies that were not matched.
            headers_found: Dictionary of headers that were present in the response.
            combined_headers: Combined headers data with source and technology information.
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
                    # Show each header value separately with sources (-vv)
                    header_data = combined_headers.get(header_name.lower(), {})
                    values_by_source = header_data.get('values_by_source', {})
                    
                    # Group identical values and combine their sources
                    value_to_sources = {}
                    for source, value in values_by_source.items():
                        if value not in value_to_sources:
                            value_to_sources[value] = []
                        value_to_sources[value].append(source)
                    
                    # Display each unique value with all its sources
                    for value, sources in value_to_sources.items():
                        source_descriptions = [self._get_source_description(source) for source in sources]
                        sources_text = ', '.join(source_descriptions)
                        ptprint(f"{header_name}: {value} [{sources_text}]", "ADDITIONS", not self.args.json, indent=8, colortext=True)

                for tech, is_classified in technologies_by_header[header_name]:
                    category_text = ""
                    if is_classified and 'category' in tech:
                        category_text = f" ({tech['category']})"
                    elif not is_classified:
                        category_text = " (Unknown)"

                    version_text = f" {tech['version']}" if tech.get('version') else ""
                    tech_name = tech.get('technology', tech['name'])

                    ptprint(f"{tech_name}{version_text}{category_text}", "VULN", not self.args.json, indent=8)

        for tech, is_classified in [
            *( (t, True) for t in found_technologies ),
            *( (t, False) for t in unclassified_technologies )
        ]:
            self._store_technology(tech, is_classified)


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the HDRVAL test."""
    HDRVAL(args, ptjsonlib, helpers, http_client, responses).run()