"""
HDRVAL - HTTP Header Technology Fingerprinting Module
"""

import re
import uuid
import ssl
from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager

from typing import List, Dict, Any, Optional, Set, Tuple
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Test for the content of HTTP response headers"


class HeaderConstants:
    DEFAULT_PROBABILITY = 100
    
    PARSEABLE_HEADERS = {
        'server', 'x-powered-by', 'x-generator', 'x-aspnet-version',
        'x-aspnetmvc-version', 'x-framework', 'x-runtime', 'x-view-time',
        'x-request-duration', 'powered-by', 'x-built-with'
    }
    
    BLACKLIST_WORDS = {'with', 'from'}
    
    NON_TECH_HEADERS = {
        'expires', 'vary', 'cache-control', 'strict-transport-security',
        'content-type', 'content-length', 'content-encoding', 'date',
        'last-modified', 'etag', 'age', 'pragma', 'connection',
        'keep-alive', 'transfer-encoding', 'upgrade', 'accept-ranges',
        'content-range', 'content-disposition', 'content-language',
        'access-control-allow-origin', 'access-control-allow-methods',
        'access-control-allow-headers', 'access-control-max-age',
        'access-control-expose-headers', 'access-control-allow-credentials',
        'set-cookie', 'content-security-policy', 'content-security-policy-report-only',
        'x-content-security-policy', 'x-webkit-csp', 'referrer-policy',
        'permissions-policy', 'feature-policy', 'nel', 'report-to',
        'x-frame-options', 'x-xss-protection', 'x-content-type-options'
    }
    
    SPECIAL_TECHNOLOGIES = {
        'asp.net framework': {
            'category': 'Backend Framework',
            'technology': 'ASP.NET Framework',
            'name': 'ASP.NET Framework'
        },
        'asp.net mvc': {
            'category': 'Backend Framework',
            'technology': 'ASP.NET MVC',
            'name': 'ASP.NET MVC'
        }
    }
    
    COMPOUND_SERVERS = ["Google Frontend", "Microsoft-HTTPAPI", "Apache Tomcat"]
    
    TIME_HEADER_FRAMEWORKS = {
        'x-runtime': 'rails',
        'x-view-time': 'django',
        'x-request-duration': 'asp.net'
    }


class HeaderParser:
    def __init__(self):
        self.blacklist = HeaderConstants.BLACKLIST_WORDS
    
    def parse(self, header_name: str, header_value: str) -> List[Dict[str, Optional[str]]]:
        parser_map = {
            'server': self._parse_server,
            'x-powered-by': self._parse_powered_by,
            'x-generator': self._parse_powered_by,
            'x-aspnet-version': self._parse_aspnet_version,
            'x-aspnetmvc-version': self._parse_aspnetmvc_version,
            'x-azure-ref': lambda v: [{'name': 'x-azure-ref', 'version': None}],
        }
        
        if header_name.lower() in ['x-runtime', 'x-view-time', 'x-request-duration']:
            return self._parse_time_header(header_name.lower())
        
        parser = parser_map.get(header_name.lower(), self._parse_generic)
        return parser(header_value)
    
    def _parse_server(self, header_value: str) -> List[Dict[str, Optional[str]]]:
        technologies = []
        
        for compound in HeaderConstants.COMPOUND_SERVERS:
            if compound.lower() in header_value.lower():
                pattern = f"{re.escape(compound)}(?:/([\\w\\.-]+))?"
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.group(1) else None
                    technologies.append({'name': compound, 'version': version})
                    header_value = re.sub(pattern, '', header_value, flags=re.IGNORECASE).strip()
        
        parts = header_value.split()
        
        for part in parts:
            part = part.strip()
            if not part or part.lower() in self.blacklist:
                continue
            
            os_match = re.search(r'\(([^)]+)\)', part)
            if os_match:
                os_content = os_match.group(1).strip()
                if os_content not in ['codeit', '@RELEASE@']:
                    main_part = re.sub(r'\([^)]*\)', '', part).strip()
                    if main_part:
                        version_match = re.match(r'^([^/]+)/([^/\s]+)', main_part)
                        if version_match:
                            technologies.append({
                                'name': version_match.group(1),
                                'version': version_match.group(2)
                            })
                        else:
                            if re.match(r'^[A-Za-z][A-Za-z0-9\-_]*', main_part):
                                technologies.append({'name': main_part, 'version': None})
                    
                    technologies.append({'name': os_content, 'version': None})
            else:
                version_match = re.match(r'^([^/]+)/([^/\s]+)', part)
                if version_match:
                    technologies.append({
                        'name': version_match.group(1),
                        'version': version_match.group(2)
                    })
                else:
                    if re.match(r'^[A-Za-z][A-Za-z0-9\-_]*', part):
                        technologies.append({'name': part, 'version': None})
        
        return technologies
    
    def _parse_powered_by(self, header_value: str) -> List[Dict[str, Optional[str]]]:
        technologies = []
        cleaned_value = re.sub(r'\(.*?\)', '', header_value).strip()
        parts = re.split(r'[,;]', cleaned_value)
        
        for part in parts:
            part = part.strip()
            if not part or part.startswith(('http://', 'https://', 'www.')):
                continue
            
            version_match = re.match(r'^([^/\s]+)/([^/\s]+)', part)
            if version_match:
                technologies.append({
                    'name': version_match.group(1),
                    'version': version_match.group(2)
                })
            else:
                name_version_match = re.match(r'^([A-Za-z][A-Za-z0-9\-_\s\.]*?)\s+([0-9][0-9\.\-]*)', part)
                if name_version_match:
                    technologies.append({
                        'name': name_version_match.group(1).strip(),
                        'version': name_version_match.group(2).strip()
                    })
                else:
                    if re.match(r'^[A-Za-z][A-Za-z0-9\-_\s]*$', part):
                        technologies.append({'name': part, 'version': None})
        
        return technologies
    
    def _parse_aspnet_version(self, header_value: str) -> List[Dict[str, Optional[str]]]:
        version = header_value.strip()
        if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+.*', version):
            return [{'name': 'ASP.NET Framework', 'version': version}]
        return []
    
    def _parse_aspnetmvc_version(self, header_value: str) -> List[Dict[str, Optional[str]]]:
        version = header_value.strip()
        if re.match(r'^[0-9]+\.[0-9]+.*', version):
            return [{'name': 'ASP.NET MVC', 'version': version}]
        return []
    
    def _parse_time_header(self, header_name: str) -> List[Dict[str, Optional[str]]]:
        framework_name = HeaderConstants.TIME_HEADER_FRAMEWORKS.get(header_name.lower())
        if framework_name:
            return [{'name': framework_name, 'version': None}]
        return []
    
    def _parse_generic(self, header_value: str) -> List[Dict[str, Optional[str]]]:
        version_match = re.match(r'^([^/]+)/([^/\s]+)', header_value)
        if version_match:
            return [{
                'name': version_match.group(1),
                'version': version_match.group(2)
            }]
        return [{'name': header_value, 'version': None}]


class TechnologyMatcher:
    def __init__(self, definitions: Dict, wapp_definitions: List, product_manager):
        self.definitions = definitions
        self.wapp_definitions = wapp_definitions
        self.product_manager = product_manager
    
    def match_wappalyzer(self, header_name: str, header_value: str, 
                        detected_products: Set[int] = None, tech_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if not isinstance(self.wapp_definitions, list):
            return None
        
        for header_group in self.wapp_definitions:
            if header_group.get('header_name', '').lower() != header_name.lower():
                continue
            
            for pattern_def in header_group.get('patterns', []):
                product_id = pattern_def.get('product_id')
                if not product_id:
                    continue
                
                if tech_name:
                    product = self.product_manager.get_product_by_id(product_id)
                    if not product:
                        continue
                    
                    products = product.get('products', [])
                    technology_name = products[0] if products else product.get('our_name', '')
                    
                    if technology_name.lower() != tech_name.lower():
                        continue
                    
                    return self._build_tech_result(product, product_id, None, header_name, header_value, pattern_def, header_value)
                else:
                    regex_pattern = pattern_def.get('regex', '')
                    try:
                        match = re.search(regex_pattern, header_value, re.IGNORECASE)
                        if match:
                            product = self.product_manager.get_product_by_id(product_id)
                            if not product:
                                continue
                            
                            version = None
                            version_group = pattern_def.get('version_group')
                            if version_group and match.groups():
                                version = match.group(version_group)
                            
                            return self._build_tech_result(product, product_id, version, header_name, header_value)
                    except (re.error, TypeError, AttributeError):
                        continue
        
        return None
    
    def match_legacy_definitions(self, tech_name: str, full_header: str, 
                                 header_name: str, detected_products: Set[int] = None, 
                                 tech_version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        definitions = self.definitions.get('definitions', self.definitions)
        if isinstance(definitions, list):
            definition_list = definitions
        else:
            definition_list = [v for k, v in definitions.items() if k != 'headers']
        
        for definition in definition_list:
            if not isinstance(definition, dict) or 'content' not in definition:
                continue
            
            required_header = definition.get('header_name')
            if required_header and required_header.lower() != header_name.lower():
                continue
            
            is_regex = definition.get('regex', False)
            pattern = definition['content']
            
            match_found = False
            if is_regex:
                try:
                    if re.search(pattern, full_header, re.IGNORECASE):
                        match_found = True
                except (re.error, TypeError, AttributeError):
                    continue
            else:
                if pattern.lower() == tech_name.lower():
                    match_found = True
            
            if match_found:
                product_id = definition.get('product_id')
                if not product_id:
                    continue
                
                product = self.product_manager.get_product_by_id(product_id)
                if not product:
                    continue
                
                products = product.get('products', [])
                technology_name = products[0] if products else product.get('our_name', tech_name)
                display_name = product.get('our_name', tech_name)
                category_name = self.product_manager.get_category_name(product.get('category_id'))
                
                return {
                    'category': category_name,
                    'technology': technology_name,
                    'display_name': display_name,
                    'name': tech_name,
                    'version': tech_version,
                    'description': f"{header_name}: {full_header}",
                    'probability': definition.get('probability', HeaderConstants.DEFAULT_PROBABILITY),
                    'product_id': product_id
                }
        
        return None
    
    def _build_tech_result(self, product: Dict, product_id: int, version: Optional[str], 
                          header_name: str, header_value: str, 
                          pattern_def: Optional[Dict] = None, 
                          full_header: Optional[str] = None) -> Dict[str, Any]:
        products = product.get('products', [])
        technology_name = products[0] if products else product.get('our_name', '')
        display_name = product.get('our_name', '')
        category_name = self.product_manager.get_category_name(product.get('category_id'))
        
        if version is None and pattern_def and full_header:
            version_group = pattern_def.get('version_group')
            if version_group:
                try:
                    regex_pattern = pattern_def.get('regex', '')
                    match = re.search(regex_pattern, full_header, re.IGNORECASE)
                    if match and match.groups():
                        version = match.group(version_group)
                except (re.error, TypeError, AttributeError):
                    pass
        
        return {
            'category': category_name,
            'technology': technology_name,
            'display_name': display_name,
            'name': display_name,
            'version': version,
            'description': f"{header_name}: {header_value}",
            'probability': HeaderConstants.DEFAULT_PROBABILITY,
            'product_id': product_id
        }


class HDRVAL:
    def __init__(self, args: object, ptjsonlib: object, helpers: object, 
                 http_client: object, responses: StoredResponses) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.product_manager = get_product_manager()
        
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
        self.wapp_definitions = self.helpers.load_definitions("hdrval_from_wappalyzer.json")
        
        self.parser = HeaderParser()
        self.matcher = TechnologyMatcher(self.definitions, self.wapp_definitions, self.product_manager)
        
        self._init_target_headers()
    
    def _init_target_headers(self) -> None:
        base_headers = self.definitions.get("headers", [
            "Server", "X-Powered-By", "X-Generator", "X-AspNet-Version", "X-AspNetMvc-Version"
        ])
        
        if isinstance(self.wapp_definitions, list):
            wapp_headers = [h['header_name'] for h in self.wapp_definitions]
        else:
            wapp_headers = self.wapp_definitions.get("headers", [])
        
        all_headers = [h.lower() for h in (base_headers + wapp_headers)]
        self.target_headers = list(set(all_headers))
    
    def run(self) -> None:
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        
        all_responses = {
            '200': self.response_hp,
            '400': self.raw_response_400,
            'favicon': self.response_favicon,
            'long': self.long_response,
            'HTTP': self.http_resp,
            'HTTPS': self.https_resp,
            'invalid_method': self.http_invalid_method,
            'invalid_protocol': self.http_invalid_protocol,
            'invalid_version': self.http_invalid_version,
        }
        
        combined_headers = self._combine_all_headers(all_responses)
        
        if not combined_headers:
            ptprint("No headers available for analysis", "INFO", not self.args.json, indent=4)
            return
        
        headers_found = self._extract_target_headers(combined_headers)
        
        if not headers_found:
            ptprint("No relevant headers found", "INFO", not self.args.json, indent=4)
            return
        
        found_technologies, unclassified_technologies = self._analyze_headers(
            headers_found, combined_headers
        )
        
        self._report(found_technologies, unclassified_technologies, headers_found, combined_headers)
    
    def _combine_all_headers(self, all_responses: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        source_headers = {}
        for source_name, response in all_responses.items():
            if response is not None and hasattr(response, 'headers'):
                source_headers[source_name] = {k.lower(): v for k, v in dict(response.headers).items()}
        
        combined = self._merge_header_sources(source_headers)
        combined = self._parse_technologies_in_headers(combined)
        
        return combined
    
    def _merge_header_sources(self, source_headers: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, Any]]:
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
        
        return combined
    
    def _parse_technologies_in_headers(self, combined: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        for header_name, header_data in combined.items():
            if header_name not in [h.lower() for h in self.target_headers]:
                continue
            
            technology_sources = {}
            
            for source, value in header_data['values_by_source'].items():
                technologies = self.parser.parse(header_name, value)
                
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
                    
                    extracted = self._extract_technology_from_header(
                        tech['name'].lower(), tech.get('version'), value
                    )
                    technology_sources[tech_key]['values'][source] = extracted
            
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
    
    def _extract_technology_from_header(self, tech_name: str, version: Optional[str], 
                                       header_value: str) -> str:
        if version:
            pattern = f"{re.escape(tech_name)}/{re.escape(version)}"
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                return match.group(0)
        
        pattern = f"{re.escape(tech_name)}(?:/[\\w\\.-]+)?"
        match = re.search(pattern, header_value, re.IGNORECASE)
        if match:
            return match.group(0)
        
        parts = header_value.split()
        for part in parts:
            if tech_name.lower() in part.lower():
                return part
        
        return f"{tech_name}/{version}" if version else tech_name
    
    def _extract_target_headers(self, combined_headers: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
        headers_found = {}
        for header_name in self.target_headers:
            header_data = combined_headers.get(header_name.lower())
            if header_data:
                headers_found[header_name] = header_data['value']
        return headers_found
    
    def _analyze_headers(self, headers_found: Dict[str, str], 
                        combined_headers: Dict[str, Dict[str, Any]]) -> Tuple[List[Dict], List[Dict]]:
        found_technologies = []
        unclassified_technologies = []
        
        for header_name in self.target_headers:
            if header_name.lower() in HeaderConstants.NON_TECH_HEADERS:
                continue
            
            header_data = combined_headers.get(header_name.lower())
            if not header_data:
                continue
            
            if header_name.lower() in HeaderConstants.PARSEABLE_HEADERS:
                self._process_parseable_header(
                    header_name, header_data, headers_found,
                    found_technologies, unclassified_technologies
                )
            else:
                self._process_regex_header(
                    header_name, header_data, headers_found,
                    found_technologies
                )
        
        return found_technologies, unclassified_technologies
    
    def _process_parseable_header(self, header_name: str, header_data: Dict, 
                                  headers_found: Dict[str, str],
                                  found_technologies: List[Dict], 
                                  unclassified_technologies: List[Dict]) -> None:
        for tech_data in header_data.get('technologies', []):
            tech = {'name': tech_data['name'], 'version': tech_data['version']}
            
            classified = self._classify_technology(
                tech, headers_found[header_name], header_name
            )
            
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
    
    def _process_regex_header(self, header_name: str, header_data: Dict,
                             headers_found: Dict[str, str],
                             found_technologies: List[Dict]) -> None:
        header_value = headers_found.get(header_name, '')
        classified = self.matcher.match_wappalyzer(
            header_name, header_value, None
        )
        
        if classified:
            classified['header'] = header_name
            classified['tech_sources'] = header_data.get('sources', [])
            classified['tech_values'] = {header_name: header_value}
            found_technologies.append(classified)
    
    def _classify_technology(self, technology: Dict[str, Optional[str]], 
                           full_header: str, header_name: str) -> Optional[Dict[str, Any]]:
        tech_name = technology['name'].lower()
        
        result = self._try_special_handling(technology, full_header, header_name)
        if result:
            return result
        
        result = self.matcher.match_wappalyzer(
            header_name, full_header, None, tech_name
        )
        if result:
            return result
        
        result = self.matcher.match_legacy_definitions(
            tech_name, full_header, header_name, None, technology.get('version')
        )
        return result
    
    def _try_special_handling(self, technology: Dict[str, Optional[str]], 
                             full_header: str, header_name: str) -> Optional[Dict[str, Any]]:
        tech_name = technology['name'].lower()
        
        if tech_name in HeaderConstants.SPECIAL_TECHNOLOGIES:
            tech_config = HeaderConstants.SPECIAL_TECHNOLOGIES[tech_name]
            return {
                'category': tech_config['category'],
                'technology': tech_config['technology'],
                'name': tech_config['name'],
                'version': technology['version'],
                'description': f"{header_name}: {full_header}",
                'probability': HeaderConstants.DEFAULT_PROBABILITY
            }
        
        return None
    
    def _report(self, found_technologies: List[Dict[str, Any]], 
               unclassified_technologies: List[Dict[str, Any]],
               headers_found: Dict[str, str], 
               combined_headers: Dict[str, Dict[str, Any]]) -> None:
        if not found_technologies and not unclassified_technologies:
            ptprint("No technologies identified in headers", "INFO", not self.args.json, indent=4)
            return
        
        self._display_results(
            found_technologies, unclassified_technologies, 
            headers_found, combined_headers
        )
        self._store_results(found_technologies, unclassified_technologies)
    
    def _display_results(self, found_technologies: List[Dict[str, Any]], 
                        unclassified_technologies: List[Dict[str, Any]],
                        headers_found: Dict[str, str], 
                        combined_headers: Dict[str, Dict[str, Any]]) -> None:
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
            if header_name not in technologies_by_header:
                continue
            
            header_display = '-'.join(word.capitalize() for word in header_name.split('-'))
            ptprint(f"{header_display} header", "INFO", not self.args.json, indent=4)
            
            if self.args.verbose:
                self._display_header_sources(header_display, combined_headers)
            
            for tech, is_classified in technologies_by_header[header_name]:
                self._display_technology(tech, is_classified)
    
    def _display_header_sources(self, header_name: str, 
                                combined_headers: Dict[str, Dict[str, Any]]) -> None:
        header_data = combined_headers.get(header_name.lower(), {})
        values_by_source = header_data.get('values_by_source', {})
        
        value_to_sources = {}
        for source, value in values_by_source.items():
            if value not in value_to_sources:
                value_to_sources[value] = []
            value_to_sources[value].append(source)
        
        for value, sources in value_to_sources.items():
            source_descriptions = [self._get_source_description(source) for source in sources]
            sources_text = ', '.join(source_descriptions)
            ptprint(f"{header_name}: {value} [{sources_text}]", "ADDITIONS", 
                   not self.args.json, indent=8, colortext=True)
    
    def _display_technology(self, tech: Dict[str, Any], is_classified: bool) -> None:
        category_text = ""
        if is_classified and 'category' in tech:
            category_text = f" ({tech['category']})"
        elif not is_classified:
            category_text = " (Unknown)"
        
        version_text = f" {tech['version']}" if tech.get('version') else ""
        display_name = tech.get('display_name', tech.get('technology', tech.get('name', 'Unknown')))
        probability = tech.get('probability', HeaderConstants.DEFAULT_PROBABILITY)
        
        ptprint(f"{display_name}{version_text}{category_text}", "VULN", 
               not self.args.json, indent=8, end=" ")
        ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True)
    
    def _store_results(self, found_technologies: List[Dict[str, Any]], 
                      unclassified_technologies: List[Dict[str, Any]]) -> None:
        stored_products = set()
        
        for tech in found_technologies:
            product_id = tech.get('product_id')
            if product_id and product_id in stored_products:
                continue
            if product_id:
                stored_products.add(product_id)
            self._store_technology(tech, is_classified=True)
        
        for tech in unclassified_technologies:
            product_id = tech.get('product_id')
            if product_id and product_id in stored_products:
                continue
            if product_id:
                stored_products.add(product_id)
            self._store_technology(tech, is_classified=False)
    
    def _store_technology(self, tech: Dict[str, Any], is_classified: bool) -> None:
        if is_classified and tech.get('category') != 'Unknown':
            tech_type = tech['category']
        else:
            tech_type = None
        
        tech_name = tech.get('technology') or tech.get('name', 'Unknown')
        version = tech.get('version')
        product_id = tech.get('product_id')
        probability = tech.get('probability', HeaderConstants.DEFAULT_PROBABILITY)
        
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
            description=description,
            probability=probability,
            product_id=product_id
        )
    
    def _get_source_description(self, source: str) -> str:
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


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    HDRVAL(args, ptjsonlib, helpers, http_client, responses).run()
