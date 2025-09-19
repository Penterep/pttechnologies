"""
Module for identifying technologies from HTML meta tags.

Analyzes HTML meta tags such as generator, application-name, author,
framework, cms, and publisher to detect web technologies and their versions.
Uses pre-fetched homepage response for efficiency.
"""

import re
from bs4 import BeautifulSoup
from ptlibs.ptprinthelper import ptprint
from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses

__TESTLABEL__ = "Test for meta tag technology identification"


class Meta:
    """
    Meta tag analyzer for technology detection.
    
    Processes HTML meta tags to identify web technologies, frameworks,
    and content management systems based on predefined patterns.
    Uses already fetched homepage response for analysis.
    
    Attributes:
        args: Command line arguments and configuration.
        ptjsonlib: JSON processing library.
        helpers: Helper utilities for loading definitions.
        definitions: Loaded meta tag patterns from meta.json.
        response_hp: Pre-fetched homepage response.
    """
    
    def __init__(self, args, ptjsonlib, helpers, http_client, responses: StoredResponses):
        """
        Initialize the meta tag analyzer.
        
        Args:
            args: Command line arguments and configuration settings.
            ptjsonlib: JSON processing library instance.
            helpers: Helper utilities for loading configuration files.
            http_client: HTTP client instance.
            responses: Container with pre-fetched responses.
        """
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.response_hp = responses.resp_hp
        self.definitions = self.helpers.load_definitions("meta.json")
    
    def run(self):
        """
        Main entry point for meta tag analysis.
        
        Extracts meta tags from the pre-fetched homepage response
        and analyzes them for technology identification patterns.
        
        Returns:
            None
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        
        html_content = self.response_hp.text
        meta_tags = self._extract_meta_tags(html_content)
        
        if not meta_tags:
            ptprint("No meta tags found", "INFO", not self.args.json, indent=4)
            return
        
        technologies_found = self._analyze_meta_tags(meta_tags)
        
        if not technologies_found:
            ptprint("No technologies identified from meta tags", "INFO", not self.args.json, indent=4)
    
    def _extract_meta_tags(self, html_content):
        """
        Extract meta tags from HTML content.
        
        Args:
            html_content: Raw HTML content string.
            
        Returns:
            dict: Dictionary of meta tag names and their content values.
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        meta_tags = {}
        
        for meta in soup.find_all('meta', attrs={'name': True, 'content': True}):
            name = meta.get('name').lower()
            content = meta.get('content')
            if content:
                meta_tags[name] = content
        
        return meta_tags
    
    def _analyze_meta_tags(self, meta_tags):
        """
        Analyze extracted meta tags against known patterns.
        
        Args:
            meta_tags: Dictionary of meta tag names and content.
            
        Returns:
            int: Number of technologies found.
        """
        technologies_found = 0
        successfully_matched_tags = set()
        
        if self.definitions:
            for meta_definition in self.definitions:
                meta_name = meta_definition.get("meta_name")
                patterns = meta_definition.get("patterns", [])
                
                if meta_name in meta_tags:
                    content = meta_tags[meta_name]
                    matches = self._check_patterns(meta_name, content, patterns)
                    if matches > 0:
                        technologies_found += matches
                        successfully_matched_tags.add(meta_name)
        
        if 'author' in meta_tags and 'author' not in successfully_matched_tags:
            self._handle_unmatched_author(meta_tags['author'])
            technologies_found += 1
            successfully_matched_tags.add('author')
        
        interesting_meta_names = {'generator', 'application-name', 'framework', 'cms', 'publisher', 'X-Powered-By', 'platform'}
        for meta_name, content in meta_tags.items():
            if meta_name not in successfully_matched_tags and meta_name in interesting_meta_names:
                self._display_unknown_meta(meta_name, content)
                technologies_found += 1
        
        return technologies_found
    
    def _check_patterns(self, meta_name, content, patterns):
        """
        Check meta tag content against defined patterns.
        
        Args:
            meta_name: Name of the meta tag being analyzed.
            content: Content value of the meta tag.
            patterns: List of pattern definitions to check against.
            
        Returns:
            int: Number of matches found (max 1 per technology).
        """
        matches_found = 0
        detected_technologies = set()
        
        for pattern in patterns:
            technology = pattern.get("technology")
            
            if technology in detected_technologies:
                continue
                
            match = self._match_pattern(content, pattern)
            if match:
                self._process_match(meta_name, content, pattern, match)
                detected_technologies.add(technology)
                matches_found += 1
        
        return matches_found
    
    def _match_pattern(self, content, pattern):
        """
        Match content against a single pattern definition.
        
        Args:
            content: Meta tag content to analyze.
            pattern: Pattern definition dictionary.
            
        Returns:
            re.Match object or None if no match found.
        """
        regex = pattern.get("regex")
        if not regex:
            return None
        
        return re.search(regex, content, re.IGNORECASE)
    
    def _process_match(self, meta_name, content, pattern, match):
        """
        Process a successful pattern match and store results.
        
        Args:
            meta_name: Name of the meta tag that matched.
            content: Original meta tag content.
            pattern: Pattern definition that matched.
            match: Regex match object.
            
        Returns:
            None
        """
        technology = pattern.get("technology")
        technology_type = pattern.get("technology_type")
        probability = pattern.get("probability", 100)
        version_group = pattern.get("version_group")
        
        version = None
        if version_group and len(match.groups()) >= version_group:
            version = match.group(version_group)
        
        description = self._create_description(meta_name, content)
        
        storage.add_to_storage(
            technology=technology,
            version=version,
            technology_type=technology_type,
            probability=probability,
            description=description
        )
        
        self._display_result(technology, version, technology_type, meta_name, content)
    
    def _handle_unmatched_author(self, content):
        """
        Handle author meta tag that didn't match any specific pattern.
        
        Args:
            content: Content of the author meta tag.
            
        Returns:
            None
        """
        display_content = content[:80] + "..." if len(content) > 80 else content
        description = self._create_description('author', content)
        
        storage.add_to_storage(
            technology=display_content,
            version=None,
            technology_type="Author",
            probability=100,
            description=description
        )
        
        main_message = f"{display_content} (Author)"
        detail_message = f"<- Meta tag 'author': {content[:50]}{'...' if len(content) > 50 else ''}"
        
        ptprint(main_message, "VULN", not self.args.json, end="", indent=4)
        if self.args.verbose:
            ptprint(f" {detail_message}", "ADDITIONS", not self.args.json, colortext=True)
        else:
            ptprint(" ")
    
    def _create_description(self, meta_name, content):
        """
        Create a description for the identified technology.
        
        Args:
            meta_name: Name of the meta tag.
            content: Content of the meta tag.
            
        Returns:
            str: Formatted description string.
        """
        display_content = content[:100] + "..." if len(content) > 100 else content
        return f"Meta tag '{meta_name}': {display_content}"
    
    def _display_result(self, technology, version, technology_type, meta_name, content):
        """
        Display the identified technology result.
        
        Args:
            technology: Technology name.
            version: Technology version or None.
            technology_type: Type of technology.
            meta_name: Meta tag name that provided the detection.
            content: Original meta tag content.
            
        Returns:
            None
        """
        tech_display = technology
        if version:
            tech_display += f" {version}"
        
        type_display = self._format_type_display(technology_type)
        main_message = f"{tech_display} ({type_display})"
        detail_message = f"<- Meta tag '{meta_name}': {content[:50]}{'...' if len(content) > 50 else ''}"
        
        ptprint(main_message, "VULN", not self.args.json, end="", indent=4)
        if self.args.verbose:
            ptprint(f" {detail_message}", "ADDITIONS", not self.args.json, colortext=True)
        else:
            ptprint(" ")

    def _display_unknown_meta(self, meta_name, content):
        """
        Display unknown but potentially interesting meta tag content.
        
        Args:
            meta_name: Name of the meta tag.
            content: Content of the meta tag.
            
        Returns:
            None
        """
        display_content = content[:80] + "..." if len(content) > 80 else content
        main_message = f"{display_content} (Unknown)"
        detail_message = f"<- Meta tag '{meta_name}': {content[:50]}{'...' if len(content) > 50 else ''}"
        
        description = self._create_description(meta_name, content)
        storage.add_to_storage(
            technology=display_content,
            version=None,
            technology_type="Unknown",
            probability=100,
            description=description
        )

        ptprint(main_message, "VULN", not self.args.json, end="", indent=4)
        if self.args.verbose:
            ptprint(f" {detail_message}", "ADDITIONS", not self.args.json, colortext=True)
        else:
            ptprint(" ")

    def _format_type_display(self, technology_type):
        """
        Format technology type for display.
        
        Args:
            technology_type: Technology type string.
            
        Returns:
            str: Human-readable type string.
        """
        display_mapping = {
            "WebApp": "WebApp",
            "FrontendFramework": "Frontend Framework", 
            "BackendFramework": "Backend Framework",
            "Os": "OS",
            "WebServer": "Webserver",
            "Interpret": "Interpreter",
            "Author": "Author"
        }
        return display_mapping.get(technology_type, technology_type)


def run(args, ptjsonlib, helpers, http_client, responses: StoredResponses):
    """Entry point for running the Meta tag detection."""
    Meta(args, ptjsonlib, helpers, http_client, responses).run()