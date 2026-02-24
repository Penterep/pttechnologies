"""
Module for identifying web author from HTML meta tags.

Analyzes HTML meta tags 'author', 'autor', 'web-author', 'web_author'
and 'reply-to' to identify the website author or contact email address.
Uses pre-fetched homepage response for efficiency.
"""

import re
from bs4 import BeautifulSoup
from ptlibs.ptprinthelper import ptprint
from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager

__TESTLABEL__ = "Test for author identification"


class AUTHOR:
    """
    Author identifier from HTML meta tags.

    Processes HTML meta tags 'author', 'autor', 'web-author', 'web_author'
    and 'reply-to' to identify the website author name or contact email address.
    Known CMS/platform authors are matched against predefined patterns.

    Attributes:
        args: Command line arguments and configuration.
        ptjsonlib: JSON processing library.
        helpers: Helper utilities for loading definitions.
        definitions: Loaded author patterns from author.json.
        response_hp: Pre-fetched homepage response.
    """

    def __init__(self, args, ptjsonlib, helpers, http_client, responses: StoredResponses):
        """
        Initialize the author identifier.

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
        self.product_manager = get_product_manager()
        self.response_hp = responses.resp_hp
        self.definitions = self.helpers.load_definitions("author.json")

    def run(self):
        """
        Main entry point for author identification.

        Extracts 'author' and 'reply-to' meta tags from the pre-fetched
        homepage response and identifies the author or contact information.

        Returns:
            None
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        html_content = self.response_hp.text
        meta_tags = self._extract_author_meta_tags(html_content)

        if not meta_tags:
            ptprint("No author meta tags found", "INFO", not self.args.json, indent=4)
            return

        found = self._analyze_author_tags(meta_tags)

        if not found:
            ptprint("No author information identified", "INFO", not self.args.json, indent=4)

    _AUTHOR_TAG_NAMES = {'author', 'autor', 'web-author', 'web_author', 'reply-to'}

    def _extract_author_meta_tags(self, html_content):
        """
        Extract author-related meta tags from HTML content.

        Looks for <meta name="author">, <meta name="autor">,
        <meta name="web-author">, <meta name="web_author">
        and <meta name="reply-to"> tags.

        Args:
            html_content: Raw HTML content string.

        Returns:
            dict: Dictionary of matched meta tag names (lowercased) and their content values.
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        meta_tags = {}

        for meta in soup.find_all('meta', attrs={'name': True, 'content': True}):
            name = meta.get('name', '').lower()
            content = meta.get('content', '').strip()
            if name in self._AUTHOR_TAG_NAMES and content:
                meta_tags[name] = content

        return meta_tags

    def _analyze_author_tags(self, meta_tags):
        """
        Analyze extracted author meta tags against known patterns.

        First checks if the author value corresponds to a known CMS/platform.
        If no pattern matches, displays the raw author value.
        Also handles 'reply-to' as a contact email address.

        Args:
            meta_tags: Dictionary of author-related meta tag names and content.

        Returns:
            int: Number of findings reported.
        """
        found = 0
        detected_products = set()

        for definition in (self.definitions or []):
            meta_name = definition.get("meta_name")
            patterns = definition.get("patterns", [])

            if meta_name not in meta_tags:
                continue

            content = meta_tags[meta_name]
            matched = False

            for pattern in patterns:
                product_id = pattern.get("product_id")
                if product_id in detected_products:
                    continue

                match = self._match_pattern(content, pattern)
                if match:
                    self._process_match(meta_name, content, pattern, match)
                    detected_products.add(product_id)
                    found += 1
                    matched = True

            if not matched:
                self._handle_raw_value(meta_name, content)
                found += 1

        for meta_name in meta_tags:
            defined_names = {d.get("meta_name") for d in (self.definitions or [])}
            if meta_name not in defined_names:
                self._handle_raw_value(meta_name, meta_tags[meta_name])
                found += 1

        return found

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
        product_id = pattern.get("product_id")
        if not product_id:
            return

        product = self.product_manager.get_product_by_id(product_id)
        if not product:
            return

        products = product.get('products', [])
        if products and products[0] is not None:
            technology = products[0]
        else:
            technology = product.get("our_name", "Unknown")
        display_name = product.get("our_name", "Unknown")
        technology_type = self.product_manager.get_category_name(product.get("category_id"))

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
            vulnerability="PTV-WEB-INFO-ANCOM",
            probability=probability,
            description=description,
            product_id=product_id
        )

        self._display_result(display_name, version, technology_type, meta_name, content, probability)

    def _handle_raw_value(self, meta_name, content):
        """
        Handle an author or reply-to value that didn't match any known pattern.

        Displays and stores the raw value as author information.

        Args:
            meta_name: Name of the meta tag ('author' or 'reply-to').
            content: Content of the meta tag.

        Returns:
            None
        """
        display_content = content[:80] + "..." if len(content) > 80 else content
        label_map = {
            "reply-to": "Reply-To",
            "web-author": "Web Author",
            "web_author": "Web Author",
            "autor": "Author",
            "author": "Author",
        }
        label = label_map.get(meta_name, "Author")
        description = self._create_description(meta_name, content)

        storage.add_to_storage(
            technology=display_content,
            version=None,
            technology_type=label,
            vulnerability="PTV-WEB-INFO-ANCOM",
            probability=100,
            description=description
        )

        probability = 100
        main_message = f"{display_content} ({label})"
        detail_message = f"<- Meta tag '{meta_name}': {content[:50]}{'...' if len(content) > 50 else ''}"

        ptprint(main_message, "VULN", not self.args.json, end=" ", indent=4)
        ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True, end="")
        if self.args.verbose:
            ptprint(f" {detail_message}", "ADDITIONS", not self.args.json, colortext=True)
        else:
            ptprint(" ")

    def _create_description(self, meta_name, content):
        """
        Create a description for the identified author value.

        Args:
            meta_name: Name of the meta tag.
            content: Content of the meta tag.

        Returns:
            str: Formatted description string.
        """
        display_content = content[:100] + "..." if len(content) > 100 else content
        return f"Meta tag '{meta_name}': {display_content}"

    def _display_result(self, technology, version, technology_type, meta_name, content, probability):
        """
        Display a matched technology result.

        Args:
            technology: Technology name.
            version: Technology version or None.
            technology_type: Type/category of the technology.
            meta_name: Meta tag name that provided the detection.
            content: Original meta tag content.
            probability: Confidence percentage.

        Returns:
            None
        """
        tech_display = technology
        if version:
            tech_display += f" {version}"

        main_message = f"{tech_display} ({technology_type})"
        detail_message = f"<- Meta tag '{meta_name}': {content[:50]}{'...' if len(content) > 50 else ''}"

        ptprint(main_message, "VULN", not self.args.json, end=" ", indent=4)
        ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True, end="")
        if self.args.verbose:
            ptprint(f" {detail_message}", "ADDITIONS", not self.args.json, colortext=True)
        else:
            ptprint(" ")


def run(args, ptjsonlib, helpers, http_client, responses: StoredResponses):
    """Entry point for running the Author meta tag detection."""
    AUTHOR(args, ptjsonlib, helpers, http_client, responses).run()
