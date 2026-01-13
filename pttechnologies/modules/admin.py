"""
ADMIN - Admin Interface Technology Detection Module

This module analyzes admin interface pages (typically /admin) to identify
technologies used by the web application. It detects CMS systems like
WordPress, Drupal, Kentico, Joomla, and others from login pages and
admin interfaces, including version information when available.

Classes:
    ADMIN: Main detector class.

Functions:
    run: Entry point to execute the detection.

Usage:
    ADMIN(args, ptjsonlib, helpers, http_client, responses).run()
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from helpers.products import get_product_manager
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Test admin interface for technology identification"


class ADMIN:
    """
    ADMIN performs technology detection from admin interfaces and login pages.
    
    This class analyzes the /admin response to identify CMS systems and
    their versions based on characteristic patterns in login pages.
    """
    
    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        """Initialize the ADMIN test with provided components."""
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.product_manager = get_product_manager()
        self.response_admin = responses.resp_admin
        self.detected_technologies = []
        self.admin_definitions = self.helpers.load_definitions("admin.json")
        self.detection_patterns = self.admin_definitions.get('technologies', []) if self.admin_definitions else []
        
    def run(self) -> None:
        """
        Execute the ADMIN test logic.
        
        Analyzes the /admin response to detect technologies from login pages
        and admin interfaces.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        
        if not self.response_admin:
            ptprint("No admin response available", "INFO", not self.args.json, indent=4)
            return
            
        content = getattr(self.response_admin, 'text', '')
        if not content:
            ptprint("Admin response has no content", "INFO", not self.args.json, indent=4)
            return
        
        # Check if this looks like a login page
        if not self._is_login_page(content):
            if self.args.verbose:
                ptprint("Admin page does not appear to be a login page", "ADDITIONS", not self.args.json, indent=4, colortext=True)
            return
        
        if not self.detection_patterns:
            ptprint("No admin technology definitions loaded from admin.json", "INFO", not self.args.json, indent=4)
            return
        
        # Analyze content for technologies
        for tech_def in self.detection_patterns:
            tech_info = self._detect_technology(content, tech_def)
            if tech_info:
                self.detected_technologies.append(tech_info)
        
        self._report_findings()
    
    def _is_login_page(self, content: str) -> bool:
        """
        Check if the content appears to be a login page.
        
        Args:
            content: HTML content to check
            
        Returns:
            True if content appears to be a login page, False otherwise
        """
        login_indicators = [
            r'<input[^>]*type=["\']password["\']',
            r'<form[^>]*login',
            r'login[^<]*form',
            r'username',
            r'password',
            r'sign\s+in',
            r'log\s+in',
        ]
        
        content_lower = content.lower()
        for indicator in login_indicators:
            if re.search(indicator, content_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _detect_technology(self, content: str, tech_def: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect a specific technology from content.
        
        Args:
            content: HTML content to analyze
            tech_def: Technology definition with patterns
            
        Returns:
            Technology information dict if detected, None otherwise
        """
        patterns = tech_def.get('patterns', [])
        flags = tech_def.get('flags', 'is')  # Default: case-insensitive, dotall
        
        # Parse flags
        re_flags = 0
        if 'i' in flags.lower():
            re_flags |= re.IGNORECASE
        if 'm' in flags.lower():
            re_flags |= re.MULTILINE
        if 's' in flags.lower():
            re_flags |= re.DOTALL
        
        # Check if any pattern matches and capture the match
        matched_text = None
        matched = False
        for pattern in patterns:
            match = re.search(pattern, content, re_flags)
            if match:
                matched = True
                matched_text = match.group(0)[:100] + ('...' if len(match.group(0)) > 100 else '')
                break
        
        if not matched:
            return None
        
        # Get product info
        product_id = tech_def.get('product_id')
        product = self.product_manager.get_product_by_id(product_id)
        if not product:
            return None
        
        products = product.get('products', [])
        technology_name = products[0] if products else product.get('our_name', 'Unknown')
        display_name = product.get('our_name', 'Unknown')
        category_name = self.product_manager.get_category_name(product.get('category_id'))
        
        # Try to detect version
        version = None
        version_patterns = tech_def.get('version_patterns', [])
        for version_pattern in version_patterns:
            match = re.search(version_pattern, content, re_flags)
            if match:
                version = match.group(1) if match.groups() else match.group(0)
                break
        
        return {
            'name': tech_def.get('name', 'Unknown'),
            'category': category_name,
            'technology': technology_name,
            'display_name': display_name,
            'product_id': product_id,
            'vendor': product.get('vendor'),
            'version': version,
            'url': getattr(self.response_admin, 'url', urljoin(self.args.url, (getattr(self.args, 'base_path', '') + '/admin') if getattr(self.args, 'base_path', '') else '/admin')),
            'status_code': getattr(self.response_admin, 'status_code', 0),
            'matched_text': matched_text
        }
    
    def _report_findings(self) -> None:
        """
        Report detected technologies and store them.
        """
        if not self.detected_technologies:
            ptprint("No technologies identified from admin interface", "INFO", not self.args.json, indent=4)
            return
        
        for tech in self.detected_technologies:
            version_text = f" {tech['version']}" if tech.get('version') else ""
            category_text = f" ({tech['category']})" if tech.get('category') else ""
            
            if self.args.verbose:
                ptprint(f"Detected from: {tech.get('url', 'unknown')}", 
                       "ADDITIONS", not self.args.json, indent=4, colortext=True)
                if tech.get('matched_text'):
                    ptprint(f"Match: '{tech.get('matched_text')}'", 
                           "ADDITIONS", not self.args.json, indent=4, colortext=True)
            
            display_name = tech.get('display_name', tech.get('technology', 'Unknown'))
            ptprint(f"{display_name}{version_text}{category_text}", 
                   "VULN", not self.args.json, indent=4)
            
            self._store_technology(tech)
    
    def _store_technology(self, tech: Dict[str, Any]) -> None:
        """
        Store detected technology in the storage system.
        
        Args:
            tech: Detected technology information
        """
        tech_name = tech.get('technology', tech.get('name', 'Unknown'))
        version = tech.get('version')
        tech_type = tech.get('category')
        product_id = tech.get('product_id')
        url = tech.get('url', 'unknown')
        status_code = tech.get('status_code')
        
        description = f"Admin interface ({url}): {tech_name}"
        if version:
            description += f" {version}"
        if status_code:
            description += f" [HTTP {status_code}]"
        
        storage.add_to_storage(
            technology=tech_name,
            version=version,
            technology_type=tech_type,
            probability=100,
            description=description,
            product_id=product_id
        )


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the ADMIN test."""
    ADMIN(args, ptjsonlib, helpers, http_client, responses).run()

