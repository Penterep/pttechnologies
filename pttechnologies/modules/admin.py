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

_CMS_SPECIFIC_PATHS = {
    "WordPress": ["/wp-admin/", "/wp-login.php"],
    "Joomla":    ["/administrator/"],
    "Drupal":    ["/user/login"],
    "Kentico":   ["/CMSDesk", "/CMSModules/"],
}

_EXISTS_CODES = {200, 301, 302, 307, 308, 401, 403}
_REDIRECT_CODES = {301, 302, 307, 308}


class ADMIN:
    """
    ADMIN performs technology detection from admin interfaces and login pages.

    Two detection strategies:
      1. CMS-specific path probing: probe well-known paths; any non-404
         response reveals the CMS (even a 403).
      2. Content matching: analyze the /admin login page body against
         patterns in admin.json.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object,
                 http_client: object, responses: StoredResponses) -> None:
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
        """Run CMS path probing and /admin content checks."""
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        if not self.detection_patterns:
            ptprint("No admin technology definitions loaded from admin.json", "INFO", not self.args.json, indent=4)
            return

        self._check_cms_paths()
        self._check_admin_content()

        self._report_findings()

    def _check_cms_paths(self) -> None:
        """Probe CMS-specific paths; non-404 status implies presence."""
        base_url = self.args.url.rstrip("/")
        base_path = getattr(self.args, 'base_path', '') or ''

        already_detected = set()

        for tech_name, paths in _CMS_SPECIFIC_PATHS.items():
            for path in paths:
                if tech_name in already_detected:
                    break

                full_url = urljoin(base_url, f"{base_path}{path}" if base_path else path)
                try:
                    resp = self.http_client.send_request(
                        full_url, method="GET",
                        headers=self.args.headers,
                        allow_redirects=False,
                    )
                except Exception:
                    continue

                if resp is None:
                    continue

                status_code = getattr(resp, 'status_code', 0)
                if status_code not in _EXISTS_CODES:
                    continue

                effective_status = status_code
                if status_code in _REDIRECT_CODES:
                    effective_status = self._get_redirect_target_status(full_url) or status_code
                    if effective_status == 404:
                        continue

                tech_def = next((t for t in self.detection_patterns if t.get('name') == tech_name), None)
                if not tech_def:
                    continue

                if status_code in _REDIRECT_CODES and effective_status != status_code:
                    matched_text = f"HTTP {status_code} -> {effective_status} on {tech_name}-specific path ({path})"
                else:
                    matched_text = f"HTTP {status_code} on {tech_name}-specific path ({path})"
                tech_info = self._build_tech_info(tech_def, full_url, status_code, matched_text)
                if tech_info and not self._already_detected(tech_def.get('product_id')):
                    self.detected_technologies.append(tech_info)
                    already_detected.add(tech_name)

    def _get_redirect_target_status(self, url: str) -> Optional[int]:
        """Return final status code for a URL when redirects are followed."""
        try:
            redirect_resp = self.http_client.send_request(
                url, method="GET",
                headers=self.args.headers,
                allow_redirects=True,
            )
        except Exception:
            return None

        if redirect_resp is None:
            return None

        return getattr(redirect_resp, 'status_code', None)

    def _check_admin_content(self) -> None:
        """Analyze pre-fetched /admin response for login patterns."""
        if not self.response_admin:
            return

        content = getattr(self.response_admin, 'text', '') or ''
        if not content or not self._is_login_page(content):
            return

        status_code = getattr(self.response_admin, 'status_code', 0)
        url = getattr(self.response_admin, 'url', '') or urljoin(
            self.args.url,
            (getattr(self.args, 'base_path', '') or '') + '/admin'
        )

        for tech_def in self.detection_patterns:
            if self._already_detected(tech_def.get('product_id')):
                continue

            matched_text = self._match_patterns(tech_def, content)
            if not matched_text:
                continue

            tech_info = self._build_tech_info(tech_def, url, status_code, matched_text, content=content)
            if tech_info:
                self.detected_technologies.append(tech_info)

    def _already_detected(self, product_id) -> bool:
        """Return True if a technology with given product_id is already stored."""
        return any(t.get('product_id') == product_id for t in self.detected_technologies)

    def _is_login_page(self, content: str) -> bool:
        """Heuristic check whether HTML looks like a login page."""
        indicators = [
            r'<input[^>]*type=["\']password["\']',
            r'<form[^>]*login', r'login[^<]*form',
            r'username', r'password', r'sign\s+in', r'log\s+in',
        ]
        for indicator in indicators:
            if re.search(indicator, content, re.IGNORECASE):
                return True
        return False

    def _match_patterns(self, tech_def: Dict[str, Any], content: str) -> Optional[str]:
        """Return matched snippet from content if any pattern matches."""
        flags = tech_def.get('flags', 'is')
        re_flags = 0
        if 'i' in flags: re_flags |= re.IGNORECASE
        if 'm' in flags: re_flags |= re.MULTILINE
        if 's' in flags: re_flags |= re.DOTALL

        for pattern in tech_def.get('patterns', []):
            m = re.search(pattern, content, re_flags)
            if m:
                txt = m.group(0)
                return txt[:100] + ('...' if len(txt) > 100 else '')
        return None

    def _build_tech_info(self, tech_def: Dict[str, Any], url: str,
                         status_code: int, matched_text: str,
                         content: str = '') -> Optional[Dict[str, Any]]:
        """Assemble a normalized technology record for reporting/storage."""
        product_id = tech_def.get('product_id')
        product = self.product_manager.get_product_by_id(product_id)
        if not product:
            return None

        products = product.get('products', [])
        technology_name = products[0] if products else product.get('our_name', 'Unknown')
        display_name = product.get('our_name', 'Unknown')
        category_name = self.product_manager.get_category_name(product.get('category_id'))

        version = None
        flags = tech_def.get('flags', 'is')
        re_flags = (re.IGNORECASE if 'i' in flags else 0) | (re.DOTALL if 's' in flags else 0)
        for vp in tech_def.get('version_patterns', []):
            m = re.search(vp, content, re_flags)
            if m:
                version = m.group(1) if m.groups() else m.group(0)
                break

        return {
            'name': tech_def.get('name', 'Unknown'),
            'category': category_name,
            'technology': technology_name,
            'display_name': display_name,
            'product_id': product_id,
            'vendor': product.get('vendor'),
            'version': version,
            'url': url,
            'status_code': status_code,
            'matched_text': matched_text,
        }

    def _report_findings(self) -> None:
        """Print and persist detected technologies."""
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
            ptprint(f"{display_name}{version_text}{category_text}", "VULN", not self.args.json, indent=4)

            self._store_technology(tech)

    def _store_technology(self, tech: Dict[str, Any]) -> None:
        """Store a single detected technology in the shared storage."""
        tech_name = tech.get('technology', tech.get('name', 'Unknown'))
        version = tech.get('version')
        status_code = tech.get('status_code')

        description = f"Admin interface ({tech.get('url', 'unknown')}): {tech_name}"
        if version:
            description += f" {version}"
        if status_code:
            description += f" [HTTP {status_code}]"

        storage.add_to_storage(
            technology=tech_name,
            version=version,
            technology_type=tech.get('category'),
            vulnerability="PTV-WEB-INFO-TEADMIN",
            probability=100,
            description=description,
            product_id=tech.get('product_id'),
        )


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    ADMIN(args, ptjsonlib, helpers, http_client, responses).run()