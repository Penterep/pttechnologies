"""
phpMyAdmin Documentation Detection Submodule

This submodule automatically checks phpMyAdmin documentation at
/doc/html/index.html to extract version information.

When phpMyAdmin is detected, this module:
- Automatically tests /phpmyadmin/doc/html/index.html
- Extracts version from documentation if available

Functions:
    analyze: Entry point for analyzing phpMyAdmin documentation (called by SOURCES)
"""

import re
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin
from helpers.result_storage import storage
from helpers.products import get_product_manager


def analyze(tech_info: Dict[str, Any], args: object, helpers: object) -> Dict[str, Any]:
    """
    Analyze phpMyAdmin documentation for version detection.
    Called by SOURCES module when phpMyAdmin is detected.
    
    Args:
        tech_info: Dictionary containing response and basic technology info
        args: Arguments object containing configuration (verbose, json, etc.)
        helpers: Helpers object with load_definitions and fetch methods
        
    Returns:
        Enhanced technology information dictionary with detected components
    """
    base_url = tech_info.get('url', '')
    
    if not base_url:
        return tech_info
    
    doc_url = _build_doc_url(base_url)
    
    if doc_url:
        doc_info = _check_documentation(doc_url, args, helpers)
        if doc_info:
            _add_detected_to_info(tech_info, doc_info)
    
    return tech_info


def _build_doc_url(base_url: str) -> Optional[str]:
    """
    Build documentation URL from base phpMyAdmin URL.
    
    Args:
        base_url: Base URL where phpMyAdmin was found
        
    Returns:
        Documentation URL
    """
    base_url = base_url.rstrip('/')
    if not base_url.endswith('/'):
        base_url += '/'
    
    doc_path = 'doc/html/index.html'
    doc_url = urljoin(base_url, doc_path)
    
    return doc_url


def _check_documentation(doc_url: str, args: object, helpers: object) -> List[Dict[str, Any]]:
    """
    Fetch and analyze phpMyAdmin documentation page.
    
    Args:
        doc_url: URL to documentation index
        args: Arguments object
        helpers: Helpers object with fetch method
        
    Returns:
        List of detected components from documentation
    """
    try:        
        doc_response = helpers.fetch(doc_url)
        
        if doc_response and doc_response.status_code == 200:
            doc_content = getattr(doc_response, 'text', getattr(doc_response, 'body', ''))
            
            if doc_content:
                patterns = _load_patterns(helpers, args)
                if patterns:
                    detected = _analyze_content(doc_content, patterns, args)
                    return detected
        
    except Exception as e:
        return []
    return []


def _load_patterns(helpers: object, args: object) -> List[Dict[str, Any]]:
    """
    Load pattern definitions from JSON file.
    
    Args:
        helpers: Helpers object with load_definitions method
        args: Arguments object
        
    Returns:
        List of pattern definitions
    """
    try:        
        definitions = helpers.load_definitions("subdefinitions/phpmyadmin.json")
        return definitions.get('patterns', []) if definitions else []
    except Exception as e:
        return []


def _analyze_content(content: str, patterns: List[Dict[str, Any]], args: object) -> List[Dict[str, Any]]:
    """
    Analyze content against all pattern definitions.
    
    Args:
        content: Page content
        patterns: Pattern definitions from JSON
        args: Configuration arguments
        
    Returns:
        List of detected technologies
    """
    detected = []
    
    for pattern_def in patterns:
        match_result = _match_pattern(content, pattern_def, args)
        if match_result:
            detected.append(match_result)
    
    return detected


def _match_pattern(content: str, pattern_def: Dict[str, Any], args: object) -> Optional[Dict[str, Any]]:
    """
    Match content against a specific pattern definition.
    
    Args:
        content: Page content to analyze
        pattern_def: Pattern definition from JSON
        args: Configuration arguments
        
    Returns:
        Technology information if matched, None otherwise
    """
    pattern = pattern_def.get('pattern', '')
    if not pattern:
        return None
    
    flags = pattern_def.get('flags', 'i')
    re_flags = 0
    if 'i' in flags.lower():
        re_flags |= re.IGNORECASE
    if 'm' in flags.lower():
        re_flags |= re.MULTILINE
    if 's' in flags.lower():
        re_flags |= re.DOTALL
    
    try:
        match = re.search(pattern, content, re_flags)
    except re.error as e:
        return None
    
    if not match:
        return None
    
    # Get product info from product_id
    product_id = pattern_def.get('product_id')
    if not product_id:
        return None  # Skip if no product_id defined
    
    product_manager = get_product_manager()
    product = product_manager.get_product_by_id(product_id)
    if not product:
        return None
    
    products = product.get('products', [])
    technology_name = products[0] if products else product.get('our_name', 'Unknown')
    category_name = product_manager.get_category_name(product.get('category_id'))
    
    result = {
        'name': pattern_def.get('name', 'Unknown'),
        'product_id': product_id,
        'technology': technology_name,
        'category': category_name,
        'version': None,
        'probability': pattern_def.get('probability', 100),
        'source': pattern_def.get('source', 'unknown'),
        'matched_text': match.group(0)[:100] + ('...' if len(match.group(0)) > 100 else '')
    }
    
    version_pattern = pattern_def.get('version_pattern')
    if version_pattern:
        try:
            version_match = re.search(version_pattern, content, re_flags)
            if version_match:
                result['version'] = version_match.group(1) if version_match.groups() else version_match.group(0)
        except re.error:
            pass
    elif match.groups():
        result['version'] = match.group(1)
    
    return result


def _add_detected_to_info(tech_info: Dict[str, Any], detected: List[Dict[str, Any]]) -> None:
    """
    Add detected components to tech_info dictionary.
    
    Args:
        tech_info: Main technology info dictionary
        detected: List of detected components
    """
    if not detected:
        return
    
    if 'additional_info' not in tech_info:
        tech_info['additional_info'] = []
    
    unique = _deduplicate_components(detected)
    
    for component in unique:
        version_str = f" {component['version']}" if component.get('version') else ""
        category_str = f" ({component['category']})" if component.get('category') else ""
        probability_str = f" ({component.get('probability', 100)}%)"
        
        info_lines = [f"{component['technology']}{version_str}{category_str}{probability_str}"]
        
        if component.get('matched_text'):
            info_lines.append(f"    Match: '{component['matched_text']}'")
        
        tech_info['additional_info'].append('\n'.join(info_lines))
        
        # Get vendor from product if product_id is available
        product_id = component.get('product_id')
        
        storage.add_to_storage(
            technology=component['technology'],
            version=component.get('version'),
            technology_type=component['category'],
            probability=component.get('probability', 100),
            description=f"phpMyAdmin Documentation: {component['technology']}",
            product_id=product_id
        )


def _deduplicate_components(components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate detected components, preferring more reliable sources.
    
    Args:
        components: List of detected technology components
        
    Returns:
        Deduplicated list with priority handling
    """
    unique = {}
    source_priority = {'title': 4, 'nav_item': 3, 'footer': 2, 'h1': 1}
    
    for component in components:
        tech_key = component['technology'].lower()
        
        if tech_key not in unique:
            unique[tech_key] = component
        else:
            existing_priority = source_priority.get(unique[tech_key].get('source', ''), 0)
            new_priority = source_priority.get(component.get('source', ''), 0)
            
            if new_priority > existing_priority:
                unique[tech_key] = component
            elif new_priority == existing_priority and component.get('version') and not unique[tech_key].get('version'):
                unique[tech_key] = component
    
    return list(unique.values())