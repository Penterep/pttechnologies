"""
WampServer Detection Submodule

This submodule automatically detects WampServer homepage and extracts
technology information from the Server Configuration section.

When the WampServer homepage is detected via defpage module, this submodule:
- Detects Apache version
- Detects PHP version
- Detects Windows OS
- Detects MySQL version
- Detects MariaDB version

Functions:
    analyze: Entry point for analyzing WampServer homepage (called by defpage)
"""

import re
from typing import Dict, Any, List, Optional
from helpers.result_storage import storage
from helpers.products import get_product_manager


def analyze(tech_info: Dict[str, Any], args: object, helpers: object) -> Dict[str, Any]:
    """
    Analyze WampServer homepage for technology detection.
    Called by defpage module when WampServer patterns are detected.
    
    Args:
        tech_info: Dictionary containing response and basic technology info
        args: Arguments object containing configuration (verbose, json, etc.)
        helpers: Helpers object with load_definitions and fetch methods
        
    Returns:
        Enhanced technology information dictionary with detected components
    """
    response = tech_info.get('response')
    
    if not response:
        return tech_info
    
    content = getattr(response, 'text', getattr(response, 'body', ''))
    
    if not content:
        return tech_info
    
    patterns = _load_patterns(helpers, args)
    if patterns:
        detected = _analyze_content(content, patterns, args)
        if detected:
            _add_detected_to_info(tech_info, detected, args)
    
    return tech_info


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
        definitions = helpers.load_definitions("subdefinitions/wampserver.json")
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
    product_manager = get_product_manager()
    product = product_manager.get_product_by_id(product_id)
    if not product:
        return None
    
    technology_name = product.get('our_name', 'Unknown')
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


def _add_detected_to_info(tech_info: Dict[str, Any], detected: List[Dict[str, Any]], args: object) -> None:
    """
    Add detected components to tech_info dictionary.
    
    Args:
        tech_info: Main technology info dictionary
        detected: List of detected components
        args: Arguments object
    """
    if not detected:
        return
    
    if 'additional_info' not in tech_info:
        tech_info['additional_info'] = []
    
    unique = _deduplicate_components(detected)
    
    for component in unique:
        if component.get('product_id') is None:
            if not getattr(args, 'json', False):
                tech_info['additional_info'].append(f"WampServer Stack Detected")
            continue
        
        version_str = f" {component['version']}" if component.get('version') else ""
        category_str = f" ({component['category']})" if component.get('category') else ""
        probability_str = f" ({component.get('probability', 100)}%)"
        
        info_line = f"{component['technology']}{version_str}{category_str}{probability_str}"
        
        if not getattr(args, 'json', False):
            tech_info['additional_info'].append(info_line)
        
        storage.add_to_storage(
            technology=component['technology'],
            version=component.get('version'),
            technology_type=component['category'],
            probability=component.get('probability', 100),
            description=f"WampServer: {component['technology']}"
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
    source_priority = {'config_table': 4, 'server_software': 3, 'title': 2}
    
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

