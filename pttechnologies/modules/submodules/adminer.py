"""
Adminer Detection Submodule

This submodule analyzes web pages to detect Adminer database management tool
and extract version information.

The module uses pattern matching to identify Adminer installations based solely
on pattern definitions from JSON file.

Functions:
    analyze: Entry point for analyzing pages for Adminer (called by SOURCES)
"""

import re
from typing import Dict, Any, List, Optional
from helpers.result_storage import storage
from helpers.products import get_product_manager


def analyze(tech_info: Dict[str, Any], args: object, helpers: object) -> Dict[str, Any]:
    """
    Analyze page content for Adminer detection.
    Called by SOURCES module when submodule is specified.
    
    Args:
        tech_info: Dictionary containing response and basic technology info
        args: Arguments object containing configuration (verbose, json, etc.)
        helpers: Helpers object with load_definitions method
        
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
    if not patterns:
        return tech_info
    
    detected_components = _analyze_content(content, patterns, args)

    unique_components = _deduplicate_components(detected_components)
    
    if unique_components:
        tech_info['additional_info'] = []
        
        for component in unique_components:
            version_str = f" {component['version']}" if component.get('version') else ""
            category_str = f" ({component['category']})" if component.get('category') else ""
            probability_str = f" ({component.get('probability', 100)}%)"
            
            info_lines = [f"{component['technology']}{version_str}{category_str}{probability_str}"]
            
            if component.get('matched_text'):
                info_lines.append(f"    Match: '{component['matched_text']}'")
            
            tech_info['additional_info'].append('\n'.join(info_lines))
            
            storage.add_to_storage(
                technology=component['technology'],
                version=component.get('version'),
                technology_type=component['category'],
                probability=component.get('probability', 100),
                description=f"Adminer Detection: {component['technology']}"
            )

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
        definitions = helpers.load_definitions("subdefinitions/adminer.json")
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
    
    if not patterns:
        return detected
    
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
        if args.verbose:
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
        'matched_text': match.group(0)[:100] + ('...' if len(match.group(0)) > 100 else ''),
        'pattern_used': pattern
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


def _deduplicate_components(components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate detected components, preferring more reliable sources.
    Priority: span_version (most reliable) > url_version > title
    
    Args:
        components: List of detected technology components
        
    Returns:
        Deduplicated list with priority handling
    """
    unique = {}
    source_priority = {'span_version': 3, 'url_version': 2, 'title': 1}
    
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
