"""
Apache Analyzer Submodule

This submodule analyzes Apache server-status and server-info pages
to extract detailed information about the Apache installation.
"""

import re
from bs4 import BeautifulSoup


def analyze(tech_info, args):
    """
    Analyzes Apache server response to extract detailed information.
    
    Args:
        tech_info (dict): Technology information from main module
        args (object): Command line arguments
        
    Returns:
        dict: Enhanced technology information
    """
    enhanced_info = {
        "additional_info": [],
        "version": None,
        "modules": [],
        "configuration": {}
    }
    
    response = tech_info.get("response")
    if not response or response.status_code != 200:
        return enhanced_info
    
    content = response.text
    file_path = tech_info.get("file_path", "")
    
    if "server-status" in file_path:
        enhanced_info.update(_analyze_server_status(content))
    elif "server-info" in file_path:
        enhanced_info.update(_analyze_server_info(content))
    
    return enhanced_info


def _analyze_server_status(content):
    """
    Analyzes Apache server-status page.
    
    Args:
        content (str): HTML content of server-status page
        
    Returns:
        dict: Extracted information
    """
    info = {
        "additional_info": [],
        "version": None,
        "configuration": {}
    }
    
    # Extract Apache version
    version_match = re.search(r'Apache/([0-9.]+)', content, re.IGNORECASE)
    if version_match:
        info["version"] = version_match.group(1)
        info["additional_info"].append(f"Apache version: {version_match.group(1)}")
    
    # Extract server uptime
    uptime_patterns = [
        r'Server uptime:\s*</dt>\s*<dd>([^<]+)</dd>',  # HTML definition list format
        r'Server uptime:\s*([^<\n]+?)(?:</[^>]+>|\n)',  # General pattern excluding HTML tags
        r'Server uptime:\s*(.+?)(?:<br>|\n)'  # Original fallback pattern
    ]
    
    for pattern in uptime_patterns:
        uptime_match = re.search(pattern, content, re.IGNORECASE)
        if uptime_match:
            uptime_text = uptime_match.group(1).strip()
            # Clean up any remaining HTML tags
            uptime_text = re.sub(r'<[^>]+>', '', uptime_text).strip()
            if uptime_text:
                info["additional_info"].append(f"Server uptime: {uptime_text}")
                break
    
    # Extract total requests
    requests_patterns = [
        r'Total accesses:\s*</dt>\s*<dd>([^<]+)</dd>',
        r'Total accesses:\s*([0-9,]+)',
        r'Total requests:\s*([0-9,]+)'
    ]
    
    for pattern in requests_patterns:
        requests_match = re.search(pattern, content, re.IGNORECASE)
        if requests_match:
            requests_text = requests_match.group(1).strip()
            requests_text = re.sub(r'<[^>]+>', '', requests_text).strip()
            if requests_text:
                info["additional_info"].append(f"Total requests: {requests_text}")
                break
    
    # Extract current requests
    current_patterns = [
        r'([0-9]+) requests currently being processed',
        r'Current requests:\s*</dt>\s*<dd>([^<]+)</dd>',
        r'Current requests:\s*([0-9]+)'
    ]
    
    for pattern in current_patterns:
        current_match = re.search(pattern, content, re.IGNORECASE)
        if current_match:
            current_text = current_match.group(1).strip()
            current_text = re.sub(r'<[^>]+>', '', current_text).strip()
            if current_text:
                info["additional_info"].append(f"Current requests: {current_text}")
                break
    
    # Extract server built date
    built_patterns = [
        r'Server Built:\s*</dt>\s*<dd>([^<]+)</dd>',
        r'Server Built:\s*([^<\n]+?)(?:</[^>]+>|\n)',
        r'Server built:\s*([^<\n]+?)(?:</[^>]+>|\n)'
    ]
    
    for pattern in built_patterns:
        built_match = re.search(pattern, content, re.IGNORECASE)
        if built_match:
            built_text = built_match.group(1).strip()
            built_text = re.sub(r'<[^>]+>', '', built_text).strip()
            if built_text:
                info["additional_info"].append(f"Server built: {built_text}")
                break
    
    return info


def _analyze_server_info(content):
    """
    Analyzes Apache server-info page.
    
    Args:
        content (str): HTML content of server-info page
        
    Returns:
        dict: Extracted information
    """
    info = {
        "additional_info": [],
        "version": None,
        "modules": [],
        "configuration": {}
    }
    
    soup = BeautifulSoup(content, 'html.parser')
    
    # Extract Apache version from title or headers
    title = soup.find('title')
    if title:
        version_match = re.search(r'Apache/([0-9.]+)', title.text, re.IGNORECASE)
        if version_match:
            info["version"] = version_match.group(1)
            info["additional_info"].append(f"Apache version: {version_match.group(1)}")
    
    # Extract loaded modules
    modules_section = soup.find('h2', string=lambda text: text and 'loaded modules' in text.lower())
    if modules_section:
        # Find the next table or list after modules header
        next_element = modules_section.find_next_sibling(['table', 'ul', 'ol', 'dl'])
        if next_element:
            if next_element.name == 'table':
                for row in next_element.find_all('tr')[1:]:  # Skip header row
                    cells = row.find_all(['td', 'th'])
                    if cells:
                        module_name = cells[0].get_text(strip=True)
                        if module_name and not module_name.lower() in ['module', 'name']:
                            info["modules"].append(module_name)
            else:
                for item in next_element.find_all(['li', 'dt']):
                    module_name = item.get_text(strip=True)
                    if module_name:
                        info["modules"].append(module_name)
    
    # Also try to find modules in plain text
    if not info["modules"]:
        module_matches = re.findall(r'mod_\w+', content, re.IGNORECASE)
        info["modules"] = list(set(module_matches))
    
    if info["modules"]:
        info["additional_info"].append(f"Loaded modules: {len(info['modules'])}")
        
        # Add some key modules to additional info
        key_modules = ['mod_ssl', 'mod_rewrite', 'mod_php', 'mod_python', 'mod_perl']
        found_key_modules = [mod for mod in info["modules"] if any(key in mod.lower() for key in key_modules)]
        if found_key_modules:
            info["additional_info"].append(f"Key modules: {', '.join(found_key_modules[:5])}")
    
    # Extract server root
    server_root_patterns = [
        r'Server Root:\s*</dt>\s*<dd>([^<]+)</dd>',
        r'Server Root:\s*([^<\n]+?)(?:</[^>]+>|\n)'
    ]
    
    for pattern in server_root_patterns:
        server_root_match = re.search(pattern, content, re.IGNORECASE)
        if server_root_match:
            root_text = server_root_match.group(1).strip()
            root_text = re.sub(r'<[^>]+>', '', root_text).strip()
            if root_text:
                info["configuration"]["server_root"] = root_text
                info["additional_info"].append(f"Server root: {root_text}")
                break
    
    # Extract config file
    config_patterns = [
        r'Config File:\s*</dt>\s*<dd>([^<]+)</dd>',
        r'Config File:\s*([^<\n]+?)(?:</[^>]+>|\n)'
    ]
    
    for pattern in config_patterns:
        config_match = re.search(pattern, content, re.IGNORECASE)
        if config_match:
            config_text = config_match.group(1).strip()
            config_text = re.sub(r'<[^>]+>', '', config_text).strip()
            if config_text:
                info["configuration"]["config_file"] = config_text
                info["additional_info"].append(f"Config file: {config_text}")
                break
    
    return info