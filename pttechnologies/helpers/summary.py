"""
Module for generating summary output of identified technologies.

Provides both console output with formatted tables and JSON output
with structured nodes and properties for vulnerability scanning results.
"""

import json
import uuid
import sys
from helpers.result_storage import storage
from helpers.products import get_product_manager
from ptlibs.ptprinthelper import ptprint

class Summary:
    """
    Summary generator for vulnerability scan results.
    
    Processes stored scan results to generate either formatted console output
    or structured JSON output containing identified technologies, their
    probabilities, and associated metadata.
    
    Attributes:
        args: Command line arguments and configuration.
        ptjsonlib: JSON processing library instance.
        product_manager: ProductManager instance for product and category definitions.
    """
    
    def __init__(self, args, ptjsonlib):
        """
        Initialize the summary generator.
        
        Args:
            args: Command line arguments and configuration settings.
            ptjsonlib: JSON processing library instance.
        """
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.product_manager = get_product_manager()
        
        # Legacy category mapping for backward compatibility
        self.legacy_categories = {
            "Operating System": ["Os"],
            "Web Server": ["WebServer"],
            "Web App": ["WebApp"],
            "Proxy / WAF": ["Proxy", "WAF", "CDN","ELB"],
            "Plugins": ["Plugin"],
            "Templates": ["Template"],
            "Database": ["Database"],
            "Programming Language": ["Interpret", "BackendFramework", "FrontendFramework"],
            "Other": []
        }
        
        # Load categories from definitions
        self.categories = self._load_categories()
    
    def _load_categories(self):
        """
        Load categories from product_categories.json or use legacy mapping.
        
        Returns:
            dict: Category mapping (category name -> list of technology types)
        """
        try:
            categories_data = self.product_manager.get_categories()
            # Build a dict: category_name -> category_id
            category_map = {}
            for cat in categories_data:
                cat_name = cat.get('name', 'Other')
                # Store category for later mapping
                category_map[cat_name] = []
            return category_map if category_map else self.legacy_categories
        except Exception:
            return self.legacy_categories
    
    def run(self):
        """
        Main entry point for summary generation.
        
        Generates either console output or JSON output based on configuration.
        Returns early if no scan results are available.
        
        Returns:
            None
        """
        if not storage.get_all_records():
            return
        
        if self.args.json:
            self._generate_json_output()
        else:
            self._generate_console_output()
    
    def _generate_console_output(self):
        """
        Generate formatted console output showing identified technologies by categories.
        
        Displays technologies grouped by category, sorted by probability in descending order.
        
        Returns:
            None
        """
        ptprint("Summary: Identified Technologies", "TITLE", True, colortext=True, newline_above=True)
        
        technologies = storage.get_technologies_with_version()
        
        if not technologies:
            ptprint("No technologies identified", "INFO", True, indent=4)
            return
        
        categorized_techs = self._categorize_technologies(technologies)
        
        for category_name in self.categories.keys():
            techs_in_category = categorized_techs.get(category_name, [])
            if techs_in_category or category_name != "Other":
                self._display_category(category_name, techs_in_category)
    
    def _categorize_technologies(self, technologies):
        """
        Categorize technologies based on their type and calculate probabilities.
        
        Args:
            technologies: List of technology information dictionaries.
            
        Returns:
            Dictionary with categories as keys and lists of technology info as values.
        """
        categorized = {}
        
        for tech_info in technologies:
            technology = tech_info["technology"]
            version = tech_info.get("version")
            version_min = tech_info.get("version_min")
            version_max = tech_info.get("version_max")
            
            data = storage.get_data_for_technology(technology)
            
            if not data:
                continue
            
            technology_type = data.get("technology_type")
            category = self._find_category(technology_type)
            
            probability = self._calculate_probability(data, category)
            
            display_name = technology
            product_id = data.get("product_id")
            if product_id:
                product = self.product_manager.get_product_by_id(product_id)
                if product:
                    display_name = product.get("our_name", technology)
            
            if category not in categorized:
                categorized[category] = []
            
            tech_entry = {
                "name": display_name,
                "version": version,
                "version_min": version_min,
                "version_max": version_max,
                "probability": probability,
                "type": technology_type,
                "product_id": product_id
            }
            
            categorized[category].append(tech_entry)
        
        for category in categorized:
            categorized[category].sort(key=lambda x: x["probability"], reverse=True)
        
        return categorized
    
    def _find_category(self, technology_type):
        """
        Find the appropriate category for a technology type.
        
        Args:
            technology_type: The type of technology to categorize (can be category name from new system).
            
        Returns:
            String representing the category name.
        """
        if not technology_type:
            return "Other"
        
        # If technology_type is already a category name, return it
        if technology_type in self.categories:
            return technology_type
        
        # Otherwise, check legacy mapping
        for category, types in self.legacy_categories.items():
            if technology_type in types:
                return category
        
        return "Other"
    
    def _format_cpe_as_link(self, cpe_string, cve_url):
        """
        Format CPE string as a clickable hyperlink using ANSI escape codes.
        
        Uses OSC 8 escape sequence for terminal hyperlinks, which is supported
        by modern terminals (Windows Terminal, WSL, iTerm2, etc.).
        The text is colored gray to indicate it's a clickable link.
        
        Args:
            cpe_string: The CPE string to display
            cve_url: The CVE details URL to link to (or None)
            
        Returns:
            Formatted string with hyperlink escape codes and gray color if URL is available,
            otherwise returns the plain CPE string.
        """
        if not cve_url:
            return cpe_string
        
        # ANSI escape sequence for hyperlinks (OSC 8)
        # Format: ESC]8;;URLESC\TEXTESC]8;;ESC\
        # ESC is \x1b, and we need ESC followed by literal backslash
        # Gray color: \033[90m (same as ADDITIONS color)
        esc = '\x1b'
        backslash = '\\'
        gray = '\033[90m'  # Gray color
        reset = '\033[0m'   # Reset color
        # Wrap the CPE string in gray color within the hyperlink
        return f"{esc}]8;;{cve_url}{esc}{backslash}{gray}{cpe_string}{reset}{esc}]8;;{esc}{backslash}"
    
    def _display_category(self, category_name, technologies):
        """
        Display a single category with its technologies.
        
        Args:
            category_name: Name of the category to display.
            technologies: List of technology dictionaries for this category.
        """
        ptprint(f"{category_name}", "INFO", True, colortext=True, indent=4)
        
        if not technologies:
            ptprint("-", "TEXT", not self.args.json, indent=8)
        else:
            for tech in technologies:
                tech_display = tech["name"]
                if tech["version"]:
                    tech_display += f" {tech['version']}"
                elif tech.get("version_min") and tech.get("version_max"):
                    # (min - max))
                    tech_display += f" {tech['version_min']} - {tech['version_max']}"
                elif tech.get("version_min") and not tech.get("version_max"):
                    # (min+)
                    tech_display += f" {tech['version_min']}+"
                elif tech.get("version_max") and not tech.get("version_min"):
                    # (< max)
                    tech_display += f" < {tech['version_max']}"

                tech_display += f" ({tech['probability']}%)"
                
                ptprint(f"{tech_display}", "TEXT", not self.args.json, indent=8, end=" ")
                
                product_id = tech.get("product_id")
                if product_id:
                    version_for_cpe = tech.get("version")
                    cpe_string = self.product_manager.generate_cpe_string(product_id, version_for_cpe)
                    if cpe_string:
                        # Get CVE details URL from product
                        product = self.product_manager.get_product_by_id(product_id)
                        cve_url = product.get("cve_details_url") if product else None
                        
                        # Print CPE as clickable link if CVE URL is available and not null
                        # If URL is null, print CPE as plain text
                        # Use direct stdout write to preserve ANSI escape codes
                        if cve_url is not None and cve_url and not self.args.json:
                            formatted_cpe = self._format_cpe_as_link(cpe_string, cve_url)
                            # Debug: Uncomment the next line to see the raw escape sequence
                            # print(f"DEBUG: Link repr = {repr(formatted_cpe)}", file=sys.stderr)
                            sys.stdout.write(formatted_cpe + "\n")
                            sys.stdout.flush()
                        else:
                            # Print CPE as plain text when URL is null or not available
                            ptprint(f"{cpe_string}", "ADDITIONS", not self.args.json, colortext=True)
                    else:
                        ptprint(" ", "TEXT", not self.args.json)
                else:
                    ptprint(" ", "TEXT", not self.args.json)
    
    def _generate_json_output(self):
        """
        Generate structured JSON output with nodes and properties.
        
        Creates a comprehensive JSON structure containing:
        - Individual technology nodes with metadata
        - Global properties mapping
        - Vulnerability list
        - Status and configuration information
        
        Returns:
            None
        """
        json_output = {
            "satid": "",
            "guid": "",
            "status": "finished",
            "message": "",
            "results": {
                "nodes": self._create_nodes(),
                "properties": storage.get_properties(),
                "vulnerabilities": self._get_vulnerabilities()
            }
        }
        
        print(json.dumps(json_output, indent=2))
    
    def _create_nodes(self):
        """
        Create technology nodes for JSON output.
        
        Converts stored technology data into structured node objects
        with unique identifiers, properties, and metadata.
        
        Returns:
            List of node dictionaries for JSON output.
        """
        nodes = []
        technologies = storage.get_technologies_with_version()
        
        for tech_info in technologies:
            technology = tech_info["technology"]
            version = tech_info["version"]
            
            data = storage.get_data_for_technology(technology, version)
            
            if not data:
                continue
            
            node = self._create_single_node(technology, version, data)
            nodes.append(node)
        
        return nodes
    
    def _create_single_node(self, technology, version, data):
        """
        Create a single technology node.
        
        Args:
            technology: Technology name string.
            version: Version string or None.
            data: Technology data dictionary from storage.
            
        Returns:
            Dictionary representing a single technology node.
        """
        node_key = str(uuid.uuid4())
        
        parent_type = self._get_parent_type(data.get("node_target_type"))
        
        description = self._create_node_description(data)
        
        # Get product_id from data if available
        product_id = data.get("product_id")
        
        # Get vendor if product_id is available
        vendor = ""
        if product_id:
            product = self.product_manager.get_product_by_id(product_id)
            if product:
                vendor = product.get("vendor", "")
        
        node = {
            "type": "software",
            "key": node_key,
            "parent": None,
            "parentType": parent_type,
            "properties": {
                "software_type": self._map_software_type(data.get("technology_type"), product_id),
                "name": technology,
                "version": version or "",
                "vendor": vendor,
                "description": description
            },
            "vulnerabilities": []
        }
        
        return node
    
    def _get_parent_type(self, node_target_type):
        """
        Map node target type to parent type.
        
        Args:
            node_target_type: Target type from technology mapping.
            
        Returns:
            String representing the parent type.
        """
        mapping = {
            "device": "group_software_device",
            "service": "group_software_service", 
            "web_app": "group_software_web_app"
        }
        return mapping.get(node_target_type, "group_software_device")
    
    def _map_software_type(self, technology_type, product_id=None):
        """
        Map technology type to software type for JSON output.
        
        If product_id is provided, uses the product manager to get the
        json_code from the category definition. Otherwise falls back to
        legacy mapping for backward compatibility.
        
        Args:
            technology_type: Technology type from storage (legacy).
            product_id: Optional product ID to lookup category json_code.
            
        Returns:
            String representing the mapped software type.
        """
        # If product_id is provided, use product_manager
        if product_id:
            product = self.product_manager.get_product_by_id(product_id)
            if product:
                category_id = product.get('category_id')
                if category_id:
                    return self.product_manager.get_category_json_code(category_id)
        
        # Legacy mapping for backward compatibility
        mapping = {
            "Os": "softwareTypeOs",
            "Operating System": "softwareTypeOs",
            "WebServer": "softwareTypeWebServer",
            "Web Server": "softwareTypeWebServer",
            "WebApp": "softwareTypeWebApp",
            "Web Application": "softwareTypeWebApp",
            "Interpret": "softwareTypeInterpreter",
            "Programming Language": "softwareTypeInterpreter",
            "BackendFramework": "softwareTypeFramework",
            "Backend Framework": "softwareTypeFramework",
            "FrontendFramework": "softwareTypeFramework",
            "Frontend Framework": "softwareTypeFramework",
            "Database": "softwareTypeDatabase",
            "Plugin": "softwareTypePlugin",
            "Application Server": "softwareTypeAppServer",
            "Load Balancer": "softwareTypeLoadBalancer",
            "CDN / WAF": "softwareTypeCDN",
            "Development Stack": "softwareTypeStack",
            "Security / Cryptography": "softwareTypeSecurity"
        }
        return mapping.get(technology_type, "softwareTypeOther")
    
    def _create_node_description(self, data):
        """
        Create description text for a node.
        
        Args:
            data: Technology data dictionary from storage.
            
        Returns:
            String description combining available information.
        """
        descriptions = data.get("descriptions", [])
        modules = data.get("modules", [])
        
        parts = []
        
        if descriptions:
            parts.extend(descriptions[:2])  # Limit to first 2 descriptions
        
        return "; ".join(parts) if parts else ""
    
    def _get_vulnerabilities(self):
        """
        Get list of vulnerability identifiers for JSON output.
        
        Returns:
            List of dictionaries containing vulnerability codes.
        """
        vulns = storage.get_vulnerabilities()
        return [{"vulnCode": vuln} for vuln in vulns]
    
    def _calculate_probability(self, data, category_name=None):
        """
        Calculate probability percentage for a technology.
        
        For categories other than "Other", computes probability based on the 
        technology's probability sum divided by the total count of all technologies 
        in the same category.
        
        For "Other" category, uses the original calculation (average of individual probabilities).
        
        Args:
            data: Technology data dictionary containing count and probability_sum.
            category_name: Name of the category this technology belongs to.
            
        Returns:
            Integer representing the probability percentage (0-100).
        """
        count = data.get("count", 0)
        probability_sum = data.get("probability_sum", 0)
        
        if count == 0:
            return 0
        
        if category_name == "Other":
            average_probability = probability_sum / count
            return max(0, min(100, int(round(average_probability))))
        
        if category_name:
            category_total_count = self._get_category_total_count(category_name)
            if category_total_count > 0:
                category_probability = probability_sum / category_total_count
                return max(0, min(100, int(round(category_probability))))
        
        average_probability = probability_sum / count
        return max(0, min(100, int(round(average_probability))))

    def _get_category_total_count(self, category_name):
        """
        Get total count of all technologies in a specific category.
        
        Args:
            category_name: Name of the category to count technologies for.
            
        Returns:
            Integer representing total count of all technologies in the category.
        """
        total_count = 0
        technologies = storage.get_technologies_with_version()
        
        for tech_info in technologies:
            technology = tech_info["technology"]
            version = tech_info["version"]
            
            data = storage.get_data_for_technology(technology, version)
            
            if not data:
                continue
            
            technology_type = data.get("technology_type")
            tech_category = self._find_category(technology_type)
            
            if tech_category == category_name:
                total_count += data.get("count", 0)
        
        return total_count
    
    def _format_technology_display(self, technology, version, technology_type):
        """
        Format technology name for display output.
        
        Args:
            technology: Technology name string.
            version: Version string or None.
            technology_type: Type of technology for display formatting.
            
        Returns:
            Formatted string for display output.
        """
        display_name = technology
        
        if version:
            display_name += f" {version}"
        
        if technology_type:
            type_display = self._format_type_display(technology_type)
            display_name += f" [{type_display}]"
        
        return display_name
    
    def _format_type_display(self, technology_type):
        """
        Format technology type for display.
        
        Args:
            technology_type: Technology type string from storage.
            
        Returns:
            Human-readable type string for display.
        """
        display_mapping = {
            "Os": "OS",
            "WebServer": "Webserver", 
            "WebApp": "WebApp",
            "Interpret": "Interpreter",
            "BackendFramework": "Backend Framework",
            "FrontendFramework": "Frontend Framework"
        }
        return display_mapping.get(technology_type, technology_type)