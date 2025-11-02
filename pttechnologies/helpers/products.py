"""
Product and Category Management Module

Provides functionality for working with product definitions, categories,
and CPE string generation for CVE database integration.
"""

import json
import os
from typing import Optional, List, Dict


class ProductManager:
    """
    Manager for product and category definitions.
    
    Handles loading, caching, and querying of product and category data
    from JSON definition files. Provides CPE string generation for
    vulnerability scanning integration.
    """
    
    def __init__(self, definitions_path: str = None):
        """
        Initialize the ProductManager.
        
        Args:
            definitions_path: Path to the definitions directory.
                            If None, will be auto-detected.
        """
        if definitions_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            definitions_path = os.path.join(current_dir, "../definitions")
        
        self.definitions_path = definitions_path
        self._products_cache: Optional[List[Dict]] = None
        self._categories_cache: Optional[List[Dict]] = None
    
    def _load_json_file(self, filename: str) -> Dict:
        """
        Load JSON file from definitions directory.
        
        Args:
            filename: Name of the JSON file to load
            
        Returns:
            Parsed JSON data as dictionary
        """
        file_path = os.path.join(self.definitions_path, filename)
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading {filename}: {e}")
            return {}
    
    def get_products(self) -> List[Dict]:
        """
        Load and return all product definitions from all category files.
        Results are cached after first load.
        
        Returns:
            List of product definitions
        """
        if self._products_cache is None:
            all_products = []
            
            # List of product category files
            product_files = [
                "products/os.json",
                "products/web_servers.json",
                "products/app_servers.json",
                "products/languages.json",
                "products/frameworks_frontend.json",
                "products/frameworks_backend.json",
                "products/cms.json",
                "products/ecommerce.json",
                "products/javascript_libraries.json",
                "products/cdn_proxy.json",
                "products/stacks.json",
                "products/database_tools.json",
                "products/databases.json",
                "products/security.json",
                "products/modules.json",
                "products/wordpress_plugins.json",
                "products/other.json"
            ]
            
            # Load and merge all product files
            for filename in product_files:
                data = self._load_json_file(filename)
                products = data.get("products", []) if isinstance(data, dict) else []
                all_products.extend(products)
            
            self._products_cache = all_products
        
        return self._products_cache
    
    def get_product_by_id(self, product_id: int) -> Optional[Dict]:
        """
        Get product definition by ID.
        
        Args:
            product_id: Product ID to look up
            
        Returns:
            Product definition dictionary or None if not found
        """
        products = self.get_products()
        for product in products:
            if product.get("id") == product_id:
                return product
        return None
    
    def get_products_by_category(self, category_id: int) -> List[Dict]:
        """
        Get all products in a specific category.
        
        Args:
            category_id: Category ID to filter by
            
        Returns:
            List of products in the category
        """
        products = self.get_products()
        return [p for p in products if p.get("category_id") == category_id]
    
    def get_categories(self) -> List[Dict]:
        """
        Load and return all product category definitions.
        Results are cached after first load.
        
        Returns:
            List of category definitions
        """
        if self._categories_cache is None:
            data = self._load_json_file("products/categories.json")
            self._categories_cache = data.get("categories", []) if isinstance(data, dict) else []
        return self._categories_cache
    
    def get_category_by_id(self, category_id: int) -> Optional[Dict]:
        """
        Get category definition by ID.
        
        Args:
            category_id: Category ID to look up
            
        Returns:
            Category definition dictionary or None if not found
        """
        categories = self.get_categories()
        for category in categories:
            if category.get("id") == category_id:
                return category
        return None
    
    def get_category_name(self, category_id: int) -> str:
        """
        Get category name by ID (convenience method).
        
        Args:
            category_id: Category ID to look up
            
        Returns:
            Category name or "Other" if not found
        """
        category = self.get_category_by_id(category_id)
        return category.get("name", "Other") if category else "Other"
    
    def get_category_json_code(self, category_id: int) -> str:
        """
        Get category JSON code (software_type) by ID.
        
        Args:
            category_id: Category ID to look up
            
        Returns:
            Category json_code or "softwareTypeOther" if not found
        """
        category = self.get_category_by_id(category_id)
        return category.get("json_code", "softwareTypeOther") if category else "softwareTypeOther"
    
    def generate_cpe_string(self, product_id: int, version: Optional[str] = None) -> Optional[str]:
        """
        Generate CPE (Common Platform Enumeration) 2.3 string for a product.
        
        CPE strings are used for vulnerability scanning and CVE database queries.
        Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        
        Args:
            product_id: Product ID from products.json
            version: Optional version string (uses '*' if None)
            
        Returns:
            CPE 2.3 formatted string or None if product not found
        """
        product = self.get_product_by_id(product_id)
        if not product:
            return None
        
        vendor = product.get('vendor', '*').lower().replace(' ', '_')
        
        products = product.get('products', [])
        product_name = products[0] if products else product.get('our_name', '*').lower().replace(' ', '_')
        
        version_str = version if version else '*'
        
        # CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        # For applications: part=a
        cpe = f"cpe:2.3:a:{vendor}:{product_name}:{version_str}:*:*:*:*:*:*:*"
        return cpe
    
    def get_product_info(self, product_id: int) -> Optional[Dict]:
        """
        Get complete product information including category details.
        
        Args:
            product_id: Product ID to look up
            
        Returns:
            Dictionary with product and category information
        """
        product = self.get_product_by_id(product_id)
        if not product:
            return None
        
        category = self.get_category_by_id(product.get("category_id"))
        
        return {
            **product,
            "category_name": category.get("name") if category else "Other",
            "category_description": category.get("description") if category else None
        }
    
    def search_products(self, search_term: str) -> List[Dict]:
        """
        Search products by name or vendor.
        
        Args:
            search_term: Term to search for (case-insensitive)
            
        Returns:
            List of matching products
        """
        search_lower = search_term.lower()
        products = self.get_products()
        
        results = []
        for product in products:
            if (search_lower in product.get("our_name", "").lower() or
                search_lower in product.get("vendor", "").lower()):
                results.append(product)
        
        return results
    
    def clear_cache(self):
        """Clear cached product and category data."""
        self._products_cache = None
        self._categories_cache = None


# Global singleton instance for easy access
_product_manager = None


def get_product_manager(definitions_path: str = None) -> ProductManager:
    """
    Get or create the global ProductManager instance.
    
    Args:
        definitions_path: Optional path to definitions directory
        
    Returns:
        ProductManager singleton instance
    """
    global _product_manager
    if _product_manager is None:
        _product_manager = ProductManager(definitions_path)
    return _product_manager

