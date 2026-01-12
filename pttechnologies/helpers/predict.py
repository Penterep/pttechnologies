"""
Module for predicting technologies based on identified components.

Analyzes existing scan results and infers additional technologies
using predefined rules from predict.json configuration file.
"""

import re
from ptlibs.ptprinthelper import ptprint
from helpers.result_storage import storage
from helpers.products import get_product_manager

class Predict:
    """
    Technology prediction engine for vulnerability scanning.

    Processes existing scan results to predict additional technologies
    based on logical dependencies and patterns defined in predict.json.
    Eliminates duplicates and provides formatted output.

    Attributes:
        args: Command line arguments and configuration.
        ptjsonlib: JSON processing library.
        helpers: Helper utilities for loading definitions.
        definitions: Loaded prediction rules from predict.json.
        predictions_made: List of predictions prepared for display output.

    Methods:
        run(): Main entry point for the prediction process.
        match_condition(rec, cond): Check if record matches rule condition.
    """
    def __init__(self, args, ptjsonlib, helpers):
        """
        Initialize the prediction engine.

        Args:
            args: Command line arguments and configuration settings.
            ptjsonlib: JSON processing library instance.
            helpers: Helper utilities for loading configuration files.
        """
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.product_manager = get_product_manager()
        self.definitions = self.helpers.load_definitions("predict.json")
        self.predictions_made = []

    def run(self):
        """
        Main entry point for technology prediction process.
        
        Orchestrates the complete prediction workflow:
        1. Collects all possible predictions from rules
        2. Collects plugin dependencies
        3. Removes duplicate predictions 
        4. Saves unique predictions to storage
        5. Displays formatted results
        
        Returns:
            None
        """
        ptprint("Predicted Technologies", "TITLE", not self.args.json, colortext=True)
        
        records = storage.get_all_records()
        all_predictions = self._collect_all_predictions(records)
        
        # Collect plugin dependencies
        plugin_dependencies = self._collect_plugin_dependencies(records)
        all_predictions.extend(plugin_dependencies)
        
        if not all_predictions:
            ptprint("It is not possible to predict any new technologies", "INFO", not self.args.json, indent=4)
            return
            
        unique_predictions = self._remove_duplicates(all_predictions)
        self._save_and_prepare_predictions(unique_predictions)
        self._display_predictions()

    def _collect_all_predictions(self, records):
        """
        Collect all possible predictions from rules.
        
        Iterates through all prediction rules and evaluates their conditions
        against existing scan records to generate potential predictions.
        
        Args:
            records: List of existing scan result records from storage.
            
        Returns:
            List of prediction dictionaries containing technology details.
        """
        all_predictions = []
        
        for rule in self.definitions:
            if self._rule_conditions_met(rule, records):
                predictions = self._create_predictions_from_rule(rule)
                all_predictions.extend(predictions)
                
        return all_predictions

    def _collect_plugin_dependencies(self, records):
        """
        Collect plugin dependencies from records with "Plugin dependency from:" description.
        
        Groups dependencies by technology and version, merging sources from multiple plugins.
        
        Args:
            records: List of existing scan result records from storage.
            
        Returns:
            List of prediction dictionaries with merged plugin sources.
        """
        plugin_deps = []
        
        dep_records = [
            rec for rec in records 
            if rec.get("description") and "Plugin dependency from:" in rec.get("description", "")
        ]
        
        if not dep_records:
            return plugin_deps
        
        # Group by technology, version, and technology_type
        grouped = {}
        for rec in dep_records:
            tech = rec.get("technology")
            version = rec.get("version")
            tech_type = rec.get("technology_type")
            product_id = rec.get("product_id")
            
            if not tech:
                continue
            
            key = (tech, version, tech_type)
            
            if key not in grouped:
                grouped[key] = {
                    'technology': tech,
                    'technology_type': tech_type,
                    'version': version,
                    'sources': [],
                    'product_id': product_id
                }
            
            desc = rec.get("description", "")
            if "Plugin dependency from:" in desc:
                source = desc.replace("Plugin dependency from:", "").strip()
                grouped[key]['sources'].append(source)
        
        # Convert grouped data to prediction format
        for key, data in grouped.items():
            if not data['sources']:
                continue
            
            sources_str = ", ".join(data['sources'])
            description = f"Plugin dependency from: {sources_str}"
            
            display_name = data['technology']
            product_id = data['product_id']
            if product_id:
                product = self.product_manager.get_product_by_id(product_id)
                if product:
                    display_name = product.get("our_name", data['technology'])
            
            prediction = {
                'technology': display_name,
                'storage_name': data['technology'],
                'technology_type': data['technology_type'],
                'version': data['version'],
                'probability': 80,
                'description': description,
                'product_id': product_id,
                'sources': data['sources']
            }
            plugin_deps.append(prediction)
        
        return plugin_deps

    def _rule_conditions_met(self, rule, records):
        """
        Check if all conditions for a prediction rule are satisfied.
        
        Args:
            rule: Prediction rule dictionary with 'when' conditions.
            records: List of scan result records to check against.
            
        Returns:
            bool: True if all rule conditions are met, False otherwise.
        """
        when_conditions = rule.get("when", [])
        
        for condition in when_conditions:
            if not any(self.match_condition(rec, condition) for rec in records):
                return False
        return True

    def _create_predictions_from_rule(self, rule):
        """
        Create prediction objects from a rule's predict items.
        
        Args:
            rule: Rule dictionary containing 'predict' items to process.
            
        Returns:
            List of prediction dictionaries with technology metadata.
        """
        predict_items = rule.get("predict", [])
        predictions = []
        
        for item in predict_items:
            # Get product info from product_id
            product_id = item.get("product_id")
            if not product_id:
                continue  # Skip if no product_id defined
            
            product = self.product_manager.get_product_by_id(product_id)
            if not product:
                continue  # Skip if product not found
            
            technology_name = product.get("our_name", "Unknown")
            products = product.get('products', [])
            storage_name = products[0] if (products and products[0] is not None) else technology_name
            category_name = self.product_manager.get_category_name(product.get("category_id"))
            
            prediction = {
                'technology': technology_name,
                'storage_name': storage_name,
                'technology_type': category_name,
                'version': item.get("version"),
                'probability': item.get("probability", 100),
                'description': item.get('description'),
                'product_id': product_id
            }
            predictions.append(prediction)
            
        return predictions

    def _remove_duplicates(self, all_predictions):
        """
        Group predictions by technology, type, and version, collecting all sources.
        
        Groups predictions with the same technology, type, and version together,
        keeping track of all sources that predicted them. Different versions
        are kept as separate predictions. Groups by storage_name to properly deduplicate.
        
        Args:
            all_predictions: List of all collected prediction dictionaries.
            
        Returns:
            List of grouped prediction dictionaries with multiple sources.
        """
        grouped = {}
        
        for pred in all_predictions:
            storage_name = pred.get('storage_name', pred['technology'])
            key = (storage_name, pred['technology_type'], pred['version'])
            
            if key not in grouped:
                grouped[key] = {
                    'technology': pred['technology'],
                    'storage_name': storage_name,
                    'technology_type': pred['technology_type'],
                    'version': pred['version'],
                    'sources': [],
                    'product_id': pred.get('product_id')
                }
            
            if 'sources' in pred and pred['sources'] and isinstance(pred['sources'], list):
                for source in pred['sources']:
                    if isinstance(source, str):
                        source_tuple = (source, pred['probability'])
                        if source_tuple not in grouped[key]['sources']:
                            grouped[key]['sources'].append(source_tuple)
                    elif isinstance(source, tuple):
                        # Already a tuple, use as is
                        if source not in grouped[key]['sources']:
                            grouped[key]['sources'].append(source)
            else:
                source_name = pred['description'].rsplit(' ', 1)[0] if pred['description'] else None
                probability = pred['probability']
                
                source_tuple = (source_name, probability)
                if source_tuple not in grouped[key]['sources']:
                    grouped[key]['sources'].append(source_tuple)
                
        return list(grouped.values())

    def _save_and_prepare_predictions(self, unique_predictions):
        """
        Save predictions to storage and prepare them for display.
        
        Processes each grouped prediction by creating descriptions from all sources,
        saving to result storage, and preparing display data.
        Plugin dependencies are not saved again (already in storage), only prepared for display.
        
        Args:
            unique_predictions: List of grouped prediction dictionaries with sources.
            
        Returns:
            None
        """
        for pred in unique_predictions:
            sources = pred['sources']
            if not sources:
                continue
                
            sorted_sources = sorted(sources, key=lambda x: (-x[1], x[0] or ''))
            primary_source, primary_probability = sorted_sources[0]
            
            is_plugin_dep = any(
                source[0] and 'Plugin dependency from:' in str(source[0]) 
                for source in sources 
                if source[0]
            )
            
            if is_plugin_dep:
                pass
            else:
                description = None
                if primary_source:
                    description = f"Prediction based on {primary_source}"
                
                self._save_to_storage(pred, description, primary_probability)
            
            self._prepare_for_display(pred)

    def _create_description(self, prediction):
        """
        Create description text for a prediction.
        
        Generates human-readable description based on the prediction's
        source description field, extracting the primary component.
        
        Args:
            prediction: Prediction dictionary containing description field.
            
        Returns:
            str or None: Formatted description text or None if no source description.
        """
        if prediction['description'] is not None:
            base = prediction['description']
            return f"Prediction based on {base}"
        return None

    def _save_to_storage(self, prediction, description, probability):
        """
        Save a single prediction to result storage.
        
        Args:
            prediction: Prediction dictionary with technology details.
            description: Generated description text for the prediction.
            probability: Probability value to use for storage.
            
        Returns:
            None
        """
        storage.add_to_storage(
            technology=prediction.get('storage_name', prediction['technology']),
            technology_type=prediction['technology_type'],
            version=prediction['version'],
            probability=probability,
            description=description,
            product_id=prediction.get('product_id')
        )

    def _prepare_for_display(self, prediction):
        """
        Prepare a prediction for display output.
        
        Formats technology name with version and creates display-ready
        data structure with all sources.
        
        Args:
            prediction: Grouped prediction dictionary with sources list.
            
        Returns:
            None
        """
        tech_display = prediction['technology']
        version = prediction.get('version')
        
        sources = [(name, prob) for name, prob in prediction['sources'] if name is not None]
        if not sources:
            return
            
        max_probability = max(prob for _, prob in sources)
        
        self.predictions_made.append({
            'technology': tech_display,
            'type': prediction['technology_type'],
            'version': version,
            'sources': sources,
            'probability': max_probability
        })

    def _display_predictions(self):
        """
        Display all predictions in formatted output.
        
        Prints predictions using the ptprint library with appropriate
        colors and formatting, showing technology and all source information.
        
        Returns:
            None
        """
        if not self.predictions_made:
            return
            
        for pred in self.predictions_made:
            tech_display = f"{pred['technology']} ({pred['type']})"
            if pred.get('version'):
                tech_display += f" {pred['version']}"
            probability = pred.get('probability', 100)
            sources = pred.get('sources', [])
            
            ptprint(f"{tech_display}", "VULN", not self.args.json, indent=4, end=" ")
            ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True)
            
            if sources and len(sources) > 0:
                sorted_sources = sorted(sources, key=lambda x: (-x[1], x[0] or ''))
                for source_name, source_prob in sorted_sources:
                    ptprint(f"        ({source_prob}%) {source_name}", "ADDITIONS", not self.args.json, colortext=True)

    def match_condition(self, rec, cond):
        """
        Check if a record matches a given condition.
        
        Evaluates both pattern-based conditions (regex, contains) and
        exact field matches against the provided record.
        
        Args:
            rec: Record dictionary to check against condition.
            cond: Condition dictionary with matching criteria.
            
        Returns:
            bool: True if record matches all condition criteria, False otherwise.
        """
        if not self._match_description_patterns(rec, cond):
            return False
            
        return self._match_exact_fields(rec, cond)

    def _match_description_patterns(self, rec, cond):
        """
        Check description-based patterns (regex and contains).
        
        Args:
            rec: Record dictionary containing description field.
            cond: Condition dictionary with pattern criteria.
            
        Returns:
            bool: True if description patterns match, False otherwise.
        """
        desc = rec.get("description") or ""
        
        regex = cond.get("description_regex")
        if regex and not re.search(regex, desc):
            return False
            
        contains = cond.get("description_contains")
        if contains and contains not in desc:
            return False
            
        return True

    def _match_exact_fields(self, rec, cond):
        """
        Check exact field matches.
        
        Compares record fields against condition values for exact equality,
        excluding special pattern-based condition keys.
        Supports matching by product_id or technology name for backward compatibility.
        
        Args:
            rec: Record dictionary to check field values.
            cond: Condition dictionary with exact match criteria.
            
        Returns:
            bool: True if all exact field matches succeed, False otherwise.
        """
        for key, val in cond.items():
            if key in ("description_regex", "description_contains", "_comment"):
                continue
            
            # Handle product_id matching
            if key == "product_id":
                if rec.get("product_id") != val:
                    # Also check if technology name matches (for backward compatibility)
                    product = self.product_manager.get_product_by_id(val)
                    if not product or rec.get("technology") != product.get("our_name"):
                        return False
            elif rec.get(key) != val:
                return False
                
        return True