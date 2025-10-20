"""
Module for thread-safe storage of scan results.

Provides a singleton `storage` instance to collect and retrieve
vulnerability scan findings from multiple concurrent modules.
"""

import threading
import inspect

from typing import Optional

class ResultStorage:
    """
    Thread-safe storage for vulnerability scan results.

    Supports concurrent access from multiple threads, allowing
    modules to add findings which are stored internally as dictionaries.

    Methods:
        add_to_storage(...): Add a new result record.
        get_all_records(): Retrieve all stored results safely.
        get_vulnerabilities(): Get unique vulnerability identifiers.
        get_technologies(): Get unique technology+version combinations.
        get_technologies_with_version(): Get unique combinations of technology and version.
        get_data_for_technology(...): Return aggregated metadata for a given technology,
                                      including version info, module usage, and mapped attributes.
    """

    TECHNOLOGY_MAPPING = [
        {
            "category": "WebApp",
            "nodeTargetType": "web_app",
            "swType": "web_app",
            "swPrefix": "webApp"
        },
        {
            "category": "FrontendFramework",
            "nodeTargetType": "web_app",
            "swType": "framework_js",
            "swPrefix": "frameworkJs"
        },
        {
            "category": "BackendFramework",
            "nodeTargetType": "web_app",
            "swType": "web_framework",
            "swPrefix": "webFramework"
        },
        {
            "category": "Interpret",
            "nodeTargetType": "web_app",
            "swType": "web_programming_language",
            "swPrefix": "webProgrammingLanguage"
        },
        {
            "category": "Os",
            "nodeTargetType": "device",
            "swType": "device_os",
            "swPrefix": "deviceOs"
        },
        {
            "category": "WebServer",
            "nodeTargetType": "service",
            "swType": "service_sw",
            "swPrefix": "serviceSw"
        }
    ]

    def __init__(self):
        self._storage = []
        self._lock = threading.Lock()

    def add_to_storage(
        self,
        technology: Optional[str] = None,
        version: Optional[str] = None,
        version_min: Optional[str] = None,
        version_max: Optional[str] = None,
        technology_type: Optional[str] = None,
        probability: Optional[int] = 100,
        vulnerability: Optional[str] = None,
        description: Optional[str] = None,
        module: Optional[str] = None
    ) -> None:
        """
        Add a record to the storage. Automatically detects the calling module if `module` is not provided.

        Args:
            technology: Technology name (e.g., OS, WebServer).
            version: Version of the technology.
            technology_type: Type of the technology (e.g., 'webserver', 'os').
            probability: Probability value (0-100).
            vulnerability: Vulnerability identifier.
            description: Description or additional information.
            module: Name of the calling module (optional; autodetected if not provided).

        Returns:
            None
        """
        if module is None:
            caller_frame = inspect.stack()[1]
            caller_module = inspect.getmodule(caller_frame[0])
            module = caller_module.__name__ if caller_module else "<unknown>"

        record = {
            "module": (module or "").strip().upper(),
            "technology": (technology or "").strip(),
            "version": (version or "").strip() if version else None,
            "version_min": (version_min or "").strip() if version_min else None,
            "version_max": (version_max or "").strip() if version_max else None,
            "technology_type": (technology_type or "").strip() if technology_type else None,
            "probability": probability,
            "vulnerability": (vulnerability or "").strip() if vulnerability else None,
            "description": (description or "").strip() if description else None
        }

        with self._lock:
            self._storage.append(record)

    def get_all_records(self) -> list[dict]:
        """Return a copy of all stored records."""
        with self._lock:
            return self._storage.copy()

    def get_vulnerabilities(self) -> list[str]:
        """
        Return a list of unique vulnerability identifiers stored in the records.

        Returns:
            List of unique vulnerability strings.
        """
        with self._lock:
            vulns = {record["vulnerability"] for record in self._storage if record["vulnerability"]}
        return list(vulns)

    def get_technologies(self) -> list[str]:
        """
        Return a list of unique technology names used in stored records.

        Returns:
            List of unique non-empty technology strings.
        """
        with self._lock:
            return list({record["technology"] for record in self._storage if record.get("technology")})

    def get_technologies_with_version(self) -> list[dict]:
        """
        Return a list of unique combinations of technology and version.

        Returns:
            List of dictionaries, each containing:
                - 'technology': technology name (str)
                - 'version': version string or None
        """
        with self._lock:
            unique_pairs = {
                (
                    record.get("technology"), 
                    record.get("version"),
                    record.get("version_min"),
                    record.get("version_max")
                )
                for record in self._storage
                if record.get("technology") # skip empty technologies
            }
        return [{"technology": tech, "version": ver, "version_min": ver_min, "version_max": ver_max} for tech, ver, ver_min, ver_max in unique_pairs]

    def get_data_for_technology(self, technology: str, version: Optional[str] = None) -> dict:
        """
        Return aggregated info for given technology and optionally version.

        Args:
            technology: Technology name to filter by (case-sensitive).
            version: Version to filter by; if None, aggregate over all versions.

        Returns:
            Dict with keys:
                - technology: filtered technology name
                - versions: list of unique versions (or single-item list if version given)
                - count: number of matching records found
                - modules: list of unique module names (already uppercased on insert)
                - probability_sum: sum of probability values from matched records (ignores None)
                - technology_type: technology_type from the first matched record (or None if not present)
                - descriptions: list of descriptions from matched records (excluding None)
                - node_target_type: mapped value from TECHNOLOGY_MAPPING
                - sw_type: mapped value from TECHNOLOGY_MAPPING
                - sw_value: swPrefix + technology (e.g., "deviceOsWindows")
        """

        with self._lock:
            filtered = [
                r for r in self._storage
                if r.get("technology") == technology
            ]
            if not filtered:
                return {}

            if version is not None:
                version_filtered = [r for r in filtered if r.get("version") == version]
                if version_filtered:
                    filtered = version_filtered

            # Prioritize version records
            exact_records = [r for r in filtered if r.get("version")]
            range_records = [r for r in filtered if not r.get("version") and r.get("version_min") and r.get("version_max")]
            minimum_records = [r for r in filtered if not r.get("version") and r.get("version_min") and not r.get("version_max")]
            maximum_records = [r for r in filtered if not r.get("version") and not r.get("version_min") and r.get("version_max")]
            
            # Select primary record for version display
            if exact_records:
                primary = exact_records[0]
                display_version = primary.get("version")
                display_version_min = None
                display_version_max = None
            elif range_records:
                primary = range_records[0]
                display_version = None
                display_version_min = primary.get("version_min")
                display_version_max = primary.get("version_max")
            elif minimum_records:
                primary = minimum_records[0]
                display_version = None
                display_version_min = primary.get("version_min")
                display_version_max = None
            elif maximum_records:
                primary = maximum_records[0]
                display_version = None
                display_version_min = None
                display_version_max = primary.get("version_max")
            else:
                primary = filtered[0]
                display_version = None
                display_version_min = None
                display_version_max = None

            modules = sorted({r["module"] for r in filtered if r.get("module")})
            probability_sum = sum(r.get("probability") or 0 for r in filtered)
            technology_type = next((r.get("technology_type") for r in filtered if r.get("technology_type")), None)
            descriptions = list({r.get("description") for r in filtered if r.get("description")})

            mapping = next((m for m in self.TECHNOLOGY_MAPPING if m["category"] == technology_type), {})
            node_target_type = mapping.get("nodeTargetType")
            sw_type = mapping.get("swType")
            sw_prefix = mapping.get("swPrefix")
            sw_value = f"{sw_prefix}{technology}" if sw_prefix else None

            return {
                "technology": technology,
                "version": display_version,
                "version_min": display_version_min,
                "version_max": display_version_max,
                "count": len(filtered),
                "modules": modules,
                "probability_sum": probability_sum,
                "technology_type": technology_type,
                "descriptions": descriptions,
                "node_target_type": node_target_type,
                "sw_type": sw_type,
                "sw_value": sw_value
            }

    def get_properties(self) -> dict[str, dict[str, str]]:
        """
        Aggregate and return a dictionary of node types (device, service, web_app) and their associated
        technology properties based on the first occurrence of each relevant technology_type in storage.

        For each supported technology_type, the method finds the first matching record in storage
        and constructs a mapping based on the corresponding configuration from TECHNOLOGY_MAPPING.

        Only technology types listed in TECHNOLOGY_MAPPING are considered.
        Records with other types (e.g., JsLib, Plugin, Theme, TemplateSystem) are skipped automatically.

        Returns:
            dict: Dictionary structured by node type with swType as key and swPrefix+technology as value.

            Example:
            {
                "device": {
                    "device_os": "deviceOsWindows"
                },
                "service": {
                    "service_sw": "serviceSwApache"
                },
                "web_app": {
                    "web_app": "webAppKentico",
                    "web_programming_language": "webProgrammingLanguageCsharp",
                    "web_framework": "webFrameworkAspNet",
                    "framework_js": "frameworkJsAngular"
                }
            }
        """
        result: dict[str, dict[str, str]] = {
            "device": {},
            "service": {},
            "web_app": {}
        }

        seen_categories: set[str] = set()

        # Only process technology types that are defined in TECHNOLOGY_MAPPING
        supported_categories = {entry["category"] for entry in self.TECHNOLOGY_MAPPING}

        with self._lock:
            for record in self._storage:
                tech_type = record.get("technology_type")
                technology = record.get("technology")

                # Skip if data is incomplete or already processed
                if not tech_type or not technology or tech_type in seen_categories:
                    continue

                # Skip unsupported categories (e.g. JsLib, Plugin, etc.)
                if tech_type not in supported_categories:
                    continue

                # Find corresponding mapping
                mapping = next((m for m in self.TECHNOLOGY_MAPPING if m["category"] == tech_type), None)
                if not mapping:
                    continue

                node = mapping["nodeTargetType"]            # e.g., web_app, service, device
                sw_type = mapping["swType"]                 # e.g., web_app, service_sw, etc.
                sw_prefix = mapping["swPrefix"]             # e.g., webApp, serviceSw, etc.

                result[node][sw_type] = f"{sw_prefix}{technology}"
                seen_categories.add(tech_type)

        # Remove empty blocks (if no tech was found for a node)
        return {k: v for k, v in result.items() if v}


# Global instance, import this instead of the class
storage = ResultStorage()