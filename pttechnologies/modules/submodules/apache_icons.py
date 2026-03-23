"""
Apache Icons Version Fingerprinting Submodule

Uses icon-file MD5 hashes to identify (or narrow down) the Apache version
running on the target server.

Algorithm (adaptive binary search):
  1. The triggering response (icons/apache_pb2.gif) is hashed first for free.
  2. Probes from apache_icons.json are tried in descending order of
     Gini split score (most discriminating first).
  3. After each probe the candidate set is intersected with the matching
     partition of that probe.
  4. The loop stops when the candidate set can no longer be narrowed, a
     single version (or group) is identified, or the request budget is
     exhausted.

Called by: modules/sources.py  (via sources.json entry for apache_pb2.gif)

Functions:
    analyze: Entry point called by SOURCES when submodule is specified.
"""

import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from helpers.result_storage import storage
from ptlibs.ptprinthelper import ptprint


_DEFINITIONS_FILE = "subdefinitions/apache_icons.json"
_MAX_EXTRA_REQUESTS = 5
_INITIAL_FILE = "apache_pb2.gif"


def analyze(tech_info: Dict[str, Any], args: object, helpers: object) -> Dict[str, Any]:
    """
    Identify the Apache version by hashing icon files.

    Called by SOURCES when icons/apache_pb2.gif (or similar) is found.

    Args:
        tech_info: Dictionary with at least 'url' and 'response' keys.
        args:      Configuration (verbose, json, timeout, …).
        helpers:   Helpers object (load_definitions, fetch).

    Returns:
        Updated tech_info with 'version' and/or 'version_range' keys set.
    """
    rules_db = _load_rules(helpers, args)
    if not rules_db:
        return tech_info

    probe_order: List[Dict]    = rules_db.get("probe_order",   [])
    
    if "unique_rules" in rules_db and "version_to_rule" in rules_db:
        unique_rules = rules_db.get("unique_rules", {})
        version_to_rule = rules_db.get("version_to_rule", {})
        all_versions = list(version_to_rule.keys())
        rules_db["_unique_rules"] = unique_rules
        rules_db["_version_to_rule"] = version_to_rule
        rules_db["_is_optimized"] = True
    else:
        version_rules = rules_db.get("version_rules", {})
        all_versions = list(version_rules.keys())
        rules_db["_version_rules"] = version_rules
        rules_db["_is_optimized"] = False

    base_url = _extract_base_url(tech_info.get("url", ""))
    if not base_url:
        return tech_info

    candidates: Set[str] = set(all_versions)
    initial_response     = tech_info.get("response")
    known_hashes: Dict[str, str] = {}

    if initial_response:
        h = _hash_response(initial_response)
        if h:
            known_hashes[_INITIAL_FILE] = h
            candidates = _apply_probe(
                _INITIAL_FILE, h, probe_order, candidates
            )

    requests_made = 0
    for probe in probe_order:
        if len(candidates) <= 1 or requests_made >= _MAX_EXTRA_REQUESTS:
            break

        file_name = probe["file"]
        if file_name in known_hashes:
            continue

        if not _probe_is_useful(probe, candidates):
            continue

        url = f"{base_url}/icons/{file_name}"
        response = helpers.fetch(url)
        requests_made += 1

        observed_hash = _hash_response(response) if response else None
        status = getattr(response, "status_code", None) if response else None
        probe_key = observed_hash if (status == 200 and observed_hash) else "404"
        known_hashes[file_name] = probe_key

        prev_size = len(candidates)
        candidates = _apply_probe(file_name, probe_key, probe_order, candidates)

    _report_result(tech_info, candidates, rules_db, args)

    return tech_info


def _load_rules(helpers: object, args: object) -> Optional[Dict]:
    """Load apache_version_rules.json via helpers."""
    try:
        db = helpers.load_definitions(_DEFINITIONS_FILE)
        return db or None
        
    except Exception as e:
        return None


def _extract_base_url(url: str) -> str:
    """
    Strip the path from a URL to get the base (scheme + host + port).
    e.g. 'http://target/icons/apache_pb2.gif' → 'http://target'
    """
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return ""


def _hash_response(response: object) -> Optional[str]:
    """Compute MD5 of the raw response body."""
    try:
        body = getattr(response, "content", None)
        if body is None:
            text = getattr(response, "text", None) or getattr(response, "body", None)
            if text:
                body = text.encode("latin-1") if isinstance(text, str) else text
        if body:
            return hashlib.md5(body).hexdigest()
    except Exception:
        pass
    return None


def _apply_probe(
    file_name: str,
    observed_key: str,
    probe_order: List[Dict],
    candidates: Set[str],
) -> Set[str]:
    """
    Narrow the candidate set using the observed result for one file probe.

    Looks up the probe entry for *file_name* in probe_order and intersects
    candidates with the matching partition.
    """
    for probe in probe_order:
        if probe["file"] != file_name:
            continue

        partitions: Dict[str, List[str]] = probe.get("partitions", {})
        matched = partitions.get(observed_key)

        if matched is not None:
            return candidates & set(matched)

        if "404" in partitions:
            return candidates - set(partitions["404"])

        return candidates

    return candidates


def _probe_is_useful(probe: Dict, candidates: Set[str]) -> bool:
    """
    Return True if this probe can further divide the current candidate set
    (i.e. not all candidates fall in the same partition).
    """
    partitions: Dict[str, List[str]] = probe.get("partitions", {})
    first_intersection: Optional[Set[str]] = None

    for partition_versions in partitions.values():
        p_set = set(partition_versions) & candidates
        if not p_set:
            continue
        if first_intersection is None:
            first_intersection = p_set
        elif p_set != first_intersection:
            return True

    return False


def _report_result(
    tech_info: Dict[str, Any],
    candidates: Set[str],
    rules_db: Dict,
    args: object,
) -> None:
    """
    Populate tech_info with the version (or version range) identified,
    and record the finding in the result storage.
    """
    if not candidates:
        return

    representative = sorted(candidates, key=_vsort)[0]
    
    # Get rule (support both optimized and legacy formats)
    if rules_db.get("_is_optimized", False):
        # Optimized format
        unique_rules = rules_db.get("_unique_rules", {})
        version_to_rule = rules_db.get("_version_to_rule", {})
        rule_id = version_to_rule.get(representative)
        rule = unique_rules.get(rule_id, {}) if rule_id else {}
    else:
        # Legacy format
        version_rules = rules_db.get("_version_rules", {})
        rule = version_rules.get(representative, {})
    
    identifies: List[str] = rule.get("identifies", sorted(candidates, key=_vsort))

    if len(identifies) == 1:
        version = identifies[0]
        version_min = None
        version_max = None
        version_str = version
        probability = 90
    else:
        version = None
        version_min = identifies[0]
        version_max = identifies[-1]
        version_str = f"{version_min} - {version_max}" if version_min != version_max else version_min
        probability = 70

    tech_info["version"]       = version_str
    tech_info["version_range"] = identifies

    if not tech_info.get("additional_info"):
        tech_info["additional_info"] = []
    tech_info["additional_info"].append(
        f"Apache {version_str} ({probability}%)"
    )

    storage.add_to_storage(
        technology="http_server",
        version=version,
        version_min=version_min,
        version_max=version_max,
        technology_type="Web Server",
        vulnerability="PTV-WEB-INFO-WSICO",
        description=f"Apache icon-file fingerprint: {version_str}",
        probability=probability,
        product_id=10,
    )


def _vsort(v: str):
    """Sortable tuple for a version string."""
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)
