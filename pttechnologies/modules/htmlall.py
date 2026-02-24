"""
HTMLALL - HTML Analysis Bundle Module

This module sequentially calls three HTML-related detection modules:
HTMLSIG, JSLIB and PLUGINS.

It is NOT included in the default test run. Use -ts HTMLALL to invoke it explicitly.

Usage:
    pttechnologies -u https://www.example.com -ts HTMLALL
"""

import os
import sys
import importlib.util

from helpers.stored_responses import StoredResponses

__TESTLABEL__ = "HTML bundle: runs HTMLSIG + JSLIB + PLUGINS"

_SUBMODULES = ["htmlsig", "jslib", "plugins"]


def _import_submodule(module_name: str):
    """
    Dynamically imports a sibling module from the same 'modules' directory.

    Args:
        module_name (str): Module filename without .py extension.

    Returns:
        ModuleType: Loaded Python module.
    """
    module_path = os.path.join(os.path.dirname(__file__), f"{module_name}.py")
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None:
        raise ImportError(f"Cannot find spec for '{module_name}' at {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def run(args, ptjsonlib, helpers, http_client, responses: StoredResponses):
    """
    Entry point for the HTML bundle.

    Sequentially calls run() on HTMLSIG, JSLIB and PLUGINS modules,
    passing through all arguments unchanged.
    """
    for i, module_name in enumerate(_SUBMODULES):
        mod = _import_submodule(module_name)
        mod.run(
            args=args,
            ptjsonlib=ptjsonlib,
            helpers=helpers,
            http_client=http_client,
            responses=responses,
        )
        if i < len(_SUBMODULES) - 1:
            print()