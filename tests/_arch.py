"""Shared helpers for the core import-boundary architecture tests.

The authoritative list of "core" modules lives in ``AGENTS.md`` (the
*Import boundary* hard rule): core modules must never import
``gpo_lens.narration`` or ``gpo_lens.web``. This module is the single
source of truth consumed by ``tests/test_narration.py`` and
``tests/test_web.py``.

The check is AST-based (``ast.parse`` + walk over ``Import`` /
``ImportFrom``), not regex, so it cannot be fooled by mentions in string
literals, comments, attribute access, or attribute-only references. Keep
this list in sync with the *Import boundary* section of ``AGENTS.md``;
widening the boundary requires editing ``AGENTS.md`` first.
"""

from __future__ import annotations

import ast
import importlib.util
from collections.abc import Collection
from pathlib import Path

import pytest

CORE_MODULES: tuple[str, ...] = (
    "model",
    "normalize",
    "ingest",
    "store",
    "queries",
    "snapshot_diff",
    "detection",
    "dependencies",
    "admx_parser",
    "display",
    "exports",
    "safe_output",
    "report",
    "events",
    "sinks",
    "query_dispatch",
    "authz",
    "topology",
    "registry_pol",
    "paths",
    "danger",
    "merge",
    "trend",
    "findings",
    "finding_model",
    "_legacy_findings",
)

FORBIDDEN_PACKAGES: tuple[str, ...] = ("narration", "web")


def module_source_paths(module_name: str) -> list[Path]:
    """Resolve the on-disk source path(s) of ``gpo_lens.<module_name>``.

    For a plain module, returns a single-element list (the ``.py`` file).
    For a package, returns every ``.py`` file in the package directory
    (including ``__init__.py``), so the import-boundary check covers every
    submodule — a package's boundary is only as clean as its weakest file.
    """
    spec = importlib.util.find_spec(f"gpo_lens.{module_name}")
    if spec is None or spec.origin is None:
        raise FileNotFoundError(f"gpo_lens.{module_name} has no source")
    init_path = Path(spec.origin)
    if spec.submodule_search_locations is None:
        # Plain module.
        return [init_path]
    # Package: walk every .py file under the package directory.
    pkg_dir = Path(next(iter(spec.submodule_search_locations)))
    return sorted(pkg_dir.rglob("*.py"))


def imported_module_paths(module_name: str) -> set[str]:
    """Return every absolute module path imported by ``gpo_lens.<module_name>``.

    Walks the full AST (not just module level), so imports nested inside
    functions or conditional blocks are caught too. Relative imports are
    resolved against the ``gpo_lens`` package. Aliased imports
    (``import a.b as c``) contribute their original dotted name (``a.b``).

    When the module is a package, every ``.py`` file in the package is
    walked and the results unioned.
    """
    out: set[str] = set()
    base_parts = "gpo_lens".split(".")
    for path in module_source_paths(module_name):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    out.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0:
                    base = node.module or ""
                else:
                    if node.level > len(base_parts):
                        continue
                    resolved = base_parts[: len(base_parts) - node.level + 1]
                    if node.module:
                        resolved.append(node.module)
                    base = ".".join(resolved)
                if base:
                    out.add(base)
                for alias in node.names:
                    joined = f"{base}.{alias.name}" if base else alias.name
                    out.add(joined)
    return out


def _is_forbidden(imported: str, forbidden: Collection[str]) -> bool:
    top = imported.split(".", 1)[0]
    if top in forbidden:
        return True
    for pkg in forbidden:
        qualified = f"gpo_lens.{pkg}"
        if imported == qualified or imported.startswith(qualified + "."):
            return True
    return False


def forbidden_imports_in(
    module_name: str,
    forbidden: Collection[str] = FORBIDDEN_PACKAGES,
) -> set[str]:
    """Return the set of forbidden imports found in ``gpo_lens.<module_name>``.

    Matches the bare packages (e.g. ``narration``, ``web``) and any subpath
    of ``gpo_lens.narration`` / ``gpo_lens.web``. Intra-core imports
    (e.g. ``queries`` importing ``model``) are allowed.
    """
    return {imp for imp in imported_module_paths(module_name) if _is_forbidden(imp, forbidden)}


def test_no_dynamic_imports_of_forbidden_modules() -> None:
    """Verify no core module uses importlib or __import__ to load narration/web."""
    forbidden_substrings = (
        "gpo_lens.narration",
        "gpo_lens.web",
        ".narration",
        ".web",
    )
    for module_name in CORE_MODULES:
        for module_path in module_source_paths(module_name):
            source = module_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(module_path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                # Check importlib.import_module("...")
                if isinstance(func, ast.Attribute) and func.attr == "import_module":
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if any(s in arg.value for s in forbidden_substrings):
                                pytest.fail(
                                    f"{module_path} uses importlib.import_module "
                                    f"to load forbidden module: {arg.value}"
                                )
                # Check __import__("...")
                if isinstance(func, ast.Name) and func.id == "__import__":
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if any(s in arg.value for s in forbidden_substrings):
                                pytest.fail(
                                    f"{module_path} uses __import__ "
                                    f"to load forbidden module: {arg.value}"
                                )
