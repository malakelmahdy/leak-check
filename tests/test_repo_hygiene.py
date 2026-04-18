from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path


def _internal_import_graph() -> tuple[dict[str, Path], dict[str, set[str]]]:
    root = Path("src/leakcheck")
    modules: dict[str, Path] = {}
    imports: dict[str, set[str]] = defaultdict(set)

    for path in root.rglob("*.py"):
        rel = path.relative_to(root).with_suffix("")
        module_name = "leakcheck" + ("." + ".".join(rel.parts) if rel.parts else "")
        modules[module_name] = path

    for module_name, path in modules.items():
        tree = ast.parse(path.read_text(encoding="utf-8") or "", filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("leakcheck"):
                        imports[module_name].add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.level:
                    base_parts = module_name.split(".")[:-node.level]
                    target = ".".join(base_parts + [node.module])
                else:
                    target = node.module
                if target.startswith("leakcheck"):
                    imports[module_name].add(target)

    return modules, imports


def _find_cycles(modules: dict[str, Path], imports: dict[str, set[str]]) -> list[tuple[str, ...]]:
    seen: set[str] = set()
    stack: list[str] = []
    cycles: set[tuple[str, ...]] = set()

    def dfs(node: str) -> None:
        seen.add(node)
        stack.append(node)
        for nxt in imports.get(node, set()):
            if nxt not in modules:
                continue
            if nxt in stack:
                start = stack.index(nxt)
                cycles.add(tuple(stack[start:] + [nxt]))
            elif nxt not in seen:
                dfs(nxt)
        stack.pop()

    for module_name in modules:
        if module_name not in seen:
            dfs(module_name)

    return sorted(cycles)


def test_repo_has_no_internal_import_cycles():
    modules, imports = _internal_import_graph()
    cycles = _find_cycles(modules, imports)
    assert not cycles, f"Import cycles detected: {cycles}"
