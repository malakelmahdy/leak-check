from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path


def _module_graph() -> tuple[dict[str, Path], dict[str, set[str]]]:
    root = Path(__file__).resolve().parents[1] / "src" / "leakcheck"
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

    def dfs(module_name: str) -> None:
        seen.add(module_name)
        stack.append(module_name)
        for target in imports.get(module_name, set()):
            if target not in modules:
                continue
            if target in stack:
                start = stack.index(target)
                cycles.add(tuple(stack[start:] + [target]))
            elif target not in seen:
                dfs(target)
        stack.pop()

    for module_name in modules:
        if module_name not in seen:
            dfs(module_name)

    return sorted(cycles)


def test_internal_import_graph_has_no_cycles():
    modules, imports = _module_graph()
    cycles = _find_cycles(modules, imports)

    assert not cycles, "Import cycles detected:\n" + "\n".join(" -> ".join(cycle) for cycle in cycles)
