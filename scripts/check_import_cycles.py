from __future__ import annotations

import ast
import sys
from collections import defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "src" / "leakcheck"


def _module_name(path: Path) -> str:
    rel = path.relative_to(PACKAGE_ROOT).with_suffix("")
    return "leakcheck" + ("." + ".".join(rel.parts) if rel.parts else "")


def _module_imports(module_name: str, path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8") or "", filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.level:
                base_parts = module_name.split(".")[:-node.level]
                target = ".".join(base_parts + [node.module])
            else:
                target = node.module
            if target.startswith("leakcheck"):
                imports.add(target)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("leakcheck"):
                    imports.add(alias.name)
    return imports


def find_cycles() -> list[tuple[str, ...]]:
    modules = {_module_name(path): path for path in PACKAGE_ROOT.rglob("*.py")}
    graph: dict[str, set[str]] = defaultdict(set)
    for module_name, path in modules.items():
        graph[module_name] = {
            target
            for target in _module_imports(module_name, path)
            if target in modules
        }

    visited: set[str] = set()
    stack: list[str] = []
    cycles: set[tuple[str, ...]] = set()

    def dfs(node: str) -> None:
        visited.add(node)
        stack.append(node)
        for target in graph.get(node, set()):
            if target in stack:
                start = stack.index(target)
                cycles.add(tuple(stack[start:] + [target]))
            elif target not in visited:
                dfs(target)
        stack.pop()

    for module_name in modules:
        if module_name not in visited:
            dfs(module_name)

    return sorted(cycles)


def main() -> int:
    cycles = find_cycles()
    if cycles:
        print("Import cycles detected:")
        for cycle in cycles:
            print(" -> ".join(cycle))
        return 1
    print("No import cycles detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
