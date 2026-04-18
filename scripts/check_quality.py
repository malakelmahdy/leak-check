from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_DIRS = [ROOT / "src", ROOT / "scripts", ROOT / "tests"]
LEAKCHECK_ROOT = ROOT / "src" / "leakcheck"


def _python_files() -> list[Path]:
    files: list[Path] = []
    for base in PYTHON_DIRS:
        if not base.exists():
            continue
        files.extend(sorted(base.rglob("*.py")))
    return files


def check_syntax() -> list[str]:
    errors: list[str] = []
    for path in _python_files():
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            errors.append(f"{path}: syntax error: {exc}")
    return errors


def _module_name(path: Path) -> str:
    rel = path.relative_to(LEAKCHECK_ROOT).with_suffix("")
    return "leakcheck" + ("." + ".".join(rel.parts) if rel.parts else "")


def _dependency_graph() -> dict[str, set[str]]:
    modules = {_module_name(path): path for path in LEAKCHECK_ROOT.rglob("*.py")}
    graph: dict[str, set[str]] = defaultdict(set)
    for mod, path in modules.items():
        tree = ast.parse(path.read_text(encoding="utf-8") or "", filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("leakcheck"):
                        graph[mod].add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.level:
                    base_parts = mod.split(".")[:-node.level]
                    target = ".".join(base_parts + [node.module])
                else:
                    target = node.module
                if target.startswith("leakcheck"):
                    graph[mod].add(target)
    return graph


def check_cycles() -> list[str]:
    graph = _dependency_graph()
    seen: set[str] = set()
    stack: list[str] = []
    cycles: set[tuple[str, ...]] = set()

    def dfs(node: str) -> None:
        seen.add(node)
        stack.append(node)
        for nxt in graph.get(node, set()):
            if not nxt.startswith("leakcheck"):
                continue
            if nxt in stack:
                idx = stack.index(nxt)
                cycles.add(tuple(stack[idx:] + [nxt]))
            elif nxt not in seen:
                dfs(nxt)
        stack.pop()

    for node in sorted(graph):
        if node not in seen:
            dfs(node)
    return [" -> ".join(cycle) for cycle in sorted(cycles)]


def run_pytest() -> int:
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "tests"], cwd=ROOT).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Run lightweight LeakCheck quality gates.")
    parser.add_argument("--run-tests", action="store_true", help="Also run the pytest suite.")
    args = parser.parse_args()

    syntax_errors = check_syntax()
    cycles = check_cycles()

    if syntax_errors:
        print("Syntax errors detected:")
        for error in syntax_errors:
            print(f"  - {error}")
    else:
        print("Syntax check: ok")

    if cycles:
        print("Import cycles detected:")
        for cycle in cycles:
            print(f"  - {cycle}")
    else:
        print("Import cycle check: ok")

    if syntax_errors or cycles:
        return 1

    if args.run_tests:
        return run_pytest()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
