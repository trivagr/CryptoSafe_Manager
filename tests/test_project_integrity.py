import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
BLOCKED_MARKERS = ("TO" + "DO", "FIX" + "ME", "X" * 3, "HA" + "CK")


def _module_name(path: Path) -> str:
    relative = path.relative_to(PROJECT_ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _source_modules() -> dict[str, Path]:
    return {_module_name(path): path for path in SOURCE_ROOT.rglob("*.py")}


def _resolve_import(module_name: str, import_node: ast.ImportFrom) -> str:
    if import_node.level == 0:
        return import_node.module or ""

    package_parts = module_name.split(".")[:-1]
    base_parts = package_parts[: len(package_parts) - import_node.level + 1]
    if import_node.module:
        base_parts.extend(import_node.module.split("."))
    return ".".join(part for part in base_parts if part)


def test_source_has_no_todo_or_fixme_markers():
    offenders = []
    for path in SOURCE_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8-sig")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if any(marker in line for marker in BLOCKED_MARKERS):
                offenders.append(f"{path.relative_to(PROJECT_ROOT)}:{line_number}: {line.strip()}")

    assert offenders == []


def test_source_modules_do_not_have_circular_imports():
    modules = _source_modules()
    edges = {module_name: set() for module_name in modules}

    for module_name, path in modules.items():
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in modules:
                        edges[module_name].add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                target = _resolve_import(module_name, node)
                if target in modules:
                    edges[module_name].add(target)
                for alias in node.names:
                    child_target = f"{target}.{alias.name}" if target else alias.name
                    if child_target in modules:
                        edges[module_name].add(child_target)

    visiting = set()
    visited = set()
    stack = []
    cycles = []

    def visit(module_name: str):
        visiting.add(module_name)
        stack.append(module_name)
        for dependency in edges[module_name]:
            if dependency == module_name:
                continue
            if dependency in visiting:
                cycles.append(stack[stack.index(dependency) :] + [dependency])
            elif dependency not in visited:
                visit(dependency)
        stack.pop()
        visiting.remove(module_name)
        visited.add(module_name)

    for module_name in modules:
        if module_name not in visited:
            visit(module_name)

    readable_cycles = [" -> ".join(cycle) for cycle in cycles]
    assert readable_cycles == []