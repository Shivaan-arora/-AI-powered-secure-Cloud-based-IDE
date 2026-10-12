"""
Feature extraction for ML-based malicious code detection (Phase 13).

Features extracted from Python source code using AST analysis:
  - Structural features (node counts, complexity)
  - Security-relevant API usage counts
  - Import patterns

These numeric features feed into the Random Forest classifier.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, asdict
from typing import Dict, Union, List, Optional


@dataclass
class CodeFeatures:
    # ── Structural ────────────────────────────────────────────────────────────
    ast_node_count: int = 0
    function_count: int = 0
    class_count: int = 0
    loop_count: int = 0
    import_count: int = 0
    lines_of_code: int = 0
    code_length: int = 0

    # ── Dangerous API counts ──────────────────────────────────────────────────
    eval_count: int = 0
    exec_count: int = 0
    compile_count: int = 0
    subprocess_count: int = 0
    os_usage_count: int = 0
    socket_count: int = 0
    file_op_count: int = 0
    network_op_count: int = 0
    dynamic_import_count: int = 0
    dangerous_api_total: int = 0

    # ── Dunder / escape patterns ──────────────────────────────────────────────
    dunder_access_count: int = 0
    subclasses_access: int = 0

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)

    def to_list(self) -> list:
        return list(asdict(self).values())

    @classmethod
    def feature_names(cls) -> list[str]:
        return list(cls.__dataclass_fields__.keys())


def extract_features(code: str) -> CodeFeatures:
    """
    Parse Python source and extract numeric features for ML classification.
    Returns a CodeFeatures instance. If the code has a syntax error,
    returns a zeroed feature vector (syntax errors are flagged elsewhere).
    """
    features = CodeFeatures()
    features.code_length = len(code)
    features.lines_of_code = code.count("\n") + 1

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return features

    for node in ast.walk(tree):
        features.ast_node_count += 1

        # Structural
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            features.function_count += 1
        elif isinstance(node, ast.ClassDef):
            features.class_count += 1
        elif isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
            features.loop_count += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            features.import_count += 1
            _check_import(node, features)

        # Dangerous calls
        elif isinstance(node, ast.Call):
            _check_call(node, features)

        # Attribute access (dunder patterns)
        elif isinstance(node, ast.Attribute):
            _check_attribute(node, features)

    # Aggregate dangerous API total
    features.dangerous_api_total = (
        features.eval_count
        + features.exec_count
        + features.compile_count
        + features.subprocess_count
        + features.os_usage_count
        + features.socket_count
        + features.network_op_count
        + features.dynamic_import_count
        + features.dunder_access_count
        + features.subclasses_access
    )

    return features


def _check_import(node: ast.Import | ast.ImportFrom, f: CodeFeatures) -> None:
    if isinstance(node, ast.Import):
        names = [a.name.split(".")[0] for a in node.names]
    else:
        names = [node.module.split(".")[0]] if node.module else []

    for name in names:
        if name == "subprocess":
            f.subprocess_count += 1
        elif name == "os":
            f.os_usage_count += 1
        elif name == "socket":
            f.socket_count += 1
        elif name in ("importlib",):
            f.dynamic_import_count += 1


def _check_call(node: ast.Call, f: CodeFeatures) -> None:
    func = node.func
    if isinstance(func, ast.Name):
        name = func.id
        if name == "eval":
            f.eval_count += 1
        elif name == "exec":
            f.exec_count += 1
        elif name == "compile":
            f.compile_count += 1
        elif name == "__import__":
            f.dynamic_import_count += 1
        elif name in ("open",):
            f.file_op_count += 1
    elif isinstance(func, ast.Attribute):
        attr = func.attr
        if attr in ("system", "popen", "execv", "execve", "fork", "spawn"):
            f.os_usage_count += 1
        elif attr in ("connect", "bind", "sendall", "recv"):
            f.network_op_count += 1
        elif attr in ("open", "read", "write"):
            f.file_op_count += 1


def _check_attribute(node: ast.Attribute, f: CodeFeatures) -> None:
    attr = node.attr
    if attr.startswith("__") and attr.endswith("__"):
        f.dunder_access_count += 1
    if attr == "__subclasses__":
        f.subclasses_access += 1
