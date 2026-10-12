"""
AST-based static security scanner for Python code.

This scanner analyses code WITHOUT executing it, using Python's built-in
`ast` module to walk the parse tree and detect dangerous patterns.

Security Philosophy:
  - Defence-in-depth: this scanner is one layer; Docker sandboxing is another.
  - We flag, not blindly block. Risk levels guide the decision pipeline.
  - False negatives are worse than false positives for a security tool.
"""
from __future__ import annotations

import ast
import time
from typing import List, Optional, Tuple, Union

from backend.schemas.security import Finding, ScanResponse


# ── Risk weights ─────────────────────────────────────────────────────────────
RISK_WEIGHTS = {"CRITICAL": 40, "HIGH": 15, "MEDIUM": 5, "LOW": 1}
RISK_THRESHOLDS = {"CRITICAL": 40, "HIGH": 15, "MEDIUM": 5}

# ── Dangerous built-in calls ──────────────────────────────────────────────────
DANGEROUS_BUILTINS: dict[str, Tuple[str, str]] = {
    "eval":         ("HIGH",     "Dynamic code evaluation via eval() is a code injection risk."),
    "exec":         ("HIGH",     "Dynamic code execution via exec() can run arbitrary code."),
    "compile":      ("MEDIUM",   "compile() can be used to build and run arbitrary code objects."),
    "__import__":   ("MEDIUM",   "Direct use of __import__() bypasses normal import security."),
    "input":        ("LOW",      "input() reads from stdin — ensure input validation."),
    "open":         ("LOW",      "File I/O detected; verify paths are not user-controlled."),
    "breakpoint":   ("LOW",      "breakpoint() should not appear in production code."),
}

# ── Dangerous module imports ──────────────────────────────────────────────────
DANGEROUS_IMPORTS: dict[str, Tuple[str, str]] = {
    "os":           ("HIGH",     "os module provides access to OS-level operations."),
    "sys":          ("MEDIUM",   "sys module can be used to manipulate the interpreter."),
    "subprocess":   ("HIGH",     "subprocess can spawn arbitrary system processes."),
    "socket":       ("HIGH",     "socket enables raw network connections."),
    "requests":     ("MEDIUM",   "HTTP library — network access inside sandbox is restricted."),
    "urllib":       ("MEDIUM",   "URL library enables outbound HTTP connections."),
    "http":         ("MEDIUM",   "HTTP module enables outbound connections."),
    "ftplib":       ("HIGH",     "FTP library can exfiltrate data."),
    "telnetlib":    ("HIGH",     "Telnet library can create remote connections."),
    "smtplib":      ("HIGH",     "SMTP library can send email — potential data exfiltration."),
    "shutil":       ("MEDIUM",   "shutil can copy/delete filesystem trees."),
    "pathlib":      ("LOW",      "pathlib provides filesystem path manipulation."),
    "tempfile":     ("LOW",      "tempfile creates temporary files/directories."),
    "ctypes":       ("CRITICAL", "ctypes allows direct C library calls — sandbox escape risk."),
    "cffi":         ("CRITICAL", "cffi provides C Foreign Function Interface — sandbox escape risk."),
    "multiprocessing": ("HIGH",  "multiprocessing spawns new OS processes."),
    "threading":    ("MEDIUM",   "threading creates OS-level threads."),
    "pickle":       ("HIGH",     "pickle deserialisation can execute arbitrary code."),
    "marshal":      ("HIGH",     "marshal can execute arbitrary bytecode."),
    "importlib":    ("HIGH",     "importlib can dynamically load arbitrary modules."),
    "pty":          ("CRITICAL", "pty provides pseudo-terminal access — sandbox escape risk."),
    "resource":     ("HIGH",     "resource module can modify process resource limits."),
    "signal":       ("MEDIUM",   "signal module can send signals to processes."),
    "gc":           ("LOW",      "gc (garbage collector) module detected."),
    "builtins":     ("HIGH",     "Direct access to __builtins__ can bypass restrictions."),
    "code":         ("HIGH",     "code module can create interactive interpreter sessions."),
    "codeop":       ("HIGH",     "codeop compiles user-supplied statements."),
    "dis":          ("MEDIUM",   "dis disassembles Python bytecode — used in obfuscation."),
}

# ── Dangerous attribute access patterns ───────────────────────────────────────
DANGEROUS_ATTRIBUTES: dict[str, Tuple[str, str]] = {
    "system":       ("HIGH",     "os.system() executes shell commands directly."),
    "popen":        ("HIGH",     "popen() opens a pipe to a shell command."),
    "execv":        ("CRITICAL", "execv() replaces the current process image."),
    "execve":       ("CRITICAL", "execve() replaces the current process image with env."),
    "fork":         ("HIGH",     "fork() creates a child process — sandbox escape risk."),
    "getenv":       ("LOW",      "getenv() reads environment variables."),
    "putenv":       ("MEDIUM",   "putenv() modifies environment variables."),
    "chmod":        ("HIGH",     "chmod() changes file permissions."),
    "chroot":       ("CRITICAL", "chroot() can escape filesystem jail."),
    "kill":         ("HIGH",     "kill() sends signals to processes."),
    "connect":      ("HIGH",     "socket.connect() establishes a network connection."),
    "bind":         ("HIGH",     "socket.bind() listens on a network port."),
    "__class__":    ("MEDIUM",   "Accessing __class__ may indicate sandbox escape attempt."),
    "__bases__":    ("MEDIUM",   "Accessing __bases__ may indicate class hierarchy traversal."),
    "__subclasses__": ("HIGH",   "__subclasses__() is commonly used in sandbox escape exploits."),
    "__globals__":  ("HIGH",     "__globals__ access can expose module-level variables."),
    "__builtins__": ("HIGH",     "Accessing __builtins__ directly may bypass restrictions."),
    "__code__":     ("HIGH",     "__code__ object access can enable code manipulation."),
    "__import__":   ("HIGH",     "Direct __import__ bypasses normal import machinery."),
}


class SecurityScanner:
    """
    Walks a Python AST and collects security findings without executing code.
    """

    def __init__(self) -> None:
        self._findings: List[Finding] = []

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, code: str) -> ScanResponse:
        """
        Parse and scan Python code; return a ScanResponse with risk rating.
        """
        start = time.perf_counter()
        self._findings = []

        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            # Unparseable code is not necessarily malicious, but flag it.
            elapsed = time.perf_counter() - start
            return ScanResponse(
                risk="LOW",
                findings=[
                    Finding(
                        type="syntax_error",
                        name="SyntaxError",
                        severity="LOW",
                        line=exc.lineno,
                        message=f"Code contains a syntax error: {exc.msg}",
                    )
                ],
                summary="Code could not be parsed — syntax error detected.",
                scan_time=round(elapsed, 4),
            )

        self._walk(tree)

        risk = self._calculate_risk()
        elapsed = time.perf_counter() - start

        return ScanResponse(
            risk=risk,
            findings=self._findings,
            summary=self._build_summary(risk),
            scan_time=round(elapsed, 4),
        )

    # ── AST Visitor ───────────────────────────────────────────────────────────

    def _walk(self, tree: ast.AST) -> None:
        """Walk every node in the AST and dispatch to handlers."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_call(node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                self._check_import(node)
            elif isinstance(node, ast.Attribute):
                self._check_attribute(node)

    def _check_call(self, node: ast.Call) -> None:
        """Detect dangerous built-in function calls."""
        func = node.func

        # Direct call: eval(...), exec(...)
        if isinstance(func, ast.Name):
            name = func.id
            if name in DANGEROUS_BUILTINS:
                severity, message = DANGEROUS_BUILTINS[name]
                self._add(
                    type="dangerous_function",
                    name=name,
                    severity=severity,
                    line=getattr(node, "lineno", None),
                    message=message,
                )

        # Method call: obj.method(...)
        elif isinstance(func, ast.Attribute):
            attr = func.attr
            if attr in DANGEROUS_ATTRIBUTES:
                severity, message = DANGEROUS_ATTRIBUTES[attr]
                self._add(
                    type="dangerous_attribute",
                    name=attr,
                    severity=severity,
                    line=getattr(node, "lineno", None),
                    message=message,
                )

    def _check_import(self, node: Union[ast.Import, ast.ImportFrom]) -> None:
        """Detect imports of dangerous modules."""
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        else:
            # from X import Y  — X is the module
            names = [node.module.split(".")[0]] if node.module else []

        for name in names:
            if name in DANGEROUS_IMPORTS:
                severity, message = DANGEROUS_IMPORTS[name]
                self._add(
                    type="dangerous_import",
                    name=name,
                    severity=severity,
                    line=getattr(node, "lineno", None),
                    message=message,
                )

    def _check_attribute(self, node: ast.Attribute) -> None:
        """
        Detect dangerous dunder/attribute access patterns commonly used in
        sandbox escape exploits (e.g. ''.__class__.__mro__[1].__subclasses__()).
        """
        attr = node.attr
        if attr in DANGEROUS_ATTRIBUTES:
            # Avoid double-reporting things already caught in _check_call
            severity, message = DANGEROUS_ATTRIBUTES[attr]
            # Only add if we haven't already added a finding for this exact line/attr
            if not any(
                f.name == attr and f.line == getattr(node, "lineno", None)
                for f in self._findings
            ):
                self._add(
                    type="dangerous_attribute",
                    name=attr,
                    severity=severity,
                    line=getattr(node, "lineno", None),
                    message=message,
                )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _add(
        self,
        type: str,
        name: str,
        severity: str,
        line: Optional[int],
        message: str,
    ) -> None:
        self._findings.append(
            Finding(type=type, name=name, severity=severity, line=line, message=message)
        )

    def _calculate_risk(self) -> str:
        """
        Aggregate findings into a single risk level using weighted scoring.
        CRITICAL > HIGH > MEDIUM > LOW
        """
        # Any single CRITICAL finding → immediately CRITICAL
        for f in self._findings:
            if f.severity == "CRITICAL":
                return "CRITICAL"

        score = sum(RISK_WEIGHTS.get(f.severity, 0) for f in self._findings)

        if score >= RISK_THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        elif score >= RISK_THRESHOLDS["HIGH"]:
            return "HIGH"
        elif score >= RISK_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        elif self._findings:
            return "LOW"
        return "LOW"

    def _build_summary(self, risk: str) -> str:
        total = len(self._findings)
        if total == 0:
            return "No suspicious patterns detected. Code appears safe for sandboxed execution."
        counts = {}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        parts = [f"{v} {k}" for k, v in sorted(counts.items(), key=lambda x: RISK_WEIGHTS.get(x[0], 0), reverse=True)]
        return f"Risk: {risk}. Found {total} issue(s): {', '.join(parts)}."


# ── Module-level singleton ────────────────────────────────────────────────────
_scanner = SecurityScanner()


def scan_code(code: str) -> ScanResponse:
    """Convenience function — scan Python source and return ScanResponse."""
    return _scanner.scan(code)
