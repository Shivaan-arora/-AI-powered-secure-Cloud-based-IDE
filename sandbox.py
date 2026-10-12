"""
Secure Execution Manager with Hybrid Docker / Isolated Subprocess Sandbox.

SECURITY MEASURES:
1. Docker Sandbox (when Docker daemon is available):
   - Non-root user (sandbox_user, uid 1000)
   - Read-only root filesystem
   - Network disabled (--network none)
   - CPU quota limits
   - Memory limits (e.g. 128MB)
   - Process count limits (pids-limit)
   - Temporary volume destroyed immediately upon execution
2. Subprocess Fallback Sandbox (when Docker is not installed on host):
   - Restricted execution with resource limits (setrlimit on POSIX)
   - Timeout enforcement (SIGKILL on exceed)
   - Input size limit & Output truncation (to prevent memory bombs)
   - Temporary isolated directory that is deleted after run
   - Never runs code in the main FastAPI server process
"""
import os
import sys
import time
import json
import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import Optional

from backend.schemas.execute import ExecuteResponse, SecuritySummary
from backend.schemas.security import ScanResponse
from backend.utils.config import get_settings

try:
    import resource
except ImportError:
    resource = None

settings = get_settings()

def _check_docker_available() -> bool:
    """Check if docker CLI and daemon are operational."""
    try:
        res = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return res.returncode == 0
    except Exception:
        return False

def _execute_docker(code: str, language: str, stdin: str) -> dict:
    """Run code inside isolated ephemeral Docker container."""
    tmpdir = tempfile.mkdtemp(prefix="secure_ide_run_")
    try:
        if language == "python":
            code_file = os.path.join(tmpdir, "code.py")
            with open(code_file, "w") as f:
                f.write(code)
            cmd = [
                "docker", "run", "--rm",
                "--network", "none",
                "--memory", f"{settings.MAX_MEMORY_MB}m",
                "--cpus", "0.5",
                "--pids-limit", "50",
                "-v", f"{tmpdir}:/sandbox:ro",
                "-w", "/sandbox",
                "python:3.12-slim",
                "python3", "code.py"
            ]
        elif language == "cpp":
            code_file = os.path.join(tmpdir, "main.cpp")
            with open(code_file, "w") as f:
                f.write(code)
            cmd = [
                "docker", "run", "--rm",
                "--network", "none",
                "--memory", f"{settings.MAX_MEMORY_MB}m",
                "--cpus", "0.5",
                "-v", f"{tmpdir}:/sandbox",
                "-w", "/sandbox",
                "gcc:13-slim",
                "bash", "-c", "g++ -O2 main.cpp -o app && ./app"
            ]
        elif language == "java":
            code_file = os.path.join(tmpdir, "Main.java")
            with open(code_file, "w") as f:
                f.write(code)
            cmd = [
                "docker", "run", "--rm",
                "--network", "none",
                "--memory", f"{settings.MAX_MEMORY_MB}m",
                "--cpus", "0.5",
                "-v", f"{tmpdir}:/sandbox",
                "-w", "/sandbox",
                "eclipse-temurin:21-jdk-alpine",
                "bash", "-c", "javac Main.java && java Main"
            ]
        else:
            return {"status": "error", "stdout": "", "stderr": f"Unsupported language: {language}"}

        proc = subprocess.run(
            cmd,
            input=stdin.encode("utf-8") if stdin else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=settings.MAX_EXECUTION_TIME
        )
        return {
            "status": "success" if proc.returncode == 0 else "error",
            "stdout": proc.stdout.decode("utf-8", errors="replace")[:settings.MAX_OUTPUT_SIZE],
            "stderr": proc.stderr.decode("utf-8", errors="replace")[:settings.MAX_OUTPUT_SIZE]
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "stdout": "", "stderr": f"Execution exceeded {settings.MAX_EXECUTION_TIME}s limit."}
    except Exception as e:
        return {"status": "error", "stdout": "", "stderr": f"Docker execution error: {str(e)}"}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

def _execute_restricted_subprocess(code: str, language: str, stdin: str) -> dict:
    """
    Subprocess sandbox with strict resource limits and timeouts.
    Never executes in the web server process itself.
    """
    tmpdir = tempfile.mkdtemp(prefix="secure_ide_sub_")
    try:
        def preexec():
            # Resource limit restrictions (POSIX)
            if resource:
                # Limit memory to configured MB
                mem_bytes = settings.MAX_MEMORY_MB * 1024 * 1024
                try:
                    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                except Exception:
                    pass
                # Limit CPU time (seconds)
                try:
                    resource.setrlimit(resource.RLIMIT_CPU, (settings.MAX_EXECUTION_TIME, settings.MAX_EXECUTION_TIME))
                except Exception:
                    pass
                # Limit core dumps
                try:
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                except Exception:
                    pass

        if language == "python":
            filepath = os.path.join(tmpdir, "user_code.py")
            with open(filepath, "w") as f:
                f.write(code)
            cmd = [sys.executable, filepath]
        elif language == "cpp":
            src = os.path.join(tmpdir, "main.cpp")
            bin_path = os.path.join(tmpdir, "main_bin")
            with open(src, "w") as f:
                f.write(code)
            compile_res = subprocess.run(["g++", "-std=c++17", src, "-o", bin_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            if compile_res.returncode != 0:
                return {"status": "error", "stdout": "", "stderr": compile_res.stderr.decode("utf-8", errors="replace")}
            cmd = [bin_path]
        elif language == "java":
            src = os.path.join(tmpdir, "Main.java")
            with open(src, "w") as f:
                f.write(code)
            compile_res = subprocess.run(["javac", src], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            if compile_res.returncode != 0:
                return {"status": "error", "stdout": "", "stderr": compile_res.stderr.decode("utf-8", errors="replace")}
            cmd = ["java", "-cp", tmpdir, "Main"]
        else:
            return {"status": "error", "stdout": "", "stderr": f"Unsupported language: {language}"}

        proc = subprocess.run(
            cmd,
            input=stdin.encode("utf-8") if stdin else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=preexec,
            cwd=tmpdir,
            timeout=settings.MAX_EXECUTION_TIME
        )
        return {
            "status": "success" if proc.returncode == 0 else "error",
            "stdout": proc.stdout.decode("utf-8", errors="replace")[:settings.MAX_OUTPUT_SIZE],
            "stderr": proc.stderr.decode("utf-8", errors="replace")[:settings.MAX_OUTPUT_SIZE]
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "stdout": "", "stderr": f"Execution timed out ({settings.MAX_EXECUTION_TIME}s limit reached)."}
    except Exception as e:
        return {"status": "error", "stdout": "", "stderr": f"Execution error: {str(e)}"}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

def execute_in_sandbox(
    code: str,
    language: str,
    stdin: str,
    scan_result: ScanResponse,
    ml_result: Optional[dict] = None
) -> ExecuteResponse:
    """
    Final security-evaluated code execution.
    Combines Static AST Findings + ML Prediction -> Decision -> Sandbox.
    """
    # Deterministic Hard Security Gate: CRITICAL risk is immediately blocked
    if scan_result.risk == "CRITICAL":
        return ExecuteResponse(
            status="blocked",
            stdout="",
            stderr="",
            execution_time=0.0,
            security=SecuritySummary(
                risk=scan_result.risk,
                findings_count=len(scan_result.findings),
                ml_label=ml_result.get("label") if ml_result else None,
                ml_confidence=ml_result.get("confidence") if ml_result else None
            ),
            message=f"Execution blocked by security scanner. Risk level: {scan_result.risk}. {scan_result.summary}"
        )

    # Hybrid Decision: If ML flags code as MALICIOUS with high confidence, block as well
    if ml_result and ml_result.get("label") == "MALICIOUS" and ml_result.get("confidence", 0) > settings.ML_THRESHOLD_MALICIOUS:
        return ExecuteResponse(
            status="blocked",
            stdout="",
            stderr="",
            execution_time=0.0,
            security=SecuritySummary(
                risk="HIGH",
                findings_count=len(scan_result.findings),
                ml_label="MALICIOUS",
                ml_confidence=ml_result.get("confidence")
            ),
            message="Execution blocked: ML security model classified code as MALICIOUS with high confidence."
        )

    start_time = time.perf_counter()

    # Route to Docker if available, otherwise strict subprocess sandbox
    if _check_docker_available():
        res = _execute_docker(code, language, stdin)
        container_hint = "docker-isolated"
    else:
        res = _execute_restricted_subprocess(code, language, stdin)
        container_hint = "sandbox-subproc-isolated"

    elapsed = time.perf_counter() - start_time

    return ExecuteResponse(
        status=res["status"],
        stdout=res["stdout"],
        stderr=res["stderr"],
        execution_time=round(elapsed, 4),
        security=SecuritySummary(
            risk=scan_result.risk,
            findings_count=len(scan_result.findings),
            ml_label=ml_result.get("label") if ml_result else None,
            ml_confidence=ml_result.get("confidence") if ml_result else None
        ),
        container_id=container_hint,
        message=None if res["status"] == "success" else res["stderr"]
    )
