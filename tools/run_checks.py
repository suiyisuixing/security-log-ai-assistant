"""Local validation runner.

Runs:
  1. pytest
  2. python -m compileall backend/app tests tools
  3. npm run build (in frontend/)

Uses only the Python standard library and shells out via subprocess. Does
not install dependencies. Does not call any external service.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"


def _run(label: str, cmd: list, cwd: Path) -> int:
    print(f"\n=== {label} ===")
    print(f"$ {' '.join(str(c) for c in cmd)} (cwd={cwd})")
    proc = subprocess.run(cmd, cwd=str(cwd))
    print(f"--- {label} exit code: {proc.returncode} ---")
    return proc.returncode


def main() -> int:
    py = sys.executable
    failures: list[str] = []

    rc = _run("pytest", [py, "-m", "pytest", "-q"], ROOT)
    if rc != 0:
        failures.append("pytest")

    rc = _run(
        "compileall",
        [py, "-m", "compileall", "backend/app", "tests", "tools"],
        ROOT,
    )
    if rc != 0:
        failures.append("compileall")

    npm = shutil.which("npm") or shutil.which("npm.cmd")
    if not npm:
        print("\n[WARN] npm not found on PATH; skipping frontend build.")
        failures.append("npm-missing")
    elif not (FRONTEND / "node_modules").exists():
        print("\n[WARN] frontend/node_modules missing; skipping frontend build.")
        print("       Run `npm install` in the frontend/ directory first.")
        failures.append("node_modules-missing")
    else:
        rc = _run("npm run build", [npm, "run", "build"], FRONTEND)
        if rc != 0:
            failures.append("npm-build")

    print("\n================ SUMMARY ================")
    if not failures:
        print("All checks passed.")
        return 0
    print("Failures:")
    for f in failures:
        print(f"  - {f}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
