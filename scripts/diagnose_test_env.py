#!/usr/bin/env python3
"""Quick environment diagnostic for local pytest failures."""

from __future__ import annotations

import ast
import platform
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

REQUIRED_PACKAGES = [
    "fastapi",
    "uvicorn",
    "pytest",
    "httpx",
    "sqlalchemy",
    "authlib",
    "alembic",
]

REQUIRED_MAIN_SYMBOLS = [
    "AUTH_MODE",
    "INGEST_API_KEY",
    "SessionLocal",
    "SecurityHeadersMiddleware",
    "IngestProtectionMiddleware",
    "detect_and_parse_report",
    "fingerprint_finding",
]


def print_header(title: str) -> None:
    print(f"\n=== {title} ===")


def collect_symbols(main_path: Path) -> set[str]:
    tree = ast.parse(main_path.read_text())
    found: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            found.add(node.name)
        elif isinstance(node, ast.AsyncFunctionDef):
            found.add(node.name)
        elif isinstance(node, ast.ClassDef):
            found.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found.add(target.id)
    return found


def main() -> int:
    print_header("Python runtime")
    print(f"python_executable: {sys.executable}")
    print(f"python_version: {platform.python_version()}")

    print_header("Package versions")
    missing_pkg = False
    for package in REQUIRED_PACKAGES:
        try:
            print(f"{package}: {version(package)}")
        except PackageNotFoundError:
            print(f"{package}: MISSING")
            missing_pkg = True

    main_path = Path("app/main.py")
    print_header("app/main.py")
    if not main_path.exists():
        print("MISSING: app/main.py")
        return 1
    print(f"path: {main_path.resolve()}")

    symbols = collect_symbols(main_path)
    print_header("Expected symbols")
    missing_symbols: list[str] = []
    for symbol in REQUIRED_MAIN_SYMBOLS:
        present = symbol in symbols
        print(f"{symbol}: {'OK' if present else 'MISSING'}")
        if not present:
            missing_symbols.append(symbol)

    if missing_pkg or missing_symbols:
        print_header("Result")
        print("Environment mismatch detected.")
        print("Run: python3 -m pip install -r requirements.txt && python3 -m pytest -q")
        if missing_symbols:
            print("If symbols remain missing, your local app/main.py is out of date.")
        return 1

    print_header("Result")
    print("Environment looks consistent with this repository.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
