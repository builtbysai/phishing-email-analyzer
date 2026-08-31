"""Tiny fallback runner for the pytest-style suite when pytest is unavailable.

The tests remain ordinary pytest tests. This runner supports the suite's only
fixture (`tmp_path`) so contributors can verify the project without installing
anything.
"""

from __future__ import annotations

import importlib
import inspect
import sys
import tempfile
import traceback
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent
    modules = [f"tests.{path.stem}" for path in sorted((root / "tests").glob("test_*.py"))]
    passed = 0
    failed = 0
    for module_name in modules:
        module = importlib.import_module(module_name)
        tests = [
            value
            for name, value in inspect.getmembers(module, inspect.isfunction)
            if name.startswith("test_") and value.__module__ == module_name
        ]
        for test in tests:
            try:
                parameters = inspect.signature(test).parameters
                if not parameters:
                    test()
                elif list(parameters) == ["tmp_path"]:
                    with tempfile.TemporaryDirectory(prefix="pea-test-") as directory:
                        test(Path(directory))
                else:
                    raise TypeError(f"Unsupported test parameters: {', '.join(parameters)}")
            except Exception:
                failed += 1
                print(f"FAIL {module_name}.{test.__name__}")
                traceback.print_exc()
            else:
                passed += 1
                print(f"PASS {module_name}.{test.__name__}")
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
