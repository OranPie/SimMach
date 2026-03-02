#!/usr/bin/env bash
set -euo pipefail

python3 -m py_compile $(find . -name "*.py" -not -path "./.git/*")
python3 -m unittest \
  tests.test_conformance_suite \
  tests.test_shell_pipeline_regression \
  tests.test_shell_runtime_integration
