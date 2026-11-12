#!/bin/sh
# Run from repository root
set -e
.venv/bin/python security/session-integrity/demo_01_signer_scope.py
echo
.venv/bin/python security/session-integrity/demo_02_protected.py
echo
.venv/bin/python -m pytest security/session-integrity/test_integrity.py -q -o addopts=
