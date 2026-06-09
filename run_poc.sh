#!/bin/bash
set -e
# This script runs the PoC for the MerkleSet depth overflow DoS.
# It requires maturin and a python environment.
if [ ! -d "venv" ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install maturin
else
    source venv/bin/activate
fi
maturin develop
python3 test_panic.py
