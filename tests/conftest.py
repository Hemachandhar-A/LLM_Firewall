"""
Pytest configuration for the Adaptive LLM Firewall test suite.

This conftest.py file ensures that the backend module can be imported
from anywhere tests are run, by adding the backend directory to sys.path.
"""

import sys
from pathlib import Path

# Add the backend directory to Python path so classifiers and other
# backend modules can be imported from tests
backend_path = Path(__file__).parent.parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))
