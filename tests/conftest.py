"""Pytest configuration — add src to path for all tests."""
import sys
import os

# Add project src directory to Python path
src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
src_path = os.path.abspath(src_path)
if src_path not in sys.path:
    sys.path.insert(0, src_path)
