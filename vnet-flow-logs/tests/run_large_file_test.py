#!/usr/bin/env python
"""
Run the large file processing test directly with detailed output
"""
import os
import sys

# Change to the vnet-flow-logs directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Run pytest programmatically
import pytest

print("Running large file processing test...")
print("=" * 80)

exit_code = pytest.main([
    "test_cortex_function.py::TestLargeFileProcessing::test_large_file_processing_with_batching",
    "-v",
    "-s",
    "--tb=short"
])

print("=" * 80)
if exit_code == 0:
    print("✅ Test passed successfully!")
else:
    print(f"❌ Test failed with exit code: {exit_code}")

sys.exit(exit_code)
