# VNET Flow Logs - Tests and Benchmarks

This directory contains tests and benchmarking tools for the VNET flow logs Azure Function.

## Files

### Test Files

- **[`test_cortex_function.py`](test_cortex_function.py)** - E2E tests for the cortex function
  - Tests v1 and v2 flow log formats
  - Tests edge cases (empty blobs, partial JSON, etc.)
  - Tests batching behavior
  - Run with: `pytest test_cortex_function.py -v`

### Benchmark Tools

- **[`generate_large_test_file.py`](generate_large_test_file.py)** - Generates large test files
  - Creates realistic VNET flow logs in v2 format
  - Default: 100 records × 10,000 tuples = 1,000,000 flow tuples
  - Output: ~73 MB JSON file
  - Run with: `python generate_large_test_file.py`

- **[`benchmark_memory.py`](benchmark_memory.py)** - Memory consumption benchmark
  - Measures peak memory usage during blob processing
  - Tracks memory overhead ratio
  - Provides estimates for different file sizes
  - Requires: `pip install psutil`
  - Run with: `python benchmark_memory.py --profile`

- **[`run_large_file_test.py`](run_large_file_test.py)** - Large file processing test runner
  - Runs the comprehensive large file test with detailed output
  - Validates batched processing with ~30 MB test file
  - Shows processing statistics and validation results
  - Run with: `python tests/run_large_file_test.py`

### Generated Files (gitignored)

- **`large_PT1H.json`** - Large test file (~73 MB)
- **`benchmark_results.json`** - Detailed benchmark results

## Running the Benchmark

### Quick Start

```bash
# 1. Install dependencies
pip install psutil pytest

# 2. Generate test file
python vnet-flow-logs/tests/generate_large_test_file.py

# 3. Run benchmark
python vnet-flow-logs/tests/benchmark_memory.py --profile

# 4. View results
cat vnet-flow-logs/tests/benchmark_results.json
```

### Benchmark Options

```bash
# Basic benchmark (no profiling)
python benchmark_memory.py

# With detailed memory profiling
python benchmark_memory.py --profile

# Custom test file
python benchmark_memory.py --file /path/to/custom.json --profile
```

## Benchmark Results Summary

**Current Implementation (as of 2026-03-18)**:

- **File Size**: 72.97 MB
- **Peak Memory**: 886.42 MB
- **Memory Overhead**: **7.83x** file size
- **Risk**: OOM errors for files > 100 MB on Consumption plans

See [`../MEMORY_BENCHMARK_REPORT.md`](../MEMORY_BENCHMARK_REPORT.md) for full analysis.

## Running Tests

```bash
# Run all tests
pytest test_cortex_function.py -v

# Run specific test
pytest test_cortex_function.py::TestCortexFunctionE2E::test_process_vnet_flow_log_v2_all_records_received -v

# Run with coverage
pytest test_cortex_function.py --cov=cortex_function --cov-report=html
```

## Test Data Format

The test files use the Azure VNET Flow Logs v2 format:

```json
{
  "records": [
    {
      "time": "2024-01-15T10:00:00.0000000Z",
      "category": "FlowLogFlowEvent",
      "operationName": "FlowLogFlowEvent",
      "flowLogResourceID": "/subscriptions/.../virtualNetworks/vnet1",
      "macAddress": "00-0D-3A-1B-2C-3D",
      "flowLogVersion": 2,
      "flowRecords": {
        "flows": [
          {
            "flowGroups": [
              {
                "rule": "SecurityRule",
                "flowTuples": [
                  "timestamp,srcIP,dstIP,srcPort,dstPort,protocol,direction,action,flowState,packets,bytes,..."
                ]
              }
            ]
          }
        ]
      }
    }
  ]
}
```

## Customizing Test File Generation

Edit [`generate_large_test_file.py`](generate_large_test_file.py) to adjust:

```python
# In main() function:
num_records = 100          # Number of top-level records
tuples_per_record = 10000  # Flow tuples per record
```

**Examples**:
- Small test: `num_records=10, tuples_per_record=100` → ~750 KB
- Medium test: `num_records=50, tuples_per_record=5000` → ~18 MB
- Large test: `num_records=100, tuples_per_record=10000` → ~73 MB
- Extra large: `num_records=200, tuples_per_record=10000` → ~146 MB

## Troubleshooting

### "psutil not found"

```bash
pip install psutil
```

### "Test file not found"

```bash
python vnet-flow-logs/tests/generate_large_test_file.py
```

### Memory benchmark shows different results

Memory usage can vary based on:
- Python version
- System memory pressure
- Background processes
- OS caching behavior

Run the benchmark multiple times and average the results for consistency.
