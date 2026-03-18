# VNet Flow Logs Function - Test Suite Added

## Problem Analysis
Customer reported OOM (Out of Memory) errors with exit code 137 when processing large VNet flow log files. The error occurred because the function loads entire blob files into memory at once.

## Root Cause Identified
The [`denormalize_vnet_records()`](cortex_function/__init__.py:153) function builds a complete list of all denormalized records in memory before passing them to [`compress_and_send()`](cortex_function/__init__.py:79). For huge P1H files with thousands of flow records, this exhausts the Azure Function runtime memory.

## Current State
Comprehensive e2e test suite has been added to establish a baseline before making any code changes. This ensures we can detect regressions when implementing the memory optimization fix.

### Tests Added
- **[`tests/test_cortex_function.py`](tests/test_cortex_function.py)**: Comprehensive e2e test suite (11 tests)
  - Tests v1 and v2 vnet flow log formats
  - Tests empty blobs, whitespace-only blobs, partial JSON
  - Tests missing environment variables
  - Tests large payload batching (1000 records)
  - All tests verify correct behavior with mocked HTTP endpoint

### Test Results
```
======================== 11 passed in 0.28s ========================
```

All tests pass against the current implementation, establishing a solid baseline for future refactoring.

## Recommended Fix (Not Yet Implemented)
Refactor [`denormalize_vnet_records()`](cortex_function/__init__.py:153) from a list-building function to a **generator** that yields records one at a time. This would enable streaming processing where:

1. Records are denormalized lazily (on-demand)
2. [`serialize_in_batches()`](cortex_function/__init__.py:55) consumes records as they're generated
3. Memory usage remains constant regardless of file size
4. Batching still works correctly - records are grouped into batches up to `MAX_PAYLOAD_SIZE`

### Expected Memory Impact After Fix
**Before**: O(n) memory where n = total denormalized records (entire file loaded)
**After**: O(1) memory - only current batch held in memory

For a file with 100,000 flow tuples:
- **Before**: ~100,000 records × ~500 bytes = ~50 MB in memory
- **After**: ~batch_size records × ~500 bytes = ~5-10 MB in memory (depending on `MAX_PAYLOAD_SIZE`)

## Next Steps
1. Implement generator-based refactoring in [`denormalize_vnet_records()`](cortex_function/__init__.py:153)
2. Run test suite to verify no regressions
3. Test with customer's actual large files in staging environment
4. Deploy to production
