"""
Memory benchmark for VNET flow logs function.
Measures peak memory consumption when processing large flow log files.

This benchmark simulates the current implementation's memory usage pattern:
1. Read entire blob into memory (blob.read())
2. Parse entire JSON
3. Denormalize all records
4. Batch and send to HTTP endpoint

Usage:
    python benchmark_memory.py [--file <path>] [--profile]
"""

import argparse
import gc
import json
import os
import sys
import tracemalloc
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class MockInputStream:
    """Mock azure.functions.InputStream for testing"""

    def __init__(self, content: str, name: str = 'test-blob.json', length: int = None):
        self.content = content
        self.name = name
        self.length = length if length is not None else len(content.encode('utf-8'))

    def read(self):
        """Simulate blob.read() - returns all content at once"""
        return self.content.encode('utf-8')


def format_bytes(bytes_value):
    """Format bytes into human-readable string"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f'{bytes_value:.2f} {unit}'
        bytes_value /= 1024.0
    return f'{bytes_value:.2f} TB'


def run_benchmark(test_file_path, use_profiler=False):
    """
    Run memory benchmark on the VNET flow logs function.

    Args:
        test_file_path: Path to the test JSON file
        use_profiler: If True, use tracemalloc for detailed profiling

    Returns:
        Dictionary with benchmark results
    """
    print('=' * 80)
    print('VNET Flow Logs - Memory Benchmark')
    print('=' * 80)
    print(f'\nTest file: {test_file_path}')

    # Get file size
    file_size = os.path.getsize(test_file_path)
    print(f'File size: {format_bytes(file_size)}')

    # Read the test file
    print('\nLoading test file into memory...')
    with open(test_file_path) as f:
        file_content = f.read()

    # Count records
    data = json.loads(file_content)
    num_records = len(data['records'])
    total_tuples = sum(
        len(flow_tuple)
        for record in data['records']
        for flow in record['flowRecords']['flows']
        for group in flow['flowGroups']
        for flow_tuple in group['flowTuples']
    )

    print(f'Records in file: {num_records:,}')
    print(f'Total flow tuples: {total_tuples:,}')

    # Setup environment
    with patch.dict(
        os.environ,
        {
            'CORTEX_HTTP_ENDPOINT': 'http://localhost:8888/api/logs',
            'CORTEX_ACCESS_TOKEN': 'test-token-benchmark',
            'MAX_PAYLOAD_SIZE': '10000000',  # 10MB
            'HTTP_MAX_RETRIES': '1',
            'RETRY_INTERVAL': '100',
        },
    ):
        # Reload module to pick up env vars
        import importlib

        import cortex_function

        importlib.reload(cortex_function)

        # Mock HTTP requests
        request_count = 0
        total_bytes_sent = 0

        def mock_post(url, data=None, headers=None):
            nonlocal request_count, total_bytes_sent
            request_count += 1
            total_bytes_sent += len(data) if data else 0
            response = Mock()
            response.status_code = 200
            return response

        # Start memory tracking
        if use_profiler:
            tracemalloc.start()

        # Force garbage collection before benchmark
        gc.collect()

        # Get baseline memory
        import psutil

        process = psutil.Process()
        baseline_memory = process.memory_info().rss

        print(f'\nBaseline memory: {format_bytes(baseline_memory)}')
        print('\n' + '-' * 80)
        print('Running benchmark...')
        print('-' * 80)

        # Create mock blob
        mock_blob = MockInputStream(file_content, 'large_PT1H.json')

        # Track peak memory during execution
        peak_memory = baseline_memory

        with patch('cortex_function.requests.post', side_effect=mock_post):
            # Run the function
            try:
                cortex_function.main(mock_blob)

                # Get memory after processing
                current_memory = process.memory_info().rss
                peak_memory = max(peak_memory, current_memory)

            except Exception as e:
                print(f'\nERROR during benchmark: {e}')
                import traceback

                traceback.print_exc()
                return None

        # Get final memory stats
        final_memory = process.memory_info().rss
        memory_used = peak_memory - baseline_memory

        # Get tracemalloc stats if enabled
        tracemalloc_peak = None
        if use_profiler:
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc_peak = peak
            tracemalloc.stop()

        # Results
        results = {
            'file_size_bytes': file_size,
            'num_records': num_records,
            'total_tuples': total_tuples,
            'baseline_memory_bytes': baseline_memory,
            'peak_memory_bytes': peak_memory,
            'final_memory_bytes': final_memory,
            'memory_used_bytes': memory_used,
            'tracemalloc_peak_bytes': tracemalloc_peak,
            'http_requests_sent': request_count,
            'total_bytes_sent': total_bytes_sent,
        }

        return results


def print_results(results):
    """Print benchmark results in a formatted way"""
    if not results:
        print('\nBenchmark failed - no results to display')
        return

    print('\n' + '=' * 80)
    print('BENCHMARK RESULTS')
    print('=' * 80)

    print('\n📊 Input Data:')
    print(f'  File size:           {format_bytes(results["file_size_bytes"])}')
    print(f'  Records:             {results["num_records"]:,}')
    print(f'  Flow tuples:         {results["total_tuples"]:,}')

    print('\n💾 Memory Usage:')
    print(f'  Baseline memory:     {format_bytes(results["baseline_memory_bytes"])}')
    print(f'  Peak memory:         {format_bytes(results["peak_memory_bytes"])}')
    print(f'  Memory used:         {format_bytes(results["memory_used_bytes"])}')

    if results['tracemalloc_peak_bytes']:
        print(f'  Tracemalloc peak:    {format_bytes(results["tracemalloc_peak_bytes"])}')

    # Calculate memory overhead
    file_size = results['file_size_bytes']
    memory_used = results['memory_used_bytes']
    overhead_ratio = memory_used / file_size if file_size > 0 else 0

    print('\n📈 Memory Overhead:')
    print(f'  File size:           {format_bytes(file_size)}')
    print(f'  Memory used:         {format_bytes(memory_used)}')
    print(f'  Overhead ratio:      {overhead_ratio:.2f}x')
    print(f'  Overhead:            {format_bytes(memory_used - file_size)}')

    print('\n📤 HTTP Transmission:')
    print(f'  Requests sent:       {results["http_requests_sent"]}')
    print(f'  Total bytes sent:    {format_bytes(results["total_bytes_sent"])}')

    # Estimate memory for different file sizes
    print('\n⚠️  Estimated Memory for Different File Sizes:')
    for size_mb in [100, 200, 500, 1000]:
        estimated_memory = size_mb * 1024 * 1024 * overhead_ratio
        print(f'  {size_mb} MB file → ~{format_bytes(estimated_memory)} memory')

    print('\n' + '=' * 80)

    # Warning if memory usage is high
    if overhead_ratio > 3:
        print('\n⚠️  WARNING: Memory overhead is very high (>3x file size)!')
        print('   This indicates the current implementation loads multiple copies')
        print('   of the data into memory during processing.')
        print('   Streaming/chunked processing is recommended.')

    print()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Benchmark memory usage of VNET flow logs function')
    parser.add_argument(
        '--file',
        default='vnet-flow-logs/tests/large_PT1H.json',
        help='Path to test JSON file (default: vnet-flow-logs/tests/large_PT1H.json)',
    )
    parser.add_argument('--profile', action='store_true', help='Enable detailed memory profiling with tracemalloc')

    args = parser.parse_args()

    # Check if file exists
    if not os.path.exists(args.file):
        print(f'Error: Test file not found: {args.file}')
        print('\nGenerate it first by running:')
        print('  python vnet-flow-logs/tests/generate_large_test_file.py')
        sys.exit(1)

    # Check if psutil is available
    try:
        import psutil  # noqa: F401
    except ImportError:
        print('Error: psutil is required for memory benchmarking')
        print('Install it with: pip install psutil')
        sys.exit(1)

    # Run benchmark
    results = run_benchmark(args.file, args.profile)

    # Print results
    print_results(results)

    # Save results to JSON
    if results:
        output_file = 'vnet-flow-logs/tests/benchmark_results.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f'Results saved to: {output_file}\n')


if __name__ == '__main__':
    main()
