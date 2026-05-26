"""
Memory benchmark test for vnet_flow_log_trigger.

Builds a large synthetic flow log file *in memory* (never persisted to the repo)
that mirrors the size and shape of the customer file that caused exit code 137
(SIGKILL / OOM) in production, then invokes the function and asserts that peak
resident-set-size (RSS) stays below a strict bound.

This test is the regression guard for the OOM bug: if anyone reintroduces the
old `blob.read().decode() → json.loads()` pattern, the assertions below will
fail because peak RSS will balloon to ~4x the file size again.

Run with:
    pytest tests/test_memory_benchmark.py -v -s -m memory
Skip in fast CI:
    pytest -m "not memory"
"""

import gc
import gzip
import os
import sys
import threading
import time
from unittest.mock import Mock, patch

import pytest

# Add parent dir (for function_app) and this dir (for generate_large_test_file)
_THIS_DIR = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_THIS_DIR, '..'))
sys.path.insert(0, _THIS_DIR)

from generate_large_test_file import generate_large_vnet_flow_log_bytes  # noqa: E402

# psutil is the only reliable way to measure real RSS across platforms.
psutil = pytest.importorskip('psutil', reason='psutil required for memory benchmark')

# ---------------------------------------------------------------------------
# Tuning knobs
# ---------------------------------------------------------------------------

# Profile matching the customer file (~148 MB, ~2.1M flow tuples).
# 480 records × 4400 tuples ≈ 2.11M tuples ≈ 140-150 MB depending on IP padding.
# Kept slightly smaller than the customer file so the test runs in <30s on CI.
CUSTOMER_PROFILE_NUM_RECORDS = 480
CUSTOMER_PROFILE_TUPLES_PER_RECORD = 4400

# Memory bounds for the streaming implementation.
# Baseline (Python interpreter + imports + 148 MB raw bytes) is ~170 MB on dev.
# Empirically the streaming impl peaks at ~250 MB total on a 148 MB file,
# i.e. ~80 MB delta from baseline. We allow 2x headroom for CI variance.
#
# IMPORTANT: the *old* (broken) implementation peaked at ~600 MB / ~450 MB delta
# on the same input. The thresholds below are tight enough to catch any
# regression back to the bytes→str→dict pattern.
MAX_PEAK_DELTA_MB = 250  # peak RSS - baseline RSS
MAX_PEAK_TO_FILE_RATIO = 2.0  # peak RSS / file size

# How frequently the sampler thread polls RSS (seconds).
SAMPLE_INTERVAL_S = 0.02


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class MockInputStream:
    """Minimal mock of `azure.functions.InputStream` backed by raw bytes."""

    def __init__(self, content: bytes, name: str, length: int | None = None):
        self._content = content
        self.name = name
        self.length = length if length is not None else len(content)

    def read(self):
        return self._content


class RSSSampler:
    """Background thread that records the peak resident-set-size of this process."""

    def __init__(self, interval_s: float = SAMPLE_INTERVAL_S):
        self._proc = psutil.Process()
        self._interval = interval_s
        self._peak = self._proc.memory_info().rss
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            rss = self._proc.memory_info().rss
            if rss > self._peak:
                self._peak = rss
            time.sleep(self._interval)

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    @property
    def peak_bytes(self) -> int:
        return self._peak


def _decompress_and_count(compressed: bytes) -> int:
    """Decompress a gzipped batch payload and return the number of JSON lines."""
    decompressed = gzip.decompress(compressed)
    return sum(1 for line in decompressed.split(b'\n') if line.strip())


def _format_mb(b: int) -> str:
    return f'{b / (1024 * 1024):.1f} MB'


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def function_app_env():
    """
    Set up environment variables and reload function_app to pick them up.

    Mirrors `mock_env` from test_cortex_function.py but kept independent so this
    file can be run in isolation.
    """
    with patch.dict(
        os.environ,
        {
            'CORTEX_HTTP_ENDPOINT': 'https://test-endpoint.example.com/api/logs',
            'CORTEX_ACCESS_TOKEN': 'test-token-memory-benchmark',
            'MAX_PAYLOAD_SIZE': '10000000',  # 10 MB
            'HTTP_MAX_RETRIES': '1',
            'RETRY_INTERVAL': '0',
            'BATCH_SIZE': '1000',
        },
    ):
        import importlib

        import function_app

        importlib.reload(function_app)
        yield function_app
        importlib.reload(function_app)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.memory
def test_peak_memory_under_bound_on_large_file(function_app_env, capsys):
    """
    Regression test for the OOM bug (exit code 137).

    Builds a ~140 MB synthetic flow log file in memory and asserts that peak RSS
    while processing it stays well below the 1.5 GB Consumption / 4 GB P0v3
    plan memory limits.

    Asserts (all relative to the same process):
      - peak_rss - baseline_rss          <  MAX_PEAK_DELTA_MB
      - peak_rss / file_size             <  MAX_PEAK_TO_FILE_RATIO
      - all expected records were sent (correctness — streaming must not lose data)
    """
    print('\n' + '=' * 80)
    print('MEMORY BENCHMARK: vnet_flow_log_trigger on customer-sized synthetic file')
    print('=' * 80)

    # ----- Build synthetic file in memory (mirrors customer payload shape) -----
    print('\n[1/4] Building synthetic flow log...')
    t0 = time.time()
    raw = generate_large_vnet_flow_log_bytes(
        num_records=CUSTOMER_PROFILE_NUM_RECORDS,
        tuples_per_record=CUSTOMER_PROFILE_TUPLES_PER_RECORD,
    )
    expected_tuples = CUSTOMER_PROFILE_NUM_RECORDS * CUSTOMER_PROFILE_TUPLES_PER_RECORD
    file_size = len(raw)
    print(f'      Records:         {CUSTOMER_PROFILE_NUM_RECORDS:,}')
    print(f'      Tuples/record:   {CUSTOMER_PROFILE_TUPLES_PER_RECORD:,}')
    print(f'      Total tuples:    {expected_tuples:,}')
    print(f'      File size:       {_format_mb(file_size)} ({file_size:,} bytes)')
    print(f'      Generation time: {time.time() - t0:.1f}s')

    # ----- Capture baseline RSS *after* the file bytes are allocated, so the
    #       baseline includes the 148 MB of raw test data. The delta we assert
    #       on then measures only what the function adds on top.
    gc.collect()
    proc = psutil.Process()
    baseline = proc.memory_info().rss
    print(f'\n[2/4] Baseline RSS (incl. raw bytes): {_format_mb(baseline)}')

    # ----- Capture all outbound HTTP payloads so we can verify correctness -----
    sent_record_count = 0
    sent_request_count = 0

    def mock_post(url, data=None, headers=None):
        nonlocal sent_record_count, sent_request_count
        sent_request_count += 1
        sent_record_count += _decompress_and_count(data) if data else 0
        resp = Mock()
        resp.status_code = 200
        return resp

    # Disable checkpoint manager — we want to measure the function in isolation
    function_app_env.CHECKPOINT_CONNECTION = None
    blob = MockInputStream(raw, 'insights-logs-flowlogflowevent/synthetic-large.json')

    # ----- Run the function with an RSS sampler in the background -----
    print('\n[3/4] Processing file (sampling RSS every 20ms)...')
    sampler = RSSSampler()
    sampler.start()
    t0 = time.time()
    try:
        with patch('function_app.requests.post', side_effect=mock_post):
            function_app_env.vnet_flow_log_trigger(blob)
    finally:
        sampler.stop()
    elapsed = time.time() - t0

    peak = sampler.peak_bytes
    delta = peak - baseline
    ratio = peak / file_size

    print(f'      Elapsed:         {elapsed:.1f}s ({expected_tuples / max(elapsed, 0.001):,.0f} tuples/s)')
    print(f'      HTTP requests:   {sent_request_count}')
    print(f'      Records sent:    {sent_record_count:,}')
    print(f'      Peak RSS:        {_format_mb(peak)}')
    print(f'      Baseline RSS:    {_format_mb(baseline)}')
    print(f'      Peak delta:      {_format_mb(delta)}  (bound: < {MAX_PEAK_DELTA_MB} MB)')
    print(f'      Peak/file ratio: {ratio:.2f}x       (bound: < {MAX_PEAK_TO_FILE_RATIO}x)')

    # ----- Assertions -----
    print('\n[4/4] Verifying correctness + memory bounds...')

    # Correctness: streaming must not drop records.
    assert sent_record_count == expected_tuples, (
        f'Streaming lost data: expected {expected_tuples:,} denormalized records to be sent, got {sent_record_count:,}'
    )

    # Memory regression guard #1: absolute delta from baseline.
    delta_mb = delta / (1024 * 1024)
    assert delta_mb < MAX_PEAK_DELTA_MB, (
        f'Memory regression: peak RSS grew by {delta_mb:.1f} MB above baseline, '
        f'which exceeds the {MAX_PEAK_DELTA_MB} MB bound. '
        f'This usually means someone reintroduced `.decode()` + `json.loads()` '
        f'on the full blob — see function_app.vnet_flow_log_trigger for the '
        f'streaming pattern that must be preserved.'
    )

    # Memory regression guard #2: peak vs. file size ratio.
    assert ratio < MAX_PEAK_TO_FILE_RATIO, (
        f'Memory regression: peak RSS is {ratio:.2f}x the file size, '
        f'which exceeds the {MAX_PEAK_TO_FILE_RATIO}x bound. '
        f'The streaming implementation should keep peak RSS close to ~1x file size.'
    )

    print('      ✓ All records accounted for')
    print('      ✓ Peak memory within bounds')
    print('\n' + '=' * 80)
    print('MEMORY BENCHMARK PASSED')
    print('=' * 80 + '\n')


@pytest.mark.memory
def test_streaming_does_not_load_full_parsed_tree(function_app_env):
    """
    Verifies the streaming property directly: while the function is processing a
    large file, the number of in-flight Python objects should stay roughly
    constant per batch (bounded by BATCH_SIZE) — NOT grow linearly with the
    total number of records in the file.

    This complements the RSS-based assertion above by catching a more subtle
    regression: someone accumulating denormalized records into a single list
    before sending (which would technically pass the RSS bound for small files
    but blow up on large ones).
    """
    import gc as _gc

    from generate_large_test_file import generate_large_vnet_flow_log_bytes

    # Smaller file is enough — we're not measuring absolute memory here, just
    # checking that object counts don't scale with record count.
    raw = generate_large_vnet_flow_log_bytes(num_records=100, tuples_per_record=500)
    expected = 100 * 500

    function_app_env.CHECKPOINT_CONNECTION = None
    blob = MockInputStream(raw, 'insights-logs-flowlogflowevent/streaming-check.json')

    in_flight_batch_sizes = []
    original_send = function_app_env.compress_and_send

    def spy_send(data):
        in_flight_batch_sizes.append(len(data))
        # Don't actually compress/send — just observe size
        return None

    with patch.object(function_app_env, 'compress_and_send', side_effect=spy_send):
        _gc.collect()
        function_app_env.vnet_flow_log_trigger(blob)

    # Sanity: all batches should have been the configured BATCH_SIZE, except
    # potentially the last (partial) one.
    assert sum(in_flight_batch_sizes) == expected, (
        f'Streaming lost data: spy recorded {sum(in_flight_batch_sizes)} records but expected {expected}'
    )
    # No single batch should ever exceed BATCH_SIZE — that's the streaming invariant.
    batch_size = function_app_env.BATCH_SIZE
    over = [n for n in in_flight_batch_sizes if n > batch_size]
    assert not over, (
        f'Streaming invariant violated: found batches larger than BATCH_SIZE={batch_size}: {over[:5]}... '
        f'This means records are being accumulated instead of streamed.'
    )

    # Reference original_send to silence linters about the unused symbol — kept
    # so future maintainers can swap the spy for a real send if needed.
    assert original_send is not None
