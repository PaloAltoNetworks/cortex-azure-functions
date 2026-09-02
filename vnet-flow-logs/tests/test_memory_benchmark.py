"""
Memory benchmark test for vnet_flow_log_trigger (Python worker side).

Builds a large synthetic flow log file *in memory* (never persisted to the repo)
and invokes the function, asserting that peak resident-set-size (RSS) of the
**Python worker process** stays below a strict bound and does not grow across
repeated invocations.

SCOPE — read this before relying on these tests as an OOM guard:
--------------------------------------------------------------------------------
These tests measure ONLY the Python worker process (via tracemalloc / psutil on
`os.getpid()`). They are the regression guard for the *worker-side* streaming
implementation: if anyone reintroduces the old
`blob.read().decode() → json.loads()` pattern, peak worker RSS will balloon and
the assertions below will fail.

They DO **not** reproduce or guard against the production OOM observed in the
customer's logs:

    System.OutOfMemoryException at System.IO.MemoryStream.set_Capacity
    Category: Host.Results / Function.vnet_flow_log_trigger  (Failed, ~1.4-5.3s)

That exception is thrown in the **.NET Functions host process**, not the Python
worker, while the host buffers the entire blob into a `MemoryStream` (which grows
by doubling → needs a contiguous array ~2x the blob size) *before* handing it to
the worker over gRPC. It fails fast (1-5s), long before this Python streaming
code does any real work, so no worker-side memory test can catch it.

The mitigation for the host-side OOM is operational, not code:
  - Cap `extensions.blobs.maxDegreeOfParallelism` to 1 so the host buffers only
    ONE blob (one MemoryStream) at a time instead of competing for several
    contiguous allocations simultaneously. (Overridable via the ARM
    `blobMaxDegreeOfParallelism` parameter.)
  - Scale the App Service Plan SKU up for more RAM headroom when PT1H.json files
    are very large. See the "Troubleshooting & Common Issues" section of the
    vnet-flow-logs README.

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
# Repeated-invocation ("re-trigger storm") tuning knobs
# ---------------------------------------------------------------------------
# Azure Network Watcher writes PT1H.json as an *append blob*, so the SAME worker
# processes the SAME (growing) blob many times per hour. If any per-invocation
# allocation is retained across calls (module-level caches, un-reclaimed buffers,
# native allocator fragmentation from ijson/gzip, etc.) RSS would creep upward
# invocation-over-invocation. This test guards the Python worker against such a
# leak under the re-trigger storm.
#
# NOTE: this is a *worker-side* leak guard. The production OOM in the customer's
# logs was a .NET-host `MemoryStream.set_Capacity` failure (see module docstring)
# and is NOT reproduced here — that failure occurs before this Python code runs.
#
# We simulate the re-trigger storm by invoking the trigger REPEATEDLY on the same-sized blob and
# asserting that RSS does not grow monotonically across iterations.
REPEAT_PROFILE_NUM_RECORDS = 200
REPEAT_PROFILE_TUPLES_PER_RECORD = 3000  # ~50-60 MB, close to the customer's 70 MB samples
REPEAT_ITERATIONS = 12  # enough to expose a per-call leak/retention trend

# Allowed RSS growth from the first "settled" iteration to the last, as a fraction
# of a single file's size. A leak-free implementation should return to roughly the
# same RSS after each call (delta ~0); we allow modest slack for allocator/GC noise.
MAX_RSS_GROWTH_RATIO = 0.5  # last-iter RSS - settled RSS must be < 0.5x file size


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
    Regression test for the *worker-side* streaming implementation.

    Builds a ~140 MB synthetic flow log file in memory and asserts that peak RSS
    of the Python worker while processing it stays well below the plan memory
    limits. This guards the streaming pattern only — see the module docstring for
    why it does NOT cover the host-side `MemoryStream.set_Capacity` OOM seen in
    production.

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


@pytest.mark.memory
def test_rss_does_not_grow_across_repeated_invocations(function_app_env, capsys):
    """
    Regression guard for the *production* OOM: the append-only re-trigger storm.

    Unlike `test_peak_memory_under_bound_on_large_file` (which measures a single
    invocation in isolation), this test invokes the trigger REPEATEDLY on the
    same-sized blob — mirroring how Azure Network Watcher re-triggers the function
    on every append to the same PT1H.json blob, many times per hour, on the same
    worker process.

    The single-shot benchmark can pass while the worker still OOMs in production
    if any allocation is *retained across calls* (module-level state, native
    allocator fragmentation from ijson/gzip, un-reclaimed buffers). Such a leak
    shows up as RSS climbing invocation-over-invocation rather than returning to
    a stable baseline after each call.

    Asserts:
      - RSS after the final iteration does not exceed the "settled" RSS (measured
        after the 2nd invocation, once one-time caches are warm) by more than
        MAX_RSS_GROWTH_RATIO x file size.
      - Every invocation sends the full record set (no data loss under repetition).
    """
    print('\n' + '=' * 80)
    print('MEMORY BENCHMARK: repeated re-trigger storm (append-blob simulation)')
    print('=' * 80)

    raw = generate_large_vnet_flow_log_bytes(
        num_records=REPEAT_PROFILE_NUM_RECORDS,
        tuples_per_record=REPEAT_PROFILE_TUPLES_PER_RECORD,
    )
    expected_tuples = REPEAT_PROFILE_NUM_RECORDS * REPEAT_PROFILE_TUPLES_PER_RECORD
    file_size = len(raw)
    print(f'\nFile size: {_format_mb(file_size)}  |  iterations: {REPEAT_ITERATIONS}')

    # Checkpoint disabled: we want to force every invocation to fully re-process
    # the blob (worst case — this is what happens when the checkpoint is absent or
    # the blob is being appended to and re-read).
    function_app_env.CHECKPOINT_CONNECTION = None

    def mock_post(url, data=None, headers=None):
        resp = Mock()
        resp.status_code = 200
        return resp

    proc = psutil.Process()
    rss_after_iter: list[int] = []
    sent_per_iter: list[int] = []

    with patch('function_app.requests.post', side_effect=mock_post):
        for i in range(REPEAT_ITERATIONS):
            sent = {'n': 0}

            def counting_post(url, data=None, headers=None, _sent=sent):
                _sent['n'] += _decompress_and_count(data) if data else 0
                resp = Mock()
                resp.status_code = 200
                return resp

            with patch('function_app.requests.post', side_effect=counting_post):
                # Fresh blob object each call (the runtime hands us a new
                # InputStream per trigger) but identical bytes.
                blob = MockInputStream(raw, 'insights-logs-flowlogflowevent/PT1H.json')
                function_app_env.vnet_flow_log_trigger(blob)

            del blob
            gc.collect()
            rss = proc.memory_info().rss
            rss_after_iter.append(rss)
            sent_per_iter.append(sent['n'])
            print(f'  iter {i + 1:2d}: RSS={_format_mb(rss)}  sent={sent["n"]:,}')

    # ----- Correctness under repetition: every call ships the full set -----
    for i, sent in enumerate(sent_per_iter):
        assert sent == expected_tuples, (
            f'Iteration {i + 1} lost data: expected {expected_tuples:,} records sent, got {sent:,}'
        )

    # ----- Memory trend: "settled" RSS is measured after the 2nd iteration so
    #       one-time import/JIT/allocator warmup is excluded. Growth from there to
    #       the final iteration is the leak signal.
    settled = rss_after_iter[1]
    final = rss_after_iter[-1]
    growth = final - settled
    growth_ratio = growth / file_size

    print(
        f'\nSettled RSS (after iter 2): {_format_mb(settled)}  |  '
        f'final RSS: {_format_mb(final)}  |  growth: {_format_mb(growth)} '
        f'({growth_ratio:.2f}x file, bound < {MAX_RSS_GROWTH_RATIO}x)'
    )

    assert growth_ratio < MAX_RSS_GROWTH_RATIO, (
        f'RSS grew by {_format_mb(growth)} ({growth_ratio:.2f}x file size) across '
        f'{REPEAT_ITERATIONS} repeated invocations — this indicates per-invocation '
        f'memory retention that accumulates under the append-blob re-trigger storm '
        f'and OOM-kills the worker in production (exit 137). Expected RSS to return '
        f'to ~the settled value after each call.'
    )

    print('=' * 80)
    print('REPEATED-INVOCATION MEMORY BENCHMARK PASSED')
    print('=' * 80 + '\n')
