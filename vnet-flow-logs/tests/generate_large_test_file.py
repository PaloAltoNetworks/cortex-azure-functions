"""
Generate large PT1H.json files simulating Azure VNET flow logs (v2 format).

The functions in this module are *streaming* / *generator-based* so that
callers can:

  1. Materialize a large file in memory (`generate_large_vnet_flow_log_bytes`)
     without persisting it to the repo. Used by the memory benchmark test.

  2. Build a Python dict (`generate_large_vnet_flow_log`) for small tests.

  3. Persist a file on disk for ad-hoc profiling (`main`, when run as a script).

Determinism: the synthetic data is fully deterministic given the input
parameters — no randomness, no time-based fields. This makes test assertions
stable across runs.
"""

import json
from io import BytesIO


def generate_flow_tuple(index, flow_state='C'):
    """Generate a single flow tuple string in the Azure VNET flow log v2 format."""
    timestamp = 1705315200 + index
    src_ip = f'10.{(index // 65536) % 256}.{(index // 256) % 256}.{index % 256}'
    dst_ip = f'20.{(index // 65536) % 256}.{(index // 256) % 256}.{index % 256}'
    src_port = 50000 + (index % 15000)
    dst_port = 443 if index % 3 == 0 else (80 if index % 3 == 1 else 22)
    protocol = 'T' if index % 2 == 0 else 'U'
    direction = 'O' if index % 2 == 0 else 'I'
    action = 'A' if index % 10 != 0 else 'D'

    if flow_state == 'B':
        # Blocked flows don't have packet/byte counts
        return f'{timestamp},{src_ip},{dst_ip},{src_port},{dst_port},{protocol},{direction},{action},{flow_state},,,,,'
    else:
        # Continuing flows have packet/byte counts
        packets_stod = (index % 1000) + 10
        bytes_stod = packets_stod * 1500
        packets_dtos = (index % 500) + 5
        bytes_dtos = packets_dtos * 1500
        return f'{timestamp},{src_ip},{dst_ip},{src_port},{dst_port},{protocol},{direction},{action},{flow_state},{packets_stod},{bytes_stod},{packets_dtos},{bytes_dtos}'


def _build_record(record_idx, tuples_per_record):
    """Build one top-level `records[]` entry."""
    flow_tuples = []
    for tuple_idx in range(tuples_per_record):
        global_idx = record_idx * tuples_per_record + tuple_idx
        # 90% continuing flows, 10% blocked — matches the customer file distribution
        flow_state = 'B' if global_idx % 10 == 0 else 'C'
        flow_tuples.append(generate_flow_tuple(global_idx, flow_state))

    return {
        'time': f'2024-01-15T{(10 + record_idx // 60) % 24:02d}:{record_idx % 60:02d}:00.0000000Z',
        'category': 'FlowLogFlowEvent',
        'operationName': 'FlowLogFlowEvent',
        'flowLogResourceID': f'/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/virtualNetworks/vnet-prod-{record_idx % 100}',
        'macAddress': f'00-0D-3A-{record_idx % 256:02X}-{(record_idx // 256) % 256:02X}-{(record_idx // 65536) % 256:02X}',
        'flowLogVersion': 2,
        'flowRecords': {
            'flows': [{'flowGroups': [{'rule': f'SecurityRule_{record_idx % 50}', 'flowTuples': flow_tuples}]}]
        },
    }


def generate_large_vnet_flow_log(num_records=1000, tuples_per_record=1000):
    """
    Generate a large VNET flow log file as a Python dict.

    WARNING: this materializes the entire dict in memory. For very large
    files (> ~50k tuples) prefer `generate_large_vnet_flow_log_bytes` which
    streams the JSON directly to a buffer without holding the dict tree.

    Args:
        num_records: Number of top-level records (default: 1000)
        tuples_per_record: Number of flow tuples per record (default: 1000)

    Returns:
        Dictionary representing the flow log structure
    """
    records = [_build_record(i, tuples_per_record) for i in range(num_records)]
    return {'records': records}


def iter_record_json_chunks(num_records, tuples_per_record):
    """
    Yield JSON byte chunks that, when concatenated, form a valid VNET flow log
    document with `num_records` top-level records.

    Streaming generator — never holds more than one record's worth of data in
    memory at a time. Used by `generate_large_vnet_flow_log_bytes` to build
    very large synthetic files without 4x memory blow-up.
    """
    yield b'{"records":['
    for i in range(num_records):
        record = _build_record(i, tuples_per_record)
        encoded = json.dumps(record, separators=(',', ':')).encode('utf-8')
        if i > 0:
            yield b','
        yield encoded
        # Drop the record reference immediately so the next iteration starts clean
        del record
    yield b']}'


def generate_large_vnet_flow_log_bytes(num_records, tuples_per_record):
    """
    Generate a large VNET flow log as raw UTF-8 bytes, suitable for feeding to
    a mocked `func.InputStream.read()`.

    Memory-efficient: the document is built one record at a time and appended
    to a single `BytesIO` buffer; the only memory cost is the final byte
    string itself (no extra full-document copies).

    Returns:
        bytes — the complete JSON document.
    """
    buf = BytesIO()
    for chunk in iter_record_json_chunks(num_records, tuples_per_record):
        buf.write(chunk)
    return buf.getvalue()


def main():
    """Generate and save a large test file on disk (for ad-hoc profiling)."""
    # Configuration: 100 records × 10,000 tuples = 1,000,000 denormalized records
    num_records = 100
    tuples_per_record = 10000

    output_file = 'vnet-flow-logs/tests/large_PT1H.json'

    print('Generating large VNET flow log file...')
    print(f'  Records: {num_records}')
    print(f'  Tuples per record: {tuples_per_record}')
    print(f'  Total flow tuples: {num_records * tuples_per_record:,}')

    print(f'\nWriting to {output_file}...')
    with open(output_file, 'wb') as f:
        for chunk in iter_record_json_chunks(num_records, tuples_per_record):
            f.write(chunk)

    import os

    file_size = os.path.getsize(output_file)
    print('File created successfully!')
    print(f'  File size: {file_size:,} bytes ({file_size / (1024 * 1024):.2f} MB)')
    print('\nThis file simulates a realistic PT1H.json (1-hour) flow log file.')


if __name__ == '__main__':
    main()
