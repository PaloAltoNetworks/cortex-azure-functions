"""
Generate a large PT1H.json file simulating VNET flow logs v2 format.
This creates a realistic test file to benchmark memory consumption.
"""

import json


def generate_flow_tuple(index, flow_state='C'):
    """Generate a single flow tuple string"""
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


def generate_large_vnet_flow_log(num_records=1000, tuples_per_record=1000):
    """
    Generate a large VNET flow log file.

    Args:
        num_records: Number of top-level records (default: 1000)
        tuples_per_record: Number of flow tuples per record (default: 1000)

    Returns:
        Dictionary representing the flow log structure
    """
    records = []

    for record_idx in range(num_records):
        # Create flow tuples for this record
        flow_tuples = []
        for tuple_idx in range(tuples_per_record):
            global_idx = record_idx * tuples_per_record + tuple_idx
            # 90% continuing flows, 10% blocked
            flow_state = 'B' if global_idx % 10 == 0 else 'C'
            flow_tuples.append(generate_flow_tuple(global_idx, flow_state))

        # Create the record structure
        record = {
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
        records.append(record)

    return {'records': records}


def main():
    """Generate and save the large test file"""
    # Configuration
    num_records = 100  # 100 records
    tuples_per_record = 10000  # 10,000 tuples per record
    # Total: 100 * 10,000 = 1,000,000 flow tuples (denormalized records)

    output_file = 'vnet-flow-logs/tests/large_PT1H.json'

    print('Generating large VNET flow log file...')
    print(f'  Records: {num_records}')
    print(f'  Tuples per record: {tuples_per_record}')
    print(f'  Total flow tuples: {num_records * tuples_per_record:,}')

    data = generate_large_vnet_flow_log(num_records, tuples_per_record)

    print(f'\nWriting to {output_file}...')
    with open(output_file, 'w') as f:
        json.dump(data, f)

    # Get file size
    import os

    file_size = os.path.getsize(output_file)
    print('File created successfully!')
    print(f'  File size: {file_size:,} bytes ({file_size / (1024 * 1024):.2f} MB)')
    print('\nThis file simulates a realistic PT1H.json (1-hour) flow log file.')


if __name__ == '__main__':
    main()
