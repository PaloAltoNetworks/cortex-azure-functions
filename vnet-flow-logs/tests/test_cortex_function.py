"""
E2E tests for vnet-flow-logs cortex_function.
Tests invoke main() with real vnet flow log blob content and verify all records arrive correctly.
"""

import gzip
import json
import os
import sys
from unittest.mock import Mock, patch

import pytest

# Add parent directory to path to import cortex_function
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from datetime import UTC

from function_app import vnet_flow_log_trigger as main

# Sample vnet flow log data (version 2 format)
SAMPLE_VNET_FLOW_LOG_V2 = {
    'records': [
        {
            'time': '2024-01-15T10:00:00.0000000Z',
            'category': 'FlowLogFlowEvent',
            'operationName': 'FlowLogFlowEvent',
            'flowLogResourceID': '/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1',
            'macAddress': '00-0D-3A-1B-2C-3D',
            'flowLogVersion': 2,
            'flowRecords': {
                'flows': [
                    {
                        'flowGroups': [
                            {
                                'rule': 'DefaultRule_AllowInternetOutBound',
                                'flowTuples': [
                                    '1705315200,10.0.0.4,20.30.40.50,54321,443,T,O,A,C,10,1500,5,750',
                                    '1705315201,10.0.0.5,20.30.40.51,54322,443,T,O,A,C,20,3000,10,1500',
                                ],
                            },
                            {
                                'rule': 'UserRule_DenyAll',
                                'flowTuples': ['1705315202,10.0.0.6,20.30.40.52,54323,80,T,I,D,B,,,,,'],
                            },
                        ]
                    }
                ]
            },
        },
        {
            'time': '2024-01-15T10:01:00.0000000Z',
            'category': 'FlowLogFlowEvent',
            'operationName': 'FlowLogFlowEvent',
            'flowLogResourceID': '/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet2',
            'macAddress': '00-0D-3A-4E-5F-6A',
            'flowLogVersion': 2,
            'flowRecords': {
                'flows': [
                    {
                        'flowGroups': [
                            {
                                'rule': 'CustomRule_AllowHTTPS',
                                'flowTuples': ['1705315260,10.0.1.10,20.30.40.60,12345,443,T,O,A,C,100,10000,50,5000'],
                            }
                        ]
                    }
                ]
            },
        },
    ]
}

# Sample vnet flow log data (version 1 format - no flow state)
SAMPLE_VNET_FLOW_LOG_V1 = {
    'records': [
        {
            'time': '2024-01-15T09:00:00.0000000Z',
            'category': 'FlowLogFlowEvent',
            'operationName': 'FlowLogFlowEvent',
            'flowLogResourceID': '/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-old',
            'macAddress': '00-0D-3A-7B-8C-9D',
            'flowLogVersion': 1,
            'flowRecords': {
                'flows': [
                    {
                        'flowGroups': [
                            {
                                'rule': 'DefaultRule',
                                'flowTuples': ['1705311600,10.0.2.20,20.30.40.70,9999,22,T,I,A'],
                            }
                        ]
                    }
                ]
            },
        }
    ]
}


class MockInputStream:
    """Mock azure.functions.InputStream for testing"""

    def __init__(self, content: str, name: str = 'test-blob.json', length: int = None):
        self.content = content
        self.name = name
        self.length = length if length is not None else len(content.encode('utf-8'))

    def read(self):
        return self.content.encode('utf-8')


def decompress_and_parse_payload(compressed_data):
    """Helper to decompress gzipped payload and parse JSON lines"""
    decompressed = gzip.decompress(compressed_data)
    lines = decompressed.decode('utf-8').strip().split('\n')
    return [json.loads(line) for line in lines if line]


@pytest.fixture(autouse=True)
def mock_env():
    """Set up environment variables for testing"""
    with patch.dict(
        os.environ,
        {
            'CORTEX_HTTP_ENDPOINT': 'https://test-endpoint.example.com/api/logs',
            'CORTEX_ACCESS_TOKEN': 'test-token-12345',
            'MAX_PAYLOAD_SIZE': '10000000',
            'HTTP_MAX_RETRIES': '3',
            'RETRY_INTERVAL': '100',
        },
    ):
        # Reload the module to pick up new env vars
        import importlib

        import function_app

        importlib.reload(function_app)
        yield
        # Reload again to restore original state
        importlib.reload(function_app)


@pytest.fixture
def captured_requests():
    """Fixture to capture HTTP requests made during test"""
    requests = []

    def mock_post(url, data=None, headers=None):
        response = Mock()
        response.status_code = 200
        requests.append({'url': url, 'data': data, 'headers': headers})
        return response

    with patch('function_app.requests.post', side_effect=mock_post):
        yield requests


class TestCortexFunctionE2E:
    """End-to-end tests for the cortex_function module"""

    def test_process_vnet_flow_log_v2_all_records_received(self, mock_env, captured_requests):
        """Test that all records from a v2 vnet flow log are correctly processed and sent"""
        # Arrange
        blob_content = json.dumps(SAMPLE_VNET_FLOW_LOG_V2)
        mock_blob = MockInputStream(blob_content, 'vnet-flow-v2.json')

        # Act
        main(mock_blob)

        # Assert - verify HTTP requests were made
        assert len(captured_requests) > 0, 'No HTTP requests were made'

        # Decompress and parse all received records
        all_received_records = []
        for req in captured_requests:
            assert req['headers']['Content-Type'] == 'application/json'
            assert req['headers']['Content-Encoding'] == 'gzip'
            assert req['headers']['Authorization'] == 'Bearer test-token-12345'

            records = decompress_and_parse_payload(req['data'])
            all_received_records.extend(records)

        # Expected: 4 denormalized records (2 + 1 from first record, 1 from second record)
        assert len(all_received_records) == 4, f'Expected 4 records, got {len(all_received_records)}'

        # Verify first record details
        record1 = all_received_records[0]
        assert record1['time'] == '2024-01-15T10:00:00.0000000Z'
        assert record1['version'] == 2.0
        assert record1['nsgRuleName'] == 'DefaultRule_AllowInternetOutBound'
        assert record1['sourceAddress'] == '10.0.0.4'
        assert record1['destinationAddress'] == '20.30.40.50'
        assert record1['sourcePort'] == '54321'
        assert record1['destinationPort'] == '443'
        assert record1['transportProtocol'] == 'T'
        assert record1['deviceDirection'] == 'O'
        assert record1['deviceAction'] == 'A'
        assert record1['flowState'] == 'C'
        assert record1['packetsStoD'] == '10'
        assert record1['bytesStoD'] == '1500'
        assert record1['packetsDtoS'] == '5'
        assert record1['bytesDtoS'] == '750'

        # Verify third record (blocked flow with flowState=B)
        record3 = all_received_records[2]
        assert record3['nsgRuleName'] == 'UserRule_DenyAll'
        assert record3['deviceAction'] == 'D'
        assert record3['flowState'] == 'B'
        # When flowState is "B", packet/byte counts should not be present
        assert 'packetsStoD' not in record3
        assert 'bytesStoD' not in record3

    def test_process_vnet_flow_log_v1_format(self, mock_env, captured_requests):
        """Test that v1 format (without flow state) is correctly processed"""
        # Arrange
        blob_content = json.dumps(SAMPLE_VNET_FLOW_LOG_V1)
        mock_blob = MockInputStream(blob_content, 'vnet-flow-v1.json')

        # Act
        main(mock_blob)

        # Assert
        assert len(captured_requests) > 0

        all_received_records = []
        for req in captured_requests:
            records = decompress_and_parse_payload(req['data'])
            all_received_records.extend(records)

        assert len(all_received_records) == 1

        record = all_received_records[0]
        assert record['version'] == 1.0
        assert record['sourceAddress'] == '10.0.2.20'
        assert record['destinationPort'] == '22'
        # v1 format should not have flowState or packet/byte counts
        assert 'flowState' not in record
        assert 'packetsStoD' not in record

    def test_empty_blob_no_requests(self, mock_env, captured_requests):
        """Test that empty blob content doesn't send any requests"""
        # Arrange
        mock_blob = MockInputStream('', 'empty.json', length=0)

        # Act
        main(mock_blob)

        # Assert
        assert len(captured_requests) == 0, 'No requests should be sent for empty blob'

    def test_whitespace_only_blob_no_requests(self, mock_env, captured_requests):
        """Test that whitespace-only blob doesn't send any requests"""
        # Arrange
        mock_blob = MockInputStream('   \n\t  ', 'whitespace.json')

        # Act
        main(mock_blob)

        # Assert
        assert len(captured_requests) == 0, 'No requests should be sent for whitespace-only blob'

    def test_partial_json_no_requests(self, mock_env, captured_requests):
        """Test that partial/invalid JSON is handled gracefully (no requests sent)"""
        # Arrange
        mock_blob = MockInputStream('{"records": [{"incomplete":', 'partial.json')

        # Act
        main(mock_blob)

        # Assert - partial JSON should be skipped, no requests sent
        assert len(captured_requests) == 0, 'No requests should be sent for invalid JSON'

    def test_empty_records_array_no_requests(self, mock_env, captured_requests):
        """Test that blob with empty records array doesn't send requests"""
        # Arrange
        blob_content = json.dumps({'records': []})
        mock_blob = MockInputStream(blob_content, 'empty-records.json')

        # Act
        main(mock_blob)

        # Assert
        assert len(captured_requests) == 0, 'No requests should be sent for empty records'

    def test_missing_endpoint_no_requests(self, captured_requests, mock_env):
        """Test that missing CORTEX_HTTP_ENDPOINT prevents processing"""
        # Arrange
        with patch.dict(os.environ, {'CORTEX_ACCESS_TOKEN': 'test-token'}, clear=True):
            import importlib

            import function_app

            importlib.reload(function_app)

            blob_content = json.dumps(SAMPLE_VNET_FLOW_LOG_V2)
            mock_blob = MockInputStream(blob_content, 'test.json')

            # Act
            function_app.vnet_flow_log_trigger(mock_blob)

            # Assert
            assert len(captured_requests) == 0, 'No requests should be sent without endpoint'

    def test_missing_token_no_requests(self, captured_requests, mock_env):
        """Test that missing CORTEX_ACCESS_TOKEN prevents processing"""
        # Arrange
        with patch.dict(os.environ, {'CORTEX_HTTP_ENDPOINT': 'https://test.example.com'}, clear=True):
            import importlib

            import function_app

            importlib.reload(function_app)

            blob_content = json.dumps(SAMPLE_VNET_FLOW_LOG_V2)
            mock_blob = MockInputStream(blob_content, 'test.json')

            # Act
            function_app.vnet_flow_log_trigger(mock_blob)

            # Assert
            assert len(captured_requests) == 0, 'No requests should be sent without token'

    def test_large_payload_batching(self, captured_requests):
        """Test that large payloads are split into multiple batches"""
        # Arrange - create a large dataset
        large_dataset = {
            'records': [
                {
                    'time': f'2024-01-15T10:{i:02d}:00.0000000Z',
                    'category': 'FlowLogFlowEvent',
                    'operationName': 'FlowLogFlowEvent',
                    'flowLogResourceID': f'/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet{i}',
                    'macAddress': f'00-0D-3A-{i:02X}-{i:02X}-{i:02X}',
                    'flowLogVersion': 2,
                    'flowRecords': {
                        'flows': [
                            {
                                'flowGroups': [
                                    {
                                        'rule': f'Rule{i}',
                                        'flowTuples': [
                                            f'170531{5200 + i},10.0.0.{i},20.30.40.{i},{50000 + i},443,T,O,A,C,{i * 10},{i * 1000},{i * 5},{i * 500}'
                                            for _ in range(10)  # 10 tuples per record
                                        ],
                                    }
                                ]
                            }
                        ]
                    },
                }
                for i in range(100)  # 100 records with 10 tuples each = 1000 total denormalized records
            ]
        }

        # Set a small max payload size to force batching
        with patch.dict(
            os.environ,
            {
                'CORTEX_HTTP_ENDPOINT': 'https://test-endpoint.example.com/api/logs',
                'CORTEX_ACCESS_TOKEN': 'test-token-12345',
                'MAX_PAYLOAD_SIZE': '5000',
                'HTTP_MAX_RETRIES': '3',
                'RETRY_INTERVAL': '100',
            },
        ):
            import importlib

            import function_app

            importlib.reload(function_app)

            blob_content = json.dumps(large_dataset)
            mock_blob = MockInputStream(blob_content, 'large.json')

            # Act
            function_app.vnet_flow_log_trigger(mock_blob)

        # Assert - should have multiple batches
        assert len(captured_requests) > 1, 'Large payload should be split into multiple batches'

        # Verify all records were sent
        all_received_records = []
        for req in captured_requests:
            records = decompress_and_parse_payload(req['data'])
            all_received_records.extend(records)

        assert len(all_received_records) == 1000, f'Expected 1000 records, got {len(all_received_records)}'


class TestLargeFileProcessing:
    """Test processing of large files to verify memory optimization and correctness"""

    def generate_deterministic_large_file(self, num_records=25, tuples_per_record=8000):
        """
        Generate a deterministic large test file (always same size/content).
        Creates a file of approximately 15 MB.

        Args:
            num_records: Number of top-level records (default: 25)
            tuples_per_record: Flow tuples per record (default: 8000)

        Returns:
            Tuple of (json_content_string, expected_total_tuples)
        """
        records = []
        total_tuples = 0

        for record_idx in range(num_records):
            flow_tuples = []
            for tuple_idx in range(tuples_per_record):
                global_idx = record_idx * tuples_per_record + tuple_idx
                total_tuples += 1

                # Deterministic values based on index
                timestamp = 1705315200 + global_idx
                src_ip = f'10.{(global_idx // 65536) % 256}.{(global_idx // 256) % 256}.{global_idx % 256}'
                dst_ip = f'20.{(global_idx // 65536) % 256}.{(global_idx // 256) % 256}.{global_idx % 256}'
                src_port = 50000 + (global_idx % 15000)
                dst_port = 443 if global_idx % 3 == 0 else (80 if global_idx % 3 == 1 else 22)
                protocol = 'T' if global_idx % 2 == 0 else 'U'
                direction = 'O' if global_idx % 2 == 0 else 'I'
                action = 'A' if global_idx % 10 != 0 else 'D'

                # 90% continuing flows, 10% blocked
                if global_idx % 10 == 0:
                    # Blocked flow (flowState=B)
                    flow_tuple = (
                        f'{timestamp},{src_ip},{dst_ip},{src_port},{dst_port},{protocol},{direction},{action},B,,,,,'
                    )
                else:
                    # Continuing flow (flowState=C)
                    packets_stod = (global_idx % 1000) + 10
                    bytes_stod = packets_stod * 1500
                    packets_dtos = (global_idx % 500) + 5
                    bytes_dtos = packets_dtos * 1500
                    flow_tuple = f'{timestamp},{src_ip},{dst_ip},{src_port},{dst_port},{protocol},{direction},{action},C,{packets_stod},{bytes_stod},{packets_dtos},{bytes_dtos}'

                flow_tuples.append(flow_tuple)

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

        data = {'records': records}
        return json.dumps(data), total_tuples

    def test_large_file_processing_with_batching(self, mock_env, captured_requests, capsys):
        """
        Test processing of a large file (30+ MB) to verify:
        1. All records are processed correctly
        2. Batching works as expected
        3. Memory optimization is effective
        4. HTTP requests are made appropriately
        """
        import time
        import tracemalloc

        print('\n' + '=' * 80)
        print('LARGE FILE PROCESSING TEST')
        print('=' * 80)

        # Generate deterministic large file (30+ MB)
        start_gen = time.time()
        print('\n📝 Generating test file...')
        json_content, expected_total_tuples = self.generate_deterministic_large_file(
            num_records=25, tuples_per_record=8000
        )
        gen_time = time.time() - start_gen

        file_size_bytes = len(json_content.encode('utf-8'))
        file_size_mb = file_size_bytes / (1024 * 1024)

        print('   Records: 25')
        print('   Tuples per record: 8,000')
        print(f'   Total flow tuples: {expected_total_tuples:,}')
        print(f'   File size: {file_size_mb:.2f} MB ({file_size_bytes:,} bytes)')
        print(f'   Generation time: {gen_time:.2f}s')

        # Set batch size for testing
        with patch.dict(
            os.environ,
            {
                'CORTEX_HTTP_ENDPOINT': 'https://test-endpoint.example.com/api/logs',
                'CORTEX_ACCESS_TOKEN': 'test-token-12345',
                'MAX_PAYLOAD_SIZE': '10000000',  # 10MB
                'HTTP_MAX_RETRIES': '3',
                'RETRY_INTERVAL': '100',
                'BATCH_SIZE': '1000',  # Process 1000 records at a time
            },
        ):
            import importlib

            import function_app

            importlib.reload(function_app)

            # Create mock blob
            mock_blob = MockInputStream(json_content, 'large_PT1H.json')

            # Start memory tracking (after test file generation)
            tracemalloc.start()

            # Process the file
            print('\n🔄 Processing file...')
            start_process = time.time()

            function_app.vnet_flow_log_trigger(mock_blob)

            process_time = time.time() - start_process

            # Get peak memory usage
            current_mem, peak_mem = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            peak_mem_mb = peak_mem / (1024 * 1024)
            memory_overhead_ratio = peak_mem / file_size_bytes

            print(f'   Processing time: {process_time:.2f}s')
            print(f'   Throughput: {expected_total_tuples / process_time:,.0f} records/sec')
            print(f'   Peak memory: {peak_mem_mb:.2f} MB')
            print(f'   Memory overhead: {memory_overhead_ratio:.2f}x file size')

        # Verify results
        print('\n✅ Verifying results...')

        # Check that HTTP requests were made
        assert len(captured_requests) > 0, 'No HTTP requests were made'
        print(f'   HTTP requests sent: {len(captured_requests)}')

        # Decompress and parse all received records
        all_received_records = []
        total_bytes_sent = 0

        for req in captured_requests:
            # Verify headers
            assert req['headers']['Content-Type'] == 'application/json'
            assert req['headers']['Content-Encoding'] == 'gzip'
            assert req['headers']['Authorization'] == 'Bearer test-token-12345'

            # Decompress and parse
            records = decompress_and_parse_payload(req['data'])
            all_received_records.extend(records)
            total_bytes_sent += len(req['data'])

        # Verify record count
        print(f'   Total records received: {len(all_received_records):,}')
        print(f'   Expected records: {expected_total_tuples:,}')
        assert len(all_received_records) == expected_total_tuples, (
            f'Expected {expected_total_tuples} records, got {len(all_received_records)}'
        )

        # Verify data integrity - check first, middle, and last records
        print('\n🔍 Verifying data integrity...')

        # First record (index 0)
        first_record = all_received_records[0]
        assert first_record['sourceAddress'] == '10.0.0.0'
        assert first_record['destinationAddress'] == '20.0.0.0'
        assert first_record['version'] == 2.0
        assert first_record['flowState'] == 'B'  # First record is blocked (index 0 % 10 == 0)
        print('   ✓ First record validated')

        # Middle record (index 50000)
        middle_record = all_received_records[50000]
        expected_src_ip = f'10.{(50000 // 65536) % 256}.{(50000 // 256) % 256}.{50000 % 256}'
        assert middle_record['sourceAddress'] == expected_src_ip
        assert middle_record['version'] == 2.0
        print('   ✓ Middle record validated (index 50000)')

        # Last record
        last_record = all_received_records[-1]
        last_idx = expected_total_tuples - 1
        expected_last_src_ip = f'10.{(last_idx // 65536) % 256}.{(last_idx // 256) % 256}.{last_idx % 256}'
        assert last_record['sourceAddress'] == expected_last_src_ip
        print(f'   ✓ Last record validated (index {last_idx})')

        # Verify blocked vs continuing flows ratio
        blocked_count = sum(1 for r in all_received_records if r.get('flowState') == 'B')
        continuing_count = sum(1 for r in all_received_records if r.get('flowState') == 'C')
        print('\n📊 Flow state distribution:')
        print(f'   Blocked flows (B): {blocked_count:,} ({blocked_count / len(all_received_records) * 100:.1f}%)')
        print(
            f'   Continuing flows (C): {continuing_count:,} ({continuing_count / len(all_received_records) * 100:.1f}%)'
        )

        # Should be approximately 10% blocked, 90% continuing
        assert abs(blocked_count / len(all_received_records) - 0.1) < 0.01, 'Blocked flow ratio should be ~10%'

        # Compression stats
        compression_ratio = file_size_bytes / total_bytes_sent if total_bytes_sent > 0 else 0
        print('\n📦 Compression stats:')
        print(f'   Original size: {file_size_mb:.2f} MB')
        print(f'   Compressed sent: {total_bytes_sent / (1024 * 1024):.2f} MB')
        print(f'   Compression ratio: {compression_ratio:.2f}x')

        # Batching efficiency
        expected_batches = (expected_total_tuples + 999) // 1000  # Ceiling division
        print('\n🔢 Batching efficiency:')
        print('   Batch size: 1,000 records')
        print(f'   Expected batches: ~{expected_batches}')
        print(f'   Actual HTTP requests: {len(captured_requests)}')
        print(f'   Records per request: {len(all_received_records) / len(captured_requests):.1f}')

        print('\n' + '=' * 80)
        print('✅ LARGE FILE PROCESSING TEST PASSED')
        print('=' * 80 + '\n')


class TestCheckpointManager:
    """Unit tests for the CheckpointManager class in checkpoint.py"""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_manager(self, mock_table_client, retention_days=2, cleanup_interval_hours=6):
        """Build a CheckpointManager with a fully mocked Azure Table client."""
        import sys
        import types

        # Stub out azure.data.tables so no real network calls are made
        azure_stub = types.ModuleType('azure')
        azure_data_stub = types.ModuleType('azure.data')
        azure_data_tables_stub = types.ModuleType('azure.data.tables')
        azure_core_stub = types.ModuleType('azure.core')
        azure_core_exc_stub = types.ModuleType('azure.core.exceptions')

        class _ResourceNotFoundError(Exception):
            pass

        class _ResourceExistsError(Exception):
            pass

        azure_core_exc_stub.ResourceNotFoundError = _ResourceNotFoundError
        azure_core_exc_stub.ResourceExistsError = _ResourceExistsError
        azure_data_tables_stub.UpdateMode = Mock(REPLACE='REPLACE')

        mock_service_client = Mock()
        mock_service_client.get_table_client.return_value = mock_table_client
        mock_service_client.create_table = Mock()

        azure_data_tables_stub.TableServiceClient = Mock(from_connection_string=Mock(return_value=mock_service_client))

        sys.modules.setdefault('azure', azure_stub)
        sys.modules['azure.data'] = azure_data_stub
        sys.modules['azure.data.tables'] = azure_data_tables_stub
        sys.modules['azure.core'] = azure_core_stub
        sys.modules['azure.core.exceptions'] = azure_core_exc_stub

        # Force reimport with stubs in place
        if 'checkpoint' in sys.modules:
            del sys.modules['checkpoint']

        from checkpoint import CheckpointManager

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_name = 'vnetflowcheckpoints'
        mgr._retention_days = retention_days
        mgr._cleanup_interval_hours = cleanup_interval_hours
        mgr._client = mock_service_client
        mgr._table_client = mock_table_client
        return mgr, _ResourceNotFoundError, _ResourceExistsError

    # ------------------------------------------------------------------
    # _make_row_key / key scheme (#4)
    # ------------------------------------------------------------------

    def test_row_key_is_stable(self):
        """Same blob name always produces the same RowKey (sha256 of full path)."""
        from checkpoint import CheckpointManager

        blob_name = 'insights-logs-flowlogflowevent/resourceId=sub/y=2024/m=01/d=15/h=10/m=00/PT1H.json'
        mgr = CheckpointManager.__new__(CheckpointManager)

        rk1 = mgr._make_row_key(blob_name)
        rk2 = mgr._make_row_key(blob_name)

        assert rk1 == rk2
        assert len(rk1) == 64  # sha256 hex digest length

    def test_row_key_different_blobs_produce_different_keys(self):
        """Different blob paths produce different RowKeys."""
        from checkpoint import CheckpointManager

        mgr = CheckpointManager.__new__(CheckpointManager)

        blob_a = 'container/y=2024/m=01/d=15/h=10/m=00/PT1H.json'
        blob_b = 'container/y=2024/m=01/d=15/h=11/m=00/PT1H.json'

        assert mgr._make_row_key(blob_a) != mgr._make_row_key(blob_b)

    def test_partition_key_is_constant(self):
        """All blobs share the same PartitionKey ('checkpoints') for a flat table."""
        from checkpoint import CheckpointManager

        assert CheckpointManager.PARTITION_KEY == 'checkpoints'

    def test_update_stores_blob_name_field(self):
        """update() stores the original blob_name in the row for human readability."""
        from datetime import datetime, timedelta

        from checkpoint import CheckpointManager

        mock_tc = Mock()
        mock_tc.upsert_entity = Mock()

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc
        mgr._retention_days = 2
        mgr._cleanup_interval_hours = 6
        # Simulate a recent cleanup so the interval guard suppresses cleanup in this test
        mgr._last_cleanup_at = datetime.now(UTC) - timedelta(minutes=1)

        blob_name = 'container/y=2024/m=01/d=15/h=10/m=00/PT1H.json'
        mgr.update(blob_name, 5, 1000)

        entity = mock_tc.upsert_entity.call_args.kwargs['entity']
        assert entity['blob_name'] == blob_name
        assert entity['PartitionKey'] == 'checkpoints'
        assert len(entity['RowKey']) == 64  # sha256 hex digest

    # ------------------------------------------------------------------
    # get()
    # ------------------------------------------------------------------

    def test_get_returns_zero_for_missing_key(self):
        """No row in table → get() returns 0."""
        from azure.core.exceptions import ResourceNotFoundError
        from checkpoint import CheckpointManager

        mock_tc = Mock()
        mock_tc.get_entity = Mock(side_effect=ResourceNotFoundError())

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc

        result = mgr.get('container/y=2024/m=01/d=15/h=10/m=00/PT1H.json')
        assert result == 0

    def test_get_returns_stored_count(self):
        """Row exists → get() returns processed_record_count."""
        from checkpoint import CheckpointManager

        mock_tc = Mock()
        mock_tc.get_entity = Mock(return_value={'processed_record_count': 42})

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc

        result = mgr.get('container/y=2024/m=01/d=15/h=10/m=00/PT1H.json')
        assert result == 42

    # ------------------------------------------------------------------
    # update()
    # ------------------------------------------------------------------

    def test_update_creates_row_with_correct_fields(self):
        """update() upserts a row with processed_record_count, blob_size_at_last_run, last_updated."""
        from datetime import datetime, timedelta

        from checkpoint import CheckpointManager

        mock_tc = Mock()
        mock_tc.upsert_entity = Mock()

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc
        mgr._retention_days = 2
        mgr._cleanup_interval_hours = 6
        # Simulate a recent cleanup so the interval guard suppresses cleanup in this test
        mgr._last_cleanup_at = datetime.now(UTC) - timedelta(minutes=1)

        mgr.update('container/y=2024/m=01/d=15/h=10/m=00/PT1H.json', 10, 5000)

        mock_tc.upsert_entity.assert_called_once()
        entity = mock_tc.upsert_entity.call_args.kwargs['entity']
        assert entity['processed_record_count'] == 10
        assert entity['blob_size_at_last_run'] == 5000
        assert 'last_updated' in entity
        assert entity['PartitionKey'] == 'checkpoints'
        assert len(entity['RowKey']) == 64  # sha256 hex digest of full blob path

    def test_update_overwrites_existing_row(self):
        """Calling update() twice overwrites the previous value."""
        from datetime import datetime, timedelta

        from checkpoint import CheckpointManager

        upserted = []
        mock_tc = Mock()
        mock_tc.upsert_entity = Mock(side_effect=lambda entity, mode: upserted.append(entity))

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc
        mgr._retention_days = 2
        mgr._cleanup_interval_hours = 6
        # Simulate a recent cleanup so the interval guard suppresses cleanup in this test
        mgr._last_cleanup_at = datetime.now(UTC) - timedelta(minutes=1)

        blob = 'container/y=2024/m=01/d=15/h=10/m=00/PT1H.json'
        mgr.update(blob, 5, 1000)
        mgr.update(blob, 10, 2000)

        assert len(upserted) == 2
        assert upserted[-1]['processed_record_count'] == 10

    # ------------------------------------------------------------------
    # maybe_cleanup_stale()
    # ------------------------------------------------------------------

    def test_cleanup_triggered_on_first_invocation_after_cold_start(self):
        """update() calls maybe_cleanup_stale() when _last_cleanup_at is None (cold start)."""
        from datetime import datetime
        from unittest.mock import patch

        from checkpoint import CheckpointManager

        mock_tc = Mock()
        mock_tc.upsert_entity = Mock()

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc
        mgr._retention_days = 2
        mgr._cleanup_interval_hours = 6
        mgr._last_cleanup_at = None  # simulates fresh cold start

        with patch.object(mgr, 'maybe_cleanup_stale') as mock_cleanup:
            fixed_dt = datetime(2024, 1, 15, 3, 30, 0, tzinfo=UTC)  # any hour — doesn't matter
            with patch('checkpoint.datetime') as mock_dt:
                mock_dt.now.return_value = fixed_dt
                mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
                mgr.update('container/PT1H.json', 5, 1000)

            mock_cleanup.assert_called_once_with(2)

    def test_cleanup_triggered_after_full_interval_elapsed(self):
        """update() calls maybe_cleanup_stale() when cleanup_interval_hours have passed since last run."""
        from datetime import datetime
        from unittest.mock import patch

        from checkpoint import CheckpointManager

        mock_tc = Mock()
        mock_tc.upsert_entity = Mock()

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc
        mgr._retention_days = 2
        mgr._cleanup_interval_hours = 6
        # Last cleanup ran exactly 6 hours ago — interval has elapsed
        mgr._last_cleanup_at = datetime(2024, 1, 15, 0, 0, 0, tzinfo=UTC)

        with patch.object(mgr, 'maybe_cleanup_stale') as mock_cleanup:
            fixed_dt = datetime(2024, 1, 15, 6, 0, 0, tzinfo=UTC)  # exactly 6h later
            with patch('checkpoint.datetime') as mock_dt:
                mock_dt.now.return_value = fixed_dt
                mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
                mgr.update('container/PT1H.json', 5, 1000)

            mock_cleanup.assert_called_once_with(2)

    def test_cleanup_not_triggered_within_interval(self):
        """update() does NOT call maybe_cleanup_stale() when the interval has not yet elapsed."""
        from datetime import datetime
        from unittest.mock import patch

        from checkpoint import CheckpointManager

        mock_tc = Mock()
        mock_tc.upsert_entity = Mock()

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc
        mgr._retention_days = 2
        mgr._cleanup_interval_hours = 6
        # Last cleanup ran only 1 minute ago — interval has NOT elapsed
        mgr._last_cleanup_at = datetime(2024, 1, 15, 3, 29, 0, tzinfo=UTC)

        with patch.object(mgr, 'maybe_cleanup_stale') as mock_cleanup:
            fixed_dt = datetime(2024, 1, 15, 3, 30, 0, tzinfo=UTC)  # only 1 min later
            with patch('checkpoint.datetime') as mock_dt:
                mock_dt.now.return_value = fixed_dt
                mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
                mgr.update('container/PT1H.json', 5, 1000)

            mock_cleanup.assert_not_called()

    def test_cleanup_not_triggered_repeatedly_within_same_hour(self):
        """1000 invocations within the same hour only trigger cleanup once."""
        from datetime import datetime, timedelta
        from unittest.mock import patch

        from checkpoint import CheckpointManager

        mock_tc = Mock()
        mock_tc.upsert_entity = Mock()

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc
        mgr._retention_days = 2
        mgr._cleanup_interval_hours = 6
        mgr._last_cleanup_at = None  # cold start

        cleanup_call_count = 0

        def fake_cleanup(retention_days):
            nonlocal cleanup_call_count
            cleanup_call_count += 1

        with patch.object(mgr, 'maybe_cleanup_stale', side_effect=fake_cleanup):
            base_dt = datetime(2024, 1, 15, 0, 0, 0, tzinfo=UTC)
            for i in range(1000):
                invocation_dt = base_dt + timedelta(seconds=i * 3)  # 3s apart, all within 1 hour
                with patch('checkpoint.datetime') as mock_dt:
                    mock_dt.now.return_value = invocation_dt
                    mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
                    mgr.update('container/PT1H.json', i, 1000)

        assert cleanup_call_count == 1, (
            f'Expected cleanup to run exactly once across 1000 invocations, but ran {cleanup_call_count} times'
        )

    def test_cleanup_uses_server_side_odata_filter(self):
        """maybe_cleanup_stale() passes an OData filter to list_entities() (#2)."""
        from datetime import datetime, timedelta
        from unittest.mock import patch

        from checkpoint import CheckpointManager

        now = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
        cutoff = now - timedelta(days=2)
        # Filter must use 'Z' suffix (not '+00:00') for correct OData lexicographic comparison
        expected_cutoff_iso = cutoff.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z'
        expected_filter = f"last_updated lt '{expected_cutoff_iso}'"

        mock_tc = Mock()
        mock_tc.list_entities = Mock(return_value=[])
        mock_tc.submit_transaction = Mock()

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc

        with patch('checkpoint.datetime') as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            mgr.maybe_cleanup_stale(retention_days=2)

        # Verify the OData filter was passed to list_entities
        mock_tc.list_entities.assert_called_once_with(filter=expected_filter)

    def test_last_updated_stored_with_z_suffix(self):
        """
        Regression test: last_updated must be stored with 'Z' suffix (not '+00:00').

        Azure Table Storage OData filters use lexicographic string comparison.
        The '+' character (ASCII 43) sorts before digits (ASCII 48-57), so a
        timestamp like '2026-03-19T00:47:22+00:00' compares as less-than any
        cutoff with the same format — causing fresh rows to appear stale and be
        deleted immediately.

        Using 'Z' suffix (ASCII 90, sorts after all digits) ensures correct
        chronological ordering via lexicographic comparison.
        """
        from datetime import datetime, timedelta

        from checkpoint import CheckpointManager

        mock_tc = Mock()
        mock_tc.upsert_entity = Mock()

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc
        mgr._retention_days = 30
        mgr._cleanup_interval_hours = 6
        # Simulate a recent cleanup so the interval guard suppresses cleanup in this test
        mgr._last_cleanup_at = datetime.now(UTC) - timedelta(minutes=1)

        mgr.update('container/y=2024/m=01/d=15/h=10/m=00/PT1H.json', 5, 1000)

        entity = mock_tc.upsert_entity.call_args.kwargs['entity']
        last_updated = entity['last_updated']

        # Must end with 'Z', not '+00:00'
        assert last_updated.endswith('Z'), (
            f"last_updated must use 'Z' suffix for correct OData lexicographic comparison, got: {last_updated!r}"
        )
        assert '+00:00' not in last_updated, (
            f"last_updated must not contain '+00:00' — it causes OData string comparison "
            f'to incorrectly treat fresh rows as stale. Got: {last_updated!r}'
        )

    def test_odata_cutoff_uses_z_suffix(self):
        """
        Regression test: OData filter cutoff must use 'Z' suffix (not '+00:00').

        Ensures the cutoff string in maybe_cleanup_stale() uses the same 'Z' format
        as last_updated, so lexicographic comparison correctly identifies stale rows.
        """
        from datetime import datetime
        from unittest.mock import patch

        from checkpoint import CheckpointManager

        now = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)

        mock_tc = Mock()
        mock_tc.list_entities = Mock(return_value=[])

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc

        with patch('checkpoint.datetime') as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            mgr.maybe_cleanup_stale(retention_days=30)

        call_kwargs = mock_tc.list_entities.call_args.kwargs
        odata_filter = call_kwargs['filter']

        # Extract the cutoff timestamp from the filter string
        # Format: "last_updated lt '2024-01-15T12:00:00.000000Z'"
        cutoff_str = odata_filter.split("'")[1]

        assert cutoff_str.endswith('Z'), (
            f"OData cutoff must use 'Z' suffix for correct lexicographic comparison, got: {cutoff_str!r}"
        )
        assert '+00:00' not in cutoff_str, f"OData cutoff must not contain '+00:00'. Got: {cutoff_str!r}"

    def test_fresh_row_not_deleted_within_retention_window(self):
        """
        Regression test: a row written moments ago must NOT be deleted by cleanup,
        even when cleanup runs immediately after (e.g. at hour 0, 6, 12, 18).

        This was the production bug: '+00:00' suffix caused fresh rows to compare
        as lexicographically less-than the cutoff, triggering immediate deletion.
        """
        from datetime import datetime, timedelta
        from unittest.mock import patch

        from checkpoint import CheckpointManager

        now = datetime(2024, 1, 15, 0, 0, 0, tzinfo=UTC)  # midnight — cleanup hour
        fresh_ts = now.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z'  # just written

        # Simulate: server returns the fresh row (as if OData filter was broken)
        # With the fix, the server-side filter should exclude it — so list_entities returns []
        mock_tc = Mock()
        mock_tc.list_entities = Mock(return_value=[])  # correct: fresh row excluded server-side
        mock_tc.submit_transaction = Mock()

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc

        with patch('checkpoint.datetime') as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            mgr.maybe_cleanup_stale(retention_days=30)

        # The OData filter cutoff must be 30 days ago, not now
        call_kwargs = mock_tc.list_entities.call_args.kwargs
        odata_filter = call_kwargs['filter']
        cutoff_str = odata_filter.split("'")[1]
        expected_cutoff = (now - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z'

        assert cutoff_str == expected_cutoff, f'Cutoff should be 30 days ago ({expected_cutoff!r}), got {cutoff_str!r}'
        # Fresh row timestamp must sort AFTER the cutoff (i.e. not be deleted)
        assert fresh_ts > cutoff_str, (
            f'Fresh row timestamp {fresh_ts!r} must be lexicographically greater than '
            f'cutoff {cutoff_str!r} — otherwise it would be incorrectly deleted'
        )
        # No deletions should occur
        mock_tc.submit_transaction.assert_not_called()

    def test_cleanup_deletes_stale_rows(self):
        """maybe_cleanup_stale() batch-deletes rows returned by the server-side filter."""
        from datetime import datetime, timedelta
        from unittest.mock import patch

        from checkpoint import CheckpointManager

        now = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
        stale_ts = (now - timedelta(days=3)).isoformat()

        # Server-side filter already excludes fresh rows — only stale rows returned
        stale_entity = {'PartitionKey': 'checkpoints', 'RowKey': 'abc123', 'last_updated': stale_ts}

        mock_tc = Mock()
        mock_tc.list_entities = Mock(return_value=[stale_entity])
        mock_tc.submit_transaction = Mock()

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc

        with patch('checkpoint.datetime') as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            mgr.maybe_cleanup_stale(retention_days=2)

        mock_tc.submit_transaction.assert_called_once()
        ops = mock_tc.submit_transaction.call_args[0][0]
        assert len(ops) == 1
        assert ops[0][1]['last_updated'] == stale_ts

    def test_cleanup_preserves_fresh_rows(self):
        """
        maybe_cleanup_stale() does not delete rows within the retention window.
        Since filtering is now server-side via OData, the mock simulates the server
        correctly excluding fresh rows — list_entities returns an empty list.
        """
        from datetime import datetime
        from unittest.mock import patch

        from checkpoint import CheckpointManager

        now = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)

        mock_tc = Mock()
        # Server-side OData filter excludes fresh rows — nothing returned
        mock_tc.list_entities = Mock(return_value=[])
        mock_tc.submit_transaction = Mock()

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc

        with patch('checkpoint.datetime') as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            mgr.maybe_cleanup_stale(retention_days=2)

        mock_tc.submit_transaction.assert_not_called()

    def test_cleanup_swallows_404_on_already_deleted_row(self):
        """maybe_cleanup_stale() does not raise when a batch delete returns 404."""
        from datetime import datetime, timedelta
        from unittest.mock import patch

        from azure.core.exceptions import ResourceNotFoundError
        from checkpoint import CheckpointManager

        now = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
        stale_ts = (now - timedelta(days=5)).isoformat()
        stale_entity = {'PartitionKey': 'pk1', 'RowKey': 'PT1H.json', 'last_updated': stale_ts}

        mock_tc = Mock()
        mock_tc.list_entities = Mock(return_value=[stale_entity])
        mock_tc.submit_transaction = Mock(side_effect=ResourceNotFoundError())

        mgr = CheckpointManager.__new__(CheckpointManager)
        mgr._table_client = mock_tc

        with patch('checkpoint.datetime') as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            # Should not raise
            mgr.maybe_cleanup_stale(retention_days=2)


class TestCheckpointBehavior:
    """Integration tests for checkpoint logic wired into main()."""

    BLOB_NAME = 'insights-logs-flowlogflowevent/resourceId=sub/y=2024/m=01/d=15/h=10/m=00/PT1H.json'

    def _make_blob(self, data: dict, name: str = None) -> MockInputStream:
        content = json.dumps(data)
        return MockInputStream(content, name or self.BLOB_NAME)

    # ------------------------------------------------------------------
    # Fixtures
    # ------------------------------------------------------------------

    @pytest.fixture
    def mock_checkpoint_mgr(self):
        """Return a Mock CheckpointManager and patch it into cortex_function."""
        mgr = Mock()
        mgr.get = Mock(return_value=0)
        mgr.update = Mock()
        with patch('function_app._build_checkpoint_manager', return_value=mgr):
            yield mgr

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_no_checkpoint_processes_all_records(self, mock_env, captured_requests, mock_checkpoint_mgr):
        """No checkpoint (get returns 0) → all records processed and checkpoint written."""
        mock_checkpoint_mgr.get.return_value = 0
        blob = self._make_blob(SAMPLE_VNET_FLOW_LOG_V2)

        main(blob)

        assert len(captured_requests) > 0
        all_records = []
        for req in captured_requests:
            all_records.extend(decompress_and_parse_payload(req['data']))
        assert len(all_records) == 4  # 2+1+1 tuples from SAMPLE_VNET_FLOW_LOG_V2

        mock_checkpoint_mgr.update.assert_called_once_with(self.BLOB_NAME, 2, blob.length)

    def test_checkpoint_skips_already_processed_records(self, mock_env, captured_requests, mock_checkpoint_mgr):
        """Checkpoint at 1 → only records[1:] are processed."""
        mock_checkpoint_mgr.get.return_value = 1  # first record already done

        blob = self._make_blob(SAMPLE_VNET_FLOW_LOG_V2)
        main(blob)

        assert len(captured_requests) > 0
        all_records = []
        for req in captured_requests:
            all_records.extend(decompress_and_parse_payload(req['data']))

        # Only the second top-level record (1 tuple) should be processed
        assert len(all_records) == 1
        assert all_records[0]['resourceId'].endswith('vnet2')

    def test_checkpoint_updated_after_success(self, mock_env, captured_requests, mock_checkpoint_mgr):
        """After successful processing, checkpoint count = old + new."""
        mock_checkpoint_mgr.get.return_value = 1  # 1 already processed

        blob = self._make_blob(SAMPLE_VNET_FLOW_LOG_V2)
        main(blob)

        # 2 total records in blob, 1 already processed → new = 1 → updated count = 2
        mock_checkpoint_mgr.update.assert_called_once_with(self.BLOB_NAME, 2, blob.length)

    def test_checkpoint_not_updated_on_send_failure(self, mock_env, mock_checkpoint_mgr):
        """HTTP send failure → checkpoint is NOT updated."""
        mock_checkpoint_mgr.get.return_value = 0

        blob = self._make_blob(SAMPLE_VNET_FLOW_LOG_V2)

        with patch('function_app.requests.post') as mock_post:
            mock_post.return_value = Mock(status_code=500)
            main(blob)

        mock_checkpoint_mgr.update.assert_not_called()

    def test_no_new_records_skips_processing(self, mock_env, captured_requests, mock_checkpoint_mgr):
        """Checkpoint == total records → no HTTP calls made."""
        mock_checkpoint_mgr.get.return_value = 2  # both records already processed

        blob = self._make_blob(SAMPLE_VNET_FLOW_LOG_V2)
        main(blob)

        assert len(captured_requests) == 0
        mock_checkpoint_mgr.update.assert_not_called()

    def test_checkpoint_reset_on_blob_shrink(self, mock_env, captured_requests, mock_checkpoint_mgr):
        """Checkpoint > total records (blob re-created) → reset to 0, process all."""
        mock_checkpoint_mgr.get.return_value = 999  # stale checkpoint from a previous larger blob

        blob = self._make_blob(SAMPLE_VNET_FLOW_LOG_V2)
        main(blob)

        # All 4 tuples should be processed (reset to 0)
        all_records = []
        for req in captured_requests:
            all_records.extend(decompress_and_parse_payload(req['data']))
        assert len(all_records) == 4

        # Checkpoint updated with full count (0 + 2 = 2 top-level records)
        mock_checkpoint_mgr.update.assert_called_once_with(self.BLOB_NAME, 2, blob.length)

    def test_checkpoint_storage_unavailable_on_get_falls_back_to_zero(
        self, mock_env, captured_requests, mock_checkpoint_mgr
    ):
        """Table Storage error on get() → falls back to 0, processes all records."""
        mock_checkpoint_mgr.get.side_effect = Exception('Table Storage unavailable')

        blob = self._make_blob(SAMPLE_VNET_FLOW_LOG_V2)
        main(blob)

        all_records = []
        for req in captured_requests:
            all_records.extend(decompress_and_parse_payload(req['data']))
        assert len(all_records) == 4

    def test_checkpoint_storage_unavailable_on_update_does_not_raise(
        self, mock_env, captured_requests, mock_checkpoint_mgr
    ):
        """Table Storage error on update() → logs error, does not raise, records still sent."""
        mock_checkpoint_mgr.get.return_value = 0
        mock_checkpoint_mgr.update.side_effect = Exception('Table Storage unavailable')

        blob = self._make_blob(SAMPLE_VNET_FLOW_LOG_V2)
        # Should not raise
        main(blob)

        # Records were still sent despite checkpoint update failure
        assert len(captured_requests) > 0

    def test_no_checkpoint_connection_env_var_processes_all_records(self, captured_requests):
        """CHECKPOINT_CONNECTION not set → processes all records (degraded mode)."""
        with patch.dict(
            os.environ,
            {
                'CORTEX_HTTP_ENDPOINT': 'https://test-endpoint.example.com/api/logs',
                'CORTEX_ACCESS_TOKEN': 'test-token-12345',
                'HTTP_MAX_RETRIES': '1',
                'RETRY_INTERVAL': '0',
            },
            clear=True,
        ):
            import importlib

            import function_app

            importlib.reload(function_app)

            blob = self._make_blob(SAMPLE_VNET_FLOW_LOG_V2)
            function_app.vnet_flow_log_trigger(blob)

        all_records = []
        for req in captured_requests:
            all_records.extend(decompress_and_parse_payload(req['data']))
        assert len(all_records) == 4

    def test_partial_batch_failure_does_not_update_checkpoint(self, mock_env, mock_checkpoint_mgr):
        """
        #1 — Partial-batch failure: if the second batch of a multi-batch run fails,
        the checkpoint is NOT updated even though the first batch was already sent.
        This makes the at-least-once boundary explicit: on the next trigger the
        first batch will be re-sent (bounded duplicate window = BATCH_SIZE records).
        """
        mock_checkpoint_mgr.get.return_value = 0

        # Build a dataset that produces exactly 3 flow tuples across 3 top-level records
        data = {
            'records': [
                {
                    'time': '2024-01-15T10:00:00.0000000Z',
                    'category': 'FlowLogFlowEvent',
                    'operationName': 'FlowLogFlowEvent',
                    'flowLogResourceID': '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1',
                    'macAddress': '00-0D-3A-1B-2C-3D',
                    'flowLogVersion': 1,
                    'flowRecords': {
                        'flows': [
                            {
                                'flowGroups': [
                                    {'rule': 'Rule1', 'flowTuples': ['1705315200,10.0.0.1,20.0.0.1,1000,443,T,O,A']}
                                ]
                            }
                        ]
                    },
                },
                {
                    'time': '2024-01-15T10:01:00.0000000Z',
                    'category': 'FlowLogFlowEvent',
                    'operationName': 'FlowLogFlowEvent',
                    'flowLogResourceID': '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet2',
                    'macAddress': '00-0D-3A-1B-2C-3E',
                    'flowLogVersion': 1,
                    'flowRecords': {
                        'flows': [
                            {
                                'flowGroups': [
                                    {'rule': 'Rule2', 'flowTuples': ['1705315201,10.0.0.2,20.0.0.2,1001,443,T,O,A']}
                                ]
                            }
                        ]
                    },
                },
            ]
        }

        blob = self._make_blob(data)

        call_count = 0

        def fail_on_second_call(url, data=None, headers=None):
            nonlocal call_count
            call_count += 1
            resp = Mock()
            # First HTTP call succeeds, second fails
            resp.status_code = 200 if call_count == 1 else 500
            return resp

        # Set BATCH_SIZE=1 so each flow tuple triggers a separate HTTP call
        with patch.dict(os.environ, {'BATCH_SIZE': '1'}):
            import importlib

            import function_app

            importlib.reload(function_app)

            with patch('function_app.requests.post', side_effect=fail_on_second_call):
                function_app.vnet_flow_log_trigger(blob)

        # Checkpoint must NOT be updated because the overall send did not fully succeed
        mock_checkpoint_mgr.update.assert_not_called()

    def test_checkpoint_manager_init_failure_falls_back_to_all_records(self, mock_env, captured_requests):
        """
        #5 — CheckpointManager init failure: if _build_checkpoint_manager() raises
        (e.g. transient Table Storage error during _ensure_table), main() falls back
        to processing all records without a checkpoint rather than crashing.
        """
        with patch('function_app._build_checkpoint_manager', side_effect=Exception('503 Service Unavailable')):
            blob = self._make_blob(SAMPLE_VNET_FLOW_LOG_V2)
            # Should not raise
            main(blob)

        # All 4 flow tuples should still be sent
        all_records = []
        for req in captured_requests:
            all_records.extend(decompress_and_parse_payload(req['data']))
        assert len(all_records) == 4


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])  # -s to show print output
