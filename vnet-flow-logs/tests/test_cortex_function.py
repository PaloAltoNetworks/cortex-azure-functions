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
from cortex_function import denormalize_vnet_records, main

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

        import cortex_function

        importlib.reload(cortex_function)
        yield
        # Reload again to restore original state
        importlib.reload(cortex_function)


@pytest.fixture
def captured_requests():
    """Fixture to capture HTTP requests made during test"""
    requests = []

    def mock_post(url, data=None, headers=None):
        response = Mock()
        response.status_code = 200
        requests.append({'url': url, 'data': data, 'headers': headers})
        return response

    with patch('cortex_function.requests.post', side_effect=mock_post):
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

            import cortex_function

            importlib.reload(cortex_function)

            blob_content = json.dumps(SAMPLE_VNET_FLOW_LOG_V2)
            mock_blob = MockInputStream(blob_content, 'test.json')

            # Act
            cortex_function.main(mock_blob)

            # Assert
            assert len(captured_requests) == 0, 'No requests should be sent without endpoint'

    def test_missing_token_no_requests(self, captured_requests, mock_env):
        """Test that missing CORTEX_ACCESS_TOKEN prevents processing"""
        # Arrange
        with patch.dict(os.environ, {'CORTEX_HTTP_ENDPOINT': 'https://test.example.com'}, clear=True):
            import importlib

            import cortex_function

            importlib.reload(cortex_function)

            blob_content = json.dumps(SAMPLE_VNET_FLOW_LOG_V2)
            mock_blob = MockInputStream(blob_content, 'test.json')

            # Act
            cortex_function.main(mock_blob)

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

            import cortex_function

            importlib.reload(cortex_function)

            blob_content = json.dumps(large_dataset)
            mock_blob = MockInputStream(blob_content, 'large.json')

            # Act
            cortex_function.main(mock_blob)

        # Assert - should have multiple batches
        assert len(captured_requests) > 1, 'Large payload should be split into multiple batches'

        # Verify all records were sent
        all_received_records = []
        for req in captured_requests:
            records = decompress_and_parse_payload(req['data'])
            all_received_records.extend(records)

        assert len(all_received_records) == 1000, f'Expected 1000 records, got {len(all_received_records)}'


class TestDenormalizeVnetRecords:
    """Unit tests for denormalize_vnet_records function"""

    def test_denormalize_single_record_v2(self):
        """Test denormalization of a single v2 record"""
        data = {
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
                                        'rule': 'TestRule',
                                        'flowTuples': [
                                            '1705315200,10.0.0.4,20.30.40.50,54321,443,T,O,A,C,10,1500,5,750'
                                        ],
                                    }
                                ]
                            }
                        ]
                    },
                }
            ]
        }

        result = denormalize_vnet_records(data)

        assert len(result) == 1
        assert result[0]['sourceAddress'] == '10.0.0.4'
        assert result[0]['flowState'] == 'C'
        assert result[0]['packetsStoD'] == '10'

    def test_denormalize_multiple_tuples(self):
        """Test denormalization with multiple flow tuples"""
        result = denormalize_vnet_records(SAMPLE_VNET_FLOW_LOG_V2)

        # Should have 4 denormalized records
        assert len(result) == 4

        # Verify they're all from the correct sources
        source_addresses = [r['sourceAddress'] for r in result]
        assert '10.0.0.4' in source_addresses
        assert '10.0.0.5' in source_addresses
        assert '10.0.0.6' in source_addresses
        assert '10.0.1.10' in source_addresses


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
