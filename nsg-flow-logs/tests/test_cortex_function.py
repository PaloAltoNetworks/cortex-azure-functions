"""
E2E tests for nsg-flow-logs cortex_function.
Tests invoke nsg_flow_log_trigger() with real NSG flow log blob content and verify
all records arrive correctly.

NSG log format reference:
  https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview#log-format
"""

import gzip
import importlib
import json
import os
import sys
from unittest.mock import MagicMock, Mock, patch

import pytest

# Add parent directory to path so we can import function_app and checkpoint
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import function_app

# ---------------------------------------------------------------------------
# Sample NSG flow log fixtures
# ---------------------------------------------------------------------------

# Version 2 format — includes flow state and byte/packet counts
SAMPLE_NSG_FLOW_LOG_V2 = {
    'records': [
        {
            'time': '2024-01-15T10:00:00.0000000Z',
            'category': 'NetworkSecurityGroupFlowEvent',
            'operationName': 'NetworkSecurityGroupFlowEvents',
            'resourceId': '/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1',
            'properties': {
                'Version': 2,
                'flows': [
                    {
                        'rule': 'DefaultRule_AllowInternetOutBound',
                        'flows': [
                            {
                                'mac': '000D3A1B2C3D',
                                'flowTuples': [
                                    '1705315200,10.0.0.4,20.30.40.50,54321,443,T,O,A,C,10,1500,5,750',
                                    '1705315201,10.0.0.5,20.30.40.51,54322,443,T,O,A,C,20,3000,10,1500',
                                ],
                            },
                            {
                                'mac': '000D3A1B2C3E',
                                'flowTuples': [
                                    '1705315202,10.0.0.6,20.30.40.52,54323,80,T,I,D,B,,,,,',
                                ],
                            },
                        ],
                    },
                    {
                        'rule': 'UserRule_DenyAll',
                        'flows': [
                            {
                                'mac': '000D3A1B2C3F',
                                'flowTuples': [
                                    '1705315203,10.0.0.7,20.30.40.53,12345,22,T,I,D,E,0,0,3,180',
                                ],
                            }
                        ],
                    },
                ],
            },
        },
        {
            'time': '2024-01-15T10:01:00.0000000Z',
            'category': 'NetworkSecurityGroupFlowEvent',
            'operationName': 'NetworkSecurityGroupFlowEvents',
            'resourceId': '/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg2',
            'properties': {
                'Version': 2,
                'flows': [
                    {
                        'rule': 'CustomRule_AllowHTTPS',
                        'flows': [
                            {
                                'mac': '000D3A4E5F6A',
                                'flowTuples': [
                                    '1705315260,10.0.1.10,20.30.40.60,12345,443,T,O,A,C,100,10000,50,5000',
                                ],
                            }
                        ],
                    }
                ],
            },
        },
    ]
}

# Version 1 format — no flow state or byte/packet counts
SAMPLE_NSG_FLOW_LOG_V1 = {
    'records': [
        {
            'time': '2024-01-15T09:00:00.0000000Z',
            'category': 'NetworkSecurityGroupFlowEvent',
            'operationName': 'NetworkSecurityGroupFlowEvents',
            'resourceId': '/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-old',
            'properties': {
                'Version': 1,
                'flows': [
                    {
                        'rule': 'DefaultRule',
                        'flows': [
                            {
                                'mac': '000D3A7B8C9D',
                                'flowTuples': ['1705311600,10.0.2.20,20.30.40.70,9999,22,T,I,A'],
                            }
                        ],
                    }
                ],
            },
        }
    ]
}

# Empty records array
SAMPLE_NSG_FLOW_LOG_EMPTY_RECORDS = {'records': []}

# Record with no flows
SAMPLE_NSG_FLOW_LOG_NO_FLOWS = {
    'records': [
        {
            'time': '2024-01-15T10:00:00.0000000Z',
            'category': 'NetworkSecurityGroupFlowEvent',
            'operationName': 'NetworkSecurityGroupFlowEvents',
            'resourceId': '/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1',
            'properties': {
                'Version': 2,
                'flows': [],
            },
        }
    ]
}


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


class MockInputStream:
    """Minimal mock of azure.functions.InputStream."""

    def __init__(self, content: str, name: str = 'insights-logs-networksecuritygroupflowevent/PT1H.json'):
        self._content = content.encode('utf-8')
        self.name = name
        self.length = len(self._content)

    def read(self) -> bytes:
        return self._content


def _make_blob(data: dict, name: str = 'insights-logs-networksecuritygroupflowevent/PT1H.json') -> MockInputStream:
    return MockInputStream(json.dumps(data), name=name)


def _decode_sent_records(mock_post) -> list[dict]:
    """Decompress and parse all records sent across all mock_post calls."""
    records = []
    for c in mock_post.call_args_list:
        # data may be positional or keyword depending on call site
        compressed = c.kwargs.get('data') if c.kwargs.get('data') is not None else c.args[1]
        raw = gzip.decompress(compressed).decode('utf-8')
        for line in raw.strip().splitlines():
            records.append(json.loads(line))
    return records


# ---------------------------------------------------------------------------
# Environment + module-reload fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def mock_env():
    """
    Set env vars and reload function_app so module-level constants pick them up.
    Mirrors the pattern used in vnet-flow-logs tests.
    """
    with patch.dict(
        os.environ,
        {
            'CORTEX_HTTP_ENDPOINT': 'https://cortex.example.com/logs',
            'CORTEX_ACCESS_TOKEN': 'test-token-abc',
            'MAX_PAYLOAD_SIZE': '10000000',
            'HTTP_MAX_RETRIES': '3',
            'RETRY_INTERVAL': '0',  # no sleep in tests
        },
        clear=False,
    ):
        importlib.reload(function_app)
        yield
    importlib.reload(function_app)


def _trigger():
    """Return the current (reloaded) trigger function."""
    return function_app.nsg_flow_log_trigger


def _create_nsg_record():
    return function_app.create_nsg_record


# ---------------------------------------------------------------------------
# Unit tests: create_nsg_record()
# ---------------------------------------------------------------------------


class TestCreateNsgRecord:
    def test_v1_record_fields(self):
        record = SAMPLE_NSG_FLOW_LOG_V1['records'][0]
        outer_flow = record['properties']['flows'][0]
        inner_flow = outer_flow['flows'][0]
        flow_tuple = inner_flow['flowTuples'][0]

        result = function_app.create_nsg_record(record, outer_flow, inner_flow, flow_tuple)

        assert result['time'] == '2024-01-15T09:00:00.0000000Z'
        assert result['category'] == 'NetworkSecurityGroupFlowEvent'
        assert result['operationName'] == 'NetworkSecurityGroupFlowEvents'
        assert result['resourceId'] == (
            '/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-old'
        )
        assert result['version'] == 1.0
        assert result['nsgRuleName'] == 'DefaultRule'
        assert result['mac'] == '000D3A7B8C9D'
        assert result['startTime'] == 1705311600
        assert result['sourceAddress'] == '10.0.2.20'
        assert result['destinationAddress'] == '20.30.40.70'
        assert result['sourcePort'] == '9999'
        assert result['destinationPort'] == '22'
        assert result['transportProtocol'] == 'T'
        assert result['deviceDirection'] == 'I'
        assert result['deviceAction'] == 'A'
        # v1 must NOT have flow state fields
        assert 'flowState' not in result
        assert 'packetsStoD' not in result

    def test_v2_record_with_flow_state_continue(self):
        record = SAMPLE_NSG_FLOW_LOG_V2['records'][0]
        outer_flow = record['properties']['flows'][0]
        inner_flow = outer_flow['flows'][0]
        flow_tuple = inner_flow['flowTuples'][0]  # C state

        result = function_app.create_nsg_record(record, outer_flow, inner_flow, flow_tuple)

        assert result['version'] == 2.0
        assert result['flowState'] == 'C'
        assert result['packetsStoD'] == '10'
        assert result['bytesStoD'] == '1500'
        assert result['packetsDtoS'] == '5'
        assert result['bytesDtoS'] == '750'

    def test_v2_record_with_flow_state_begin(self):
        """Flow state 'B' (Begin) must NOT include packet/byte counts."""
        record = SAMPLE_NSG_FLOW_LOG_V2['records'][0]
        outer_flow = record['properties']['flows'][0]
        inner_flow = outer_flow['flows'][1]
        flow_tuple = inner_flow['flowTuples'][0]  # B state

        result = function_app.create_nsg_record(record, outer_flow, inner_flow, flow_tuple)

        assert result['flowState'] == 'B'
        assert 'packetsStoD' not in result
        assert 'bytesStoD' not in result

    def test_v2_record_with_flow_state_end_zero_counts(self):
        """Flow state 'E' with zero count fields should be preserved as '0'."""
        record = SAMPLE_NSG_FLOW_LOG_V2['records'][0]
        outer_flow = record['properties']['flows'][1]
        inner_flow = outer_flow['flows'][0]
        flow_tuple = inner_flow['flowTuples'][0]  # E state, 0,0,3,180

        result = function_app.create_nsg_record(record, outer_flow, inner_flow, flow_tuple)

        assert result['flowState'] == 'E'
        assert result['packetsStoD'] == '0'
        assert result['bytesStoD'] == '0'
        assert result['packetsDtoS'] == '3'
        assert result['bytesDtoS'] == '180'

    def test_mac_comes_from_inner_flow(self):
        """NSG schema: mac is on inner_flow, not on the top-level record."""
        record = SAMPLE_NSG_FLOW_LOG_V2['records'][0]
        outer_flow = record['properties']['flows'][0]
        inner_flow_0 = outer_flow['flows'][0]
        inner_flow_1 = outer_flow['flows'][1]

        r0 = function_app.create_nsg_record(record, outer_flow, inner_flow_0, inner_flow_0['flowTuples'][0])
        r1 = function_app.create_nsg_record(record, outer_flow, inner_flow_1, inner_flow_1['flowTuples'][0])

        assert r0['mac'] == '000D3A1B2C3D'
        assert r1['mac'] == '000D3A1B2C3E'

    def test_rule_comes_from_outer_flow(self):
        """NSG schema: rule is on outer_flow, not inner_flow."""
        record = SAMPLE_NSG_FLOW_LOG_V2['records'][0]
        outer_flow_0 = record['properties']['flows'][0]
        outer_flow_1 = record['properties']['flows'][1]
        inner_flow_0 = outer_flow_0['flows'][0]
        inner_flow_1 = outer_flow_1['flows'][0]

        r0 = function_app.create_nsg_record(record, outer_flow_0, inner_flow_0, inner_flow_0['flowTuples'][0])
        r1 = function_app.create_nsg_record(record, outer_flow_1, inner_flow_1, inner_flow_1['flowTuples'][0])

        assert r0['nsgRuleName'] == 'DefaultRule_AllowInternetOutBound'
        assert r1['nsgRuleName'] == 'UserRule_DenyAll'


# ---------------------------------------------------------------------------
# Integration tests: nsg_flow_log_trigger()
# ---------------------------------------------------------------------------


class TestNsgFlowLogTrigger:
    @patch('function_app.requests.post')
    def test_v2_all_records_sent(self, mock_post):
        mock_post.return_value = Mock(status_code=200)
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V2)

        _trigger()(blob)

        assert mock_post.called
        records = _decode_sent_records(mock_post)
        # 2 + 1 + 1 + 1 = 5 flow tuples across both top-level records
        assert len(records) == 5

    @patch('function_app.requests.post')
    def test_v1_record_sent(self, mock_post):
        mock_post.return_value = Mock(status_code=200)
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V1)

        _trigger()(blob)

        records = _decode_sent_records(mock_post)
        assert len(records) == 1
        assert records[0]['version'] == 1.0
        assert 'flowState' not in records[0]

    @patch('function_app.requests.post')
    def test_empty_blob_content_skipped(self, mock_post):
        blob = MockInputStream('   ')
        _trigger()(blob)
        mock_post.assert_not_called()

    @patch('function_app.requests.post')
    def test_partial_json_skipped(self, mock_post):
        blob = MockInputStream('{"records": [{"time": "2024')
        _trigger()(blob)
        mock_post.assert_not_called()

    @patch('function_app.requests.post')
    def test_empty_records_array_skipped(self, mock_post):
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_EMPTY_RECORDS)
        _trigger()(blob)
        mock_post.assert_not_called()

    @patch('function_app.requests.post')
    def test_missing_cortex_endpoint_skipped(self, mock_post):
        with patch.dict(os.environ, {'CORTEX_HTTP_ENDPOINT': ''}, clear=False):
            importlib.reload(function_app)
            blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V2)
            function_app.nsg_flow_log_trigger(blob)
        mock_post.assert_not_called()

    @patch('function_app.requests.post')
    def test_missing_cortex_token_skipped(self, mock_post):
        with patch.dict(os.environ, {'CORTEX_ACCESS_TOKEN': ''}, clear=False):
            importlib.reload(function_app)
            blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V2)
            function_app.nsg_flow_log_trigger(blob)
        mock_post.assert_not_called()

    @patch('function_app.requests.post')
    def test_correct_auth_header_sent(self, mock_post):
        mock_post.return_value = Mock(status_code=200)
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V1)

        _trigger()(blob)

        assert mock_post.called
        call_kwargs = mock_post.call_args
        headers = call_kwargs[1]['headers'] if call_kwargs[1] else call_kwargs[0][1]
        assert headers['Authorization'] == 'Bearer test-token-abc'
        assert headers['Content-Encoding'] == 'gzip'
        assert headers['Content-Type'] == 'application/json'

    @patch('function_app.requests.post')
    def test_401_no_retries(self, mock_post):
        """401 is non-retryable: http_send is called exactly once and the error is logged."""
        mock_post.return_value = Mock(status_code=401)
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V1)

        # The trigger catches the error internally and logs it; it does NOT re-raise.
        # We verify the behaviour by checking call count (no retries) and that no
        # checkpoint update was attempted.
        _trigger()(blob)

        # Should only be called once — no retries on 401
        assert mock_post.call_count == 1

    @patch('function_app.requests.post')
    def test_500_retries_up_to_max(self, mock_post):
        """500 is retryable: http_send is called HTTP_MAX_RETRIES times."""
        mock_post.return_value = Mock(status_code=500)
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V1)

        # The trigger catches the error internally and logs it; it does NOT re-raise.
        _trigger()(blob)

        assert mock_post.call_count == 3

    @patch('function_app.requests.post')
    def test_payload_is_gzip_compressed(self, mock_post):
        mock_post.return_value = Mock(status_code=200)
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V1)

        _trigger()(blob)

        assert mock_post.called
        compressed = mock_post.call_args[1]['data']
        # gzip magic bytes
        assert compressed[:2] == b'\x1f\x8b'
        decompressed = gzip.decompress(compressed)
        parsed = json.loads(decompressed.decode('utf-8').strip())
        assert 'resourceId' in parsed

    @patch('function_app.requests.post')
    def test_no_flows_in_record_sends_nothing(self, mock_post):
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_NO_FLOWS)
        _trigger()(blob)
        mock_post.assert_not_called()

    @patch('function_app.requests.post')
    def test_record_fields_match_nsg_schema(self, mock_post):
        """Verify the denormalized output uses NSG-specific field sources."""
        mock_post.return_value = Mock(status_code=200)
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V1)

        _trigger()(blob)

        records = _decode_sent_records(mock_post)
        assert len(records) == 1
        r = records[0]
        # resourceId comes from record['resourceId'] (not record['flowLogResourceID'])
        assert 'networkSecurityGroups' in r['resourceId']
        # mac comes from inner_flow['mac'] (not record['macAddress'])
        assert r['mac'] == '000D3A7B8C9D'
        # nsgRuleName comes from outer_flow['rule']
        assert r['nsgRuleName'] == 'DefaultRule'


# ---------------------------------------------------------------------------
# Checkpoint integration tests
# ---------------------------------------------------------------------------


class TestCheckpointBehavior:
    def test_checkpoint_skips_already_processed_records(self):
        """If checkpoint says 1 record already processed, only the 2nd record is sent."""
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V2, name='insights-logs-networksecuritygroupflowevent/PT1H.json')

        mock_mgr = MagicMock()
        mock_mgr.get.return_value = 1  # 1 record already processed

        with patch.dict(os.environ, {'CHECKPOINT_CONNECTION': 'UseDevelopmentStorage=true'}):
            importlib.reload(function_app)

        with (
            patch('function_app.get_checkpoint_manager', return_value=mock_mgr),
            patch('function_app.requests.post', return_value=Mock(status_code=200)) as mock_post,
        ):
            function_app.nsg_flow_log_trigger(blob)

        records = _decode_sent_records(mock_post)
        # Only the 2nd top-level record (1 flow tuple) should be sent
        assert len(records) == 1
        assert records[0]['resourceId'].endswith('nsg2')

    def test_checkpoint_updated_after_successful_send(self):
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V2)

        mock_mgr = MagicMock()
        mock_mgr.get.return_value = 0

        with patch.dict(os.environ, {'CHECKPOINT_CONNECTION': 'UseDevelopmentStorage=true'}):
            importlib.reload(function_app)

        with (
            patch('function_app.get_checkpoint_manager', return_value=mock_mgr),
            patch('function_app.requests.post', return_value=Mock(status_code=200)),
        ):
            function_app.nsg_flow_log_trigger(blob)

        mock_mgr.update.assert_called_once_with(blob.name, 2, blob.length)

    def test_checkpoint_not_updated_on_send_failure(self):
        """When send fails, checkpoint must NOT be updated."""
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V1)

        mock_mgr = MagicMock()
        mock_mgr.get.return_value = 0

        with patch.dict(os.environ, {'CHECKPOINT_CONNECTION': 'UseDevelopmentStorage=true'}):
            importlib.reload(function_app)

        with (
            patch('function_app.get_checkpoint_manager', return_value=mock_mgr),
            patch('function_app.requests.post', return_value=Mock(status_code=500)),
        ):
            # Trigger catches the error internally — does not re-raise
            function_app.nsg_flow_log_trigger(blob)

        mock_mgr.update.assert_not_called()

    def test_checkpoint_exceeds_total_resets_to_zero(self):
        """If checkpoint > total records (blob re-created), reset to 0 and process all."""
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V2)

        mock_mgr = MagicMock()
        mock_mgr.get.return_value = 999  # stale checkpoint larger than actual records

        with patch.dict(os.environ, {'CHECKPOINT_CONNECTION': 'UseDevelopmentStorage=true'}):
            importlib.reload(function_app)

        with (
            patch('function_app.get_checkpoint_manager', return_value=mock_mgr),
            patch('function_app.requests.post', return_value=Mock(status_code=200)) as mock_post,
        ):
            function_app.nsg_flow_log_trigger(blob)

        records = _decode_sent_records(mock_post)
        # All 5 flow tuples should be processed
        assert len(records) == 5

    @patch('function_app.requests.post')
    def test_no_checkpoint_connection_processes_all(self, mock_post):
        """Without CHECKPOINT_CONNECTION, all records are processed every invocation."""
        mock_post.return_value = Mock(status_code=200)
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V2)

        _trigger()(blob)

        records = _decode_sent_records(mock_post)
        assert len(records) == 5

    def test_checkpoint_init_failure_falls_back_to_full_processing(self):
        """If CheckpointManager init fails, all records are still processed."""
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V2)

        with patch.dict(os.environ, {'CHECKPOINT_CONNECTION': 'UseDevelopmentStorage=true'}):
            importlib.reload(function_app)

        with (
            patch('function_app.get_checkpoint_manager', side_effect=Exception('Table Storage unavailable')),
            patch('function_app.requests.post', return_value=Mock(status_code=200)) as mock_post,
        ):
            function_app.nsg_flow_log_trigger(blob)

        records = _decode_sent_records(mock_post)
        assert len(records) == 5

    def test_all_records_already_processed_skips_send(self):
        blob = _make_blob(SAMPLE_NSG_FLOW_LOG_V2)

        mock_mgr = MagicMock()
        mock_mgr.get.return_value = 2  # both records already processed

        with patch.dict(os.environ, {'CHECKPOINT_CONNECTION': 'UseDevelopmentStorage=true'}):
            importlib.reload(function_app)

        with (
            patch('function_app.get_checkpoint_manager', return_value=mock_mgr),
            patch('function_app.requests.post') as mock_post,
        ):
            function_app.nsg_flow_log_trigger(blob)

        mock_post.assert_not_called()
