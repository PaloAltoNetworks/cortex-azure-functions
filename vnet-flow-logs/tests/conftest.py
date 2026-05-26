"""
pytest configuration for vnet-flow-logs tests.

Registers custom markers so that `pytest --strict-markers` and IDE tooling
don't warn on `@pytest.mark.memory`.
"""


def pytest_configure(config):
    config.addinivalue_line(
        'markers',
        'memory: slow memory-benchmark tests that build large synthetic files '
        'and assert peak RSS bounds. Run with `pytest -m memory` or skip with '
        '`pytest -m "not memory"`.',
    )
