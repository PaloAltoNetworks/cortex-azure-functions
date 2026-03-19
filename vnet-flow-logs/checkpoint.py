import hashlib
import logging
from datetime import UTC, datetime, timedelta

from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.data.tables import TableServiceClient, UpdateMode

# ---------------------------------------------------------------------------
# Module-level singleton — created once at cold start, reused across all
# warm invocations on the same worker instance (#3).
# ---------------------------------------------------------------------------
_checkpoint_manager_instance: 'CheckpointManager | None' = None


def get_checkpoint_manager(
    connection_string: str,
    table_name: str,
    retention_days: int,
    cleanup_interval_hours: int,
) -> 'CheckpointManager':
    """
    Return the module-level CheckpointManager singleton, creating it on the
    first call.  Subsequent calls with the same or different arguments return
    the existing instance — configuration is fixed at cold-start time.
    """
    global _checkpoint_manager_instance
    if _checkpoint_manager_instance is None:
        _checkpoint_manager_instance = CheckpointManager(
            connection_string=connection_string,
            table_name=table_name,
            retention_days=retention_days,
            cleanup_interval_hours=cleanup_interval_hours,
        )
    return _checkpoint_manager_instance


class CheckpointManager:
    """
    Manages per-blob processing checkpoints in Azure Table Storage.

    Each checkpoint row tracks how many top-level `records[]` entries have been
    successfully sent for a given blob, so that on the next trigger invocation
    only newly appended records are processed.

    Key scheme (flat table — single partition)
    ------------------------------------------
    PartitionKey : "checkpoints"  (constant — keeps the table flat and readable)
    RowKey       : sha256 hex digest of the full blob_name
                   (blob paths contain '/', '\\', '#', '?' which are forbidden
                   in Table Storage keys, so we hash the full path)
    blob_name    : stored as a plain field so the row is human-readable in the
                   Azure Portal without needing to reverse the hash

    Row fields
    ----------
    processed_record_count : int  — number of top-level records[] already sent
    blob_size_at_last_run  : int  — blob.length at last successful run
    blob_name              : str  — original blob path (for human readability)
    last_updated           : str  — ISO 8601 UTC timestamp of last upsert

    Passive cleanup
    ---------------
    `update()` calls `maybe_cleanup_stale()` when
    `datetime.now(utc).hour % cleanup_interval_hours == 0`.
    `maybe_cleanup_stale()` uses an OData server-side filter on `last_updated`
    so only stale rows are transferred over the wire (#2).
    """

    PARTITION_KEY = 'checkpoints'
    DEFAULT_TABLE_NAME = 'vnetflowcheckpoints'

    def __init__(
        self,
        connection_string: str,
        table_name: str = DEFAULT_TABLE_NAME,
        retention_days: int = 2,
        cleanup_interval_hours: int = 6,
    ):
        self._table_name = table_name
        self._retention_days = retention_days
        self._cleanup_interval_hours = cleanup_interval_hours
        logging.info(
            f'CheckpointManager initializing: table={table_name}, '
            f'retention_days={retention_days}, cleanup_interval_hours={cleanup_interval_hours}'
        )
        self._client = TableServiceClient.from_connection_string(connection_string)
        self._table_client = self._client.get_table_client(table_name)
        self._ensure_table()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, blob_name: str) -> int:
        """
        Return the number of already-processed top-level records for *blob_name*.
        Returns 0 if no checkpoint exists yet.
        """
        row_key = self._make_row_key(blob_name)
        try:
            entity = self._table_client.get_entity(partition_key=self.PARTITION_KEY, row_key=row_key)
            count = int(entity.get('processed_record_count', 0))
            logging.info(f'Checkpoint found for {blob_name}: {count} records already processed')
            return count
        except ResourceNotFoundError:
            logging.info(f'No checkpoint found for {blob_name}, starting from 0')
            return 0

    def update(self, blob_name: str, processed_count: int, blob_size: int) -> None:
        """
        Upsert the checkpoint row for *blob_name* with the new *processed_count*.

        Also triggers passive stale-row cleanup when the current UTC hour is a
        multiple of *cleanup_interval_hours*.
        """
        row_key = self._make_row_key(blob_name)
        now_utc = datetime.now(UTC)
        now_iso = now_utc.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z'
        entity = {
            'PartitionKey': self.PARTITION_KEY,
            'RowKey': row_key,
            'blob_name': blob_name,
            'processed_record_count': processed_count,
            'blob_size_at_last_run': blob_size,
            'last_updated': now_iso,
        }
        self._table_client.upsert_entity(entity=entity, mode=UpdateMode.REPLACE)
        logging.info(
            f'Checkpoint updated for {blob_name}: processed_record_count={processed_count}, '
            f'blob_size={blob_size} bytes, last_updated={now_iso}'
        )

        # Passive cleanup — runs only on matching hours to keep overhead minimal
        if now_utc.hour % self._cleanup_interval_hours == 0:
            try:
                self.maybe_cleanup_stale(self._retention_days)
            except Exception as e:
                # Cleanup failure must never block the main processing path
                logging.warning(f'Stale checkpoint cleanup failed (non-fatal): {e}')

    def maybe_cleanup_stale(self, retention_days: int) -> None:
        """
        Delete all checkpoint rows whose *last_updated* timestamp is older than
        *retention_days* days.

        Uses an OData server-side filter on `last_updated` so only stale rows
        are transferred over the wire (#2).  ISO 8601 timestamps sort
        lexicographically, making string comparison equivalent to datetime
        comparison for UTC timestamps in this format.

        Uses Table Storage batch transactions (max 100 rows per batch, same
        partition required).  Rows already deleted by a concurrent invocation
        produce a 404 which is swallowed safely.
        """
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        cutoff_iso = cutoff.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z'

        logging.info(f'Running stale checkpoint cleanup: deleting rows with last_updated < {cutoff_iso}')

        # Server-side OData filter — only stale rows are returned (#2)
        odata_filter = f"last_updated lt '{cutoff_iso}'"
        stale_entities = list(self._table_client.list_entities(filter=odata_filter))

        if not stale_entities:
            logging.info('No stale checkpoints found')
            return

        logging.info(f'Deleting {len(stale_entities)} stale checkpoint row(s)')

        # All rows share the same PartitionKey so we can batch them together.
        # Process in chunks of 100 (Table Storage batch limit per transaction).
        deleted = 0
        for chunk in _chunks(stale_entities, 100):
            operations = [('delete', entity, {}) for entity in chunk]
            try:
                self._table_client.submit_transaction(operations)
                deleted += len(chunk)
            except ResourceNotFoundError:
                # One or more rows already deleted by a concurrent invocation — safe to ignore
                logging.debug('Some stale checkpoint rows were already deleted by a concurrent cleanup run')
                deleted += len(chunk)

        logging.info(f'Stale checkpoint cleanup complete: {deleted} row(s) deleted')

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _make_row_key(self, blob_name: str) -> str:
        """
        Derive a stable, Table-Storage-safe RowKey from the full *blob_name*.

        blob_name example:
            insights-logs-flowlogflowevent/resourceId=.../y=2024/m=01/d=15/h=10/m=00/PT1H.json

        Azure Table Storage forbids '/', '\\', '#', '?' in key fields, all of
        which appear in blob paths.  We use the SHA-256 hex digest of the full
        path as the RowKey.  The original path is stored in the `blob_name`
        field of the row for human readability in the Azure Portal.

        A single constant PartitionKey ("checkpoints") keeps the table flat and
        allows all rows to be batch-deleted in a single transaction per chunk.
        """
        return hashlib.sha256(blob_name.encode('utf-8')).hexdigest()

    def _ensure_table(self) -> None:
        """Create the checkpoint table if it does not already exist."""
        try:
            self._client.create_table(self._table_name)
            logging.info(f'Created checkpoint table: {self._table_name}')
        except ResourceExistsError:
            pass  # Table already exists — expected on all runs after the first


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _chunks(lst: list, size: int):
    """Yield successive *size*-length chunks from *lst*."""
    for i in range(0, len(lst), size):
        yield lst[i : i + size]
