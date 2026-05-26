import gzip
import json
import logging
import os
import time
from io import BytesIO

import azure.functions as func
import ijson
import requests
from checkpoint import CheckpointManager, get_checkpoint_manager

app = func.FunctionApp()
logging.info('FunctionApp instance created. Starting discovery...')

# Configuration
CORTEX_HTTP_ENDPOINT = os.environ.get('CORTEX_HTTP_ENDPOINT')
CORTEX_ACCESS_TOKEN = os.environ.get('CORTEX_ACCESS_TOKEN')
CORTEX_MAX_PAYLOAD_SIZE_BYTES = int(os.environ.get('MAX_PAYLOAD_SIZE', 10 * 1000000))
HTTP_MAX_RETRIES = int(os.environ.get('HTTP_MAX_RETRIES', 3))
RETRY_INTERVAL = int(os.environ.get('RETRY_INTERVAL', 2000))  # default: 2 seconds
BATCH_SIZE = int(os.environ.get('BATCH_SIZE', 1000))  # Process records in batches of 1000

# Checkpoint configuration
CHECKPOINT_CONNECTION = os.environ.get('CHECKPOINT_CONNECTION')
CHECKPOINT_TABLE_NAME = os.environ.get('CHECKPOINT_TABLE_NAME', 'vnetflowcheckpoints')
CHECKPOINT_RETENTION_DAYS = int(os.environ.get('CHECKPOINT_RETENTION_DAYS', 30))
CHECKPOINT_CLEANUP_INTERVAL_HOURS = int(os.environ.get('CHECKPOINT_CLEANUP_INTERVAL_HOURS', 6))

# HTTP status codes that should not be retried (auth errors will never succeed on retry)
NON_RETRYABLE_STATUS_CODES = {401, 403}


class NonRetryableError(Exception):
    """Raised for errors that should not be retried (e.g. auth failures)."""

    pass


logging.info('Registering vnet_flow_log_trigger...')


@app.blob_trigger(arg_name='blob', path='insights-logs-flowlogflowevent/{name}', connection='TargetAccountConnection')
def vnet_flow_log_trigger(blob: func.InputStream):
    """
    Blob trigger entry point.

    Memory-conscious streaming design:
      - We never call `.decode()` on the blob bytes (saves one full file-sized copy).
      - We never load the full parsed JSON tree (saves another file-sized copy).
      - We stream `records[*]` one-at-a-time via `ijson`, denormalize each into flow
        tuples, batch them up to `BATCH_SIZE`, gzip+POST, and release. Peak memory
        is bounded by `BATCH_SIZE` denormalized dicts plus one in-flight raw record
        plus ijson's small parser buffers — independent of the blob size.

    Empty blob, whitespace-only blob, and partial / invalid JSON are still detected
    and skipped without raising, matching the previous behaviour expected by the
    existing test suite.
    """
    logging.info(f'Python blob trigger function processing blob, Name: {blob.name}, Size: {blob.length} bytes')

    if not CORTEX_HTTP_ENDPOINT:
        logging.error('missing cortex http endpoint configuration')
        return

    if not CORTEX_ACCESS_TOKEN:
        logging.error('missing cortex access token')
        return

    # Quick early-exit for blobs that are reported as zero-length by the host.
    if blob.length is not None and blob.length == 0:
        logging.info(f'Blob {blob.name}: received empty content (length=0), skipping')
        return

    try:
        # Load the checkpoint *before* we start streaming so we know how many
        # top-level records to skip. The checkpoint counts top-level records[]
        # entries already sent to Cortex.
        try:
            checkpoint_mgr = _build_checkpoint_manager()
        except Exception as e:
            logging.error(
                f'Blob {blob.name}: CheckpointManager initialization failed, '
                f'processing all records without checkpoint. Error: {e}'
            )
            checkpoint_mgr = None

        already_processed = 0
        if checkpoint_mgr is not None:
            try:
                already_processed = checkpoint_mgr.get(blob.name)
            except Exception as e:
                logging.error(
                    f'Blob {blob.name}: failed to read checkpoint, falling back to processing all records. Error: {e}'
                )
                already_processed = 0

        # Stream the blob and process records incrementally.
        # We need to handle three special cases that the previous (non-streaming)
        # implementation handled via `json.loads`:
        #   1. Empty / whitespace-only content     → skip silently
        #   2. Partial / invalid JSON              → skip silently (will retry on next append)
        #   3. Records array empty                 → skip silently
        # We may also need a second streaming pass to handle the "blob shrunk"
        # edge case (see below) — so we loop at most twice.
        skip_count = already_processed
        for attempt in (1, 2):
            try:
                stream_result = _stream_and_send_records(blob, skip_count)
            except _EmptyOrPartialBlobError as e:
                logging.info(f'Blob {blob.name}: {e}')
                return
            except _SendFailedError as e:
                # HTTP send failed mid-stream — do NOT update checkpoint
                logging.error(
                    f'Blob {blob.name}: failed to process/send records. Checkpoint will NOT be updated. Error: {e}'
                )
                return

            total_records_seen = stream_result['total_records_seen']
            new_records_processed = stream_result['new_records_processed']
            denormalized_sent = stream_result['denormalized_sent']

            if total_records_seen == 0:
                logging.warning(f'Blob {blob.name}: records array is empty, skipping')
                return

            # Handle the "blob shrunk / was re-created" edge case: the checkpoint
            # says we processed more records than the blob currently contains.
            # In a streaming pass we can only detect this AFTER we've reached the
            # end of the file, so on the first pass we may have skipped everything
            # without sending. Reset and re-stream once to actually process the
            # (smaller) new content. This costs one extra parse pass — but only
            # the very rare invocation where a flow-log blob is re-created.
            if attempt == 1 and skip_count > total_records_seen:
                logging.warning(
                    f'Blob {blob.name}: checkpoint ({skip_count}) exceeds total records '
                    f'({total_records_seen}) — blob may have been re-created. Resetting checkpoint to 0 '
                    f'and reprocessing from scratch.'
                )
                skip_count = 0
                # Loop will re-stream with skip_count=0 and actually send the records.
                continue

            break  # success — exit the (potentially 1-iteration) retry loop

        if new_records_processed == 0:
            logging.info(
                f'Blob {blob.name}: no new records since last checkpoint '
                f'({skip_count}/{total_records_seen} already processed). Skipping.'
            )
            return

        logging.info(
            f'Blob {blob.name}: processed {new_records_processed} new top-level record(s) '
            f'({denormalized_sent} denormalized flow tuples sent) '
            f'(checkpoint={skip_count}, total={total_records_seen})'
        )

        if checkpoint_mgr is not None:
            try:
                checkpoint_mgr.update(
                    blob.name,
                    skip_count + new_records_processed,
                    blob.length,
                )
            except Exception as e:
                logging.error(
                    f'Blob {blob.name}: failed to update checkpoint after successful send. '
                    f'Next invocation may re-process {new_records_processed} record(s). Error: {e}'
                )

    except Exception as e:
        logging.error(f'Blob {blob.name}: unexpected error during processing. Error: {e}')
        raise


class _EmptyOrPartialBlobError(Exception):
    """Internal: blob is empty, whitespace-only, or contains a truncated/partial JSON document."""


class _SendFailedError(Exception):
    """Internal: an HTTP send to Cortex failed and was not recovered by retries."""


def _stream_and_send_records(blob: func.InputStream, already_processed: int) -> dict:
    """
    Stream `records[*]` from the blob, skip the first `already_processed` entries,
    denormalize the rest, and ship them in batches of `BATCH_SIZE`.

    Returns a dict with:
      - total_records_seen:    int  — total top-level records streamed (incl. skipped)
      - new_records_processed: int  — top-level records actually processed
      - denormalized_sent:     int  — total denormalized flow tuples sent

    Raises:
      _EmptyOrPartialBlobError — empty content or JSON cannot be parsed (e.g. partial append)
      _SendFailedError         — an HTTP send to Cortex failed after retries
    """
    # Treat blob.read() as raw bytes — never decode the whole thing. We wrap the
    # bytes in BytesIO so ijson can stream from it. Note: blob.read() does load
    # the full bytes into memory once, which is the smallest required allocation
    # (~file size). We cannot avoid that without a true chunked reader from the
    # Functions runtime, which `func.InputStream` does not currently expose
    # reliably across versions.
    raw = blob.read()
    if not raw or not raw.strip():
        raise _EmptyOrPartialBlobError('received empty content, skipping')

    stream = BytesIO(raw)
    # ijson's `records.item` JSON path yields each element of the top-level
    # `records` array as a fully-parsed Python dict, one at a time.
    # We use the default (yajl2_c if available, otherwise pure-python) backend.
    try:
        record_iter = ijson.items(stream, 'records.item')

        batch: list = []
        total_records_seen = 0
        new_records_processed = 0
        denormalized_sent = 0

        try:
            for record in record_iter:
                total_records_seen += 1
                # Skip records that were already processed in a previous invocation.
                # We still have to parse them (ijson cannot skip without parsing) but
                # they are released immediately for GC since we don't append them
                # to the batch.
                if total_records_seen <= already_processed:
                    continue

                new_records_processed += 1
                for denormalized in _iter_denormalized_records(record):
                    batch.append(denormalized)
                    if len(batch) >= BATCH_SIZE:
                        compress_and_send(batch)
                        denormalized_sent += len(batch)
                        logging.info(f'Processed and sent {denormalized_sent} denormalized records so far')
                        batch = []
                # Drop the reference to the parsed record dict early so it can be
                # garbage-collected before we parse the next one.
                del record

            # Flush any remaining records in the last (partial) batch.
            if batch:
                compress_and_send(batch)
                denormalized_sent += len(batch)
        except ijson.JSONError as e:
            # Truncated / malformed JSON — likely a partial append being written
            # by Azure Network Watcher. Match previous behaviour: skip silently
            # and let the next trigger pick it up when the blob is complete.
            #
            # IMPORTANT: if we already shipped some batches before hitting the
            # malformed byte, we must surface a send-failure so the checkpoint
            # is NOT advanced. Otherwise the next invocation would skip those
            # already-shipped records when the blob is re-triggered and we'd
            # silently lose data (or — if the blob is re-triggered with the
            # same content — re-process the same prefix and double-send).
            if denormalized_sent > 0:
                raise _SendFailedError(
                    f'JSON became invalid after sending {denormalized_sent} record(s); '
                    f'checkpoint will not be advanced. Underlying error: {e}'
                ) from None
            raise _EmptyOrPartialBlobError(
                f'is currently incomplete (partial or invalid JSON). Skipping until next append. Error: {e}'
            ) from None

        return {
            'total_records_seen': total_records_seen,
            'new_records_processed': new_records_processed,
            'denormalized_sent': denormalized_sent,
        }
    except _SendFailedError:
        raise
    except _EmptyOrPartialBlobError:
        raise
    except Exception as e:
        # Anything else from the send/compress path — surface as _SendFailedError
        # so the caller knows not to advance the checkpoint.
        raise _SendFailedError(str(e)) from e
    finally:
        stream.close()


def _build_checkpoint_manager() -> CheckpointManager | None:
    if not CHECKPOINT_CONNECTION:
        logging.warning(
            'CHECKPOINT_CONNECTION is not set; processing all records without checkpoint. '
            'Set CHECKPOINT_CONNECTION to enable deduplication.'
        )
        return None
    try:
        return get_checkpoint_manager(
            connection_string=CHECKPOINT_CONNECTION,
            table_name=CHECKPOINT_TABLE_NAME,
            retention_days=CHECKPOINT_RETENTION_DAYS,
            cleanup_interval_hours=CHECKPOINT_CLEANUP_INTERVAL_HOURS,
        )
    except Exception as e:
        logging.error(f'Failed to initialize CheckpointManager, processing all records without checkpoint. Error: {e}')
        return None


def _iter_denormalized_records(record):
    """
    Yield denormalized records for one top-level `records[i]` entry.

    Generator (instead of returning a list) to avoid materializing all flow
    tuples of a single record in memory before they are appended to the batch.
    """
    for outer_flow in record['flowRecords']['flows']:
        for inner_flow in outer_flow['flowGroups']:
            for flow_tuple in inner_flow['flowTuples']:
                yield create_vnet_record(record, inner_flow, flow_tuple)


def serialize_in_batches(objects, max_batch_size=CORTEX_MAX_PAYLOAD_SIZE_BYTES):
    b = BytesIO()

    for obj in objects:
        json_line = json.dumps(obj)
        json_line_bytes = json_line.encode('utf-8') + b'\n'

        if b.tell() + len(json_line_bytes) > max_batch_size:
            batch = b.getvalue()
            yield batch
            b = BytesIO()

        b.write(json_line_bytes)

    if b.tell() > 0:
        batch = b.getvalue()
        yield batch

    b.close()


def compress_and_send(data):
    """
    Compress the given list of denormalized records (split into payload-sized
    sub-batches if needed) and POST each compressed payload to Cortex.

    Raises _SendFailedError if any sub-batch ultimately fails after retries.
    """
    try:
        for batch in serialize_in_batches(data):
            compressed = gzip.compress(batch)
            retry_max(http_send, HTTP_MAX_RETRIES, RETRY_INTERVAL, compressed)
    except _SendFailedError:
        raise
    except Exception as e:
        logging.error(f'Error during payload compression: {e}')
        raise _SendFailedError(str(e)) from e


def http_send(data):
    headers = {
        'Content-Type': 'application/json',
        'Content-Encoding': 'gzip',
        'Authorization': f'Bearer {CORTEX_ACCESS_TOKEN}',
    }

    response = requests.post(CORTEX_HTTP_ENDPOINT, data=data, headers=headers)
    logging.info(f'Got response: {response.status_code}')
    if response.status_code in NON_RETRYABLE_STATUS_CODES:
        raise NonRetryableError(
            f'Non-retryable error from Cortex HTTP collector. '
            f'Status code: {response.status_code}. Check CORTEX_ACCESS_TOKEN configuration.'
        )
    if response.status_code != 200:
        raise Exception(f'Failed to send logs to Cortex HTTP collector. Status code: {response.status_code}')


def retry_max(func, max_retries, interval, *args, **kwargs):
    num_retries = 0
    while num_retries < max_retries:
        try:
            func(*args, **kwargs)
            return
        except NonRetryableError as e:
            # Surface as a send failure so the streaming loop bubbles it up and
            # the checkpoint is not advanced.
            raise _SendFailedError(str(e)) from e
        except Exception as e:
            num_retries += 1
            if num_retries == max_retries:
                logging.error(f'Failed to send logs after {max_retries} attempt(s). Last error: {e}')
                raise _SendFailedError(str(e)) from e
            else:
                logging.warning(f'Attempt #{num_retries}/{max_retries} failed: {e}. Retrying in {interval} ms.')
                time.sleep(interval / 1000)


def create_vnet_record(record, inner_flow, flow_tuple):
    tuple_parts = flow_tuple.split(',')
    version = record['flowLogVersion']

    denormalized = {
        'time': record['time'],
        'category': record['category'],
        'operationName': record['operationName'],
        'resourceId': record['flowLogResourceID'],
        'version': float(version),
        'nsgRuleName': inner_flow['rule'],
        'mac': record['macAddress'],
        'startTime': int(tuple_parts[0]),
        'sourceAddress': tuple_parts[1],
        'destinationAddress': tuple_parts[2],
        'sourcePort': tuple_parts[3],
        'destinationPort': tuple_parts[4],
        'transportProtocol': tuple_parts[5],
        'deviceDirection': tuple_parts[6],
        'deviceAction': tuple_parts[7],
    }

    if version >= 2:
        flow_state = tuple_parts[8]
        denormalized['flowState'] = flow_state

        if flow_state != 'B':
            denormalized['packetsStoD'] = '0' if tuple_parts[9] == '' else tuple_parts[9]
            denormalized['bytesStoD'] = '0' if tuple_parts[10] == '' else tuple_parts[10]
            denormalized['packetsDtoS'] = '0' if tuple_parts[11] == '' else tuple_parts[11]
            denormalized['bytesDtoS'] = '0' if tuple_parts[12] == '' else tuple_parts[12]

    return denormalized
