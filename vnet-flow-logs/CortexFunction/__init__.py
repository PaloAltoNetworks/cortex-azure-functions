import azure.functions as func
import os
import json
import gzip
import logging
import requests
import time
from io import BytesIO

app = func.FunctionApp()

# Configuration
CORTEX_HTTP_ENDPOINT = os.environ.get('CORTEX_HTTP_ENDPOINT')
CORTEX_ACCESS_TOKEN = os.environ.get('CORTEX_ACCESS_TOKEN')
CORTEX_MAX_PAYLOAD_SIZE_BYTES = int(os.environ.get('MAX_PAYLOAD_SIZE', 10 * 1000000))
HTTP_MAX_RETRIES = int(os.environ.get('HTTP_MAX_RETRIES', 3))
RETRY_INTERVAL = int(os.environ.get('RETRY_INTERVAL', 2000))  # default: 2 seconds


def main(blob: func.InputStream):
    logging.info(f"Python blob trigger function processing blob, Name: {blob.name}, Size: {blob.length} bytes")

    if not CORTEX_HTTP_ENDPOINT:
        logging.error('missing cortex http endpoint configuration')
        return

    if not CORTEX_ACCESS_TOKEN:
        logging.error('missing cortex access token')
        return

    try:
        content = blob.read().decode('utf-8')

        if isinstance(content, str) and not content.strip():
            logging.info(f'received an empty blob: {blob.name}')
            return

        log_lines = json.loads(content)
        if not log_lines:
            logging.warning('empty blob, no logs')
            return
        denormalized = denormalize_vnet_records(log_lines)
        compress_and_send(denormalized)
    except Exception as e:
        logging.error(f'Error processing blob: {e}')


def serialize_in_batches(objects, max_batch_size=CORTEX_MAX_PAYLOAD_SIZE_BYTES):
    b = BytesIO()

    for obj in objects:
        json_line = json.dumps(obj)
        json_line_bytes = json_line.encode('utf-8') + b'\n'

        # Check if the compressed batch size exceeds the max batch size
        if b.tell() + len(json_line_bytes) > max_batch_size:
            # If the batch size is exceeded, yield the compressed batch (excluding the current object)
            batch = b.getvalue()
            yield batch
            b = BytesIO()

        b.write(json_line_bytes)

    # Yield the last batch if there are any remaining objects
    if b.tell() > 0:
        batch = b.getvalue()
        yield batch

    b.close()


def compress_and_send(data):
    try:
        for batch in serialize_in_batches(data):
            compressed = gzip.compress(batch)
            retry_max(http_send, HTTP_MAX_RETRIES, RETRY_INTERVAL, compressed)
    except Exception as e:
        logging.error(f'Error during payload compression: {e}')


def http_send(data):
    headers = {
        'Content-Type': 'application/json',
        'Content-Encoding': 'gzip',
        'Authorization': f'Bearer {CORTEX_ACCESS_TOKEN}'
    }

    response = requests.post(CORTEX_HTTP_ENDPOINT, data=data, headers=headers)
    logging.info(f'Got response: {response.status_code}')
    if response.status_code != 200:
        raise Exception(f'Failed to send logs to Cortex HTTP collector. Status code: {response.status_code}')


def retry_max(func, max_retries, interval, *args, **kwargs):
    num_retries = 0
    while num_retries < max_retries:
        try:
            func(*args, **kwargs)
            return
        except Exception as e:
            num_retries += 1
            if num_retries == max_retries:
                logging.error(f'Failed to send logs after {max_retries} attempts')
                raise e
            else:
                logging.info(f'Attempt #{num_retries} failed. Retrying in {interval} ms.')
                time.sleep(interval / 1000)


def create_vnet_record(record, inner_flow, flow_tuple):
    tuple_parts = flow_tuple.split(",")
    version = record["flowLogVersion"]

    # Log format reference: https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview?tabs=Americas#log-format
    denormalized = {
        "time": record["time"],
        "category": record["category"],
        "operationName": record["operationName"],
        "resourceId": record["flowLogResourceID"],
        "version": float(version),
        "nsgRuleName": inner_flow["rule"],
        "mac": record["macAddress"],
        "startTime": int(tuple_parts[0]),
        "sourceAddress": tuple_parts[1],
        "destinationAddress": tuple_parts[2],
        "sourcePort": tuple_parts[3],
        "destinationPort": tuple_parts[4],
        "transportProtocol": tuple_parts[5],
        "deviceDirection": tuple_parts[6],
        "deviceAction": tuple_parts[7],
    }

    if version >= 2:
        flow_state = tuple_parts[8]
        denormalized["flowState"] = flow_state

        if flow_state != "B":
            denormalized["packetsStoD"] = ("0" if tuple_parts[9] == "" else tuple_parts[9])
            denormalized["bytesStoD"] = ("0" if tuple_parts[10] == "" else tuple_parts[10])
            denormalized["packetsDtoS"] = ("0" if tuple_parts[11] == "" else tuple_parts[11])
            denormalized["bytesDtoS"] = ("0" if tuple_parts[12] == "" else tuple_parts[12])

    return denormalized


def denormalize_vnet_records(data):
    result = []
    for record in data["records"]:
        for outer_flow in record["flowRecords"]["flows"]:
            for inner_flow in outer_flow["flowGroups"]:
                for flow_tuple in inner_flow["flowTuples"]:
                    result.append(create_vnet_record(record, inner_flow, flow_tuple))
    return result