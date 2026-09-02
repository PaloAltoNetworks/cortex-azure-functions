[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FPaloAltoNetworks%2Fcortex-azure-functions%2Fmaster%2Fvnet-flow-logs%2Farm_template%2Fprivate_storage.json)


## Cortex Azure VNET Flow Logs Collector
This repository contains an Azure Function that collects VNET Flow Logs from Azure and forwards them to Cortex. The Azure Function is deployed using an ARM template that creates all the necessary Azure resources such as a private storage account (for internal usage), private endpoints, and subnets.

*Please note that this Azure Function uses the **P0v3 App Service Premium plan** for optimal performance and advanced features, such as virtual network integration. The premium plan is required to enable the Azure Function to securely access the private storage account through virtual network integration, ensuring that the communication remains within the designated virtual network.*

### Prerequisites
Before deploying the Azure Function, ensure you have the following:

- Azure subscription with permissions to deploy ARM templates and create the required resources
- Cortex HTTP endpoint and Cortex access token

### Deployment
To deploy the Azure Function and the required resources, follow these steps:

1. Click the "Deploy to Azure" button above.

2. Fill in the required parameters in the Azure Portal:

   * **uniqueName**: A unique name for the Azure Function.
   * **cortexAccessToken**: The Cortex access token.
   * **targetStorageAccountResourceGroup**: The name of the resource group where the storage account containing the VNET Flow Logs was created.
   * **targetStorageAccountName**: The name of the Azure Storage Account from which you want to capture the log blobs.
   * **targetContainerName**: The name of the container that holds the logs you want to forward (default: `insights-logs-flowlogflowevent`).
   * **location**: The region where all the resources will be deployed (leave blank to use the same region as the resource group).
   * **cortexHttpEndpoint**: The Cortex HTTP endpoint.
   * **remotePackage**: The URL of the remote package ZIP file containing the Azure Function code.

3. Click **Review + Create** to review your deployment settings.
4. If the validation passes, click **Create** to start the deployment process.

### Important: Storage Account Network Access Configuration
If your Storage Account restricts public access, you must manually authorize the Collector's Virtual Network to allow the function app to pull flow logs.

**When is this required?** This step is necessary if your Storage Account is configured with:
* Public network access is disabled
* Public network access is enabled only from selected virtual networks and IP addresses

#### Required Steps:
1. In the Azure Portal, go to your Storage Account > **Security + networking** > **Networking**.
2. Locate the **Virtual networks** section.
3. Click **+ Add existing virtual network**.
4. Select the VNET and Subnet created during the Cortex Flow Logs Collector deployment.
5. Click **Add** and then **Save** at the bottom of the page.

> **Note:** It may take 5–10 minutes for the Azure network policy to propagate. Ingestion should begin automatically once the connection is authorized.

### How It Works

The function is triggered each time a new blob is written or updated in the configured container of your target storage account. On each trigger, it **streams** the blob content (one top-level `records[]` entry at a time, via [`ijson`](https://pypi.org/project/ijson/)), denormalizes the nested VNET flow log records into individual flow tuples, and forwards them to Cortex in compressed batches over HTTPS.

#### Concurrency caps

To make per-instance peak memory deterministic — particularly when bursts of flow-log blobs arrive simultaneously at the top of every hour — the deployment pins concurrency to predictable values:

| Setting | Value | Where | Purpose |
|---|---|---|---|
| `FUNCTIONS_WORKER_PROCESS_COUNT` | `1` | ARM app settings | One Python worker per instance |
| `PYTHON_THREADPOOL_THREAD_COUNT` | `1` | ARM app settings | One thread per worker for sync triggers |
| `extensions.blobs.maxDegreeOfParallelism` | `1` | `host.json` (overridable) | At most 1 concurrent blob invocation per instance |
| `concurrency.dynamicConcurrencyEnabled` | `true` | `host.json` | Host auto-throttles further if memory pressure is detected |

With these settings, on a P0v3 instance (≈4 GB RAM, 1 vCPU) the function comfortably handles bursts of large flow-log files. If you observe sustained back-pressure (long blob queues), scale out the App Service Plan rather than removing these caps.

**Why `maxDegreeOfParallelism = 1`?** Each in-flight blob is buffered in memory **twice** — once in the .NET Functions host and once in the Python worker — before and while your code streams it. Because the worker is pinned to a single process/thread, admitting more than one blob concurrently only stacks up buffered copies waiting for that one thread, multiplying peak memory for **zero** throughput gain, and increasing the frequency of benign `412 ConditionNotMet` blob-receipt races. Capping to 1 aligns admission with the single-threaded executor.

**Tuning at runtime (no redeploy of code):** `host.json` values can be overridden by app settings using the `AzureFunctionsJobHost__<path>` convention. The deployment exposes this as the `blobMaxDegreeOfParallelism` ARM parameter, which sets the `AzureFunctionsJobHost__extensions__blobs__maxDegreeOfParallelism` app setting. To change concurrency, update that app setting (or redeploy with a new parameter value) — for example set it to `2` only if the instance has memory headroom and you need more throughput. The change takes effect on the next worker restart; no code change is required.

#### Checkpoint Tracking

VNET Flow Log blobs are **append-only**: Azure continuously appends new flow records to the same blob throughout its active hour. This means the function may be triggered multiple times for the same blob as new data arrives.

To avoid re-sending records that have already been forwarded, the function maintains a **checkpoint** for each blob. The checkpoint records how many top-level flow log entries have already been successfully sent. On each invocation, only the newly appended records since the last checkpoint are processed and forwarded.

Checkpoints are stored in an **Azure Table Storage** table (`vnetflowcheckpoints`) within the private storage account that is automatically provisioned by the ARM template as part of the deployment. This storage account is isolated within the dedicated virtual network and is not publicly accessible.

Checkpoint entries are automatically cleaned up after 30 days, keeping the table lean without any manual intervention.

> **Reliability note:** The checkpoint is only updated after records have been successfully delivered to Cortex. If a delivery attempt fails, the checkpoint is not advanced, so the same records will be retried on the next invocation.

### Provisioned Azure Resources

The ARM template deploys the following resources into your subscription:

| Resource | Purpose |
|---|---|
| **Storage Account** (private) | Internal use by the Function App: hosts function state, triggers, and the checkpoint table used for deduplication |
| **App Service Plan** (P0v3 Premium) | Hosts the Function App with VNet integration support |
| **Function App** | Runs the log collection and forwarding logic |
| **Virtual Network** | Isolates the Function App and private storage from the public internet |
| **Private Endpoints** (×4) | Expose the private storage account's blob, file, queue, and table services within the VNet |
| **Private DNS Zones** (×4) | Enable DNS resolution for the private endpoints within the VNet |

### Usage
Once the deployment is complete, the Azure Function will automatically start collecting VNET flow logs from the specified storage account and container. The logs will be forwarded to the configured Cortex HTTP endpoint using the provided access token.

### Troubleshooting & Common Issues

#### `System.OutOfMemoryException` on very large `PT1H.json` files

**Symptom.** In the function logs you see entries such as:

```
System.OutOfMemoryException at System.IO.MemoryStream.set_Capacity
Category: Host.Results / Function.vnet_flow_log_trigger
Executed 'Functions.vnet_flow_log_trigger' (Failed, Duration=1385ms)
```

The invocation fails **quickly** (typically 1–5 seconds) and the host may report `Host is shutting down.`

**Root cause.** This exception originates in the **.NET Azure Functions host process**, not in the Python code. Before the blob is handed to the Python worker, the host buffers the *entire* blob into a `MemoryStream`. A `MemoryStream` grows by **doubling** its internal buffer, so at each growth step it must allocate a **single contiguous array roughly twice the blob's current size**. When `PT1H.json` files are very large — and especially when several are buffered at once — that contiguous allocation can fail on a memory-fragmented or memory-pressured instance, producing the `set_Capacity` OutOfMemoryException.

Because the failure happens in the host *before* the function's streaming code runs, it is unaffected by the worker-side memory optimizations (streaming parse + batching). The function's own peak memory is small and bounded; the pressure comes from the host's whole-blob buffering.

**Mitigations (in order of preference):**

1. **Keep blob concurrency at 1 (default).** `extensions.blobs.maxDegreeOfParallelism` is set to `1` so the host buffers only **one** blob (one `MemoryStream`) per instance at a time, instead of competing for multiple large contiguous allocations simultaneously. If you previously raised this, lower it back to `1`. It is controllable at runtime via the `blobMaxDegreeOfParallelism` ARM parameter (which sets the `AzureFunctionsJobHost__extensions__blobs__maxDegreeOfParallelism` app setting) — no code redeploy needed.

2. **Scale up the App Service Plan SKU (more RAM).** The host must hold the whole blob (plus headroom for the doubling allocation) in memory. If your environment produces genuinely large `PT1H.json` files (hundreds of MB — flow-log blobs grow throughout their active hour and can spike during traffic peaks), the default **P0v3 (~4 GB RAM)** instance may be insufficient. Move to a larger Premium SKU to increase available contiguous memory:

   | SKU | vCPU | RAM (approx.) |
   |---|---|---|
   | **P0v3** (default) | 1 | 4 GB |
   | **P1v3** | 2 | 8 GB |
   | **P2v3** | 4 | 16 GB |
   | **P3v3** | 8 | 32 GB |

   Change the plan tier on the App Service Plan created by the deployment (or update the ARM template's `serverfarms` SKU) and restart the Function App. More RAM both reduces fragmentation pressure and allows the larger contiguous `MemoryStream` allocation to succeed.

   > **Rule of thumb:** the host needs on the order of **2–3× the largest expected `PT1H.json` size** in free contiguous memory per concurrently-buffered blob. With `maxDegreeOfParallelism = 1`, budget for a single blob; if you must run higher concurrency, multiply accordingly.

3. **Scale out (add instances) for throughput, not for this OOM.** Adding instances spreads *different* blobs across machines but does **not** make any single blob smaller — each instance still buffers whole blobs. Scale out to keep up with volume, but scale **up** (bigger SKU) to fix the `set_Capacity` OOM on large files.

> **Note:** The worker-side memory tests in `tests/test_memory_benchmark.py` verify the Python streaming implementation only. They intentionally do **not** reproduce this host-side `MemoryStream` OOM, because that allocation happens in a separate (.NET) process before the Python code executes.

### Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

### License
This project is licensed under the MIT License.
