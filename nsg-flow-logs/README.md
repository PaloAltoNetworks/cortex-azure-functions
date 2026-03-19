[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FPaloAltoNetworks%2Fcortex-azure-functions%2Fmaster%2Fnsg-flow-logs%2Farm_template%2Fprivate_storage.json)

---

> [!WARNING]
> ## ⚠️ Microsoft Deprecation Notice: NSG Flow Logs
>
> **NSG Flow Logs are being retired by Microsoft on September 30, 2027.**
>
> - **After June 30, 2025**, you will **no longer be able to create new NSG flow logs**.
> - **After September 30, 2027**, all existing NSG flow log resources in your subscriptions will be **automatically deleted** by Microsoft. Traffic Analytics enabled for NSG flow logs will also stop working.
> - Existing NSG flow log records already stored in Azure Storage will **not** be deleted and will continue to follow their configured retention policies.
>
> ### What you should do
>
> Microsoft recommends migrating to **Virtual Network (VNet) Flow Logs**, which overcome the limitations of NSG flow logs and provide broader, more flexible network visibility at the VNet level.
>
> **This repository provides a ready-to-use VNet Flow Logs collector** as a drop-in replacement:
> 👉 See the [`vnet-flow-logs/`](../vnet-flow-logs/README.md) directory.
>
> ### How to migrate
>
> Refer to the official Microsoft documentation for full migration instructions:
> 🔗 [Migrate from NSG flow logs to Virtual Network flow logs](https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-migrate)

---

## Cortex Azure NSG Flow Logs Collector
This repository contains an Azure Function that collects NSG Flow Logs from Azure and forwards them to Cortex. The Azure Function is deployed using an ARM template that creates all the necessary Azure resources such as a private storage account (for internal usage), private endpoints, and subnets.

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
   * **targetStorageAccountResourceGroup**: The name of the resource group where the storage account containing the NSG Flow Logs was created.
   * **targetStorageAccountName**: The name of the Azure Storage Account from which you want to capture the log blobs.
   * **targetContainerName**: The name of the container that holds the logs you want to forward (default: `insights-logs-networksecuritygroupflowevent`).
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

The function is triggered each time a new blob is written or updated in the configured container of your target storage account. On each trigger, it reads the blob content, denormalizes the nested NSG flow log records into individual flow tuples, and forwards them to Cortex in compressed batches over HTTPS.

#### Checkpoint Tracking

NSG Flow Log blobs are **append-only**: Azure continuously appends new flow records to the same blob throughout its active hour. This means the function may be triggered multiple times for the same blob as new data arrives.

To avoid re-sending records that have already been forwarded, the function maintains a **checkpoint** for each blob. The checkpoint records how many top-level flow log entries have already been successfully sent. On each invocation, only the newly appended records since the last checkpoint are processed and forwarded.

Checkpoints are stored in an **Azure Table Storage** table (`nsgflowcheckpoints`) within the private storage account that is automatically provisioned by the ARM template as part of the deployment. This storage account is isolated within the dedicated virtual network and is not publicly accessible.

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
Once the deployment is complete, the Azure Function will automatically start collecting NSG flow logs from the specified storage account and container. The logs will be forwarded to the configured Cortex HTTP endpoint using the provided access token.

### Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

### License
This project is licensed under the MIT License.
