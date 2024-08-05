[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fhafuta%2FAzureNetworkWatcherNSGFlowLogsConnector%2Frc-0.1%2Farm_template%2Fprivate_storage.json)


## Cortex Azure NSG Flow Logs Collector
This repository contains an Azure Function that collects NSG flow logs from Azure and forwards them to Cortex. The Azure Function is deployed using an ARM template that creates all the necessary Azure resources, including a private storage account, storage endpoints, subnets, and an internal storage account. This repository supports deployments where a private storage account is required, ensuring secure communication between the Azure Function and the storage resources.

*Please note that this Azure Function uses the **P0v3 App Service Premium plan** for optimal performance and advanced features, such as virtual network integration. The premium plan is required to enable the Azure Function to securely access the private storage account through virtual network integration, ensuring that the communication remains within the designated virtual network.*

### Prerequisites
Before deploying the Azure Function, ensure you have the following:

- Azure subscription with permissions to deploy ARM templates and create the required resources
- Cortex HTTP endpoint and Cortex access token

### Deployment
To deploy the Azure Function and the required resources, follow these steps:

1. Click the "Deploy to Azure" button above.

2. Fill in the required parameters in the Azure Portal:

   * uniqueName: A unique name for the Azure Function.
   cortexAccessToken: The Cortex access token.
   * targetStorageAccountName: The name of the Azure Storage Account from which you want to capture the log blobs.
   * targetContainerName: The name of the container that holds the logs you want to forward (default: "insights-logs-networksecuritygroupflowevent").
   * location: The region where all the resources will be deployed (leave blank to use the same region as the resource group).
   * cortexHttpEndpoint: The Cortex HTTP endpoint.
   * remotePackage: The URL of the remote package ZIP file containing the Azure Function code
   * Click "Review + Create" to review your deployment settings.
   * If the validation passes, click "Create" to start the deployment process.

### Usage
Once the deployment is complete, the Azure Function will automatically start collecting NSG flow logs from the specified storage account and container. The logs will be forwarded to the configured Cortex HTTP endpoint using the provided access token.

### Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

### License
This project is licensed under the MIT License.