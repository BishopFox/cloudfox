# Azure Service Layer

This directory contains service abstractions for Azure API calls. The service layer sits between command modules and the Azure SDK, providing:

- **API abstraction**: Clean interfaces for Azure service operations
- **Type safety**: Strongly-typed data structures for resources
- **Caching**: Efficient caching of API responses
- **Testability**: Mockable interfaces for unit testing

## Directory Structure

```
azure/services/
├── README.md               # This file
├── storageService/         # Azure Storage operations
├── acrService/             # Azure Container Registry
├── aksService/             # Azure Kubernetes Service
├── keyvaultService/        # Azure Key Vault
├── vmService/              # Virtual Machines
├── rbacService/            # RBAC operations
├── networkService/         # Network resources (VNets, NSGs, NICs, etc.)
├── databaseService/        # Database resources (SQL, Cosmos, PostgreSQL, MySQL)
├── graphService/           # Microsoft Graph API (Entra ID)
├── devopsService/          # Azure DevOps API
├── functionService/        # Azure Functions
├── policyService/          # Azure Policy
├── apimService/            # API Management
├── automationService/      # Azure Automation
├── containerService/       # Container Apps & Instances
├── monitoringService/      # Azure Monitor
├── mlService/              # Machine Learning
├── logicappService/        # Logic Apps
├── batchService/           # Azure Batch
├── arcService/             # Azure Arc
├── dnsService/             # DNS & Private DNS
├── webappService/          # Web Apps & App Service
├── eventgridService/       # Event Grid
└── servicebusService/      # Service Bus
```

## Migration Status

The Azure codebase is being migrated from `internal/azure/*_helpers.go` to this service layer pattern.

### Completed (24 Services)

| Service | Description | Key Methods |
|---------|-------------|-------------|
| `storageService/` | Azure Storage | ListStorageAccounts, ListContainers, GetKeys, ListFileShares, ListTables |
| `acrService/` | Container Registry | ListRegistries, ListRepositories, ListTags, GetCredentials |
| `aksService/` | Kubernetes Service | ListClusters, GetCredentials, ListAgentPools |
| `keyvaultService/` | Key Vault | ListVaults, ListSecrets, GetSecret |
| `vmService/` | Virtual Machines | ListVMs, ListVMSS, ListDisks, GetInstanceView |
| `rbacService/` | RBAC | ListRoleAssignments, ListRoleDefinitions, ListEligibleRoleAssignments |
| `networkService/` | Networking | ListVNets, ListNSGs, ListNICs, ListPublicIPs, ListLoadBalancers |
| `databaseService/` | Databases | ListSQLServers, ListCosmosDBAccounts, ListPostgreSQLServers, ListMySQLServers |
| `graphService/` | Entra ID (Graph API) | ListUsers, ListGroups, ListServicePrincipals, ListApplications |
| `devopsService/` | Azure DevOps | ListProjects, ListRepositories, ListPipelines, ListAgentPools |
| `functionService/` | Azure Functions | ListFunctionApps, ListFunctions, GetAppSettings |
| `policyService/` | Azure Policy | ListPolicyDefinitions, ListPolicyAssignments, ListPolicyExemptions |
| `apimService/` | API Management | ListServices, ListAPIs, ListSubscriptions, ListNamedValues |
| `automationService/` | Azure Automation | ListAccounts, ListRunbooks, ListCredentials, ListVariables |
| `containerService/` | Container Apps/Instances | ListContainerApps, ListContainerGroups, GetSecrets |
| `monitoringService/` | Azure Monitor | ListDiagnosticSettings, ListMetricAlerts, ListActionGroups |
| `mlService/` | Machine Learning | ListWorkspaces, ListComputes, ListDatastores |
| `logicappService/` | Logic Apps | ListWorkflows, ListTriggers, GetTriggerCallbackURL |
| `batchService/` | Azure Batch | ListAccounts, ListPools, GetAccountKeys, ListApplications |
| `arcService/` | Azure Arc | ListMachines, GetMachine, ListExtensions |
| `dnsService/` | DNS | ListZones, ListRecordSets, ListPrivateZones, ListVNetLinks |
| `webappService/` | Web Apps | ListWebApps, GetAppSettings, ListAppServicePlans, ListDeploymentSlots |
| `eventgridService/` | Event Grid | ListTopics, ListDomains, ListSystemTopics, GetTopicKeys |
| `servicebusService/` | Service Bus | ListNamespaces, ListQueues, ListTopics, GetNamespaceKeys |

### Service Layer Complete!

All major Azure services have been abstracted into the service layer. The service layer now covers:
- **Compute**: VMs, AKS, Container Apps, Batch, Arc, Functions, Web Apps
- **Storage**: Storage Accounts, Blobs, Files, Tables
- **Identity**: RBAC, Graph API, Key Vault
- **Networking**: VNets, NSGs, DNS, Load Balancers, Application Gateways
- **Databases**: SQL, Cosmos DB, PostgreSQL, MySQL
- **Integration**: Service Bus, Event Grid, Logic Apps, API Management
- **DevOps**: Azure DevOps, Automation
- **Governance**: Policy, Monitoring

## Service Pattern

Each service should follow this pattern:

```go
package storageservice

import (
    "context"
    azinternal "github.com/BishopFox/cloudfox/internal/azure"
)

// StorageService provides methods for interacting with Azure Storage
type StorageService struct {
    session *azinternal.SafeSession
}

// New creates a new StorageService instance
func New(session *azinternal.SafeSession) *StorageService {
    return &StorageService{session: session}
}

// ListStorageAccounts lists all storage accounts in a subscription
func (s *StorageService) ListStorageAccounts(ctx context.Context, subscriptionID string) ([]*StorageAccountInfo, error) {
    // Implementation
}
```

## Usage in Command Modules

```go
import (
    storageservice "github.com/BishopFox/cloudfox/azure/services/storageService"
)

func (m *StorageModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
    svc := storageservice.New(m.Session)
    accounts, err := svc.ListStorageAccounts(ctx, subID)
    // ...
}
```

## Caching

The service layer includes built-in caching for better performance. Each service has cached versions of its main methods:

### Available Cached Methods

All 24 services now have built-in caching:

| Service | Cached Methods |
|---------|----------------|
| `storageService` | `CachedListStorageAccounts`, `CachedListStorageAccountsByResourceGroup`, `CachedListContainers`, `CachedListFileShares`, `CachedListTables` |
| `acrService` | `CachedListRegistries`, `CachedListRegistriesByResourceGroup`, `CachedListRepositories`, `CachedListTags` |
| `aksService` | `CachedListClusters`, `CachedListClustersByResourceGroup`, `CachedListAgentPools` |
| `keyvaultService` | `CachedListVaults`, `CachedListVaultsByResourceGroup`, `CachedListSecrets` |
| `vmService` | `CachedListVMs`, `CachedListVMsByResourceGroup`, `CachedListVMSS`, `CachedListDisks`, `CachedListDisksByResourceGroup` |
| `rbacService` | `CachedListRoleAssignments`, `CachedListRoleAssignmentsForSubscription`, `CachedListRoleDefinitions`, `CachedListEligibleRoleAssignments` |
| `networkService` | `CachedListVirtualNetworks`, `CachedListNSGs`, `CachedListNetworkInterfaces`, `CachedListPublicIPAddresses`, `CachedListLoadBalancers`, `CachedListApplicationGateways`, `CachedListPrivateEndpoints` |
| `databaseService` | `CachedListSQLServers`, `CachedListSQLServersByResourceGroup`, `CachedListCosmosDBAccounts`, `CachedListPostgreSQLFlexibleServers`, `CachedListMySQLFlexibleServers` |
| `graphService` | `CachedListUsers`, `CachedListGroups`, `CachedListServicePrincipals`, `CachedListApplications`, `CachedListOAuth2PermissionGrants` |
| `devopsService` | `CachedListProjects`, `CachedListRepositories`, `CachedListPipelines`, `CachedListAgentPools`, `CachedListServiceConnections`, `CachedListVariableGroups` |
| `functionService` | `CachedListFunctionApps`, `CachedListFunctionAppsByResourceGroup`, `CachedListFunctions` |
| `policyService` | `CachedListPolicyDefinitions`, `CachedListPolicyAssignments`, `CachedListPolicySetDefinitions`, `CachedListPolicyExemptions` |
| `apimService` | `CachedListServices`, `CachedListAPIs`, `CachedListSubscriptions`, `CachedListNamedValues` |
| `automationService` | `CachedListAccounts`, `CachedListRunbooks`, `CachedListCredentials`, `CachedListVariables`, `CachedListSchedules` |
| `containerService` | `CachedListContainerApps`, `CachedListContainerAppEnvironments`, `CachedListContainerGroups` |
| `monitoringService` | `CachedListMetricAlerts`, `CachedListActionGroups`, `CachedListActivityLogAlerts` |
| `mlService` | `CachedListWorkspaces`, `CachedListComputes`, `CachedListDatastores` |
| `logicappService` | `CachedListWorkflows`, `CachedListTriggers`, `CachedListIntegrationAccounts` |
| `batchService` | `CachedListAccounts`, `CachedListPools`, `CachedListApplications` |
| `arcService` | `CachedListMachines`, `CachedListExtensions` |
| `dnsService` | `CachedListZones`, `CachedListPrivateZones`, `CachedListRecordSets` |
| `webappService` | `CachedListWebApps`, `CachedListAppServicePlans`, `CachedListDeploymentSlots` |
| `eventgridService` | `CachedListTopics`, `CachedListDomains`, `CachedListSystemTopics` |
| `servicebusService` | `CachedListNamespaces`, `CachedListQueues`, `CachedListTopics` |

### Using Cached Methods

```go
import (
    storageservice "github.com/BishopFox/cloudfox/azure/services/storageService"
)

func (m *StorageModule) processResourceGroup(ctx context.Context, subID, rgName string) {
    svc := storageservice.New(m.Session)

    // Use cached method for better performance
    accounts, err := svc.CachedListStorageAccountsByResourceGroup(ctx, subID, rgName)
    if err != nil {
        // handle error
    }

    for _, acct := range accounts {
        // Process account...

        // Containers are also cached
        containers, err := svc.CachedListContainers(ctx, subID, *acct.Name, rgName, location, kind)
        // ...
    }
}
```

### Cache Configuration

- **Default TTL**: 2 hours
- **Cleanup Interval**: 10 minutes
- **Cache Library**: `github.com/patrickmn/go-cache`

Each service maintains its own cache instance with unique cache keys to avoid collisions.

## Base Module and Session

The service layer uses the standardized files:

- **`internal/azure/base.go`**: `BaseAzureModule`, `CommandContext`, `NewBaseAzureModule()`
- **`internal/azure/session.go`**: `SafeSession`, token management, auth helpers

See `/tmp/docs/standardization/STANDARDIZATION.md` for complete details.
