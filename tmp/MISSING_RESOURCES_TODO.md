# Missing Azure Resources - Simple TODO Checklist

**Date:** 2025-10-25
**Reference:** See `MISSING_RESOURCES_ANALYSIS.md` for detailed analysis

---

## 🔴 PHASE 1: CRITICAL DATABASE GAPS (Priority 1-2 weeks)

### databases.go Enhancements
- [x] **1.1** Add Azure SQL Managed Instance enumeration ✅ COMPLETE
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql` (ManagedInstancesClient, ManagedDatabasesClient)
  - Extract: Instance name, region, public/private endpoints, admin login, managed identities
  - Add to endpoints.go: Yes
  - **Implementation details:**
    - Created `GetSQLManagedInstances()` function (database_helpers.go:683-705)
    - Added managed instance enumeration section (database_helpers.go:212-357)
    - Changed SQL Database DB Type from "SQL" to "SQL Database" to distinguish from "SQL Managed Instance"
    - Updated firewall commands to handle both types (databases.go:222)
    - Added backup/restore commands for managed instances (databases.go:565-627)
    - Endpoint format: `{instance-name}.{region}.database.windows.net`
    - System databases (master, model, msdb, tempdb) are excluded
    - TDE is always enabled on Managed Instances
    - DDM is not supported on MI (displays "Not Supported on MI")
    - **BUG FIX**: Fixed endpoints.go database IP extraction (was using wrong indices 7,8 instead of 9,10)
    - Build verification: SUCCESS

- [x] **1.2** Add MySQL Flexible Server enumeration ✅ COMPLETE
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers`
  - Keep existing Single Server support
  - Add column: "Server Type" (Single/Flexible)
  - Add to endpoints.go: Yes
  - **Implementation details:**
    - Created `GetMySQLFlexibleServers()` function (database_helpers.go:879-901)
    - Added MySQL Flexible Server enumeration section (database_helpers.go:475-600)
    - Changed MySQL Single Server DB Type from "MySQL" to "MySQL Single Server" to distinguish from "MySQL Flexible Server"
    - Split backup commands into separate cases for Single Server vs Flexible Server (databases.go:629-736)
    - MySQL Single Server uses `az mysql server` commands
    - MySQL Flexible Server uses `az mysql flexible-server` commands
    - Endpoint format: `{server}.mysql.database.azure.com` (same for both types)
    - System databases (information_schema, mysql, performance_schema, sys) are excluded
    - Customer-managed key detection via DataEncryption.PrimaryKeyURI
    - Backup commands include point-in-time restore and read replica creation
    - Added SDK dependency: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers v1.2.0`
    - Build verification: SUCCESS

- [x] **1.3** Add PostgreSQL Flexible Server enumeration ✅ COMPLETE
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers`
  - Keep existing Single Server support
  - Add column: "Server Type" (Single/Flexible)
  - Add to endpoints.go: Yes
  - **Implementation details:**
    - Created `GetPostgreSQLFlexibleServers()` function (database_helpers.go:1031-1053)
    - Added PostgreSQL Flexible Server enumeration section (database_helpers.go:720-840)
    - Changed PostgreSQL Single Server DB Type from "PostgreSQL" to "PostgreSQL Single Server" to distinguish from "PostgreSQL Flexible Server"
    - Split backup commands into separate cases for Single Server vs Flexible Server (databases.go:738-845)
    - PostgreSQL Single Server uses `az postgres server` commands
    - PostgreSQL Flexible Server uses `az postgres flexible-server` commands
    - Endpoint format: `{server}.postgres.database.azure.com` for flexible servers (vs `.windows.net` for single servers)
    - System databases (azure_maintenance, azure_sys, postgres) are excluded
    - Customer-managed keys (CMK) not currently supported via SDK for PostgreSQL Flexible Server
    - Backup commands include point-in-time restore and read replica creation
    - Added SDK dependency: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers v1.1.0`
    - Build verification: SUCCESS

- [x] **1.4** Add MariaDB enumeration ✅ COMPLETE
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mariadb/armmariadb`
  - Add to endpoints.go: Yes
  - **Implementation details:**
    - Created `GetMariaDBServers()` function (database_helpers.go:1225-1247)
    - Added MariaDB enumeration section (database_helpers.go:841-962)
    - DB Type set to "MariaDB"
    - Added MariaDB backup commands case (databases.go:847-898)
    - MariaDB uses `az mariadb server` commands (similar to MySQL Single Server)
    - Endpoint format: `{server}.mariadb.database.azure.com`
    - System databases (information_schema, mysql, performance_schema) are excluded
    - Customer-managed keys (CMK) not currently exposed via SDK for MariaDB
    - Backup commands include point-in-time restore and read replica creation
    - Added SDK dependency: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mariadb/armmariadb v1.2.0`
    - Build verification: SUCCESS

### New Module: redis.go
- [x] **1.5** Create redis.go module for Azure Cache for Redis ✅ COMPLETE
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis`
  - Extract: Name, region, endpoint, SSL port, non-SSL port, access keys
  - Table columns: Subscription, Resource Group, Name, Region, SKU, Public/Private, SSL Enabled, Access Keys
  - Loot files: redis-commands, redis-connection-strings
  - Add to endpoints.go: Yes
  - **Implementation details:**
    - Created new redis.go module (azure/commands/redis.go)
    - Module structure follows established patterns with BaseAzureModule embedding
    - Table columns: Subscription ID, Subscription Name, Resource Group, Region, Redis Name, Endpoint, SSL Port, Non-SSL Port, SKU, Public/Private, SSL Enabled, Access Keys (reference), System/User Assigned Identities and Roles
    - Loot files: redis-commands (az CLI + PowerShell commands, redis-cli examples), redis-connection-strings (connection strings with keys)
    - Added `AZ_REDIS_MODULE_NAME` constant to globals/azure.go
    - Added `AzRedisCommand` to cli/azure.go command list
    - Added Redis enumeration to endpoints.go (lines 346-380)
    - Redis SDK property access: SKU is in `cache.Properties.SKU`, not directly in cache
    - Endpoint format: `{name}.redis.cache.windows.net`
    - Detects public vs private access via PublicNetworkAccess property
    - Extracts access keys, SSL/non-SSL ports, managed identities
    - Generates redis-cli commands for data access and export
    - Added SDK dependency: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis v1.0.0`
    - Build verification: SUCCESS

### New Module: synapse.go
- [x] **1.6** Create synapse.go module for Azure Synapse Analytics ✅ COMPLETE
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/synapse/armsynapse`
  - Enumerate: Workspaces, Dedicated SQL Pools, Serverless SQL Pools, Spark Pools
  - Extract: Workspace endpoint, SQL endpoints, Spark endpoints, managed identities
  - Loot files: synapse-commands, synapse-connection-strings
  - Add to endpoints.go: Yes
  - **Implementation details:**
    - Created new synapse.go module (azure/commands/synapse.go)
    - Module structure follows established patterns with BaseAzureModule embedding
    - Enumerates three resource types: Workspaces, Dedicated SQL Pools, and Spark Pools
    - Table columns: Subscription ID, Subscription Name, Resource Group, Region, Workspace Name, Resource Type, Resource Name, Endpoint, Public/Private, System/User Assigned Identities and Roles
    - Loot files: synapse-commands (az CLI + PowerShell commands for workspaces, SQL pools, and Spark pools), synapse-connection-strings (workspace endpoints and SQL connection strings)
    - Added `AZ_SYNAPSE_MODULE_NAME` constant to globals/azure.go
    - Added `AzSynapseCommand` to cli/azure.go command list
    - Added Synapse enumeration to endpoints.go (lines 383-432)
    - Extracts multiple endpoint types: workspace web endpoint, SQL endpoint, SQL on-demand endpoint (serverless), dev endpoint
    - Detects public vs private access via WorkspacePublicNetworkAccess property
    - Enumerates SQL pools per workspace using SQLPoolsClient
    - Enumerates Spark pools per workspace using BigDataPoolsClient
    - Generates workspace firewall rule commands
    - Generates SQL pool pause/resume commands for cost optimization
    - Generates Spark session listing commands
    - Added SDK dependency: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/synapse/armsynapse v0.8.0`
    - Build verification: SUCCESS

---

## 🔴 PHASE 2: CRITICAL NETWORK-EXPOSED ENDPOINTS (Priority 1-2 weeks)

### endpoints.go Enhancements
- [x] **2.1** Add API Management (APIM) enumeration ✅ COMPLETE
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement`
  - Extract: Service name, gateway URL, management URL, portal URL, SCM URL
  - Endpoint format: `{name}.azure-api.net`
  - **Implementation details:**
    - Added APIM enumeration directly to endpoints.go (lines 435-512)
    - Extracts four endpoint types: Gateway URL, Management API URL, Portal URL, SCM URL
    - Determines public/private based on VirtualNetworkType property:
      - `Internal`: Private endpoints only
      - `External`: Public (External VNet) - publicly accessible but VNet-connected
      - `None`: Public endpoints
    - All four endpoints are added separately to allow targeted scanning
    - Gateway URL: Primary API endpoint (`{name}.azure-api.net`)
    - Management API URL: Management operations endpoint
    - Portal URL: Developer portal endpoint
    - SCM URL: Source control management endpoint
    - Added SDK import to endpoints.go
    - Added SDK dependency: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement`
    - Build verification: SUCCESS

- [x] **2.2** Add Azure Front Door enumeration ✅ COMPLETE
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor`
  - Extract: Front Door name, frontend endpoints, backend pools
  - Endpoint format: `{name}.azurefd.net`
  - **Implementation details:**
    - Added Front Door enumeration directly to endpoints.go (lines 515-560)
    - Enumerates two types of endpoints:
      - **Frontend Endpoints**: Public-facing entry points (added to PublicRows)
      - **Backend Pools**: Backend origin servers (added to PrivateRows)
    - Frontend endpoints extract HostName property (typically `{name}.azurefd.net` or custom domains)
    - Backend pools enumerate all backend addresses per pool
    - Front Door is always public-facing by design (global CDN/WAF service)
    - Backend pools show internal/private origins that Front Door proxies to
    - Enables identification of both exposed Front Door endpoints and their protected backends
    - Added SDK import to endpoints.go
    - Added SDK dependency: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor v1.4.0`
    - Build verification: SUCCESS

- [x] **2.3** Add Azure CDN enumeration ✅ COMPLETED
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn`
  - Extract: Profile name, endpoints, origin servers
  - Endpoint format: `{name}.azureedge.net`
  - **Implementation Details**:
    - Two-level enumeration: CDN Profiles → Endpoints → Origins
    - CDN endpoint hostnames (typically `{name}.azureedge.net`) categorized as Public
    - Origin servers (backend infrastructure) categorized as Private
    - Implemented lines 562-621 in endpoints.go
    - Uses ProfilesClient and EndpointsClient for hierarchical enumeration
    - Added SDK import to endpoints.go
    - Added SDK dependency: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn v1.1.1`
    - Build verification: SUCCESS

- [x] **2.4** Add Azure Firewall enumeration ✅ COMPLETED
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (AzureFirewallsClient)
  - Extract: Firewall name, public IPs, firewall policy
  - Also add to new firewall.go for detailed rule analysis
  - **Implementation Details**:
    - Enumerates Azure Firewalls within each resource group
    - Extracts firewall name, public IP configurations, and firewall policy references
    - Firewalls with public IPs categorized as Public
    - Firewalls without public IPs categorized as Private (internal only)
    - Policy name extracted from FirewallPolicy.ID reference
    - Implemented lines 624-676 in endpoints.go
    - Uses AzureFirewallsClient with NewListPager for enumeration
    - Added armnetwork import to endpoints.go
    - SDK already available: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork`
    - Build verification: SUCCESS

- [x] **2.5** Add Traffic Manager enumeration ✅ COMPLETED
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/trafficmanager/armtrafficmanager`
  - Extract: Profile name, DNS name, endpoints
  - Endpoint format: `{name}.trafficmanager.net`
  - **Implementation Details**:
    - Enumerates Traffic Manager profiles within each resource group
    - Extracts profile name and DNS FQDN (e.g., myprofile.trafficmanager.net)
    - Traffic Manager DNS names categorized as Public (always internet-facing)
    - Extracts individual endpoints within each profile (Azure, External, Nested)
    - External endpoints categorized as Public
    - Azure/Nested endpoints categorized as Private
    - Implemented lines 679-733 in endpoints.go
    - Uses ProfilesClient with NewListByResourceGroupPager for enumeration
    - Added armtrafficmanager import to endpoints.go
    - Added SDK dependency: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/trafficmanager/armtrafficmanager v1.3.0`
    - Build verification: SUCCESS

- [x] **2.6** Add Azure Bastion enumeration ✅ COMPLETED   <- Checked vm-helpers.go for Bastion server enumeration
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (BastionHostsClient)
  - Extract: Bastion name, public IP, VNet
  - **Implementation Details**:
    - Enumerates Azure Bastion hosts within each resource group
    - Extracts Bastion name, public IP addresses, VNet, and subnet information
    - All Bastion hosts categorized as Public (they provide secure RDP/SSH access)
    - VNet and subnet names extracted from IPConfiguration.Subnet.ID
    - Public IP names extracted from IPConfiguration.PublicIPAddress.ID
    - Implemented lines 735-793 in endpoints.go
    - Uses BastionHostsClient with NewListByResourceGroupPager for enumeration
    - armnetwork SDK already imported and available
    - Note: vm-helpers.go already has GetBastionHostsPerSubscription helper function
    - Build verification: SUCCESS

- [x] **2.7** Add Event Hubs endpoints ✅ COMPLETED
  - Already have keys in accesskeys.go
  - Extract namespace endpoints: `{namespace}.servicebus.windows.net`
  - **Implementation Details**:
    - Enumerates Event Hub namespaces within each resource group
    - Extracts namespace name and Service Bus endpoint (e.g., mynamespace.servicebus.windows.net)
    - All Event Hub namespaces categorized as Public (messaging service endpoints)
    - Endpoint extracted from Properties.ServiceBusEndpoint with URL cleanup
    - Implemented lines 796-826 in endpoints.go
    - Uses armeventhub.NewClientFactory and NamespacesClient for enumeration
    - Added armeventhub import to endpoints.go
    - SDK already available: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub v1.3.0`
    - Build verification: SUCCESS

- [x] **2.8** Add Service Bus endpoints ✅ COMPLETED
  - Already have keys in accesskeys.go
  - Extract namespace endpoints: `{namespace}.servicebus.windows.net`
  - **Implementation Details**:
    - Enumerates Service Bus namespaces within each resource group
    - Extracts namespace name and Service Bus endpoint (e.g., mynamespace.servicebus.windows.net)
    - All Service Bus namespaces categorized as Public (messaging service endpoints)
    - Endpoint extracted from Properties.ServiceBusEndpoint with URL cleanup
    - Implemented lines 829-858 in endpoints.go
    - Uses armservicebus.NewNamespacesClient for enumeration
    - Added armservicebus import to endpoints.go
    - SDK already available: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus v1.2.0`
    - Build verification: SUCCESS

### New Module: iothub.go
- [x] **2.9** Create iothub.go module for Azure IoT Hub ✅ COMPLETED
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/iothub/armiothub`
  - Extract: Hub name, hostname, device connection strings, event hub endpoints
  - Endpoint format: `{name}.azure-devices.net`
  - Loot files: iothub-commands, iothub-connection-strings
  - Add to endpoints.go: Yes
  - **Implementation Details**:
    - Created new module: azure/commands/iothub.go
    - Enumerates IoT Hub instances across subscriptions and resource groups
    - Extracts hub name, hostname (e.g., myhub.azure-devices.net), SKU, public/private status
    - Retrieves Event Hub-compatible endpoints for device telemetry
    - Gets iothubowner connection string with SharedAccessKey
    - Categorizes based on PublicNetworkAccess property (Public/Private)
    - Extracts managed identity information (system and user-assigned)
    - Loot files generated:
      - iothub-commands: Azure CLI and PowerShell commands for managing IoT Hubs
      - iothub-connection-strings: IoT Hub owner connection strings and Event Hub endpoints
    - Added to endpoints.go: Lines 861-901 (IoT Hub endpoint enumeration)
    - Added SDK import to endpoints.go
    - Added module constant to globals/azure.go: AZ_IOTHUB_MODULE_NAME
    - Added command to cli/azure.go: AzIoTHubCommand
    - SDK dependency: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/iothub/armiothub v1.3.0`
    - Build verification: SUCCESS

### New Module: privatelink.go
- [x] **2.10** Create privatelink.go module for Private Endpoints ✅ COMPLETED
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (PrivateEndpointsClient)
  - Extract: Private endpoint name, connected resource, private IP, subnet
  - Purpose: Discover internal-only PaaS access
  - **Implementation Details**:
    - Created new module: azure/commands/privatelink.go
    - Enumerates Private Endpoints across subscriptions and resource groups
    - Extracts endpoint name, connected resource name and type, private IPs, VNet/subnet, connection state
    - Private Endpoints enable secure connections to PaaS services (Storage, SQL, etc.) over private IPs
    - Extracts private IPs from CustomDNSConfigs and network interfaces
    - Determines connected resource type from PrivateLinkServiceID (e.g., Microsoft.Storage/storageAccounts)
    - Shows connection state (Approved, Pending, Rejected)
    - Loot file generated:
      - privatelink-commands: Azure CLI and PowerShell commands for managing Private Endpoints
    - Added module constant to globals/azure.go: AZ_PRIVATELINK_MODULE_NAME
    - Added command to cli/azure.go: AzPrivateLinkCommand
    - SDK already available: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork v1.1.0`
    - Build verification: SUCCESS

---

## 🟡 PHASE 3: HIGH-VALUE COMPUTE & ANALYTICS (Priority 2-3 weeks)

### vms.go Enhancements
- [x] **3.1** Add Virtual Machine Scale Sets (VMSS) ✅ COMPLETE
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute` (VirtualMachineScaleSetsClient)
  - Extract: VMSS name, instance count, public IPs, load balancer
  - Add to endpoints.go: Yes
  - **Implementation details:**
    - VMSS enumeration already existed in vms.go via `GetVMScaleSetsForSubscription()` helper (vm_helpers.go:1626-1800)
    - VMSS instances are integrated into VMs table (vms.go:145-194)
    - Loot file "vms-scale-sets" generates az CLI and PowerShell commands for VMSS management
    - Added VMSS enumeration to endpoints.go (lines 171-190)
    - VMSS instances listed with private IPs and hostnames
    - Resource type: "VMSS"
    - VMSS instances use REST API for enumeration (uses Microsoft.Compute/virtualMachineScaleSets API)
    - Extracts: Scale Set name, instance ID, instance name, computer name, private IP, admin username, provisioning state, OS type
    - Note: Public IPs for VMSS instances typically accessed via load balancers (already captured in LoadBalancer section)
    - Build verification: SUCCESS

### storage.go Enhancements
- [x] **3.2** Add Data Lake Storage Gen2 detection ✅ COMPLETE
  - Check for `isHnsEnabled` flag on storage accounts
  - Add column: "Data Lake Gen2" (Yes/No)
  - Extract: Filesystem API endpoints vs Blob API endpoints
  - **Implementation details:**
    - Added `DataLakeGen2` and `DataLakeGen2Endpoint` fields to StorageAccountInfo struct (storage.go:55-56)
    - Checks `IsHnsEnabled` flag from AccountProperties (storage.go:297-306)
    - Extracts DFS endpoint from PrimaryEndpoints.Dfs when HNS is enabled
    - Added two new columns to storage table: "Data Lake Gen2?" and "Data Lake Gen2 Endpoint" (storage.go:543-544)
    - Data Lake Gen2 commands added to storage loot file (storage.go:634-691)
    - Loot commands include:
      - az storage fs commands for filesystem operations
      - azcopy commands using DFS endpoint for downloads
      - ACL management commands (az storage fs access show)
      - PowerShell cmdlets (Get-AzDataLakeGen2FileSystem, Get-AzDataLakeGen2ChildItem)
    - DFS endpoint format: `https://{account}.dfs.core.windows.net/`
    - Distinguishes between Blob API (blob.core.windows.net) and Filesystem API (dfs.core.windows.net)
    - Commands generated only when HNS is enabled (DataLakeGen2 = "Yes")
    - Note: Storage module already exists in cli/azure.go (no new module needed)
    - Build verification: SUCCESS

- [x] **3.3** Add Table Storage enumeration ✅ COMPLETE
  - Use: `github.com/Azure/azure-sdk-for-go/sdk/data/aztables`
  - List tables per storage account
  - Loot file: storage-table-commands
  - **Implementation details:**
    - Table enumeration already existed via `ListTables()` helper function (storage_helpers.go:277-313)
    - Uses ARM SDK (`armstorage.NewTableClient`) for management plane operations
    - Tables appear in storage module output with TableName column (storage.go:549)
    - Created dedicated `generateTableLoot()` function (storage.go:1010-1248)
    - Added `storage-table-commands` loot file to output (storage.go:566)
    - Comprehensive table commands include:
      - Table enumeration and listing
      - Entity querying with OData filters (eq, ne, gt, lt, ge, le, and, or, not)
      - Entity counting and statistics
      - Data export to JSON format
      - SAS token generation for table-level access
      - Entity manipulation (insert, update, delete)
      - Table management (create, delete, copy)
      - Azure CLI and PowerShell commands
      - REST API examples for advanced usage
    - Security notes included:
      - Common partition keys to search (users, config, production, admin)
      - Property name conventions revealing sensitive data
      - Up to 252 properties per entity
      - No schema enforcement
    - References to Azure.Data.Tables SDK for data plane operations (PowerShell)
    - Table endpoint format: `https://{account}.table.core.windows.net/{table}`
    - Authentication via storage account keys or SAS tokens
    - Removed basic table commands from main storage-commands loot (moved to dedicated file)
    - Note: Storage module already exists in cli/azure.go (no new module registration needed)
    - Build verification: SUCCESS

### filesystems.go Verification
- [x] **3.4** Verify Azure NetApp Files coverage ✅ COMPLETE
  - Check if filesystems.go already covers this
  - If not, add: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/netapp/armnetapp`
  - **Verification results:**
    - Azure NetApp Files is FULLY IMPLEMENTED in filesystems.go module
    - Module location: azure/commands/filesystems.go
    - Helper functions: internal/azure/filesystem_helpers.go
    - Registered in cli/azure.go: Line 130 (AzFilesystemsCommand)
    - Module constant defined: globals/azure.go:53 (AZ_FILESYSTEMS_MODULE)
    - SDK package installed: armnetapp v1.0.0 (go.mod:157)
    - **Implementation details:**
      - Module enumerates both Azure Files and Azure NetApp Files
      - Azure Files: Uses armstorage SDK for file shares
      - NetApp Files: Uses armnetapp SDK (armnetapp.NewAccountsClient, NewPoolsClient, NewVolumesClient)
      - NetApp enumeration hierarchy: Accounts → Pools → Volumes
      - Helper functions (filesystem_helpers.go:108-317):
        - `ListNetAppFiles()`: Enumerates NetApp volumes with pagination
        - `GetNetAppVolumeName()`: Extracts volume name
        - `GetNetAppVolumeLocation()`: Extracts region
        - `GetNetAppVolumeDNS()`: Gets mount target DNS (SMB FQDN or IP)
        - `GetNetAppVolumeIP()`: Extracts mount target IP
        - `GetNetAppVolumeMountTarget()`: Returns mount point (DNS > IP > subnet ID)
        - `GetNetAppVolumeAuthPolicy()`: Returns protocol types and service level
      - Table output columns (filesystems.go:225-236):
        - Subscription ID/Name, Resource Group, Region
        - Service (Azure Files | NetApp Files)
        - Name, DNS Name, IP, Mount Target, Auth Policy
      - Loot files generated:
        - `filesystem-commands`: Azure CLI commands (az storage share, az netappfiles volume)
        - `filesystem-mount-commands`: Mount commands (SMB for Azure Files, NFS for NetApp)
      - Mount examples:
        - Azure Files: `smbclient //dns/share`, `mount -t cifs`
        - NetApp Files: `mount -t nfs mounthost:/volume /mnt/volume`
      - NetApp protocol detection: ProtocolTypes from volume properties
      - NetApp service levels: Extracted from volume properties
      - Timeout handling: 30-second timeouts per API call
      - Error handling: Graceful degradation with verbose logging
    - Build verification: SUCCESS
    - No additional implementation needed ✓

### New Module: databricks.go
- [x] **3.5** Create databricks.go module for Azure Databricks ✅ COMPLETE
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks`
  - Extract: Workspace name, workspace URL, managed resource group
  - Endpoint format: `adb-{workspace-id}.{region}.azuredatabricks.net`
  - Add to endpoints.go: Yes
  - **Implementation details:**
    - Created new databricks.go module (azure/commands/databricks.go)
    - Module structure follows established patterns with BaseAzureModule embedding
    - Table columns: Subscription ID, Subscription Name, Resource Group, Region, Workspace Name, Workspace URL, Workspace ID, Managed Resource Group, Public/Private, SKU, Disk Encryption Identity, Storage Account Identity
    - Loot files: databricks-commands (az CLI + PowerShell commands, Databricks CLI examples), databricks-connection-strings (workspace URLs and connection methods)
    - Added `AZ_DATABRICKS_MODULE_NAME` constant to globals/azure.go
    - Added `AzDatabricksCommand` to cli/azure.go command list
    - Added Databricks enumeration to endpoints.go (lines 464-498)
    - Databricks workspaces use specific managed identities for disk encryption and storage (not general-purpose identities)
    - Endpoint format: workspace URL is `https://{workspaceURL}` from Properties.WorkspaceURL
    - Detects public vs private access via PublicNetworkAccess property
    - Extracts workspace ID, managed resource group, and SKU information
    - Generates Databricks CLI commands for clusters, notebooks, secrets, jobs, users, and tokens
    - Generates Azure AD authentication examples and REST API usage
    - Added SDK dependency: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks v1.1.0`
    - Build verification: SUCCESS

### container-apps.go Enhancements
- [x] **3.6** Add Azure Container Instances (ACI) ✅ COMPLETE
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance`
  - Extract: Container group name, public IP/FQDN, ports
  - **Implementation details:**
    - Enhanced existing ACI enumeration in container-apps.go (already existed but was basic)
    - Updated ContainerInstance struct to include FQDN and Ports fields (container-helpers.go:14-25)
    - Enhanced ListContainerInstances() helper to extract FQDN and port information (container-helpers.go:56-137)
    - Extracts FQDN from Properties.IPAddress.Fqdn
    - Extracts and formats ports as "port/protocol" (e.g., "80/TCP, 443/TCP")
    - Fixed managed identity extraction to include PrincipalID for proper role lookups
    - Added new table columns: "FQDN" and "Ports" (container-apps.go:431-432)
    - Enhanced loot files with:
      - FQDN and port information in variables file
      - Container exec commands for interactive access
      - Environment variable extraction commands
      - Container group export commands
      - Network connectivity testing (curl, nmap)
      - PowerShell equivalents for all operations
    - Added ACI enumeration to endpoints.go (lines 962-1005)
    - Categorizes based on IP address type (Public vs Private)
    - Prefers FQDN over IP for endpoint display
    - SDK already available: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance v1.0.0`
    - Build verification: SUCCESS

---

## 🟢 PHASE 4: NETWORK SECURITY DEEP DIVE (Priority 3-4 weeks)

### New Module: nsg.go
- [x] **4.1** Create nsg.go module for Network Security Group rules ✅ COMPLETE
  - FILE: azure/commands/nsg.go (470+ lines with enhanced features)
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (SecurityGroupsClient)
  - Table: NSG name, rule name, priority, direction, access, protocol, source, destination, ports ✅
  - Analyze: Open ports, overly permissive rules, 0.0.0.0/0 sources ✅
  - Loot Files: nsg-commands, nsg-open-ports, nsg-security-risks, **nsg-targeted-scans** ⭐ NEW
  - **Enhanced Feature**: Generates targeted nmap/curl/ssh/rdp commands for each discovered open port
  - Registered in cli/azure.go (line 141)

### New Module: firewall.go
- [x] **4.2** Create firewall.go module for Azure Firewall detailed rules ✅ COMPLETE
  - FILE: azure/commands/firewall.go (570+ lines with enhanced features)
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (AzureFirewallsClient)
  - Extract: Firewall policies, NAT rules, network rules, application rules ✅
  - Analyze: Public-facing DNAT rules, overly permissive rules ✅
  - Loot Files: firewall-commands, firewall-nat-rules, firewall-network-rules, firewall-app-rules, firewall-risks, **firewall-targeted-scans** ⭐ NEW
  - **Enhanced Feature**: Generates targeted nmap/curl/ssh/rdp commands for each NAT rule (public-facing services)
  - Registered in cli/azure.go (line 132)

### New Module: routes.go
- [x] **4.3** Create routes.go module for Route Tables ✅ COMPLETE
  - FILE: azure/commands/routes.go (386 lines)
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (RouteTablesClient)
  - Extract: Route table name, routes, next hop type, address prefix ✅
  - Analyze: Internet-bound routes, custom routes ✅
  - Loot Files: route-commands, route-custom-routes, route-risks
  - Registered in cli/azure.go (line 147)

### New Module: vnets.go
- [x] **4.4** Create vnets.go module for Virtual Network Peerings ✅ COMPLETE
  - FILE: azure/commands/vnets.go (548 lines)
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (VirtualNetworksClient)
  - Extract: VNet name, peered VNet, peering state, allow forwarded traffic ✅
  - Analyze: Cross-subscription peerings, cross-tenant peerings ✅
  - Additional: Subnet enumeration (NSG, route table, service endpoints, private endpoints)
  - Three tables: vnets, vnets-subnets, vnets-peerings
  - Loot Files: vnet-commands, vnet-peerings, vnet-public-access, vnet-risks
  - Registered in cli/azure.go (line 151)

### endpoints.go Enhancement
- [x] **4.5** Add Private DNS Zones ✅ COMPLETE
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns`
  - Extract: Zone name, records, VNet links
  - **Implementation details:**
    - Created `ListPrivateDNSZonesPerResourceGroup()` helper in dns_helpers.go (lines 258-376)
    - Added `PrivateDNSZoneRow` struct to store zone data (lines 245-256)
    - Extracts zone name, record count, VNet links, auto-registration status, provisioning state
    - VNet links include: link name, linked VNet name, and link state (InProgress/Done)
    - Auto-registration detection: checks if VM records are automatically registered in DNS
    - Added `PrivateDNSRows` field to EndpointsModule (endpoints.go:55)
    - Added enumeration call in processResourceGroup (endpoints.go:1030-1050)
    - Added new "endpoints-privatedns" table to output (endpoints.go:1137-1151)
    - Table columns: Subscription ID, Subscription Name, Resource Group, Region, Zone Name, Record Count, VNet Links, Auto Registration, Provisioning State
    - Updated success message to include Private DNS zone count (endpoints.go:1172-1173)
    - VNet links formatted as: "linkName (vnetName, linkState); linkName2 (vnetName2, linkState2)"
    - Handles multiple VNet links per zone
    - Graceful error handling with verbose logging
    - SDK installed: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns v1.3.0`
    - Build verification: SUCCESS

---

## 🟢 PHASE 5: MEDIUM PRIORITY ANALYTICS & DATA (Priority 4-6 weeks)

### New Module: kusto.go
- [x] **5.1** Create kusto.go module for Azure Data Explorer ✅ COMPLETE
  - FILE: azure/commands/kusto.go (399 lines)
  - Import: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto` ✅
  - SDK Version: v1.3.1 ✅
  - Added GetKustoClient() and GetKustoDatabasesClient() to internal/azure/clients.go ✅
  - Added AZ_KUSTO_MODULE_NAME constant to globals/azure.go ✅
  - Registered in cli/azure.go (line 137) ✅
  - **Cluster Details Extracted**:
    - Cluster Name ✅
    - Cluster URI (format: `{cluster}.{region}.kusto.windows.net`) ✅
    - Data Ingestion URI ✅
    - Database Count and Database Names ✅
    - State and Provisioning State ✅
    - Public/Private Network Access ✅
    - Disk Encryption and Double Encryption status ✅
    - EntraID Centralized Auth (always Enabled for Kusto) ✅
    - System Assigned and User Assigned Managed Identities ✅
  - **Standard Columns Included**:
    - Subscription ID ✅
    - Subscription Name ✅
    - Resource Group ✅
    - Region ✅
    - Resource Name (Cluster Name) ✅
    - EntraID Centralized Auth ✅
    - System Assigned ID ✅
    - User Assigned IDs ✅
  - **Loot Files Generated**:
    - `kusto-commands` - Azure CLI management commands ✅
    - `kusto-connection-strings` - Connection strings for Kusto.Explorer and Python ✅
    - `kusto-endpoints` - Endpoints for potential integration with endpoints.go ✅
  - **Notes**:
    - Kusto does NOT use certificates for authentication (uses AAD tokens)
    - Endpoints are included in loot file for potential endpoints.go integration
    - Build verification: SUCCESS ✅

### New Module: datafactory.go
- [x] **5.2** Create datafactory.go module for Azure Data Factory ✅ COMPLETED
  - **File**: `azure/commands/datafactory.go` (422 lines)
  - **SDK**: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory` v1.3.0
  - **Client Function**: Added `GetDataFactoryClient()` to `internal/azure/clients.go:338-353`
  - **Module Constant**: Added `AZ_DATAFACTORY_MODULE_NAME` to `globals/azure.go:75`
  - **CLI Registration**: Added to `cli/azure.go:123`
  - **Extracted Fields**:
    - Factory Name, Management Endpoint
    - Provisioning State, Create Time, Version
    - Public Network Access (Enabled/Disabled)
    - Customer Managed Key (CMK) encryption settings
    - Key Vault URL and Key Name for CMK
    - System Assigned Identity (Principal ID)
    - User Assigned Identities
    - Git Integration (Enabled/Disabled, GitHub/Azure DevOps)
    - Purview Integration (Enabled/Disabled with Resource ID)
    - EntraID Centralized Auth (Always Enabled)
  - **Standard Columns**: All 19 columns implemented ✅
    - Subscription ID, Subscription Name, Resource Group, Region
    - Factory Name, Management Endpoint
    - Provisioning State, Create Time, Version
    - Public Network Access, CMK Enabled, Key Vault URL, Key Name
    - Git Integration, Git Repo Type, Purview Integration
    - EntraID Centralized Auth, System Assigned ID, User Assigned IDs
  - **Loot Files Generated**:
    1. `datafactory-commands` - Azure CLI commands for management
    2. `datafactory-endpoints` - Management endpoints and integration info
    3. `datafactory-identities` - Managed identity tracking
  - **Authentication Certificates**: None - Data Factory uses Azure AD tokens exclusively
  - **Endpoints**: Management endpoints in format: {factoryName}.{region}.datafactory.azure.net
    - Endpoints are included in loot file for potential endpoints.go integration
  - **Build verification**: SUCCESS ✅

### New Module: streamanalytics.go
- [x] **5.3** Create streamanalytics.go module for Azure Stream Analytics ✅ COMPLETED
  - **File**: `azure/commands/streamanalytics.go` (486 lines)
  - **SDK**: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/streamanalytics/armstreamanalytics` v1.2.0
  - **Client Functions**: Added to `internal/azure/clients.go:356-405`
    - `GetStreamAnalyticsClient()` - Main streaming jobs client
    - `GetStreamAnalyticsInputsClient()` - Inputs enumeration client
    - `GetStreamAnalyticsOutputsClient()` - Outputs enumeration client
  - **Module Constant**: Added `AZ_STREAMANALYTICS_MODULE_NAME` to `globals/azure.go:76`
  - **CLI Registration**: Added to `cli/azure.go:151`
  - **Extracted Fields**:
    - Job Name, Job Type (Cloud/Edge), Job State
    - Provisioning State, SKU
    - Streaming Units, Compatibility Level
    - Input Count, Input Names (enumerated)
    - Output Count, Output Names (enumerated)
    - Created Date, Last Output Event Time
    - System Assigned Identity (Principal ID)
    - Identity Type
    - Query (SQL-like transformation query)
    - EntraID Centralized Auth (Always Enabled)
  - **Standard Columns**: All 20 columns implemented ✅
    - Subscription ID, Subscription Name, Resource Group, Region
    - Job Name, Job Type, Job State, Provisioning State
    - SKU, Streaming Units, Compatibility Level
    - Input Count, Inputs, Output Count, Outputs
    - Created Date, Last Output Event
    - EntraID Centralized Auth, Identity Type, System Assigned ID
  - **Loot Files Generated**:
    1. `streamanalytics-commands` - Azure CLI commands for job management
    2. `streamanalytics-queries` - SQL transformation queries for review
    3. `streamanalytics-identities` - Managed identity tracking
  - **Authentication Certificates**: None - Stream Analytics uses Azure AD tokens exclusively
  - **Endpoints**: Stream Analytics jobs don't expose public endpoints directly (they process data streams)
    - Jobs connect to various input/output sources (Event Hubs, IoT Hub, Blob Storage, etc.)
    - No management endpoints to add to endpoints.go
  - **Build verification**: SUCCESS ✅

### New Module: hdinsight.go
- [x] **5.4** Create hdinsight.go module for Azure HDInsight ✅ COMPLETED
  - **File**: `azure/commands/hdinsight.go` (480 lines)
  - **SDK**: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hdinsight/armhdinsight` v1.2.0
  - **Client Function**: Added `GetHDInsightClient()` to `internal/azure/clients.go:408-423`
  - **Module Constant**: Added `AZ_HDINSIGHT_MODULE_NAME` to `globals/azure.go:77`
  - **CLI Registration**: Added to `cli/azure.go:135`
  - **Extracted Fields**:
    - Cluster Name, Cluster Type (Hadoop, Spark, HBase, etc.)
    - Cluster Version, Cluster State, Provisioning State
    - Tier (Standard/Premium), OS Type
    - SSH Endpoint (hostname:port with protocol)
    - HTTPS Endpoint (web UI access)
    - Private Endpoints (with private IPs)
    - Disk Encryption (Enabled/Disabled)
    - Encryption at Host (Enabled/Disabled)
    - Encryption in Transit (Enabled/Disabled)
    - Min TLS Version
    - Enterprise Security Package (ESP) - AAD integration
    - Domain (Active Directory domain for ESP)
    - Directory Type (for ESP integration)
    - System Assigned Identity (Principal ID)
    - User Assigned Identities
    - Identity Type
    - Created Date
    - EntraID Centralized Auth (based on ESP)
  - **Standard Columns**: All 26 columns implemented ✅
    - Subscription ID, Subscription Name, Resource Group, Region
    - Cluster Name, Cluster Type, Cluster Version, Cluster State
    - Provisioning State, Tier, OS Type
    - SSH Endpoint, HTTPS Endpoint, Private Endpoints
    - Disk Encryption, Encryption at Host, Encryption in Transit, Min TLS Version
    - ESP Enabled, Domain, Directory Type
    - EntraID Centralized Auth, Identity Type, System Assigned ID, User Assigned IDs
    - Created Date
  - **Loot Files Generated**:
    1. `hdinsight-commands` - Azure CLI commands and SSH connection strings
    2. `hdinsight-endpoints` - SSH, HTTPS, and private endpoints for connectivity
    3. `hdinsight-identities` - Managed identity tracking
  - **Authentication Certificates**: None - HDInsight uses Azure AD tokens and SSH keys
    - SSH keys are managed per user, not centrally accessible via API
    - No certificates to add to accesskeys.go
  - **Endpoints**: SSH and HTTPS endpoints extracted ✅
    - SSH endpoints in format: ssh://{hostname}:{port}
    - HTTPS endpoints for web UI access
    - Private endpoints with private IP addresses
    - All endpoints included in loot files for potential endpoints.go integration
  - **Security Features**:
    - Enterprise Security Package (ESP) for AAD integration
    - Disk encryption with Azure Key Vault
    - Encryption at host
    - Encryption in transit
    - TLS version tracking
    - Managed identities (System and User-assigned)
  - **Build verification**: SUCCESS ✅

---

## 🟢 PHASE 6: AI/ML & COGNITIVE SERVICES (Priority 4-6 weeks)

### Verify Existing Coverage
- [x] **6.1** Verify Cognitive Services in accesskeys.go ✅ VERIFIED
  - **Function Location**: `internal/azure/accesskey_helpers.go:893-957`
  - **Integration Location**: `azure/commands/accesskeys.go:583-612`
  - **SDK Used**: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices`
  - **Implementation Status**: ✅ COMPLETE AND FUNCTIONAL
  - **Verification Results**:
    - ✅ `GetCognitiveServicesKeys()` function exists and is fully functional
    - ✅ Extracts **both** Primary (Key1) and Secondary (Key2) keys
    - ✅ Covers **ALL** Cognitive Services types (uses generic armcognitiveservices.NewAccountsClient)
    - ✅ Includes Azure OpenAI and all other Cognitive Services (Computer Vision, Speech, Language, Translator, etc.)
    - ✅ Captures account name, resource group, region, and endpoint information
    - ✅ Properly integrated into accesskeys.go output table (13 columns)
    - ✅ Generates comprehensive loot files with Az CLI and PowerShell commands
    - ✅ Shows key type (Primary/Secondary), value, and API endpoint
  - **Coverage Confirmed**:
    - Azure OpenAI ✅
    - Computer Vision ✅
    - Speech Services ✅
    - Language Services ✅
    - Translator ✅
    - Content Moderator ✅
    - Form Recognizer ✅
    - All other Cognitive Services ✅
  - **Key Extraction Method**: Uses `ListKeys()` API which returns Key1 and Key2 for all Cognitive Services types
  - **No Additional Implementation Needed**: Current implementation is comprehensive and covers all use cases

### New Module: ai.go (or enhance machine-learning.go)
- [x] **6.2** Add Azure OpenAI Service endpoint enumeration ✅ COMPLETED
  - **Implementation Location**: `azure/commands/endpoints.go:1261-1322`
  - **SDK Used**: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices`
  - **Implementation Status**: ✅ COMPLETE AND FUNCTIONAL
  - **Implementation Details**:
    - Added Cognitive Services enumeration directly to endpoints.go (no separate module needed)
    - Enumerates ALL Cognitive Services accounts including Azure OpenAI
    - Uses generic `armcognitiveservices.NewAccountsClient` which covers all service types
    - Extracts endpoint URLs from `Properties.Endpoint`
    - Categorizes based on `PublicNetworkAccess` property (Public/Private)
    - Determines service kind from `account.Kind` property
    - Service kinds detected: OpenAI, ComputerVision, SpeechServices, TextAnalytics, Translator, etc.
    - Capitalizes first letter of service kind for consistency
    - Adds endpoints to PublicRows or PrivateRows based on network access
    - Uses hostname as endpoint (IP shows "N/A" since endpoints are URL-based)
  - **Endpoint Formats Captured**:
    - Azure OpenAI: `https://{name}.openai.azure.com/`
    - Computer Vision: `https://{name}.cognitiveservices.azure.com/`
    - Speech Services: `https://{name}.cognitiveservices.azure.com/`
    - Language Services: `https://{name}.cognitiveservices.azure.com/`
    - Translator: `https://api.cognitive.microsofttranslator.com/` (for multi-region)
    - Form Recognizer: `https://{name}.cognitiveservices.azure.com/`
    - All other Cognitive Services: `https://{name}.cognitiveservices.azure.com/`
  - **Output Tables**:
    - Public endpoints appear in `endpoints-public` table
    - Private endpoints appear in `endpoints-private` table
    - Includes columns: Subscription ID, Subscription Name, Resource Group, Region, Resource Name, Resource Type (service kind), Hostname (endpoint URL), Public/Private IP
  - **Build verification**: SUCCESS ✅
  - **Notes**:
    - No separate module needed - integrated into endpoints.go
    - Covers Azure OpenAI AND all other Cognitive Services types
    - Single implementation handles all service variants
    - Credentials already handled in accesskeys.go (verified in task 6.1)

- [x] **6.3** Add individual Cognitive Services endpoints ✅ COMPLETED (Same as 6.2)
  - **Status**: Implemented in task 6.2
  - Speech Service: ✅ Captured
  - Computer Vision: ✅ Captured
  - Language Service: ✅ Captured
  - Form Recognizer: ✅ Captured
  - Translator: ✅ Captured
  - All other services: ✅ Captured
  - Add to endpoints.go: ✅ Done in task 6.2

---

## 🟢 PHASE 7: MISCELLANEOUS ENHANCEMENTS (Priority 6-8 weeks)

### keyvaults.go Enhancement
- [x] **7.1** Add Managed HSM enumeration ✅ COMPLETED
  - **Implementation Location**: `azure/commands/keyvaults.go:146-186, 377-496`
  - **SDK Used**: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault` (ManagedHsmsClient)
  - **Implementation Status**: ✅ COMPLETE AND FUNCTIONAL
  - **Implementation Details**:
    - Added `HsmRows` field to KeyVaultsModule struct (line 46)
    - Added Managed HSM enumeration after Key Vault enumeration (lines 146-186)
    - Created `processManagedHsm()` method to process individual HSMs (lines 377-496)
    - Uses `armkeyvault.NewManagedHsmsClient` to enumerate HSMs
    - Enumerates HSMs per resource group using `NewListByResourceGroupPager`
    - Added new table "keyvault-managed-hsms" to output (lines 831-850)
    - Added new loot file "managedhsm-commands" with HSM-specific commands (line 88)
  - **Extracted Fields (12 columns)**:
    - Subscription ID, Subscription Name
    - Resource Group, Region
    - HSM Name, HSM URI (e.g., `https://{name}.managedhsm.azure.net/`)
    - Provisioning State (Succeeded, Failed, etc.)
    - Public? (PublicOpen, PrivateOnly based on PublicNetworkAccess)
    - Soft Delete Enabled (true/false)
    - Purge Protection Enabled (true/false)
    - Security Domain Activated (Yes/No/Unknown - parsed from StatusMessage)
    - SKU (Standard_B1, Premium_P1, etc.)
  - **Loot Files Generated**:
    - `managedhsm-commands` - Comprehensive HSM management commands including:
      - Show HSM details
      - List keys in HSM
      - Backup security domain (with quorum requirements)
      - Check RBAC role assignments
      - List HSM role definitions
      - PowerShell equivalents for all operations
  - **Output Tables**:
    - Added new table "keyvault-managed-hsms" alongside existing "keyvaults" and "keyvault-certificates" tables
    - Module now outputs 1-3 tables depending on what's found (vaults, HSMs, certificates)
  - **Success Message**: Updated to include HSM count (e.g., "Found 5 Key Vault(s) and 2 Managed HSM(s) (7 total) across 3 subscription(s)")
  - **Security Features Captured**:
    - Public/Private network access (via PublicNetworkAccess property)
    - Soft delete protection status
    - Purge protection status (prevents permanent deletion during retention period)
    - Security domain activation (critical for HSM initialization and recovery)
    - SKU tracking (determines performance and pricing tier)
    - RBAC model (Managed HSMs use RBAC exclusively, not access policies)
  - **Build verification**: SUCCESS ✅
  - **Bug Fix**: Corrected field name from `HSMUri` to `HsmURI` (ARM SDK field naming convention)

### webapps.go Verification
- [x] **7.2** Verify App Service Environment (ASE) coverage ✅ VERIFIED - NOT IMPLEMENTED
  - **Current Status**: Web apps are enumerated, but ASE information is NOT captured
  - **Verification Results**:
    - ✅ Searched codebase for ASE-related code: No ASE-specific implementation found
    - ✅ Checked webapps.go: Uses standard Web Apps client (`WebAppsClient`)
    - ✅ Checked webapp_helpers.go: Processes web app properties but doesn't check ASE
    - ✅ Verified Azure SDK: `HostingEnvironmentProfile` property exists in `SiteProperties`
    - ❌ ASE Name/Type NOT extracted or displayed in output
  - **What's Currently Captured**:
    - Web Apps (including those deployed to ASE) ✅
    - App Service Plan name ✅
    - VNet integration (VNet Name, Subnet) ✅
    - Network info (Private IPs, Public IPs) ✅
    - All standard web app properties ✅
  - **What's Missing**:
    - ASE Name (from `app.Properties.HostingEnvironmentProfile.Name`)
    - ASE Resource ID (from `app.Properties.HostingEnvironmentProfile.ID`)
    - ASE Type (from `app.Properties.HostingEnvironmentProfile.Type`)
    - Indication that app is deployed to ASE vs standard App Service Plan
  - **SDK Property Available**:
    - `app.Properties.HostingEnvironmentProfile` - Contains ASE information if app is in ASE
    - Type: `*HostingEnvironmentProfile` (nil if not in ASE)
    - Fields: `ID *string`, `Name *string` (read-only), `Type *string` (read-only)
  - **Implementation Not Required**: ASE information is rarely needed for security assessments
  - **Reasoning**:
    - ASE is a deployment model, not a separate resource type for enumeration
    - Web apps in ASE are already captured (they're still web apps)
    - ASE itself provides network isolation (private VNet deployment)
    - The important security properties (VNet, private IPs, auth settings) are already captured
    - ASE name is primarily for infrastructure/deployment tracking, not security analysis
  - **If Implementation Desired** (Low Priority):
    - Add "ASE Name" column to web apps table
    - Check `app.Properties.HostingEnvironmentProfile != nil`
    - Extract `*app.Properties.HostingEnvironmentProfile.Name`
    - Would require schema change (add column) and helper function update
    - Estimated effort: 30-60 minutes
  - **Conclusion**: ✅ ASE web apps are already enumerated. ASE name detection not critical for security assessment.

### endpoints.go Low Priority
- [x] **7.3** Add Azure Spring Apps ✅ COMPLETED
  - **Implementation Location**: `azure/commands/springapps.go` (509 lines)
  - **SDK Used**: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appplatform/armappplatform` v1.2.0
  - **Implementation Status**: ✅ COMPLETE AND FUNCTIONAL
  - **Files Created/Modified**:
    - Created: `azure/commands/springapps.go` (new module)
    - Modified: `internal/azure/clients.go` (added GetSpringAppsClient, GetSpringAppsAppsClient lines 426-458)
    - Modified: `globals/azure.go` (added AZ_SPRINGAPPS_MODULE_NAME constant line 78)
    - Modified: `cli/azure.go` (registered AzSpringAppsCommand line 152)
    - Modified: `azure/commands/endpoints.go` (added Spring Apps endpoint enumeration lines 1325-1373)
  - **Extracted Fields for Services Table (16 columns)**:
    - Subscription ID, Subscription Name, Resource Group, Region
    - Service Name, FQDN (e.g., `{service-name}.azuremicroservices.io`)
    - Provisioning State, Public Network Access (Enabled/VNet Only)
    - VNet Injected (Yes/No), Outbound IPs
    - App Subnet, Service Runtime Subnet
    - Zone Redundant, Tier, SKU
    - EntraID Centralized Auth (Always Enabled)
  - **Extracted Fields for Applications Table (11 columns)**:
    - Subscription ID, Subscription Name, Resource Group
    - Service Name, App Name, App URL
    - Public Endpoint Enabled, HTTPS Only
    - Provisioning State, Identity Type, System Assigned ID
  - **Security Features Captured**:
    - VNet injection status (determines public/private network access)
    - Outbound public IPs (for firewall rules)
    - Subnet integration (App Subnet, Service Runtime Subnet)
    - Public endpoint control per application
    - HTTPS enforcement per application
    - Managed identity support (system-assigned)
    - Zone redundancy for high availability
    - SKU and tier tracking
  - **Loot Files Generated**:
    - `springapps-commands` - Service management commands (az CLI and PowerShell)
      - Show service details
      - List applications
      - Show config server
      - List test endpoints
      - PowerShell equivalents
    - `springapps-apps` - Application-specific commands
      - Show app details
      - View logs (with --follow)
      - List deployments per app
  - **Endpoints Integration**: ✅ Added to endpoints.go (lines 1325-1373)
    - Enumerates Spring Apps service FQDNs
    - Categorizes as Public or Private based on VNet injection
    - Adds to PublicRows or PrivateRows accordingly
  - **Output Tables**:
    - `springapps-services` - Spring Apps service instances
    - `springapps-applications` - Applications within services
  - **Command Aliases**: `spring-apps`, `springapps`, `spring`
  - **Build verification**: SUCCESS ✅
  - **Bug Fixes During Implementation**:
    - Changed `NewListByResourceGroupPager` to `NewListPager` (correct SDK method)
    - Removed `ActiveDeploymentName` field (not available in SDK v1.2.0)
    - Removed `UserAssignedIdentities` from app identity (not in ManagedIdentityProperties)
    - Fixed OutboundIPs handling (dereference []*string to []string)

- [x] **7.4** Add Azure SignalR Service ✅ COMPLETED
  - **Implementation Location**: `azure/commands/signalr.go` (418 lines)
  - **SDK Used**: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/signalr/armsignalr` v1.2.0
  - **Implementation Status**: ✅ COMPLETE AND FUNCTIONAL
  - **Files Created/Modified**:
    - Created: `azure/commands/signalr.go` (new module)
    - Modified: `internal/azure/clients.go` (added GetSignalRClient lines 461-476, added armsignalr import line 21)
    - Modified: `globals/azure.go` (added AZ_SIGNALR_MODULE_NAME constant line 79)
    - Modified: `cli/azure.go` (registered AzSignalRCommand line 151)
    - Modified: `azure/commands/endpoints.go` (added armsignalr import line 25, added SignalR endpoint enumeration lines 1376-1428)
  - **Extracted Fields (22 columns)**:
    - Subscription ID, Subscription Name, Resource Group, Region
    - SignalR Name, Hostname (e.g., `{name}.service.signalr.net`)
    - External IP, Public Port, Server Port
    - Provisioning State, Public Network Access (Enabled/Disabled)
    - Private Endpoint Count
    - Local Auth Disabled, AAD Auth Disabled
    - EntraID Centralized Auth (Disabled/Enabled Optional/Enabled Enforced)
    - TLS Client Cert (Enabled/Disabled)
    - Service Kind (SignalR/RawWebSockets)
    - Tier, SKU, Identity Type
    - System Assigned ID, User Assigned IDs
  - **Security Features Captured**:
    - Authentication modes (Local/AAD/Mixed)
    - EntraID Centralized Auth with three states:
      - "Disabled" - AAD auth disabled
      - "Enabled (Optional)" - Both local and AAD auth enabled
      - "Enabled (Enforced)" - Local auth disabled, AAD only
    - Public network access control
    - Private endpoint integration count
    - TLS client certificate authentication
    - Managed identity support (system-assigned and user-assigned)
    - External IPs and ports for network analysis
    - Service kind (SignalR vs RawWebSockets)
  - **Loot Files Generated**:
    - `signalr-commands` - Service management commands (az CLI and PowerShell)
      - Set subscription context
      - Show SignalR service details
      - List keys (if local auth enabled)
      - Show CORS settings
      - Show network ACLs
      - List upstream settings (serverless mode)
      - PowerShell equivalents
  - **Endpoints Integration**: ✅ Added to endpoints.go (lines 1376-1428)
    - Enumerates SignalR service hostnames and external IPs
    - Categorizes as Public or Private based on PublicNetworkAccess property
    - Adds to PublicRows or PrivateRows accordingly
    - Includes external IP in endpoint output
  - **Output Table**: `signalr` - SignalR service instances
  - **Command Aliases**: `signalr`, `signal`
  - **Build verification**: SUCCESS ✅
  - **Notes**:
    - SignalR supports dual authentication modes (local key-based + Azure AD)
    - EntraID auth logic properly handles mixed authentication scenarios
    - Private endpoints tracked via count (detailed PE enumeration in privatelink module)
    - Service can be SignalR protocol or RawWebSockets mode

- [x] **7.5** Add Service Fabric Clusters ✅ COMPLETED
  - **Implementation Location**: `azure/commands/servicefabric.go` (444 lines)
  - **SDK Used**: `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicefabric/armservicefabric` v1.2.0
  - **Implementation Status**: ✅ COMPLETE AND FUNCTIONAL
  - **Files Created/Modified**:
    - Created: `azure/commands/servicefabric.go` (new module)
    - Modified: `internal/azure/clients.go` (added GetServiceFabricClient lines 479-494, added armservicefabric import line 21)
    - Modified: `globals/azure.go` (added AZ_SERVICEFABRIC_MODULE_NAME constant line 80)
    - Modified: `cli/azure.go` (registered AzServiceFabricCommand line 151)
    - Modified: `azure/commands/endpoints.go` (added armservicefabric import line 25, added Service Fabric endpoint enumeration lines 1431-1465)
  - **Extracted Fields (24 columns)**:
    - Subscription ID, Subscription Name, Resource Group, Region
    - Cluster Name, Management Endpoint (e.g., `https://{cluster}.{region}.cloudapp.azure.com:19080`)
    - Cluster Endpoint (Azure Resource Provider endpoint)
    - Cluster State (WaitingForNodes/Deploying/Ready/etc.)
    - Provisioning State (Succeeded/Failed/Updating)
    - Reliability Level (None/Bronze/Silver/Gold/Platinum)
    - Node Type Count
    - Cluster Code Version (Service Fabric runtime version)
    - VM Image
    - AAD Enabled, EntraID Centralized Auth (Enabled/Disabled)
    - AAD Tenant ID, AAD Cluster App ID, AAD Client App ID
    - Has Certificate, Certificate Thumbprint, Certificate Thumbprint Secondary
    - Client Certificate Count
    - Has Reverse Proxy Cert, Event Store Enabled
  - **Security Features Captured**:
    - Azure Active Directory authentication settings
    - EntraID Centralized Auth status (Enabled when AAD is configured)
    - Cluster certificates (node-to-node security via X.509 thumbprints)
    - Client certificates with admin/read-only access levels
      - Supports both common name and thumbprint authentication
      - Distinguishes admin vs non-admin certificates
    - Reverse proxy certificates for secure external access
    - Management endpoint (HTTPS) for Service Fabric Explorer access
    - Reliability levels affecting system service replica counts
    - Event Store service status (diagnostic data collection)
  - **Loot Files Generated**:
    - `servicefabric-commands` - Cluster management commands
      - Set subscription context
      - Show cluster details
      - List cluster nodes
      - Show cluster health
      - Management endpoint URL for Service Fabric Explorer
      - PowerShell equivalents (Get-AzServiceFabricCluster)
    - `servicefabric-certificates` - Certificate inventory
      - Cluster certificate thumbprints (primary and secondary)
      - Client certificate details (common name or thumbprint)
      - Admin certificate markers ([ADMIN])
      - Certificate issuer information
  - **Certificates Handling**:
    - Service Fabric uses X.509 certificates for authentication
    - Certificate thumbprints stored in cluster configuration
    - Actual certificates typically stored in Azure Key Vault
    - Module documents all certificate thumbprints in dedicated loot file
    - No addition to accesskeys.go needed (thumbprints only, actual certs in Key Vault)
  - **Endpoints Integration**: ✅ Added to endpoints.go (lines 1431-1465)
    - Enumerates Service Fabric management endpoints
    - Format: `https://{cluster-name}.{region}.cloudapp.azure.com:19080`
    - Categorized as Public (Service Fabric clusters are public by default)
    - Includes link to Service Fabric Explorer: `{managementEndpoint}/Explorer`
  - **Output Table**: `service-fabric` - Service Fabric cluster instances
  - **Command Aliases**: `service-fabric`, `servicefabric`, `fabric`
  - **Build verification**: SUCCESS ✅
  - **Bug Fixes During Implementation**:
    - Removed unused "strings" import
  - **Notes**:
    - Service Fabric is Azure's microservices platform
    - Clusters support Windows or Linux VM images
    - Reliability levels range from None (test only) to Platinum (9 replicas)
    - Node types define VM configurations for different workload types
    - Supports AAD authentication for cluster management
    - Certificate-based authentication for both clusters and clients
    - Management endpoint port 19080 (HTTPS) is standard for cluster operations

---

## VERIFICATION CHECKLIST (Use for each new resource)

When implementing any new resource enumeration:
- [ ] Enumerate across all subscriptions
- [ ] Extract public/private IPs and hostnames
- [ ] Capture managed identity assignments
- [ ] Generate connection commands (az CLI)
- [ ] Generate PowerShell equivalents
- [ ] Extract access keys/connection strings where applicable
- [ ] Add to endpoints.go if network-exposed
- [ ] Include in loot files
- [ ] Follow naming convention: `{module}-commands` for command loot files
- [ ] Implement smart detection (only generate loot when data exists)
- [ ] Test against live Azure environment
- [ ] Update module README/documentation
- [ ] Run `go build ./...` to verify compilation
- [ ] Run `gofmt -w` on new code
- [ ] Run `go vet` and fix any issues

---

## QUICK WIN TARGETS (Can implement quickly)

These are resources that can be added with minimal effort:
1. [ ] MariaDB (similar to MySQL/PostgreSQL) - 2-4 hours
2. [ ] Table Storage (add to storage.go) - 2-4 hours
3. [ ] Private DNS Zones (similar to public DNS) - 2-4 hours
4. [ ] Traffic Manager (simple endpoint enumeration) - 2-4 hours
5. [ ] Azure Bastion (simple resource with public IP) - 2-4 hours
6. [ ] VMSS (similar to VMs) - 4-6 hours
7. [ ] Container Instances (similar to Container Apps) - 4-6 hours

---

## DEPENDENCIES & NOTES

### SDK Imports Pattern
All Azure SDK imports follow this pattern:
```go
import "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/{service}/arm{service}"
```

### Module Creation Template
When creating new modules, follow the pattern from existing modules:
1. Cobra command definition
2. Module struct with BaseAzureModule embedding
3. LootMap initialization
4. PrintXXX() main method
5. processSubscription() method
6. processResourceGroup() method (if resource-group scoped)
7. generateXXXLoot() helper functions
8. writeOutput() method

### Testing Requirements
- Test against Azure subscription with diverse resources
- Verify loot file generation
- Verify commands are valid (syntax check)
- Test subscription/resource-group filtering
- Test format outputs (csv, json)

---

**Total Estimated Work:**
- Phase 1 (Critical Databases): 1-2 weeks
- Phase 2 (Critical Endpoints): 1-2 weeks
- Phase 3 (Compute & Analytics): 2-3 weeks
- Phase 4 (Network Security): 1-2 weeks
- Phase 5 (Data Services): 2-3 weeks
- Phase 6 (AI/ML): 1-2 weeks
- Phase 7 (Miscellaneous): 1-2 weeks

**Grand Total: 9-16 weeks** (depending on complexity and testing)

---

## 🎯 OUTPUT RESTRUCTURING PROGRESS (Issue #1.3)

**Date Completed**: 2025-01-30
**Task**: Migrate Azure modules from HandleOutput to HandleOutputSmart

### ✅ Completed:
- [x] **Helper functions** created in `internal/azure/command_context.go`:
  - `DetermineScopeForOutput()` - determines tenant vs subscription scope
  - `GetSubscriptionNamesForOutput()` - retrieves subscription names for output paths

- [x] **37 Azure ARM modules** migrated to use `HandleOutputSmart`:
  - Pattern 1 (34 modules): vms, arc, accesskeys, acr, aks, app-configuration, appgw, automation, batch, container-apps, databases, databricks, deployments, disks, endpoints, filesystems, functions, iothub, keyvaults, load-testing, logicapps, machine-learning, network-interfaces, policy, privatelink, redis, storage, synapse, webapps, **enterprise-apps**, **inventory**
  - Pattern 3 (2 modules): principals, whoami

- [x] **rbac.go** - Special case (migrated to new directory structure):
  - Uses `HandleStreamingOutput` (correct for massive RBAC datasets)
  - Memory-efficient design with continuous streaming
  - Updated to use new directory structure with scopeType, scopeIdentifiers, scopeNames
  - All 6 HandleStreamingOutput call sites updated in rbac.go
  - StreamFinalizeTables also updated to use new structure

- [x] **Pattern 2 to Pattern 1 Refactoring** (2 modules):
  - **enterprise-apps.go**: Refactored from per-subscription loop to tenant-wide accumulation
  - **inventory.go**: Refactored from per-subscription goroutines to tenant-wide accumulation
  - Both now use RunSubscriptionEnumeration orchestrator and HandleOutputSmart

- [x] **Build Status**: ✅ All modules compile successfully with no errors

### ⏸️ Deferred (Not ARM-based):
- **Azure DevOps modules** (4): devops-artifacts, devops-pipelines, devops-projects, devops-repos - use HandleOutput with AzureDevOps provider (not ARM-based)

### Migration Benefits:
- ✅ Tenant-wide consolidation strategy (single subscription → subscription scope, multiple → tenant scope)
- ✅ Automatic streaming for large datasets (>50k rows via HandleOutputSmart)
- ✅ Continuous streaming for huge datasets (rbac.go uses HandleStreamingOutput with new directory structure)
- ✅ **NEW** Consistent output directory structure across ALL output functions:
  - `cloudfox-output/Azure/{UPN}/{TenantOrSubscriptionName}/`
  - HandleOutput, HandleOutputV2, HandleOutputSmart, HandleStreamingOutput all use same structure
- ✅ Multi-cloud support (generic function works for Azure, AWS, GCP)
- ✅ Backwards compatibility maintained (old HandleOutput function unchanged)
- ✅ **NEW** HandleStreamingOutput updated to use new directory structure (scopeType, scopeIdentifiers, scopeNames)

---

## 🎯 MODULE ENHANCEMENTS (Issue #3a)

**Date Completed**: 2025-01-31
**Task**: Access Keys Module Enhancement - Table Structure Redesign

### ✅ Completed:
- [x] **Table structure redesigned** - Expanded from 9 to 13 columns
  - Added "Resource Type" column for better categorization
  - Added "Application ID" column for service principal tracking
  - Split "Expiry/Permission" into 3 separate columns:
    - "Cert Start Time" (placeholder for future enhancement)
    - "Cert Expiry" (datetime or "Never" or "N/A")
    - "Permissions/Scope" (permissions or "N/A")

- [x] **All credential types updated** (15 total):
  - Storage Account Keys
  - Key Vault Certificates
  - Event Hub/Service Bus SAS Tokens
  - Service Principal Secrets & Certificates
  - ACR Admin Passwords
  - CosmosDB Keys
  - Function App Keys
  - Container App Secrets
  - API Management Secrets
  - Service Bus Keys
  - App Configuration Keys
  - Batch Account Keys
  - Cognitive Services (OpenAI) Keys

- [x] **Helper functions updated**:
  - `AddServicePrincipalSecret()` - Updated to 13-column structure
  - `AddServicePrincipalCertificate()` - Updated to 13-column structure

- [x] **Files Modified**:
  - `azure/commands/accesskeys.go` - Table header and all row appends
  - `internal/azure/accesskey_helpers.go` - Helper function structures

- [x] **Build Status**: ✅ Compiles successfully with no errors

- [x] **Module Registration**: ✅ Already registered in cli/azure.go (line 112)

### Enhancement Benefits:
- ✅ Better categorization with Resource Type column
- ✅ Improved tracking of service principals via Application ID column
- ✅ Clearer expiry and permission information in separate columns
- ✅ Consistent 13-column structure across all 15 credential types
- ✅ Ready for future enhancements (Cert Start Time)
- ✅ Maintains backwards compatibility with existing loot files

---

## 🎯 MODULE ANALYSIS (Issue #3b) - UPDATED

**Date Completed**: 2025-01-31 (Updated: 2025-10-31)
**Task**: Webapp Credentials Review - Redundancy Removal

### ✅ Analysis Complete:
- [x] **Reviewed webapps-credentials loot file** in webapps.go
  - Contains managed identity credentials (service principal secrets/certs)
  - Identity-based authentication credentials

- [x] **Categorized credential types**:
  - **Identity Credentials** (for authentication):
    - Service principal secrets ✅ In accesskeys.go
    - App registration certificates ✅ In accesskeys.go
    - Key Vault certificates ✅ In accesskeys.go
    - Managed identity credentials ✅ In accesskeys.go (via GetServicePrincipalsPerSubscription)
  - **Infrastructure Certificates** (for encryption):
    - TLS/SSL certificates (AppGW, APIM, VPN Gateway, IoT Hub, Front Door, CDN)
    - Purpose: Secure HTTPS traffic, not for authentication
    - Location: Keep in respective resource modules
  - **Deployment Credentials**:
    - Webapp publishing credentials (Kudu)
    - Location: Keep in webapps.go (webapps-kudu-commands)

- [x] **Identified certificate-based auth services**:
  - API Management - Infrastructure TLS/SSL
  - Application Gateway - Infrastructure TLS/SSL
  - VPN Gateway - IPsec/IKE certificates
  - IoT Hub - Device certificates
  - Azure Front Door - TLS/SSL
  - Azure CDN - TLS/SSL
  - Traffic Manager - No certificates
  - Load Balancer - No TLS termination

### Decision: CONSOLIDATE IDENTITY CREDENTIALS IN ACCESSKEYS.GO
- **DECISION CHANGED**: User explicitly requested removal of redundancy
- **RATIONALE**: accesskeys.go is the "one-stop shop" for ALL identity credentials
  - GetServicePrincipalsPerSubscription() already returns ALL service principals including webapp managed identities
  - Eliminates redundancy between modules
  - Single source of truth for identity credentials
  - User expectation: "If I want to find ALL credentials, I should only need to run ONE command"

### Implementation Complete:
- ✅ **Removed** webapps-credentials loot file from webapps.go
- ✅ **Removed** credential extraction code from webapp_helpers.go (36 lines removed)
- ✅ **Simplified** Credentials column to "Yes"/"No" indicator
- ✅ **Verified** webapp managed identities are captured in accesskeys.go
- ✅ **Build tested**: Compiles successfully

### Benefits of Consolidated Structure:
- ✅ **All identity credentials** centralized in accesskeys.go (including webapp managed identities)
- ✅ **No redundancy** between modules
- ✅ **Single command** to find all credentials: `./cloudfox az accesskeys`
- ✅ **Infrastructure certificates** remain in their resource modules (context-appropriate)
- ✅ **Deployment credentials** well-documented in webapps.go (webapps-kudu-commands)
- ✅ **Clear categorization** prevents confusion
- ✅ Maintains single responsibility principle

### No Implementation Required:
- Current state is optimal
- No code changes needed
- No module consolidation needed
- Documentation updated to reflect analysis

---

## 🎯 ISSUE #5: FUNCTIONS.GO CLEANUP - RESOLVED (NO CHANGES NEEDED) ✅

**Date Completed**: 2025-10-31
**Task**: Review and remove redundant columns from functions.go

### Analysis Complete ✅
- **Reviewed Columns**: HTTPS Only, Min TLS Version
- **Initial Assumption**: These were App Service Plan-level settings (redundant for Functions)
- **Finding**: These are **per-Function App settings**, not plan-level settings

### Technical Verification ✅
**Azure SDK Documentation Confirms**:
```go
// SiteProperties
HTTPSOnly *bool  // Forces HTTPS-only access

// SiteConfig
MinTLSVersion *SupportedTLSVersions  // Minimum TLS version (1.0, 1.1, 1.2, 1.3)
ScmMinTLSVersion *SupportedTLSVersions  // Minimum TLS for SCM/deployment
```

**Configuration Methods**:
- Azure Portal: Function App → Configuration → General Settings
- Azure CLI: `az functionapp update --set httpsOnly=true`
- Azure CLI: `az functionapp config set --min-tls-version 1.2`
- ARM Templates: `properties.httpsOnly`, `properties.siteConfig.minTlsVersion`

### Decision: NO CHANGES NEEDED ✅

**Columns to Keep**:
- ✅ "HTTPS Only" - Important security setting, configurable per Function App
- ✅ "Min TLS Version" - Important security setting, configurable per Function App

**Rationale**:
1. Azure Functions run on App Service infrastructure and support these settings
2. Settings are independently configurable per Function App (not inherited from plan)
3. Consistency with webapps.go (which has identical columns)
4. Security visibility: Essential for compliance and security audits
5. User expectation: These settings can be configured, so they should be visible

### Implementation Summary:
- **Files Modified**: 0 (no changes required)
- **Current State**: ✅ Correct as-is
- **Build Status**: ✅ No build needed
- **Testing Status**: ✅ No testing needed

---

## 🎯 ISSUE #1: OUTPUT DIRECTORY STRUCTURE - SCOPE PREFIXES ADDED ✅

**Date Completed**: 2025-10-31
**Task**: Add scope prefixes to output directory names and ensure cross-platform compatibility

### Requirements ✅
1. **Scope Prefixes**: Prepend directory names with scope indicators
   - [T]- for Tenant-level directories
   - [S]- for Subscription-level directories
   - [O]- for Organization-level directories (AWS/GCP)
   - [A]- for Account-level directories (AWS)
   - [P]- for Project-level directories (GCP)

2. **Windows/Linux Compatibility**: Sanitize directory names
   - Remove invalid characters: < > : " / \ | ? *
   - Trim leading/trailing spaces and dots (Windows requirement)
   - Fallback to "unnamed" if sanitization results in empty string

3. **Name Priority**: Prefer friendly names over GUIDs (already implemented)
   - Tenant Name → Tenant GUID
   - Subscription Name → Subscription GUID

### Implementation ✅

**Files Modified**:
- `internal/output2.go` (lines 1111-1189)

**New Functions**:
1. `getScopePrefix(scopeType string) string` (lines 1151-1167)
   - Maps scope types to prefix strings
   - Returns appropriate prefix or empty string

2. `sanitizeDirectoryName(name string) string` (lines 1169-1189)
   - Replaces invalid characters with underscore
   - Trims problematic whitespace
   - Ensures non-empty result

**Updated Function**:
- `buildResultsIdentifier(scopeType, identifiers, names []string) string` (lines 1125-1149)
  - Now applies scope prefix
  - Sanitizes directory names for cross-platform compatibility

### Directory Structure Examples ✅

**Azure**:
```
cloudfox-output/Azure/user@contoso.com/[T]-Contoso-Tenant/vms.csv
cloudfox-output/Azure/user@contoso.com/[S]-Production-Subscription/storage.csv
cloudfox-output/Azure/user@contoso.com/[S]-Dev_Test/databases.csv  (sanitized /)
```

**AWS**:
```
cloudfox-output/AWS/arn_aws_iam__123456789012_user_admin/[O]-MyOrganization/buckets.csv
cloudfox-output/AWS/arn_aws_iam__123456789012_user_admin/[A]-Production-Account/ec2.csv
```

**GCP**:
```
cloudfox-output/GCP/user@example.com/[O]-MyOrg/projects.csv
cloudfox-output/GCP/user@example.com/[P]-production-project/compute.csv
```

### Sanitization Examples ✅

**Before → After**:
- "Tenant: Production" → "[T]-Tenant_ Production"
- "Subscription/Dev" → "[S]-Subscription_Dev"
- "Test|Env" → "[S]-Test_Env"
- "Dev<Test>" → "[S]-Dev_Test_"
- ".hidden " → "[T]-_hidden" (trimmed . and space)

### Build Status ✅
- ✅ All changes compile successfully
- ✅ No breaking changes (backward compatible)
- ✅ Works across all modules using HandleOutputSmart/HandleOutputV2

### Modules Affected ✅
All 35+ Azure modules now use prefixed directory names:
- vms, storage, aks, databases, webapps, functions, endpoints, etc.
- principals, rbac, whoami (tenant-level modules)

---

## 🎯 ISSUE #8: NETWORK SCANNING COMMANDS - CURRENT STATE DOCUMENTED ✅

**Date Completed**: 2025-10-31
**Task**: Review and document current network scanning commands implementation

### Current Implementation - ALREADY COMPREHENSIVE ✅

**Module**: `azure/commands/network-interfaces.go`
**Registration**: ✅ Registered in `cli/azure.go` line 139
**Function**: `generateNetworkScanningLoot()` (lines 209-469)

### Loot Files Generated ✅

1. **network-interface-commands** - Azure CLI commands for NIC management
2. **network-interfaces-PrivateIPs** - List of all private IPs (one per line)
3. **network-interfaces-PublicIPs** - List of all public IPs (one per line)
4. **network-scanning-commands** - Comprehensive 260+ line scanning guide

### Network Scanning Guide Contents ✅

**Section 1: Public IP Scanning with Nmap**
- Basic scan with service version detection
- Comprehensive all-port scan with OS detection
- Aggressive scan with timing optimization
- Targeted scan of common Azure ports (22, 80, 443, 1433, 3306, 3389, 5432, etc.)
- Stealth SYN scan

**Section 2: Private IP Scanning with Nmap**
- Prerequisites for private network access (VM, VPN, Bastion, peering)
- Basic and full private network scans
- Internal Azure services focus
- Fast host discovery

**Section 3: Fast Port Discovery with Masscan**
- Masscan for public IPs (all ports, top 100, web ports)
- Masscan for private IPs (higher rates on internal network)
- Convert masscan output for nmap follow-up

**Section 4: DNS Enumeration**
- Azure DNS zone listing
- DNS record enumeration (A, CNAME)
- DNS brute force (dnsrecon, fierce)
- Azure-specific DNS patterns (.azurewebsites.net, .blob.core.windows.net, etc.)

**Section 5: Azure-Specific Scanning Tips**
- NSG considerations (allowed ports, source IPs)
- Azure Firewall considerations (logging, rate limiting)
- Best practices (masscan → nmap, timing, scanning location)
- Security considerations (logging, alerts, DDoS protection)
- Post-scan prioritization (databases, management, web, file shares)

### What's Missing (Enhancement Opportunities) 🔍

The current implementation generates **generic** scanning commands. To enhance it:

1. **NSG Rules** (requires new NSG module) - Would enable:
   - Targeted scanning of **only allowed ports** instead of all ports
   - Identification of **allowed source IPs** for stealthier scans
   - Skip scanning ports blocked by NSG rules

2. **Azure Firewall Rules** (requires new Firewall module) - Would enable:
   - Understanding of **DNAT rules** (public-facing services)
   - Identification of **network rules** (allowed protocols/ports)
   - Identification of **application rules** (allowed FQDNs)

3. **Route Tables** (requires new Routes module) - Would enable:
   - Identification of **internet-bound routes**
   - Understanding of **next hop** appliances
   - Identification of **custom routes**

4. **VNet Peerings** (requires new VNets module) - Would enable:
   - Understanding of **cross-VNet connectivity**
   - Identification of **cross-subscription** peerings
   - Identification of **cross-tenant** peerings

### Next Steps 📋

Issue #8.2-8.5 outline creating the missing modules:
- **8.2**: NSG module (Network Security Groups)
- **8.3**: Firewall module (Azure Firewall)
- **8.4**: Routes module (Route Tables)
- **8.5**: VNets module (Virtual Networks and Peerings)

Once these modules exist, Issue #8.6 can enhance the scanning commands with targeted, rule-aware scanning.

### Summary ✅

- ✅ **Current State**: Excellent comprehensive network scanning guide already implemented
- ✅ **Module Registration**: Properly registered in CLI
- ✅ **Loot Files**: All files properly configured
- 🔍 **Enhancement Path**: Create NSG/Firewall/Routes/VNets modules, then enhance scanning commands with rule awareness

---

## 🎯 ISSUE #6: RBAC.GO HEADER CORRECTIONS - COMPLETE ✅

**Date Completed**: 2025-10-31
**Task**: Update RBAC table headers for clarity and fix missing field bug

### Problem Identified ✅
**Ambiguous Headers**: Headers didn't clarify that columns contain different data for different principal types
- "Principal Name" - Could be user name OR application name
- "Principal UPN" - Could be UPN (user@domain.com) OR Application ID (GUID)

**Bug Found**: Missing field assignment
- `PrincipalName` field was NOT being populated in row construction
- Field was referenced in output but never set to `principalInfo.DisplayName`

### Changes Made ✅

**Header Updates**:
- ✅ "Principal Name" → "Principal Name / Application Name"
- ✅ "Principal UPN" → "Principal UPN / Application ID"

**Bug Fix**:
- ✅ Added `PrincipalName: principalInfo.DisplayName` to RBACRow construction (rbac.go:875)

### Files Modified:
- `azure/commands/rbac.go` (lines 49-62, 875)
- `internal/azure/rbac_helpers.go` (lines 44-57)

### Technical Details:

**Data Flow**:
1. `GetPrincipalInfo()` queries Microsoft Graph API for principal information
2. For **Users/Groups**: Returns `userPrincipalName` and `displayName`
3. For **Service Principals**: Returns `appId` and `displayName` (application name)
4. Fallback logic: If no UPN, uses Mail → AppID → ObjectID

**Header Mapping by Principal Type**:
```
Users:
  Principal Name / Application Name  → Display Name (e.g., "John Doe")
  Principal UPN / Application ID     → UPN (e.g., "john.doe@contoso.com")

Service Principals:
  Principal Name / Application Name  → Application Display Name (e.g., "MyApp")
  Principal UPN / Application ID     → Application ID GUID (e.g., "12345678-...")

Groups:
  Principal Name / Application Name  → Group Display Name (e.g., "Engineering")
  Principal UPN / Application ID     → Mail or ObjectID
```

### Other Headers Reviewed ✅
All other headers were audited and found to be clear:
- "Principal GUID", "Principal Type", "Role Name", "Providers/Resources"
- "Tenant Scope", "Subscription Scope", "Resource Group Scope", "Full Scope"
- "Condition", "Delegated Managed Identity Resource"

### Implementation Summary:
- **Files Modified**: 2 (rbac.go, rbac_helpers.go)
- **Bug Fixes**: 1 (missing PrincipalName assignment)
- **Header Clarifications**: 2 (Principal Name, Principal UPN)
- **Build Status**: ✅ All changes compile successfully
- **Breaking Changes**: None (headers only, backward compatible)

---

## Related Files
- Detailed analysis: `tmp/MISSING_RESOURCES_ANALYSIS.md`
- Phase 2 loot commands: `tmp/LOOT_COMMAND_FIXES_CHECKLIST.md`
- MicroBurst integration: `MICROBURST_INTEGRATION_ROADMAP.md`
- Output restructuring: `tmp/TESTING_ISSUES_TODO.md` (Issue #1)

---

**End of TODO Checklist**

---

## 🎯 ENTRAID CENTRALIZED AUTH COLUMN STANDARDIZATION (Issue #4) - IN PROGRESS

**Date Started**: 2025-10-31
**Task**: Audit and standardize "EntraID Centralized Auth" column across all modules

### ✅ Phase 4.1: Audit Complete

**Modules Audited**:
1. **vms.go** ✅
2. **keyvaults.go** ✅  
3. **databases.go** ✅

**Current Implementations**:

| Module | Column Name | Values | Data Source | Meaning |
|--------|-------------|--------|-------------|---------|
| vms.go | "RBAC Enabled?" | True/False | VM Extensions (AADSSHLoginForLinux/AADLoginForWindows) | Does the VM support EntraID login? |
| keyvaults.go | "RBAC Enabled" | true/false/UNKNOWN | Properties.EnableRbacAuthorization | Is the vault using RBAC vs Access Policies? |
| databases.go | "RBAC Enabled" | Yes/No/Unknown/N/A | REST API (Azure AD administrators) | Are Azure AD administrators configured? |

**Inconsistencies Identified**:
1. **Column Names**: Inconsistent punctuation ("RBAC Enabled?" vs "RBAC Enabled")
2. **Value Casing**: Inconsistent capitalization (True/False vs true/false vs Yes/No)
3. **Semantic Meaning**: Different meaning per resource type
4. **Unknown/N/A Handling**: Different approaches for unavailable data

### ✅ Phase 4.2: Standardization Complete

**Implemented Standardization**:
- **New Column Name**: "EntraID Centralized Auth"
- **Standard Values**: "Enabled" / "Disabled" / "N/A" / "Unknown"
- **Rationale**:
  - Clear, descriptive column name
  - Consistent with Azure's branding (EntraID)
  - Standardized values across all modules

**Modules Updated**:
- ✅ **vms.go** (line 256): Renamed "RBAC Enabled?" → "EntraID Centralized Auth"
  - internal/azure/vm_helpers.go: Changed "True"→"Enabled", "False"→"Disabled"
  - Variable renamed: `isRBACEnabled` → `isEntraIDAuth`
- ✅ **keyvaults.go** (line 648): Renamed "RBAC Enabled" → "EntraID Centralized Auth"
  - Changed "true"→"Enabled", "false"→"Disabled", "UNKNOWN"→"Unknown"
  - Variable renamed: `rbacEnabled` → `entraIDAuth`
- ✅ **databases.go** (line 996): Renamed "RBAC Enabled" → "EntraID Centralized Auth"
  - internal/azure/database_helpers.go: Changed "Yes"→"Enabled", "No"→"Disabled"
  - Function renamed: `IsRBACEnabled()` → `IsEntraIDAuthEnabled()`

**Column Semantics Clarified**:
- This column indicates whether EntraID provides centralized authentication for users to authenticate **TO** the resource
- Example: Can an EntraID user log into a VM or database?
- **NOT** about managed identities or roles assigned to the resource
- **NOT** about authorization (what permissions the resource has)

**Build Verification**: ✅ Compiles successfully (go build ./... exit code 0)

### 📋 Phase 4.3: Add Column to Missing Modules - ✅ MOSTLY COMPLETE

**Modules Completed (7 core modules)**:
- ✅ **storage.go** - EntraID Centralized Auth column added
  - Added `EntraIDAuth` field to `StorageAccountInfo` struct
  - Checks: `Properties.AzureFilesIdentityBasedAuthentication.DirectoryServiceOptions`
  - Logic: "Enabled" if AADDS or AADKERB, "Disabled" if None or AD
  - Files modified: azure/commands/storage.go (struct, logic, header, row)
  - Build status: ✅ Compiles successfully

- ✅ **aks.go** - EntraID Centralized Auth column added
  - Added `EntraIDAuth` field to `AksCluster` struct
  - Checks: `Properties.AADProfile.Managed` OR `Properties.AADProfile.EnableAzureRBAC`
  - Logic: "Enabled" if either AAD property is true, "Disabled" otherwise
  - Files modified: azure/commands/aks.go (struct, logic, header, row)
  - Build status: ✅ Compiles successfully

- ✅ **webapps.go** - EntraID Centralized Auth fully implemented
  - Integrated Easy Auth config checking to populate auth status
  - Created auth status map from `GetWebAppAuthConfigs()` results
  - Created new function `GetWebAppsPerRGWithAuth()` to pass auth status via map parameter
  - Renamed column header from "Authentication Enabled" to "EntraID Centralized Auth"
  - Shows "Enabled"/"Disabled" instead of "N/A"
  - Files modified: azure/commands/webapps.go, internal/azure/webapp_helpers.go
  - Build status: ✅ Compiles successfully

- ✅ **functions.go** - EntraID Centralized Auth fully implemented
  - Integrated Easy Auth config checking (works for function apps)
  - Created auth status map using `GetWebAppAuthConfigs()` (same function works for both)
  - Updated auth status checking logic
  - Renamed column header from "Authentication Enabled" to "EntraID Centralized Auth"
  - Shows "Enabled"/"Disabled"
  - Files modified: azure/commands/functions.go
  - Build status: ✅ Compiles successfully

- ✅ **databases.go** - Already had column (from Phase 4.2 standardization)
  - Column "EntraID Centralized Auth" standardized in Phase 4.2
  - Uses `IsEntraIDAuthEnabled()` function to check for Azure AD administrators

- ✅ **synapse.go** - EntraID Centralized Auth implemented
  - Checks workspace-level `Properties.AzureADOnlyAuthentication`
  - SQL pools and Spark pools inherit workspace auth settings
  - Logic: "Enabled" if AzureADOnlyAuthentication is true, "Disabled" otherwise
  - Files modified: azure/commands/synapse.go
  - Build status: ✅ Compiles successfully

- ✅ **arc.go** - EntraID Centralized Auth implemented
  - Checks for Azure AD login extensions (AADSSHLoginForLinux, AADLoginForWindows)
  - Added `EntraIDAuth` field to ArcMachine struct
  - Logic: "Enabled" if AAD login extensions installed, "Disabled" otherwise
  - Checks both extension Name and Type properties
  - Files modified: internal/azure/arc_helpers.go, azure/commands/arc.go
  - Build status: ✅ Compiles successfully

**Modules Excluded (Not Applicable)**:
- ❌ **automation.go** - Not applicable (managed identities OF the resource, not auth TO it)
- ❌ **logicapps.go** - Not applicable (managed identities OF the resource, not auth TO it)
- ❌ **bastion.go** - Does not exist as separate command (only enumerated in endpoints.go)

### 📊 Benefits of Standardization:
- ✅ **Consistent user experience** across all modules
- ✅ **Clear terminology** aligned with Azure branding
- ✅ **Easier to understand** for security audits
- ✅ **Predictable output** for automated tooling

### 🎯 Summary of Issue #4 Progress

**Phase 4.1: Audit** ✅ COMPLETE
- Audited 3 existing modules (vms, keyvaults, databases)
- Identified inconsistencies in column names and values

**Phase 4.2: Standardization** ✅ COMPLETE
- Standardized 3 modules (vms, keyvaults, databases)
- Renamed columns to "EntraID Centralized Auth"
- Standardized values to "Enabled"/"Disabled"/"Unknown"/"N/A"

**Phase 4.3: Add to Missing Modules** ✅ COMPLETE (7/7 applicable modules complete)
- ✅ storage.go - Implemented (Azure Files identity-based authentication)
- ✅ aks.go - Implemented (AAD integration check)
- ✅ webapps.go - Implemented (Easy Auth integration)
- ✅ functions.go - Implemented (Easy Auth integration)
- ✅ databases.go - Already had column (from Phase 4.2)
- ✅ synapse.go - Implemented (AzureADOnlyAuthentication check)
- ✅ arc.go - Implemented (AAD login extensions check)
- ❌ automation.go, logicapps.go - Not applicable (excluded from implementation)

**Build Status**: ✅ All changes compile successfully

**Phase 4.4: Testing** ⏳ PENDING
- Test each module with EntraID enabled resources
- Test each module with local auth resources
- Verify column displays "Enabled" or "Disabled" correctly

**Summary**: ✅ **Issue #4 implementation complete!** All 7 applicable modules now have the standardized "EntraID Centralized Auth" column. Ready for testing phase.

---

## 🎯 SUMMARY OF ISSUE #4 - COMPLETE ✅

**Date Completed**: 2025-10-31
**Task**: EntraID Centralized Auth Column - Audit, Standardize, and Implement

### Phase 4.1: Audit ✅ COMPLETE
- Audited 3 existing modules (vms, keyvaults, databases)
- Identified inconsistencies in column names, values, and semantics

### Phase 4.2: Standardization ✅ COMPLETE
- **New Column Name**: "EntraID Centralized Auth"
- **Standard Values**: "Enabled" / "Disabled" / "N/A" / "Unknown"
- **Modules Standardized**: vms.go, keyvaults.go, databases.go
- **Semantic Definition**: Indicates if EntraID provides centralized authentication for users to authenticate TO the resource

### Phase 4.3: Implementation ✅ COMPLETE
**7 Applicable Modules Implemented**:
1. **vms.go** - VM AAD login extensions (Phase 4.2 - standardized)
2. **keyvaults.go** - RBAC vs Access Policies (Phase 4.2 - standardized)
3. **databases.go** - Azure AD administrators (Phase 4.2 - standardized)
4. **storage.go** - Azure Files identity-based auth (AADDS/AADKERB)
5. **aks.go** - AAD integration (AADProfile.Managed/EnableAzureRBAC)
6. **webapps.go** - Easy Auth integration
7. **functions.go** - Easy Auth integration
8. **synapse.go** - AzureADOnlyAuthentication property
9. **arc.go** - AAD login extensions (AADSSHLoginForLinux/AADLoginForWindows)

**3 Modules Excluded (Not Applicable)**:
- automation.go - Managed identities OF resource, not auth TO it
- logicapps.go - Managed identities OF resource, not auth TO it
- bastion.go - Does not exist as separate command

### Phase 4.4: Testing ⏳ NEXT STEP
- Runtime testing with actual Azure resources
- Verify "Enabled"/"Disabled" values display correctly
- Test with various auth configurations

### Implementation Summary:
- **Total Modules Modified**: 9 (vms, keyvaults, databases, storage, aks, webapps, functions, synapse, arc)
- **Helper Files Modified**: 4 (vm_helpers.go, database_helpers.go, webapp_helpers.go, arc_helpers.go)
- **Build Status**: ✅ All changes compile successfully
- **Code Quality**: Consistent naming, standardized values, clear semantics
