# Azure CloudFox - Missing Resources Analysis

**Date:** 2025-10-25
**Purpose:** Identify Azure resources missing from enumeration modules
**Scope:** All azure/commands modules

---

## Executive Summary

This analysis identifies Azure resources and services that are **not currently enumerated** by CloudFox Azure modules. The focus is on:
1. **Database services** - Managed databases, flexible servers, and caching
2. **Network-exposed endpoints** - All services with public/private IPs that can be scanned
3. **Compute resources** - VMs, containers, serverless
4. **Storage services** - Blob, file, table, queue, data lake
5. **Network infrastructure** - Firewalls, gateways, DNS, peering
6. **Security & Identity** - Advanced identity, encryption services
7. **Analytics & Big Data** - Data processing, streaming, warehousing

---

## Current Module Coverage (33 modules)

### ✅ Well-Covered Areas
- Azure SQL Database (Single Server)
- MySQL (Single Server)
- PostgreSQL (Single Server)
- CosmosDB (all APIs)
- Storage Accounts (Blob, Queue, File)
- Virtual Machines
- Web Apps & App Services
- Function Apps
- AKS (Kubernetes)
- Container Apps
- Container Registry (ACR)
- Key Vaults
- Automation Accounts
- Load Balancers
- Application Gateways
- VPN Gateways
- Network Interfaces
- Public IPs
- DNS Zones
- RBAC
- Service Principals
- Managed Identities
- Access Keys & Certificates
- Deployments
- Azure DevOps (Projects, Repos, Pipelines, Artifacts)
- Azure Arc
- Azure Batch
- Machine Learning workspaces
- App Configuration
- Logic Apps
- Managed Disks
- Enterprise Applications
- Load Testing

---

## 🚨 CRITICAL MISSING RESOURCES

### 1. Databases Module - Missing Managed Databases

**Current Coverage:** SQL Database (Single Server), MySQL (Single Server), PostgreSQL (Single Server), CosmosDB

**Missing:**

#### 1.1 Azure SQL Managed Instance ⚠️ CRITICAL
- **Why Critical:** Full SQL Server compatibility, different networking model, often used for production workloads
- **Difference from SQL Database:** Runs in VNet, has instance-level resources, different pricing
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql` (ManagedInstancesClient)
- **Endpoint Format:** `{instance-name}.{region}.database.windows.net`
- **Attack Surface:** Instance-scoped permissions, cross-database queries, linked servers
- **Recommendation:** HIGH PRIORITY - Add to databases.go

#### 1.2 Azure Database for MySQL - Flexible Server ⚠️ IMPORTANT
- **Why Important:** New deployment model replacing Single Server (which will be retired)
- **Difference:** Better performance, HA options, different firewall/private endpoint model
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers`
- **Endpoint Format:** `{server-name}.mysql.database.azure.com`
- **Current:** Only Single Server enumerated (armmysql package)
- **Recommendation:** HIGH PRIORITY - Add alongside Single Server

#### 1.3 Azure Database for PostgreSQL - Flexible Server ⚠️ IMPORTANT
- **Why Important:** New deployment model replacing Single Server
- **Difference:** Better performance, more PostgreSQL extensions, different network model
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armmpostgresqlflexibleservers`
- **Endpoint Format:** `{server-name}.postgres.database.azure.com`
- **Current:** Only Single Server enumerated (armpostgresql package)
- **Recommendation:** HIGH PRIORITY - Add alongside Single Server

#### 1.4 Azure Database for MariaDB ⚠️ MEDIUM
- **Why Important:** Fork of MySQL, some organizations use it
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mariadb/armmariadb`
- **Endpoint Format:** `{server-name}.mariadb.database.azure.com`
- **Recommendation:** MEDIUM PRIORITY - Add to databases.go

#### 1.5 Azure Cache for Redis ⚠️ HIGH
- **Why Critical:** Often contains session data, cache poisoning attacks, exposed endpoints
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis`
- **Endpoint Format:** `{name}.redis.cache.windows.net:6380`
- **Attack Surface:** Access keys, SSL/non-SSL ports, public vs private endpoints
- **Data Exposure:** Session tokens, cached credentials, PII in cache
- **Recommendation:** HIGH PRIORITY - Create new module redis.go OR add to databases.go

#### 1.6 Azure Synapse Analytics ⚠️ HIGH
- **Why Critical:** Data warehouse, often contains sensitive data, multiple endpoints
- **Components:**
  - Dedicated SQL Pools (formerly SQL Data Warehouse)
  - Serverless SQL Pools
  - Apache Spark Pools
  - Workspace endpoints
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/synapse/armsynapse`
- **Endpoint Format:** `{workspace-name}.sql.azuresynapse.net`, `{workspace-name}-ondemand.sql.azuresynapse.net`
- **Attack Surface:** SQL injection, Spark cluster access, managed identity permissions
- **Recommendation:** HIGH PRIORITY - Create new module synapse.go

#### 1.7 Azure Data Explorer (Kusto) ⚠️ MEDIUM
- **Why Important:** Big data analytics, query language injection, API access
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto`
- **Endpoint Format:** `{cluster-name}.{region}.kusto.windows.net`
- **Attack Surface:** Kusto Query Language injection, data exfiltration
- **Recommendation:** MEDIUM PRIORITY - Add to databases.go or new module

---

### 2. Endpoints Module - Missing Network-Exposed Services

**Current Coverage:** VMs, Functions, Load Balancers, App Gateways, VPN Gateways, AKS, Databases, DNS

**Missing:**

#### 2.1 API Management (APIM) ⚠️ CRITICAL
- **Why Critical:** Publicly exposed APIs, authentication bypass, rate limit bypass
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement`
- **Endpoints:** Gateway URL, Management URL, Developer Portal URL, SCM URL
- **Endpoint Format:** `{name}.azure-api.net`, custom domains
- **Attack Surface:** API gateway vulnerabilities, subscription keys, OAuth misconfigurations
- **Recommendation:** HIGH PRIORITY - Add to endpoints.go

#### 2.2 Azure Front Door ⚠️ CRITICAL
- **Why Critical:** Global load balancer, WAF bypass, backend exposure
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor`
- **Endpoint Format:** `{name}.azurefd.net`, custom domains
- **Attack Surface:** WAF rules, routing rules, backend pool discovery
- **Recommendation:** HIGH PRIORITY - Add to endpoints.go

#### 2.3 Azure CDN ⚠️ HIGH
- **Why Critical:** Content delivery, origin exposure, cache poisoning
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn`
- **Endpoint Format:** `{name}.azureedge.net`, custom domains
- **Attack Surface:** Origin server discovery, cache key manipulation
- **Recommendation:** HIGH PRIORITY - Add to endpoints.go

#### 2.4 Traffic Manager ⚠️ MEDIUM
- **Why Important:** DNS-based load balancing, endpoint discovery
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/trafficmanager/armtrafficmanager`
- **Endpoint Format:** `{name}.trafficmanager.net`
- **Attack Surface:** Endpoint enumeration, routing method analysis
- **Recommendation:** MEDIUM PRIORITY - Add to endpoints.go

#### 2.5 Azure Firewall ⚠️ HIGH
- **Why Important:** Public IP, rule analysis, bypass opportunities
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (AzureFirewallsClient)
- **Attack Surface:** Public IP for management, firewall rules, DNAT rules
- **Recommendation:** HIGH PRIORITY - Add to endpoints.go

#### 2.6 Azure Bastion ⚠️ MEDIUM
- **Why Important:** RDP/SSH access point, public IP
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (BastionHostsClient)
- **Attack Surface:** Public IP, Azure Portal-based access
- **Recommendation:** MEDIUM PRIORITY - Add to endpoints.go

#### 2.7 Azure Spring Apps (formerly Spring Cloud) ⚠️ MEDIUM
- **Why Important:** Public endpoints, Spring Boot vulnerabilities
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appplatform/armappplatform`
- **Endpoint Format:** `{app-name}.{region}.azuremicroservices.io`
- **Attack Surface:** Spring Boot actuators, application endpoints
- **Recommendation:** MEDIUM PRIORITY - Add to endpoints.go

#### 2.8 Event Hubs ⚠️ MEDIUM
- **Why Important:** Public endpoints, SAS tokens, data streaming
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub`
- **Endpoint Format:** `{namespace}.servicebus.windows.net`
- **Current:** SAS tokens in accesskeys.go, but not endpoints
- **Recommendation:** MEDIUM PRIORITY - Add to endpoints.go

#### 2.9 Service Bus ⚠️ MEDIUM
- **Why Important:** Public endpoints, message queues, SAS tokens
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus`
- **Endpoint Format:** `{namespace}.servicebus.windows.net`
- **Current:** Keys in accesskeys.go, but not endpoints
- **Recommendation:** MEDIUM PRIORITY - Add to endpoints.go

#### 2.10 IoT Hub ⚠️ HIGH
- **Why Important:** Device management, public endpoints, connection strings
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/iothub/armiothub`
- **Endpoint Format:** `{name}.azure-devices.net`
- **Attack Surface:** Device provisioning, message routing, connection strings
- **Recommendation:** HIGH PRIORITY - Create new module iothub.go

#### 2.11 Azure SignalR Service ⚠️ LOW
- **Why Important:** Real-time communication endpoints
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/signalr/armsignalr`
- **Endpoint Format:** `{name}.service.signalr.net`
- **Recommendation:** LOW PRIORITY

#### 2.12 Service Fabric Clusters ⚠️ LOW
- **Why Important:** Public endpoints for management
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicefabric/armservicefabric`
- **Endpoint Format:** Custom domain or `{name}.{region}.cloudapp.azure.com`
- **Recommendation:** LOW PRIORITY

---

### 3. Compute Module - Missing Resources

**Current Coverage:** VMs, Functions, Container Apps, AKS, Batch

**Missing:**

#### 3.1 Virtual Machine Scale Sets (VMSS) ⚠️ HIGH
- **Why Critical:** Auto-scaling VM groups, often overlooked, public IPs
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute` (VirtualMachineScaleSetsClient)
- **Attack Surface:** Instance-level access, load balancer rules, managed identities
- **Recommendation:** HIGH PRIORITY - Add to vms.go or create vmss.go

#### 3.2 Azure Container Instances (ACI) ⚠️ MEDIUM
- **Why Important:** Serverless containers, public IPs, environment variables
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance`
- **Endpoint Format:** Public IPs or FQDN
- **Current:** Container Apps covered, but not Container Instances
- **Recommendation:** MEDIUM PRIORITY - Add to container-apps.go

#### 3.3 Azure App Service Environment (ASE) ⚠️ MEDIUM
- **Why Important:** Isolated App Service deployment, VNet integration
- **SDK:** Part of App Service SDK
- **Difference:** Dedicated infrastructure vs multi-tenant
- **Recommendation:** MEDIUM PRIORITY - Check if webapps.go covers this

---

### 4. Storage Module - Missing Resources

**Current Coverage:** Blob, Queue, File shares

**Missing:**

#### 4.1 Table Storage ⚠️ MEDIUM
- **Why Important:** NoSQL key-value store, often contains application data
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/data/aztables`
- **Access:** Account keys, SAS tokens
- **Data Exposure:** Application configuration, user data, logs
- **Recommendation:** MEDIUM PRIORITY - Add to storage.go

#### 4.2 Data Lake Storage Gen2 (ADLS Gen2) ⚠️ HIGH
- **Why Critical:** Big data storage, ACLs, hierarchical namespace
- **SDK:** Uses Blob SDK with `isHnsEnabled` flag
- **Difference:** Hierarchical filesystem, POSIX ACLs
- **Attack Surface:** ACL misconfigurations, path traversal
- **Recommendation:** HIGH PRIORITY - Add to storage.go (check for HNS-enabled accounts)

#### 4.3 Azure NetApp Files ⚠️ MEDIUM
- **Why Important:** Enterprise NFS/SMB file shares, high-performance
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/netapp/armnetapp`
- **Current:** Might be in filesystems.go - VERIFY
- **Recommendation:** MEDIUM PRIORITY - Verify coverage in filesystems.go

---

### 5. Network Infrastructure - Missing Resources

**Current Coverage:** Network Interfaces, VPN Gateways, Load Balancers, App Gateways, DNS Zones

**Missing:**

#### 5.1 Azure Firewall ⚠️ HIGH
- **Why Important:** Network security, rule analysis, public IPs
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (AzureFirewallsClient)
- **Recommendation:** HIGH PRIORITY - Add to endpoints.go and new firewall.go

#### 5.2 Network Security Groups (NSG) - Detailed Rules ⚠️ HIGH
- **Why Important:** Firewall rules, security analysis
- **Current:** NSG names shown in network-interfaces.go, but not detailed rules
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (SecurityRulesClient)
- **Recommendation:** HIGH PRIORITY - Create nsg.go or expand network-interfaces.go

#### 5.3 Route Tables ⚠️ MEDIUM
- **Why Important:** Network routing, traffic interception opportunities
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (RouteTablesClient)
- **Recommendation:** MEDIUM PRIORITY - Create routes.go

#### 5.4 Virtual Network Peerings ⚠️ MEDIUM
- **Why Important:** Cross-VNet connectivity, lateral movement
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (VirtualNetworkPeeringsClient)
- **Recommendation:** MEDIUM PRIORITY - Add to network module

#### 5.5 Private DNS Zones ⚠️ MEDIUM
- **Why Important:** Internal name resolution, Private Link discovery
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns`
- **Current:** Only public DNS zones enumerated
- **Recommendation:** MEDIUM PRIORITY - Add to endpoints.go or dns.go

#### 5.6 Private Endpoints / Private Link ⚠️ HIGH
- **Why Critical:** Discover internal access to PaaS services
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (PrivateEndpointsClient)
- **Attack Surface:** Internal-only access, service connections
- **Recommendation:** HIGH PRIORITY - Create privatelink.go

#### 5.7 NAT Gateway ⚠️ LOW
- **Why Useful:** Outbound internet connectivity analysis
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (NatGatewaysClient)
- **Recommendation:** LOW PRIORITY

#### 5.8 ExpressRoute Circuits ⚠️ LOW
- **Why Useful:** On-premises connectivity, circuit enumeration
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` (ExpressRouteCircuitsClient)
- **Recommendation:** LOW PRIORITY

---

### 6. Security & Identity - Missing Resources

**Current Coverage:** Key Vaults, Access Keys, Certificates, Service Principals, Managed Identities, RBAC, Enterprise Apps

**Missing:**

#### 6.1 Managed HSM ⚠️ MEDIUM
- **Why Important:** Hardware Security Module for key storage
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault` (ManagedHsmsClient)
- **Difference from Key Vault:** FIPS 140-2 Level 3, single-tenant
- **Recommendation:** MEDIUM PRIORITY - Add to keyvaults.go

#### 6.2 Azure AD B2C Tenants ⚠️ LOW
- **Why Useful:** Customer identity management
- **Recommendation:** LOW PRIORITY - Complex to enumerate

#### 6.3 Azure Confidential Ledger ⚠️ LOW
- **Why Useful:** Tamper-proof ledger
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/confidentialledger/armconfidentialledger`
- **Recommendation:** LOW PRIORITY

---

### 7. Analytics & Big Data - Missing Resources

**Current Coverage:** Machine Learning workspaces

**Missing:**

#### 7.1 Azure Synapse Analytics ⚠️ HIGH
- **Already covered in section 1.6 above**
- **Recommendation:** HIGH PRIORITY - Create synapse.go

#### 7.2 Azure Databricks ⚠️ HIGH
- **Why Critical:** Big data processing, notebooks, secrets, clusters
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks`
- **Attack Surface:** Workspace secrets, notebook code, cluster access tokens
- **Recommendation:** HIGH PRIORITY - Create databricks.go

#### 7.3 Azure Data Factory ⚠️ MEDIUM
- **Why Important:** ETL pipelines, connection strings, linked services
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory`
- **Attack Surface:** Linked service credentials, pipeline definitions
- **Recommendation:** MEDIUM PRIORITY - Create datafactory.go

#### 7.4 Azure Stream Analytics ⚠️ MEDIUM
- **Why Important:** Real-time data processing, inputs/outputs
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/streamanalytics/armstreamanalytics`
- **Attack Surface:** Input/output connection strings
- **Recommendation:** MEDIUM PRIORITY - Create streamanalytics.go

#### 7.5 Azure HDInsight ⚠️ MEDIUM
- **Why Important:** Hadoop/Spark clusters, SSH access, storage accounts
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hdinsight/armhdinsight`
- **Attack Surface:** SSH keys, storage credentials, cluster endpoints
- **Recommendation:** MEDIUM PRIORITY - Create hdinsight.go

#### 7.6 Event Grid ⚠️ LOW
- **Why Useful:** Event routing, subscription enumeration
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid`
- **Recommendation:** LOW PRIORITY

---

### 8. AI/ML - Partially Covered

**Current Coverage:** Machine Learning workspaces (machine-learning.go)

**Missing:**

#### 8.1 Azure Cognitive Services ⚠️ MEDIUM
- **Why Important:** API keys, endpoints for Speech, Vision, Language, etc.
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices`
- **Current:** Keys might be in accesskeys.go (check GetCognitiveServicesKeys)
- **Recommendation:** MEDIUM PRIORITY - Verify coverage, add individual service endpoints

#### 8.2 Azure OpenAI Service ⚠️ HIGH
- **Why Critical:** GPT models, API keys, deployments
- **SDK:** Part of Cognitive Services SDK
- **Attack Surface:** Model deployments, API keys, prompt injection via stored data
- **Current:** Likely covered in accesskeys.go as Cognitive Services
- **Recommendation:** HIGH PRIORITY - Add specific OpenAI endpoint enumeration

#### 8.3 Bot Services ⚠️ LOW
- **Why Useful:** Chatbot configurations, channels
- **SDK:** `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/botservice/armbotservice`
- **Recommendation:** LOW PRIORITY

---

## Priority Matrix

### 🔴 CRITICAL (Implement First)
1. Azure SQL Managed Instance (databases.go)
2. Azure Cache for Redis (new redis.go or databases.go)
3. Azure Synapse Analytics (new synapse.go)
4. API Management (endpoints.go)
5. Azure Front Door (endpoints.go)
6. Azure CDN (endpoints.go)
7. Azure Firewall (endpoints.go + new firewall.go)
8. IoT Hub (new iothub.go)
9. Private Endpoints / Private Link (new privatelink.go)
10. Azure Databricks (new databricks.go)

### 🟡 HIGH PRIORITY (Implement Second)
11. MySQL Flexible Server (databases.go)
12. PostgreSQL Flexible Server (databases.go)
13. Virtual Machine Scale Sets (vms.go or new vmss.go)
14. Data Lake Storage Gen2 (storage.go)
15. Network Security Group Rules (new nsg.go or expand network-interfaces.go)
16. Azure OpenAI Service endpoints (new ai.go or expand existing)

### 🟢 MEDIUM PRIORITY (Implement Third)
17. MariaDB (databases.go)
18. Azure Data Explorer (databases.go or new kusto.go)
19. Traffic Manager (endpoints.go)
20. Azure Bastion (endpoints.go)
21. Azure Spring Apps (endpoints.go)
22. Event Hubs endpoints (endpoints.go)
23. Service Bus endpoints (endpoints.go)
24. Container Instances (container-apps.go)
25. App Service Environment (verify webapps.go)
26. Table Storage (storage.go)
27. Azure NetApp Files (verify filesystems.go)
28. Route Tables (new routes.go)
29. Virtual Network Peerings (new vnets.go)
30. Private DNS Zones (endpoints.go)
31. Managed HSM (keyvaults.go)
32. Azure Data Factory (new datafactory.go)
33. Azure Stream Analytics (new streamanalytics.go)
34. Azure HDInsight (new hdinsight.go)
35. Cognitive Services individual endpoints (new ai.go)

### ⚪ LOW PRIORITY (Nice to Have)
36. Azure SignalR Service (endpoints.go)
37. Service Fabric Clusters (endpoints.go)
38. NAT Gateway (network module)
39. ExpressRoute Circuits (network module)
40. Azure AD B2C (identity module)
41. Azure Confidential Ledger (security module)
42. Event Grid (events module)
43. Bot Services (ai module)

---

## Recommended Implementation Plan

### Phase 1: Critical Database Gaps (1-2 weeks)
- Task 1: Add Azure SQL Managed Instance to databases.go
- Task 2: Add Azure Cache for Redis (new redis.go)
- Task 3: Add Azure Synapse Analytics (new synapse.go)
- Task 4: Add MySQL/PostgreSQL Flexible Servers to databases.go

### Phase 2: Critical Network-Exposed Endpoints (1-2 weeks)
- Task 5: Add API Management to endpoints.go
- Task 6: Add Azure Front Door to endpoints.go
- Task 7: Add Azure CDN to endpoints.go
- Task 8: Add Azure Firewall (new firewall.go)
- Task 9: Add Private Endpoints (new privatelink.go)

### Phase 3: High-Value Compute & Analytics (1-2 weeks)
- Task 10: Add VMSS to vms.go
- Task 11: Add IoT Hub (new iothub.go)
- Task 12: Add Azure Databricks (new databricks.go)
- Task 13: Add Data Lake Gen2 detection to storage.go

### Phase 4: Network Security Deep Dive (1 week)
- Task 14: Create nsg.go for detailed NSG rule analysis
- Task 15: Add Route Tables (routes.go)
- Task 16: Add VNet Peerings
- Task 17: Add Private DNS Zones

### Phase 5: Medium Priority Additions (2-3 weeks)
- Task 18: Implement remaining medium-priority items from list above

---

## Verification Checklist

For each new resource type added:
- [ ] Enumerate across all subscriptions
- [ ] Extract public/private IPs and hostnames
- [ ] Capture managed identity assignments
- [ ] Generate connection commands (az CLI + PowerShell)
- [ ] Extract access keys/connection strings where applicable
- [ ] Add to endpoints.go if network-exposed
- [ ] Include in loot files
- [ ] Test against live Azure environment
- [ ] Document in README

---

## Notes

1. **Flexible Servers vs Single Servers:** Azure is deprecating Single Server deployments for MySQL/PostgreSQL in favor of Flexible Servers. CloudFox should enumerate BOTH during the transition period.

2. **Managed Instance vs SQL Database:** These are fundamentally different services with different networking models, pricing, and attack surfaces.

3. **Endpoints Module Strategy:** The endpoints.go module should aggregate ALL network-exposed resources from ALL modules, not just specific resource types.

4. **Network Scanning Integration:** All endpoints enumerated should feed into the network-scanning-commands loot file for nmap/masscan integration.

5. **Private Link Discovery:** Critical for understanding internal-only access to PaaS services that might bypass public firewalls.

6. **SDK Package Structure:** Azure SDK uses specific resource provider packages. Import paths follow pattern:
   ```go
   github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/{service}/arm{service}
   ```

---

## Quick Reference: What Gets Added Where

| Resource Type | Add To Module | Create New Module | Add To Endpoints |
|--------------|---------------|-------------------|------------------|
| SQL Managed Instance | databases.go | - | Yes |
| Redis Cache | databases.go | redis.go (optional) | Yes |
| Synapse Analytics | - | synapse.go | Yes |
| API Management | endpoints.go | apim.go (optional) | Yes |
| Azure Front Door | endpoints.go | - | Yes |
| Azure CDN | endpoints.go | - | Yes |
| Azure Firewall | endpoints.go | firewall.go | Yes |
| VMSS | vms.go | vmss.go (optional) | Yes |
| IoT Hub | - | iothub.go | Yes |
| Private Endpoints | - | privatelink.go | No (internal) |
| NSG Rules | - | nsg.go | No |
| Databricks | - | databricks.go | Yes |
| Data Factory | - | datafactory.go | No |
| Table Storage | storage.go | - | No |
| Data Lake Gen2 | storage.go | - | No |

---

## Related Files

- Implementation checklist: `tmp/MISSING_RESOURCES_TODO.md`
- Current Phase 2 work: `tmp/LOOT_COMMAND_FIXES_CHECKLIST.md`
- MicroBurst integration: `MICROBURST_INTEGRATION_ROADMAP.md`

---

**End of Analysis**
