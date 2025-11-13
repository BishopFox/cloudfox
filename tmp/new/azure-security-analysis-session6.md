# Azure CloudFox Security Module Analysis - SESSION 6
## Platform Services Security Analysis

**Document Version:** 1.0
**Last Updated:** 2025-01-12
**Analysis Session:** 6 of Multiple
**Focus Area:** Platform-as-a-Service (PaaS) Resources

---

## SESSION 6 OVERVIEW: Platform Services Modules

This session analyzes Azure Platform-as-a-Service (PaaS) modules to identify security gaps, missing features, and enhancement opportunities.

### Modules Analyzed in This Session:
1. **Data Factory** - Data integration pipelines
2. **Databricks** - Apache Spark analytics
3. **HDInsight** - Hadoop/Spark clusters
4. **IoT Hub** - IoT device management
5. **Kusto** - Azure Data Explorer
6. **Stream Analytics** - Real-time analytics
7. **Endpoints** - Event Hubs, Service Bus, Event Grid
8. **Machine Learning** - ML workspaces
9. **SignalR** - Real-time messaging
10. **Spring Apps** - Spring Boot applications
11. **Service Fabric** - Microservices platform
12. **App Configuration** - Configuration management
13. **Arc** - Hybrid/multi-cloud management
14. **Load Testing** - Load testing service

---

## 1. DATA FACTORY Module (`datafactory.go`)

**Current Capabilities:**
- Data Factory instance enumeration
- Managed identity enumeration
- Public vs private network access

**Security Gaps Identified:**
1. ❌ **No Pipelines Enumeration** - Data movement/transformation pipelines
2. ❌ **No Linked Services** - Connection strings to data sources
3. ❌ **No Integration Runtimes** - Self-hosted IR (on-prem connectivity)
4. ❌ **No Datasets** - Data source/sink definitions
5. ❌ **No Triggers** - Scheduled/event-based pipeline triggers
6. ❌ **No Pipeline Run History** - Execution logs and status
7. ❌ **No Git Integration** - Source control configuration
8. ❌ **No Managed VNet** - Data Factory managed VNet status
9. ❌ **No Customer-Managed Keys** - Encryption configuration
10. ❌ **No Data Flow Debug** - Interactive debugging sessions
11. ❌ **No Pipeline Parameters** - Parameterized values (may contain secrets)
12. ❌ **No Firewall Rules** - IP-based access control
13. ❌ **No Diagnostic Settings** - Logging configuration
14. ❌ **No Data Exfiltration Prevention** - Outbound firewall rules
15. ❌ **No Copy Activity Sources/Sinks** - Where data is moved from/to

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add pipeline enumeration with activity details
- [ ] Add linked services enumeration (connection strings, credentials)
- [ ] Add integration runtime configuration (self-hosted IR = hybrid connectivity)
- [ ] Add datasets and data source details
- [ ] Add managed VNet status and configuration
- [ ] Add public network access enforcement
- [ ] Add customer-managed key encryption status
- [ ] Add Git integration configuration (repo, branch)

HIGH PRIORITY:
- [ ] Add trigger enumeration (schedule, tumbling window, event-based)
- [ ] Add pipeline run history and execution logs
- [ ] Add pipeline parameters and variables (potential secrets)
- [ ] Add copy activity source/sink analysis (data movement paths)
- [ ] Add firewall rules and allowed IP ranges
- [ ] Add diagnostic settings (Log Analytics integration)
- [ ] Add data exfiltration prevention settings
- [ ] Add RBAC role assignments (Data Factory Contributor, etc.)
- [ ] Add data flow debug sessions (active sessions)
- [ ] Add global parameters (shared across pipelines)

MEDIUM PRIORITY:
- [ ] Add linked service credential management (Azure Key Vault references)
- [ ] Add pipeline retry and timeout policies
- [ ] Add activity-level failure handling
- [ ] Add data flow sink/source lineage
```

**Attack Surface Considerations:**
- Linked services = external system credentials
- Self-hosted integration runtime = on-prem connectivity vector
- Pipeline parameters = potential secrets
- Git integration = source code access
- Managed identity = Azure privilege escalation
- Copy activities = data exfiltration paths
- Public network access = internet accessibility
- Triggers = automated execution vectors

---

## 2. DATABRICKS Module (`databricks.go`)

**Current Capabilities:**
- Databricks workspace enumeration
- Workspace URL
- Managed resource group
- SKU tier (Standard, Premium)
- Managed identity enumeration

**Security Gaps Identified:**
1. ❌ **No Cluster Configuration** - Interactive & job clusters
2. ❌ **No Notebooks** - Stored notebooks (may contain secrets)
3. ❌ **No Jobs** - Scheduled jobs and workflows
4. ❌ **No Secrets** - Databricks secrets (scopes, keys, values)
5. ❌ **No Workspace Access Control** - User/group permissions
6. ❌ **No Cluster Policies** - Allowed cluster configurations
7. ❌ **No Init Scripts** - Cluster initialization scripts
8. ❌ **No DBFS Contents** - Databricks File System files
9. ❌ **No Libraries** - Installed packages and dependencies
10. ❌ **No VNet Injection Status** - VNet-injected workspace
11. ❌ **No Public IP Disabled** - No-public-IP configuration
12. ❌ **No Private Link** - Private Link configuration
13. ❌ **No Git Integration** - Repos and source control
14. ❌ **No Unity Catalog** - Data governance and lineage
15. ❌ **No Credential Passthrough** - Azure AD credential passthrough
16. ❌ **No Cluster Logs** - Driver and executor logs
17. ❌ **No Personal Access Tokens** - Long-lived PATs
18. ❌ **No SQL Warehouses** - Databricks SQL endpoints
19. ❌ **No Delta Lake Tables** - Managed tables and schemas
20. ❌ **No MLflow Experiments** - ML tracking and models

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add cluster enumeration (interactive, job, all-purpose clusters)
- [ ] Add notebooks enumeration (code, secrets embedded in notebooks)
- [ ] Add Databricks secrets enumeration (secret scopes, keys - not values)
- [ ] Add jobs enumeration (scheduled jobs, triggers, parameters)
- [ ] Add workspace access control (admin, user permissions)
- [ ] Add VNet injection status (VNet-injected = private)
- [ ] Add no-public-IP status (secure cluster connectivity)
- [ ] Add private link configuration
- [ ] Add personal access token enumeration (long-lived credentials)
- [ ] Add init scripts (cluster startup scripts may contain secrets)

HIGH PRIORITY:
- [ ] Add cluster policies (allowed configurations, cost control)
- [ ] Add DBFS contents enumeration (files, datasets)
- [ ] Add installed libraries (Maven, PyPI, CRAN packages)
- [ ] Add Git integration (repos connected to workspace)
- [ ] Add Unity Catalog configuration (data governance)
- [ ] Add credential passthrough status (AAD credentials)
- [ ] Add SQL warehouses (Databricks SQL endpoints)
- [ ] Add Delta Lake table enumeration (managed tables)
- [ ] Add MLflow experiments and registered models
- [ ] Add cluster autoscaling configuration

MEDIUM PRIORITY:
- [ ] Add cluster logs location (driver, executor logs)
- [ ] Add job run history and execution logs
- [ ] Add notebook execution context (who ran what)
- [ ] Add Databricks Connect configuration
- [ ] Add workspace features enabled (DBFS, Git, etc.)
- [ ] Add IP access lists (allowed IP ranges)
```

**Attack Surface Considerations:**
- Notebooks = embedded secrets and code
- Secrets = credentials for external systems
- Personal access tokens = long-lived workspace access
- Init scripts = arbitrary code execution on clusters
- DBFS = stored datasets and files
- Public clusters = internet-accessible Spark clusters
- Jobs = automated execution with credentials
- Managed identity = Azure privilege escalation
- Git repos = source code access
- Libraries = supply chain risks

---

## 3. HDINSIGHT Module (`hdinsight.go`)

**Current Capabilities:**
- HDInsight cluster enumeration
- Cluster type (Hadoop, Spark, HBase, Kafka, Storm, Interactive Query)
- Cluster tier (Standard, Premium)
- Public endpoints (SSH, HTTPS)
- Managed identity enumeration
- Security profile (ESP - Enterprise Security Package)
- Connectivity endpoints

**Security Gaps Identified:**
1. ❌ **No Cluster Credentials** - SSH username, Ambari credentials
2. ❌ **No ESP Configuration Details** - Domain, users, groups
3. ❌ **No Encryption at Rest** - Disk encryption status
4. ❌ **No Encryption in Transit** - Wire encryption status
5. ❌ **No Storage Account Details** - Default and additional storage
6. ❌ **No Metastore Configuration** - External Hive/Oozie/Ambari metastores
7. ❌ **No Script Actions** - Custom scripts executed on cluster
8. ❌ **No Kafka Configuration** - Kafka broker endpoints, security
9. ❌ **No Cluster Size** - Node counts, VM sizes
10. ❌ **No Autoscale Configuration** - Auto-scaling rules
11. ❌ **No Disk Encryption Key** - Customer-managed key for encryption
12. ❌ **No VNet Configuration** - VNet injection status
13. ❌ **No NSG Applied** - Network security groups
14. ❌ **No Application Gateway** - App Gateway integration
15. ❌ **No Cluster Monitoring** - Azure Monitor integration

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add cluster admin credentials (username - not password)
- [ ] Add ESP configuration details (domain, users with access)
- [ ] Add encryption at rest status (disk encryption)
- [ ] Add encryption in transit status (wire encryption)
- [ ] Add VNet injection status and subnet details
- [ ] Add storage account configuration (default and additional storage)
- [ ] Add script actions enumeration (custom initialization scripts)
- [ ] Add disk encryption key configuration (CMK vs Microsoft-managed)

HIGH PRIORITY:
- [ ] Add metastore configuration (external Hive/Oozie metastores)
- [ ] Add cluster size (head nodes, worker nodes, VM sizes)
- [ ] Add autoscale configuration (schedule-based, load-based)
- [ ] Add Kafka configuration (brokers, topics, security)
- [ ] Add NSG association per cluster
- [ ] Add Azure Monitor configuration (diagnostic logs)
- [ ] Add application gateway integration (if applicable)
- [ ] Add cluster access methods (SSH keys, passwords)
- [ ] Add Ambari credentials and configuration
- [ ] Add Ranger policies (if ESP enabled)

MEDIUM PRIORITY:
- [ ] Add cluster creation date and lifetime
- [ ] Add cluster idleness timeout
- [ ] Add cluster tags and metadata
- [ ] Add HBase configuration (if HBase cluster)
- [ ] Add Storm configuration (if Storm cluster)
- [ ] Add Interactive Query configuration
```

**Attack Surface Considerations:**
- Public endpoints = SSH/HTTPS exposure
- Cluster credentials = cluster admin access
- Script actions = code execution on all nodes
- Storage accounts = data access
- Metastores = Hive metadata and queries
- No ESP = no domain authentication
- No encryption at rest = data exposure
- No VNet = direct internet connectivity
- Managed identity = Azure privilege escalation

---

## CONSOLIDATED PLATFORM SERVICES ANALYSIS

Given the large number of platform services, I'll provide a consolidated analysis for the remaining services:

## 4. IOT HUB Module (`iothub.go`)

**Key Gaps:**
- No device enumeration (registered IoT devices)
- No shared access policies (connection strings)
- No IoT Hub routes (message routing to endpoints)
- No consumer groups (Event Hub-compatible endpoints)
- No device-to-cloud messages inspection
- No file upload configuration
- No device twin queries
- No IoT Edge deployment manifests

**Critical Enhancements:**
- [ ] Device enumeration with authentication methods
- [ ] Shared access policy keys (connection strings)
- [ ] Message routing configuration
- [ ] File upload storage account configuration
- [ ] IoT Hub endpoints (Event Hub, Service Bus, Storage)

---

## 5. KUSTO Module (`kusto.go`)

**Key Gaps:**
- No database enumeration within cluster
- No table schemas and data
- No query history
- No ingestion mappings (data format)
- No external tables (data lake queries)
- No functions and stored procedures
- No access policies (database-level)
- No data retention policies

**Critical Enhancements:**
- [ ] Database and table enumeration
- [ ] Data retention and caching policies
- [ ] Principal assignments (database users)
- [ ] External table configuration
- [ ] Query result cache configuration

---

## 6. STREAM ANALYTICS Module (`streamanalytics.go`)

**Key Gaps:**
- No input source configuration (Event Hub, IoT Hub, Blob)
- No output sink configuration (SQL, Cosmos, Blob, Power BI)
- No query logic (stream processing query)
- No function definitions (UDF, ML Studio)
- No job metrics (input/output rates, errors)
- No streaming units configuration
- No compatibility level
- No diagnostic logs

**Critical Enhancements:**
- [ ] Input source enumeration with connection strings
- [ ] Output sink enumeration with credentials
- [ ] Query logic extraction (may contain secrets)
- [ ] Job monitoring configuration
- [ ] Reference data configuration (blob storage)

---

## 7. ENDPOINTS Module (`endpoints.go`)

**Covers:** Event Hubs, Service Bus, Event Grid

**Key Gaps:**
- No Event Hub namespace shared access policies
- No Event Hub consumer groups
- No Event Hub partition configuration
- No Service Bus queue/topic enumeration
- No Service Bus subscriptions and filters
- No Service Bus dead-letter queue analysis
- No Event Grid topic subscriptions
- No Event Grid webhook endpoints
- No Event Grid system topics

**Critical Enhancements:**
- [ ] Event Hub shared access policy keys
- [ ] Event Hub throughput units (standard) or processing units (premium)
- [ ] Service Bus queue/topic message counts
- [ ] Service Bus authorization rules
- [ ] Event Grid subscription endpoints (webhooks)
- [ ] Event Grid subscription filters

---

## 8. MACHINE LEARNING Module (`machine-learning.go`)

**Key Gaps:**
- No compute instances and clusters
- No datastores (storage connections)
- No datasets (registered datasets)
- No experiments and runs
- No models (registered models)
- No endpoints (real-time, batch inference)
- No pipelines (ML pipelines)
- No workspace keys (API keys)
- No custom roles (workspace-level RBAC)

**Critical Enhancements:**
- [ ] Compute instance enumeration (Jupyter notebooks)
- [ ] Compute cluster configuration (training clusters)
- [ ] Datastore credentials (storage account connections)
- [ ] Registered models and versions
- [ ] Deployed endpoints (scoring URIs, keys)
- [ ] Workspace connection strings and keys

---

## 9-14. ADDITIONAL PLATFORM SERVICES

### SignalR (`signalr.go`)
- Add access keys and connection strings
- Add CORS configuration
- Add upstream URL patterns
- Add service mode (default, serverless, classic)

### Spring Apps (`springapps.go`)
- Add app deployment source (JAR, source code, container)
- Add app environment variables (may contain secrets)
- Add app persistent storage
- Add app custom domain and TLS certificates
- Add app service bindings (databases, caches)

### Service Fabric (`servicefabric.go`)
- Add cluster certificate configuration
- Add application types and versions
- Add service manifests
- Add reverse proxy configuration
- Add node types and VM scale sets

### App Configuration (`app-configuration.go`)
- Add configuration keys and values (may contain secrets)
- Add feature flags
- Add Key Vault references
- Add access policies and keys

### Arc (`arc.go`)
- Add connected Kubernetes clusters
- Add Arc-enabled servers
- Add Arc-enabled data services
- Add GitOps configurations
- Add Azure Policy assignments

### Load Testing (`load-testing.go`)
- Add test scripts and scenarios
- Add test run history
- Add load test file uploads
- Add test environment variables (may contain secrets)

---

## SESSION 6 SUMMARY: Platform Services Gaps

### Critical Gaps Across Platform Services

1. **Embedded Secrets** - Notebooks, scripts, pipelines contain hardcoded credentials
2. **Connection Strings** - Linked services, datastores, message queues not fully enumerated
3. **Access Keys** - Shared access policies, PATs, API keys missing
4. **Data Lineage** - Where data flows from/to not tracked
5. **Code Execution Contexts** - Init scripts, notebooks, pipelines not analyzed
6. **Hybrid Connectivity** - Self-hosted runtimes, Arc, on-prem connections incomplete
7. **Network Isolation** - VNet injection, private endpoints inconsistent
8. **Governance** - Unity Catalog, data classification, retention policies missing
9. **Monitoring** - Diagnostic logs, metrics, alerts not tracked
10. **Credential Management** - How secrets are stored (Key Vault vs plaintext) not checked

### Recommended New Platform Services Modules

```markdown
NEW MODULE SUGGESTIONS:

1. **DATA-FLOW-ANALYSIS Module**
   - Map data movement across all services
   - Data Factory pipelines → Databricks → Synapse → Storage
   - Identify data exfiltration paths
   - Track sensitive data movement

2. **SECRETS-IN-CODE Module**
   - Scan notebooks (Databricks, Synapse, ML)
   - Scan pipeline definitions (Data Factory, Logic Apps)
   - Scan init scripts (Databricks, HDInsight)
   - Scan configuration values (App Configuration, Function Apps)
   - Flag hardcoded credentials

3. **REAL-TIME-SERVICES Module**
   - Consolidated view of Event Hubs, Service Bus, IoT Hub
   - Message flow analysis
   - Consumer group enumeration
   - Throughput and scaling configuration

4. **ML-SECURITY Module**
   - Machine Learning workspace security posture
   - Model endpoint exposure
   - Datastore credential analysis
   - Compute instance access

5. **HYBRID-CONNECTIVITY Module**
   - Self-hosted integration runtimes (Data Factory)
   - Arc-enabled resources
   - On-premises data gateways
   - VPN/ExpressRoute paths
```

---

## PLATFORM SERVICES ATTACK SURFACE MATRIX

| Service | Critical Vectors | Data Exfiltration | Privilege Escalation | Code Execution |
|---------|-----------------|-------------------|---------------------|----------------|
| Data Factory | Linked services, Self-hosted IR | Pipeline copy activities | MI + RBAC | Pipeline execution |
| Databricks | Notebooks, Secrets, PATs | DBFS, Delta tables | MI + RBAC, Cluster access | Notebook execution |
| HDInsight | SSH access, Script actions | HDFS, Hive queries | ESP users, MI + RBAC | Script actions |
| IoT Hub | Device connection strings | D2C messages, File upload | Shared access policies | N/A |
| Stream Analytics | Input/output credentials | Output sinks | MI + RBAC | UDF functions |
| Event Hub | SAS policies | Consumer applications | Namespace keys | N/A |

---

## NEXT SESSIONS PLAN

**Session 7:** DevOps & Management Modules (Azure DevOps Projects/Repos/Pipelines/Artifacts, Automation, Policy, Deployments, Inventory, Access Keys, Whoami)
**Session 8:** Final Consolidated Recommendations + Missing Azure Services + Implementation Roadmap

---

**END OF SESSION 6**

*Next session will analyze DevOps & Management modules*
