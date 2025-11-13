# Azure CloudFox Security Module Analysis - SESSION 5
## Database Security Analysis

**Document Version:** 1.0
**Last Updated:** 2025-01-12
**Analysis Session:** 5 of Multiple
**Focus Area:** Database Resources

---

## SESSION 5 OVERVIEW: Database Modules

This session analyzes Azure database modules to identify security gaps, missing features, and enhancement opportunities for offensive security assessments.

### Modules Analyzed in This Session:
1. **Databases** - SQL Server, MySQL, PostgreSQL, CosmosDB
2. **Redis** - Azure Cache for Redis
3. **Synapse** - Azure Synapse Analytics (SQL pools, Spark pools)

---

## 1. DATABASES Module (`databases.go`)

**Current Capabilities:**
- Comprehensive database enumeration across multiple types:
  - Azure SQL Database & SQL Server
  - MySQL (Single Server, Flexible Server)
  - PostgreSQL (Single Server, Flexible Server)
  - CosmosDB (all APIs: SQL, MongoDB, Cassandra, Gremlin, Table)
- Firewall rule enumeration per database
- Admin credentials (admin username)
- Public vs private network access
- SSL/TLS enforcement status
- Entra ID authentication status
- Managed identity enumeration
- Generates extensive loot files:
  - Firewall manipulation commands
  - Database backup access commands
  - Connection strings
  - Data exfiltration scripts
  - Targeted port scanning commands

**Security Gaps Identified:**
1. ❌ **No Database Encryption Status** - TDE (Transparent Data Encryption) not checked
2. ❌ **No Advanced Threat Protection** - ATP/Microsoft Defender for SQL status
3. ❌ **No Auditing Configuration** - SQL auditing and diagnostic logs
4. ❌ **No Vulnerability Assessment** - VA scan results and findings
5. ❌ **No Data Classification** - Sensitive data discovery and classification
6. ❌ **No Dynamic Data Masking** - DDM rules and masked columns
7. ❌ **No Long-Term Retention Backup** - LTR backup configuration
8. ❌ **No Geo-Replication Configuration** - Read replicas, failover groups
9. ❌ **No Elastic Pool Configuration** - Shared resource pools
10. ❌ **No Customer-Managed Key Encryption** - BYOK status
11. ❌ **No Private Endpoint Details** - Private Link connections
12. ❌ **No SQL MI (Managed Instance)** - SQL Managed Instance not covered
13. ❌ **No Database Size and DTU** - Resource utilization metrics
14. ❌ **No Database Users and Roles** - Internal database principals
15. ❌ **No Ledger Configuration** - Immutable ledger table status
16. ❌ **No Always Encrypted** - Column-level encryption status
17. ❌ **No Row-Level Security** - RLS policies
18. ❌ **No Database Principals** - Contained database users
19. ❌ **No CosmosDB Consistency Level** - Read consistency configuration
20. ❌ **No CosmosDB Throughput** - RU/s provisioned vs autoscale

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add TDE (Transparent Data Encryption) status per database
- [ ] Add Advanced Threat Protection / Microsoft Defender for SQL status
- [ ] Add auditing configuration (audit logs destination, retention)
- [ ] Add vulnerability assessment status and last scan date
- [ ] Add customer-managed key encryption status (BYOK, Key Vault)
- [ ] Add private endpoint enumeration and DNS configuration
- [ ] Add SQL Managed Instance enumeration (separate service)
- [ ] Add geo-replication and failover group configuration
- [ ] Add public network access validation (should be disabled)
- [ ] Add firewall rule overpermission detection (0.0.0.0-255.255.255.255)

HIGH PRIORITY:
- [ ] Add data classification status (sensitive data columns)
- [ ] Add dynamic data masking rules and masked columns
- [ ] Add long-term retention backup policy
- [ ] Add elastic pool configuration (for SQL Database)
- [ ] Add database size, DTU/vCore, and resource utilization
- [ ] Add database users and roles (query internal principals)
- [ ] Add Always Encrypted configuration (encrypted columns)
- [ ] Add row-level security policies
- [ ] Add ledger configuration (ledger tables, digest storage)
- [ ] Add database-level firewall rules (not just server-level)
- [ ] Add CosmosDB consistency level (Strong, Bounded, Session, Consistent Prefix, Eventual)
- [ ] Add CosmosDB throughput (RU/s, autoscale vs manual)
- [ ] Add CosmosDB partition key strategy
- [ ] Add CosmosDB analytical store status (Synapse Link)

MEDIUM PRIORITY:
- [ ] Add database collation settings
- [ ] Add database compatibility level (SQL)
- [ ] Add database backup retention period
- [ ] Add point-in-time restore capability
- [ ] Add automatic tuning status (SQL Database)
- [ ] Add query performance insights configuration
- [ ] Add service tier and compute size
- [ ] Add zone redundancy configuration
- [ ] Add CosmosDB regions and multi-region write
- [ ] Add CosmosDB backup policy (continuous vs periodic)
- [ ] Add MySQL/PostgreSQL server parameters (security settings)
- [ ] Add PostgreSQL extensions installed
- [ ] Add database maintenance windows
```

**Attack Surface Considerations:**
- Public network access = internet-accessible databases
- Firewall rule 0.0.0.0/0 = global accessibility
- No Advanced Threat Protection = undetected SQL injection
- No auditing = no attack visibility
- TDE disabled = data at rest exposure
- No private endpoints = network-level access
- Weak admin passwords = brute force opportunity
- SSL not enforced = man-in-the-middle attacks
- Firewall manipulation = attacker can add their IP
- Backup access = historical data exfiltration
- No encryption with CMK = Microsoft-managed keys only

---

## 2. REDIS Module (`redis.go`)

**Current Capabilities:**
- Redis cache instance enumeration
- Endpoint and port configuration (SSL, non-SSL)
- SKU details (Basic, Standard, Premium)
- Public vs private network access
- SSL enforcement status
- Access key retrieval (primary, secondary)
- Managed identity enumeration
- Generates loot files:
  - Redis CLI connection commands
  - Connection strings with keys
  - Redis access commands

**Security Gaps Identified:**
1. ❌ **No Redis Version** - Redis server version not shown
2. ❌ **No Cluster Configuration** - Whether clustering is enabled
3. ❌ **No Persistence Configuration** - RDB/AOF persistence settings
4. ❌ **No Eviction Policy** - Memory eviction strategy
5. ❌ **No Firewall Rules** - IP-based access control
6. ❌ **No VNet Integration** - VNet injection status (Premium)
7. ❌ **No Data Encryption at Rest** - Encryption configuration
8. ❌ **No Data Persistence Status** - Whether data survives reboots
9. ❌ **No Geo-Replication** - Active geo-replication status (Premium)
10. ❌ **No Zone Redundancy** - Availability zone distribution
11. ❌ **No Diagnostic Logs** - Log Analytics integration
12. ❌ **No Key Rotation History** - When keys were last rotated
13. ❌ **No Maxmemory Policy** - Memory limit and eviction behavior
14. ❌ **No Redis Modules** - Installed Redis modules (RediSearch, etc.)
15. ❌ **No Private Endpoint Details** - Private Link connections

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add Redis version (identify outdated/vulnerable versions)
- [ ] Add firewall rule enumeration (allowed IP ranges)
- [ ] Add private endpoint configuration and DNS
- [ ] Add VNet integration status (Premium tier)
- [ ] Add public network access enforcement
- [ ] Add SSL minimum version (TLS 1.0, 1.1, 1.2)
- [ ] Add access key rotation recommendations (last rotated date)

HIGH PRIORITY:
- [ ] Add cluster configuration (cluster mode, shard count)
- [ ] Add persistence configuration (RDB, AOF, both, none)
- [ ] Add eviction policy (allkeys-lru, volatile-lru, etc.)
- [ ] Add maxmemory configuration and policy
- [ ] Add geo-replication status (active geo-replication, replicas)
- [ ] Add zone redundancy configuration
- [ ] Add diagnostic settings (Log Analytics, Storage, Event Hub)
- [ ] Add data encryption at rest status
- [ ] Add Redis modules installed (RediSearch, RedisJSON, etc.)
- [ ] Add patching schedule (maintenance window)

MEDIUM PRIORITY:
- [ ] Add Redis configuration parameters (non-default settings)
- [ ] Add memory usage and fragmentation ratio
- [ ] Add connection limits (max clients)
- [ ] Add slowlog configuration
- [ ] Add Redis Insights configuration
- [ ] Add export/import configuration
- [ ] Add scheduled updates configuration
```

**Attack Surface Considerations:**
- Public network access = internet-exposed cache
- Non-SSL port enabled = plaintext traffic
- Weak access keys = brute force opportunity
- No firewall rules = unrestricted access
- No VNet integration = no network isolation
- Outdated Redis version = known vulnerabilities
- No persistence = data loss on restart
- No key rotation = long-lived credentials
- Access keys exposed = full data access

---

## 3. SYNAPSE Module (`synapse.go`)

**Current Capabilities:**
- Synapse workspace enumeration
- SQL pool enumeration (dedicated SQL pools)
- Spark pool enumeration (big data pools)
- Connectivity endpoints (web, SQL, SQL on-demand, dev)
- Public vs private network access
- Entra ID-only authentication status
- Managed identity enumeration
- Generates loot files:
  - Synapse connection strings
  - Access commands

**Security Gaps Identified:**
1. ❌ **No SQL Pool Encryption** - TDE status on dedicated SQL pools
2. ❌ **No Synapse SQL Auditing** - Auditing configuration
3. ❌ **No Synapse Advanced Threat Protection** - ATP status
4. ❌ **No Spark Pool Configuration** - Node size, auto-scale, auto-pause
5. ❌ **No Synapse Pipelines** - Data integration pipeline enumeration
6. ❌ **No Linked Services** - External data source connections
7. ❌ **No Synapse Notebooks** - Stored notebooks with potential secrets
8. ❌ **No SQL Scripts** - Stored SQL scripts
9. ❌ **No Data Lake Storage Gen2** - Primary ADLS Gen2 account
10. ❌ **No Firewall Rules** - IP-based access control
11. ❌ **No Private Endpoints** - Private Link configuration
12. ❌ **No Synapse Role Assignments** - Workspace-level RBAC
13. ❌ **No SQL Pool Size and DWU** - Data warehouse units
14. ❌ **No Integration Runtimes** - Self-hosted IR, Azure IR
15. ❌ **No Synapse Git Integration** - Source control configuration
16. ❌ **No Managed Private Endpoints** - Workspace-managed private endpoints
17. ❌ **No Spark Libraries** - Custom libraries and packages
18. ❌ **No SQL Pool Vulnerability Assessment** - VA scan status
19. ❌ **No Customer-Managed Keys** - Workspace encryption with CMK
20. ❌ **No Purview Integration** - Data catalog and lineage

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add SQL pool TDE encryption status
- [ ] Add Synapse SQL auditing configuration
- [ ] Add Advanced Threat Protection status
- [ ] Add firewall rule enumeration (IP allow list)
- [ ] Add private endpoint configuration per workspace
- [ ] Add managed private endpoints (workspace-managed)
- [ ] Add Entra ID admin configuration (SQL admin)
- [ ] Add customer-managed key encryption status (workspace)
- [ ] Add public network access enforcement
- [ ] Add SQL pool vulnerability assessment status

HIGH PRIORITY:
- [ ] Add Spark pool configuration (node size, count, auto-scale, auto-pause)
- [ ] Add Synapse pipelines enumeration (data movement, transformation)
- [ ] Add linked services enumeration (connection strings, credentials)
- [ ] Add integration runtimes (self-hosted IR = on-prem connectivity)
- [ ] Add Synapse notebooks (may contain secrets, code)
- [ ] Add SQL scripts (stored queries, procedures)
- [ ] Add Data Lake Storage Gen2 primary account
- [ ] Add SQL pool size (DWU, compute tier)
- [ ] Add Synapse workspace-level RBAC (Synapse Administrator, etc.)
- [ ] Add Synapse Git integration (repo, branch, root folder)
- [ ] Add Spark libraries and packages (custom dependencies)
- [ ] Add SQL pool database-level users and roles

MEDIUM PRIORITY:
- [ ] Add Synapse monitoring configuration (Log Analytics)
- [ ] Add Spark pool library requirements
- [ ] Add Spark pool session-level packages
- [ ] Add SQL pool workload management (resource classes, groups)
- [ ] Add Synapse workspace identity federation
- [ ] Add Purview integration status (data catalog)
- [ ] Add Synapse Link for Cosmos DB
- [ ] Add data exfiltration prevention settings
- [ ] Add column-level security (SQL pools)
- [ ] Add row-level security (SQL pools)
- [ ] Add dynamic data masking (SQL pools)
```

**Attack Surface Considerations:**
- Public network access = internet-accessible analytics workspace
- SQL pools without TDE = data at rest exposure
- No firewall rules = unrestricted access
- Linked services = external system credentials
- Integration runtimes = hybrid connectivity vectors
- Notebooks = embedded secrets and code
- SQL scripts = stored procedures with logic
- Managed identity = Azure privilege escalation
- Pipelines = data movement and transformation logic
- No auditing = no visibility into queries and access
- No ATP = SQL injection and anomaly detection disabled

---

## SESSION 5 SUMMARY: Database Module Gaps

### Critical Gaps Across Database Modules

1. **Encryption Posture** - TDE, Always Encrypted, CMK not consistently tracked
2. **Threat Detection** - Advanced Threat Protection / Defender for SQL missing
3. **Auditing and Monitoring** - Audit logs, diagnostic settings not analyzed
4. **Vulnerability Management** - VA scan status and findings not integrated
5. **Network Security** - Private endpoints, firewall rules incomplete
6. **Data Classification** - Sensitive data discovery not performed
7. **Access Control Granularity** - Database-level users, roles, RLS, DDM missing
8. **Backup and DR** - LTR, geo-replication, failover groups not detailed
9. **Compliance Features** - Ledger, data retention policies not checked
10. **Internal Configuration** - Database parameters, extensions, modules not enumerated

### Recommended New Database Modules

```markdown
NEW MODULE SUGGESTIONS:

1. **DATABASE-SECURITY Module**
   - Consolidated security posture across all database types
   - Encryption status (TDE, Always Encrypted, CMK)
   - Advanced Threat Protection status
   - Auditing configuration
   - Vulnerability assessment findings
   - Data classification results
   - Dynamic data masking rules
   - Row-level security policies

2. **DATABASE-BACKUP Module**
   - Backup retention policies
   - Long-term retention backups
   - Geo-redundant backup status
   - Point-in-time restore capability
   - Last backup date and size
   - Backup encryption status
   - Backup access audit (who accessed backups)

3. **DATABASE-REPLICATION Module**
   - Geo-replication configuration
   - Failover groups and policies
   - Read replicas and endpoints
   - Multi-region write configuration (CosmosDB)
   - Replication lag monitoring
   - Failover history

4. **SQL-MANAGED-INSTANCE Module** (Currently completely missing!)
   - SQL MI instance enumeration
   - VNet integration (always VNet-injected)
   - Instance collation and version
   - Instance pools
   - Failover groups
   - TDE and CMK configuration
   - Time zone configuration
   - Instance-level settings

5. **DATABASE-CREDENTIALS Module**
   - All database connection strings
   - Admin usernames (no passwords)
   - Entra ID admin configuration
   - Contained database users
   - Firewall rule effectiveness (can current user connect?)
   - Service principal database access
   - Managed identity database roles

6. **COSMOSDB-ADVANCED Module**
   - Consistency level per account
   - Throughput configuration (RU/s, autoscale)
   - Partition key strategies
   - Indexing policies
   - Analytical store status (Synapse Link)
   - Multi-region configuration
   - Cosmos API type analysis
   - Cosmos Cassandra keyspaces
   - Cosmos Gremlin graphs
   - Cosmos Table API tables
```

---

## DATABASE ATTACK SURFACE MATRIX

| Database Type | Critical Vectors | Data Exfiltration | Privilege Escalation | Persistence |
|---------------|-----------------|-------------------|---------------------|-------------|
| SQL Database | Public access, 0.0.0.0/0 firewall | Backup download, SQL query | Managed identity + RBAC | Firewall rule injection |
| MySQL/PostgreSQL | Public access, weak admin password | mysqldump, pg_dump | Server parameters, UDF | Firewall rule addition |
| CosmosDB | Global public access | Bulk export, change feed | Account keys, MI + RBAC | Account key regeneration |
| Redis | No firewall, non-SSL port | DUMP command, KEYS * | N/A | Access key static |
| Synapse | Public workspace, SQL pool | CETAS, pipelines | Linked services, MI | Notebook code injection |

---

## DATABASE DATA EXFILTRATION MATRIX

| Service | Exfiltration Method | Detection Difficulty | Prerequisites |
|---------|-------------------|---------------------|---------------|
| SQL Database | Backup download via SAS URL | Low (logged if auditing enabled) | Database backup permission |
| SQL Database | SELECT INTO OUTFILE / BCP | Medium | Database read permission |
| SQL Database | SQL injection + UNION | High | Vulnerable application |
| MySQL/PostgreSQL | mysqldump / pg_dump | Low | Database credentials |
| MySQL/PostgreSQL | SELECT INTO OUTFILE | Medium | FILE privilege (MySQL) |
| CosmosDB | Bulk export via SDK | Low | Account key or Data Reader role |
| CosmosDB | Change feed consumption | High | Read permission |
| Redis | DUMP all keys | Low | Access key |
| Redis | SAVE RDB file | Low | Access key + file access |
| Synapse SQL Pool | CETAS (external table) | Medium | External data source + credential |
| Synapse | Pipeline copy activity | Low | Pipeline create permission |

---

## DATABASE SECURITY POSTURE CHECKLIST

### Network Security
- [ ] All databases use private endpoints
- [ ] Public network access disabled
- [ ] Firewall rules restrictive (no 0.0.0.0/0)
- [ ] VNet integration enabled (Redis Premium, SQL MI)
- [ ] SSL/TLS enforcement enabled

### Encryption
- [ ] TDE enabled on all SQL databases/pools
- [ ] Always Encrypted for sensitive columns
- [ ] Customer-managed keys (BYOK) where required
- [ ] Redis data encryption at rest
- [ ] CosmosDB encryption with CMK

### Threat Detection
- [ ] Microsoft Defender for SQL enabled
- [ ] Advanced Threat Protection configured
- [ ] Vulnerability Assessment running
- [ ] Suspicious activity alerts configured

### Auditing
- [ ] SQL auditing enabled
- [ ] Diagnostic logs sent to Log Analytics
- [ ] Audit retention meets compliance requirements
- [ ] Database access logging enabled

### Access Control
- [ ] Entra ID authentication enforced
- [ ] No SQL authentication (username/password)
- [ ] Managed identities for application access
- [ ] Row-level security implemented
- [ ] Dynamic data masking configured

---

## NEXT SESSIONS PLAN

**Session 6:** Platform Services (Data Factory, Databricks, HDInsight, IoT Hub, Stream Analytics, Event Hubs, Service Bus, etc.)
**Session 7:** DevOps & Management Modules (Azure DevOps, Automation, Policy, Deployments, Monitor, Resource Graph)
**Session 8:** Missing Azure Services & Final Consolidated Recommendations + Implementation Priorities

---

**END OF SESSION 5**

*Next session will analyze Platform Services (Data Factory, Databricks, IoT Hub, and more)*
