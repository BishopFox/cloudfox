# Azure CloudFox Security Module Analysis - SESSION 3
## Storage & Data Resources Security Analysis

**Document Version:** 1.0
**Last Updated:** 2025-01-12
**Analysis Session:** 3 of Multiple
**Focus Area:** Storage & Data Resources

---

## SESSION 3 OVERVIEW: Storage & Data Modules

This session analyzes Azure storage and data-related modules to identify security gaps, missing features, and enhancement opportunities for offensive security assessments.

### Modules Analyzed in This Session:
1. **Storage** - Storage Accounts (Blob, File, Table, Queue)
2. **Key Vaults** - Secret, key, and certificate management
3. **Disks** - Managed Disks
4. **Filesystems** - Azure Files & NetApp Files
5. **ACR** - Azure Container Registry

---

## 1. STORAGE Module (`storage.go`)

**Current Capabilities:**
- Comprehensive storage account enumeration
- Container and blob enumeration
- File share enumeration
- Table and queue enumeration
- Public access level detection (container, blob, none)
- Network access rules (firewall, VNets)
- Storage account keys retrieval
- SAS token generation capabilities
- Managed identity enumeration
- Generates extensive loot files:
  - Publicly accessible blob URLs
  - Storage access commands with keys
  - SAS token generation examples
  - Data exfiltration scripts

**Security Gaps Identified:**
1. ❌ **No Encryption Status** - No detection of encryption at rest configuration (CMK vs Microsoft-managed)
2. ❌ **No Blob Versioning Status** - Whether versioning is enabled for immutability
3. ❌ **No Blob Soft Delete Status** - Recoverability of deleted blobs
4. ❌ **No Lifecycle Management Policies** - Automatic blob tiering/deletion rules
5. ❌ **No Static Website Configuration** - Whether storage account hosts static site
6. ❌ **No CORS Configuration** - Cross-origin resource sharing rules
7. ❌ **No Anonymous Blob Detection** - Specific blobs allowing anonymous access
8. ❌ **No Shared Access Signature Enumeration** - Existing SAS tokens not listed
9. ❌ **No Access Tier Detection** - Hot, Cool, Archive tier per blob
10. ❌ **No Blob Metadata Analysis** - Custom metadata may contain secrets
11. ❌ **No Immutable Storage (WORM)** - Write-once-read-many policy status
12. ❌ **No Azure AD Authentication Status** - Whether AAD auth is enforced
13. ❌ **No Storage Logging Analysis** - Storage Analytics logging configuration
14. ❌ **No Blob Snapshot Enumeration** - Blob snapshots contain historical data
15. ❌ **No Cross-Tenant Replication** - Object replication to other accounts
16. ❌ **No Large File Share Status** - Premium vs standard file shares
17. ❌ **No NFS 3.0 Protocol Status** - NFS-enabled blob containers
18. ❌ **No SFTP Configuration** - SFTP endpoint exposure
19. ❌ **No Data Lake Gen2 Hierarchical Namespace** - ADLS Gen2 features
20. ❌ **No Table/Queue Access Policies** - Stored access policies on tables/queues

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add encryption status (CMK vs Microsoft-managed, Key Vault URI)
- [ ] Add blob-level anonymous access detection (scan for public blobs within private containers)
- [ ] Add static website configuration (exposed web content, error documents)
- [ ] Add CORS configuration analysis (wildcard origins = security issue)
- [ ] Add SFTP endpoint detection (username/password auth risk)
- [ ] Add NFS 3.0 protocol detection (weak auth, network exposure)
- [ ] Add Azure AD authentication enforcement status (shared key allowed?)
- [ ] Add storage account failover configuration (GRS, RA-GRS exposure)
- [ ] Add existing SAS token enumeration (via stored access policies)
- [ ] Add immutable storage (WORM) policy detection

HIGH PRIORITY:
- [ ] Add blob versioning and soft delete status
- [ ] Add lifecycle management policy analysis (auto-delete rules)
- [ ] Add blob access tier per blob (archive = exfiltration time)
- [ ] Add blob metadata enumeration (may contain secrets)
- [ ] Add blob snapshot enumeration (historical data access)
- [ ] Add object replication configuration (cross-tenant replication)
- [ ] Add storage analytics logging configuration (audit log availability)
- [ ] Add large file share status (premium file shares)
- [ ] Add Data Lake Gen2 hierarchical namespace detection
- [ ] Add customer-managed key rotation status
- [ ] Add table/queue stored access policy enumeration
- [ ] Add blob index tags (searchable metadata)

MEDIUM PRIORITY:
- [ ] Add container lease status (locked containers)
- [ ] Add blob lease status (locked blobs)
- [ ] Add last access tracking status (identify unused data)
- [ ] Add blob change feed status (audit trail)
- [ ] Add point-in-time restore configuration
- [ ] Add Azure Files identity-based authentication (AD DS, Azure AD)
- [ ] Add network routing preference (Microsoft vs Internet routing)
- [ ] Add blob inventory policy (metadata at scale)
```

**Attack Surface Considerations:**
- Public blob containers = data exposure
- Storage account keys = full data access
- SAS tokens = scoped but powerful access
- No IP restrictions = internet-accessible storage
- Managed identities = privilege escalation to storage
- Static websites = web application hosting
- SFTP endpoints = SSH-based access with password auth
- NFS 3.0 = weak authentication protocol
- CORS misconfiguration = XSS attacks
- Blob snapshots = historical data access
- Cross-tenant replication = data leakage
- Weak encryption = data at rest compromise

---

## 2. KEYVAULTS Module (`keyvaults.go`)

**Current Capabilities:**
- Key Vault enumeration
- Secret enumeration (names only, not values by default)
- Key enumeration
- Certificate enumeration
- Access policy enumeration (identities with permissions)
- Network access rules (firewall, private endpoints)
- Soft delete and purge protection status
- RBAC vs access policy mode detection
- Managed HSM detection
- Generates loot files:
  - Secret access commands
  - Key access commands
  - Certificate download commands
  - Access policy details

**Security Gaps Identified:**
1. ❌ **No Secret Value Extraction** - Secret values not automatically retrieved
2. ❌ **No Certificate Private Key Extraction** - Private keys not downloaded
3. ❌ **No Key Exportability Status** - Whether keys can be exported
4. ❌ **No Secret/Key/Certificate Expiration Dates** - Expiration tracking
5. ❌ **No Secret/Key/Certificate Tags** - Metadata analysis
6. ❌ **No Secret/Key/Certificate Enabled Status** - Whether item is active
7. ❌ **No Secret Version History** - Multiple secret versions
8. ❌ **No Key Rotation Policy** - Automatic key rotation configuration
9. ❌ **No Diagnostic Settings** - Logging and monitoring configuration
10. ❌ **No Private Endpoint DNS Resolution** - Private DNS zone configuration
11. ❌ **No Access Policy Overpermissions** - Principals with List+Get on all secrets
12. ❌ **No Managed Identity Access** - Which managed identities have access
13. ❌ **No Key Vault References** - App Services/Functions referencing this vault
14. ❌ **No Managed HSM Pool Details** - HSM security domain, activation status
15. ❌ **No Key Vault Backup Status** - Whether vault can be backed up
16. ❌ **No Certificate Issuers** - Integrated CAs (DigiCert, GlobalSign)
17. ❌ **No Certificate Auto-Renewal** - Automatic renewal configuration
18. ❌ **No Key Operations Logging** - Whether all operations are logged
19. ❌ **No Deleted Vaults Enumeration** - Soft-deleted Key Vaults (recoverable)
20. ❌ **No Key Vault Network Exposure Score** - Public, private, or hybrid

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add secret value extraction (with opt-in flag, requires permission)
- [ ] Add certificate private key export (PFX format, requires permission)
- [ ] Add secret/key/certificate expiration analysis (expired = unused access)
- [ ] Add access policy overpermission detection (List+Get = full secret access)
- [ ] Add managed identity access tracking (which MIs have vault access)
- [ ] Add deleted Key Vault enumeration (soft-deleted vaults can be recovered)
- [ ] Add network exposure analysis (public vs private endpoint only)
- [ ] Add diagnostic settings analysis (audit log configuration)
- [ ] Add purge protection status (permanent delete protection)

HIGH PRIORITY:
- [ ] Add key exportability status (non-exportable keys = HSM-backed)
- [ ] Add secret/key/certificate enabled status (disabled items)
- [ ] Add secret/key version history (multiple versions = secret rotation)
- [ ] Add key rotation policy configuration (automatic rotation)
- [ ] Add secret/key/certificate tags analysis (may contain sensitive metadata)
- [ ] Add private endpoint DNS configuration (DNS resolution issues)
- [ ] Add Key Vault references (which resources reference this vault)
- [ ] Add certificate issuer configuration (CA integration)
- [ ] Add certificate auto-renewal status
- [ ] Add Managed HSM security domain and activation status
- [ ] Add RBAC role assignment analysis (vs access policies)
- [ ] Add Key Vault firewall bypass settings (trusted services)

MEDIUM PRIORITY:
- [ ] Add key operations logging verification
- [ ] Add Key Vault backup capability (whether backup is enabled)
- [ ] Add Key Vault geo-replication status
- [ ] Add Key Vault ARM template deployment history
- [ ] Add Key Vault activity log analysis (recent access)
- [ ] Add certificate thumbprint and validity analysis
- [ ] Add secret content type detection (password, connection string, etc.)
```

**Attack Surface Considerations:**
- Public Key Vaults = network-accessible secrets
- Access policies with Get+List = full secret exfiltration
- Expired certificates = service disruption
- No purge protection = permanent deletion risk
- Managed identities with vault access = privilege escalation
- Secret versions = historical credentials
- Certificate private keys = TLS credential compromise
- Soft-deleted vaults = data recovery opportunity
- No diagnostic logging = no audit trail
- Key exportability = key extraction risk

---

## 3. DISKS Module (`disks.go`)

**Current Capabilities:**
- Managed disk enumeration
- Disk size and state (attached, unattached)
- OS type detection (Windows, Linux)
- Encryption type and status
- VM attachment status (which VM uses the disk)
- Resource group and region
- Identifies unencrypted disks in loot file
- Generates commands for:
  - Disk inspection
  - Snapshot creation
  - Encryption enablement

**Security Gaps Identified:**
1. ❌ **No Disk Snapshot Enumeration** - Existing disk snapshots not listed
2. ❌ **No Disk Snapshot Access SAS URLs** - How to access snapshot data
3. ❌ **No Disk Export Capability Detection** - Whether disk can be exported
4. ❌ **No Disk Backup Status** - Whether disk is backed up
5. ❌ **No Customer-Managed Key Details** - Key Vault, key name, key version
6. ❌ **No Disk Access Resource** - Private endpoint configuration
7. ❌ **No Public Network Access Status** - Whether disk allows public access
8. ❌ **No Disk Bursting Configuration** - Performance tier
9. ❌ **No Disk Tier** - Premium SSD, Standard SSD, Standard HDD
10. ❌ **No Disk IOPS and Throughput** - Performance characteristics
11. ❌ **No Disk Incremental Snapshots** - Incremental snapshot capability
12. ❌ **No Disk Gallery Image Version** - Source image if from gallery
13. ❌ **No Disk Creation Source** - Created from snapshot, image, import, empty
14. ❌ **No Disk Tags Analysis** - Metadata may indicate purpose/sensitivity
15. ❌ **No Unattached Disk Detection** - Orphaned disks = forgotten data

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add disk snapshot enumeration (snapshots = point-in-time data copies)
- [ ] Add disk snapshot SAS URL generation (data exfiltration opportunity)
- [ ] Add unattached disk detection and highlighting (orphaned data)
- [ ] Add customer-managed key details (Key Vault, key name, rotation status)
- [ ] Add disk access resource configuration (private endpoint exposure)
- [ ] Add public network access status (internet-accessible disks)
- [ ] Add disk export capability (VHD export for offline analysis)
- [ ] Add disk creation source analysis (import = external data source)

HIGH PRIORITY:
- [ ] Add disk backup status and recovery vault association
- [ ] Add disk tier classification (Premium vs Standard)
- [ ] Add disk IOPS and throughput limits (performance indicators)
- [ ] Add incremental snapshot capability
- [ ] Add disk gallery image version (source image tracking)
- [ ] Add disk tags analysis (environment, owner, sensitivity)
- [ ] Add disk bursting configuration (on-demand performance)
- [ ] Add disk last attachment timestamp (when was disk last used)
- [ ] Add disk size optimization recommendations (underutilized disks)
- [ ] Add disk encryption set configuration (multiple disks, one key)

MEDIUM PRIORITY:
- [ ] Add disk availability zone configuration
- [ ] Add disk network access policy (private endpoint only)
- [ ] Add disk shareable configuration (shared disks)
- [ ] Add disk logical sector size (512 vs 4096)
- [ ] Add disk provisioning state (succeeded, failed, creating)
- [ ] Add disk hyperV generation (V1 vs V2)
```

**Attack Surface Considerations:**
- Unencrypted disks = data at rest exposure
- Unattached disks = forgotten data with historical information
- Disk snapshots = point-in-time data copies
- Public network access = internet-accessible disk data
- Disk export = VHD download for offline analysis
- Customer-managed key access = decrypt all disks
- Incremental snapshots = efficient data exfiltration
- Shared disks = multi-VM access to same data

---

## 4. FILESYSTEMS Module (`filesystems.go`)

**Current Capabilities:**
- Azure Files share enumeration
- Azure NetApp Files volume enumeration
- DNS name and IP address resolution
- Mount target identification
- Authentication policy detection
- Generates loot files:
  - SMB mount commands (Azure Files)
  - NFS mount commands (NetApp Files)
  - File share access commands

**Security Gaps Identified:**
1. ❌ **No Azure Files Share Quota** - Maximum share size configuration
2. ❌ **No Azure Files Share Snapshots** - Point-in-time snapshots
3. ❌ **No Azure Files Access Tier** - Transaction optimized, hot, cool
4. ❌ **No Azure Files Protocol Support** - SMB vs NFS vs both
5. ❌ **No Azure Files Identity-Based Auth** - AD DS, Azure AD integration
6. ❌ **No Azure Files Root Squash** - NFS root squash configuration
7. ❌ **No Azure Files Share-Level Permissions** - SMB ACLs
8. ❌ **No Azure Files Encryption at Rest** - Encryption configuration
9. ❌ **No NetApp Files Volume Capacity** - Volume size and usage
10. ❌ **No NetApp Files Volume Throughput** - Performance tier
11. ❌ **No NetApp Files Snapshot Policy** - Automatic snapshot schedule
12. ❌ **No NetApp Files Export Policy** - NFS export rules and restrictions
13. ❌ **No NetApp Files Volume Backup Status** - Backup configuration
14. ❌ **No NetApp Files Replication Status** - Cross-region replication
15. ❌ **No NetApp Files Service Level** - Standard, Premium, Ultra
16. ❌ **No Azure Files Public Endpoint Exposure** - Internet accessibility
17. ❌ **No Azure Files Storage Account Firewall** - Network restrictions
18. ❌ **No Azure Files Kerberos Auth** - On-premises AD authentication

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add Azure Files protocol support detection (SMB 3.0, NFS 4.1)
- [ ] Add Azure Files identity-based authentication (AD DS, Azure AD Kerberos)
- [ ] Add Azure Files public endpoint exposure (storage account network rules)
- [ ] Add Azure Files snapshot enumeration (point-in-time recovery)
- [ ] Add NetApp Files export policy analysis (allowed clients, read/write permissions)
- [ ] Add NetApp Files security style (UNIX, NTFS, mixed)
- [ ] Add Azure Files root squash configuration (NFS security)
- [ ] Add Azure Files Kerberos authentication status

HIGH PRIORITY:
- [ ] Add Azure Files share quota and usage
- [ ] Add Azure Files access tier (transaction optimization)
- [ ] Add Azure Files share-level permissions (SMB ACLs)
- [ ] Add Azure Files encryption at rest status
- [ ] Add NetApp Files volume capacity and utilization
- [ ] Add NetApp Files throughput and service level (Standard, Premium, Ultra)
- [ ] Add NetApp Files snapshot policy (automatic snapshots)
- [ ] Add NetApp Files backup status (Azure Backup integration)
- [ ] Add NetApp Files replication status (cross-region DR)
- [ ] Add Azure Files private endpoint configuration
- [ ] Add NetApp Files capacity pool association
- [ ] Add Azure Files SMB multichannel status (performance)

MEDIUM PRIORITY:
- [ ] Add Azure Files metadata (custom properties)
- [ ] Add Azure Files last modified timestamp
- [ ] Add Azure Files soft delete configuration
- [ ] Add Azure Files CORS configuration
- [ ] Add NetApp Files volume tags
- [ ] Add NetApp Files volume placement rules
- [ ] Add NetApp Files QoS type (auto, manual)
- [ ] Add NetApp Files LDAP integration
```

**Attack Surface Considerations:**
- Azure Files without identity auth = network-based access only
- Azure Files public endpoints = internet-accessible file shares
- NFS 4.1 without root squash = root access from clients
- NetApp Files weak export policies = unauthorized NFS mounts
- Azure Files SMB signing not enforced = man-in-the-middle attacks
- File share snapshots = historical data access
- NetApp Files cross-region replication = data in multiple regions
- Azure Files without firewall = unrestricted network access
- Kerberos not enabled = weaker authentication

---

## 5. ACR Module (`acr.go`)

**Current Capabilities:**
- Container registry enumeration
- Repository and image tag enumeration
- Image digest tracking
- Admin user status detection
- Managed identity enumeration (system and user-assigned)
- Generates extensive loot files:
  - Docker login and pull commands
  - Image download and analysis commands
  - Managed identity token extraction via ACR Tasks
  - ACR Task templates for token generation across multiple scopes (ARM, Graph, Key Vault)

**Security Gaps Identified:**
1. ❌ **No Image Vulnerability Scan Results** - Defender for Containers findings
2. ❌ **No Image Signature Verification** - Content trust / Notary v2 status
3. ❌ **No Quarantine Status** - Whether images are quarantined
4. ❌ **No Retention Policy** - Automatic image cleanup rules
5. ❌ **No Webhooks Configuration** - Event-driven actions on push/delete
6. ❌ **No Geo-Replication Configuration** - Multi-region replication
7. ❌ **No Network Access Rules** - Public, private, or hybrid access
8. ❌ **No Customer-Managed Key** - CMK encryption status
9. ❌ **No Scope Map Configuration** - Token-based repository permissions
10. ❌ **No ACR Task Enumeration** - Existing ACR Tasks (build automation)
11. ❌ **No Anonymous Pull Status** - Whether anonymous pulls are allowed
12. ❌ **No Soft Delete Status** - Deleted artifact recovery
13. ❌ **No ACR Token Enumeration** - Repository-scoped tokens
14. ❌ **No Helm Chart Enumeration** - Helm charts in OCI format
15. ❌ **No ORAS Artifact Enumeration** - Non-container artifacts
16. ❌ **No Image Manifest Analysis** - Multi-arch, layers, config
17. ❌ **No Azure Container Registry Cache** - Cached upstream registries
18. ❌ **No Trust Policy Configuration** - Trusted base images
19. ❌ **No Export Pipeline** - Data exfiltration to storage account
20. ❌ **No Import Pipeline** - Data sources from external registries

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add image vulnerability scan results (Defender for Containers / Qualys)
- [ ] Add quarantine status per image (quarantined images blocked from pull)
- [ ] Add anonymous pull status (publicly pullable registries)
- [ ] Add network access rules (public, private endpoint only, firewall rules)
- [ ] Add webhooks configuration (POST endpoints on image events)
- [ ] Add ACR task enumeration (existing tasks may execute code)
- [ ] Add ACR token enumeration (repository-scoped access tokens)
- [ ] Add scope map configuration (token permissions)
- [ ] Add geo-replication configuration (data in multiple regions)
- [ ] Add customer-managed key encryption status

HIGH PRIORITY:
- [ ] Add image signature verification status (Notary v2, content trust)
- [ ] Add retention policy (auto-delete old images)
- [ ] Add soft delete status (deleted artifact recovery window)
- [ ] Add Helm chart enumeration (OCI artifacts)
- [ ] Add ORAS artifact enumeration (SBOMs, signatures, attestations)
- [ ] Add image manifest analysis (layers, architecture, OS)
- [ ] Add trust policy configuration (allowed base images)
- [ ] Add export pipeline configuration (exfiltrate to storage account)
- [ ] Add import pipeline configuration (external registry sync)
- [ ] Add Azure Container Registry cache configuration (upstream mirrors)
- [ ] Add registry SKU (Basic, Standard, Premium)
- [ ] Add data endpoint status (dedicated data endpoints for geo-replicas)

MEDIUM PRIORITY:
- [ ] Add image tag timestamp (last push date)
- [ ] Add image size per tag
- [ ] Add image pull count (usage metrics)
- [ ] Add connected registry configuration (IoT edge scenarios)
- [ ] Add artifact reference tracking (SBOMs, signatures linked to images)
- [ ] Add ACR build history (past build logs)
- [ ] Add agent pool configuration (dedicated build agents)
```

**Attack Surface Considerations:**
- Admin user enabled = static credentials
- Anonymous pull enabled = public image access
- No vulnerability scanning = vulnerable base images
- Managed identity token extraction = Azure privilege escalation via ACR Tasks
- Webhooks = external HTTP callbacks (SSRF risk)
- Geo-replication = data in multiple regions
- Public network access = internet-accessible registry
- ACR Tasks = container-based code execution
- Repository tokens = long-lived credentials
- Export pipeline = data exfiltration to storage account
- Quarantine bypass = malicious image deployment
- No image signing = supply chain attack risk

---

## SESSION 3 SUMMARY: Storage & Data Module Gaps

### Critical Gaps Across Storage & Data Modules

1. **Data Exfiltration Vectors** - Snapshots, backups, export capabilities not fully enumerated
2. **Encryption Posture** - CMK vs Microsoft-managed keys not consistently tracked
3. **Network Exposure** - Public vs private endpoint status incomplete
4. **Access Control Granularity** - Blob-level, file-level, image-level permissions not detailed
5. **Lifecycle Management** - Retention, deletion, archival policies missing
6. **Versioning and Immutability** - Version history and WORM policies not analyzed
7. **Vulnerability Management** - Image scanning results not integrated
8. **Secret Extraction** - Key Vault secret values, certificate private keys not retrieved
9. **Historical Data Access** - Snapshots, versions, soft-deleted items not enumerated
10. **Cross-Service References** - Which compute resources access which storage not tracked

### Recommended New Storage & Data Modules

```markdown
NEW MODULE SUGGESTIONS:

1. **STORAGE-SECURITY Module**
   - Consolidated storage security posture
   - Encryption, public access, CORS, SFTP, NFS exposure
   - SAS token risk analysis
   - Blob-level anonymous access detection
   - Cross-tenant replication risks

2. **DATA-EXFILTRATION-PATHS Module**
   - All data egress mechanisms
   - Snapshots (disk, blob, file share)
   - Backups (VM, database, file)
   - Export capabilities (disk, ACR pipeline)
   - Replication (storage, NetApp, ACR)
   - SAS tokens and access URLs

3. **KEYVAULT-SECRETS-DUMP Module** (Opt-in with explicit user consent)
   - Extract all accessible secret values
   - Download certificate private keys
   - Export keys (if exportable)
   - Secret version history
   - Categorize secrets by type (connection string, API key, password)
   - Identify expired secrets

4. **IMAGE-VULNERABILITY-SCANNER Module**
   - Integrate with Defender for Containers API
   - Pull vulnerability scan results for all ACR images
   - Identify critical CVEs in running containers (AKS, ACI, Container Apps)
   - Map images to running workloads
   - Supply chain risk analysis (base image provenance)

5. **SNAPSHOT-INVENTORY Module**
   - Enumerate ALL snapshots across resources
   - Disk snapshots with access SAS URLs
   - Blob snapshots with access paths
   - File share snapshots with mount commands
   - NetApp snapshots with restore procedures
   - Snapshot age and ownership analysis

6. **ENCRYPTION-POSTURE Module**
   - Encryption status across all storage services
   - Customer-managed key tracking (Key Vault associations)
   - Key rotation status
   - Encryption in transit status (HTTPS only, TLS versions)
   - Unencrypted resource inventory
```

---

## STORAGE ATTACK SURFACE MATRIX

| Resource Type | Critical Vectors | Data Exfiltration | Privilege Escalation | Persistence |
|---------------|-----------------|-------------------|---------------------|-------------|
| Storage Account | Public blobs, Account keys, SAS | Blob copy, Snapshot, AzCopy | Managed identity + RBAC | SAS token with long expiry |
| Key Vault | Public endpoint, Access policies | Secret export, Backup | Managed identity access | No audit logs |
| Managed Disk | Unencrypted, Unattached | Snapshot + export VHD | N/A | Orphaned disks |
| Azure Files | Public endpoint, No auth | SMB/NFS mount, Copy | Identity-based auth bypass | Mount from external network |
| NetApp Files | Weak export policy | NFS mount, Snapshot | Root squash disabled | Persistent NFS mount |
| ACR | Admin user, Anonymous pull | Docker pull, Export pipeline | MI token extraction via Tasks | Webhooks, Tokens |

---

## DATA EXFILTRATION OPPORTUNITY MATRIX

| Service | Exfiltration Method | Detection Difficulty | Prerequisites |
|---------|-------------------|---------------------|---------------|
| Blob Storage | AzCopy with SAS token | Low (logged if diagnostics enabled) | Storage account key or SAS token |
| Blob Storage | Blob snapshot + copy | Low | Snapshot create permission |
| Managed Disk | Snapshot + export SAS | Medium | Disk snapshot permission |
| Managed Disk | Attach to attacker VM | Medium | VM creation, disk attach permission |
| Key Vault | Secret export via script | High | Key Vault Get secret permission |
| ACR | Docker pull all images | Low | ACR pull permission or admin creds |
| ACR | Export pipeline to storage | Medium | ACR export pipeline permission |
| Azure Files | SMB/NFS bulk copy | Low | Storage account key or file permission |
| NetApp Files | NFS recursive copy | Low | Network access, weak export policy |

---

## NEXT SESSIONS PLAN

**Session 4:** Networking Modules (NSG, VNets, Firewalls, App Gateway, Load Balancers, Routes)
**Session 5:** Database Modules (SQL, MySQL, PostgreSQL, CosmosDB, Redis, Synapse)
**Session 6:** Platform Services (Data Factory, Databricks, HDInsight, IoT Hub, etc.)
**Session 7:** DevOps & Management Modules (DevOps, Automation, Policy, Deployments)
**Session 8:** Missing Azure Services & Final Recommendations

---

**END OF SESSION 3**

*Next session will analyze Networking modules (NSG, VNets, Firewalls, routing)*
