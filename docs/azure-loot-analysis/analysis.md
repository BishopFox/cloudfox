# Azure CloudFox Commands - Loot File Comprehensive Analysis

**Analysis Date:** 2025-11-13
**Directory Analyzed:** `azure/commands/`
**Total Modules:** 72
**Modules with Loot Files:** 64 (88.9%)
**Modules WITHOUT Loot Files:** 8 (11.1%) ⚠️
**Total Unique Loot Files:** 261

---

## Executive Summary

This document provides a comprehensive review of loot file implementation across ALL 72 Azure CloudFox command modules in `azure/commands/`. The analysis reveals that **88.9% of modules already have loot files implemented**, which is excellent coverage. However, **8 critical modules are missing loot files**, representing significant gaps in:

- Kubernetes credential extraction (aks.go)
- Storage account key/SAS token commands (storage.go)
- High-privilege RBAC enumeration (rbac.go)
- Dangerous permission abuse paths (permissions.go)
- Federated identity exploitation (federated-credentials.go)
- OAuth consent abuse (consent-grants.go)
- DevOps agent token extraction (devops-agents.go)
- Conditional Access bypass identification (conditional-access.go)

**Key Achievement:** 261 loot files are already implemented across 64 modules, providing actionable commands, credentials, connection strings, and attack paths for security assessments.

---

## 1. CRITICAL GAPS - Modules WITHOUT Loot Files (8 modules)

### 🔴 **CRITICAL Priority**

#### 1.1. **aks.go** - Azure Kubernetes Service
**Category:** Compute / Kubernetes
**Current State:** Enumerates AKS clusters but NO loot files
**Impact:** Cannot extract Kubernetes credentials or access clusters

**Missing Loot Files:**
- `aks-kubeconfig` - kubectl config generation
- `aks-credentials` - Cluster credential extraction commands
- `aks-identity-tokens` - Managed identity token access
- `aks-pod-exec` - Pod execution commands
- `aks-privilege-escalation` - Container escape paths
- `aks-service-principals` - SP credential extraction
- `aks-secrets` - Kubernetes secret enumeration

**Actionable Data Missing:**
```bash
# Critical missing commands
az aks get-credentials --resource-group <rg> --name <cluster>
kubectl get pods --all-namespaces
kubectl exec -it <pod> -- /bin/bash
kubectl get secrets --all-namespaces
az aks show --resource-group <rg> --name <cluster> --query servicePrincipalProfile
```

---

#### 1.2. **storage.go** - Storage Accounts
**Category:** Storage
**Current State:** Enumerates storage accounts and containers but NO loot files
**Impact:** Cannot extract storage keys or generate SAS tokens for data access

**Missing Loot Files:**
- `storage-keys` - Storage account key extraction
- `storage-sas-tokens` - SAS token generation
- `storage-public-blobs` - Public container access URLs
- `storage-download-commands` - Blob/file download scripts
- `storage-mount-commands` - File share mounting (SMB/NFS)
- `storage-data-exfiltration` - Bulk data exfiltration scripts

**Actionable Data Missing:**
```bash
# Critical missing commands
az storage account keys list --account-name <account> --resource-group <rg>
az storage account generate-sas --account-name <account> --services b --resource-types sco --permissions rwdlac
azcopy copy "https://<account>.blob.core.windows.net/<container>" "./local" --recursive
mount -t cifs //<account>.file.core.windows.net/<share> /mnt -o username=<account>,password=<key>
```

---

#### 1.3. **rbac.go** - Role-Based Access Control
**Category:** Identity & Access
**Current State:** Comprehensive RBAC enumeration but NO loot files
**Impact:** Cannot identify high-privilege roles or PIM activation commands

**Missing Loot Files:**
- `rbac-high-privilege` - Owner/Contributor/User Access Administrator assignments
- `rbac-pim-activation` - PIM role activation commands
- `rbac-service-principals` - Service principals with privileged roles
- `rbac-orphaned` - Orphaned role assignments
- `rbac-persistence` - Role assignment scripts for persistence
- `rbac-privilege-escalation` - RBAC-based escalation paths

**Actionable Data Missing:**
```bash
# High-privilege role identification
az role assignment list --role "Owner" --all
az role assignment list --role "Contributor" --all
az role assignment list --role "User Access Administrator" --all

# PIM activation
az role assignment create --role "Owner" --assignee <principal-id> --scope <scope>

# Service principal with Owner role
az ad sp list --all --query "[?servicePrincipalType=='Application']" | jq -r '.[].appId' | xargs -I {} az role assignment list --assignee {}
```

---

#### 1.4. **permissions.go** - Granular Permissions
**Category:** Identity & Access
**Current State:** Granular permission enumeration but NO loot files
**Impact:** Cannot identify dangerous permission combinations or abuse commands

**Missing Loot Files:**
- `permissions-dangerous` - Dangerous action combinations
- `permissions-escalation` - Privilege escalation actions
- `permissions-abuse-commands` - Action abuse commands
- `permissions-write-actions` - All write permissions

**Actionable Data Missing:**
```bash
# Dangerous actions
# Principals with Microsoft.Compute/virtualMachines/runCommand/action
# Principals with Microsoft.Authorization/roleAssignments/write
# Principals with Microsoft.KeyVault/vaults/secrets/write
# Principals with Microsoft.Storage/storageAccounts/listKeys/action

# Example abuse:
az vm run-command invoke --resource-group <rg> --name <vm> --command-id RunShellScript --scripts "whoami; cat /etc/shadow"
```

---

### 🟡 **HIGH Priority**

#### 1.5. **federated-credentials.go** - Federated Identity Credentials
**Category:** Identity & Access
**Current State:** Enumerates federated credentials but NO loot files
**Impact:** Cannot exploit OIDC/GitHub Actions integration

**Missing Loot Files:**
- `fedcred-github-actions` - GitHub Actions abuse paths
- `fedcred-oidc-issuers` - OIDC issuer enumeration
- `fedcred-exploitation` - Token exchange commands
- `fedcred-workload-identity` - Workload identity federation abuse

**Actionable Data Missing:**
- GitHub/GitLab Actions workflow exploitation
- OIDC token exchange commands
- Subject identifier enumeration
- Workload identity federation token generation

---

#### 1.6. **consent-grants.go** - OAuth Consent Grants
**Category:** Identity & Access
**Current State:** Enumerates OAuth consent grants but NO loot files
**Impact:** Cannot identify over-privileged consent grants or abuse paths

**Missing Loot Files:**
- `consent-overprivileged` - Over-privileged grants
- `consent-tenant-wide` - Tenant-wide admin consents
- `consent-risky-permissions` - Mail.Read, Files.ReadWrite.All, etc.
- `consent-abuse-commands` - OAuth abuse techniques

**Actionable Data Missing:**
- Applications with tenant-wide admin consent
- Delegated permissions (Mail.Read, Files.ReadWrite.All)
- Application permission abuse paths
- OAuth token generation commands

---

### 🟢 **MEDIUM Priority**

#### 1.7. **devops-agents.go** - Azure DevOps Agents
**Category:** DevOps
**Current State:** Enumerates DevOps agents but NO loot files
**Impact:** Cannot extract agent tokens or identify self-hosted agents

**Missing Loot Files:**
- `devops-agents-self-hosted` - Self-hosted agent list
- `devops-agents-capabilities` - Agent capabilities and installed software
- `devops-agents-tokens` - Agent token extraction
- `devops-agents-pools` - Pool permissions
- `devops-agents-registration` - Agent registration commands

---

#### 1.8. **conditional-access.go** - Conditional Access Policies
**Category:** Security & Governance
**Current State:** Enumerates CA policies but NO loot files
**Impact:** Cannot identify policy bypass opportunities

**Missing Loot Files:**
- `ca-bypass-opportunities` - Policy bypass paths
- `ca-excluded-principals` - Excluded users/groups
- `ca-legacy-auth` - Legacy authentication gaps
- `ca-report-only` - Report-only policies (not enforced)
- `ca-mfa-gaps` - MFA enforcement gaps

---

## 2. EXCELLENT IMPLEMENTATIONS - Top Modules by Loot File Count

### 🏆 **Champions (10 loot files each)**

#### 2.1. **vms.go** - Virtual Machines
**Loot Files (10):**
1. `vms-run-command` - VM run-command execution templates
2. `vms-bulk-command` - Bulk command execution across VMs
3. `vms-boot-diagnostics` - Boot diagnostics log access
4. `vms-bastion` - Bastion host connection commands
5. `vms-custom-script` - Custom script extension deployment
6. `vms-userdata` - User data extraction (secrets in cloud-init)
7. `vms-extension-settings` - VM extension enumeration
8. `vms-scale-sets` - VMSS instance enumeration
9. `vms-disk-snapshot-commands` - Disk snapshot and mounting
10. `vms-password-reset-commands` - Password reset and SSH key injection

**Why Excellent:** Comprehensive coverage of all VM attack vectors - command execution, credential extraction, disk access, and persistence.

---

#### 2.2. **arc.go** - Azure Arc
**Loot Files (10):**
1. `arc-commands` - Arc-enabled server enumeration
2. `arc-machines` - Machine inventory
3. `arc-identities` - Managed identity token extraction
4. `arc-cert-extraction` - Arc agent certificate extraction
5. `arc-kubernetes` - Kubernetes cluster access
6. `arc-data-services` - SQL Managed Instance connections
7. `arc-extensions` - Extension exploitation
8. `arc-security-analysis` - Security posture
9. `arc-privilege-escalation` - Escalation paths
10. `arc-hybrid-connectivity` - Hybrid connectivity abuse

**Why Excellent:** Thorough hybrid connectivity exploitation covering certificates, managed identities, and privilege escalation.

---

#### 2.3. **automation.go** - Automation Accounts
**Loot Files (10):**
1. `automation-variables` - Variable extraction (credentials)
2. `automation-commands` - Enumeration commands
3. `automation-runbooks` - Runbook code extraction
4. `automation-schedules` - Schedule manipulation
5. `automation-assets` - Asset enumeration
6. `automation-connections` - Connection string extraction
7. `automation-scope-runbooks` - Scoped runbooks
8. `automation-hybrid-workers` - Hybrid worker exploitation
9. `automation-hybrid-cert-extraction` - Certificate extraction
10. `automation-hybrid-jrds-extraction` - JRDS extraction

**Why Excellent:** Comprehensive runbook and hybrid worker exploitation with credential extraction.

---

### 🥈 **Strong Implementations (7-8 loot files)**

#### 2.4. **webapps.go** - Web Apps (8 loot files)
- `webapps-configuration` - App Service config secrets
- `webapps-connectionstrings` - Connection strings (SQL, Redis)
- `webapps-commands` - Enumeration commands
- `webapps-bulk-commands` - Bulk operations
- `webapps-easyauth-tokens` - EasyAuth token extraction
- `webapps-easyauth-sp` - Service principal from EasyAuth
- `webapps-kudu-commands` - Kudu SCM access (source download)
- `webapps-backup-commands` - Backup downloads

**Why Strong:** Excellent Kudu and EasyAuth coverage for credential extraction.

---

#### 2.5. **devops-pipelines.go** - DevOps Pipelines (8 loot files)
- `pipeline-commands` - Pipeline enumeration
- `pipeline-templates` - Pipeline definitions (YAML)
- `pipeline-variables` - Pipeline variables (secrets)
- `pipeline-service-connections` - Service connection abuse
- `pipeline-variable-groups` - Variable group exfiltration
- `pipeline-inline-scripts` - Inline script extraction
- `pipeline-secure-files` - Secure file downloads
- `pipeline-secrets-detected` - Secret scanning results

**Why Strong:** Thorough CI/CD secret extraction covering all secret storage locations.

---

#### 2.6. **databricks.go** - Databricks (7 loot files)
- `databricks-commands` - Workspace access
- `databricks-connection-strings` - Connection strings
- `databricks-rest-api` - REST API access
- `databricks-notebooks` - Notebook export (secrets)
- `databricks-secrets` - Secret scope enumeration
- `databricks-jobs` - Job execution
- `databricks-clusters` - Cluster manipulation

---

#### 2.7. **hdinsight.go** - HDInsight (7 loot files)
- `hdinsight-commands` - Cluster access
- `hdinsight-identities` - Managed identities
- `hdinsight-esp-analysis` - Enterprise Security Pack
- `hdinsight-kerberos-config` - Kerberos keytab extraction
- `hdinsight-ranger-policies` - Ranger policy enumeration
- `hdinsight-ldap-integration` - LDAP integration
- `hdinsight-security-posture` - Security analysis

---

## 3. Category Coverage Analysis

| **Category** | **Total Modules** | **With Loot** | **Without Loot** | **Coverage** | **Status** |
|--------------|-------------------|---------------|------------------|--------------|------------|
| Identity & Access | 8 | 4 | 4 | 50% | ⚠️ **Critical Gap** |
| Compute | 10 | 9 | 1 | 90% | ✅ Excellent |
| Storage & Data | 15 | 14 | 1 | 93% | ✅ Excellent |
| Networking | 14 | 14 | 0 | 100% | ✅ Perfect |
| Application Services | 6 | 6 | 0 | 100% | ✅ Perfect |
| DevOps | 6 | 5 | 1 | 83% | ✅ Good |
| Security & Governance | 9 | 7 | 2 | 78% | ✅ Good |
| Specialized | 5 | 5 | 0 | 100% | ✅ Perfect |

**Key Insight:** Identity & Access category has only 50% coverage - this is the biggest gap area requiring immediate attention.

---

## 4. Loot File Distribution Statistics

| **Loot File Count** | **Number of Modules** | **Examples** |
|---------------------|----------------------|--------------|
| 10 loot files | 3 | vms, arc, automation |
| 8 loot files | 2 | webapps, devops-pipelines |
| 7 loot files | 2 | databricks, hdinsight |
| 6 loot files | 7 | synapse, datafactory, firewall, api-management |
| 5 loot files | 8 | frontdoor, cdn, backup-inventory, bastion, compliance |
| 4 loot files | 8 | vnets, databases, logicapps, network-interfaces |
| 3 loot files | 11 | acr, app-configuration, functions, keyvaults |
| 2 loot files | 13 | accesskeys, iothub, redis, kusto, disks |
| 1 loot file | 10 | appgw, batch, endpoints, enterprise-apps |
| **0 loot files** | **8** | **aks, storage, rbac, permissions, federated-credentials, consent-grants, devops-agents, conditional-access** |

---

## 5. Common Loot File Patterns (Best Practices)

### Naming Conventions
- `<module>-commands` - General enumeration commands
- `<module>-strings` / `<module>-connection-strings` - Credentials and connection strings
- `<module>-firewall-commands` - Network access manipulation
- `<module>-backup-commands` - Backup access and restore
- `<module>-identities` - Managed identity enumeration
- `<module>-secrets-detected` - Secret scanning results
- `<module>-privilege-escalation` - Escalation paths
- `<module>-exploitation` - Exploitation techniques

### Loot File Structure (from code analysis)
```go
// Each module uses a LootMap
LootMap: map[string]*internal.LootFile{
    "module-name-commands": {
        Name:     "module-name-commands",
        Contents: "", // Populated during execution
    },
    // ... more loot files
},

// At the end, build loot array from non-empty files
loot := []internal.LootFile{}
for _, lf := range m.LootMap {
    if lf.Contents != "" {
        loot = append(loot, *lf)
    }
}
```

---

## 6. Actionable Data Types Across All Modules

### Most Common Actionable Items

#### Credentials & Secrets (Highest Value)
- **Storage Account Keys** - accesskeys.go, (missing: storage.go)
- **Database Connection Strings** - databases.go, databricks.go, synapse.go, redis.go, kusto.go
- **Service Principal Credentials** - accesskeys.go, enterprise-apps.go, devops-security.go
- **API Keys & Tokens** - functions.go, logicapps.go, api-management.go, devops-projects.go
- **Certificate Private Keys** - accesskeys.go, keyvaults.go, automation.go, arc.go
- **SSH Keys** - vms.go, arc.go, automation.go, machine-learning.go
- **OAuth Tokens** - enterprise-apps.go, webapps.go, (missing: consent-grants.go)
- **Kubernetes Credentials** - (missing: aks.go)

#### Commands & Scripts
- **Azure CLI Commands** - All 64 modules with loot files
- **PowerShell Commands** - Most modules
- **REST API Calls** - databricks.go, synapse.go, api-management.go
- **kubectl Commands** - (missing: aks.go)
- **Git Commands** - devops-repos.go
- **Network Scanning** - nsg.go, network-interfaces.go, firewall.go, load-balancers.go

#### Configuration & Definitions
- **ARM Templates** - deployments.go
- **Pipeline YAMLs** - devops-pipelines.go
- **Policy Definitions** - policy.go, compliance-dashboard.go
- **Network Topology** - network-topology.go, vnets.go
- **Firewall Rules** - firewall.go, nsg.go, databases.go

#### Attack Paths & Pivots
- **Lateral Movement** - lateral-movement.go
- **Privilege Escalation** - arc.go, automation.go, (missing: permissions.go)
- **Data Exfiltration** - data-exfiltration.go, (missing: storage.go), databases.go
- **Network Exposure** - network-exposure.go, network-interfaces.go

---

## 7. Implementation Recommendations

### Phase 1: Critical Gaps (Week 1-2) 🔴
**Immediate implementation required - security assessment blind spots**

1. **aks.go** - Add 7 loot files for Kubernetes credential extraction
2. **storage.go** - Add 6 loot files for storage key/SAS token commands
3. **rbac.go** - Add 6 loot files for high-privilege role enumeration
4. **permissions.go** - Add 4 loot files for dangerous permission abuse

**Impact:** Closes critical gaps in Kubernetes, storage, and identity attack vectors.

---

### Phase 2: High-Priority Additions (Week 3) 🟡
**Important for comprehensive identity attack surface coverage**

5. **federated-credentials.go** - Add 4 loot files for OIDC/GitHub Actions exploitation
6. **consent-grants.go** - Add 4 loot files for OAuth consent abuse
7. **devops-agents.go** - Add 5 loot files for agent token extraction
8. **conditional-access.go** - Add 5 loot files for policy bypass identification

**Impact:** Completes Identity & Access category coverage (50% → 100%).

---

### Phase 3: Enhancements (Week 4) 🟢
**Improve existing strong modules**

9. Enhance **vms.go** - Add VMware Arc integration
10. Enhance **webapps.go** - Add Logic App integration
11. Enhance **databases.go** - Add more exfiltration techniques
12. Enhance **keyvaults.go** - Add RBAC-based access paths

---

## 8. Comparison: Before vs After Implementation

| **Metric** | **Current** | **After Phase 1** | **After Phase 2** | **Target** |
|------------|-------------|-------------------|-------------------|------------|
| Modules with Loot | 64/72 (88.9%) | 68/72 (94.4%) | 72/72 (100%) | 100% ✅ |
| Total Loot Files | 261 | ~285 | ~305 | 300+ |
| Identity & Access Coverage | 50% ⚠️ | 75% | 100% ✅ | 100% |
| Critical Gaps | 4 modules | 0 modules ✅ | 0 modules ✅ | 0 |

---

## 9. Testing & Validation Checklist

For each new loot file implementation:

- [ ] Test with data that should trigger loot file creation
- [ ] Test with data that should NOT trigger loot file creation
- [ ] Verify loot file is created in correct directory
- [ ] Verify loot file content format is correct and actionable
- [ ] Verify no empty loot files are created
- [ ] Test commands in loot files are syntactically correct
- [ ] Verify dynamic values (subscription IDs, resource names) are correctly populated
- [ ] Test with multiple subscriptions/tenants
- [ ] Verify LootMap structure follows existing patterns
- [ ] Check for any hardcoded values that should be dynamic

---

## 10. Conclusion

**Current State:** Azure CloudFox has **excellent loot file coverage** with 88.9% of modules already implemented (261 loot files across 64 modules).

**Critical Finding:** Only **8 modules lack loot files**, but these represent **critical security assessment gaps** in:
- Kubernetes credential extraction
- Storage account access
- High-privilege RBAC identification
- Dangerous permission abuse

**Recommended Action:** Prioritize Phase 1 implementation (4 critical modules) to close the most significant security assessment blind spots.

**Long-Term Goal:** Achieve 100% loot file coverage across all 72 modules with standardized patterns and cross-module correlation.

---

**Analysis Complete - Ready for Implementation**
