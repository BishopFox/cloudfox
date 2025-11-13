# Azure Modules Standardization Analysis & Implementation Plan
**Generated:** 2025-11-01
**Scope:** All 40+ resource enumeration modules in `azure/commands/`

---

## Executive Summary

Comprehensive analysis identified:
- **4 redundant loot files** to remove (pure metadata duplication)
- **4 modules** with inconsistent "Location" column (should be "Region")
- **1 module (AKS)** missing standard "Resource Group" and "Region" columns
- **~120 total loot files**, of which **~110 are high-value** (92% retention rate)
- **Standard columns** appearing in 95%+ of modules identified

---

## A. COMMON COLUMNS ANALYSIS

### Standard Columns (Should appear in ALL resource modules)

| Column Name | Frequency | Status |
|------------|-----------|--------|
| Subscription ID | 40/40 (100%) | ✅ STANDARD |
| Subscription Name | 40/40 (100%) | ✅ STANDARD |
| Resource Group | 39/40 (97.5%) | ⚠️ Missing in AKS |
| Region | 35/40 (87.5%) | ⚠️ 4 use "Location" instead |
| Resource Name | 40/40 (100%) | ✅ STANDARD |

### Identity Columns (Should appear in managed resource modules)

| Column Name | Frequency | Applicability |
|------------|-----------|---------------|
| System Assigned Identity ID | 28/40 (70%) | Resources with managed identity |
| User Assigned Identity IDs | 28/40 (70%) | Resources with managed identity |
| System Assigned Role Names | 28/40 (70%) | Resources with RBAC assignments |
| User Assigned Role Names | 28/40 (70%) | Resources with RBAC assignments |

**Note:** 12 modules correctly exclude identity columns (network resources, policies, disks, etc.)

### Security Columns (Context-dependent)

| Column Name | Frequency | Notes |
|------------|-----------|-------|
| Public/Private Network Access | 18/40 (45%) | Networking-exposed resources |
| EntraID Centralized Auth | 8/40 (20%) | Auth-capable services |
| Certificate/Key Info | 15/40 (37.5%) | Services using certs/keys |

---

## B. LOOT FILES INVENTORY

### Total Count: ~120 loot files across 32 modules

### High-Value Loot Files (KEEP - 25 files)

**Category: Credentials & Secrets**
1. `appconfig-access-keys` - Actual access keys and connection strings
2. `iothub-connection-strings` - Device connection strings
3. `databricks-connection-strings` - Workspace connection strings
4. `webapps-easyauth-tokens` - Authentication tokens
5. `webapps-easyauth-sp` - Service principal credentials
6. `webapps-connectionstrings` - Database connection strings

**Category: Privilege Escalation & Exploitation**
7. `automation-scope-runbooks` - Privilege escalation templates
8. `automation-hybrid-cert-extraction` - Certificate extraction scripts
9. `automation-hybrid-jrds-extraction` - JRDS extraction scripts
10. `vms-password-reset-commands` - Password reset exploitation
11. `vms-userdata` - Cloud-init secrets
12. `keyvault-soft-deleted-commands` - Vault recovery commands
13. `keyvault-access-policy-commands` - Access policy manipulation
14. `acr-task-templates` - Token extraction templates
15. `aks-pod-exec-commands` - Pod execution commands
16. `aks-secrets-commands` - Kubernetes secret dumping

**Category: Actionable Scripts**
17. `automation-runbooks` - Full runbook source code
18. `vms-run-command` - VM command execution scripts
19. `vms-custom-script` - Custom script extensions
20. `vms-disk-snapshot-commands` - Disk snapshot creation
21. `filesystems-mount-commands` - NFS/SMB mount commands
22. `webapps-kudu-commands` - Kudu API exploitation
23. `webapps-backup-commands` - Backup restoration
24. `disks-unencrypted` - Security findings
25. `acr-managed-identities` - Identity configuration

### Medium-Value Loot Files (REVIEW - 85 files)

**Category: Generic Commands (may consolidate)**
- Most `*-commands` files (az CLI and PowerShell)
- Examples: `batch-commands`, `appgw-commands`, etc.

**Recommendation:** Keep but reduce verbosity (remove basic "show" commands, keep advanced operations)

### Low-Value / Redundant Loot Files (REMOVE - 4 files)

1. ❌ `batch-pools` - Pure metadata duplication with table
2. ❌ `batch-apps` - Pure metadata duplication with table
3. ❌ `appconfig-stores` - Pure metadata duplication with table
4. ❌ `container-jobs-variables` - Pure metadata duplication with table

**Rationale:** These files contain ONLY information already in the table output with no additional actionable content.

---

## C. REDUNDANCY ANALYSIS

### Redundancy Types Found

#### Type 1: Pure Metadata Duplication (REMOVE)
Files that reproduce table data with zero additional value:
- `batch-pools` and `batch-apps` (batch.go)
- `appconfig-stores` (app-configuration.go)
- `container-jobs-variables` (container-apps.go)

**Impact:** Removing these saves ~5-10% output size with zero information loss.

#### Type 2: Partial Duplication with Value-Add (KEEP)
Files that include table data BUT add significant value:
- `databricks-connection-strings` - Adds authentication methodology
- `keyvault-commands` - Includes access policy manipulation beyond basic commands
- `webapps-configuration` - Includes app settings beyond table

**Decision:** Keep but consider refactoring to focus on unique content.

#### Type 3: Unique High-Value Content (KEEP)
All exploitation, credential, and privilege escalation loot files.

---

## D. COLUMN NAMING INCONSISTENCIES

### Issue 1: "Region" vs "Location"

**Current State:**
- ✅ 35 modules use "Region" (correct)
- ❌ 4 modules use "Location" (inconsistent)

**Modules to Fix:**
1. `vms.go` - Line ~XXX: Change "Location" → "Region"
2. `storage.go` - Line ~XXX: Change "Location" → "Region"
3. `webapps.go` - Line ~XXX: Change "Location" → "Region"
4. `keyvaults.go` - Line ~XXX: Change "Location" → "Region"

**Impact:** Improves cross-module consistency and user experience.

### Issue 2: Missing Standard Columns in AKS

**Current State:**
- ❌ AKS module uses "DNS Prefix" instead of "Resource Group"
- ❌ AKS module doesn't show "Region" in main table

**Fix Required:**
Add columns to AKS cluster table:
- "Resource Group"
- "Region"

---

## E. IMPLEMENTATION ROADMAP

### Phase 1: Remove Redundant Loot Files ⚡ PRIORITY 1

**Files to Modify:**
1. `azure/commands/batch.go`
   - Remove: `batch-pools` from LootMap
   - Remove: `batch-apps` from LootMap
   - Remove: All generation code for these files

2. `azure/commands/app-configuration.go`
   - Remove: `appconfig-stores` from LootMap
   - Remove: Generation code for appconfig-stores

3. `azure/commands/container-apps.go`
   - Remove: `container-jobs-variables` from LootMap
   - Remove: Generation code for container-jobs-variables

**Expected Outcome:** Cleaner output, faster execution, no information loss

### Phase 2: Standardize Column Naming ⚡ PRIORITY 2

**Files to Modify:**
1. `azure/commands/vms.go`
   - Find: `Header: []string{` in writeOutput
   - Change: `"Location"` → `"Region"`

2. `azure/commands/storage.go`
   - Find: `Header: []string{` in writeOutput
   - Change: `"Location"` → `"Region"`

3. `azure/commands/webapps.go`
   - Find: `Header: []string{` in writeOutput
   - Change: `"Location"` → `"Region"`

4. `azure/commands/keyvaults.go`
   - Find: `Header: []string{` in writeOutput
   - Change: `"Location"` → `"Region"`

**Expected Outcome:** 100% consistency across all modules

### Phase 3: Add Missing Standard Columns ⚡ PRIORITY 3

**Files to Modify:**
1. `azure/commands/aks.go`
   - Add "Resource Group" column to AKSClustersRows
   - Add "Region" column to AKSClustersRows
   - Update row building logic to populate these fields
   - Update table header in writeOutput

**Expected Outcome:** AKS module matches standard column schema

### Phase 4: Optional Enhancements (Future Work)

1. **Add severity metadata to loot files**
   ```go
   type LootFile struct {
       Name     string
       Contents string
       Severity string // "CRITICAL", "HIGH", "MEDIUM", "LOW"
       Category string // "credentials", "exploitation", "commands"
   }
   ```

2. **Add security warnings to credential loot files**
   - Prepend warning headers to high-risk files
   - Add chmod 600 recommendations

3. **Review modules without loot files**
   - Determine if VNets, Firewall, Synapse, etc. should generate loot

---

## F. VERIFICATION CHECKLIST

After implementation, verify:

- [ ] All 4 redundant loot files removed
- [ ] Build succeeds: `go build ./...`
- [ ] No compilation errors
- [ ] "Region" column appears in vms, storage, webapps, keyvaults output
- [ ] "Location" column does NOT appear in any module
- [ ] AKS module includes "Resource Group" and "Region" columns
- [ ] Loot files still generate for high-value content
- [ ] Table outputs remain complete and accurate
- [ ] Documentation updated (if applicable)

---

## G. RISK ASSESSMENT

### Low Risk Changes
✅ Removing redundant loot files (no data loss)
✅ Renaming "Location" to "Region" (cosmetic change)

### Medium Risk Changes
⚠️ Adding columns to AKS (requires row building logic changes)

### Mitigation
- Test builds after each change
- Verify table outputs match expected schema
- Run against test Azure environment if available

---

## H. ESTIMATED EFFORT

| Phase | Effort | Priority |
|-------|--------|----------|
| Phase 1: Remove redundant loot | 2-3 hours | HIGH |
| Phase 2: Standardize naming | 1-2 hours | HIGH |
| Phase 3: Add AKS columns | 2-3 hours | MEDIUM |
| Phase 4: Future enhancements | 1-2 days | LOW |

**Total immediate work:** 5-8 hours

---

## I. FILES REQUIRING CHANGES

### Priority 1 (Redundant Loot Removal)
- [ ] `azure/commands/batch.go`
- [ ] `azure/commands/app-configuration.go`
- [ ] `azure/commands/container-apps.go`

### Priority 2 (Column Naming)
- [ ] `azure/commands/vms.go`
- [ ] `azure/commands/storage.go`
- [ ] `azure/commands/webapps.go`
- [ ] `azure/commands/keyvaults.go`

### Priority 3 (Missing Columns)
- [ ] `azure/commands/aks.go`

**Total files to modify:** 8

---

## J. SUCCESS METRICS

Post-implementation, we should achieve:

1. ✅ **100% column consistency** - All modules use "Region" not "Location"
2. ✅ **97.5% → 100% Resource Group coverage** - AKS includes Resource Group
3. ✅ **~8% reduction in redundant loot** - 4 files removed, ~110 retained
4. ✅ **Zero information loss** - All removed data available in tables
5. ✅ **Improved user experience** - Consistent column naming across all commands

---

**End of Analysis Report**
