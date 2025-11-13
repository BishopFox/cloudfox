# Azure CloudFox Loot File Cleanup Recommendations

**Analysis Date:** 2025-11-13
**Branch:** cloudfox-azure-new
**Modules Analyzed:** 72 Azure command modules
**Total Loot Files:** 200+ across all modules

---

## Executive Summary

After comprehensive analysis of all 72 Azure CloudFox modules, **the vast majority of loot files (95%+) are properly actionable** and contain commands, credentials, URLs, or exploitation techniques.

However, **5 loot files** were identified as **non-actionable** and should be removed or moved to standard table output:

| Module | Loot File | Issue | Recommendation |
|--------|-----------|-------|----------------|
| routes.go | `route-custom-routes` | Just lists route details | **REMOVE** |
| nsg.go | `nsg-open-ports` | Just lists open ports | **REMOVE** |
| arc.go | `arc-machines` | Reformats table data | **REMOVE** |
| arc.go | `arc-identities` | Lists identity IDs | **REMOVE** |
| hdinsight.go | `hdinsight-identities` | Lists identity info | **REMOVE** |

**Impact:** Removing these 5 loot files will:
- ✅ Reduce noise and improve signal-to-noise ratio
- ✅ Keep loot files focused on actionable items only
- ✅ Prevent duplication of data already in standard table output

---

## 1. Detailed Analysis of NON-ACTIONABLE Loot Files

### 1.1. routes.go - `route-custom-routes`

**Location:** azure/commands/routes.go:317-322

**Current Content:**
```go
m.LootMap["route-custom-routes"].Contents += fmt.Sprintf("Route Table: %s/%s\n", rgName, rtName)
m.LootMap["route-custom-routes"].Contents += fmt.Sprintf("  Route: %s\n", routeName)
m.LootMap["route-custom-routes"].Contents += fmt.Sprintf("  Address Prefix: %s\n", addressPrefix)
m.LootMap["route-custom-routes"].Contents += fmt.Sprintf("  Next Hop Type: %s\n", nextHopType)
m.LootMap["route-custom-routes"].Contents += fmt.Sprintf("  Next Hop IP: %s\n", nextHopIP)
m.LootMap["route-custom-routes"].Contents += fmt.Sprintf("  Subscription: %s\n\n", subName)
```

**Why Non-Actionable:**
- ❌ No commands to execute
- ❌ No credentials or secrets
- ❌ Just reformats table data
- ❌ Provides no next steps

**Recommendation:** **REMOVE** - This data is already in the table output columns.

---

### 1.2. nsg.go - `nsg-open-ports`

**Location:** azure/commands/nsg.go:317-322

**Current Content:**
```go
m.LootMap["nsg-open-ports"].Contents += fmt.Sprintf("NSG: %s/%s\n", rgName, nsgName)
m.LootMap["nsg-open-ports"].Contents += fmt.Sprintf("  Rule: %s\n", ruleName)
m.LootMap["nsg-open-ports"].Contents += fmt.Sprintf("  Protocol: %s\n", protocol)
m.LootMap["nsg-open-ports"].Contents += fmt.Sprintf("  Source: %s\n", srcPrefix)
m.LootMap["nsg-open-ports"].Contents += fmt.Sprintf("  Destination: %s\n", dstPrefix)
m.LootMap["nsg-open-ports"].Contents += fmt.Sprintf("  Ports: %s\n\n", dstPort)
```

**Why Non-Actionable:**
- ❌ Just lists NSG rules - already in table
- ❌ No exploitation commands
- ❌ Redundant with `nsg-targeted-scans` loot file

**IMPORTANT:** nsg.go has **OTHER loot files that ARE actionable:**
- ✅ `nsg-targeted-scans` - Contains nmap/ssh/curl commands (KEEP!)
- ✅ `nsg-security-risks` - Contains risk analysis (KEEP!)
- ✅ `nsg-commands` - Contains enumeration commands (KEEP!)

**Recommendation:** **REMOVE `nsg-open-ports`** - Keep the other actionable loot files.

---

### 1.3. arc.go - `arc-machines`

**Location:** azure/commands/arc.go:238-252

**Current Content:**
```go
lf.Contents += fmt.Sprintf("\n## Arc Machine: %s\n", machine.Name)
lf.Contents += fmt.Sprintf("# Resource Group: %s, Subscription: %s (%s)\n", machine.ResourceGroup, subName, subID)
lf.Contents += fmt.Sprintf("- **Location**: %s\n", machine.Location)
lf.Contents += fmt.Sprintf("- **Hostname**: %s\n", machine.Hostname)
lf.Contents += fmt.Sprintf("- **Private IP**: %s\n", machine.PrivateIP)
lf.Contents += fmt.Sprintf("- **OS**: %s (%s)\n", machine.OSName, machine.OSVersion)
lf.Contents += fmt.Sprintf("- **Status**: %s\n", machine.Status)
lf.Contents += fmt.Sprintf("- **Provisioning State**: %s\n", machine.ProvisioningState)
lf.Contents += fmt.Sprintf("- **Agent Version**: %s\n", machine.AgentVersion)
```

**Why Non-Actionable:**
- ❌ Just reformats table data into markdown
- ❌ No commands or exploitation techniques
- ❌ No credentials or connection strings

**IMPORTANT:** arc.go has **OTHER loot files that ARE actionable:**
- ✅ `arc-commands` - Azure Arc CLI commands (KEEP!)
- ✅ `arc-cert-extraction` - Certificate extraction commands (KEEP!)
- ✅ `arc-security-analysis` - Security analysis (KEEP!)

**Recommendation:** **REMOVE `arc-machines`** - Keep the other actionable loot files.

---

### 1.4. arc.go - `arc-identities`

**Location:** azure/commands/arc.go:256-272

**Current Content:**
```go
lf.Contents += fmt.Sprintf("\n## Arc Machine: %s\n", machine.Name)
lf.Contents += fmt.Sprintf("# Resource Group: %s, Subscription: %s (%s)\n", machine.ResourceGroup, subName, subID)
lf.Contents += fmt.Sprintf("- **Identity Type**: %s\n", machine.IdentityType)
lf.Contents += fmt.Sprintf("- **Principal ID**: %s\n", machine.PrincipalID)
lf.Contents += fmt.Sprintf("- **Tenant ID**: %s\n", machine.TenantID)
lf.Contents += fmt.Sprintf("- **OS**: %s\n", machine.OSName)
lf.Contents += fmt.Sprintf("- **Certificate Path**: C:\\ProgramData\\AzureConnectedMachineAgent\\Certs\\myCert.cer\n")
```

**Why Non-Actionable:**
- ❌ Just lists identity GUIDs - already in table
- ❌ Certificate path is hardcoded (not dynamic)
- ❌ No commands to extract or use the identities

**Recommendation:** **REMOVE** - Identity info is already in table columns.

---

### 1.5. hdinsight.go - `hdinsight-identities`

**Location:** azure/commands/hdinsight.go:420-430

**Current Content:**
```go
m.LootMap["hdinsight-identities"].Contents += fmt.Sprintf("# Cluster: %s/%s\n", rgName, clusterName)
m.LootMap["hdinsight-identities"].Contents += fmt.Sprintf("Subscription: %s\n", subName)
m.LootMap["hdinsight-identities"].Contents += fmt.Sprintf("Identity Type: %s\n", identityType)
if systemAssignedID != "N/A" {
    m.LootMap["hdinsight-identities"].Contents += fmt.Sprintf("System Assigned Identity: %s\n", systemAssignedID)
}
if userAssignedIDs != "N/A" {
    m.LootMap["hdinsight-identities"].Contents += fmt.Sprintf("User Assigned Identities: %s\n", userAssignedIDs)
}
```

**Why Non-Actionable:**
- ❌ Just lists managed identity GUIDs
- ❌ No commands to exploit or enumerate these identities
- ❌ Data already in table output

**IMPORTANT:** hdinsight.go has **OTHER loot files that ARE actionable:**
- ✅ `hdinsight-commands` - Cluster access commands (KEEP!)
- ✅ `hdinsight-kerberos-config` - Kerberos keytab extraction (KEEP!)
- ✅ `hdinsight-esp-analysis` - Enterprise Security Pack analysis (KEEP!)

**Recommendation:** **REMOVE `hdinsight-identities`** - Keep the other actionable loot files.

---

## 2. Examples of PROPERLY ACTIONABLE Loot Files (Keep)

### ✅ Excellent Example: permissions.go - 4 Loot Files

**Location:** azure/commands/permissions.go:1372-1407

**Loot Files:**
1. `permissions-dangerous` - Investigation commands for dangerous permissions
2. `permissions-service-principals` - SP credential enumeration
3. `permissions-enumeration-commands` - Graph API & CLI commands
4. `permissions-privilege-escalation` - Step-by-step exploitation

**Example Content (lines 1520-1523):**
```go
loot.WriteString("**Investigation Commands**:\n")
loot.WriteString(fmt.Sprintf("```bash\n# Get full details about this principal\naz ad sp show --id %s\naz ad user show --id %s\n\n", principalGUID, principalGUID))
loot.WriteString(fmt.Sprintf("# Get all role assignments for this principal\naz role assignment list --assignee %s --all --output table\n\n", principalGUID))
loot.WriteString("# Check for PIM eligibility\naz rest --method GET --url \"https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=asTarget()\"\n```\n\n")
```

**Why Actionable:** ✅ Contains ready-to-execute Azure CLI and API commands

---

### ✅ Excellent Example: nsg.go - `nsg-targeted-scans`

**Location:** azure/commands/nsg.go:377-420

**Example Content:**
```go
switch port {
    case "22":
        m.LootMap["nsg-targeted-scans"].Contents += "# SSH Access (Port 22)\n"
        m.LootMap["nsg-targeted-scans"].Contents += "ssh <username>@<TARGET_IP>\n"
        m.LootMap["nsg-targeted-scans"].Contents += "nmap -p 22 -sV --script ssh-auth-methods,ssh-hostkey <TARGET_IP>\n\n"

    case "3389":
        m.LootMap["nsg-targeted-scans"].Contents += "# RDP Access (Port 3389)\n"
        m.LootMap["nsg-targeted-scans"].Contents += "xfreerdp /v:<TARGET_IP> /u:<username>\n"
        m.LootMap["nsg-targeted-scans"].Contents += "nmap -p 3389 -sV --script rdp-enum-encryption <TARGET_IP>\n\n"

    case "1433":
        m.LootMap["nsg-targeted-scans"].Contents += "# SQL Server (Port 1433)\n"
        m.LootMap["nsg-targeted-scans"].Contents += "nmap -p 1433 -sV --script ms-sql-info,ms-sql-brute <TARGET_IP>\n"
        m.LootMap["nsg-targeted-scans"].Contents += "# Warning: SQL Server should NOT be exposed to the Internet\n\n"
}
```

**Why Actionable:** ✅ Contains nmap, ssh, xfreerdp commands ready to execute

---

### ✅ Excellent Example: automation.go - `automation-runbooks`

**Location:** azure/commands/automation.go:469-482

**Example Content:**
```go
// Download actual runbook script content
script, err := azinternal.FetchRunbookScript(ctx, m.Session, subID, rgName, accName, rbName)
lf.Contents += "# BEGIN SCRIPT CONTENT\n"
lf.Contents += script + "\n\n"  // ← Actual PowerShell/Python code!!!
```

**Why Actionable:** ✅ Contains ACTUAL runbook script code that may have credentials or exploitation logic

---

### ✅ Excellent Example: app-configuration.go - `appconfig-access-keys`

**Location:** azure/commands/app-configuration.go:257-268

**Example Content:**
```go
lf.Contents += fmt.Sprintf("### Access Key: %s (%s)\n", key.Name, keyType)
lf.Contents += fmt.Sprintf("- **ID**: %s\n", key.ID)
lf.Contents += fmt.Sprintf("- **Value**: %s\n", key.Value)  // ← CREDENTIAL!
lf.Contents += fmt.Sprintf("- **Connection String**: %s\n", key.ConnectionString)  // ← CREDENTIAL!
```

**Why Actionable:** ✅ Contains actual credentials (API keys and connection strings)

---

### ✅ Excellent Example: kusto.go - `kusto-connection-strings`

**Location:** azure/commands/kusto.go:326-339

**Example Content:**
```go
lf.Contents += fmt.Sprintf("Cluster URI: %s\n", uri)  // ← Direct URL
lf.Contents += "# Kusto CLI Connection:\n"
lf.Contents += fmt.Sprintf("Kusto.Explorer.exe -uri:%s\n\n", uri)  // ← Command
lf.Contents += "# Python Connection:\n"
lf.Contents += "from azure.kusto.data import KustoClient, KustoConnectionStringBuilder\n"  // ← Code
lf.Contents += fmt.Sprintf("kcsb = KustoConnectionStringBuilder.with_aad_device_authentication(\"%s\")\n", uri)
```

**Why Actionable:** ✅ Contains connection commands and Python code snippets

---

### ✅ Excellent Example: vms.go - `vms-password-reset-commands`

**Location:** azure/commands/vms.go:565-569

**Example Content:**
```go
lf.Contents += "# For Windows VMs: Reset administrator password\n"
lf.Contents += fmt.Sprintf("az vm user update \\\n")
lf.Contents += fmt.Sprintf("  --resource-group %s \\\n", vm.ResourceGroup)
lf.Contents += fmt.Sprintf("  --name %s \\\n", vm.VMName)
lf.Contents += fmt.Sprintf("  --username <NEW-ADMIN-USERNAME> \\\n")
lf.Contents += fmt.Sprintf("  --password <NEW-PASSWORD>\n\n")
```

**Why Actionable:** ✅ Contains VM password reset commands for privilege escalation

---

### ✅ Excellent Example: databases.go - Backup access commands

**Location:** azure/commands/databases.go:497-525

**Example Content:**
```go
"# List all available backups (automatic backups)\n"+
"az sql db list-backups \\\n"+
"  --resource-group %s \\\n"+
"  --server %s \\\n"+
"  --database %s\n\n"+
"# Export database to storage account (requires admin credentials)\n"+
"az sql db export \\\n"+
"  --resource-group %s \\\n"+
"  --server %s \\\n"+
"  --name %s \\\n"+
"  --admin-user <ADMIN-USERNAME> \\\n"+
"  --admin-password <ADMIN-PASSWORD> \\\n"+
"  --storage-key <STORAGE-KEY> \\\n"+
"  --storage-uri https://<storage-account>.blob.core.windows.net/<container>/<backup>.bacpac\n\n"
```

**Why Actionable:** ✅ Contains database export/backup commands for data exfiltration

---

## 3. Decision Criteria (Reference)

### ✅ Data That BELONGS in Loot Files

**1. Commands to Execute:**
- Azure CLI commands (az, kubectl, nmap, etc.)
- PowerShell commands
- Bash/shell scripts
- Python/Ruby/other language code snippets

**2. Credentials & Secrets:**
- API keys, passwords, tokens
- Storage account keys / SAS tokens
- Connection strings
- SSH keys / certificates
- OAuth tokens
- Service principal credentials

**3. Direct Access:**
- Publicly accessible URLs
- Endpoint addresses for exploitation
- Kubeconfig files
- Connection details
- URIs for databases/APIs

**4. Attack Techniques:**
- Privilege escalation commands
- Persistence mechanisms
- Lateral movement techniques
- Data exfiltration scripts
- Container escape techniques

---

### ❌ Data That BELONGS in Standard Output

**1. Inventory & Lists:**
- Resource counts
- Resource type distributions
- Location summaries
- Simple lists of resource names

**2. Context Information:**
- Tenant/subscription details
- Authentication status
- Environment overview
- Non-sensitive metadata

**3. Basic Configurations:**
- Role assignments WITHOUT exploitation commands
- Resource ownership WITHOUT next steps
- Configuration settings WITHOUT secrets
- Status/health information

**4. Reformatted Table Data:**
- Data that just reformats existing table columns
- Markdown-formatted lists with no added value
- Duplicate information from standard output

---

## 4. Implementation Recommendations

### Phase 1: Remove Non-Actionable Loot Files (Immediate)

**Priority:** HIGH
**Effort:** 1-2 hours
**Impact:** Reduces noise, improves loot file quality

**Files to Modify:**

1. **azure/commands/routes.go**
   - Remove `"route-custom-routes"` from LootMap initialization (line ~72)
   - Remove loot generation code (lines 317-322)
   - Keep: `route-commands` and `route-risks`

2. **azure/commands/nsg.go**
   - Remove `"nsg-open-ports"` from LootMap initialization (line ~74)
   - Remove loot generation code (lines 317-322)
   - Keep: `nsg-targeted-scans`, `nsg-security-risks`, `nsg-commands`

3. **azure/commands/arc.go**
   - Remove `"arc-machines"` from LootMap initialization
   - Remove `"arc-identities"` from LootMap initialization
   - Remove corresponding loot generation code (lines 238-272)
   - Keep: `arc-commands`, `arc-cert-extraction`, `arc-security-analysis`, etc.

4. **azure/commands/hdinsight.go**
   - Remove `"hdinsight-identities"` from LootMap initialization
   - Remove corresponding loot generation code (lines 420-430)
   - Keep: `hdinsight-commands`, `hdinsight-kerberos-config`, `hdinsight-esp-analysis`

---

### Phase 2: Enhance Remaining Loot Files (Optional)

**Priority:** MEDIUM
**Effort:** Variable
**Impact:** Improves value of existing loot files

**Suggestions:**
1. Add more detailed exploitation examples to existing loot files
2. Include MITRE ATT&CK technique references
3. Add risk severity ratings (CRITICAL/HIGH/MEDIUM/LOW)
4. Include remediation commands alongside exploitation commands

---

## 5. Testing Checklist

After removing non-actionable loot files, verify:

- [ ] Modules still compile successfully
- [ ] No loot files are created with empty/minimal content
- [ ] Remaining loot files contain actionable data
- [ ] No regression in functionality
- [ ] Table output still contains all necessary information
- [ ] Output directory structure is correct

---

## 6. Summary

### Current State
- **Total Modules:** 72
- **Total Loot Files:** 200+
- **Actionable Loot Files:** 95%+
- **Non-Actionable Loot Files:** 5 (identified in this analysis)

### Recommended Actions
1. **Remove 5 non-actionable loot files:**
   - route-custom-routes
   - nsg-open-ports
   - arc-machines
   - arc-identities
   - hdinsight-identities

2. **Keep all other 195+ loot files** - They contain actionable commands, credentials, or exploitation techniques

### Expected Outcome
- ✅ Improved signal-to-noise ratio for loot files
- ✅ Clearer separation between informational (table) and actionable (loot) data
- ✅ Better user experience - loot files will always have high-value content
- ✅ No loss of information - data is still in table output

---

**Analysis Complete - Ready for Implementation**
