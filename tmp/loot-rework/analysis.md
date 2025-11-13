# Azure Commands Loot File Analysis

## Overview
This document provides a comprehensive analysis of loot file implementation across all Azure CloudFox modules. The analysis focuses on identifying:
- Current loot files and their contents
- Missing/recommended loot files
- Proper categorization of actionable vs. informational data

**Date:** 2025-11-13
**Scope:** azure/ directory modules
**Total Modules Analyzed:** 5

---

## Module-by-Module Analysis

### 1. whoami.go

**Purpose:** Enumerates Azure CLI sessions, tenants, subscriptions, and resource groups.

**Current Loot Files:**
- ❌ None

**Current Output:**
- Table format with: Tenant ID, Tenant Primary Domain, Subscription ID, Subscription Name, (optionally) RG Name, Region

**Analysis:**
The module outputs purely informational/contextual data that serves as reconnaissance baseline but lacks actionable items for post-exploitation or further enumeration.

**Recommended Loot Files:**

1. **tenant-subscription-enumeration-commands.txt**
   - **Contents:** Commands for further enumeration
   - **Examples:**
     ```bash
     # Enumerate all resources in subscription
     az resource list --subscription <subscription-id>

     # Get subscription details
     az account subscription show --subscription-id <subscription-id>

     # List all resource groups
     az group list --subscription <subscription-id>

     # Enumerate RBAC assignments
     az role assignment list --subscription <subscription-id>
     ```

2. **tenant-domains-for-recon.txt** (if interesting domains found)
   - **Contents:** Domain names for external reconnaissance
   - **Examples:**
     ```
     contoso.onmicrosoft.com
     contoso.com
     ```
   - **Use case:** External DNS recon, certificate transparency searches

**Rationale:**
While tenant/subscription info is contextual, generating enumeration commands would be actionable and help users know what to do next.

---

### 2. inventory.go

**Purpose:** Gathers inventory of all resources by type and location across subscriptions/tenants.

**Current Loot Files:**
- ❌ None

**Current Output:**
- Table format showing resource counts by type and location

**Analysis:**
Current output is a summary/inventory view that shows resource types and their distribution. This is useful for understanding the attack surface but doesn't provide actionable items directly.

**Recommended Loot Files:**

1. **high-value-resources-commands.txt**
   - **Contents:** Commands to enumerate high-value resource types
   - **Generated when:** Specific high-value resources detected (VMs, storage accounts, key vaults, databases, app services, function apps, etc.)
   - **Examples:**
     ```bash
     # Virtual Machines detected - enumerate details
     az vm list --subscription <subscription-id> -o table
     az vm list --subscription <subscription-id> --show-details

     # Storage Accounts detected - check for public access
     az storage account list --subscription <subscription-id>
     az storage container list --account-name <account>

     # Key Vaults detected - attempt to list secrets
     az keyvault list --subscription <subscription-id>
     az keyvault secret list --vault-name <vault-name>

     # SQL Databases detected - enumerate servers
     az sql server list --subscription <subscription-id>
     az sql db list --server <server> --resource-group <rg>

     # Function Apps detected - look for secrets/config
     az functionapp list --subscription <subscription-id>
     az functionapp config appsettings list --name <app> --resource-group <rg>
     ```

2. **resource-type-enumeration.txt**
   - **Contents:** PowerShell commands for detailed resource enumeration
   - **Examples:**
     ```powershell
     # Get all resources of specific type
     Get-AzResource -ResourceType Microsoft.Compute/virtualMachines -ExpandProperties
     Get-AzResource -ResourceType Microsoft.Storage/storageAccounts -ExpandProperties
     Get-AzResource -ResourceType Microsoft.KeyVault/vaults -ExpandProperties

     # Get resource details with full properties
     Get-AzResource | Where-Object {$_.ResourceType -eq "Microsoft.Web/sites"} | Get-AzResource -ExpandProperties
     ```

3. **interesting-resources.txt**
   - **Contents:** List of potentially interesting resources with reasons
   - **Generated when:** Resources like Key Vaults, Automation Accounts, DevOps resources, or less common services are found
   - **Example:**
     ```
     [HIGH] Microsoft.KeyVault/vaults - 5 instances found
     Reason: May contain secrets, certificates, and keys
     Action: Run Key Vault enumeration commands

     [MEDIUM] Microsoft.Web/sites - 12 instances found
     Reason: Web apps may expose configuration, connection strings
     Action: Check app settings and deployment credentials

     [MEDIUM] Microsoft.Automation/automationAccounts - 2 instances found
     Reason: May contain runbooks with credentials or elevated permissions
     Action: Enumerate runbooks and variables
     ```

**Rationale:**
Inventory data becomes actionable when combined with next-step enumeration commands based on what resource types exist in the environment.

---

### 3. rbac.go

**Purpose:** Enumerates RBAC permissions showing users, roles, and scopes.

**Current Loot Files:**
- ❌ None

**Current Output:**
- Table format with: User Name, Role Name, Role Scope

**Analysis:**
RBAC data is highly actionable for privilege escalation and lateral movement but currently only outputs to tables. Missing: privileged role identification, actionable privilege escalation paths, and commands to abuse identified permissions.

**Recommended Loot Files:**

1. **privileged-users.txt**
   - **Contents:** Users with high-privilege roles
   - **Criteria:** Roles like Owner, Contributor, User Access Administrator, privileged built-in roles
   - **Example:**
     ```
     USER: john@contoso.com
     ROLE: Owner
     SCOPE: /subscriptions/12345678-1234-1234-1234-123456789012
     RISK: Full control over subscription resources

     USER: admin@contoso.com
     ROLE: User Access Administrator
     SCOPE: /subscriptions/12345678-1234-1234-1234-123456789012
     RISK: Can grant roles to any principal
     ```

2. **rbac-privilege-escalation-paths.txt**
   - **Contents:** Potential privilege escalation opportunities
   - **Examples:**
     ```
     [Contributor on Resource Group]
     User: user@contoso.com
     Current: Contributor on /subscriptions/.../resourceGroups/prod-rg
     Path: Deploy ARM template with managed identity -> Extract secrets from Key Vault
     Commands:
       az deployment group create --resource-group prod-rg --template-file template.json

     [Virtual Machine Contributor]
     User: ops@contoso.com
     Current: Virtual Machine Contributor on subscription
     Path: Execute commands on VMs -> Access local secrets/credentials
     Commands:
       az vm run-command invoke --resource-group <rg> --name <vm> --command-id RunShellScript --scripts "cat /etc/shadow"
     ```

3. **rbac-enumeration-commands.txt**
   - **Contents:** Commands to further enumerate permissions
   - **Examples:**
     ```bash
     # Check current user's permissions
     az role assignment list --assignee <user-object-id>
     az role assignment list --all --assignee <user-object-id>

     # Get role definition details
     az role definition list --name "Contributor"
     az role definition list --name "Owner"

     # Find users with specific roles
     az role assignment list --role "Owner" --subscription <subscription-id>
     az role assignment list --role "User Access Administrator"

     # Enumerate service principal permissions
     az ad sp list --all
     az role assignment list --assignee <service-principal-id>
     ```

4. **service-principals-with-roles.txt** (if service principals found)
   - **Contents:** Service principals with role assignments
   - **Rationale:** Service principals are often overlooked but can be compromised

**Rationale:**
RBAC data is one of the most actionable outputs for privilege escalation. Identifying privileged roles and providing next-step commands significantly increases the value of this module.

---

### 4. storage.go

**Purpose:** Enumerates storage accounts and checks for public blob access.

**Current Loot Files:**
- ✅ **public-blob-urls.txt**

**Current Loot File Contents:**
- URLs to publicly accessible blobs

**Current Output:**
- Table format with: Subscription Name, Storage Account Name, Container Name, Access Status

**Analysis:**
This module has the best loot file implementation currently. The `public-blob-urls.txt` file contains directly actionable URLs that can be accessed without authentication.

**Current Implementation (storage.go:148-172):**
```go
func writeBlobURLslootFile(callingModule, controlMessagePrefix, outputDirectory string, publicBlobURLs []string) error {
	lootDirectory := filepath.Join(outputDirectory, "loot")
	lootFilePath := filepath.Join(lootDirectory, "public-blob-urls.txt")
	// ... creates loot file with URLs
}
```

**Recommended Additional Loot Files:**

1. **storage-enumeration-commands.txt**
   - **Contents:** Commands to enumerate storage accounts and check permissions
   - **Examples:**
     ```bash
     # List all storage accounts
     az storage account list --subscription <subscription-id>

     # Check storage account keys (requires permissions)
     az storage account keys list --account-name <account> --resource-group <rg>

     # List containers in storage account
     az storage container list --account-name <account> --account-key <key>

     # Check for SAS tokens
     az storage account show-connection-string --name <account> --resource-group <rg>

     # Download blobs
     az storage blob download --account-name <account> --container-name <container> --name <blob> --file <local-file>

     # PowerShell - enumerate with connection string
     $context = New-AzStorageContext -ConnectionString "<connection-string>"
     Get-AzStorageContainer -Context $context
     Get-AzStorageBlob -Container <container> -Context $context
     ```

2. **storage-accounts-with-keys.txt** (if keys accessible)
   - **Contents:** Storage account names and access keys
   - **Generated when:** Current user has permissions to list storage account keys
   - **Example:**
     ```
     STORAGE ACCOUNT: contosodata
     RESOURCE GROUP: prod-rg
     KEY1: [REDACTED-BUT-SHOWN-IN-LOOT]
     CONNECTION STRING: DefaultEndpointsProtocol=https;AccountName=contosodata;AccountKey=...
     ```

3. **private-containers-enumeration.txt**
   - **Contents:** Private containers found with commands to attempt access
   - **Rationale:** Even private containers might be accessible with obtained credentials
   - **Example:**
     ```
     Container: backup-data (Private)
     Storage Account: contosobackup
     Commands to try:
       az storage blob list --account-name contosobackup --container-name backup-data --auth-mode login
       az storage blob list --account-name contosobackup --container-name backup-data --account-key <key>
     ```

**Rationale:**
Expand on the existing good implementation by providing enumeration commands and capturing storage account keys when available.

---

### 5. vms.go

**Purpose:** Enumerates virtual machines with network info and extracts user-data.

**Current Loot Files:**
- ✅ **virtualmachines-user-data** (text file)

**Current Loot File Contents:**
- Decoded user-data from VMs with VM metadata (name, subscription, location, resource group)

**Current Output:**
- Table format with: Subscription Name, VM Name, VM Location, Private IPs, Public IPs, Admin Username, Resource Group Name

**Analysis:**
Good loot file implementation for user-data extraction. User-data often contains secrets, credentials, or startup scripts.

**Current Implementation (vms.go:59-65, 127-133):**
```go
o.Loot.LootFiles = append(o.Loot.LootFiles,
    internal.LootFile{
        Contents: userData,
        Name:     "virtualmachines-user-data"})
```

**Recommended Additional Loot Files:**

1. **vms-public-access.txt**
   - **Contents:** VMs with public IPs and access commands
   - **Generated when:** Public IPs found
   - **Example:**
     ```
     VM: web-server-01
     Public IP: 20.10.30.40
     Admin Username: azureuser
     Location: eastus
     Resource Group: prod-rg

     SSH Access Commands:
       ssh azureuser@20.10.30.40
       ssh -i ~/.ssh/id_rsa azureuser@20.10.30.40

     RDP Access (if Windows):
       xfreerdp /v:20.10.30.40 /u:azureuser

     Port Scanning:
       nmap -Pn -sV -p- 20.10.30.40
       nmap -Pn -sC -sV -p22,80,443,3389 20.10.30.40
     ```

2. **vm-run-command-scripts.txt**
   - **Contents:** Pre-built run-command scripts for VMs where user has access
   - **Examples:**
     ```bash
     # Linux VMs - Extract credentials and secrets
     az vm run-command invoke --resource-group <rg> --name <vm-name> --command-id RunShellScript --scripts "
     cat /etc/shadow
     cat /etc/passwd
     find / -name '*.key' -o -name '*.pem' 2>/dev/null
     cat ~/.ssh/authorized_keys
     cat ~/.bash_history
     env | grep -i 'key\|secret\|password\|token'
     "

     # Windows VMs - Extract credentials
     az vm run-command invoke --resource-group <rg> --name <vm-name> --command-id RunPowerShellScript --scripts "
     Get-ChildItem Env: | Where-Object {$_.Name -match 'password|key|secret|token'}
     Get-Content C:\Users\*\.ssh\* -ErrorAction SilentlyContinue
     Get-ChildItem C:\Users\*\AppData\Local\Microsoft\Credentials\ -ErrorAction SilentlyContinue
     "
     ```

3. **vm-enumeration-commands.txt**
   - **Contents:** Commands to further enumerate VMs
   - **Examples:**
     ```bash
     # Get VM details
     az vm list --subscription <subscription-id> --show-details
     az vm get-instance-view --resource-group <rg> --name <vm-name>

     # Check VM extensions (may reveal managed identity usage)
     az vm extension list --resource-group <rg> --vm-name <vm-name>

     # Get VM diagnostics
     az vm boot-diagnostics get-boot-log --resource-group <rg> --name <vm-name>

     # Check for managed identity
     az vm identity show --resource-group <rg> --name <vm-name>

     # Enumerate network security groups
     az network nsg list --resource-group <rg>
     az network nsg rule list --resource-group <rg> --nsg-name <nsg-name>
     ```

4. **admin-usernames.txt**
   - **Contents:** List of admin usernames found (useful for brute force attempts if needed)
   - **Example:**
     ```
     VM: web-01, Username: azureuser
     VM: db-01, Username: dbadmin
     VM: jump-01, Username: administrator
     ```

**Rationale:**
VMs are critical attack targets. Public IP addresses are highly actionable and should be highlighted with ready-to-use commands for SSH/RDP access and port scanning.

---

## Summary Table

| Module | Current Loot Files | Recommended Loot Files | Priority |
|--------|-------------------|----------------------|----------|
| whoami.go | 0 | 2 | Medium |
| inventory.go | 0 | 3 | Medium |
| rbac.go | 0 | 4 | **HIGH** |
| storage.go | 1 | +3 more | High |
| vms.go | 1 | +4 more | **HIGH** |

---

## General Loot File Guidelines

### What SHOULD be in loot files (Actionable):
- ✅ Commands to execute (az CLI, PowerShell, nmap, etc.)
- ✅ URLs/endpoints to access
- ✅ Credentials, keys, tokens, secrets
- ✅ Usernames for potential attacks
- ✅ Public IP addresses with access commands
- ✅ Privilege escalation paths
- ✅ Configuration containing sensitive data
- ✅ Next-step enumeration commands

### What SHOULD NOT be in loot files (Informational):
- ❌ Software versions (put in table columns)
- ❌ Resource IDs (unless needed for commands)
- ❌ General inventory counts
- ❌ Informational metadata without action items
- ❌ Configuration that doesn't reveal secrets

---

## Implementation Patterns Observed

### Good Pattern (storage.go, vms.go):
```go
if publicBlobURLs != nil {
    err := writeBlobURLslootFile(
        globals.AZ_STORAGE_MODULE_NAME,
        o.PrefixIdentifier,
        o.Table.DirectoryName,
        publicBlobURLs)
}
```

### Recommended Pattern for New Loot Files:
```go
// Create loot file structure
if hasActionableData {
    o.Loot.DirectoryName = filepath.Join(outputDirectory, "loot")
    o.Loot.LootFiles = append(o.Loot.LootFiles,
        internal.LootFile{
            Contents: actionableContent,
            Name:     "descriptive-filename"})
}

// Write at end
o.WriteFullOutput(o.Table.TableFiles, o.Loot.LootFiles)
```

---

## Next Steps

See `todo.md` for detailed implementation tasks.
