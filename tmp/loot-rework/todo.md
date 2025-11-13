# Azure Loot Files Implementation TODO

## Overview
This document contains detailed implementation tasks for adding/improving loot files across Azure CloudFox modules.

**Priority Legend:**
- 🔴 HIGH - Critical for security assessment value
- 🟡 MEDIUM - Valuable but not critical
- 🟢 LOW - Nice to have

---

## Module: rbac.go 🔴 HIGH PRIORITY

### Task 1.1: Add privileged-users.txt loot file
**Priority:** 🔴 HIGH

**Location:** `azure/rbac.go`

**Implementation Details:**
1. Define high-privilege roles to detect:
   ```go
   var highPrivilegeRoles = []string{
       "Owner",
       "Contributor",
       "User Access Administrator",
       "Security Admin",
       "Global Administrator",
       "Privileged Role Administrator",
   }
   ```

2. In `GetRelevantRBACData()` function, add filtering logic:
   ```go
   var privilegedUsers []string
   for _, result := range sortedResults {
       if isHighPrivilegeRole(result.roleName) {
           entry := fmt.Sprintf(
               "USER: %s\nROLE: %s\nSCOPE: %s\nRISK: %s\n\n",
               result.userDisplayName,
               result.roleName,
               result.roleScope,
               getRiskDescription(result.roleName))
           privilegedUsers = append(privilegedUsers, entry)
       }
   }
   ```

3. Add helper functions:
   ```go
   func isHighPrivilegeRole(roleName string) bool {
       for _, privRole := range highPrivilegeRoles {
           if strings.Contains(strings.ToLower(roleName), strings.ToLower(privRole)) {
               return true
           }
       }
       return false
   }

   func getRiskDescription(roleName string) string {
       // Map roles to risk descriptions
       switch {
       case strings.Contains(roleName, "Owner"):
           return "Full control over resources"
       case strings.Contains(roleName, "User Access Administrator"):
           return "Can grant roles to any principal"
       // ... etc
       }
   }
   ```

4. Write loot file in both `getRBACperTenant()` and `getRBACperSubscription()`:
   ```go
   if len(privilegedUsers) > 0 {
       lootContent := strings.Join(privilegedUsers, "---\n")
       // Add to o.Loot.LootFiles similar to vms.go pattern
   }
   ```

**Files to modify:**
- `azure/rbac.go` - Add loot file generation logic

**Testing:**
- Run against test data with privileged roles
- Verify loot file created only when privileged roles exist
- Check file format and content accuracy

---

### Task 1.2: Add rbac-enumeration-commands.txt loot file
**Priority:** 🔴 HIGH

**Implementation Details:**
1. Generate dynamic commands based on discovered users and roles
2. Template structure:
   ```go
   func generateRBACEnumerationCommands(tenantID, subscriptionID string, users []string) string {
       var commands strings.Builder

       commands.WriteString("# RBAC Enumeration Commands\n\n")
       commands.WriteString("## Check current user permissions\n")
       commands.WriteString("az role assignment list --all\n\n")

       commands.WriteString("## Enumerate specific users\n")
       for _, user := range users {
           commands.WriteString(fmt.Sprintf("az role assignment list --assignee %s\n", user))
       }

       // Add more commands...
       return commands.String()
   }
   ```

**Files to modify:**
- `azure/rbac.go`

---

### Task 1.3: Add rbac-privilege-escalation-paths.txt loot file
**Priority:** 🔴 HIGH

**Implementation Details:**
1. Create privilege escalation path detector:
   ```go
   type PrivEscPath struct {
       User           string
       CurrentRole    string
       Scope          string
       EscalationPath string
       Commands       []string
   }

   func detectPrivilegeEscalationPaths(roleAssignments []RoleAssignmentRelevantData) []PrivEscPath {
       var paths []PrivEscPath

       for _, ra := range roleAssignments {
           if isEscalationRole(ra.roleName) {
               path := PrivEscPath{
                   User:           ra.userDisplayName,
                   CurrentRole:    ra.roleName,
                   Scope:          ra.roleScope,
                   EscalationPath: getEscalationPath(ra.roleName),
                   Commands:       getEscalationCommands(ra.roleName, ra.roleScope),
               }
               paths = append(paths, path)
           }
       }
       return paths
   }
   ```

2. Define escalation mappings:
   ```go
   var roleEscalationPaths = map[string]string{
       "Contributor": "Deploy ARM template with managed identity",
       "Virtual Machine Contributor": "Execute commands on VMs via run-command",
       "Automation Contributor": "Create/modify runbooks with high privileges",
       // ... more mappings
   }
   ```

**Files to modify:**
- `azure/rbac.go`

---

### Task 1.4: Add service-principals-with-roles.txt loot file
**Priority:** 🟡 MEDIUM

**Implementation Details:**
1. Modify `GetRelevantRBACData()` to distinguish between users and service principals
2. Service principals have different ObjectType or can be identified by checking PrincipalType
3. Create separate list for service principals with their app IDs and permissions

**Files to modify:**
- `azure/rbac.go`

---

## Module: vms.go 🔴 HIGH PRIORITY

### Task 2.1: Add vms-public-access.txt loot file
**Priority:** 🔴 HIGH

**Location:** `azure/vms.go`

**Implementation Details:**
1. In `getComputeRelevantData()` function, collect VMs with public IPs:
   ```go
   type VMPublicAccess struct {
       VMName           string
       SubscriptionName string
       ResourceGroup    string
       PublicIP         string
       AdminUsername    string
       Location         string
       PrivateIPs       []string
   }

   var vmsWithPublicAccess []VMPublicAccess
   ```

2. During iteration, check for public IPs:
   ```go
   privateIPs, publicIPs := getIPs(...)

   for _, publicIP := range publicIPs {
       if publicIP != "" && publicIP != "NoPublicIP" && !strings.Contains(publicIP, "Error") {
           vmsWithPublicAccess = append(vmsWithPublicAccess, VMPublicAccess{
               VMName:           ptr.ToString(vm.Name),
               SubscriptionName: subscriptionName,
               ResourceGroup:    resourceGroupName,
               PublicIP:         publicIP,
               AdminUsername:    adminUsername,
               Location:         ptr.ToString(vm.Location),
               PrivateIPs:       privateIPs,
           })
       }
   }
   ```

3. Generate loot file content:
   ```go
   func generatePublicAccessCommands(vms []VMPublicAccess) string {
       var output strings.Builder

       output.WriteString("# Virtual Machines with Public IP Access\n\n")

       for _, vm := range vms {
           output.WriteString("===============================================================\n")
           output.WriteString(fmt.Sprintf("VM: %s\n", vm.VMName))
           output.WriteString(fmt.Sprintf("Public IP: %s\n", vm.PublicIP))
           output.WriteString(fmt.Sprintf("Admin Username: %s\n", vm.AdminUsername))
           output.WriteString(fmt.Sprintf("Location: %s\n", vm.Location))
           output.WriteString(fmt.Sprintf("Resource Group: %s\n\n", vm.ResourceGroup))

           output.WriteString("SSH Access Commands (Linux):\n")
           output.WriteString(fmt.Sprintf("  ssh %s@%s\n", vm.AdminUsername, vm.PublicIP))
           output.WriteString(fmt.Sprintf("  ssh -i ~/.ssh/id_rsa %s@%s\n\n", vm.AdminUsername, vm.PublicIP))

           output.WriteString("RDP Access Commands (Windows):\n")
           output.WriteString(fmt.Sprintf("  xfreerdp /v:%s /u:%s\n", vm.PublicIP, vm.AdminUsername))
           output.WriteString(fmt.Sprintf("  rdesktop %s -u %s\n\n", vm.PublicIP, vm.AdminUsername))

           output.WriteString("Port Scanning:\n")
           output.WriteString(fmt.Sprintf("  nmap -Pn -sV -p- %s\n", vm.PublicIP))
           output.WriteString(fmt.Sprintf("  nmap -Pn -sC -sV -p22,80,443,3389,5985,5986 %s\n\n", vm.PublicIP))
       }

       return output.String()
   }
   ```

4. Add to loot files in return statement:
   ```go
   if len(vmsWithPublicAccess) > 0 {
       publicAccessCommands := generatePublicAccessCommands(vmsWithPublicAccess)
       // Add to o.Loot.LootFiles
   }
   ```

**Files to modify:**
- `azure/vms.go` - Modify `getComputeRelevantData()`, `getVMsPerTenantID()`, `getVMsPerSubscriptionID()`

**Testing:**
- Test with VMs that have public IPs
- Test with VMs that don't have public IPs
- Verify commands are correctly formatted

---

### Task 2.2: Add vm-run-command-scripts.txt loot file
**Priority:** 🔴 HIGH

**Implementation Details:**
1. Generate pre-built run-command scripts for enumeration:
   ```go
   func generateRunCommandScripts(subscriptionName, resourceGroup string, vms []string) string {
       var output strings.Builder

       output.WriteString("# VM Run-Command Scripts for Credential Extraction\n\n")
       output.WriteString("## Linux VMs\n\n")

       for _, vmName := range vms {
           output.WriteString(fmt.Sprintf("### VM: %s\n", vmName))
           output.WriteString(fmt.Sprintf("az vm run-command invoke \\\n"))
           output.WriteString(fmt.Sprintf("  --resource-group %s \\\n", resourceGroup))
           output.WriteString(fmt.Sprintf("  --name %s \\\n", vmName))
           output.WriteString(fmt.Sprintf("  --command-id RunShellScript \\\n"))
           output.WriteString(fmt.Sprintf("  --scripts '\n"))
           output.WriteString("    # Extract password hashes\n")
           output.WriteString("    cat /etc/shadow\n")
           output.WriteString("    cat /etc/passwd\n\n")
           output.WriteString("    # Find SSH keys\n")
           output.WriteString("    find /home -name authorized_keys 2>/dev/null\n")
           output.WriteString("    find /home -name id_rsa 2>/dev/null\n")
           output.WriteString("    find /root/.ssh/ 2>/dev/null\n\n")
           output.WriteString("    # Find private keys and certificates\n")
           output.WriteString("    find / -name \"*.key\" -o -name \"*.pem\" 2>/dev/null | head -20\n\n")
           output.WriteString("    # Check bash history\n")
           output.WriteString("    cat ~/.bash_history\n")
           output.WriteString("    cat /root/.bash_history 2>/dev/null\n\n")
           output.WriteString("    # Environment variables\n")
           output.WriteString("    env | grep -i \"key\\|secret\\|password\\|token\"\n")
           output.WriteString("'\n\n")
       }

       output.WriteString("## Windows VMs\n\n")
       // Similar for Windows with PowerShell

       return output.String()
   }
   ```

**Files to modify:**
- `azure/vms.go`

---

### Task 2.3: Add vm-enumeration-commands.txt loot file
**Priority:** 🟡 MEDIUM

**Implementation Details:**
1. Generate general VM enumeration commands
2. Include commands for:
   - Getting VM details
   - Checking extensions
   - Examining managed identities
   - Boot diagnostics
   - NSG rules

**Files to modify:**
- `azure/vms.go`

---

### Task 2.4: Add admin-usernames.txt loot file
**Priority:** 🟢 LOW

**Implementation Details:**
1. Simple extraction of admin usernames from all VMs
2. Format: `VM: <name>, Username: <username>`
3. Useful for password spray attempts

**Files to modify:**
- `azure/vms.go`

---

## Module: storage.go 🟡 MEDIUM PRIORITY

### Task 3.1: Add storage-enumeration-commands.txt loot file
**Priority:** 🟡 MEDIUM

**Location:** `azure/storage.go`

**Implementation Details:**
1. Generate commands based on discovered storage accounts:
   ```go
   func generateStorageEnumerationCommands(storageAccounts []string, subscriptionID string) string {
       var output strings.Builder

       output.WriteString("# Storage Account Enumeration Commands\n\n")

       for _, sa := range storageAccounts {
           output.WriteString(fmt.Sprintf("## Storage Account: %s\n\n", sa))

           output.WriteString("### List containers\n")
           output.WriteString(fmt.Sprintf("az storage container list --account-name %s --auth-mode login\n\n", sa))

           output.WriteString("### Attempt to get access keys\n")
           output.WriteString(fmt.Sprintf("az storage account keys list --account-name %s --subscription %s\n\n", sa, subscriptionID))

           output.WriteString("### Get connection string\n")
           output.WriteString(fmt.Sprintf("az storage account show-connection-string --name %s\n\n", sa))

           // More commands...
       }

       return output.String()
   }
   ```

**Files to modify:**
- `azure/storage.go` - Modify `getRelevantStorageAccountData()`

---

### Task 3.2: Add storage-accounts-with-keys.txt loot file (SENSITIVE)
**Priority:** 🔴 HIGH

**Implementation Details:**
1. **Security Note:** This will contain sensitive credentials
2. Attempt to retrieve storage account keys if user has permissions:
   ```go
   func attemptToGetStorageKeys(subscriptionID, resourceGroup, storageAccountName string) (*string, error) {
       // Use internal client to attempt key retrieval
       client := internal.GetStorageClient(subscriptionID)
       keys, err := client.ListKeys(context.TODO(), resourceGroup, storageAccountName, "")

       if err != nil {
           return nil, err // User doesn't have permission
       }

       if keys.Keys != nil && len(*keys.Keys) > 0 {
           return (*keys.Keys)[0].Value, nil
       }

       return nil, fmt.Errorf("no keys found")
   }
   ```

3. Store successfully retrieved keys securely:
   ```go
   type StorageAccountWithKey struct {
       AccountName      string
       ResourceGroup    string
       SubscriptionName string
       Key              string
       ConnectionString string
   }
   ```

4. Generate loot file only if keys successfully retrieved

**Files to modify:**
- `azure/storage.go`

**Security considerations:**
- Clearly mark this file as containing sensitive data
- Consider adding warning in file header

---

### Task 3.3: Add private-containers-enumeration.txt loot file
**Priority:** 🟢 LOW

**Implementation Details:**
1. List all private containers with attempted access commands
2. Useful for trying different authentication methods

**Files to modify:**
- `azure/storage.go`

---

## Module: inventory.go 🟡 MEDIUM PRIORITY

### Task 4.1: Add high-value-resources-commands.txt loot file
**Priority:** 🟡 MEDIUM

**Location:** `azure/inventory.go`

**Implementation Details:**
1. Define high-value resource types:
   ```go
   var highValueResourceTypes = map[string]string{
       "Microsoft.Compute/virtualMachines":         "Virtual Machines",
       "Microsoft.Storage/storageAccounts":         "Storage Accounts",
       "Microsoft.KeyVault/vaults":                "Key Vaults",
       "Microsoft.Sql/servers":                    "SQL Servers",
       "Microsoft.Web/sites":                      "Web Apps",
       "Microsoft.Automation/automationAccounts":  "Automation Accounts",
       "Microsoft.ContainerRegistry/registries":   "Container Registries",
       // ... more
   }
   ```

2. In `getInventoryInfoPerSubscription()` or `getInventoryInfoPerTenant()`, track found resource types:
   ```go
   var foundHighValueResources []string

   for resourceType := range resourceTypes {
       if _, isHighValue := highValueResourceTypes[resourceType]; isHighValue {
           foundHighValueResources = append(foundHighValueResources, resourceType)
       }
   }
   ```

3. Generate enumeration commands:
   ```go
   func generateHighValueResourceCommands(resourceTypes []string, subscriptionID string) string {
       var output strings.Builder

       output.WriteString("# High-Value Resource Enumeration Commands\n\n")

       for _, rt := range resourceTypes {
           output.WriteString(fmt.Sprintf("## %s\n\n", highValueResourceTypes[rt]))

           switch rt {
           case "Microsoft.KeyVault/vaults":
               output.WriteString("### List Key Vaults\n")
               output.WriteString(fmt.Sprintf("az keyvault list --subscription %s\n\n", subscriptionID))
               output.WriteString("### List secrets (requires permissions)\n")
               output.WriteString("az keyvault secret list --vault-name <vault-name>\n")
               output.WriteString("az keyvault secret show --vault-name <vault-name> --name <secret-name>\n\n")

           case "Microsoft.Sql/servers":
               output.WriteString("### List SQL Servers\n")
               output.WriteString(fmt.Sprintf("az sql server list --subscription %s\n\n", subscriptionID))
               output.WriteString("### List databases\n")
               output.WriteString("az sql db list --server <server-name> --resource-group <rg>\n\n")

           // ... more cases
           }
       }

       return output.String()
   }
   ```

**Files to modify:**
- `azure/inventory.go`

---

### Task 4.2: Add resource-type-enumeration.txt loot file
**Priority:** 🟢 LOW

**Implementation Details:**
1. Generate PowerShell commands for detailed resource property enumeration
2. Use `Get-AzResource` with `-ExpandProperties` flag

**Files to modify:**
- `azure/inventory.go`

---

### Task 4.3: Add interesting-resources.txt loot file
**Priority:** 🟡 MEDIUM

**Implementation Details:**
1. Create risk-based categorization of found resources
2. Provide reasoning and suggested actions
3. Format example:
   ```
   [HIGH] Microsoft.KeyVault/vaults - 5 instances found
   Reason: May contain secrets, certificates, and keys
   Action: Enumerate secrets using Key Vault commands
   Priority: Immediate

   [MEDIUM] Microsoft.Web/sites - 12 instances found
   Reason: Web apps often expose configuration and connection strings
   Action: Check application settings for secrets
   Priority: Medium
   ```

**Files to modify:**
- `azure/inventory.go`

---

## Module: whoami.go 🟢 LOW PRIORITY

### Task 5.1: Add tenant-subscription-enumeration-commands.txt loot file
**Priority:** 🟢 LOW

**Location:** `azure/whoami.go`

**Implementation Details:**
1. Generate basic enumeration commands for discovered tenants/subscriptions:
   ```go
   func generateWhoamiEnumerationCommands(tenants []string, subscriptions []string) string {
       var output strings.Builder

       output.WriteString("# Azure Environment Enumeration Commands\n\n")

       output.WriteString("## Subscription Enumeration\n")
       for _, sub := range subscriptions {
           output.WriteString(fmt.Sprintf("az resource list --subscription %s\n", sub))
           output.WriteString(fmt.Sprintf("az role assignment list --subscription %s\n", sub))
       }

       // ... more commands

       return output.String()
   }
   ```

**Files to modify:**
- `azure/whoami.go`

---

### Task 5.2: Add tenant-domains-for-recon.txt loot file
**Priority:** 🟢 LOW

**Implementation Details:**
1. Extract domain names from tenant info
2. Format for external reconnaissance tools
3. Only create if non-generic domains found

**Files to modify:**
- `azure/whoami.go`

---

## Cross-Cutting Tasks

### Task 6.1: Create shared loot file utilities
**Priority:** 🟡 MEDIUM

**Location:** Create new file `azure/loot_utils.go`

**Implementation Details:**
1. Create shared helper functions:
   ```go
   package azure

   import (
       "fmt"
       "os"
       "path/filepath"
       "github.com/BishopFox/cloudfox/internal"
   )

   // WriteLootFile writes a loot file to the specified directory
   func WriteLootFile(outputDirectory, fileName, content string) error {
       if content == "" {
           return nil // Don't create empty loot files
       }

       lootDirectory := filepath.Join(outputDirectory, "loot")
       err := os.MkdirAll(lootDirectory, os.ModePerm)
       if err != nil {
           return fmt.Errorf("failed to create loot directory: %w", err)
       }

       lootFilePath := filepath.Join(lootDirectory, fileName)
       err = os.WriteFile(lootFilePath, []byte(content), 0644)
       if err != nil {
           return fmt.Errorf("failed to write loot file: %w", err)
       }

       return nil
   }

   // AddLootFileToOutput adds a loot file to the OutputClient
   func AddLootFileToOutput(o *internal.OutputClient, fileName, content string) {
       if content == "" {
           return
       }

       o.Loot.LootFiles = append(o.Loot.LootFiles,
           internal.LootFile{
               Contents: content,
               Name:     fileName,
           })
   }
   ```

**Files to create:**
- `azure/loot_utils.go`

---

### Task 6.2: Add loot file tests
**Priority:** 🟡 MEDIUM

**Implementation Details:**
1. Create test files for each module's loot file generation
2. Example structure:
   ```go
   func TestGenerateRBACPrivilegedUsersLoot(t *testing.T) {
       // Test with privileged roles
       // Test with no privileged roles
       // Test file format
   }
   ```

**Files to create:**
- `azure/rbac_loot_test.go`
- `azure/vms_loot_test.go`
- `azure/storage_loot_test.go`
- etc.

---

### Task 6.3: Update documentation
**Priority:** 🟢 LOW

**Implementation Details:**
1. Update README.md with loot file descriptions
2. Document what each loot file contains
3. Provide examples of loot file output

**Files to modify:**
- `README.md` or relevant docs

---

## Implementation Order Recommendation

### Phase 1: High-Impact, Critical Modules (Week 1-2)
1. ✅ rbac.go - Task 1.1 (privileged-users.txt)
2. ✅ rbac.go - Task 1.2 (rbac-enumeration-commands.txt)
3. ✅ vms.go - Task 2.1 (vms-public-access.txt)
4. ✅ vms.go - Task 2.2 (vm-run-command-scripts.txt)
5. ✅ storage.go - Task 3.2 (storage-accounts-with-keys.txt)

### Phase 2: Medium-Priority Enhancements (Week 3)
6. ✅ rbac.go - Task 1.3 (rbac-privilege-escalation-paths.txt)
7. ✅ storage.go - Task 3.1 (storage-enumeration-commands.txt)
8. ✅ inventory.go - Task 4.1 (high-value-resources-commands.txt)
9. ✅ inventory.go - Task 4.3 (interesting-resources.txt)

### Phase 3: Low-Priority Additions (Week 4)
10. ✅ vms.go - Task 2.3 (vm-enumeration-commands.txt)
11. ✅ rbac.go - Task 1.4 (service-principals-with-roles.txt)
12. ✅ storage.go - Task 3.3 (private-containers-enumeration.txt)
13. ✅ whoami.go - Task 5.1 (tenant-subscription-enumeration-commands.txt)

### Phase 4: Infrastructure & Testing (Week 5)
14. ✅ Task 6.1 (shared utilities)
15. ✅ Task 6.2 (tests)
16. ✅ Task 6.3 (documentation)

---

## Testing Checklist

For each loot file implementation:

- [ ] Test with data that should trigger loot file creation
- [ ] Test with data that should NOT trigger loot file creation (no false positives)
- [ ] Verify file is created in correct directory
- [ ] Verify file content format is correct
- [ ] Verify no empty loot files are created
- [ ] Test with multiple subscriptions/tenants (merged table mode)
- [ ] Test with single subscription mode
- [ ] Verify commands in loot files are syntactically correct
- [ ] Check for any hardcoded values that should be dynamic

---

## Notes

- All loot files should be in `.txt` format for easy viewing
- Commands should be copy-paste ready
- Include comments in command files to explain what each command does
- Consider adding warnings for destructive or risky commands
- Loot files should only be created when there's actual actionable content
- Follow the existing pattern from `storage.go` and `vms.go` for consistency
