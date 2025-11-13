# HandleOutput vs HandleOutputV2 - Comprehensive Comparison

## 📊 Overview

This document compares `HandleOutput` (old) and `HandleOutputV2` (new) to show the differences in directory structure, file paths, and how command-line flags affect output.

---

## 🔑 Key Differences Summary

| Feature | HandleOutput (OLD) | HandleOutputV2 (NEW) |
|---------|-------------------|---------------------|
| **Directory Structure** | `{provider}/{principal}-{identifier}/{module}/` | `{provider}/{principal}/{scope-identifier}/` |
| **Scope Awareness** | Uses `resultsIdentifier` (single string) | Uses `scopeType` + `scopeIdentifiers` + `scopeNames` |
| **Scope Prefix** | None | `[T]-`, `[S]-`, `[O]-`, `[A]-`, `[P]-` (with dash separator) |
| **Tenant-Level Output** | Not supported (per-subscription only) | **Supported** via `scopeType="tenant"` |
| **Multi-Subscription Default** | Creates separate directories per subscription | **Creates separate directories** (one per subscription, no --tenant flag) |
| **Multi-Subscription Consolidated** | Not supported | **Supported** via `--tenant` flag (tenant directory) |
| **Resource Group Support** | No scope awareness | Scope-aware (future: `[RG]-` prefix) |
| **Used By** | DevOps modules only | All Azure modules (via HandleOutputSmart) |
| **Status** | Legacy (deprecated) | **Current standard** |

---

## 🗂️ Directory Structure Comparison

### HandleOutput (OLD) - DevOps Modules Only

**Function Signature:**
```go
HandleOutput(
    cloudProvider string,          // "AzureDevOps"
    format string,                 // "all", "csv", "json"
    outputDirectory string,        // Base directory
    verbosity int,                 // 0-3
    wrap bool,                     // Table wrapping
    baseCloudfoxModule string,     // Module name (e.g., "devops-artifacts")
    principal string,              // Email address
    resultsIdentifier string,      // Organization name
    dataToOutput CloudfoxOutput,
)
```

**Directory Pattern:**
```
{outputDirectory}/cloudfox-output/{cloudProvider}/{principal}-{resultsIdentifier}/{baseCloudfoxModule}/
```

**Example:**
```bash
# Command:
./cloudfox az devops-artifacts --organization "contoso-org"

# Directory created:
~/.cloudfox/cloudfox-output/AzureDevOps/user@contoso.com-contoso-org/devops-artifacts/
├── table/
│   └── devops-artifacts.txt
├── csv/
│   └── devops-artifacts.csv
├── json/
│   └── devops-artifacts.json
└── loot/
    └── artifact-commands.txt
```

**Key Points:**
- ❌ **No scope prefixes** (`[T]`, `[S]`, etc.)
- ❌ **Hardcoded** to single organization per run
- ❌ **Cannot consolidate** multiple organizations
- ❌ **Not tenant-aware** (Azure DevOps specific)

---

### HandleOutputV2 (NEW) - All Azure Modules

**Function Signature:**
```go
HandleOutputV2(
    cloudProvider string,           // "Azure", "AWS", "GCP"
    format string,                  // "all", "csv", "json"
    outputDirectory string,         // Base directory
    verbosity int,                  // 0-3
    wrap bool,                      // Table wrapping
    scopeType string,               // "tenant", "subscription", "organization", etc.
    scopeIdentifiers []string,      // Tenant IDs, Subscription IDs, etc.
    scopeNames []string,            // Friendly names for scopes
    principal string,               // UPN or IAM user
    dataToOutput CloudfoxOutput,
)
```

**Directory Pattern:**
```
{outputDirectory}/cloudfox-output/{cloudProvider}/{principal}/{scopePrefix}{scopeName}/
```

**Scope Prefixes:**
- `[T]-` - Tenant-level (Azure) / Organization-level (AWS, GCP)
- `[S]-` - Subscription-level (Azure) / Account-level (AWS) / Project-level (GCP)
- `[O]-` - Organization-level (legacy AWS/GCP prefix)
- `[A]-` - Account-level (legacy AWS prefix)
- `[P]-` - Project-level (legacy GCP prefix)

**Note:** The dash separator (`-`) is now standard for all scope prefixes.

---

## 📁 Examples with Different Flags

### Example 1: Single Subscription (--subscription flag)

**Azure Command:**
```bash
./cloudfox az aks --subscription "prod-subscription"
```

**AWS Equivalent:**
```bash
./cloudfox aws eks --account "prod-account"
```

**GCP Equivalent:**
```bash
./cloudfox gcp gke --project "prod-project"
```

**HandleOutputV2 Logic:**
```go
// DetermineScopeForOutput determines scope based on subscription count
subscriptions := []string{"abc-123-guid"}  // 1 subscription
scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
    subscriptions,           // 1 subscription
    "tenant-guid",          // tenantID
    "Contoso Tenant",       // tenantName
)
// Returns: scopeType="subscription", scopeIDs=["abc-123-guid"], scopeNames=nil

// Then get subscription name
scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, session, scopeType, scopeIDs)
// scopeNames = ["prod-subscription"]
```

**Directory Created (Azure):**
```
~/.cloudfox/cloudfox-output/Azure/user@contoso.com/[S]-prod-subscription/
├── table/
│   └── aks.txt
├── csv/
│   └── aks.csv
├── json/
│   └── aks.json
└── loot/
    └── aks-commands.txt
```

**Directory Created (AWS):**
```
~/.cloudfox/cloudfox-output/AWS/user@company.com/[A]-prod-account/
├── table/
│   └── eks.txt
└── ...
```

**Directory Created (GCP):**
```
~/.cloudfox/cloudfox-output/GCP/user@company.com/[P]-prod-project/
├── table/
│   └── gke.txt
└── ...
```

**Key Points:**
- ✅ Uses **subscription/account/project scope** (`[S]-`, `[A]-`, `[P]-`)
- ✅ Uses **friendly name** ("prod-subscription")
- ✅ Outputs to **single subscription directory**
- ✅ **ONE file** containing data from that subscription
- ✅ Cloud-agnostic pattern

---

### Example 2: Multiple Subscriptions via --tenant Flag (Auto-Enumerate All)

**Azure Command:**
```bash
./cloudfox az aks --tenant "contoso-tenant-id"
# Automatically enumerates ALL accessible subscriptions in tenant
```

**AWS Equivalent:**
```bash
./cloudfox aws eks --organization "org-id"
# Automatically enumerates ALL accessible accounts in organization
```

**GCP Equivalent:**
```bash
./cloudfox gcp gke --organization "org-id"
# Automatically enumerates ALL accessible projects in organization
```

**HandleOutputV2 Logic:**
```go
// Multiple subscriptions auto-enumerated (18 in this example)
subscriptions := []string{"sub1-guid", "sub2-guid", ..., "sub18-guid"}  // 18 subscriptions
scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
    subscriptions,                // 18 subscriptions
    "tenant-guid",               // tenantID
    "Contoso Tenant",            // tenantName
)
// Returns: scopeType="tenant", scopeIDs=["tenant-guid"], scopeNames=nil

// Note: scopeNames=nil forces use of tenant GUID instead of tenant name
// (see buildResultsIdentifier logic)
```

**Directory Created (Azure):**
```
~/.cloudfox/cloudfox-output/Azure/user@contoso.com/[T]-tenant-guid/
├── table/
│   └── aks.txt                               (ALL 18 subscriptions in ONE file)
├── csv/
│   └── aks.csv                               (ALL 18 subscriptions in ONE file)
├── json/
│   └── aks.json                              (ALL 18 subscriptions in ONE file)
└── loot/
    └── aks-commands.txt
```

**Directory Created (AWS):**
```
~/.cloudfox/cloudfox-output/AWS/user@company.com/[O]-org-id/
├── table/
│   └── eks.txt                               (ALL accounts in ONE file)
└── ...
```

**Directory Created (GCP):**
```
~/.cloudfox/cloudfox-output/GCP/user@company.com/[O]-org-id/
├── table/
│   └── gke.txt                               (ALL projects in ONE file)
└── ...
```

**Key Points:**
- ✅ Uses **tenant/organization scope** (`[T]-`, `[O]-`)
- ✅ Uses **tenant/organization GUID** (not name, because scopeNames=nil)
- ✅ **Consolidates** all subscriptions/accounts/projects into **ONE file**
- ✅ **No per-subscription files** - all data in single file
- ✅ **One location** for all data (easier to find and analyze)
- ✅ **Auto-enumeration** of all accessible resources

---

### Example 3: Specific Subscriptions WITHOUT --tenant Flag (DEFAULT - Separate Directories)

**Azure Command:**
```bash
./cloudfox az aks --subscription "prod-sub,dev-sub,test-sub"
# OR with space separation:
./cloudfox az aks --subscription "prod-sub dev-sub test-sub"
# Note: NO --tenant flag specified
```

**AWS Equivalent:**
```bash
./cloudfox aws eks --account "prod-account,dev-account,test-account"
```

**GCP Equivalent:**
```bash
./cloudfox gcp gke --project "prod-project,dev-project,test-project"
```

**HandleOutputV2 Logic:**
```go
// Multiple subscriptions specified (3 in this example)
subscriptions := []string{"prod-sub-guid", "dev-sub-guid", "test-sub-guid"}  // 3 subscriptions

// DEFAULT BEHAVIOR: Process each subscription separately
for _, subID := range subscriptions {
    scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
        []string{subID},          // Single subscription at a time
        "tenant-guid",           // tenantID
        "Contoso Tenant",        // tenantName
    )
    // Returns: scopeType="subscription", scopeIDs=[subID], scopeNames=[subName]

    // Write output for THIS subscription only
    HandleOutputSmart(..., scopeType, scopeIDs, scopeNames, ...)
}
```

**Directories Created (Azure):**
```
~/.cloudfox/cloudfox-output/Azure/user@contoso.com/[S]-prod-sub/
├── table/
│   └── aks.txt                               (prod-sub ONLY)
├── csv/
│   └── aks.csv
└── loot/
    └── aks-commands.txt

~/.cloudfox/cloudfox-output/Azure/user@contoso.com/[S]-dev-sub/
├── table/
│   └── aks.txt                               (dev-sub ONLY)
└── ...

~/.cloudfox/cloudfox-output/Azure/user@contoso.com/[S]-test-sub/
├── table/
│   └── aks.txt                               (test-sub ONLY)
└── ...
```

**Directories Created (AWS):**
```
~/.cloudfox/cloudfox-output/AWS/user@company.com/[A]-prod-account/
├── table/
│   └── eks.txt                               (prod-account ONLY)
└── ...

~/.cloudfox/cloudfox-output/AWS/user@company.com/[A]-dev-account/
├── table/
│   └── eks.txt                               (dev-account ONLY)
└── ...

~/.cloudfox/cloudfox-output/AWS/user@company.com/[A]-test-account/
├── table/
│   └── eks.txt                               (test-account ONLY)
└── ...
```

**Key Points:**
- ✅ Uses **subscription/account/project scope** (`[S]-`, `[A]-`, `[P]-`)
- ✅ **SEPARATE directories** for each subscription (default when --tenant NOT specified)
- ✅ **ONE file per directory** containing data from that subscription only
- ✅ User has **granular control** - can inspect each subscription independently
- ✅ **No consolidation** - each subscription processed separately
- ✅ Useful when subscriptions have different security postures or owners
- ✅ To consolidate, add `--tenant` flag (see Example 4)

---

### Example 4: Specific Subscriptions WITH --tenant Flag (Consolidated Output)

**Azure Command:**
```bash
./cloudfox az aks --subscription "prod-sub,dev-sub,test-sub" --tenant
# --tenant with no value signals: "consolidate to tenant-level directory"
# OR specify tenant ID explicitly:
./cloudfox az aks --subscription "prod-sub,dev-sub,test-sub" --tenant "tenant-id"
```

**AWS Equivalent:**
```bash
./cloudfox aws eks --account "prod-account,dev-account,test-account" --organization
```

**GCP Equivalent:**
```bash
./cloudfox gcp gke --project "prod-project,dev-project,test-project" --organization
```

**HandleOutputV2 Logic:**
```go
// Multiple subscriptions specified (3 in this example)
subscriptions := []string{"prod-sub-guid", "dev-sub-guid", "test-sub-guid"}  // 3 subscriptions

// --tenant flag is set (with or without value), so use tenant-level consolidation
tenantFlagPresent := true  // User specified --tenant

if tenantFlagPresent {
    // CONSOLIDATED BEHAVIOR: Treat as tenant-level scope
    scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
        subscriptions,            // ALL 3 subscriptions
        "tenant-guid",           // tenantID (auto-detected or from flag)
        "Contoso Tenant",        // tenantName
    )
    // Returns: scopeType="tenant", scopeIDs=["tenant-guid"], scopeNames=nil

    // Write output ONCE with ALL subscriptions in ONE file
    HandleOutputSmart(..., scopeType, scopeIDs, scopeNames, ...)
}
```

**Directory Created (Azure):**
```
~/.cloudfox/cloudfox-output/Azure/user@contoso.com/[T]-tenant-guid/
├── table/
│   └── aks.txt                               (ALL 3 subscriptions in ONE file)
├── csv/
│   └── aks.csv                               (ALL 3 subscriptions in ONE file)
├── json/
│   └── aks.json                              (ALL 3 subscriptions in ONE file)
└── loot/
    └── aks-commands.txt
```

**Directory Created (AWS):**
```
~/.cloudfox/cloudfox-output/AWS/user@company.com/[O]-org-id/
├── table/
│   └── eks.txt                               (ALL 3 accounts in ONE file)
└── ...
```

**Directory Created (GCP):**
```
~/.cloudfox/cloudfox-output/GCP/user@company.com/[O]-org-id/
├── table/
│   └── gke.txt                               (ALL 3 projects in ONE file)
└── ...
```

**Key Points:**
- ✅ Uses **tenant/organization scope** (`[T]-`, `[O]-`)
- ✅ **ONE consolidated directory** for all subscriptions
- ✅ **ONE file** containing data from ALL 3 subscriptions
- ✅ Easier for **cross-subscription analysis** and reporting
- ✅ Reduces number of files to manage
- ✅ Same output behavior as `--tenant` flag (Example 2), but with explicit subscription selection
- ✅ **--tenant flag acts as consolidation signal** (no new flag needed)

**Implementation Notes:**
- When `--tenant` flag is present (with or without value), code detects tenant context
- If tenant not specified in flag, auto-detect from current Azure context
- Allows blank `--tenant` flag: `--tenant ""` or just `--tenant` to signal consolidation

**Comparison: Example 3 vs Example 4**

| Aspect | Example 3 (NO --tenant) | Example 4 (WITH --tenant) |
|--------|------------------------|---------------------------|
| **Command** | `--subscription "a,b,c"` | `--subscription "a,b,c" --tenant` |
| **Directories** | 3 separate (`[S]-a/`, `[S]-b/`, `[S]-c/`) | 1 consolidated (`[T]-tenant-guid/`) |
| **Files** | 3 files (one per subscription) | 1 file (all subscriptions) |
| **Use Case** | Granular per-subscription analysis | Cross-subscription analysis |
| **Easier for** | Comparing individual subscriptions | Finding patterns across all |

---

## 🔄 HandleOutputSmart (Wrapper Around HandleOutputV2)

**HandleOutputSmart** is the **RECOMMENDED** function that automatically chooses between:
- `HandleOutputV2` (for datasets < 50k rows)
- `HandleStreamingOutput` (for datasets ≥ 50k rows)

**Function Signature:**
```go
HandleOutputSmart(
    cloudProvider string,
    format string,
    outputDirectory string,
    verbosity int,
    wrap bool,
    scopeType string,              // Same as HandleOutputV2
    scopeIdentifiers []string,     // Same as HandleOutputV2
    scopeNames []string,           // Same as HandleOutputV2
    principal string,
    dataToOutput CloudfoxOutput,
)
```

**Auto-Streaming Logic:**
```go
totalRows := 0
for _, tableFile := range dataToOutput.TableFiles() {
    totalRows += len(tableFile.Body)
}

if totalRows >= 50000 {
    // Large dataset: Use HandleStreamingOutput (constant memory)
    logger.InfoM(fmt.Sprintf("Using streaming output for memory efficiency (%s rows)",
        formatNumberWithCommas(totalRows)), "output")
    return HandleStreamingOutput(...)
}

// Small dataset: Use HandleOutputV2 (faster, in-memory)
return HandleOutputV2(...)
```

**Thresholds:**
| Rows | Method | Memory | Message |
|------|--------|--------|---------|
| < 50k | HandleOutputV2 | ~1-50 MB | None |
| 50k - 500k | HandleStreamingOutput | ~10-20 MB | "Using streaming output for memory efficiency" |
| 500k - 1M | HandleStreamingOutput | ~10-20 MB | "WARNING: Large dataset detected" |
| ≥ 1M | HandleStreamingOutput | ~10-20 MB | "WARNING: Very large dataset detected" |

---

## 📊 Complete Example with RBAC Module

### RBAC with Single Subscription

**Command:**
```bash
./cloudfox az rbac --subscription "prod-subscription"
```

**Output Directory:**
```
~/.cloudfox/cloudfox-output/Azure/user@contoso.com/[S]-prod-subscription/
├── table/
│   └── rbac.txt
├── csv/
│   └── rbac.csv
└── json/
    └── rbac.json
```

**Console Output:**
```
[rbac] Starting RBAC enumeration
[rbac] Tenant: Contoso Tenant (tenant-guid)
[rbac] Subscriptions: 1
[rbac] Processing subscription: prod-subscription
[rbac] Collected 450 RBAC assignments from prod-subscription
[rbac] Status: 1/1 subscriptions complete (0 errors)
[output] Dataset size: 450 rows
```

---

### RBAC with Tenant (Multiple Subscriptions)

**Command:**
```bash
./cloudfox az rbac --tenant "contoso-tenant-id"
```

**Output Directory:**
```
~/.cloudfox/cloudfox-output/Azure/user@contoso.com/[T]-tenant-guid/
├── table/
│   └── rbac.txt                              (12,450 rows - ALL 18 subscriptions)
├── csv/
│   └── rbac.csv                              (12,450 rows - ALL 18 subscriptions)
└── json/
    └── rbac.json                             (12,450 rows - ALL 18 subscriptions)
```

**Console Output:**
```
[rbac] Starting RBAC enumeration
[rbac] Tenant: Contoso Tenant (tenant-guid)
[rbac] Subscriptions: 18
[rbac] Processing subscription: prod-subscription
[rbac] Collected 4,200 RBAC assignments from prod-subscription
[rbac] Processing subscription: dev-subscription
[rbac] Collected 3,850 RBAC assignments from dev-subscription
... (continues for all subscriptions)
[rbac] Status: 18/18 subscriptions complete (0 errors)
[output] Dataset size: 12,450 rows
```

---

### RBAC with Large Dataset (Auto-Streaming)

**Command:**
```bash
./cloudfox az rbac --tenant "large-enterprise-tenant"
```

**Scenario:** Enterprise with 78,450 RBAC assignments

**Output Directory:**
```
~/.cloudfox/cloudfox-output/Azure/user@contoso.com/[T]-tenant-guid/
├── table/
│   └── rbac.txt                              (78,450 rows - ALL 50 subs - STREAMED)
├── csv/
│   └── rbac.csv                              (78,450 rows - ALL 50 subs - STREAMED)
└── json/
    └── rbac.json                             (78,450 rows - ALL 50 subs)
```

**Console Output:**
```
[rbac] Starting RBAC enumeration
[rbac] Tenant: Enterprise Tenant (tenant-guid)
[rbac] Subscriptions: 50
[rbac] Processing subscription: production-1
[rbac] Collected 12,200 RBAC assignments from production-1
... (continues for all subscriptions)
[rbac] Status: 50/50 subscriptions complete (0 errors)
[output] Dataset size: 78,450 rows
[output] Using streaming output for memory efficiency (78,450 rows)
```

**Memory Usage:**
- Without streaming: ~78 MB in memory
- With auto-streaming: **~10-20 MB constant** (streaming to disk)

---

## 🎯 Summary of Key Advantages (HandleOutputV2)

### 1. **Scope Awareness**
```go
// OLD (HandleOutput)
HandleOutput(..., "devops-artifacts", "user@contoso.com", "contoso-org", ...)
// Directory: .../AzureDevOps/user@contoso.com-contoso-org/devops-artifacts/

// NEW (HandleOutputV2)
HandleOutputV2(..., "tenant", ["tenant-guid"], ["Contoso Tenant"], "user@contoso.com", ...)
// Directory: .../Azure/user@contoso.com/[T]tenant-guid/
```

### 2. **Flexible Multi-Subscription Behavior**
```go
// DEFAULT (no --tenant flag): Separate directories (granular control)
~/.cloudfox/cloudfox-output/Azure/user@contoso.com/[S]-subscription1/table/rbac.txt
~/.cloudfox/cloudfox-output/Azure/user@contoso.com/[S]-subscription2/table/rbac.txt
~/.cloudfox/cloudfox-output/Azure/user@contoso.com/[S]-subscription3/table/rbac.txt

// WITH --tenant flag: Single consolidated location
~/.cloudfox/cloudfox-output/Azure/user@contoso.com/[T]-tenant-guid/
└── table/
    └── rbac.txt  (ALL subscriptions in ONE file)
```

### 3. **Clear Scope Prefixes with Dash Separator**
- `[T]-` = Tenant-level (Azure) / Organization-level (AWS/GCP)
- `[S]-` = Subscription-level (Azure) / Account-level (AWS) / Project-level (GCP)
- `[O]-` = Organization-level (legacy AWS/GCP prefix)
- `[A]-` = Account-level (legacy AWS prefix)
- `[P]-` = Project-level (legacy GCP prefix)

### 4. **Automatic Memory Management (via HandleOutputSmart)**
- < 50k rows: In-memory (fast)
- ≥ 50k rows: Auto-streaming (memory-efficient)

### 5. **Cross-Cloud Consistency**
- Same pattern for Azure, AWS, GCP
- Same scope prefixes across providers
- Easier to script and automate

---

## 📋 Migration Checklist

### For Developers

**Replace HandleOutput with HandleOutputSmart:**

**BEFORE:**
```go
if err := internal.HandleOutput(
    "Azure",
    m.Format,
    m.OutputDirectory,
    m.Verbosity,
    m.WrapTable,
    m.Organization,      // Module name
    m.Email,             // Principal
    m.Organization,      // Results identifier
    output,
); err != nil {
    logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), moduleName)
}
```

**AFTER:**
```go
// Determine scope type and identifiers
scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
    m.Subscriptions, m.TenantID, m.TenantName)

// Get subscription names for output (if single subscription)
scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

// Write output using HandleOutputSmart (auto-streaming for large datasets)
if err := internal.HandleOutputSmart(
    "Azure",
    m.Format,
    m.OutputDirectory,
    m.Verbosity,
    m.WrapTable,
    scopeType,
    scopeIDs,
    scopeNames,
    m.UserUPN,
    output,
); err != nil {
    logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), moduleName)
    m.CommandCounter.Error++
}
```

### Benefits of Migration
- ✅ Automatic streaming for large datasets
- ✅ Tenant-level consolidation (with --tenant flag)
- ✅ Flexible output: separate OR consolidated directories
- ✅ Scope-aware directory structure
- ✅ Cross-cloud consistency
- ✅ Dash-separated scope prefixes for clarity

---

## 📚 References

- **HandleOutput**: `internal/output2.go:76` (Legacy)
- **HandleOutputV2**: `internal/output2.go:986` (Current standard)
- **HandleOutputSmart**: `internal/output2.go:1047` (**RECOMMENDED**)
- **DetermineScopeForOutput**: `internal/azure/command_context.go:500`
- **buildResultsIdentifier**: `internal/output2.go:1132`

---

## ✅ Recommendation

**Use `HandleOutputSmart` for all new modules and refactors:**

1. **Best of both worlds**: In-memory for small datasets, streaming for large
2. **Automatic decision**: No manual tuning required
3. **Memory efficient**: Constant ~10-20 MB for datasets > 50k rows
4. **Scope aware**: Supports tenant-level consolidation via --tenant flag
5. **Cross-cloud**: Consistent across Azure, AWS, GCP
6. **Flexible**: User controls output via --tenant flag presence

**Example Pattern:**
```go
scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
    m.Subscriptions, m.TenantID, m.TenantName)
scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

if err := internal.HandleOutputSmart(
    "Azure", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
    scopeType, scopeIDs, scopeNames, m.UserUPN, output,
); err != nil {
    logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), moduleName)
}
```

---

## 📖 Complete Behavior Summary

### Output Behavior Decision Tree

```
User Command → Output Behavior

1. --subscription "single-sub"
   → [S]-single-sub/ (ONE directory, ONE file)

2. --tenant "tenant-id" (auto-enumerate all)
   → [T]-tenant-guid/ (ONE directory, ONE file with ALL subscriptions)

3. --subscription "sub1,sub2,sub3" (NO --tenant flag)
   → [S]-sub1/ + [S]-sub2/ + [S]-sub3/ (THREE directories, THREE files)

4. --subscription "sub1,sub2,sub3" --tenant
   → [T]-tenant-guid/ (ONE directory, ONE file with ALL subscriptions)
```

### Key Decision: --tenant Flag Presence

| Flag Combination | Subscriptions | Output Strategy | Scope Type | Directories | Files |
|-----------------|---------------|-----------------|------------|-------------|-------|
| `--subscription "sub1"` | 1 | Single subscription | `subscription` | 1: `[S]-sub1/` | 1 per directory |
| `--tenant "id"` | N (auto-enum) | Consolidated tenant | `tenant` | 1: `[T]-tenant-guid/` | 1 total |
| `--subscription "sub1,sub2,sub3"` | 3 | Separate subscriptions | `subscription` | 3: `[S]-sub1/`, `[S]-sub2/`, `[S]-sub3/` | 3 total (1 per directory) |
| `--subscription "sub1,sub2,sub3" --tenant` | 3 | Consolidated tenant | `tenant` | 1: `[T]-tenant-guid/` | 1 total |

### Cloud-Agnostic Equivalents

**Azure:**
- Single: `--subscription "sub1"` → `[S]-sub1/`
- Consolidated: `--subscription "sub1,sub2" --tenant` → `[T]-tenant-guid/`
- Separate: `--subscription "sub1,sub2"` → `[S]-sub1/` + `[S]-sub2/`

**AWS:**
- Single: `--account "account1"` → `[A]-account1/`
- Consolidated: `--account "account1,account2" --organization` → `[O]-org-id/`
- Separate: `--account "account1,account2"` → `[A]-account1/` + `[A]-account2/`

**GCP:**
- Single: `--project "project1"` → `[P]-project1/`
- Consolidated: `--project "project1,project2" --organization` → `[O]-org-id/`
- Separate: `--project "project1,project2"` → `[P]-project1/` + `[P]-project2/`

### Implementation Requirements

**Code Changes Required:**
1. Update `InitializeCommandContext` to allow blank `--tenant` flag
2. Update logic to detect `--tenant` flag presence (not just value)
3. Update `DetermineScopeForOutput` to check for `--tenant` flag
4. Add iteration logic for separate subscription processing when --tenant NOT present
5. Update `getScopePrefix` to include dash separator for all prefixes

**Flag Parsing Logic:**
```go
tenantFlag, _ := cmd.Flags().GetString("tenant")
tenantFlagPresent := cmd.Flags().Changed("tenant")  // True if --tenant specified (even if blank)

if tenantFlagPresent {
    // User wants tenant-level consolidation
    // Use tenantFlag value if provided, else auto-detect
} else if len(subscriptions) > 1 {
    // User specified multiple subscriptions WITHOUT --tenant flag
    // Process each subscription separately
    for _, sub := range subscriptions {
        // Process and output for THIS subscription only
    }
} else {
    // Single subscription - use subscription scope
}
```
