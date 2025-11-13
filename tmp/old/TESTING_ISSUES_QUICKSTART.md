# CloudFox Azure Testing Issues - Quick Start Guide

**Date**: 2025-01-XX
**Audience**: Developers

---

## Getting Started

This guide helps you quickly understand and start fixing the testing issues identified in CloudFox Azure.

---

## Document Overview

### 📄 Related Documents

1. **`testing issues`** - Original issue list from testing
2. **`TESTING_ISSUES_ROADMAP.md`** - High-level roadmap with phases and priorities
3. **`TESTING_ISSUES_TODO.md`** - Detailed actionable todo list (THIS IS YOUR MAIN WORKING DOC)
4. **`TESTING_ISSUES_QUICKSTART.md`** - This document

---

## Quick Start: First Issue to Fix

### 🔥 Start Here: Issue #2.1 - Virtual Machines Endpoint Fix

**Why this one?**
- P0 (Critical) - Data accuracy issue
- Self-contained fix (doesn't affect other modules)
- Good learning experience with CloudFox structure

**Time Estimate**: 2-3 hours

**Files to modify**:
- `azure/commands/endpoints.go` (primary)
- `internal/azure/network_helpers.go` (if needed)

**Steps**:

1. **Understand the problem**:
   ```bash
   # Run endpoints module and look at VM entries
   ./cloudfox azure endpoints -t <TENANT> -v 4

   # Look at the output CSV/table
   # Problem: Hostname column has IP addresses, IP column is wrong
   ```

2. **Find the code**:
   ```bash
   cd azure/commands
   grep -n "Virtual Machine\|VirtualMachine\|compute" endpoints.go
   ```

3. **Locate VM enumeration section**:
   - Look for VM/compute resource enumeration
   - Should be around line 200-400 in endpoints.go
   - Find where hostname and IP are extracted

4. **Fix the extraction**:
   ```go
   // BEFORE (example - this is likely wrong):
   hostname := vm.Properties.SomeIPField
   ip := vm.Properties.SomeHostnameField

   // AFTER (correct):
   hostname := getVMHostname(vm)  // Should return FQDN or computer name
   ip := getVMIPAddress(vm)       // Should return actual IP or "N/A"
   ```

5. **Test**:
   ```bash
   go build -o cloudfox .
   ./cloudfox azure endpoints -t <TENANT> -s <SUBSCRIPTION>

   # Verify:
   # - Hostname is not an IP address
   # - IP is a valid IP or "N/A"
   ```

6. **Mark complete**:
   - Update `TESTING_ISSUES_TODO.md`: Check off items 2.1.1 through 2.1.5

---

## Development Workflow

### Branch Strategy

```bash
# For P0 fixes (critical data accuracy)
git checkout -b fix/issue-2-endpoints-alignment

# For P1 enhancements (output restructuring)
git checkout -b feature/issue-1-output-restructure

# For P2 improvements (module enhancements)
git checkout -b enhance/issue-4-entraid-column
```

### Commit Message Format

```
[Issue #X.Y] Brief description

Detailed explanation of what was fixed/added.

- Specific change 1
- Specific change 2

Fixes: #X.Y from TESTING_ISSUES_TODO.md
```

Example:
```
[Issue #2.1] Fix VM hostname/IP column misalignment

VMs were showing IP addresses in hostname column and
incorrect values in IP column.

- Extract hostname from Properties.OSProfile.ComputerName
- Extract IP from network interface PrivateIPAddress
- Handle VMs without public IPs gracefully

Fixes: #2.1.1, #2.1.2, #2.1.3, #2.1.4 from TESTING_ISSUES_TODO.md
```

---

## Testing Strategy

### For Each Fix

1. **Unit Test** (if applicable):
   ```bash
   go test ./internal/azure/... -run TestVMEndpointExtraction
   ```

2. **Manual Test**:
   ```bash
   # Build
   go build -o cloudfox .

   # Run with verbose logging
   ./cloudfox azure <module> -t <TENANT> -v 4

   # Check output files
   ls -la cloudfox-output/Azure/<UPN>/<Tenant>/csv/
   cat cloudfox-output/Azure/<UPN>/<Tenant>/csv/<module>.csv
   ```

3. **Validation Script** (create if needed):
   ```bash
   # Example: tmp/validate_endpoints.sh
   #!/bin/bash
   # Check that hostname column doesn't contain IP addresses
   grep -E "^\d+\.\d+\.\d+\.\d+" endpoints.csv
   # Should return empty if fixed
   ```

---

## Priority Order for Solo Developer

If you're working alone, tackle issues in this order:

### Week 1: Critical Data Fixes (P0)
1. ✅ **Day 1-2**: Issue #2.1 - Fix VM endpoints
2. ✅ **Day 2-3**: Issue #2.2 - Fix Web App endpoints
3. ✅ **Day 3-4**: Issue #2.3 - Fix Bastion endpoints
4. ✅ **Day 4-5**: Issue #2.4 - Fix Firewall endpoints
5. ✅ **Day 5**: Issue #2.5 - Verify Arc endpoints

### Week 2: Principals Data Quality (P0)
1. ✅ **Day 1-2**: Issue #7.1 - Fix RBAC role GUID display
2. ✅ **Day 2-3**: Issue #7.2 - Ensure all roles captured
3. ✅ **Day 3-4**: Issue #7.3 - Fix Graph permissions
4. ✅ **Day 4-5**: Issue #7.4 - Verify OAuth2 grants

### Week 3: Quick Wins (P2)
1. ✅ **Day 1**: Issue #5 - Functions.go cleanup (easy)
2. ✅ **Day 1**: Issue #6 - RBAC.go headers (easy)
3. ✅ **Day 2-5**: Issue #4 - EntraID Centralized Auth column (medium)

### Week 4: Access Keys Enhancement (P1)
1. ✅ **Day 1-3**: Issue #3a - Redesign accesskeys.go
2. ✅ **Day 4-5**: Issue #3b - Review webapp credentials

### Week 5+: Output Restructuring (P1)
1. ✅ **Week 5**: Issue #1 - Design and implement new output structure
2. ✅ **Week 6**: Issue #1 - Update all modules

### Later: Network Security (P2)
1. ✅ **Week 7-8**: Issue #8 - Implement NSG/Firewall/Routes/VNets modules

---

## Quick Reference: File Locations

### Modules (Commands)
```
azure/commands/
├── accesskeys.go      # Issue #3a, #3b
├── endpoints.go       # Issue #2 (all)
├── functions.go       # Issue #5
├── principals.go      # Issue #7
├── rbac.go           # Issue #6
├── vms.go            # Issue #4
├── keyvaults.go      # Issue #4
├── storage.go        # Issue #4
├── aks.go            # Issue #4
└── ... (other modules for Issue #4)
```

### Helpers
```
internal/azure/
├── network_helpers.go     # Issue #2 endpoint extraction
├── rbac_helpers.go        # Issue #7 role resolution
├── dns_helpers.go         # Related to endpoints
└── command_context.go     # Output directory logic (Issue #1)
```

### Output
```
internal/
└── output2.go         # Issue #1 - HandleOutput function
```

---

## Common Patterns

### Pattern 1: Extracting Azure Resource Properties

```go
// Safe string pointer access
hostname := azinternal.SafeStringPtr(resource.Properties.HostName)

// Safe nested property access
if resource.Properties != nil && resource.Properties.NetworkProfile != nil {
    ip = *resource.Properties.NetworkProfile.IPAddress
}

// Default to "N/A" if missing
ip := "N/A"
if resource.Properties != nil && resource.Properties.IPAddress != nil {
    ip = *resource.Properties.IPAddress
}
```

### Pattern 2: Role GUID to Name Resolution

```go
// Create role definitions client
roleDefsClient, _ := armauthorization.NewRoleDefinitionsClient(subID, cred, nil)

// Get role definition by ID
roleDef, err := roleDefsClient.Get(ctx, scope, roleDefID, nil)
if err == nil && roleDef.Properties != nil && roleDef.Properties.RoleName != nil {
    roleName = *roleDef.Properties.RoleName
} else {
    roleName = roleDefID  // Fallback to GUID
}
```

### Pattern 3: Adding Table Column

```go
// 1. Add to header array
Header: []string{
    "Subscription ID",
    "Resource Name",
    "EntraID Centralized Auth",  // NEW COLUMN
    "Other Column",
},

// 2. Add to row data
row := []string{
    subID,
    resourceName,
    getEntraIDAuthStatus(resource),  // NEW DATA
    otherData,
}
```

---

## Debugging Tips

### Enable Verbose Logging

```bash
./cloudfox azure <module> -t <TENANT> -v 4
# Level 4 shows debug messages
```

### Check Module Execution

```bash
# See what's being enumerated
./cloudfox azure endpoints -t <TENANT> -v 4 2>&1 | grep "Enumerating"
```

### Inspect API Calls

```go
// Add temporary logging in your code
logger.InfoM(fmt.Sprintf("VM Properties: %+v", vm.Properties), "endpoints")
```

### Check Output Files

```bash
# Find your output
find cloudfox-output -name "endpoints*.csv"

# View CSV
column -t -s',' cloudfox-output/.../endpoints.csv | less -S
```

---

## Getting Help

### Resources

1. **Azure SDK Documentation**:
   - https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk

2. **CloudFox Patterns**:
   - Look at similar modules (e.g., storage.go, vms.go)
   - Follow established patterns

3. **Testing Issues**:
   - See `tmp/testing issues` for original problem descriptions
   - See `tmp/TESTING_ISSUES_ROADMAP.md` for context

### Questions to Ask

Before starting:
1. Which module is affected?
2. What data is wrong/missing?
3. Where is that data extracted? (which file/function?)
4. What should the correct behavior be?
5. How can I test the fix?

---

## Validation Checklist

Before marking an issue complete:

- [ ] Code builds without errors: `go build ./...`
- [ ] Module runs without crashes: `./cloudfox azure <module> -t <TENANT>`
- [ ] Output data is correct: manual inspection of CSV/JSON
- [ ] Verbose logging shows no errors: `-v 4`
- [ ] Documentation updated (if needed)
- [ ] TESTING_ISSUES_TODO.md checkboxes marked complete

---

## Example: Complete Fix for Issue #2.1 (VM Endpoints)

Here's a complete example of how to fix the VM endpoint issue:

### 1. Find the Problem

```bash
# Run current code
./cloudfox azure endpoints -t <TENANT>

# Output shows (WRONG):
# Hostname: 10.0.0.4
# IP: myvm-01
```

### 2. Locate the Code

```bash
grep -n "Virtual Machine" azure/commands/endpoints.go
# Found at line 250
```

### 3. Review Current Code

```go
// Line 250 - CURRENT (WRONG)
hostname := azinternal.SafeStringPtr(vm.Properties.NetworkProfile.IPAddress)
ip := azinternal.SafeStringPtr(vm.Name)
```

### 4. Fix the Code

```go
// Line 250 - FIXED
// Get hostname from computer name or construct from VM name
hostname := "N/A"
if vm.Properties != nil && vm.Properties.OSProfile != nil && vm.Properties.OSProfile.ComputerName != nil {
    hostname = *vm.Properties.OSProfile.ComputerName
} else {
    hostname = azinternal.SafeStringPtr(vm.Name)
}

// Get IP from network interface
ip := "N/A"
if vm.Properties != nil && vm.Properties.NetworkProfile != nil {
    // Get primary network interface
    for _, nic := range vm.Properties.NetworkProfile.NetworkInterfaces {
        if nic.Properties != nil && nic.Properties.Primary != nil && *nic.Properties.Primary {
            // Get private IP from first IP configuration
            if len(nic.Properties.IPConfigurations) > 0 {
                ipConfig := nic.Properties.IPConfigurations[0]
                if ipConfig.Properties != nil && ipConfig.Properties.PrivateIPAddress != nil {
                    ip = *ipConfig.Properties.PrivateIPAddress
                }
            }
            break
        }
    }
}
```

### 5. Build and Test

```bash
go build -o cloudfox .
./cloudfox azure endpoints -t <TENANT>

# Output shows (CORRECT):
# Hostname: myvm-01
# IP: 10.0.0.4
```

### 6. Mark Complete

Update `tmp/TESTING_ISSUES_TODO.md`:
```markdown
- [x] **2.1.1** Read current VM endpoint extraction logic
- [x] **2.1.2** Identify where VM hostnames are being populated with IP addresses
- [x] **2.1.3** Fix VM hostname extraction
- [x] **2.1.4** Fix VM IP address extraction
- [x] **2.1.5** Test VM endpoint output
```

### 7. Commit

```bash
git add azure/commands/endpoints.go
git commit -m "[Issue #2.1] Fix VM hostname/IP column misalignment

VMs were showing IP addresses in hostname column and
computer names in IP column.

- Extract hostname from Properties.OSProfile.ComputerName
- Extract IP from network interface PrivateIPAddress
- Handle VMs without network interfaces gracefully

Fixes: #2.1.1, #2.1.2, #2.1.3, #2.1.4, #2.1.5 from TESTING_ISSUES_TODO.md"
```

---

## Next Steps

1. ✅ Review this quickstart guide
2. ✅ Read `tmp/TESTING_ISSUES_TODO.md` for your chosen issue
3. ✅ Create a feature branch
4. ✅ Make your changes
5. ✅ Test thoroughly
6. ✅ Update TODO.md checkboxes
7. ✅ Commit with proper message format
8. ✅ Move to next issue

Good luck! 🚀
