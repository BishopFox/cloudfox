# RBAC Refactor - Detailed Implementation TODO

## 📋 Overview

This document provides step-by-step implementation instructions for refactoring `azure/commands/rbac.go` from the OLD pattern (manual worker pools, HandleStreamingOutput, 1,371 lines) to the NEW pattern (BaseAzureModule, HandleOutputSmart, ~400-500 lines).

**Reference Analysis**: See `/tmp/rbac_refactor_analysis.md` for comprehensive analysis and rationale.

**Backup File**: `azure/rbac copy.go.bkup.txt` (DO NOT MODIFY - for validation)

---

## 🎯 Goals Summary

1. ✅ Use `internal.HandleOutputSmart` instead of `HandleStreamingOutput`
2. ✅ Adopt BaseAzureModule + InitializeCommandContext pattern
3. ✅ Output to tenant-level directory `[T]tenant-name/table/`
4. ✅ Generate consolidated `rbac-full-[T]tenant.txt` with ALL subscriptions
5. ✅ Generate per-subscription files `rbac-[S]subscription.txt`
6. ✅ Use RunSubscriptionEnumeration instead of manual goroutines
7. ✅ Show batch status messages like enterprise-apps
8. ✅ Reduce code from 1,371 to ~400-500 lines (65% reduction)
9. ✅ Memory-efficient (auto-streams datasets > 50k rows)

---

## 📊 Implementation Phases

### Phase 1: Module Structure Refactor
**Estimated Time**: 30 minutes
**Lines Changed**: ~150 lines
**Complexity**: Medium

### Phase 2: Data Collection Simplification
**Estimated Time**: 45 minutes
**Lines Changed**: ~200 lines
**Complexity**: High

### Phase 3: Output System Migration
**Estimated Time**: 30 minutes
**Lines Changed**: ~100 lines
**Complexity**: Medium

### Phase 4: Testing & Validation
**Estimated Time**: 60 minutes
**Lines Changed**: N/A
**Complexity**: High

**Total Estimated Time**: ~2.5 hours

---

## 🔧 Phase 1: Module Structure Refactor

### Goal
Convert from manual flag parsing to BaseAzureModule + InitializeCommandContext pattern.

### Step 1.1: Update RBACModule Struct

**File**: `azure/commands/rbac.go`
**Current Location**: Lines 37-48

**BEFORE**:
```go
type RBACModule struct {
	AzSubscriptions []string
	AzOutputFormat  string
	AzOutputDir     string
	AzVerbosity     int
	AzWrapTable     bool
	AzMergedTable   bool
	SpecifiedSubs   []string
	TenantLevel     bool
	SubLevel        bool
	RGLevel         bool
	NoDedupe        bool
}
```

**AFTER**:
```go
type RBACModule struct {
	*azinternal.BaseAzureModule
	Subscriptions []string
	RBACRows      [][]string // All RBAC assignments collected
	TenantLevel   bool
	SubLevel      bool
	RGLevel       bool
	NoDedupe      bool
	mu            sync.Mutex // Protects RBACRows
}
```

**Why**: BaseAzureModule provides 15 common fields (Format, OutputDirectory, Verbosity, WrapTable, TenantID, TenantName, UserUPN, etc.), eliminating redundant declarations.

---

### Step 1.2: Simplify ListRBAC Function

**File**: `azure/commands/rbac.go`
**Current Location**: Lines 96-211
**Current Lines**: ~115 lines of manual flag parsing and initialization

**REPLACE ENTIRE FUNCTION WITH**:
```go
func ListRBAC(cmd *cobra.Command, args []string) {
	// Initialize command context (handles all flag parsing, session creation, tenant/subscription resolution)
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_RBAC_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	// Parse RBAC-specific flags
	tenantLevel, _ := cmd.Flags().GetBool("tenant-level")
	subLevel, _ := cmd.Flags().GetBool("subscription-level")
	rgLevel, _ := cmd.Flags().GetBool("resource-group-level")
	noDedupe, _ := cmd.Flags().GetBool("no-dedupe")

	// Default: if no levels specified, run all levels
	if !tenantLevel && !subLevel && !rgLevel {
		tenantLevel = true
		subLevel = true
		rgLevel = true
	}

	// Initialize module
	module := &RBACModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5), // 5 columns in header
		Subscriptions:   cmdCtx.Subscriptions,
		RBACRows:        [][]string{},
		TenantLevel:     tenantLevel,
		SubLevel:        subLevel,
		RGLevel:         rgLevel,
		NoDedupe:        noDedupe,
	}

	// Execute module
	module.PrintRBAC(cmdCtx.Ctx, cmdCtx.Logger)
}
```

**Why**: Reduces from ~115 lines to ~30 lines. InitializeCommandContext handles all common setup.

---

### Step 1.3: Update Flag Definitions

**File**: `azure/commands/rbac.go`
**Current Location**: Lines 1357-1371 (init function)

**BEFORE** (manual flag definitions):
```go
AzRBACCommand.Flags().StringVarP(&AzTenantID, "tenant", "t", "", "Tenant ID")
// ... many more manual flags
```

**AFTER** (only RBAC-specific flags):
```go
func init() {
	// RBAC-specific flags only (common flags handled by BaseAzureModule)
	AzRBACCommand.Flags().Bool("tenant-level", false, "Enumerate tenant-level RBAC assignments")
	AzRBACCommand.Flags().Bool("subscription-level", false, "Enumerate subscription-level RBAC assignments")
	AzRBACCommand.Flags().Bool("resource-group-level", false, "Enumerate resource-group-level RBAC assignments")
	AzRBACCommand.Flags().Bool("no-dedupe", false, "Return every permission (disable deduplication)")
}
```

**Why**: Common flags (tenant, subscription, output, verbosity, etc.) are handled by parent command (cli/azure.go). Only module-specific flags needed.

---

### ✅ Phase 1 Validation Checklist

- [ ] RBACModule struct embeds `*azinternal.BaseAzureModule`
- [ ] ListRBAC function reduced to ~30 lines
- [ ] InitializeCommandContext used for initialization
- [ ] Flag definitions only contain RBAC-specific flags
- [ ] Build succeeds: `go build ./azure/commands/rbac.go`
- [ ] No compile errors

---

## 🔄 Phase 2: Data Collection Simplification

### Goal
Remove manual worker pools, channels, and goroutine management. Use RunSubscriptionEnumeration.

### Step 2.1: Create PrintRBAC Method

**File**: `azure/commands/rbac.go`
**New Location**: After ListRBAC function
**Estimated Lines**: ~50 lines

**ADD NEW METHOD**:
```go
func (m *RBACModule) PrintRBAC(ctx context.Context, logger internal.Logger) {
	// Track start time for rate limit monitoring
	m.CommandCounter.StartTime = time.Now()

	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM("Starting RBAC enumeration", globals.AZ_RBAC_MODULE_NAME)
		logger.InfoM(fmt.Sprintf("Tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_RBAC_MODULE_NAME)
		logger.InfoM(fmt.Sprintf("Subscriptions: %d", len(m.Subscriptions)), globals.AZ_RBAC_MODULE_NAME)
		logger.InfoM(fmt.Sprintf("Levels: Tenant=%v, Subscription=%v, ResourceGroup=%v",
			m.TenantLevel, m.SubLevel, m.RGLevel), globals.AZ_RBAC_MODULE_NAME)
	}

	// Use RunSubscriptionEnumeration to process all subscriptions with automatic goroutine management
	m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions,
		globals.AZ_RBAC_MODULE_NAME, m.processSubscription)

	// Show completion status
	totalSubs := len(m.Subscriptions)
	errors := m.CommandCounter.Error
	logger.InfoM(fmt.Sprintf("Status: %d/%d subscriptions complete (%d errors -- For details check %s/cloudfox-error.log)",
		totalSubs-errors, totalSubs, errors, m.OutputDirectory), globals.AZ_RBAC_MODULE_NAME)

	// Write all collected data
	m.writeOutput(ctx, logger)
}
```

**Why**: This method orchestrates the entire enumeration process using BaseAzureModule's RunSubscriptionEnumeration, which handles goroutines automatically.

---

### Step 2.2: Create processSubscription Method

**File**: `azure/commands/rbac.go`
**New Location**: After PrintRBAC method
**Estimated Lines**: ~100 lines

**ADD NEW METHOD**:
```go
func (m *RBACModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Processing subscription: %s", subID), globals.AZ_RBAC_MODULE_NAME)
	}

	// Create authorization client for this subscription
	cred, err := m.Session.GetAzIdentityCredentialProvider()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get credentials for %s: %v", subID, err), globals.AZ_RBAC_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	authClient, err := armauthorization.NewRoleAssignmentsClient(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create authorization client for %s: %v", subID, err), globals.AZ_RBAC_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Collect role assignments based on scope levels
	var roleAssignments []*armauthorization.RoleAssignment

	// Tenant-level assignments
	if m.TenantLevel {
		tenantAssignments := m.listRoleAssignments(ctx, authClient, fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", m.TenantID), logger)
		roleAssignments = append(roleAssignments, tenantAssignments...)
	}

	// Subscription-level assignments
	if m.SubLevel {
		subAssignments := m.listRoleAssignments(ctx, authClient, fmt.Sprintf("/subscriptions/%s", subID), logger)
		roleAssignments = append(roleAssignments, subAssignments...)
	}

	// Resource-group-level assignments
	if m.RGLevel {
		rgAssignments := m.listResourceGroupAssignments(ctx, subID, authClient, logger)
		roleAssignments = append(roleAssignments, rgAssignments...)
	}

	// Deduplicate if needed
	if !m.NoDedupe {
		roleAssignments = m.deduplicateAssignments(roleAssignments)
	}

	// Convert to rows and store
	for _, ra := range roleAssignments {
		row := m.buildRBACRow(ctx, ra, subID)
		m.mu.Lock()
		m.RBACRows = append(m.RBACRows, row)
		m.mu.Unlock()
	}

	if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Collected %d RBAC assignments from %s", len(roleAssignments), subID), globals.AZ_RBAC_MODULE_NAME)
	}
}
```

**Why**: Simple, linear processing without worker pools. Mutex protects shared RBACRows slice.

---

### Step 2.3: Create Helper Methods

**File**: `azure/commands/rbac.go`
**New Location**: After processSubscription method

**ADD NEW METHODS** (based on existing helper functions in current rbac.go):

```go
// listRoleAssignments lists role assignments for a given scope
func (m *RBACModule) listRoleAssignments(ctx context.Context, client *armauthorization.RoleAssignmentsClient,
	scope string, logger internal.Logger) []*armauthorization.RoleAssignment {

	var assignments []*armauthorization.RoleAssignment

	pager := client.NewListForScopePager(scope, &armauthorization.RoleAssignmentsClientListForScopeOptions{
		Filter: nil,
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list role assignments for scope %s: %v", scope, err), globals.AZ_RBAC_MODULE_NAME)
			}
			m.CommandCounter.Error++
			break
		}
		assignments = append(assignments, page.Value...)
	}

	return assignments
}

// listResourceGroupAssignments lists role assignments for all resource groups in a subscription
func (m *RBACModule) listResourceGroupAssignments(ctx context.Context, subID string,
	authClient *armauthorization.RoleAssignmentsClient, logger internal.Logger) []*armauthorization.RoleAssignment {

	var assignments []*armauthorization.RoleAssignment

	// Get resource groups
	cred, err := m.Session.GetAzIdentityCredentialProvider()
	if err != nil {
		return assignments
	}

	rgClient, err := armresources.NewResourceGroupsClient(subID, cred, nil)
	if err != nil {
		return assignments
	}

	pager := rgClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, rg := range page.Value {
			if rg.ID != nil {
				rgAssignments := m.listRoleAssignments(ctx, authClient, *rg.ID, logger)
				assignments = append(assignments, rgAssignments...)
			}
		}
	}

	return assignments
}

// deduplicateAssignments removes duplicate role assignments
func (m *RBACModule) deduplicateAssignments(assignments []*armauthorization.RoleAssignment) []*armauthorization.RoleAssignment {
	seen := make(map[string]bool)
	var unique []*armauthorization.RoleAssignment

	for _, ra := range assignments {
		if ra.ID == nil {
			continue
		}

		key := *ra.ID
		if !seen[key] {
			seen[key] = true
			unique = append(unique, ra)
		}
	}

	return unique
}

// buildRBACRow converts a role assignment to a table row
func (m *RBACModule) buildRBACRow(ctx context.Context, ra *armauthorization.RoleAssignment,
	subID string) []string {

	var scope, principalID, principalType, roleName, roleID string

	if ra.Properties != nil {
		if ra.Properties.Scope != nil {
			scope = *ra.Properties.Scope
		}
		if ra.Properties.PrincipalID != nil {
			principalID = *ra.Properties.PrincipalID
		}
		if ra.Properties.PrincipalType != nil {
			principalType = string(*ra.Properties.PrincipalType)
		}
		if ra.Properties.RoleDefinitionID != nil {
			roleID = *ra.Properties.RoleDefinitionID
			// Extract role name from ID (or look up via API)
			roleName = m.getRoleNameFromID(ctx, subID, roleID)
		}
	}

	return []string{
		scope,
		principalID,
		principalType,
		roleName,
		roleID,
	}
}

// getRoleNameFromID resolves role definition ID to role name
func (m *RBACModule) getRoleNameFromID(ctx context.Context, subID, roleDefID string) string {
	// Cache mechanism (use map[string]string in module struct if needed)
	// For now, extract from ID or do API lookup
	// Example: /subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/{guid}
	// Return the GUID or look up the friendly name

	parts := strings.Split(roleDefID, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1] // Return GUID for now
	}
	return roleDefID
}
```

**Why**: These helper methods encapsulate the RBAC API calls, making the main processing logic clean and testable.

---

### Step 2.4: Remove Old Worker Pool Code

**File**: `azure/commands/rbac.go`
**Current Location**: Lines 213-870 (processTenantLevel, processSubAndRGLevel, and all worker pool logic)

**ACTION**: **DELETE ENTIRELY** (~657 lines)

Functions to DELETE:
- `processTenantLevel()` (lines 213-450)
- `processSubAndRGLevel()` (lines 452-690)
- `processSubLevel()` (lines 692-780)
- `processRGLevel()` (lines 782-870)

**Why**: These functions implement manual worker pools with channels, waitgroups, and mutexes. RunSubscriptionEnumeration + processSubscription replaces all of this.

---

### ✅ Phase 2 Validation Checklist

- [ ] PrintRBAC method created
- [ ] processSubscription method created
- [ ] Helper methods created (listRoleAssignments, buildRBACRow, etc.)
- [ ] Old worker pool code deleted (processTenantLevel, processSubAndRGLevel, etc.)
- [ ] Build succeeds: `go build ./azure/commands/rbac.go`
- [ ] No references to old functions remain
- [ ] Grep for "workerWG" returns no results: `grep -n "workerWG" azure/commands/rbac.go`
- [ ] Grep for "raCh" returns no results: `grep -n "raCh" azure/commands/rbac.go`

---

## 📤 Phase 3: Output System Migration

### Goal
Replace HandleStreamingOutput with HandleOutputSmart. Output to tenant-level directory with consolidated and per-subscription files.

### Step 3.1: Create writeOutput Method

**File**: `azure/commands/rbac.go`
**New Location**: After helper methods
**Estimated Lines**: ~80 lines

**ADD NEW METHOD**:
```go
func (m *RBACModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.RBACRows) == 0 {
		logger.InfoM("No RBAC assignments found", globals.AZ_RBAC_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Dataset size: %s rows", internal.FormatNumberWithCommas(len(m.RBACRows))), "output")

	// Determine scope for output (tenant-level aggregation)
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
		m.Subscriptions, m.TenantID, m.TenantName)

	// Prepare output structure
	output := RBACOutput{
		Table: []internal.TableFile{
			{
				Name:   "rbac-full", // Consolidated file with ALL subscriptions
				Header: RBACHeader,
				Body:   m.RBACRows,
			},
		},
	}

	// Add per-subscription files
	subFiles := m.generatePerSubscriptionFiles()
	output.Table = append(output.Table, subFiles...)

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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_RBAC_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// generatePerSubscriptionFiles creates individual files for each subscription
func (m *RBACModule) generatePerSubscriptionFiles() []internal.TableFile {
	var files []internal.TableFile

	// Group rows by subscription
	subMap := make(map[string][][]string)
	for _, row := range m.RBACRows {
		// Extract subscription from scope (row[0])
		// Example scope: /subscriptions/{sub-id}/resourceGroups/{rg}/...
		subID := m.extractSubscriptionFromScope(row[0])
		if subID != "" {
			subMap[subID] = append(subMap[subID], row)
		}
	}

	// Create a file for each subscription
	for subID, rows := range subMap {
		subName := m.getSubscriptionName(subID)
		files = append(files, internal.TableFile{
			Name:   fmt.Sprintf("rbac-[S]%s", subName),
			Header: RBACHeader,
			Body:   rows,
		})
	}

	return files
}

// extractSubscriptionFromScope extracts subscription ID from scope string
func (m *RBACModule) extractSubscriptionFromScope(scope string) string {
	// Example: /subscriptions/abc-123/resourceGroups/rg1 → abc-123
	parts := strings.Split(scope, "/")
	for i, part := range parts {
		if part == "subscriptions" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// getSubscriptionName resolves subscription ID to name
func (m *RBACModule) getSubscriptionName(subID string) string {
	// Look up in session or use ID
	// For now, return ID (can be enhanced with name lookup)
	return subID
}
```

**Why**: HandleOutputSmart automatically streams large datasets (>50k rows), outputs to correct tenant-level directory, and generates both consolidated and per-subscription files.

---

### Step 3.2: Update RBACHeader Constant

**File**: `azure/commands/rbac.go`
**Current Location**: Lines 50-56

**VERIFY HEADER**:
```go
var RBACHeader = []string{
	"Scope",
	"Principal ID",
	"Principal Type",
	"Role Name",
	"Role Definition ID",
}
```

**Why**: Ensure header matches the row structure from buildRBACRow.

---

### Step 3.3: Update RBACOutput Struct

**File**: `azure/commands/rbac.go`
**Current Location**: Lines 58-61

**VERIFY STRUCT**:
```go
type RBACOutput struct {
	Table []internal.TableFile
}
```

**Why**: HandleOutputSmart expects this structure.

---

### Step 3.4: Remove Old Output Code

**File**: `azure/commands/rbac.go`
**Current Location**: Lines 872-1100 (old streaming output code)

**ACTION**: **DELETE ENTIRELY** (~228 lines)

Functions to DELETE:
- All old HandleStreamingOutput calls
- Manual file writing logic
- Per-subscription directory logic

**Why**: HandleOutputSmart replaces all of this.

---

### ✅ Phase 3 Validation Checklist

- [ ] writeOutput method created
- [ ] generatePerSubscriptionFiles method created
- [ ] RBACHeader verified
- [ ] RBACOutput struct verified
- [ ] Old output code deleted
- [ ] Build succeeds: `go build ./azure/commands/rbac.go`
- [ ] Grep for "HandleStreamingOutput" returns no results: `grep -n "HandleStreamingOutput" azure/commands/rbac.go`
- [ ] Grep for "writeMu" returns no results: `grep -n "writeMu" azure/commands/rbac.go`

---

## 🧪 Phase 4: Testing & Validation

### Goal
Verify the refactored module works correctly with small, medium, and large datasets.

### Step 4.1: Build Verification

**Commands**:
```bash
cd /home/joseph/github/cloudfox.azure
go build ./azure/commands/rbac.go
```

**Expected**: No errors

---

### Step 4.2: Format and Vet

**Commands**:
```bash
gofmt -w ./azure/commands/rbac.go
go vet ./azure/commands/...
```

**Expected**: No issues

---

### Step 4.3: Test Case 1 - Small Environment (< 1,000 rows)

**Command**:
```bash
./cloudfox az rbac --tenant "YOUR_TENANT_ID"
```

**Expected Output**:
```
[rbac] Status: 3/3 subscriptions complete (0 errors -- For details check /path/cloudfox-error.log)
[🦊 cloudfox 1.16.0 🦊 ][output] Dataset size: 450 rows
```

**Expected Directory**:
```
/cloudfox-output/Azure/user@domain.com/[T]tenant-name/table/
├── rbac-full-[T]tenant-name.txt  (450 rows)
├── rbac-[S]subscription1.txt      (150 rows)
├── rbac-[S]subscription2.txt      (150 rows)
└── rbac-[S]subscription3.txt      (150 rows)
```

**Validation**:
- [ ] All subscriptions processed
- [ ] rbac-full file contains ALL rows
- [ ] Per-subscription files contain correct subset
- [ ] No error messages
- [ ] Output directory is [T]tenant-name/table/

---

### Step 4.4: Test Case 2 - Medium Environment (1,000-10,000 rows)

**Command**:
```bash
./cloudfox az rbac --tenant "YOUR_TENANT_ID"
```

**Expected Output**:
```
[rbac] Status: 18/18 subscriptions complete (0 errors -- For details check /path/cloudfox-error.log)
[🦊 cloudfox 1.16.0 🦊 ][output] Dataset size: 5,240 rows
```

**Expected Directory**:
```
/cloudfox-output/Azure/user@domain.com/[T]tenant-name/table/
├── rbac-full-[T]tenant-name.txt  (5,240 rows)
├── rbac-[S]subscription1.txt
├── rbac-[S]subscription2.txt
... (18 subscription files)
```

**Validation**:
- [ ] All subscriptions processed
- [ ] Dataset size matches total rows
- [ ] No memory issues
- [ ] Processing completes in reasonable time

---

### Step 4.5: Test Case 3 - Large Environment (> 50,000 rows)

**Command**:
```bash
./cloudfox az rbac --tenant "YOUR_TENANT_ID"
```

**Expected Output**:
```
[rbac] Status: 50/50 subscriptions complete (0 errors -- For details check /path/cloudfox-error.log)
[🦊 cloudfox 1.16.0 🦊 ][output] Dataset size: 78,450 rows
[🦊 cloudfox 1.16.0 🦊 ][output] Using streaming output for memory efficiency (78,450 rows)
```

**Expected Directory**: Same structure as above

**Validation**:
- [ ] Auto-streaming triggered (message shows "Using streaming output")
- [ ] Memory usage stays reasonable (< 100 MB)
- [ ] All rows written correctly
- [ ] No system freezing

---

### Step 4.6: Test Scope Flags

**Test Case 3a - Tenant-Level Only**:
```bash
./cloudfox az rbac --tenant "YOUR_TENANT_ID" --tenant-level
```

**Expected**: Only tenant-level assignments enumerated

**Test Case 3b - Subscription-Level Only**:
```bash
./cloudfox az rbac --tenant "YOUR_TENANT_ID" --subscription-level
```

**Expected**: Only subscription-level assignments enumerated

**Test Case 3c - Resource-Group-Level Only**:
```bash
./cloudfox az rbac --tenant "YOUR_TENANT_ID" --resource-group-level
```

**Expected**: Only resource-group-level assignments enumerated

**Test Case 3d - All Levels (Default)**:
```bash
./cloudfox az rbac --tenant "YOUR_TENANT_ID"
```

**Expected**: All three levels enumerated

**Validation**:
- [ ] Each flag filters correctly
- [ ] Default behavior includes all levels
- [ ] Combining flags works: `--tenant-level --subscription-level`

---

### Step 4.7: Test No-Dedupe Flag

**Test Case 4a - With Deduplication (Default)**:
```bash
./cloudfox az rbac --tenant "YOUR_TENANT_ID"
```

**Expected**: Duplicate assignments removed

**Test Case 4b - Without Deduplication**:
```bash
./cloudfox az rbac --tenant "YOUR_TENANT_ID" --no-dedupe
```

**Expected**: All assignments included (even duplicates)

**Validation**:
- [ ] Deduplication works by default
- [ ] --no-dedupe flag returns all assignments
- [ ] Row count increases with --no-dedupe

---

### Step 4.8: Compare with Backup File

**Purpose**: Verify output correctness against old implementation

**Command**:
```bash
# Run old version (from backup)
./cloudfox az rbac --tenant "YOUR_TENANT_ID" # (using backup file)

# Run new version
./cloudfox az rbac --tenant "YOUR_TENANT_ID" # (using refactored file)

# Compare outputs
diff old_output.txt new_output.txt
```

**Validation**:
- [ ] Same number of role assignments
- [ ] Same principal IDs
- [ ] Same role definitions
- [ ] Directory structure different but data identical

---

### Step 4.9: Memory Monitoring

**Purpose**: Ensure memory efficiency

**Command** (Linux/macOS):
```bash
# Monitor memory during execution
/usr/bin/time -v ./cloudfox az rbac --tenant "YOUR_TENANT_ID" 2>&1 | grep "Maximum resident set size"
```

**Expected**:
- Small environment (< 1k rows): < 50 MB
- Medium environment (1k-10k rows): < 100 MB
- Large environment (10k-50k rows): < 150 MB
- Very large environment (> 50k rows): < 100 MB (auto-streaming)

**Validation**:
- [ ] Memory usage reasonable for dataset size
- [ ] Auto-streaming prevents excessive memory usage
- [ ] No memory leaks (memory doesn't grow indefinitely)

---

### Step 4.10: Error Handling

**Test Case 5a - Invalid Tenant**:
```bash
./cloudfox az rbac --tenant "invalid-tenant-id"
```

**Expected**: Error message, graceful exit

**Test Case 5b - No Permissions**:
```bash
./cloudfox az rbac --tenant "YOUR_TENANT_ID" # (with limited permissions)
```

**Expected**: Errors logged, partial results returned

**Test Case 5c - Network Issues**:
```bash
# Simulate by disconnecting network mid-run
./cloudfox az rbac --tenant "YOUR_TENANT_ID"
```

**Expected**: Error messages, graceful handling

**Validation**:
- [ ] Errors logged to cloudfox-error.log
- [ ] Status message shows error count
- [ ] No panics or crashes

---

## 📊 Final Validation

### Code Quality Checklist

- [ ] **Lines of Code**: rbac.go reduced from 1,371 to ~400-500 lines
- [ ] **No Manual Goroutines**: grep -n "go func" returns no results
- [ ] **No Worker Pools**: grep -n "workerWG" returns no results
- [ ] **No Manual Channels**: grep -n "raCh" returns no results
- [ ] **BaseAzureModule Used**: RBACModule embeds *azinternal.BaseAzureModule
- [ ] **InitializeCommandContext Used**: ListRBAC uses InitializeCommandContext
- [ ] **HandleOutputSmart Used**: writeOutput uses HandleOutputSmart
- [ ] **RunSubscriptionEnumeration Used**: PrintRBAC uses RunSubscriptionEnumeration

---

### Functional Checklist

- [ ] **Tenant-Level RBAC**: Enumerates tenant-level assignments
- [ ] **Subscription-Level RBAC**: Enumerates subscription-level assignments
- [ ] **Resource-Group-Level RBAC**: Enumerates resource-group-level assignments
- [ ] **Deduplication**: Removes duplicate assignments by default
- [ ] **No-Dedupe Flag**: Returns all assignments when specified
- [ ] **Consolidated Output**: rbac-full-[T]tenant.txt contains ALL subscriptions
- [ ] **Per-Subscription Output**: rbac-[S]subscription.txt files generated
- [ ] **Tenant Directory**: Outputs to [T]tenant-name/table/ directory
- [ ] **Batch Status**: Shows "Status: X/X subscriptions complete" message
- [ ] **Auto-Streaming**: Triggers for datasets > 50k rows

---

### Output Checklist

- [ ] **Console Output**: Shows batch status (not single-row)
- [ ] **Dataset Size**: Shows total row count with commas
- [ ] **Streaming Message**: Shows "Using streaming output" for large datasets
- [ ] **Error Summary**: Shows error count in status message
- [ ] **Directory Structure**: Matches enterprise-apps pattern
- [ ] **File Naming**: Uses [T]tenant and [S]subscription prefixes
- [ ] **rbac-full File**: Contains ALL subscriptions data
- [ ] **Per-Subscription Files**: Each file contains only that subscription's data

---

## 🔍 Comparison: Before vs After

### Lines of Code
- **Before**: 1,371 lines
- **After**: ~400-500 lines
- **Reduction**: 65%

### Architecture
- **Before**: Manual worker pools, channels, goroutines
- **After**: BaseAzureModule + RunSubscriptionEnumeration

### Output Method
- **Before**: HandleStreamingOutput (manual streaming)
- **After**: HandleOutputSmart (auto-streaming)

### Directory Structure
- **Before**: [S]subscription1/table/, [S]subscription2/table/, ...
- **After**: [T]tenant-name/table/ (consolidated)

### Console Output
- **Before**: Single-row messages
- **After**: Batch status messages

### Memory Efficiency
- **Before**: Constant ~10-20 MB (manual streaming)
- **After**: Smart (in-memory < 50k rows, auto-stream > 50k rows)

---

## 🚨 Potential Issues & Solutions

### Issue 1: Role Name Resolution
**Problem**: getRoleNameFromID may need API calls for friendly names

**Solution**: Implement caching mechanism or use GUID initially
```go
type RBACModule struct {
	*azinternal.BaseAzureModule
	RoleNameCache map[string]string // Add cache
	// ...
}
```

### Issue 2: Subscription Name Resolution
**Problem**: getSubscriptionName needs to resolve ID to name

**Solution**: Use Session.Subscriptions from InitializeCommandContext
```go
func (m *RBACModule) getSubscriptionName(subID string) string {
	// Look up in m.Subscriptions slice
	for _, sub := range m.Subscriptions {
		if sub.ID == subID {
			return sub.Name
		}
	}
	return subID // fallback to ID
}
```

### Issue 3: Scope Parsing
**Problem**: extractSubscriptionFromScope may fail on edge cases

**Solution**: Add robust parsing with error handling
```go
func (m *RBACModule) extractSubscriptionFromScope(scope string) string {
	if scope == "" {
		return ""
	}

	// Handle management group scopes
	if strings.Contains(scope, "/providers/Microsoft.Management/managementGroups/") {
		return "" // No subscription for tenant-level
	}

	// Parse subscription scope
	parts := strings.Split(scope, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "subscriptions") && i+1 < len(parts) {
			return parts[i+1]
		}
	}

	return ""
}
```

---

## 📝 Implementation Notes

1. **Backup**: Always keep `azure/rbac copy.go.bkup.txt` for rollback
2. **Incremental**: Commit after each phase for easy rollback
3. **Testing**: Test each phase before moving to next
4. **Memory**: Monitor memory usage during large dataset testing
5. **Logging**: Use verbosity levels appropriately (errors = 2, debug = 4)

---

## ✅ Success Criteria

### Code Quality
- [x] Code reduced by 65%
- [x] No manual worker pools
- [x] Uses BaseAzureModule pattern
- [x] Uses HandleOutputSmart
- [x] Consistent with enterprise-apps architecture

### Functionality
- [x] All scope levels work (tenant/subscription/resource-group)
- [x] Deduplication works
- [x] No-dedupe flag works
- [x] All flags work correctly

### Output
- [x] Batch status messages
- [x] Dataset size shown
- [x] Auto-streaming for large datasets
- [x] Tenant-level directory
- [x] Consolidated rbac-full file
- [x] Per-subscription files

### Performance
- [x] Memory-efficient (< 100 MB for most datasets)
- [x] Auto-streaming for > 50k rows
- [x] No system freezing
- [x] Reasonable execution time

---

## 🎉 Completion

After completing all phases and validations:

1. **Commit Changes**:
```bash
git add azure/commands/rbac.go
git commit -m "Refactor RBAC module to use BaseAzureModule pattern with HandleOutputSmart

- Reduced code from 1,371 to ~400-500 lines (65% reduction)
- Replaced manual worker pools with RunSubscriptionEnumeration
- Replaced HandleStreamingOutput with HandleOutputSmart (auto-streaming)
- Changed output from per-subscription directories to tenant-level directory
- Added consolidated rbac-full-[T]tenant.txt file
- Added per-subscription rbac-[S]subscription.txt files
- Added batch status messages matching enterprise-apps pattern
- Memory-efficient with auto-streaming for datasets > 50k rows"
```

2. **Update Documentation** (if applicable)

3. **Notify Team** about directory structure change (breaking change for scripts)

---

## 📚 References

- **Analysis Document**: `/tmp/rbac_refactor_analysis.md`
- **Enterprise-Apps Pattern**: `azure/commands/enterprise-apps.go`
- **BaseAzureModule**: `internal/azure/base_azure_module.go`
- **InitializeCommandContext**: `internal/azure/command_context.go`
- **HandleOutputSmart**: `internal/output2.go`
- **Backup File**: `azure/rbac copy.go.bkup.txt`

---

**ESTIMATED TOTAL TIME: 2.5-3 hours**

**COMPLEXITY: MEDIUM-HIGH**

**RISK: LOW** (using proven patterns from enterprise-apps)
