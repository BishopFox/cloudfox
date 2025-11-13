# Azure CLI Improvements - TODO List

## Overview
This document tracks improvements to cli/azure.go for:
1. Support multiple tenants/subscriptions with flexible parsing ("abc def" OR "abc,def")
2. Run principals.go module first in all-checks command

---

## Phase 1: Analysis (COMPLETED)

### Current State Analysis:

**Subscriptions:**
- ✅ Currently supports: `--subscription "abc,def"` (comma-separated)
- ❌ Does NOT support: `--subscription "abc def"` (space-separated)
- Location: `internal/azure/command_context.go:76-84`
- Current parsing: `strings.Split(subscriptionFlag, ",")`

**Tenants:**
- ❌ Currently supports: ONLY single tenant (`--tenant "abc"`)
- ❌ Does NOT support: Multiple tenants at all
- Location: `internal/azure/command_context.go:32-59`
- Current structure: `tenantID` is a string, not a slice

**All-Checks Command:**
- Location: `cli/azure.go:45-81`
- Currently runs commands in arbitrary order (alphabetical by command registration)
- Does NOT run principals.go first
- Line 71-78: `for _, childCmd := range AzCommands.Commands()`

---

## Phase 2: Design Decisions

### Decision 1: Parsing Strategy for Multiple Values
**Approach:** Support BOTH comma AND space delimiters simultaneously

**Rationale:**
- Users might use either `"abc,def"` OR `"abc def"`
- Shell quoting varies: `--subscription "abc def"` vs `--subscription abc,def`
- Most flexible: split by both comma AND space, then trim/dedupe

**Implementation:**
```go
// Parse subscription/tenant flags supporting both comma and space delimiters
func parseMultiValueFlag(flagValue string) []string {
    if flagValue == "" {
        return nil
    }

    // Replace commas with spaces, then split by whitespace
    normalized := strings.ReplaceAll(flagValue, ",", " ")
    fields := strings.Fields(normalized) // automatically trims and handles multiple spaces

    // Deduplicate
    seen := make(map[string]bool)
    result := []string{}
    for _, field := range fields {
        if !seen[field] && field != "" {
            seen[field] = true
            result = append(result, field)
        }
    }
    return result
}
```

### Decision 2: Multiple Tenants Support
**Challenge:** Current architecture assumes single tenant throughout

**Options:**
1. ❌ **Full multi-tenant support**: Major refactor (hundreds of lines across 30+ modules)
2. ✅ **Validation + Error Message**: Parse multiple tenants but error if >1 provided
3. ⏰ **Future Enhancement**: Add multi-tenant iteration in all-checks only

**Chosen Approach for NOW:** Option 2 (Validation)
- Parse `--tenant "abc def"` into array
- If len > 1, show error: "Multiple tenants not yet supported. Run separately for each tenant."
- Future: all-checks can iterate over multiple tenants

---

## Phase 3: Implementation Tasks

### Task 1: Add parseMultiValueFlag Helper Function
**File:** `internal/azure/command_context.go`
**Location:** Before `InitializeCommandContext` (after imports)
**Estimated Lines:** ~20 lines

```go
// parseMultiValueFlag parses a flag value that can contain comma-separated
// and/or space-separated values. Examples:
//   "abc,def" -> ["abc", "def"]
//   "abc def" -> ["abc", "def"]
//   "abc, def ghi" -> ["abc", "def", "ghi"]
func parseMultiValueFlag(flagValue string) []string {
    if flagValue == "" {
        return nil
    }

    // Replace commas with spaces, then split by whitespace
    normalized := strings.ReplaceAll(flagValue, ",", " ")
    fields := strings.Fields(normalized) // automatically trims and handles multiple spaces

    // Deduplicate while preserving order
    seen := make(map[string]bool)
    result := []string{}
    for _, field := range fields {
        if !seen[field] {
            seen[field] = true
            result = append(result, field)
        }
    }
    return result
}
```

---

### Task 2: Update Tenant Parsing Logic
**File:** `internal/azure/command_context.go`
**Line:** ~32-59 (tenant determination section)
**Changes:**
1. Parse `tenantFlag` using `parseMultiValueFlag()`
2. If multiple tenants provided, show error message
3. Use first tenant for now

**Code Changes:**
```go
// BEFORE (line ~32):
if tenantFlag != "" {
    // Explicit tenant provided
    tenantID = tenantFlag
    tenantInfo = PopulateTenant(session, tenantID)
    ...
}

// AFTER:
if tenantFlag != "" {
    // Parse potentially multiple tenants (support both comma and space delimiters)
    tenants := parseMultiValueFlag(tenantFlag)

    if len(tenants) == 0 {
        logger.ErrorM("Empty tenant flag provided", moduleName)
        session.StopMonitoring()
        return nil, fmt.Errorf("empty tenant flag")
    }

    if len(tenants) > 1 {
        logger.ErrorM(fmt.Sprintf("Multiple tenants not yet supported. Provided: %v. Please run separately for each tenant.", tenants), moduleName)
        session.StopMonitoring()
        return nil, fmt.Errorf("multiple tenants not supported")
    }

    // Use first (and only) tenant
    tenantID = tenants[0]
    tenantInfo = PopulateTenant(session, tenantID)
    tenantName = GetTenantNameFromID(ctx, session, tenantID)
    if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
        logger.InfoM(fmt.Sprintf("Tenant explicitly provided: %s, name resolved as: %s", tenantID, tenantName), moduleName)
    }
}
```

---

### Task 3: Update Subscription Parsing Logic
**File:** `internal/azure/command_context.go`
**Line:** ~76-84 (subscription determination section)
**Changes:**
1. Replace `strings.Split(subscriptionFlag, ",")` with `parseMultiValueFlag(subscriptionFlag)`
2. No other changes needed (already handles multiple subscriptions)

**Code Changes:**
```go
// BEFORE (line ~76):
if subscriptionFlag != "" {
    // User specified subscriptions
    for _, sub := range strings.Split(subscriptionFlag, ",") {
        sub = strings.TrimSpace(sub)
        if sub == "" {
            continue
        }
        ...
    }
}

// AFTER:
if subscriptionFlag != "" {
    // User specified subscriptions (support both comma and space delimiters)
    subscriptionsFromFlag := parseMultiValueFlag(subscriptionFlag)

    for _, sub := range subscriptionsFromFlag {
        found := false
        // First, try to match against tenant subscriptions
        for _, s := range tenantInfo.Subscriptions {
            if strings.EqualFold(s.ID, sub) || strings.EqualFold(s.Name, sub) {
                subscriptions = append(subscriptions, s.ID)
                found = true
                break
            }
        }

        // If not found in tenant enumeration, add it anyway since user explicitly requested it
        if !found {
            subscriptions = append(subscriptions, sub)
            if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
                logger.InfoM(fmt.Sprintf("Subscription %s not found in tenant enumeration, but adding as explicitly requested", sub), moduleName)
            }
        }
    }
}
```

---

### Task 4: Update Tenant Resolution from Subscription
**File:** `internal/azure/command_context.go`
**Line:** ~44-59 (tenant resolution from subscription)
**Changes:** Parse subscriptions before resolving tenant

**Code Changes:**
```go
// BEFORE (line ~44):
} else if subscriptionFlag != "" {
    // Resolve tenant from subscription
    subscriptions := strings.Split(subscriptionFlag, ",")
    for i := range subscriptions {
        subscriptions[i] = strings.TrimSpace(subscriptions[i])
    }
    if tID := GetTenantIDFromSubscription(session, subscriptions[0]); tID != nil {
        tenantID = *tID
        ...
    }
}

// AFTER:
} else if subscriptionFlag != "" {
    // Resolve tenant from subscription (support both comma and space delimiters)
    subscriptionsFromFlag := parseMultiValueFlag(subscriptionFlag)

    if len(subscriptionsFromFlag) == 0 {
        logger.ErrorM("Empty subscription flag provided", moduleName)
        session.StopMonitoring()
        return nil, fmt.Errorf("empty subscription flag")
    }

    // Resolve tenant from first subscription
    if tID := GetTenantIDFromSubscription(session, subscriptionsFromFlag[0]); tID != nil {
        tenantID = *tID
        tenantName = GetTenantNameFromID(ctx, session, tenantID)
        tenantInfo = PopulateTenant(session, tenantID)
        if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
            logger.InfoM(fmt.Sprintf("Tenant resolved from subscription %s: %s (%s)", subscriptionsFromFlag[0], tenantID, tenantName), moduleName)
        }
    } else {
        logger.ErrorM("Failed to resolve tenant from subscription", moduleName)
        session.StopMonitoring()
        return nil, fmt.Errorf("failed to resolve tenant from subscription")
    }
}
```

---

### Task 5: Run Principals First in All-Checks
**File:** `cli/azure.go`
**Line:** 61-79 (AzAllChecksCommand.Run)
**Changes:**
1. Run `commands.AzPrincipalsCommand` first
2. Then run all other commands

**Code Changes:**
```go
// BEFORE (line ~61):
Run: func(cmd *cobra.Command, args []string) {
    // commands we want to skip
    skip := map[string]bool{
        commands.AzDevOpsArtifactsCommand.Use: true,
        commands.AzDevOpsPipelinesCommand.Use: true,
        commands.AzDevOpsProjectsCommand.Use:  true,
        commands.AzDevOpsReposCommand.Use:     true,
    }

    for _, childCmd := range AzCommands.Commands() {
        // Skip self and skip unwanted commands
        if childCmd == cmd || skip[childCmd.Use] {
            continue
        }

        logger.InfoM(fmt.Sprintf("Running command: %s", childCmd.Use), "all-checks")
        childCmd.Run(cmd, args)
    }
},

// AFTER:
Run: func(cmd *cobra.Command, args []string) {
    // ========== STEP 1: Run Principals FIRST ==========
    logger.InfoM("Running command: principals (FIRST - for identity/RBAC lookup)", "all-checks")
    commands.AzPrincipalsCommand.Run(cmd, args)

    // ========== STEP 2: Run all other commands ==========
    // Commands we want to skip
    skip := map[string]bool{
        commands.AzDevOpsArtifactsCommand.Use:  true,
        commands.AzDevOpsPipelinesCommand.Use:  true,
        commands.AzDevOpsProjectsCommand.Use:   true,
        commands.AzDevOpsReposCommand.Use:      true,
        commands.AzPrincipalsCommand.Use:       true,  // Skip since we ran it first
    }

    for _, childCmd := range AzCommands.Commands() {
        // Skip self and skip unwanted commands
        if childCmd == cmd || skip[childCmd.Use] {
            continue
        }

        logger.InfoM(fmt.Sprintf("Running command: %s", childCmd.Use), "all-checks")
        childCmd.Run(cmd, args)
    }
},
```

---

## Phase 4: Testing Plan

### Test Case 1: Single Subscription (Comma)
```bash
./cloudfox az webapps --subscription "abc123"
# Expected: Works as before
```

### Test Case 2: Multiple Subscriptions (Comma)
```bash
./cloudfox az webapps --subscription "abc123,def456"
# Expected: Enumerates both subscriptions
```

### Test Case 3: Multiple Subscriptions (Space)
```bash
./cloudfox az webapps --subscription "abc123 def456"
# Expected: Enumerates both subscriptions
```

### Test Case 4: Multiple Subscriptions (Mixed)
```bash
./cloudfox az webapps --subscription "abc123, def456 ghi789"
# Expected: Enumerates all 3 subscriptions: abc123, def456, ghi789
```

### Test Case 5: Single Tenant
```bash
./cloudfox az principals --tenant "tenant123"
# Expected: Works as before
```

### Test Case 6: Multiple Tenants (Should Fail)
```bash
./cloudfox az principals --tenant "tenant1,tenant2"
# Expected: Error message "Multiple tenants not yet supported..."
```

### Test Case 7: All-Checks Principals First
```bash
./cloudfox az all-checks --tenant "tenant123"
# Expected: principals runs FIRST, then all other commands
```

---

## Phase 5: Implementation Checklist

- [ ] **Task 1:** Add `parseMultiValueFlag()` helper function
- [ ] **Task 2:** Update tenant parsing logic (with multi-tenant validation)
- [ ] **Task 3:** Update subscription parsing in user-specified section
- [ ] **Task 4:** Update subscription parsing in tenant-resolution section
- [ ] **Task 5:** Modify all-checks to run principals first
- [ ] **Task 6:** Test all 7 test cases
- [ ] **Task 7:** Build verification (`go build ./...`)
- [ ] **Task 8:** Format code (`gofmt -w`)

---

## Estimated Effort

| Task | Lines Changed | Complexity | Time Estimate |
|------|---------------|------------|---------------|
| Task 1 | +20 | Low | 5 min |
| Task 2 | ~30 modified | Medium | 10 min |
| Task 3 | ~20 modified | Low | 5 min |
| Task 4 | ~20 modified | Low | 5 min |
| Task 5 | ~15 modified | Low | 5 min |
| Testing | N/A | Medium | 15 min |
| **TOTAL** | ~105 lines | **Medium** | **~45 min** |

---

## Risk Assessment

### Low Risk Changes:
✅ Task 1 (new helper function - no existing code affected)
✅ Task 5 (all-checks ordering - isolated change)

### Medium Risk Changes:
⚠️ Task 2, 3, 4 (subscription/tenant parsing - core functionality)
- **Mitigation:** Thorough testing with existing single-value flags
- **Rollback:** Simple revert if issues arise

### Breaking Changes:
❌ None - All changes are backward compatible
- Single values still work: `--subscription "abc"` → parsed as `["abc"]`
- Comma-separated still works: `--subscription "a,b"` → parsed as `["a", "b"]`
- NEW: Space-separated now works: `--subscription "a b"` → parsed as `["a", "b"]`

---

## Future Enhancements (Out of Scope)

### Multi-Tenant Support in All-Checks
**Future State:**
```bash
./cloudfox az all-checks --tenant "tenant1 tenant2 tenant3"
# Runs all commands for tenant1, then tenant2, then tenant3
```

**Implementation Notes:**
- Would require iterating over tenants in all-checks
- Each module already handles multi-subscription within single tenant
- Estimated effort: 2-3 hours (requires testing across all 40+ modules)

---

## Notes

1. **Backward Compatibility:** All existing commands continue to work unchanged
2. **User Experience:** More flexible input parsing reduces user errors
3. **Documentation:** Should update help text to mention both comma and space delimiters
4. **Future:** Multi-tenant iteration can be added later in all-checks without breaking changes
