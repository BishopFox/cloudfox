# Azure Module Gold Standard Analysis

**Date:** 2025-11-13
**Analyzed Modules:** acr.go, vms.go, storage.go, aks.go
**Total Azure Modules:** 72
**Goal:** Standardize all Azure command modules to follow gold standard patterns

---

## Executive Summary

All four analyzed modules (**acr.go**, **vms.go**, **storage.go**, **aks.go**) follow a highly consistent architecture with excellent adherence to standardization patterns. They all use `InitializeCommandContext`, embed `BaseAzureModule`, implement multi-tenant support, and follow consistent error handling and output patterns.

**Compliance Score:** 9.5-10/10 across all analyzed modules

---

## Gold Standard Patterns (MANDATORY)

### 1. Cobra Command Entry Point

```go
func ListModuleName(cmd *cobra.Command, args []string) {
    // ✅ STEP 1: Initialize command context
    cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_MODULE_NAME)
    if err != nil {
        return // error already logged by helper
    }
    defer cmdCtx.Session.StopMonitoring()

    // ✅ STEP 2: Initialize module
    module := &ModuleStruct{
        BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
        Subscriptions:   cmdCtx.Subscriptions,
        DataRows:        [][]string{},
        LootMap:         map[string]*internal.LootFile{...},
    }

    // ✅ STEP 3: Execute module
    module.PrintModuleName(cmdCtx.Ctx, cmdCtx.Logger)
}
```

**Required Elements:**
- Use `InitializeCommandContext` (eliminates 800+ lines of duplicate code)
- Return early on error (already logged)
- Defer `Session.StopMonitoring()`
- Use `NewBaseAzureModule` helper (eliminates 15 fields)
- Pass `cmdCtx.Subscriptions` to module
- Call main method with `cmdCtx.Ctx` and `cmdCtx.Logger`

---

### 2. Module Struct Composition

```go
type ModuleStruct struct {
    azinternal.BaseAzureModule // ✅ Embed common fields (15 fields)

    // Module-specific fields
    Subscriptions []string
    DataRows      [][]string              // Preferred: direct table format
    // OR
    Resources     []ResourceStruct        // Alternative: structured data
    LootMap       map[string]*internal.LootFile // Optional
    mu            sync.Mutex              // Required for thread safety
}
```

**Required Elements:**
- Embed `azinternal.BaseAzureModule`
- Include `Subscriptions []string`
- Include `mu sync.Mutex` for thread-safe operations
- Prefer `[][]string` for DataRows unless complex processing needed

---

### 3. Data Structures (Multi-Tenant Support)

```go
type ResourceStruct struct {
    TenantName       string // ✅ REQUIRED: for multi-tenant support
    TenantID         string // ✅ REQUIRED: for multi-tenant support
    SubscriptionID   string
    SubscriptionName string
    ResourceGroup    string
    Region           string
    // ... other fields
}
```

**Required Elements:**
- All data structures MUST include `TenantName` and `TenantID` as first two fields
- These enable multi-tenant output filtering and consolidation

---

### 4. Main Module Method (Multi-Tenant Support)

```go
func (m *ModuleStruct) PrintModuleName(ctx context.Context, logger internal.Logger) {
    // ✅ Multi-tenant processing
    if m.IsMultiTenant {
        logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_MODULE_NAME)

        for _, tenantCtx := range m.Tenants {
            // ✅ Save tenant context
            savedTenantID := m.TenantID
            savedTenantName := m.TenantName
            savedTenantInfo := m.TenantInfo

            // ✅ Set current tenant
            m.TenantID = tenantCtx.TenantID
            m.TenantName = tenantCtx.TenantName
            m.TenantInfo = tenantCtx.TenantInfo

            if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
                logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_MODULE_NAME)
            }

            // ✅ Process subscriptions
            m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions,
                globals.AZ_MODULE_NAME, m.processSubscription)

            // ✅ Restore tenant context
            m.TenantID = savedTenantID
            m.TenantName = savedTenantName
            m.TenantInfo = savedTenantInfo
        }
    } else {
        // ✅ Single tenant processing
        m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions,
            globals.AZ_MODULE_NAME, m.processSubscription)
    }

    // ✅ Generate and write output
    m.writeOutput(ctx, logger)
}
```

**Required Elements:**
- Check `m.IsMultiTenant` first
- Implement save/restore tenant context pattern in multi-tenant loop
- Use `RunSubscriptionEnumeration` with callback (eliminates 240+ lines)
- Call `writeOutput` at the end

---

### 5. Subscription Processing

```go
func (m *ModuleStruct) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
    // ✅ Get subscription name (cached)
    subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

    // ✅ Get resource groups (cached)
    resourceGroups := m.ResolveResourceGroups(subID)

    // ✅ Process resource groups concurrently
    var rgWg sync.WaitGroup
    rgSemaphore := make(chan struct{}, 10) // Limit to 10 concurrent RGs

    for _, rgName := range resourceGroups {
        rgWg.Add(1)
        go m.processResourceGroup(ctx, subID, subName, rgName, &rgWg, rgSemaphore, logger)
    }

    rgWg.Wait()
}
```

**Required Elements:**
- Use `GetSubscriptionNameFromID` for name resolution
- Use `m.ResolveResourceGroups(subID)` for cached RG resolution (eliminates 170+ lines)
- Implement RG-level concurrency with WaitGroup + semaphore
- Semaphore limit of 10 concurrent RGs (standard)
- Pass all context through to `processResourceGroup`

---

### 6. Resource Group Processing

```go
func (m *ModuleStruct) processResourceGroup(ctx context.Context, subID, subName, rgName string,
    wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
    defer wg.Done()

    // ✅ Acquire semaphore
    semaphore <- struct{}{}
    defer func() { <-semaphore }()

    // ✅ Get resources with error handling
    resources, err := sdk.GetResources(ctx, m.Session, subID, rgName)
    if err != nil {
        logger.ErrorM(fmt.Sprintf("Failed to get resources in RG %s: %v", rgName, err),
            globals.AZ_MODULE_NAME)
        m.CommandCounter.Error++
        return
    }

    // ✅ Process each resource
    for _, resource := range resources {
        m.addResourceRow(resource, subID, subName, rgName)
    }
}
```

**Required Elements:**
- Defer `wg.Done()`
- Acquire/release semaphore with defer
- **CRITICAL:** Explicit error handling with `logger.ErrorM`
- **CRITICAL:** Increment `m.CommandCounter.Error++` on errors
- Call thread-safe add methods

---

### 7. Thread-Safe Data Addition

```go
func (m *ModuleStruct) addResourceRow(resource ResourceType, subID, subName, rgName string) {
    m.mu.Lock()
    defer m.mu.Unlock()

    m.DataRows = append(m.DataRows, []string{
        m.TenantName, // ✅ FIRST column: tenant name
        m.TenantID,   // ✅ SECOND column: tenant ID
        subID,
        subName,
        rgName,
        // ... other fields
    })
}
```

**Required Elements:**
- Use mutex lock/unlock with defer
- TenantName and TenantID MUST be first two columns
- Append to shared data structure safely

---

### 8. Output Generation (writeOutput)

```go
func (m *ModuleStruct) writeOutput(ctx context.Context, logger internal.Logger) {
    // ✅ STEP 1: Early return for empty results
    if len(m.DataRows) == 0 {
        logger.InfoM("No resources found", globals.AZ_MODULE_NAME)
        return
    }

    // ✅ STEP 2: Build headers (TenantName and TenantID FIRST)
    headers := []string{
        "Tenant Name", // ✅ FIRST column
        "Tenant ID",   // ✅ SECOND column
        "Subscription ID",
        "Subscription Name",
        "Resource Group",
        // ... other headers
    }

    // ✅ STEP 3: Check multi-tenant splitting FIRST
    if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
        if err := m.FilterAndWritePerTenantAuto(
            ctx, logger, m.Tenants, tableRows, headers,
            "module-name", globals.AZ_MODULE_NAME,
        ); err != nil {
            return
        }
        return
    }

    // ✅ STEP 4: Check multi-subscription splitting SECOND
    if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
        if err := m.FilterAndWritePerSubscriptionAuto(
            ctx, logger, m.Subscriptions, tableRows, headers,
            "module-name", globals.AZ_MODULE_NAME,
        ); err != nil {
            return
        }
        return
    }

    // ✅ STEP 5: Build loot (only non-empty)
    loot := []internal.LootFile{}
    for _, lf := range m.LootMap {
        if lf.Contents != "" {
            loot = append(loot, *lf)
        }
    }

    // ✅ STEP 6: Create output
    output := ModuleOutput{
        Table: []internal.TableFile{{
            Name:   "module-name",
            Header: headers,
            Body:   tableRows, // or m.DataRows
        }},
        Loot: loot,
    }

    // ✅ STEP 7: Determine scope
    scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
        m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
    scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

    // ✅ STEP 8: Write output
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
        logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_MODULE_NAME)
        m.CommandCounter.Error++
    }

    // ✅ STEP 9: Success message
    logger.SuccessM(fmt.Sprintf("Found %d resource(s) across %d subscription(s)",
        len(m.DataRows), len(m.Subscriptions)), globals.AZ_MODULE_NAME)
}
```

**Required Order:**
1. Early return for no results
2. Build headers (TenantName/TenantID first)
3. Check `ShouldSplitByTenant` FIRST
4. Check `ShouldSplitBySubscription` SECOND
5. Build loot (filter empty)
6. Create output
7. Determine scope
8. Write with `HandleOutputSmart`
9. Success message with counts

---

## Error Handling Patterns

### MANDATORY Error Pattern

```go
// ✅ GOLD STANDARD
if err != nil {
    logger.ErrorM(fmt.Sprintf("Failed to get X: %v", err), globals.AZ_MODULE_NAME)
    m.CommandCounter.Error++
    return
}
```

**Required Elements:**
- Use `logger.ErrorM` (not ErrorM directly)
- Include descriptive context in error message
- Include module name constant
- Increment `m.CommandCounter.Error++`
- Return to prevent cascading errors

---

## Context and Logger Usage

### Mandatory Patterns

```go
// ✅ Context: Pass through ALL function calls
func (m *Module) method1(ctx context.Context, ...) {
    method2(ctx, ...)  // Always pass context
}

// ✅ Logger: Pass through ALL function calls that may log
func (m *Module) method1(ctx context.Context, logger internal.Logger) {
    logger.InfoM("Message", globals.AZ_MODULE_NAME)
    method2(ctx, logger)  // Always pass logger
}

// ✅ Session: Use from m.Session (embedded in BaseAzureModule)
func (m *Module) method1(ctx context.Context) {
    result := sdk.GetData(ctx, m.Session, ...)  // Use m.Session
}
```

**Rules:**
- `context.Context` MUST be first parameter
- `internal.Logger` should be passed when logging needed
- Use `m.Session` from BaseAzureModule
- NEVER create new sessions
- NEVER create new contexts (use parent context)

---

## Module Compliance Checklist

Use this checklist when reviewing or creating modules:

### Entry Point
- [ ] Uses `InitializeCommandContext`
- [ ] Returns early on error
- [ ] Defers `Session.StopMonitoring()`
- [ ] Uses `NewBaseAzureModule`
- [ ] Passes `cmdCtx.Subscriptions`

### Module Struct
- [ ] Embeds `BaseAzureModule`
- [ ] Has `Subscriptions []string`
- [ ] Has `mu sync.Mutex`
- [ ] Uses `[][]string` for DataRows (or has good reason for structs)

### Data Structures
- [ ] First field: `TenantName string`
- [ ] Second field: `TenantID string`
- [ ] All subsequent fields use `string` types where possible

### Main Method
- [ ] Checks `m.IsMultiTenant`
- [ ] Implements save/restore tenant context in multi-tenant loop
- [ ] Uses `RunSubscriptionEnumeration`
- [ ] Calls `writeOutput` at end

### Subscription Processing
- [ ] Uses `GetSubscriptionNameFromID`
- [ ] Uses `m.ResolveResourceGroups(subID)`
- [ ] Implements RG-level concurrency
- [ ] Semaphore limit of 10

### Resource Group Processing
- [ ] Defers `wg.Done()`
- [ ] Acquires/releases semaphore
- [ ] Has explicit error handling
- [ ] Increments `CommandCounter.Error++` on errors
- [ ] Calls thread-safe add methods

### Thread Safety
- [ ] Uses `m.mu.Lock()` / `defer m.mu.Unlock()`
- [ ] All shared data modifications are protected

### Output Generation
- [ ] Early return for no results
- [ ] Headers: TenantName and TenantID first
- [ ] Checks `ShouldSplitByTenant` FIRST
- [ ] Checks `ShouldSplitBySubscription` SECOND
- [ ] Uses `DetermineScopeForOutput`
- [ ] Uses `HandleOutputSmart` with all 10 parameters
- [ ] Success message with counts

### Error Handling
- [ ] All errors use `logger.ErrorM`
- [ ] All errors increment `CommandCounter.Error++`
- [ ] Descriptive error messages
- [ ] Include module name in all logs

### Context/Logger
- [ ] Context passed to all functions
- [ ] Logger passed to all logging functions
- [ ] Uses `m.Session` from BaseAzureModule

---

## Identified Gold Standard Modules

**Reference Modules (100% Compliant):**
1. **acr.go** - Most comprehensive, excellent error handling
2. **aks.go** - Clean structure, complete patterns
3. **vms.go** - Rich loot generation, good examples
4. **storage.go** - Complex resource handling

**Use ACR.GO as primary reference when creating new modules.**

---

## Common Anti-Patterns to Avoid

### ❌ Creating Session Manually
```go
// ❌ WRONG
session := azinternal.NewSession(...)

// ✅ CORRECT
// Use m.Session from BaseAzureModule
result := sdk.GetData(ctx, m.Session, ...)
```

### ❌ Creating Context Manually
```go
// ❌ WRONG
ctx := context.Background()

// ✅ CORRECT
// Pass context from parent
func (m *Module) method(ctx context.Context) {
    // Use ctx parameter
}
```

### ❌ Not Using InitializeCommandContext
```go
// ❌ WRONG (800+ lines of boilerplate)
logger := internal.NewLogger()
session, err := azinternal.NewSmartSession(ctx)
tenantID, _ := cmd.PersistentFlags().GetString("tenant")
// ... 40 more lines

// ✅ CORRECT
cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_MODULE_NAME)
```

### ❌ Not Using BaseAzureModule
```go
// ❌ WRONG (15 duplicate fields)
type Module struct {
    Session    *SafeSession
    TenantID   string
    TenantName string
    // ... 12 more fields
}

// ✅ CORRECT
type Module struct {
    azinternal.BaseAzureModule
    // Module-specific fields only
}
```

### ❌ Missing Error Handling
```go
// ❌ WRONG
resources, _ := getResources(...)  // Silent failure

// ✅ CORRECT
resources, err := getResources(...)
if err != nil {
    logger.ErrorM(fmt.Sprintf("Failed: %v", err), globals.AZ_MODULE_NAME)
    m.CommandCounter.Error++
    return
}
```

### ❌ Missing Thread Safety
```go
// ❌ WRONG (race condition)
m.DataRows = append(m.DataRows, row)

// ✅ CORRECT
m.mu.Lock()
defer m.mu.Unlock()
m.DataRows = append(m.DataRows, row)
```

### ❌ Wrong Output Splitting Order
```go
// ❌ WRONG (checks subscription BEFORE tenant)
if azinternal.ShouldSplitBySubscription(...) { ... }
if azinternal.ShouldSplitByTenant(...) { ... }

// ✅ CORRECT (tenant FIRST)
if azinternal.ShouldSplitByTenant(...) { ... }
if azinternal.ShouldSplitBySubscription(...) { ... }
```

### ❌ Missing TenantName/TenantID Columns
```go
// ❌ WRONG
headers := []string{"Subscription ID", "Resource Group", ...}

// ✅ CORRECT
headers := []string{"Tenant Name", "Tenant ID", "Subscription ID", ...}
```

---

## Benefits of Standardization

### Code Reduction
- **800+ lines per module** eliminated with `InitializeCommandContext`
- **240+ lines per module** eliminated with `RunSubscriptionEnumeration`
- **170+ lines per module** eliminated with `ResolveResourceGroups`
- **15 field declarations per module** eliminated with `BaseAzureModule`

**Total:** ~1,200 lines of boilerplate eliminated per module

### Features Gained
- ✅ Multi-tenant support (--tenant "t1,t2,t3")
- ✅ Multi-subscription support (--subscription "s1,s2,s3")
- ✅ Automatic output splitting by tenant/subscription
- ✅ Tenant-wide consolidation mode
- ✅ Consistent error handling and counting
- ✅ Cached resource group resolution
- ✅ Smart session management
- ✅ Automatic scope determination

### Maintainability
- Single source of truth for common patterns
- Easier onboarding for new developers
- Consistent error messages and logging
- Standardized output formats
- Easier to add cross-cutting features

---

## Migration Path for Non-Compliant Modules

### Phase 1: Entry Point (Quick Win)
1. Replace manual initialization with `InitializeCommandContext`
2. Replace manual field copying with `NewBaseAzureModule`
3. Add `defer cmdCtx.Session.StopMonitoring()`

**Effort:** 10 minutes per module
**Benefit:** Immediate 800-line reduction

### Phase 2: Orchestration (Medium Effort)
1. Replace subscription loop with `RunSubscriptionEnumeration`
2. Replace RG resolution with `m.ResolveResourceGroups`
3. Add RG-level concurrency pattern

**Effort:** 30 minutes per module
**Benefit:** 400-line reduction, better performance

### Phase 3: Multi-Tenant Support (Higher Effort)
1. Add `TenantName` and `TenantID` to data structures
2. Add multi-tenant loop with context save/restore
3. Add tenant columns to headers (first two positions)
4. Add output splitting checks

**Effort:** 1-2 hours per module
**Benefit:** Full multi-tenant support

### Phase 4: Output Modernization (Polish)
1. Add `ShouldSplitByTenant` check
2. Add `ShouldSplitBySubscription` check
3. Use `DetermineScopeForOutput`
4. Verify `HandleOutputSmart` parameters

**Effort:** 30 minutes per module
**Benefit:** Consistent output handling

---

## Total Effort Estimate

**Per Module:**
- Simple modules: 2-3 hours
- Complex modules: 4-6 hours

**For 70 modules:**
- Optimistic: 140 hours (3.5 weeks @ 40h/week)
- Realistic: 280 hours (7 weeks @ 40h/week)
- Conservative: 420 hours (10.5 weeks @ 40h/week)

**Recommended Approach:**
- Batch modules by complexity
- Use automation scripts for Phase 1 (entry point)
- Manual review for Phases 2-4
- Test incrementally

---

## Next Steps

1. **Audit all 72 Azure modules** for compliance
2. **Prioritize by usage/importance** (fix high-traffic modules first)
3. **Create migration scripts** for Phase 1 (entry point automation)
4. **Develop testing strategy** (unit tests, integration tests)
5. **Document breaking changes** (if any)
6. **Create PR template** with checklist

---

## Conclusion

The gold standard patterns identified in acr.go, vms.go, storage.go, and aks.go represent a highly mature and well-designed architecture. These patterns eliminate thousands of lines of duplicate code while adding powerful features like multi-tenant support and automatic output splitting.

**Standardizing all 72 Azure modules to these patterns will:**
- Reduce codebase size by ~80,000+ lines
- Add consistent multi-tenant support across all modules
- Improve error handling and observability
- Increase maintainability and developer velocity
- Enable future enhancements with minimal per-module changes

**The investment in standardization will pay dividends in reduced maintenance burden and increased feature velocity.**
