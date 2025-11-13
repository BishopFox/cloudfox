# Azure Modules Standardization - TODO Tracker
**Created:** 2025-11-01
**Status:** IN PROGRESS

---

## Phase 1: Remove Redundant Loot Files ⚡ HIGH PRIORITY

### Task 1.1: Remove redundant loot from batch.go
**Status:** ⏳ PENDING
**File:** `azure/commands/batch.go`
**Estimated Time:** 30 minutes

**Changes Required:**
1. Remove `"batch-pools"` from LootMap initialization
2. Remove `"batch-apps"` from LootMap initialization
3. Remove all code that generates content for batch-pools loot file
4. Remove all code that generates content for batch-apps loot file
5. Keep `"batch-commands"` loot file (contains actionable commands)

**Lines to Remove/Modify:**
- LootMap initialization (remove 2 entries)
- processPool() or similar function (remove loot generation)
- processApp() or similar function (remove loot generation)

**Verification:**
- [ ] Build succeeds
- [ ] batch-commands loot file still generated
- [ ] batch-pools loot file NOT generated
- [ ] batch-apps loot file NOT generated
- [ ] Table output unchanged

---

### Task 1.2: Remove redundant loot from app-configuration.go
**Status:** ⏳ PENDING
**File:** `azure/commands/app-configuration.go`
**Estimated Time:** 20 minutes

**Changes Required:**
1. Remove `"appconfig-stores"` from LootMap initialization
2. Remove all code that generates content for appconfig-stores loot file
3. Keep all other loot files:
   - ✅ `appconfig-commands` (actionable)
   - ✅ `appconfig-access-keys` (credentials - HIGH VALUE)
   - ✅ `appconfig-access-scripts` (actionable scripts)

**Lines to Remove/Modify:**
- LootMap initialization (remove 1 entry)
- generateLoot() or processStore() function (remove appconfig-stores generation)

**Verification:**
- [ ] Build succeeds
- [ ] appconfig-stores loot file NOT generated
- [ ] appconfig-access-keys still generated (CRITICAL)
- [ ] appconfig-commands still generated
- [ ] Table output unchanged

---

### Task 1.3: Remove redundant loot from container-apps.go
**Status:** ⏳ PENDING
**File:** `azure/commands/container-apps.go`
**Estimated Time:** 20 minutes

**Changes Required:**
1. Remove `"container-jobs-variables"` from LootMap initialization
2. Remove all code that generates content for container-jobs-variables loot file
3. Keep all other loot files:
   - ✅ `container-jobs-commands` (actionable)
   - ✅ `container-jobs-templates` (deployment templates)

**Lines to Remove/Modify:**
- LootMap initialization (remove 1 entry)
- processJob() or similar function (remove variables loot generation)

**Verification:**
- [ ] Build succeeds
- [ ] container-jobs-variables loot file NOT generated
- [ ] container-jobs-commands still generated
- [ ] container-jobs-templates still generated
- [ ] Table output unchanged

---

## Phase 2: Standardize Column Naming ⚡ HIGH PRIORITY

### Task 2.1: Change "Location" to "Region" in vms.go
**Status:** ⏳ PENDING
**File:** `azure/commands/vms.go`
**Estimated Time:** 15 minutes

**Changes Required:**
1. Find table header definition in writeOutput()
2. Change `"Location"` to `"Region"`
3. Verify row data population uses correct field (likely already using region variable)

**Search Pattern:**
```go
Header: []string{
    ...
    "Location",  // ← Change this to "Region"
    ...
}
```

**Verification:**
- [ ] Build succeeds
- [ ] Header shows "Region" not "Location"
- [ ] Data population unchanged (already correct)
- [ ] Output displays correctly

---

### Task 2.2: Change "Location" to "Region" in storage.go
**Status:** ⏳ PENDING
**File:** `azure/commands/storage.go`
**Estimated Time:** 15 minutes

**Changes Required:**
1. Find table header definition in writeOutput()
2. Change `"Location"` to `"Region"`
3. Verify row data population uses correct field

**Search Pattern:**
```go
Header: []string{
    ...
    "Location",  // ← Change this to "Region"
    ...
}
```

**Verification:**
- [ ] Build succeeds
- [ ] Header shows "Region" not "Location"
- [ ] Data population unchanged
- [ ] Output displays correctly

---

### Task 2.3: Change "Location" to "Region" in webapps.go
**Status:** ⏳ PENDING
**File:** `azure/commands/webapps.go`
**Estimated Time:** 15 minutes

**Changes Required:**
1. Find table header definition in writeOutput()
2. Change `"Location"` to `"Region"` (may appear in multiple tables)
3. Verify row data population uses correct field

**Search Pattern:**
```go
Header: []string{
    ...
    "Location",  // ← Change this to "Region"
    ...
}
```

**Verification:**
- [ ] Build succeeds
- [ ] All table headers show "Region" not "Location"
- [ ] Data population unchanged
- [ ] Output displays correctly

---

### Task 2.4: Change "Location" to "Region" in keyvaults.go
**Status:** ⏳ PENDING
**File:** `azure/commands/keyvaults.go`
**Estimated Time:** 15 minutes

**Changes Required:**
1. Find table header definition in writeOutput()
2. Change `"Location"` to `"Region"`
3. Verify row data population uses correct field

**Search Pattern:**
```go
Header: []string{
    ...
    "Location",  // ← Change this to "Region"
    ...
}
```

**Verification:**
- [ ] Build succeeds
- [ ] Header shows "Region" not "Location"
- [ ] Data population unchanged
- [ ] Output displays correctly

---

## Phase 3: Add Missing Standard Columns ⚡ MEDIUM PRIORITY

### Task 3.1: Add "Resource Group" and "Region" columns to aks.go
**Status:** ⏳ PENDING
**File:** `azure/commands/aks.go`
**Estimated Time:** 45-60 minutes

**Changes Required:**
1. Update table header to include "Resource Group" and "Region"
2. Update row building logic to populate these fields
3. Extract resource group from cluster resource ID or properties
4. Extract region from cluster location property

**Current Header (approximate):**
```go
Header: []string{
    "Subscription ID",
    "Subscription Name",
    // Missing: "Resource Group"
    // Missing: "Region"
    "Cluster Name",
    "DNS Prefix",
    ...
}
```

**Target Header:**
```go
Header: []string{
    "Subscription ID",
    "Subscription Name",
    "Resource Group",      // NEW
    "Region",             // NEW
    "Cluster Name",
    "DNS Prefix",
    ...
}
```

**Row Building Changes:**
- Extract resource group from cluster.ID (parse ARM resource ID)
- Extract region from cluster.Location
- Insert into row array at correct positions

**Verification:**
- [ ] Build succeeds
- [ ] "Resource Group" column appears
- [ ] "Region" column appears
- [ ] Data correctly populated for all clusters
- [ ] No nil pointer errors
- [ ] Output displays correctly

---

## Final Verification Checklist

### Build & Compilation
- [ ] `go build ./...` succeeds
- [ ] No compilation errors
- [ ] No unused import warnings
- [ ] No undefined variable errors

### Loot File Verification
- [ ] batch-pools loot NOT generated
- [ ] batch-apps loot NOT generated
- [ ] appconfig-stores loot NOT generated
- [ ] container-jobs-variables loot NOT generated
- [ ] All HIGH-VALUE loot files still generated:
  - [ ] appconfig-access-keys
  - [ ] webapps-easyauth-tokens
  - [ ] automation-scope-runbooks
  - [ ] vms-userdata
  - [ ] keyvault-soft-deleted-commands

### Column Naming Verification
- [ ] vms.go uses "Region" not "Location"
- [ ] storage.go uses "Region" not "Location"
- [ ] webapps.go uses "Region" not "Location"
- [ ] keyvaults.go uses "Region" not "Location"
- [ ] aks.go includes "Resource Group" column
- [ ] aks.go includes "Region" column

### Functionality Verification
- [ ] Table outputs remain complete
- [ ] No data loss from removed loot files
- [ ] All commands still executable
- [ ] Output formatting correct

---

## Progress Tracking

### Completion Summary
- [x] Phase 1: Remove Redundant Loot Files (3/3 tasks) ✅
- [x] Phase 2: Standardize Column Naming (1/1 tasks - others already correct) ✅
- [x] Phase 3: Add Missing Columns (0/0 tasks - already complete) ✅

**Overall Progress:** 4/4 tasks complete (100%) ✅ COMPLETE

---

## Implementation Order

**Recommended sequence:**
1. ✅ Create this TODO file
2. ⏳ Task 1.1: batch.go loot removal
3. ⏳ Task 1.2: app-configuration.go loot removal
4. ⏳ Task 1.3: container-apps.go loot removal
5. ⏳ Task 2.1: vms.go column rename
6. ⏳ Task 2.2: storage.go column rename
7. ⏳ Task 2.3: webapps.go column rename
8. ⏳ Task 2.4: keyvaults.go column rename
9. ⏳ Task 3.1: aks.go add columns
10. ⏳ Final verification
11. ⏳ Update MISSING_RESOURCES_TODO.md with completion notes

---

## Notes & Considerations

### Why Remove Loot Files?
- Pure metadata duplication with table output
- No additional actionable content
- Reduces output size without information loss
- Improves signal-to-noise ratio

### Why Standardize to "Region"?
- 87.5% of modules already use "Region"
- Consistency improves user experience
- Matches Azure portal terminology
- Easier to grep/search across outputs

### Why Add Columns to AKS?
- Only module missing standard "Resource Group" column
- Improves consistency with other resource modules
- Resource Group is critical for context
- Region information is standard across all resources

---

**Last Updated:** 2025-11-01
**Next Review:** After Phase 1 completion
