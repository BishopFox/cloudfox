# Loot File Redundancy Removal - Checkbox TODO

**Goal:** Remove 4 redundant loot files that only duplicate table data
**Estimated Time:** 2 hours total
**Impact:** Cleaner code, no loss of functionality

---

## Task 1: Remove `endpoints-commands` from endpoints.go

- [ ] **1.1** Open `azure/commands/endpoints.go`
- [ ] **1.2** Find LootMap initialization (around line 60-65) and remove the `"endpoints-commands"` entry
- [ ] **1.3** Search for any code that populates `endpoints-commands` loot file (around line 220-225) and remove it
- [ ] **1.4** Ensure `endpoints-commands` is not added to the loot output array in writeOutput function
- [ ] **1.5** Build: `go build ./azure/commands/endpoints.go`
- [ ] **1.6** Verify: grep for any remaining references: `grep -n "endpoints-commands" azure/commands/endpoints.go`

---

## Task 2: Remove `container-jobs-variables` from container-apps.go

- [ ] **2.1** Open `azure/commands/container-apps.go`
- [ ] **2.2** Find LootMap initialization (around line 70-75) and remove ONLY the `"container-jobs-variables"` entry
- [ ] **2.3** KEEP `"container-jobs-commands"` and `"container-jobs-templates"` - these are valuable
- [ ] **2.4** Search for code that appends to `container-jobs-variables` (around line 180-200) and remove it
      - Look for: `m.LootMap["container-jobs-variables"].Contents += ...`
- [ ] **2.5** Ensure the other two loot files (commands and templates) remain untouched
- [ ] **2.6** Build: `go build ./azure/commands/container-apps.go`
- [ ] **2.7** Verify: grep for any remaining references: `grep -n "container-jobs-variables" azure/commands/container-apps.go`

---

## Task 3: Remove `network-interface-commands` from network-interfaces.go

- [ ] **3.1** Open `azure/commands/network-interfaces.go`
- [ ] **3.2** Find LootMap initialization (around line 65-70) and remove ONLY the `"network-interface-commands"` entry
- [ ] **3.3** KEEP `"network-interfaces-PrivateIPs"` and `"network-interfaces-PublicIPs"` - these are valuable for nmap/masscan
- [ ] **3.4** Search for code that populates `network-interface-commands` (around line 200-215) and remove it
- [ ] **3.5** Ensure IP list loot files remain untouched
- [ ] **3.6** Build: `go build ./azure/commands/network-interfaces.go`
- [ ] **3.7** Verify: grep for any remaining references: `grep -n "network-interface-commands" azure/commands/network-interfaces.go`

---

## Task 4: Remove `app-gateway-commands` from appgw.go

- [ ] **4.1** Open `azure/commands/appgw.go`
- [ ] **4.2** Find LootMap initialization (around line 70-75) and remove the `"app-gateway-commands"` entry
- [ ] **4.3** Search for any code that populates `app-gateway-commands` and remove it (likely none exists)
      - Run: `grep -n "app-gateway-commands" azure/commands/appgw.go`
- [ ] **4.4** Ensure it's not added to loot output array in writeOutput function
- [ ] **4.5** Build: `go build ./azure/commands/appgw.go`

---

## Final Verification

### Build Verification
- [ ] **V.1** Full build: `cd /home/joseph/github/cloudfox.azure && go build ./...`
- [ ] **V.2** Verify no compilation errors

### Code Verification
- [ ] **V.3** Search entire codebase for removed loot file names:
  ```bash
  grep -r "endpoints-commands" azure/commands/
  grep -r "container-jobs-variables" azure/commands/
  grep -r "network-interface-commands" azure/commands/
  grep -r "app-gateway-commands" azure/commands/
  ```
  - Expected: No results (or only comments)

### Runtime Verification (Optional - requires Azure access)
- [ ] **V.4** Test endpoints module: `./cloudfox az endpoints --subscription <sub-id>`
- [ ] **V.5** Test container-apps module: `./cloudfox az container-apps --subscription <sub-id>`
- [ ] **V.6** Test network-interfaces module: `./cloudfox az network-interfaces --subscription <sub-id>`
- [ ] **V.7** Test appgw module: `./cloudfox az appgw --subscription <sub-id>`

### Output Verification (Optional - requires Azure access)
- [ ] **V.8** Check output directory: `ls -la ~/.cloudfox-output/azure-*/`
- [ ] **V.9** Confirm these files DO NOT exist:
  - `endpoints-commands.txt`
  - `container-jobs-variables.txt`
  - `network-interface-commands.txt`
  - `app-gateway-commands.txt`
- [ ] **V.10** Confirm these files STILL exist (if applicable):
  - `container-jobs-commands.txt`
  - `container-jobs-templates.txt`
  - `network-interfaces-PrivateIPs.txt`
  - `network-interfaces-PublicIPs.txt`

### Table Data Integrity (Optional - requires Azure access)
- [ ] **V.11** Verify all table columns still present in output
- [ ] **V.12** Verify table row counts unchanged (compare before/after)
- [ ] **V.13** Verify data completeness unchanged

---

## Quick Summary

**Files to Modify:**
1. `azure/commands/endpoints.go` - Remove `endpoints-commands`
2. `azure/commands/container-apps.go` - Remove `container-jobs-variables` (keep commands & templates)
3. `azure/commands/network-interfaces.go` - Remove `network-interface-commands` (keep IP lists)
4. `azure/commands/appgw.go` - Remove `app-gateway-commands`

**What to Remove in Each File:**
- LootMap initialization entry for the redundant loot file
- Any code that populates the loot file (appends to `.Contents`)
- Any code that adds the loot file to output array

**What NOT to Touch:**
- Table generation code
- Other valuable loot files
- Helper functions
- Any existing comments/documentation

**Success Criteria:**
✅ Build succeeds
✅ No grep results for removed loot file names
✅ All 4 files removed from LootMap
✅ No loot generation code remains

---

## Rollback (if needed)

If something breaks:
```bash
# Reset specific file
git checkout -- azure/commands/<filename>.go

# Or reset all changes
git checkout -- azure/commands/endpoints.go
git checkout -- azure/commands/container-apps.go
git checkout -- azure/commands/network-interfaces.go
git checkout -- azure/commands/appgw.go

# Rebuild
go build ./...
```

---

## Context for AI Assistant

When implementing this checklist, follow these patterns:

**LootMap Removal Pattern:**
```go
// BEFORE
LootMap: map[string]*internal.LootFile{
    "redundant-loot": {Name: "redundant-loot", Contents: ""},
    "valuable-loot": {Name: "valuable-loot", Contents: ""}, // KEEP THIS
},

// AFTER
LootMap: map[string]*internal.LootFile{
    "valuable-loot": {Name: "valuable-loot", Contents: ""}, // KEEP THIS
},
```

**Loot Generation Code Removal Pattern:**
```go
// BEFORE
m.mu.Lock()
m.LootMap["redundant-loot"].Contents += fmt.Sprintf("...")
m.mu.Unlock()

// AFTER
// (removed entirely)
```

**Output Array Pattern (already handled by loot system):**
```go
// The loot system automatically excludes empty loot files
// Just remove from LootMap and generation code
```

**Key Points:**
- Remove from LootMap initialization
- Remove generation code (searches for `m.LootMap["loot-name"]`)
- Keep all other loot files untouched
- Verify with grep after each removal
- Build after each file to catch errors early
