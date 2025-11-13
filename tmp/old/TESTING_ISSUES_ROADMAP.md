# CloudFox Azure Testing Issues - Remediation Roadmap

**Date**: 2025-01-XX
**Version**: 1.0
**Status**: Planning Phase

---

## Executive Summary

This document provides a comprehensive roadmap to address testing issues identified during CloudFox Azure validation. Issues are categorized by priority (P0-P3) and grouped into logical phases.

---

## Priority Definitions

- **P0 (Critical)**: Breaks core functionality, data accuracy issues
- **P1 (High)**: Significant UX issues, missing critical features
- **P2 (Medium)**: Enhancements, non-critical bugs
- **P3 (Low)**: Nice-to-have improvements, long-term planning

---

## 🔴 PHASE 1: CRITICAL DATA ACCURACY FIXES (P0) - Week 1

### Issue #2: Endpoint Column Misalignments (P0)
**Impact**: Data accuracy issues - hostnames showing IPs, IPs showing wrong values

**Problems Identified**:
- Virtual Machines: Hostnames contain IP addresses, IPs are wrong
- Web Apps: Hostnames contain IP addresses, IPs are wrong
- Azure Bastion: Hostname not FQDN, IP not actual IP address
- Azure Firewall: Hostname not FQDN, IP not actual IP address
- Arc: IP addresses may not be included

**Root Cause**: Likely column mapping errors in endpoints.go data extraction

**Action Items**:
1. Audit all endpoint extraction functions
2. Fix VM hostname/IP extraction
3. Fix Web App hostname/IP extraction
4. Fix Azure Bastion FQDN/IP extraction
5. Fix Azure Firewall FQDN/IP extraction
6. Verify Arc IP address inclusion
7. Add validation tests for endpoint data

**Estimated Effort**: 2-3 days
**Files**: `azure/commands/endpoints.go`, `internal/azure/network_helpers.go`

---

### Issue #7: Principals.go Data Integrity (P0)
**Impact**: Critical information showing incorrectly

**Problems Identified**:
- RBAC roles showing GUIDs instead of role names
- Not all roles being populated
- Graph permissions showing "unknown"
- OAuth2 delegated grants potentially not working

**Root Cause**: Likely role resolution failures, Graph API permission enumeration issues

**Action Items**:
1. Fix RBAC role GUID-to-name resolution
2. Ensure all role assignments are captured
3. Fix Graph permission enumeration
4. Verify OAuth2 delegated grants functionality
5. Add proper error handling and logging

**Estimated Effort**: 2-3 days
**Files**: `azure/commands/principals.go`, `internal/azure/rbac_helpers.go`

---

## 🟡 PHASE 2: OUTPUT RESTRUCTURING (P1) - Week 2

### Issue #1: Output Directory Structure Changes (P1)
**Impact**: UX improvement, better organization

**Current Structure**:
```
cloudfox-output/Azure/[subscription]/[format]/[files]
```

**Target Structure**:
```
cloudfox-output/Azure/[UPN]/[Tenant Name or GUID]/[format]/[files]
```

**Requirements**:
- When `-t` only: Combine all subscriptions into tenant-level files
- When `-s` specified: Output under subscription name/GUID (even if `-t` also provided)
- When `-g` specified: Requires `-s`, follows subscription rules
- Fallback hierarchy: Tenant Name → Tenant GUID → Subscription Name → Subscription GUID

**Considerations**:
- Memory consumption risk analysis for large tenants
- Determine if single file vs multiple files approach
- Backward compatibility (optional)

**Action Items**:
1. Analyze memory consumption risks for large tenants
2. Design new output structure logic
3. Create new `HandleOutputAzure()` function in internal/output2.go
4. Update all Azure modules to use new function
5. Special handling for: enterprise-apps, inventory, rbac
6. Update documentation

**Estimated Effort**: 4-5 days
**Files**: `internal/output2.go`, all `azure/commands/*.go`

---

## 🟢 PHASE 3: MODULE ENHANCEMENTS (P1-P2) - Week 3

### Issue #3a: Access Keys Module Enhancement (P1)
**Impact**: Improved credential tracking

**Requirements**:
- Split "Expiry/Permission" into "Certificate Expiry" and "Permission"
- Add principals/service account client secrets and certificates
- Add enterprise application client secrets and certificates
- New headers: Subscription ID, Subscription Name, Resource Group, Region, Resource Name, Application ID, Key/Cert Name, Key/Cert Type, Identifier/Thumbprint, Cert Start Time, Cert Expiry, Permissions

**Action Items**:
1. Redesign accesskeys.go table structure
2. Add service principal credential enumeration
3. Add enterprise app credential enumeration
4. Implement new column structure
5. Update loot file generation

**Estimated Effort**: 2-3 days
**Files**: `azure/commands/accesskeys.go`

---

### Issue #3b: Webapp Credentials Review (P2)
**Impact**: Ensure credential completeness

**Questions to Answer**:
- Should webapps-credentials be part of accesskeys.go?
- Are there other certificate-based auth services to include?

**Action Items**:
1. Audit webapp credential enumeration
2. Identify other certificate-based auth services
3. Determine if accesskeys.go should be central credential module
4. Implement consolidation if appropriate

**Estimated Effort**: 1-2 days
**Files**: `azure/commands/webapps.go`, `azure/commands/accesskeys.go`

---

### Issue #4: EntraID Centralized Auth Column (P1)
**Impact**: Security visibility improvement

**Services Requiring Column**:
- Virtual Machines (may exist as "RBAC Enabled")
- Key Vaults (may exist as "RBAC Enabled")
- Storage Accounts
- AKS
- Databases
- App Service / Functions
- Data Explorer / Synapse / Data Lake
- Azure Bastion
- Azure Arc-enabled Servers
- Azure Automation / Logic Apps / DevOps Agents

**Action Items**:
1. Audit all listed modules for existing RBAC columns
2. Rename "RBAC Enabled" to "EntraID Centralized Auth"
3. Add column to modules missing it
4. Ensure consistent data extraction logic
5. Document what this column means

**Estimated Effort**: 3-4 days
**Files**: Multiple module files

---

### Issue #5: Functions.go Cleanup (P2)
**Impact**: Remove confusing/redundant columns

**Requirements**:
- Remove HTTPS column (configured at App Service level)
- Remove TLS column (configured at App Service level)
- Remove any other redundant columns

**Action Items**:
1. Review functions.go output columns
2. Identify App Service-level configurations
3. Remove redundant columns
4. Update documentation

**Estimated Effort**: 1 day
**Files**: `azure/commands/functions.go`

---

### Issue #6: RBAC.go Header Corrections (P2)
**Impact**: Clarity improvement

**Requirements**:
- "Principal UPN" → "Principal UPN / Application ID"
- "Principal Name" → "Principal Name / Application Name"
- Review for other confusing headers

**Action Items**:
1. Update rbac.go table headers
2. Audit for other unclear headers
3. Update documentation

**Estimated Effort**: 1 day
**Files**: `azure/commands/rbac.go`

---

## 🔵 PHASE 4: NETWORK SECURITY CONSOLIDATION (P2) - Week 4

### Issue #8: Network Scanning Commands Enhancement (P2)
**Impact**: Better targeted network scanning

**Requirements**:
- Fine-tune network-scanning-commands loot output
- Use enumerated port information from ACLs, NSGs, firewall rules
- Potentially combine with Network Security modules

**Related Missing Resources**:
- NSG.go module (Network Security Group rules)
- Firewall.go module (Azure Firewall rules)
- Routes.go module (Route Tables)
- VNets.go module (Virtual Network Peerings)

**Proposed Solution**:
Create unified network security module or enhance existing modules to work together

**Action Items**:
1. Review network-interfaces.go scanning commands
2. Implement NSG enumeration (from MISSING_RESOURCES_TODO.md)
3. Implement Firewall enumeration (from MISSING_RESOURCES_TODO.md)
4. Implement Routes enumeration (from MISSING_RESOURCES_TODO.md)
5. Implement VNet peering enumeration (from MISSING_RESOURCES_TODO.md)
6. Generate targeted scan commands based on discovered rules
7. Create comprehensive network security loot output

**Estimated Effort**: 5-7 days
**Files**: `azure/commands/network-interfaces.go`, new network security modules

---

## 🟣 PHASE 5: LONG-TERM ROADMAP (P3) - Future

### Issue #A: AWS Output Restructuring (P3)
**Target Structure**:
```
cloudfox-output/AWS/[UPN]/[Organization or Account ID]/[format]/[files]
```

**Dependencies**: Complete Azure restructuring first
**Estimated Effort**: 3-4 days

---

### Issue #B: GCP Output Restructuring (P3)
**Target Structure**:
```
cloudfox-output/GCP/[UPN]/[Organization or Project ID]/[format]/[files]
```

**Dependencies**: Complete Azure and AWS restructuring first
**Estimated Effort**: 3-4 days

---

## Timeline Summary

| Week | Phase | Focus | Priority |
|------|-------|-------|----------|
| 1 | Phase 1 | Data Accuracy Fixes | P0 |
| 2 | Phase 2 | Output Restructuring | P1 |
| 3 | Phase 3 | Module Enhancements | P1-P2 |
| 4 | Phase 4 | Network Security | P2 |
| Future | Phase 5 | Multi-Cloud | P3 |

---

## Risk Assessment

### High Risk
- **Output restructuring memory consumption**: Large tenants may cause OOM
  - Mitigation: Implement streaming or chunked output
  - Mitigation: Add configuration for single vs multi-file output

### Medium Risk
- **Breaking changes**: Output structure changes may break existing workflows
  - Mitigation: Add backward compatibility flag
  - Mitigation: Document migration guide

### Low Risk
- **Column additions**: May break CSV parsers expecting fixed columns
  - Mitigation: Document schema changes
  - Mitigation: Version output format

---

## Success Criteria

### Phase 1 (Critical)
- ✅ All endpoints show correct hostnames and IPs
- ✅ Principals module shows role names, not GUIDs
- ✅ All Graph permissions correctly identified
- ✅ OAuth2 delegated grants working

### Phase 2 (Output)
- ✅ Output organized by Tenant (when `-t` only)
- ✅ Output organized by Subscription (when `-s` specified)
- ✅ Memory consumption acceptable for large tenants
- ✅ All modules updated to new structure

### Phase 3 (Enhancements)
- ✅ Access keys module includes all credential types
- ✅ EntraID Centralized Auth column in all relevant modules
- ✅ Functions.go cleaned of redundant columns
- ✅ RBAC and Principals headers clarified

### Phase 4 (Network)
- ✅ Network scanning commands based on actual discovered rules
- ✅ NSG, Firewall, Routes, VNet modules implemented
- ✅ Comprehensive network security assessment possible

---

## Dependencies

### External
- Azure SDK stability
- Microsoft Graph API permissions

### Internal
- Must complete P0 fixes before P1 enhancements
- Output restructuring affects all modules
- Network security modules can be developed in parallel

---

## Resources Required

- 1 Senior Developer (Phase 1-4)
- QA/Testing environment with large tenant
- Documentation updates
- Migration guide for users

---

## Notes

- Phases can overlap slightly
- P0 issues should be addressed immediately
- Consider creating feature flags for major changes
- Add regression tests for fixed issues
- Update user documentation with each phase
