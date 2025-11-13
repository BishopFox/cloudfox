# CloudFox Azure Testing Issues - Implementation Tracker

**Last Updated**: 2025-01-XX
**Format**: Copy to spreadsheet for tracking

---

## How to Use This Tracker

1. Copy the table below into Excel/Google Sheets/GitHub Projects
2. Update "Status" column as you progress
3. Fill in "Assignee", "Start Date", "End Date" as needed
4. Update "Notes" with blockers or important findings

---

## Master Tracker

| Issue ID | Title | Priority | Category | Est. Hours | Status | Assignee | Start Date | End Date | % Done | Notes |
|----------|-------|----------|----------|------------|--------|----------|------------|----------|--------|-------|
| 2.1 | VM Endpoint Fix | P0 | Data Accuracy | 3 | Not Started | | | | 0% | |
| 2.2 | Web App Endpoint Fix | P0 | Data Accuracy | 3 | Not Started | | | | 0% | |
| 2.3 | Bastion Endpoint Fix | P0 | Data Accuracy | 2 | Not Started | | | | 0% | |
| 2.4 | Firewall Endpoint Fix | P0 | Data Accuracy | 2 | Not Started | | | | 0% | |
| 2.5 | Arc IP Verification | P0 | Data Accuracy | 1 | Not Started | | | | 0% | |
| 2.6 | Endpoint Testing | P0 | Data Accuracy | 2 | Not Started | | | | 0% | Depends on 2.1-2.5 |
| 7.1 | RBAC Role Resolution | P0 | Data Accuracy | 8 | Not Started | | | | 0% | |
| 7.2 | Complete Role Capture | P0 | Data Accuracy | 4 | Not Started | | | | 0% | |
| 7.3 | Graph Permission Fix | P0 | Data Accuracy | 6 | Not Started | | | | 0% | |
| 7.4 | OAuth2 Grant Verify | P0 | Data Accuracy | 4 | Not Started | | | | 0% | |
| 7.5 | Principals Testing | P0 | Data Accuracy | 3 | Not Started | | | | 0% | Depends on 7.1-7.4 |
| 1.1 | Output Analysis | P1 | Output Struct | 4 | Not Started | | | | 0% | |
| 1.2 | Output Function Design | P1 | Output Struct | 8 | Not Started | | | | 0% | |
| 1.3 | Module Updates | P1 | Output Struct | 24 | Not Started | | | | 0% | ~30 modules |
| 1.4 | Output Testing | P1 | Output Struct | 6 | Not Started | | | | 0% | |
| 1.5 | Output Documentation | P1 | Output Struct | 3 | Not Started | | | | 0% | |
| 3a.1 | Access Keys Redesign | P1 | Enhancement | 4 | Not Started | | | | 0% | |
| 3a.2 | Service Principal Creds | P1 | Enhancement | 6 | Not Started | | | | 0% | |
| 3a.3 | Enterprise App Creds | P1 | Enhancement | 4 | Not Started | | | | 0% | |
| 3a.4 | Column Split | P1 | Enhancement | 2 | Not Started | | | | 0% | |
| 3a.5 | Access Keys Testing | P1 | Enhancement | 3 | Not Started | | | | 0% | |
| 3b | Webapp Creds Review | P2 | Enhancement | 8 | Not Started | | | | 0% | |
| 4.1 | Audit Existing RBAC Col | P1 | Enhancement | 2 | Not Started | | | | 0% | |
| 4.2 | Standardize Column Name | P1 | Enhancement | 2 | Not Started | | | | 0% | |
| 4.3 | Add to Missing Modules | P1 | Enhancement | 16 | Not Started | | | | 0% | ~10 modules |
| 4.4 | EntraID Auth Testing | P1 | Enhancement | 4 | Not Started | | | | 0% | |
| 5 | Functions.go Cleanup | P2 | Enhancement | 4 | Not Started | | | | 0% | |
| 6 | RBAC.go Headers | P2 | Enhancement | 2 | Not Started | | | | 0% | |
| 8.1 | Review Network Scanning | P2 | Network | 2 | Not Started | | | | 0% | |
| 8.2 | Implement NSG Module | P2 | Network | 12 | Not Started | | | | 0% | |
| 8.3 | Implement Firewall Module | P2 | Network | 16 | Not Started | | | | 0% | |
| 8.4 | Implement Routes Module | P2 | Network | 10 | Not Started | | | | 0% | |
| 8.5 | Implement VNets Module | P2 | Network | 12 | Not Started | | | | 0% | |
| 8.6 | Enhanced Scan Commands | P2 | Network | 8 | Not Started | | | | 0% | Depends on 8.2-8.5 |
| 8.7 | Network Testing | P2 | Network | 6 | Not Started | | | | 0% | |
| A | AWS Output Restructure | P3 | Future | 24 | Not Started | | | | 0% | After Issue #1 |
| B | GCP Output Restructure | P3 | Future | 24 | Not Started | | | | 0% | After Issue #A |

---

## Phase Rollup

| Phase | Issues | Total Hours | Priority | Status | Start | End | % Done |
|-------|--------|-------------|----------|--------|-------|-----|--------|
| Phase 1: Data Accuracy | 2.1-2.6, 7.1-7.5 | 38 | P0 | Not Started | | | 0% |
| Phase 2: Output | 1.1-1.5 | 45 | P1 | Not Started | | | 0% |
| Phase 3: Enhancements | 3a.1-3a.5, 3b, 4.1-4.4, 5, 6 | 60 | P1-P2 | Not Started | | | 0% |
| Phase 4: Network | 8.1-8.7 | 66 | P2 | Not Started | | | 0% |
| Phase 5: Multi-Cloud | A, B | 48 | P3 | Not Started | | | 0% |
| **TOTAL** | **36 Issues** | **257 Hours** | | | | | **0%** |

---

## Weekly Sprint Planning Template

### Sprint 1 (Week 1): Critical Data Fixes

| Day | Issue | Task | Hours | Status |
|-----|-------|------|-------|--------|
| Mon | 2.1 | Fix VM endpoints | 3 | |
| Tue | 2.2 | Fix Web App endpoints | 3 | |
| Wed | 2.3 | Fix Bastion endpoints | 2 | |
| Wed | 2.4 | Fix Firewall endpoints | 2 | |
| Thu | 2.5 | Verify Arc endpoints | 1 | |
| Thu | 2.6 | Endpoint testing | 2 | |
| Fri | 7.1 | Start RBAC role resolution | 4 | |

### Sprint 2 (Week 2): Principals Data Quality

| Day | Issue | Task | Hours | Status |
|-----|-------|------|-------|--------|
| Mon | 7.1 | Complete RBAC role resolution | 4 | |
| Tue | 7.2 | Complete role capture | 4 | |
| Wed | 7.3 | Graph permission fix | 6 | |
| Thu | 7.4 | OAuth2 grant verify | 4 | |
| Fri | 7.5 | Principals testing | 3 | |

### Sprint 3 (Week 3): Quick Wins

| Day | Issue | Task | Hours | Status |
|-----|-------|------|-------|--------|
| Mon | 5 | Functions.go cleanup | 4 | |
| Mon | 6 | RBAC.go headers | 2 | |
| Tue | 4.1 | Audit existing RBAC column | 2 | |
| Tue | 4.2 | Standardize column name | 2 | |
| Wed-Fri | 4.3 | Add to missing modules | 16 | |

---

## Blockers & Dependencies

| Issue | Blocked By | Blocking | Notes |
|-------|------------|----------|-------|
| 2.6 | 2.1, 2.2, 2.3, 2.4, 2.5 | - | Cannot test until all endpoint fixes done |
| 7.5 | 7.1, 7.2, 7.3, 7.4 | - | Cannot test until all principal fixes done |
| 1.3 | 1.2 | 1.4 | Module updates need design complete |
| 1.4 | 1.3 | 1.5 | Testing needs modules updated |
| 3a.5 | 3a.1, 3a.2, 3a.3, 3a.4 | - | Testing needs all access key work done |
| 4.4 | 4.1, 4.2, 4.3 | - | Testing needs all EntraID work done |
| 8.6 | 8.2, 8.3, 8.4, 8.5 | 8.7 | Scan commands need network data |
| 8.7 | 8.6 | - | Testing needs scan commands |
| A | 1 (complete) | B | AWS depends on Azure pattern |
| B | A (complete) | - | GCP depends on AWS pattern |

---

## Risk Register

| Risk | Probability | Impact | Mitigation | Owner |
|------|-------------|--------|------------|-------|
| Memory issues with large tenants (Issue #1) | Medium | High | Implement streaming output, chunked processing | |
| Breaking existing user workflows (Issue #1) | High | Medium | Add backward compatibility flag, migration guide | |
| Graph API permission issues (Issue #7.3) | Low | High | Document required Graph permissions | |
| Azure SDK API changes | Low | High | Pin SDK versions, monitor changelogs | |
| Time estimation too low | High | Medium | Add 20% buffer, re-estimate after Phase 1 | |

---

## Quality Gates

### Before Merging Each Issue

- [ ] Code builds: `go build ./...`
- [ ] No new vet warnings: `go vet ./...`
- [ ] Module runs: `./cloudfox azure <module> -t <TENANT>`
- [ ] Output validated: Manual check of CSV/JSON
- [ ] No errors in verbose mode: `-v 4`
- [ ] TODO.md updated with checkboxes
- [ ] Commit message follows format
- [ ] Branch merged to main

### Before Completing Each Phase

- [ ] All issues in phase marked complete
- [ ] Integration testing with all modules
- [ ] Documentation updated
- [ ] User migration guide (if breaking changes)
- [ ] Phase retrospective completed

---

## Status Legend

| Status | Meaning |
|--------|---------|
| Not Started | No work begun |
| In Progress | Actively working |
| Blocked | Waiting on dependency |
| In Review | Code review in progress |
| Testing | QA/validation phase |
| Complete | Done and merged |

---

## Notes Section

### General Notes
- Add project-wide notes here
- Track key decisions
- Document assumptions

### Issue-Specific Notes
- Add detailed notes for complex issues
- Document workarounds
- Track API limitations

---

## Reporting Template

### Weekly Status Report

**Week Ending**: [DATE]

**Completed This Week**:
- Issue #X.Y: [Brief description]
- Issue #X.Z: [Brief description]

**In Progress**:
- Issue #A.B: [Status, % complete]

**Blocked**:
- Issue #C.D: [Blocker description]

**Next Week**:
- Plan to complete Issue #E.F
- Start Issue #G.H

**Risks/Concerns**:
- [Any new risks or concerns]

**Hours**: [Actual] / [Estimated]

---

## Change Log

| Date | Change | By |
|------|--------|-----|
| 2025-01-XX | Initial tracker created | |
| | | |
| | | |

---

## How to Copy to Spreadsheet

### Google Sheets / Excel

1. Copy the "Master Tracker" table above
2. Paste into new spreadsheet
3. Format as table with filters
4. Add conditional formatting:
   - Red: Not Started
   - Yellow: In Progress / Blocked
   - Green: Complete
5. Use formulas for % Done rollup

### GitHub Projects

1. Create new project
2. Add columns: Status, Priority, Assignee, Est. Hours, % Done
3. Create card for each issue
4. Use automation for status changes

### Jira / Azure DevOps

1. Create Epic for each Phase
2. Create Story for each Issue
3. Set story points based on Est. Hours
4. Link dependencies
5. Track using sprint boards
