# Azure CloudFox Security Module Analysis & Enhancement Recommendations
## Comprehensive Security Analysis for Azure Tenant & Subscription Review

**Document Version:** 1.0
**Last Updated:** 2025-01-12
**Analysis Session:** 1 of Multiple
**Purpose:** Identify missing security features and recommend enhancements for each Azure module

---

## Executive Summary

CloudFox for Azure is a comprehensive offensive security enumeration tool designed for Azure tenant and subscription security assessments. This analysis reviews all 51 existing modules to identify gaps, missing features, and enhancement opportunities that would benefit security analysts conducting Azure security reviews.

### Current Module Count: 51 Modules

**Categories Covered:**
- Identity & Access Management (IAM)
- Compute Resources
- Storage & Data
- Networking & Connectivity
- Databases
- Platform Services (PaaS)
- DevOps & CI/CD
- Analytics & Data Processing
- Security & Compliance
- Management & Operations

---

## Analysis Methodology

For each module, this analysis evaluates:

1. **Current Capabilities** - What the module currently enumerates
2. **Security Gaps** - Missing security-relevant information
3. **Recommended Enhancements** - Specific features to add
4. **Attack Surface Considerations** - Additional data useful for penetration testing
5. **Priority Level** - Critical, High, Medium, Low

---

## SESSION 1: Identity & Access Management (IAM) Modules

### 1. PRINCIPALS Module (`principals.go`)

**Current Capabilities:**
- Enumerates users (Member & Guest)
- Service principals & managed identities
- Security groups
- RBAC role assignments with scope hierarchy
- PIM (Privileged Identity Management) eligible & active roles
- Directory roles (Entra ID admin roles)
- Conditional Access Policies
- Graph API permissions
- OAuth2 delegated grants
- Nested group memberships
- Multi-tenant support

**Security Gaps Identified:**
1. ❌ **No MFA Status** - Missing multi-factor authentication enrollment status
2. ❌ **No Sign-in Activity** - Last sign-in date, risky sign-ins, sign-in frequency
3. ❌ **No License Analysis** - Premium P1/P2 licenses affecting security features
4. ❌ **No Guest User Source** - Which external organization invited the guest
5. ❌ **No Service Principal Secrets/Certificates** - Expiration dates, rotation status
6. ❌ **No Application Ownership** - Who created/owns service principals
7. ❌ **No Privileged Role Activation History** - PIM activation logs
8. ❌ **No Authentication Methods** - Phone, email, authenticator apps registered
9. ❌ **No Disabled/Deleted Users** - Soft-deleted principals still in directory
10. ❌ **No Emergency Access Accounts** - Break-glass accounts identification
11. ❌ **No Cross-Tenant Access Settings** - B2B collaboration policies
12. ❌ **No Consent Grants** - User/admin consent grants to applications

**Recommended Enhancements:**

```markdown
HIGH PRIORITY:
- [ ] Add MFA enrollment status per user (via Graph API /users/{id}/authentication/methods)
- [ ] Add sign-in activity (last interactive/non-interactive sign-in from signInActivity)
- [ ] Add service principal secret/certificate expiration dates and rotation recommendations
- [ ] Add soft-deleted principals enumeration (deletedItems API)
- [ ] Add authentication methods per user (phone, email, FIDO2 keys)
- [ ] Add PIM role activation history (roleAssignmentScheduleRequests API)

MEDIUM PRIORITY:
- [ ] Add license assignment details (affects available security features)
- [ ] Add guest user source tenant information
- [ ] Add application/SP ownership and creation date
- [ ] Add risky user detection (Identity Protection)
- [ ] Add emergency access account detection (by naming convention or role)
- [ ] Add user risk level (from Identity Protection)

LOW PRIORITY:
- [ ] Add password change/last set date
- [ ] Add account enabled/disabled status
- [ ] Add user creation date
- [ ] Add cross-tenant access policy settings
```

**Attack Surface Considerations:**
- Expired SP credentials = potential orphaned access
- Users without MFA = phishing targets
- Guest users = potential lateral movement paths
- Highly privileged users without MFA = critical risk
- Service principals with secrets expiring soon = operational disruption opportunity

---

### 2. RBAC Module (`rbac.go`)

**Current Capabilities:**
- Comprehensive role assignment enumeration at all scopes
- Tenant root (/) assignments
- Management group hierarchy assignments
- Subscription, Resource Group, Resource-level assignments
- PIM eligible and active assignments
- Nested group resolution
- Inherited permissions tracking
- Role definition permission expansion (Actions, NotActions, DataActions, NotDataActions)
- Multi-tenant support

**Security Gaps Identified:**
1. ❌ **No Deny Assignments** - Azure Deny Assignments not enumerated
2. ❌ **No Classic Administrators** - Co-Administrators and Service Administrators missing
3. ❌ **No Role Assignment Conditions** - ABAC conditions not fully analyzed
4. ❌ **No Custom Role Risk Analysis** - Wildcard permissions in custom roles
5. ❌ **No Assignment Creation Date** - When was the role assigned (audit trail)
6. ❌ **No PIM Approval Requirements** - Whether PIM roles require approval
7. ❌ **No PIM Maximum Duration** - How long PIM roles can be activated
8. ❌ **No Role Assignment Justification** - Justification text from PIM activations
9. ❌ **No Orphaned Assignments** - Assignments to deleted principals
10. ❌ **No Blueprint Assignments** - Azure Blueprints role assignments

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add Deny Assignments enumeration (often overlooked but critical)
- [ ] Add Classic Administrator enumeration (Co-Admin, Service Admin)
- [ ] Add orphaned role assignment detection (principal no longer exists)

HIGH PRIORITY:
- [ ] Add custom role risk analysis (wildcard permissions, overly broad roles)
- [ ] Add role assignment creation date and creator information
- [ ] Add ABAC condition analysis (parse and flag weak conditions)
- [ ] Add PIM configuration details (approval required, max duration, MFA required)
- [ ] Add role assignment expiration dates

MEDIUM PRIORITY:
- [ ] Add role assignment audit history (recent changes via Activity Logs)
- [ ] Add privileged role assignment alerts (detect new Owner/Contributor assignments)
- [ ] Add role assignment scope analysis (overly broad scopes)
```

**Attack Surface Considerations:**
- Orphaned assignments = persistent access after user deletion
- Deny assignments = potential privilege escalation blocks
- Classic administrators = legacy high-privilege access
- PIM roles without approval = easy privilege escalation
- Custom roles with wildcards = unintended permissions

---

### 3. PERMISSIONS Module (`permissions.go`)

**Current Capabilities:**
- Granular permission enumeration (one row per action)
- Expands role definitions into individual Actions/NotActions/DataActions/NotDataActions
- Enumerates ALL principals (users, SPs, groups, managed identities)
- Includes tenant root, management groups, subscription, RG, and resource-level permissions
- PIM eligible and active permissions included
- Orphaned principal detection (fallback scan)
- System-assigned and user-assigned MI enumeration from resources
- Group-based permission attribution

**Security Gaps Identified:**
1. ❌ **No Wildcard Permission Flagging** - Permissions with * not highlighted
2. ❌ **No Dangerous Permission Combinations** - e.g., Microsoft.Authorization/roleAssignments/write + other perms
3. ❌ **No Privilege Escalation Path Detection** - Automated detection of privilege escalation vectors
4. ❌ **No Data Exfiltration Permission Analysis** - Permissions that allow data access/export
5. ❌ **No Permission Usage Analytics** - Are these permissions actually being used?
6. ❌ **No Permission Conflict Detection** - Allow vs Deny conflicts
7. ❌ **No Just-In-Time Permissions** - PIM vs Permanent permission differentiation
8. ❌ **No Permission Recommendations** - Least privilege recommendations

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add dangerous permission combination detection (privilege escalation vectors)
  - Microsoft.Authorization/roleAssignments/write
  - Microsoft.Compute/virtualMachines/runCommand/action
  - Microsoft.KeyVault/vaults/write
  - Microsoft.Storage/storageAccounts/listKeys/action
  - Microsoft.Web/sites/config/write

HIGH PRIORITY:
- [ ] Add wildcard permission flagging (highlight * permissions)
- [ ] Add data exfiltration permission analysis
  - Storage read/list/export permissions
  - Database backup/export permissions
  - Disk snapshot permissions
- [ ] Add JIT vs permanent permission analysis
- [ ] Add permission scope analysis (flag overly broad scopes)

MEDIUM PRIORITY:
- [ ] Add least privilege recommendations (based on Azure recommendations)
- [ ] Add permission usage analytics integration (if available via logs)
- [ ] Add sensitive resource permission tracking (KeyVaults, Databases, Storage)
```

**Attack Surface Considerations:**
- Wildcard permissions = unintended access
- RoleAssignment write permission = privilege escalation to Owner
- RunCommand permission on VMs = code execution
- ListKeys on storage = full data access
- Backup/export permissions = data exfiltration

---

### 4. ENTERPRISE-APPS Module (`enterprise-apps.go`)

**Current Capabilities:**
- Service principal enumeration
- Application permissions (roles and OAuth scopes)
- App role assignments
- Publisher verification status
- Service principal type identification
- Multi-tenant support

**Security Gaps Identified:**
1. ❌ **No Application Secrets/Certificates** - Expiration tracking
2. ❌ **No Consent Grants** - User consent vs admin consent
3. ❌ **No Application Permissions Risk Analysis** - Dangerous permissions flagged
4. ❌ **No Application Owners** - Who can manage the application
5. ❌ **No Sign-in Activity** - Last used, usage frequency
6. ❌ **No Conditional Access Policies** - CA policies applied to apps
7. ❌ **No Token Lifetime Policies** - Custom token lifetimes
8. ❌ **No Home Tenant Detection** - External vs internal apps
9. ❌ **No Disabled Applications** - Soft-deleted applications
10. ❌ **No Application Proxy Connectors** - On-prem app publishing
11. ❌ **No SAML/WS-Fed Configuration** - Federation settings

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add application secrets and certificate expiration enumeration
- [ ] Add consent grants (user vs admin, delegated vs application permissions)
- [ ] Add dangerous permission analysis
  - Mail.ReadWrite, Mail.Send = email compromise
  - Files.ReadWrite.All = data access
  - User.ReadWrite.All = privilege escalation
  - Directory.ReadWrite.All = full tenant control

HIGH PRIORITY:
- [ ] Add application owners enumeration
- [ ] Add sign-in activity and usage statistics
- [ ] Add publisher verification status analysis
- [ ] Add multi-tenant application detection (external publishers)
- [ ] Add Conditional Access policy coverage

MEDIUM PRIORITY:
- [ ] Add token lifetime policies
- [ ] Add application proxy connector enumeration
- [ ] Add SAML/WS-Fed configuration details
- [ ] Add certificate-based authentication settings
```

**Attack Surface Considerations:**
- Expired credentials = service disruption or orphaned access
- Excessive permissions = potential abuse
- Unverified publishers = potentially malicious apps
- User consent = shadow IT and data leakage
- Application owners = who can add credentials

---

## SESSION 1 SUMMARY: IAM Module Gaps

### Critical Gaps Across IAM Modules

1. **MFA Enforcement Visibility** - No module shows MFA status comprehensively
2. **Credential Hygiene** - Missing expiration tracking for secrets/certificates
3. **Sign-in Analytics** - No visibility into account usage and activity
4. **Privilege Escalation Paths** - Not automatically detected
5. **Dangerous Permission Combinations** - Not highlighted
6. **Consent Grants** - User/admin consent to applications not enumerated
7. **Conditional Access Coverage** - Limited CA policy analysis

### Recommended New IAM Modules

```markdown
NEW MODULE SUGGESTIONS:

1. **MFA-STATUS Module**
   - Enumerate MFA enrollment status for all users
   - Identify privileged users without MFA
   - Show authentication methods per user
   - Flag accounts with phone-based MFA only (less secure)

2. **CONDITIONAL-ACCESS Module** (Currently missing!)
   - Enumerate all Conditional Access policies
   - Show policy assignments (users/groups/apps)
   - Flag disabled policies
   - Identify gaps in CA coverage

3. **CONSENT-GRANTS Module** (Currently missing!)
   - List all OAuth consent grants
   - User vs admin consent
   - Identify risky permissions granted
   - External apps with access

4. **IDENTITY-PROTECTION Module** (Currently missing!)
   - Risky users and sign-ins
   - Risk detections and events
   - User risk policy enforcement
   - Sign-in risk policy enforcement

5. **CREDENTIAL-HYGIENE Module**
   - All secrets and certificates across SPs
   - Expiration dates and rotation status
   - Orphaned credentials
   - Long-lived credentials (>365 days)

6. **PRIVILEGE-ESCALATION-PATHS Module**
   - Automated detection of escalation vectors
   - Permission combinations analysis
   - Path visualization (user -> role -> action)
```

---

## NEXT SESSIONS PLAN

**Session 2:** Compute & Container Modules (VMs, AKS, Container Apps, Functions, WebApps)
**Session 3:** Storage & Data Modules (Storage, Key Vaults, Disks, Filesystems)
**Session 4:** Networking Modules (NSG, VNets, Firewalls, App Gateway, etc.)
**Session 5:** Database Modules (SQL, MySQL, PostgreSQL, CosmosDB, etc.)
**Session 6:** Platform Services (Data Factory, Synapse, Logic Apps, etc.)
**Session 7:** DevOps & Automation Modules
**Session 8:** Missing Azure Services & Final Recommendations

---

## Quick Reference: Module Priority Matrix

| Module | Current Coverage | Critical Gaps | Priority |
|--------|-----------------|---------------|----------|
| Principals | ⭐⭐⭐⭐ (Excellent) | MFA, Sign-ins, Creds | HIGH |
| RBAC | ⭐⭐⭐⭐⭐ (Outstanding) | Deny Assignments, Classic Admins | MEDIUM |
| Permissions | ⭐⭐⭐⭐⭐ (Outstanding) | Privilege Escalation Detection | HIGH |
| Enterprise-Apps | ⭐⭐⭐ (Good) | Consent Grants, Creds | CRITICAL |

---

**END OF SESSION 1**

*Next session will analyze Compute resources (VMs, AKS, Functions, WebApps)*
