# Azure CloudFox Security Module Analysis - SESSION 7
## DevOps & Management Security Analysis

**Document Version:** 1.0
**Last Updated:** 2025-01-12
**Analysis Session:** 7 of Multiple
**Focus Area:** DevOps, Automation, and Management Resources

---

## SESSION 7 OVERVIEW: DevOps & Management Modules

This session analyzes Azure DevOps and management-related modules to identify security gaps and enhancement opportunities.

### Modules Analyzed in This Session:
1. **DevOps-Projects** - Azure DevOps project enumeration
2. **DevOps-Repos** - Git repositories
3. **DevOps-Pipelines** - CI/CD pipelines
4. **DevOps-Artifacts** - Package feeds
5. **Automation** - Automation accounts and runbooks
6. **Policy** - Azure Policy assignments
7. **Deployments** - ARM template deployments
8. **Inventory** - Resource inventory
9. **Access Keys** - Service keys enumeration
10. **Whoami** - Current user context

---

## 1. DEVOPS-PROJECTS Module (`devops-projects.go`)

**Current Capabilities:**
- Azure DevOps organization and project enumeration
- Project visibility (public, private)
- Project description

**Security Gaps Identified:**
1. ❌ **No Project Permissions** - User/group access levels
2. ❌ **No Service Connections** - External service credentials
3. ❌ **No Variable Groups** - Shared pipeline variables (secrets)
4. ❌ **No Secure Files** - Certificates and config files
5. ❌ **No Project Settings** - Security policies and features
6. ❌ **No PATs (Personal Access Tokens)** - Long-lived credentials
7. ❌ **No SSH Keys** - Git SSH keys
8. ❌ **No OAuth Apps** - Third-party integrations
9. ❌ **No Audit Logs** - Who accessed what
10. ❌ **No Branch Policies** - Code review requirements

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add service connection enumeration (Azure, GitHub, Docker, etc. credentials)
- [ ] Add variable group enumeration (pipeline secrets)
- [ ] Add secure files (certificates, kubeconfig, keystore files)
- [ ] Add personal access tokens (PAT) enumeration per user
- [ ] Add SSH keys registered to organization
- [ ] Add OAuth authorized applications

HIGH PRIORITY:
- [ ] Add project-level permissions (admin, contributor, reader)
- [ ] Add security policies (credential scanner, secret detection)
- [ ] Add audit log access and retention
- [ ] Add external user access (B2B collaboration)
- [ ] Add organization-level settings (security, policies)
```

---

## 2. DEVOPS-REPOS Module (`devops-repos.go`)

**Current Capabilities:**
- Git repository enumeration
- Repository URL and default branch
- Repository size

**Security Gaps Identified:**
1. ❌ **No Branch Protection** - Branch policies and required reviewers
2. ❌ **No Commit History** - Recent commits and authors
3. ❌ **No File Content Scanning** - Secrets in code
4. ❌ **No Repository Permissions** - Who can push/admin
5. ❌ **No Forks** - Forked repositories (shadow IT)
6. ❌ **No Pull Request Policies** - Review requirements
7. ❌ **No Git Hooks** - Pre-commit, pre-push hooks
8. ❌ **No Repository Audit** - Clone/push/pull history
9. ❌ **No CODEOWNERS File** - Code ownership configuration
10. ❌ **No Secret Scanning Results** - GitHub Advanced Security findings

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add branch protection policies (required reviewers, status checks)
- [ ] Add repository permissions (users/groups with write/admin access)
- [ ] Add secret scanning results (credential scanner findings)
- [ ] Add commit history analysis (recent commits, large file commits)
- [ ] Add file content scanning for common secrets (API keys, passwords)
- [ ] Add pull request policies (minimum reviewers, linked work items)

HIGH PRIORITY:
- [ ] Add CODEOWNERS file analysis (code ownership)
- [ ] Add repository forks (internal and external)
- [ ] Add repository settings (allow force push, allow PR rebase)
- [ ] Add Git LFS configuration (large file storage)
- [ ] Add repository audit logs (clone, push, pull events)
- [ ] Add default branch protection status
```

---

## 3. DEVOPS-PIPELINES Module (`devops-pipelines.go`)

**Current Capabilities:**
- Pipeline enumeration
- Pipeline type (build, release, YAML)
- Pipeline enabled/disabled status

**Security Gaps Identified:**
1. ❌ **No Pipeline Variables** - Secrets and configuration
2. ❌ **No Pipeline Service Connections** - Which credentials are used
3. ❌ **No Pipeline Triggers** - CI/CD trigger configuration
4. ❌ **No Pipeline Tasks** - Task definitions and scripts
5. ❌ **No Pipeline Run History** - Execution logs
6. ❌ **No Pipeline Permissions** - Who can run/edit
7. ❌ **No Agent Pools** - Self-hosted agents (attack surface)
8. ❌ **No Pipeline Approvals** - Manual intervention gates
9. ❌ **No Pipeline Artifacts** - Build artifacts produced
10. ❌ **No Inline Scripts** - PowerShell/Bash scripts in pipeline
11. ❌ **No Docker Build Steps** - Container image builds
12. ❌ **No Kubernetes Deployments** - K8s deployment tasks
13. ❌ **No Terraform/ARM Deployments** - IaC deployment steps
14. ❌ **No Pipeline YAML Content** - Full pipeline definition

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add pipeline variable enumeration (secrets, non-secrets)
- [ ] Add service connection usage per pipeline
- [ ] Add inline script extraction (PowerShell, Bash, Python scripts)
- [ ] Add pipeline YAML/JSON definition export
- [ ] Add pipeline permissions (authorized users/groups)
- [ ] Add agent pool configuration (self-hosted agents)
- [ ] Add pipeline secret detection (hardcoded credentials in YAML)

HIGH PRIORITY:
- [ ] Add pipeline task enumeration (all tasks used)
- [ ] Add pipeline trigger configuration (CI, scheduled, manual)
- [ ] Add pipeline run history (recent runs, failures)
- [ ] Add pipeline approvals and gates
- [ ] Add pipeline artifact configuration (publish locations)
- [ ] Add Docker build task analysis (image names, registries)
- [ ] Add Kubernetes deployment task analysis (manifests, namespaces)
- [ ] Add Terraform/ARM deployment analysis (template files)
- [ ] Add pipeline caching configuration
- [ ] Add pipeline resources (repos, pipelines, containers referenced)
```

---

## 4. DEVOPS-ARTIFACTS Module (`devops-artifacts.go`)

**Current Capabilities:**
- Artifact feed enumeration
- Feed visibility (organization, private, public)
- Feed capabilities (npm, NuGet, Maven, Python, Universal)

**Security Gaps Identified:**
1. ❌ **No Feed Permissions** - Who can publish/consume
2. ❌ **No Package Enumeration** - Packages in each feed
3. ❌ **No Package Versions** - Version history
4. ❌ **No Upstream Sources** - External package sources (npmjs, PyPI, Maven Central)
5. ❌ **No Feed Views** - Release, prerelease, local views
6. ❌ **No Package Retention** - Package retention policies
7. ❌ **No Package Download Stats** - Usage metrics
8. ❌ **No Feed Credentials** - Personal access tokens for feeds

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add feed permissions (users/groups with contributor/reader access)
- [ ] Add package enumeration (all packages in each feed)
- [ ] Add upstream source configuration (external package proxies)
- [ ] Add feed credentials and PAT usage

HIGH PRIORITY:
- [ ] Add package version history (all versions, publish dates)
- [ ] Add package download statistics (usage tracking)
- [ ] Add feed retention policies (days to keep packages)
- [ ] Add feed views (release, prerelease, local)
- [ ] Add package promotion history (view-to-view promotion)
```

---

## 5. AUTOMATION Module (`automation.go`)

**Current Capabilities:**
- Automation account enumeration
- Managed identity enumeration
- Basic account details

**Security Gaps Identified:**
1. ❌ **No Runbook Enumeration** - PowerShell/Python runbooks
2. ❌ **No Runbook Content** - Script content (may contain secrets)
3. ❌ **No Runbook Schedules** - When runbooks execute
4. ❌ **No Runbook Jobs** - Execution history and logs
5. ❌ **No Variables** - Automation variables (secrets)
6. ❌ **No Credentials** - Stored credentials and certificates
7. ❌ **No Connections** - Azure, Azure Classic connections
8. ❌ **No Modules** - Imported PowerShell modules
9. ❌ **No Hybrid Worker Groups** - On-prem runbook execution
10. ❌ **No Webhook Configuration** - HTTP-triggered runbooks
11. ❌ **No DSC Configurations** - Desired State Configuration
12. ❌ **No Update Management** - Patch management configuration
13. ❌ **No Change Tracking** - File and registry monitoring
14. ❌ **No Inventory** - VM inventory data

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add runbook enumeration (PowerShell, Python, PowerShell Workflow)
- [ ] Add runbook content extraction (full script code)
- [ ] Add automation variables (encrypted and plaintext variables)
- [ ] Add credential assets (username/password pairs)
- [ ] Add certificate assets (uploaded certificates)
- [ ] Add connection assets (Azure subscriptions, Classic Run As)
- [ ] Add webhook enumeration (webhook URLs and expiration)
- [ ] Add hybrid worker group configuration (on-prem agents)

HIGH PRIORITY:
- [ ] Add runbook schedules (when runbooks are triggered)
- [ ] Add runbook job history (recent runs, output, errors)
- [ ] Add PowerShell module list (imported modules and versions)
- [ ] Add DSC configuration enumeration
- [ ] Add Update Management configuration (patch compliance)
- [ ] Add Change Tracking configuration (tracked files/registry)
- [ ] Add source control integration (Git repos for runbooks)
- [ ] Add Run As accounts (service principal credentials)
```

---

## 6. POLICY Module (`policy.go`)

**Current Capabilities:**
- Azure Policy assignment enumeration at multiple scopes
- Policy definition details
- Enforcement mode (enforced, disabled)
- Scope hierarchy (management group, subscription, resource group)

**Security Gaps Identified:**
1. ❌ **No Policy Compliance Status** - Which resources are compliant/non-compliant
2. ❌ **No Policy Remediation Tasks** - Active remediation operations
3. ❌ **No Policy Exemptions** - Resources exempted from policies
4. ❌ **No Policy Initiatives** - Initiative (policy set) definitions not fully expanded
5. ❌ **No Policy Parameters** - Parameter values per assignment
6. ❌ **No Policy Effects** - Audit, Deny, DeployIfNotExists, Modify effects
7. ❌ **No Custom Policy Definitions** - Organization-created policies
8. ❌ **No Policy Aliases** - Resource property aliases used
9. ❌ **No Policy Activity Logs** - Policy enforcement events

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add policy compliance status per assignment (compliant, non-compliant counts)
- [ ] Add non-compliant resources enumeration (which resources violate policy)
- [ ] Add policy exemption enumeration (exempt resources and reasons)
- [ ] Add policy effect analysis (Audit vs Deny vs DeployIfNotExists)
- [ ] Add custom policy definition enumeration (user-created policies)

HIGH PRIORITY:
- [ ] Add policy initiative (set) details and included policies
- [ ] Add policy parameter values per assignment
- [ ] Add policy remediation tasks (active remediation operations)
- [ ] Add policy activity log integration (policy evaluation events)
- [ ] Add policy aliases used in definitions
- [ ] Add policy metadata (category, description, version)
- [ ] Add policy assignment identity (managed identity for remediation)
```

---

## 7. DEPLOYMENTS Module (`deployments.go`)

**Current Capabilities:**
- ARM template deployment enumeration
- Deployment state (succeeded, failed, running)
- Deployment timestamp
- Resource group scope

**Security Gaps Identified:**
1. ❌ **No Deployment Template** - ARM template JSON content
2. ❌ **No Deployment Parameters** - Parameter values (may contain secrets)
3. ❌ **No Deployment Operations** - Resource creation/modification steps
4. ❌ **No Deployment Output** - Deployment output values
5. ❌ **No Deployment Errors** - Error messages and stack traces
6. ❌ **No Deployment Correlation ID** - Activity log correlation
7. ❌ **No Deployment What-If Results** - Predicted changes
8. ❌ **No Deployment Script Output** - Deployment script logs
9. ❌ **No Deployment Dependencies** - Resource dependency graph
10. ❌ **No Subscription/Management Group Deployments** - Deployments at higher scopes

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add deployment template content (ARM JSON)
- [ ] Add deployment parameter values (check for secrets)
- [ ] Add deployment operations (what resources were created/modified)
- [ ] Add deployment output values (exposed endpoints, connection strings)
- [ ] Add deployment error details (failure reasons)

HIGH PRIORITY:
- [ ] Add subscription-level deployments
- [ ] Add management group-level deployments
- [ ] Add deployment script output (inline script logs)
- [ ] Add deployment correlation ID (link to Activity Log)
- [ ] Add deployment dependencies (resource dependency graph)
- [ ] Add deployment provisioning state per resource
- [ ] Add deployment duration and performance
```

---

## 8. INVENTORY Module (`inventory.go`)

**Current Capabilities:**
- Comprehensive resource inventory across subscriptions
- Resource type classification
- Resource group and region
- Tags enumeration

**Security Gaps Identified:**
1. ❌ **No Resource Cost** - Estimated monthly cost per resource
2. ❌ **No Resource Creation Date** - When resource was created
3. ❌ **No Resource Creator** - Who created the resource (Activity Log)
4. ❌ **No Resource Health** - Azure Resource Health status
5. ❌ **No Resource Locks** - Delete/ReadOnly locks
6. ❌ **No Resource Recommendations** - Azure Advisor recommendations
7. ❌ **No Resource Alerts** - Configured alerts per resource
8. ❌ **No Resource Metrics** - Key performance metrics
9. ❌ **No Resource Dependencies** - Which resources depend on others
10. ❌ **No Orphaned Resources** - Resources not attached to anything

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add resource locks (delete locks, read-only locks)
- [ ] Add orphaned resource detection (unattached disks, NICs, etc.)
- [ ] Add resource cost estimation (monthly cost per resource)
- [ ] Add resource creation date and creator (from Activity Log)

HIGH PRIORITY:
- [ ] Add resource health status (available, degraded, unavailable)
- [ ] Add Azure Advisor recommendations per resource
- [ ] Add resource alerts and action groups
- [ ] Add resource dependencies (dependency graph)
- [ ] Add resource activity log recent events
- [ ] Add resource diagnostic settings status
```

---

## 9. ACCESS KEYS Module (`accesskeys.go`)

**Current Capabilities:**
- Service access key enumeration across multiple Azure services
- Key rotation recommendations

**Security Gaps Identified:**
1. ❌ **No Key Expiration Dates** - When keys expire (if applicable)
2. ❌ **No Key Last Used** - When key was last utilized
3. ❌ **No Key Rotation History** - When key was last rotated
4. ❌ **No Key Permissions** - What the key can access
5. ❌ **No Key Origin** - Primary vs secondary key

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add key rotation history (last rotated date)
- [ ] Add key expiration dates (for services that support it)
- [ ] Add key last used timestamp (if available via logs)
- [ ] Add key origin (primary vs secondary)

HIGH PRIORITY:
- [ ] Add key permissions and scope (what the key allows)
- [ ] Add key regeneration recommendations (keys older than X days)
- [ ] Add key usage statistics (API call counts if available)
```

---

## 10. WHOAMI Module (`whoami.go`)

**Current Capabilities:**
- Current user identity (UPN, object ID)
- Tenant information
- Subscription access
- Token claims

**Security Gaps Identified:**
1. ❌ **No Effective Permissions** - What can the current user actually do
2. ❌ **No Group Memberships** - Which Entra ID groups
3. ❌ **No Role Assignments** - RBAC roles at all scopes
4. ❌ **No PIM Eligibility** - Eligible roles (not activated)
5. ❌ **No Conditional Access Policies Applied** - CA policies affecting user
6. ❌ **No MFA Status** - Whether MFA is enabled for current user
7. ❌ **No Recent Sign-Ins** - User's sign-in history
8. ❌ **No Token Expiration** - When access token expires

**Recommended Enhancements:**

```markdown
CRITICAL PRIORITY:
- [ ] Add effective permissions (what actions can be performed)
- [ ] Add RBAC role assignments at all scopes (subscription, RG, resource)
- [ ] Add PIM eligible role assignments
- [ ] Add group memberships (security groups, AAD groups)

HIGH PRIORITY:
- [ ] Add conditional access policies applied to user
- [ ] Add MFA enforcement status
- [ ] Add token expiration time
- [ ] Add recent sign-in activity
- [ ] Add service principal permissions (if running as SP)
```

---

## SESSION 7 SUMMARY: DevOps & Management Gaps

### Critical Gaps Across DevOps & Management Modules

1. **Embedded Secrets** - Pipeline variables, runbook content, deployment parameters
2. **Service Connections** - Azure DevOps service connections (AWS, Azure, K8s credentials)
3. **Runbook Automation** - Automation runbook content and variables
4. **Pipeline Security** - Inline scripts, agent pools, approval gates
5. **Policy Enforcement** - Compliance status, exemptions, remediation
6. **Deployment History** - Template content, parameters, outputs
7. **Resource Inventory** - Locks, costs, health, orphaned resources
8. **Access Key Rotation** - Key age, last used, rotation tracking
9. **Identity Context** - Current user's effective permissions
10. **Repository Secrets** - Secrets in code, branch protection

### Recommended New DevOps & Management Modules

```markdown
NEW MODULE SUGGESTIONS:

1. **DEVOPS-SECURITY Module**
   - Comprehensive Azure DevOps security posture
   - Service connections with credentials
   - Variable groups and secure files
   - PATs and SSH keys
   - Repository secret scanning results

2. **AUTOMATION-SECURITY Module**
   - Runbook content with secret detection
   - Automation variables and credentials
   - Hybrid worker security
   - Webhook exposure
   - Run As account permissions

3. **COMPLIANCE-DASHBOARD Module**
   - Policy compliance across all subscriptions
   - Non-compliant resources
   - Policy exemptions
   - Security Center recommendations
   - Advisor security recommendations

4. **DEPLOYMENT-HISTORY Module**
   - Recent ARM deployments with templates
   - Parameter value analysis (secret detection)
   - Deployment errors and failures
   - What-If analysis results

5. **COST-SECURITY Module**
   - Resource cost estimation
   - Orphaned resource cost
   - Over-provisioned resources
   - Cost anomalies (crypto mining detection)
```

---

## DEVOPS ATTACK SURFACE MATRIX

| Component | Critical Vectors | Secret Exposure | Privilege Escalation | Code Execution |
|-----------|-----------------|-----------------|---------------------|----------------|
| DevOps Repos | Secrets in code, No branch protection | Hardcoded credentials | Service connection credentials | CI/CD pipeline triggers |
| DevOps Pipelines | Pipeline variables, Inline scripts | Secrets in YAML | Service connection elevation | Agent pools, pipeline tasks |
| Automation | Runbook content, Variables | Automation variables/credentials | Hybrid workers, Run As | Runbook execution |
| Deployments | Template parameters | Secrets in parameters/outputs | Resource creation | Deployment scripts |
| Policy | Policy exemptions | N/A | Assignment identity | DeployIfNotExists remediation |

---

## FINAL PREPARATION

**Session 8:** Final Consolidated Recommendations + Missing Azure Services + Complete Implementation Roadmap + Priority Matrix

---

**END OF SESSION 7**

*Next session will provide final recommendations and missing services*
