# Future Roadmap: GitHub Actions Workload Identity Enumeration

**Status**: Future Enhancement
**Priority**: Medium
**Complexity**: Medium
**Estimated Size**: ~800-1000 lines of code

---

## Overview

Implement a **new CloudFox command group** for GitHub repository security enumeration, specifically focusing on GitHub Actions runners and their authentication to Azure using Workload Identity Federation (OIDC).

This would be similar to the Azure DevOps enumeration capabilities but for GitHub Actions.

---

## Proposed CLI Structure

```bash
# New command group
cloudfox github <subcommand>

# Subcommands
cloudfox github actions-runners    # Enumerate GitHub Actions runners
cloudfox github secrets            # Enumerate repository/org secrets
cloudfox github environments       # Enumerate deployment environments
cloudfox github workload-identity  # Enumerate OIDC federated credentials for GitHub Actions
cloudfox github webhooks           # Enumerate repository webhooks
cloudfox github deployments        # Enumerate deployment history
```

---

## Authentication Requirements

### GitHub Side (GitHub Token Required)
- **Personal Access Token (PAT)** or **GitHub App** with permissions:
  - `repo` scope (for private repositories)
  - `admin:org` scope (for organization-level runners)
  - `read:org` scope (for organization secrets)
  - `actions` scope (for workflow enumeration)

### Azure Side (Azure Credentials Required)
- Uses existing Azure authentication (az login)
- Microsoft Graph API access for federated credentials
- Azure Resource Manager API for subscription/resource access

---

## Module 1: `github actions-runners`

### Purpose
Enumerate GitHub Actions runners (similar to Azure DevOps agents) and identify self-hosted runners as HIGH RISK credential targets.

### Data Sources
- **GitHub REST API**: `/orgs/{org}/actions/runners`
- **GitHub REST API**: `/repos/{owner}/{repo}/actions/runners`

### Enumeration Targets

#### Organization-Level Runners
```
GET /orgs/{org}/actions/runners
```
- Runner ID, name, status (online/offline)
- OS and version
- Labels (self-hosted, Linux, Windows, etc.)
- Runner group membership
- Last job execution timestamp
- IP address (if available)

#### Repository-Level Runners
```
GET /repos/{owner}/{repo}/actions/runners
```
- Same as org-level but scoped to specific repositories
- Which repositories can access which runners

### Security Analysis

1. **Self-Hosted Runner Detection** (HIGH RISK)
   - Flag all self-hosted runners as credential exposure risks
   - Identify runners accessible to public repositories
   - Detect runners running on personal machines vs. cloud VMs

2. **Runner Group Permissions**
   - Which repositories have access to which runner groups
   - Overly permissive runner groups (accessible by many repos)
   - Public repositories with access to self-hosted runners (CRITICAL)

3. **Outdated Runner Versions**
   - Detect runners running old versions with known CVEs
   - Compare against latest GitHub Actions runner version

4. **Stale/Offline Runners**
   - Runners registered but offline for extended periods
   - Potential indicators of compromised/abandoned infrastructure

### Loot Files (5)
1. `github-runners-self-hosted.txt` - Self-hosted runners (HIGH RISK)
2. `github-runners-security-summary.txt` - Security analysis per runner
3. `github-runners-outdated.txt` - Runners with old versions
4. `github-runners-public-access.txt` - Runners accessible by public repos (CRITICAL)
5. `github-runners-permissions.txt` - Runner group access mappings

### Table Output (11 columns)
- Org/Repo, Runner Name, Type, Status, OS, Version, Labels, Last Job, Runner Group, Public Access, Security Risks

---

## Module 2: `github workload-identity`

### Purpose
Enumerate Azure AD Federated Credentials configured for GitHub Actions OIDC authentication. This allows GitHub Actions workflows to authenticate to Azure **without storing secrets**.

### Data Sources

#### Azure Side (Microsoft Graph API)
```
GET /servicePrincipals/{id}/federatedIdentityCredentials
```

Filter for GitHub-specific issuers:
- Issuer: `https://token.actions.githubusercontent.com`

#### GitHub Side (GitHub API)
```
GET /repos/{owner}/{repo}/actions/secrets
GET /repos/{owner}/{repo}/actions/variables
GET /repos/{owner}/{repo}/environments
```

Look for environment variables like:
- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`

### Enumeration Targets

#### Federated Credentials (Azure Side)
- Service principal display name and app ID
- Issuer URL (should be `https://token.actions.githubusercontent.com`)
- **Subject identifier** (critical for security analysis):
  - `repo:owner/repo:ref:refs/heads/main` - Scoped to main branch
  - `repo:owner/repo:ref:refs/heads/*` - Any branch (RISK)
  - `repo:owner/repo:pull_request` - Pull requests (HIGH RISK)
  - `repo:owner/repo:environment:production` - Scoped to environment (GOOD)
- Audiences (usually `api://AzureADTokenExchange`)
- Azure subscription and resource access
- RBAC roles assigned to the service principal

#### GitHub Repository Configuration
- Which repositories use Azure credentials
- Which workflows authenticate to Azure
- Which environments are configured for Azure deployments
- Secret/variable naming patterns indicating Azure authentication

### Security Analysis

1. **Overly Permissive Subject Scopes** (HIGH RISK)
   - Subject: `repo:owner/repo:pull_request` - PRs can authenticate to Azure (CRITICAL)
   - Subject: `repo:owner/repo:ref:refs/heads/*` - Any branch can authenticate (HIGH RISK)
   - Recommendation: Scope to specific branches or environments

2. **Pull Request Access to Production** (CRITICAL)
   - Federated credentials that allow PRs to authenticate to Azure
   - Allows external contributors (in public repos) to execute code with Azure access
   - This is a **supply chain attack vector**

3. **Public Repositories with Azure Access**
   - Public repos where workflows can authenticate to Azure
   - External contributors can fork and modify workflows
   - Risk of credential harvesting via malicious PR workflows

4. **Overprivileged Service Principals**
   - Service principals with Owner/Contributor roles on subscriptions
   - Should use least-privilege custom roles

5. **Secret-Based Authentication Still in Use**
   - Repositories still using `AZURE_CREDENTIALS` secret (client secret)
   - Should migrate to OIDC workload identity federation

### Cross-Reference Analysis

Link GitHub Actions runners to Azure identities:

```
GitHub Self-Hosted Runner
  └─> Running in Azure VM
      └─> VM has Managed Identity
          └─> Managed Identity has Azure RBAC roles
              └─> Attack Path: Compromise runner → Steal managed identity token → Access Azure resources

GitHub Actions Workflow
  └─> Authenticates via Workload Identity Federation
      └─> Uses Service Principal
          └─> Service Principal has Azure RBAC roles
              └─> Attack Path: Malicious PR → OIDC token → Azure access
```

### Loot Files (6)
1. `github-workload-identity-overpermissive.txt` - Broad subject scopes (HIGH RISK)
2. `github-workload-identity-pr-access.txt` - PRs can authenticate to Azure (CRITICAL)
3. `github-workload-identity-public-repos.txt` - Public repos with Azure access
4. `github-workload-identity-secrets.txt` - Repos still using client secrets
5. `github-workload-identity-summary.txt` - Overall security posture
6. `github-workload-identity-attack-paths.txt` - Complete attack path mappings

### Table Output (13 columns)
- Repository, Service Principal, Auth Method, Subject Scope, Azure Subscription, RBAC Roles, Environment, Branch Scope, PR Access, Public Repo, Last Used, Risk Level, Recommendations

---

## Module 3: `github secrets`

### Purpose
Enumerate GitHub repository and organization secrets, identifying potential credential exposure risks.

### Data Sources
```
GET /orgs/{org}/actions/secrets
GET /repos/{owner}/{repo}/actions/secrets
GET /repos/{owner}/{repo}/environments/{environment}/secrets
```

### Enumeration Targets
- Organization-level secrets (accessible by multiple repos)
- Repository-level secrets
- Environment-level secrets (production, staging, etc.)
- Secret names (values are not retrievable via API)
- Which repositories have access to org-level secrets
- When secrets were last updated

### Security Analysis
1. **Sensitive Secret Names**
   - `AZURE_CREDENTIALS` - Legacy authentication (should migrate to OIDC)
   - `AWS_ACCESS_KEY_ID` - Should use OIDC if possible
   - `PRIVATE_KEY`, `SSH_KEY` - Rotation policy needed
   - Database connection strings

2. **Overshared Organization Secrets**
   - Org secrets accessible by public repositories
   - Org secrets accessible by too many repositories

3. **Stale Secrets**
   - Secrets not updated in >90 days
   - May indicate forgotten credentials

---

## Module 4: `github environments`

### Purpose
Enumerate deployment environments and their protection rules.

### Data Sources
```
GET /repos/{owner}/{repo}/environments
GET /repos/{owner}/{repo}/environments/{environment}/deployment-branch-policies
```

### Enumeration Targets
- Environment names (production, staging, development)
- Required reviewers for deployments
- Branch protection policies
- Deployment branch restrictions
- Environment secrets and variables

### Security Analysis
1. **Production Environment Without Reviewers**
   - Deployments can proceed without manual approval
   - Risk of unauthorized deployments

2. **Deployment Branch Policies**
   - Environments accessible from any branch vs. specific branches
   - Best practice: Production should only deploy from main/release branches

---

## Attack Scenarios

### Scenario 1: Self-Hosted Runner Compromise
```
1. Identify self-hosted runner in public repository
2. Submit malicious PR with workflow that:
   - Harvests environment variables
   - Extracts Azure CLI credentials
   - Dumps runner capabilities
   - Establishes reverse shell for lateral movement
3. Self-hosted runner executes malicious code
4. Attacker gains access to corporate network and Azure credentials
```

### Scenario 2: OIDC Pull Request Attack
```
1. Identify public repository with workload identity federation
2. Identify federated credential with subject: "repo:owner/repo:pull_request"
3. Fork repository and create malicious workflow in PR
4. Workflow authenticates to Azure using OIDC token
5. Workflow harvests Azure access token
6. Attacker uses token to access Azure resources
```

### Scenario 3: Organization Secret Harvesting
```
1. Identify organization secrets shared with public repositories
2. Create new public repository in the organization
3. New repo inherits org-level secrets
4. Create workflow to exfiltrate secret values
5. Attacker gains access to credentials used across multiple repositories
```

---

## Implementation Notes

### Project Structure
```
cloudfox/
├── github/
│   ├── commands/
│   │   ├── actions-runners.go
│   │   ├── workload-identity.go
│   │   ├── secrets.go
│   │   ├── environments.go
│   │   ├── webhooks.go
│   │   └── deployments.go
│   └── internal/
│       └── github/
│           ├── client.go
│           ├── runner_helpers.go
│           ├── oidc_helpers.go
│           └── secret_helpers.go
├── cli/
│   └── github.go (new file)
└── globals/
    └── github.go (new file)
```

### Dependencies
```go
// GitHub API client
github.com/google/go-github/v57/github

// OAuth for GitHub authentication
golang.org/x/oauth2
```

### Authentication Flow
```go
// GitHub Token from environment variable
token := os.Getenv("GITHUB_TOKEN")

// Azure credentials (existing cloudfox authentication)
azureClient := azinternal.NewAzureClient()
```

---

## Security Recommendations for Users

### For Self-Hosted Runners:
1. **Never use self-hosted runners for public repositories**
2. Isolate self-hosted runners in dedicated network segments
3. Use ephemeral runners (destroy after each job)
4. Enable audit logging for all runner activity
5. Rotate runner registration tokens regularly

### For Workload Identity Federation:
1. **Always scope federated credentials to specific branches**
   - Good: `repo:owner/repo:ref:refs/heads/main`
   - Bad: `repo:owner/repo:ref:refs/heads/*`
2. **Never allow pull_request access for production environments**
   - Never: `repo:owner/repo:pull_request`
3. Use environment protection rules with required reviewers
4. Use least-privilege RBAC roles for service principals
5. Migrate from client secrets to OIDC workload identity

### For Secrets Management:
1. Avoid storing long-lived credentials as secrets
2. Use OIDC workload identity instead of client secrets where possible
3. Rotate secrets regularly (90-day policy)
4. Minimize organization-level secrets (use repo-level instead)
5. Never share org secrets with public repositories

---

## Related Research

- [GitHub Actions Security Best Practices](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Azure Workload Identity Federation for GitHub Actions](https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure)
- [Attacking Self-Hosted GitHub Actions Runners](https://www.praetorian.com/blog/self-hosted-github-actions-runner-security/)
- [GitHub Actions OIDC Security Considerations](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)

---

## Estimated Timeline

- **Module 1 (actions-runners)**: 2-3 days
- **Module 2 (workload-identity)**: 3-4 days (most complex due to cross-referencing)
- **Module 3 (secrets)**: 1-2 days
- **Module 4 (environments)**: 1-2 days
- **Testing & Documentation**: 2 days

**Total**: 9-13 days for full implementation

---

## Success Metrics

- Enumerate 100% of self-hosted runners in organization
- Identify all federated credentials with overpermissive scopes
- Flag all public repositories with access to organization secrets
- Generate actionable security recommendations with attack scenarios
- Provide complete attack path mappings (runner → identity → Azure resources)

---

**Next Steps**:
1. Get GitHub Token with appropriate scopes
2. Set up test environment with sample repositories and runners
3. Implement `actions-runners` module first (foundational)
4. Implement `workload-identity` module second (most critical for security)
5. Add remaining modules (secrets, environments, webhooks, deployments)
6. Create integration tests with real GitHub organizations
7. Add to CloudFox documentation and help system

---

**Document Version**: 1.0
**Created**: 2025-11-13
**Last Updated**: 2025-11-13
**Author**: CloudFox Development Team
