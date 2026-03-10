package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	organizationsservice "github.com/BishopFox/cloudfox/gcp/services/organizationsService"
	orgpolicyservice "github.com/BishopFox/cloudfox/gcp/services/orgpolicyService"
	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPOrgPoliciesCommand = &cobra.Command{
	Use:     globals.GCP_ORGPOLICIES_MODULE_NAME,
	Aliases: []string{"orgpolicy", "policies"},
	Short:   "Enumerate organization policies and identify security weaknesses",
	Long: `Enumerate GCP organization policies to identify security configuration weaknesses.

Organization policies control security constraints across GCP resources. This module
identifies policies that may be misconfigured or weakened, creating security risks.

Enumerates policies at organization, folder, and project levels. Org and folder level
enumeration requires orgpolicy.policies.list at those scopes and is best-effort.

Security-Relevant Policies Analyzed:
- Domain restrictions (iam.allowedPolicyMemberDomains)
- Service account key controls (iam.disableServiceAccountKeyCreation)
- Workload identity restrictions
- Compute security (Shielded VM, OS Login, external IPs)
- Storage security (public access, uniform access)
- SQL security (public IPs, authorized networks)
- GKE security (public endpoints)
- Resource location restrictions

Risk Indicators:
- AllowAll: Policy allows any value (HIGH risk)
- Wildcard patterns: Overly permissive allowed values
- Unenforced: Security constraint not enabled
- Override: Project overrides parent restrictions`,
	Run: runGCPOrgPoliciesCommand,
}

type OrgPoliciesModule struct {
	gcpinternal.BaseGCPModule
	ProjectPolicies map[string][]orgpolicyservice.OrgPolicyInfo // projectID -> policies
	OrgPolicies     map[string][]orgpolicyservice.OrgPolicyInfo // orgID -> policies
	FolderPolicies  map[string][]orgpolicyservice.OrgPolicyInfo // folderID -> policies
	LootMap         map[string]map[string]*internal.LootFile    // scopeID -> loot files
	mu              sync.Mutex
}

type OrgPoliciesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o OrgPoliciesOutput) TableFiles() []internal.TableFile { return o.Table }
func (o OrgPoliciesOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPOrgPoliciesCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_ORGPOLICIES_MODULE_NAME)
	if err != nil {
		return
	}

	module := &OrgPoliciesModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectPolicies: make(map[string][]orgpolicyservice.OrgPolicyInfo),
		OrgPolicies:     make(map[string][]orgpolicyservice.OrgPolicyInfo),
		FolderPolicies:  make(map[string][]orgpolicyservice.OrgPolicyInfo),
		LootMap:         make(map[string]map[string]*internal.LootFile),
	}
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

func (m *OrgPoliciesModule) Execute(ctx context.Context, logger internal.Logger) {
	// Enumerate org-level and folder-level policies (best-effort)
	m.enumerateOrgAndFolderPolicies(logger)

	// Enumerate project-level policies
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ORGPOLICIES_MODULE_NAME, m.processProject)

	allPolicies := m.getAllPolicies()
	if len(allPolicies) == 0 {
		logger.InfoM("No organization policies found (may require orgpolicy.policies.list permission)", globals.GCP_ORGPOLICIES_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d organization policy(ies)", len(allPolicies)), globals.GCP_ORGPOLICIES_MODULE_NAME)
	m.writeOutput(ctx, logger)
}

func (m *OrgPoliciesModule) enumerateOrgAndFolderPolicies(logger internal.Logger) {
	orgSvc := organizationsservice.New()
	policySvc := orgpolicyservice.New()

	// Discover organizations
	orgs, err := orgSvc.SearchOrganizations()
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM("Could not enumerate organizations (may lack permissions)", globals.GCP_ORGPOLICIES_MODULE_NAME)
		}
	} else {
		for _, org := range orgs {
			orgID := strings.TrimPrefix(org.Name, "organizations/")
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Enumerating org policies for organization: %s (%s)", org.DisplayName, orgID), globals.GCP_ORGPOLICIES_MODULE_NAME)
			}

			policies, err := policySvc.ListOrganizationPolicies(orgID, org.DisplayName)
			if err != nil {
				if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
					gcpinternal.HandleGCPError(err, logger, globals.GCP_ORGPOLICIES_MODULE_NAME,
						fmt.Sprintf("Could not enumerate org policies for organization %s", orgID))
				}
				continue
			}

			m.mu.Lock()
			m.OrgPolicies[orgID] = policies
			m.initLootForScope(orgID)
			for _, policy := range policies {
				m.addPolicyToLoot(orgID, policy)
			}
			m.mu.Unlock()

			if len(policies) > 0 {
				logger.SuccessM(fmt.Sprintf("Found %d org-level policy(ies) for organization %s", len(policies), org.DisplayName), globals.GCP_ORGPOLICIES_MODULE_NAME)
			}
		}
	}

	// Discover folders
	folders, err := orgSvc.SearchAllFolders()
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM("Could not enumerate folders (may lack permissions)", globals.GCP_ORGPOLICIES_MODULE_NAME)
		}
	} else {
		for _, folder := range folders {
			folderID := strings.TrimPrefix(folder.Name, "folders/")
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Enumerating org policies for folder: %s (%s)", folder.DisplayName, folderID), globals.GCP_ORGPOLICIES_MODULE_NAME)
			}

			policies, err := policySvc.ListFolderPolicies(folderID, folder.DisplayName)
			if err != nil {
				if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
					gcpinternal.HandleGCPError(err, logger, globals.GCP_ORGPOLICIES_MODULE_NAME,
						fmt.Sprintf("Could not enumerate org policies for folder %s", folderID))
				}
				continue
			}

			m.mu.Lock()
			m.FolderPolicies[folderID] = policies
			m.initLootForScope(folderID)
			for _, policy := range policies {
				m.addPolicyToLoot(folderID, policy)
			}
			m.mu.Unlock()

			if len(policies) > 0 {
				logger.SuccessM(fmt.Sprintf("Found %d folder-level policy(ies) for folder %s", len(policies), folder.DisplayName), globals.GCP_ORGPOLICIES_MODULE_NAME)
			}
		}
	}
}

func (m *OrgPoliciesModule) getAllPolicies() []orgpolicyservice.OrgPolicyInfo {
	var all []orgpolicyservice.OrgPolicyInfo
	for _, policies := range m.OrgPolicies {
		all = append(all, policies...)
	}
	for _, policies := range m.FolderPolicies {
		all = append(all, policies...)
	}
	for _, policies := range m.ProjectPolicies {
		all = append(all, policies...)
	}
	return all
}

func (m *OrgPoliciesModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating org policies in project: %s", projectID), globals.GCP_ORGPOLICIES_MODULE_NAME)
	}

	m.mu.Lock()
	m.initLootForScope(projectID)
	m.mu.Unlock()

	svc := orgpolicyservice.New()
	policies, err := svc.ListProjectPolicies(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_ORGPOLICIES_MODULE_NAME,
			fmt.Sprintf("Could not enumerate org policies in project %s", projectID))
		return
	}

	// Set ScopeName from project name map
	for i := range policies {
		policies[i].ScopeName = m.GetProjectName(projectID)
	}

	m.mu.Lock()
	m.ProjectPolicies[projectID] = policies
	for _, policy := range policies {
		m.addPolicyToLoot(projectID, policy)
	}
	m.mu.Unlock()
}

func (m *OrgPoliciesModule) initLootForScope(scopeID string) {
	if m.LootMap[scopeID] == nil {
		m.LootMap[scopeID] = make(map[string]*internal.LootFile)
		m.LootMap[scopeID]["orgpolicies-commands"] = &internal.LootFile{
			Name:     "orgpolicies-commands",
			Contents: "# Organization Policy Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}
}

func (m *OrgPoliciesModule) addPolicyToLoot(scopeID string, policy orgpolicyservice.OrgPolicyInfo) {
	lootFile := m.LootMap[scopeID]["orgpolicies-commands"]
	if lootFile == nil {
		return
	}
	// Extract short constraint name for commands
	constraintName := policy.Constraint
	if strings.HasPrefix(constraintName, "constraints/") {
		constraintName = strings.TrimPrefix(constraintName, "constraints/")
	}

	// Scope label for loot comments
	scopeLabel := fmt.Sprintf("%s: %s", policy.ScopeType, policy.ScopeID)
	if policy.ScopeName != "" {
		scopeLabel = fmt.Sprintf("%s: %s (%s)", policy.ScopeType, policy.ScopeName, policy.ScopeID)
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# CONSTRAINT: %s\n"+
			"# =============================================================================\n"+
			"# Scope: %s\n",
		policy.Constraint,
		scopeLabel,
	)

	if policy.Description != "" {
		lootFile.Contents += fmt.Sprintf("# Description: %s\n", policy.Description)
	}

	lootFile.Contents += fmt.Sprintf(
		"# Enforced: %s, AllowAll: %s, DenyAll: %s, Inherit: %s\n",
		shared.BoolToYesNo(policy.Enforced),
		shared.BoolToYesNo(policy.AllowAll),
		shared.BoolToYesNo(policy.DenyAll),
		shared.BoolToYesNo(policy.InheritParent),
	)

	if len(policy.AllowedValues) > 0 {
		lootFile.Contents += fmt.Sprintf("# Allowed Values: %s\n", strings.Join(policy.AllowedValues, ", "))
	}
	if len(policy.DeniedValues) > 0 {
		lootFile.Contents += fmt.Sprintf("# Denied Values: %s\n", strings.Join(policy.DeniedValues, ", "))
	}

	// Build enumeration commands based on scope type
	lootFile.Contents += "\n# === ENUMERATION COMMANDS ===\n\n"
	switch policy.ScopeType {
	case "organization":
		lootFile.Contents += fmt.Sprintf(
			"# Describe this policy:\n"+
				"gcloud org-policies describe %s --organization=%s\n\n"+
				"# Get effective policy (includes inheritance):\n"+
				"gcloud org-policies describe %s --organization=%s --effective\n\n"+
				"# List all constraints for this organization:\n"+
				"gcloud org-policies list --organization=%s\n\n",
			constraintName, policy.ScopeID,
			constraintName, policy.ScopeID,
			policy.ScopeID,
		)
	case "folder":
		lootFile.Contents += fmt.Sprintf(
			"# Describe this policy:\n"+
				"gcloud org-policies describe %s --folder=%s\n\n"+
				"# Get effective policy (includes inheritance):\n"+
				"gcloud org-policies describe %s --folder=%s --effective\n\n"+
				"# List all constraints for this folder:\n"+
				"gcloud org-policies list --folder=%s\n\n",
			constraintName, policy.ScopeID,
			constraintName, policy.ScopeID,
			policy.ScopeID,
		)
	default: // project
		lootFile.Contents += fmt.Sprintf(
			"# Describe this policy:\n"+
				"gcloud org-policies describe %s --project=%s\n\n"+
				"# Get effective policy (includes inheritance):\n"+
				"gcloud org-policies describe %s --project=%s --effective\n\n"+
				"# List all constraints for this project:\n"+
				"gcloud org-policies list --project=%s\n\n",
			constraintName, policy.ScopeID,
			constraintName, policy.ScopeID,
			policy.ScopeID,
		)
	}

	// Exploit/bypass commands based on specific constraint types
	lootFile.Contents += "# === EXPLOIT / BYPASS COMMANDS ===\n\n"

	// For exploit commands, use project ID if available, otherwise use scope ID
	targetProject := policy.ProjectID
	if targetProject == "" {
		targetProject = "<PROJECT_ID>"
	}

	switch constraintName {
	case "iam.allowedPolicyMemberDomains":
		if policy.AllowAll {
			lootFile.Contents += "# [FINDING] Domain restriction is DISABLED (AllowAll) - any external identity can be granted access\n"
			lootFile.Contents += fmt.Sprintf(
				"# Grant access to external identity:\n"+
					"gcloud projects add-iam-policy-binding %s --member=user:attacker@external.com --role=roles/viewer\n\n",
				targetProject,
			)
		} else if !policy.Enforced {
			lootFile.Contents += "# [FINDING] Domain restriction is NOT ENFORCED\n\n"
		}

	case "iam.disableServiceAccountKeyCreation":
		if !policy.Enforced || policy.AllowAll {
			lootFile.Contents += "# [FINDING] SA key creation is NOT restricted - create keys for persistence:\n"
			lootFile.Contents += fmt.Sprintf(
				"gcloud iam service-accounts keys create /tmp/sa-key.json --iam-account=SA_EMAIL@%s.iam.gserviceaccount.com\n\n",
				targetProject,
			)
		} else {
			lootFile.Contents += "# SA key creation is restricted - try alternative persistence methods:\n" +
				"# - Workload identity federation\n" +
				"# - Service account impersonation chain\n\n"
		}

	case "iam.disableServiceAccountCreation":
		if !policy.Enforced || policy.AllowAll {
			lootFile.Contents += "# [FINDING] SA creation is NOT restricted - create backdoor service accounts:\n"
			lootFile.Contents += fmt.Sprintf(
				"gcloud iam service-accounts create cloudfox-backdoor --display-name='System Service' --project=%s\n\n",
				targetProject,
			)
		}

	case "compute.requireShieldedVm":
		if !policy.Enforced || policy.AllowAll {
			lootFile.Contents += "# [FINDING] Shielded VM is NOT required - unshielded VMs can be created:\n" +
				"# Boot integrity monitoring is not enforced\n\n"
		}

	case "compute.requireOsLogin":
		if !policy.Enforced || policy.AllowAll {
			lootFile.Contents += "# [FINDING] OS Login is NOT required - SSH keys can be added to project/instance metadata:\n"
			lootFile.Contents += fmt.Sprintf(
				"# Add SSH key to project metadata:\n"+
					"gcloud compute project-info add-metadata --metadata=ssh-keys=\"attacker:ssh-rsa AAAA...\" --project=%s\n\n",
				targetProject,
			)
		}

	case "compute.vmExternalIpAccess":
		if policy.AllowAll {
			lootFile.Contents += "# [FINDING] External IP access is NOT restricted - VMs can have public IPs:\n" +
				"# Any VM can be assigned a public IP for data exfiltration\n\n"
		}

	case "storage.uniformBucketLevelAccess":
		if !policy.Enforced || policy.AllowAll {
			lootFile.Contents += "# [FINDING] Uniform bucket access is NOT enforced - ACLs can be used:\n" +
				"# Fine-grained ACLs allow per-object permissions that are harder to audit\n\n"
		}

	case "storage.publicAccessPrevention":
		if !policy.Enforced || policy.AllowAll {
			lootFile.Contents += "# [FINDING] Public access prevention is NOT enforced:\n"
			lootFile.Contents += fmt.Sprintf(
				"# Make a bucket publicly accessible:\n"+
					"gsutil iam ch allUsers:objectViewer gs://BUCKET_NAME\n"+
					"# Or set public ACL:\n"+
					"gsutil acl ch -u AllUsers:R gs://BUCKET_NAME/OBJECT\n\n",
			)
		}

	case "sql.restrictPublicIp":
		if !policy.Enforced || policy.AllowAll {
			lootFile.Contents += "# [FINDING] Public IP restriction is NOT enforced on Cloud SQL:\n" +
				"# SQL instances can be created with public IPs\n\n"
		}

	case "sql.restrictAuthorizedNetworks":
		if !policy.Enforced || policy.AllowAll {
			lootFile.Contents += "# [FINDING] Authorized network restriction is NOT enforced:\n" +
				"# 0.0.0.0/0 can be added to authorized networks\n\n"
		}

	default:
		if policy.AllowAll {
			lootFile.Contents += fmt.Sprintf("# [FINDING] Policy %s has AllowAll - constraint is effectively disabled\n\n", constraintName)
		} else if !policy.Enforced {
			lootFile.Contents += fmt.Sprintf("# [FINDING] Policy %s is not enforced\n\n", constraintName)
		}
	}
}

func (m *OrgPoliciesModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *OrgPoliciesModule) getHeader() []string {
	return []string{
		"Scope Type",
		"Scope ID",
		"Scope Name",
		"Constraint",
		"Description",
		"Enforced",
		"Allow All",
		"Deny All",
		"Inherit",
		"Allowed Values",
		"Denied Values",
	}
}

func (m *OrgPoliciesModule) policiesToTableBody(policies []orgpolicyservice.OrgPolicyInfo) [][]string {
	var body [][]string
	for _, policy := range policies {
		description := policy.Description
		if description == "" {
			description = "-"
		}

		allowedValues := "-"
		if len(policy.AllowedValues) > 0 {
			allowedValues = strings.Join(policy.AllowedValues, ", ")
		}

		deniedValues := "-"
		if len(policy.DeniedValues) > 0 {
			deniedValues = strings.Join(policy.DeniedValues, ", ")
		}

		scopeName := policy.ScopeName
		if scopeName == "" {
			scopeName = "-"
		}

		body = append(body, []string{
			policy.ScopeType,
			policy.ScopeID,
			scopeName,
			policy.Constraint,
			description,
			shared.BoolToYesNo(policy.Enforced),
			shared.BoolToYesNo(policy.AllowAll),
			shared.BoolToYesNo(policy.DenyAll),
			shared.BoolToYesNo(policy.InheritParent),
			allowedValues,
			deniedValues,
		})
	}
	return body
}

func (m *OrgPoliciesModule) buildTablesForScope(scopeID string, policies []orgpolicyservice.OrgPolicyInfo) []internal.TableFile {
	var tableFiles []internal.TableFile
	if len(policies) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "orgpolicies",
			Header: m.getHeader(),
			Body:   m.policiesToTableBody(policies),
		})
	}
	return tableFiles
}

func (m *OrgPoliciesModule) collectLootForScope(scopeID string) []internal.LootFile {
	var lootFiles []internal.LootFile
	if scopeLoot, ok := m.LootMap[scopeID]; ok {
		for _, loot := range scopeLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}
	return lootFiles
}

func (m *OrgPoliciesModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		FolderLevelData:  make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Org-level data
	for orgID, policies := range m.OrgPolicies {
		tableFiles := m.buildTablesForScope(orgID, policies)
		lootFiles := m.collectLootForScope(orgID)
		outputData.OrgLevelData[orgID] = OrgPoliciesOutput{Table: tableFiles, Loot: lootFiles}
	}

	// Folder-level data
	for folderID, policies := range m.FolderPolicies {
		tableFiles := m.buildTablesForScope(folderID, policies)
		lootFiles := m.collectLootForScope(folderID)
		outputData.FolderLevelData[folderID] = OrgPoliciesOutput{Table: tableFiles, Loot: lootFiles}
	}

	// Project-level data
	for projectID, policies := range m.ProjectPolicies {
		tableFiles := m.buildTablesForScope(projectID, policies)
		lootFiles := m.collectLootForScope(projectID)
		outputData.ProjectLevelData[projectID] = OrgPoliciesOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_ORGPOLICIES_MODULE_NAME)
	}
}

func (m *OrgPoliciesModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allPolicies := m.getAllPolicies()

	var tables []internal.TableFile
	if len(allPolicies) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "orgpolicies",
			Header: m.getHeader(),
			Body:   m.policiesToTableBody(allPolicies),
		})
	}

	var lootFiles []internal.LootFile
	for _, scopeLoot := range m.LootMap {
		for _, loot := range scopeLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := OrgPoliciesOutput{Table: tables, Loot: lootFiles}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_ORGPOLICIES_MODULE_NAME)
	}
}
