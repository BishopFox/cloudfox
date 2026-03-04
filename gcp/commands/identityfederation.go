package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	workloadidentityservice "github.com/BishopFox/cloudfox/gcp/services/workloadIdentityService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPIdentityFederationCommand = &cobra.Command{
	Use:     globals.GCP_IDENTITY_FEDERATION_MODULE_NAME,
	Aliases: []string{"federation", "wif", "federated-identity"},
	Short:   "Enumerate Workload Identity Federation (external identities)",
	Long: `Enumerate Workload Identity Federation pools, providers, and federated bindings.

Workload Identity Federation allows external identities (AWS, GitHub Actions,
GitLab CI, Azure AD, etc.) to authenticate as GCP service accounts without
using service account keys.

Features:
- Lists Workload Identity Pools and Providers
- Analyzes AWS, OIDC (GitHub Actions, GitLab CI), and SAML providers
- Identifies risky provider configurations (missing attribute conditions)
- Shows federated identity bindings to GCP service accounts
- Generates exploitation commands for pentesting

Security Considerations:
- Providers without attribute conditions allow ANY identity from the source
- OIDC providers (GitHub Actions, GitLab) may allow any repo/pipeline to authenticate
- AWS providers allow cross-account access from the configured AWS account
- Federated identities inherit all permissions of the bound GCP service account

TIP: Run 'workload-identity' to enumerate GKE-specific K8s SA -> GCP SA bindings.
TIP: Run foxmapper first to populate the Attack Paths column with privesc/exfil/lateral movement analysis.`,
	Run: runGCPIdentityFederationCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type IdentityFederationModule struct {
	gcpinternal.BaseGCPModule

	ProjectPools             map[string][]workloadidentityservice.WorkloadIdentityPool     // projectID -> pools
	ProjectProviders         map[string][]workloadidentityservice.WorkloadIdentityProvider  // projectID -> providers
	ProjectFederatedBindings map[string][]workloadidentityservice.FederatedIdentityBinding  // projectID -> federated bindings
	LootMap                  map[string]map[string]*internal.LootFile                       // projectID -> loot files
	FoxMapperCache           *gcpinternal.FoxMapperCache
	mu                       sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type IdentityFederationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o IdentityFederationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o IdentityFederationOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPIdentityFederationCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_IDENTITY_FEDERATION_MODULE_NAME)
	if err != nil {
		return
	}

	module := &IdentityFederationModule{
		BaseGCPModule:            gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectPools:             make(map[string][]workloadidentityservice.WorkloadIdentityPool),
		ProjectProviders:         make(map[string][]workloadidentityservice.WorkloadIdentityProvider),
		ProjectFederatedBindings: make(map[string][]workloadidentityservice.FederatedIdentityBinding),
		LootMap:                  make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *IdentityFederationModule) Execute(ctx context.Context, logger internal.Logger) {
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Using FoxMapper cache for attack path analysis", globals.GCP_IDENTITY_FEDERATION_MODULE_NAME)
	}

	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_IDENTITY_FEDERATION_MODULE_NAME, m.processProject)

	allPools := m.getAllPools()
	allProviders := m.getAllProviders()
	allFederatedBindings := m.getAllFederatedBindings()

	if len(allPools) == 0 {
		logger.InfoM("No Workload Identity Federation configurations found", globals.GCP_IDENTITY_FEDERATION_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d pool(s), %d provider(s), %d federated binding(s)",
		len(allPools), len(allProviders), len(allFederatedBindings)), globals.GCP_IDENTITY_FEDERATION_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// getAllPools returns all pools from all projects
func (m *IdentityFederationModule) getAllPools() []workloadidentityservice.WorkloadIdentityPool {
	var all []workloadidentityservice.WorkloadIdentityPool
	for _, pools := range m.ProjectPools {
		all = append(all, pools...)
	}
	return all
}

// getAllProviders returns all providers from all projects
func (m *IdentityFederationModule) getAllProviders() []workloadidentityservice.WorkloadIdentityProvider {
	var all []workloadidentityservice.WorkloadIdentityProvider
	for _, providers := range m.ProjectProviders {
		all = append(all, providers...)
	}
	return all
}

// getAllFederatedBindings returns all federated bindings from all projects
func (m *IdentityFederationModule) getAllFederatedBindings() []workloadidentityservice.FederatedIdentityBinding {
	var all []workloadidentityservice.FederatedIdentityBinding
	for _, bindings := range m.ProjectFederatedBindings {
		all = append(all, bindings...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *IdentityFederationModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Identity Federation in project: %s", projectID), globals.GCP_IDENTITY_FEDERATION_MODULE_NAME)
	}

	wiSvc := workloadidentityservice.New()

	// Get Workload Identity Pools
	allPools, err := wiSvc.ListWorkloadIdentityPools(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_IDENTITY_FEDERATION_MODULE_NAME,
			fmt.Sprintf("Could not list Workload Identity Pools in project %s", projectID))
		return
	}

	// Filter out GKE Workload Identity pools (*.svc.id.goog) - those belong to the workload-identity module
	var pools []workloadidentityservice.WorkloadIdentityPool
	for _, pool := range allPools {
		if !strings.HasSuffix(pool.PoolID, ".svc.id.goog") {
			pools = append(pools, pool)
		}
	}

	var providers []workloadidentityservice.WorkloadIdentityProvider

	// Get providers for each pool
	for _, pool := range pools {
		poolProviders, err := wiSvc.ListWorkloadIdentityProviders(projectID, pool.PoolID)
		if err != nil {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_IDENTITY_FEDERATION_MODULE_NAME,
				fmt.Sprintf("Could not list providers for pool %s", pool.PoolID))
			continue
		}
		providers = append(providers, poolProviders...)
	}

	// Find federated identity bindings
	fedBindings, err := wiSvc.FindFederatedIdentityBindings(projectID, pools)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_IDENTITY_FEDERATION_MODULE_NAME,
			fmt.Sprintf("Could not find federated identity bindings in project %s", projectID))
	}

	m.mu.Lock()
	m.ProjectPools[projectID] = pools
	m.ProjectProviders[projectID] = providers
	m.ProjectFederatedBindings[projectID] = fedBindings

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["identity-federation-commands"] = &internal.LootFile{
			Name:     "identity-federation-commands",
			Contents: "# Identity Federation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	for _, pool := range pools {
		m.addPoolToLoot(projectID, pool)
	}
	for _, provider := range providers {
		m.addProviderToLoot(projectID, provider)
	}
	for _, fedBinding := range fedBindings {
		m.addFederatedBindingToLoot(projectID, fedBinding)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d pool(s), %d provider(s), %d federated binding(s) in project %s",
			len(pools), len(providers), len(fedBindings), projectID), globals.GCP_IDENTITY_FEDERATION_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *IdentityFederationModule) addPoolToLoot(projectID string, pool workloadidentityservice.WorkloadIdentityPool) {
	lootFile := m.LootMap[projectID]["identity-federation-commands"]
	if lootFile == nil {
		return
	}
	status := "Active"
	if pool.Disabled {
		status = "Disabled"
	}
	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# FEDERATION POOL: %s\n"+
			"# =============================================================================\n"+
			"# Display Name: %s\n"+
			"# State: %s (%s)\n"+
			"# Description: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe pool:\n"+
			"gcloud iam workload-identity-pools describe %s --location=global --project=%s\n\n"+
			"# List providers:\n"+
			"gcloud iam workload-identity-pools providers list --workload-identity-pool=%s --location=global --project=%s\n\n",
		pool.PoolID,
		pool.DisplayName,
		pool.State, status,
		pool.Description,
		pool.PoolID, pool.ProjectID,
		pool.PoolID, pool.ProjectID,
	)
}

func (m *IdentityFederationModule) addProviderToLoot(projectID string, provider workloadidentityservice.WorkloadIdentityProvider) {
	lootFile := m.LootMap[projectID]["identity-federation-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# -----------------------------------------------------------------------------\n"+
			"# PROVIDER: %s/%s (%s)\n"+
			"# -----------------------------------------------------------------------------\n",
		provider.PoolID, provider.ProviderID,
		provider.ProviderType,
	)

	if provider.ProviderType == "AWS" {
		lootFile.Contents += fmt.Sprintf(
			"# AWS Account: %s\n", provider.AWSAccountID)
	} else if provider.ProviderType == "OIDC" {
		lootFile.Contents += fmt.Sprintf(
			"# OIDC Issuer: %s\n", provider.OIDCIssuerURI)
	}

	if provider.AttributeCondition != "" {
		lootFile.Contents += fmt.Sprintf(
			"# Attribute Condition: %s\n", provider.AttributeCondition)
	} else {
		lootFile.Contents += "# Attribute Condition: NONE (any identity from this provider can authenticate!)\n"
	}

	lootFile.Contents += "\n# === ENUMERATION COMMANDS ===\n\n"
	lootFile.Contents += fmt.Sprintf(
		"# Describe provider:\n"+
			"gcloud iam workload-identity-pools providers describe %s --workload-identity-pool=%s --location=global --project=%s\n\n",
		provider.ProviderID, provider.PoolID, provider.ProjectID,
	)

	// Add exploitation guidance based on provider type
	lootFile.Contents += "# === EXPLOIT COMMANDS ===\n\n"
	switch provider.ProviderType {
	case "AWS":
		lootFile.Contents += fmt.Sprintf(
			"# From AWS account %s, exchange credentials:\n"+
				"# gcloud iam workload-identity-pools create-cred-config \\\n"+
				"#   projects/%s/locations/global/workloadIdentityPools/%s/providers/%s \\\n"+
				"#   --aws --output-file=gcp-creds.json\n\n",
			provider.AWSAccountID,
			provider.ProjectID, provider.PoolID, provider.ProviderID,
		)
	case "OIDC":
		if strings.Contains(provider.OIDCIssuerURI, "github") {
			lootFile.Contents += fmt.Sprintf(
				"# From GitHub Actions workflow, add:\n"+
					"# permissions:\n"+
					"#   id-token: write\n"+
					"#   contents: read\n"+
					"# Then use:\n"+
					"# gcloud iam workload-identity-pools create-cred-config \\\n"+
					"#   projects/%s/locations/global/workloadIdentityPools/%s/providers/%s \\\n"+
					"#   --service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com \\\n"+
					"#   --output-file=gcp-creds.json\n\n",
				provider.ProjectID, provider.PoolID, provider.ProviderID,
			)
		}
	}
}

func (m *IdentityFederationModule) addFederatedBindingToLoot(projectID string, binding workloadidentityservice.FederatedIdentityBinding) {
	lootFile := m.LootMap[projectID]["identity-federation-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# -----------------------------------------------------------------------------\n"+
			"# FEDERATED BINDING\n"+
			"# -----------------------------------------------------------------------------\n"+
			"# Pool: %s\n"+
			"# GCP Service Account: %s\n"+
			"# External Subject: %s\n\n",
		binding.PoolID,
		binding.GCPServiceAccount,
		binding.ExternalSubject,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *IdentityFederationModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *IdentityFederationModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	for projectID := range m.ProjectPools {
		tables := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = IdentityFederationOutput{Table: tables, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart(
		"gcp",
		m.Format,
		m.Verbosity,
		m.WrapTable,
		pathBuilder,
		outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_IDENTITY_FEDERATION_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

func (m *IdentityFederationModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allPools := m.getAllPools()
	allProviders := m.getAllProviders()
	allFederatedBindings := m.getAllFederatedBindings()

	tables := m.buildTables(allPools, allProviders, allFederatedBindings)

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := IdentityFederationOutput{
		Table: tables,
		Loot:  lootFiles,
	}

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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_IDENTITY_FEDERATION_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// buildTablesForProject builds tables for a specific project
func (m *IdentityFederationModule) buildTablesForProject(projectID string) []internal.TableFile {
	pools := m.ProjectPools[projectID]
	providers := m.ProjectProviders[projectID]
	federatedBindings := m.ProjectFederatedBindings[projectID]
	return m.buildTables(pools, providers, federatedBindings)
}

// buildTables builds all tables from the given data
func (m *IdentityFederationModule) buildTables(
	pools []workloadidentityservice.WorkloadIdentityPool,
	providers []workloadidentityservice.WorkloadIdentityProvider,
	federatedBindings []workloadidentityservice.FederatedIdentityBinding,
) []internal.TableFile {
	var tables []internal.TableFile

	// Pools table
	if len(pools) > 0 {
		poolsHeader := []string{
			"Project",
			"Pool ID",
			"Display Name",
			"State",
			"Disabled",
		}

		var poolsBody [][]string
		for _, pool := range pools {
			disabled := "No"
			if pool.Disabled {
				disabled = "Yes"
			}
			poolsBody = append(poolsBody, []string{
				m.GetProjectName(pool.ProjectID),
				pool.PoolID,
				pool.DisplayName,
				pool.State,
				disabled,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "identity-federation-pools",
			Header: poolsHeader,
			Body:   poolsBody,
		})
	}

	// Providers table
	if len(providers) > 0 {
		providersHeader := []string{
			"Project",
			"Pool",
			"Provider",
			"Type",
			"OIDC Issuer / AWS Account",
			"Trust Scope",
			"Access Condition",
		}

		var providersBody [][]string
		for _, p := range providers {
			issuerOrAccount := "-"
			if p.ProviderType == "AWS" {
				issuerOrAccount = p.AWSAccountID
			} else if p.ProviderType == "OIDC" {
				issuerOrAccount = p.OIDCIssuerURI
			}

			attrCond := "NONE"
			if p.AttributeCondition != "" {
				attrCond = p.AttributeCondition
			}

			trustScope := analyzeTrustScope(p)

			providersBody = append(providersBody, []string{
				m.GetProjectName(p.ProjectID),
				p.PoolID,
				p.ProviderID,
				p.ProviderType,
				issuerOrAccount,
				trustScope,
				attrCond,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "identity-federation-providers",
			Header: providersHeader,
			Body:   providersBody,
		})
	}

	// Federated bindings table
	if len(federatedBindings) > 0 {
		fedBindingsHeader := []string{
			"Project",
			"Pool",
			"GCP Service Account",
			"External Identity",
			"SA Attack Paths",
		}

		var fedBindingsBody [][]string
		for _, fb := range federatedBindings {
			attackPaths := gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, fb.GCPServiceAccount)

			fedBindingsBody = append(fedBindingsBody, []string{
				m.GetProjectName(fb.ProjectID),
				fb.PoolID,
				fb.GCPServiceAccount,
				fb.ExternalSubject,
				attackPaths,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "identity-federation-bindings",
			Header: fedBindingsHeader,
			Body:   fedBindingsBody,
		})
	}

	return tables
}

// analyzeTrustScope examines a provider's configuration and returns a human-readable
// summary of how broad the trust is. Flags overly permissive configurations.
func analyzeTrustScope(p workloadidentityservice.WorkloadIdentityProvider) string {
	// No attribute condition = any identity from this provider
	if p.AttributeCondition == "" {
		switch p.ProviderType {
		case "AWS":
			return "BROAD: Any role in AWS account " + p.AWSAccountID
		case "OIDC":
			return "BROAD: Any identity from issuer"
		case "SAML":
			return "BROAD: Any SAML assertion"
		default:
			return "BROAD: No condition set"
		}
	}

	cond := p.AttributeCondition
	var issues []string

	// Check for wildcard patterns in the condition
	if strings.Contains(cond, `"*"`) || strings.Contains(cond, `'*'`) {
		issues = append(issues, "wildcard (*) in condition")
	}

	// GitHub Actions specific analysis
	if p.ProviderType == "OIDC" && strings.Contains(p.OIDCIssuerURI, "github") {
		// Check if repo is scoped
		if !strings.Contains(cond, "repository") && !strings.Contains(cond, "repo") {
			issues = append(issues, "no repo restriction")
		}

		// Check if branch/ref is scoped
		if strings.Contains(cond, "repository") || strings.Contains(cond, "repo") {
			if !strings.Contains(cond, "ref") && !strings.Contains(cond, "branch") {
				issues = append(issues, "no branch restriction")
			}
		}

		// Check for org-wide trust (repo starts with org/)
		if strings.Contains(cond, ".startsWith(") {
			issues = append(issues, "prefix match (org-wide?)")
		}
	}

	// GitLab CI specific analysis
	if p.ProviderType == "OIDC" && strings.Contains(p.OIDCIssuerURI, "gitlab") {
		if !strings.Contains(cond, "project_path") && !strings.Contains(cond, "namespace_path") {
			issues = append(issues, "no project restriction")
		}
		if !strings.Contains(cond, "ref") && !strings.Contains(cond, "branch") {
			issues = append(issues, "no branch restriction")
		}
	}

	// AWS specific analysis
	if p.ProviderType == "AWS" {
		if !strings.Contains(cond, "arn") && !strings.Contains(cond, "account") {
			issues = append(issues, "no role/account restriction")
		}
	}

	if len(issues) > 0 {
		return "BROAD: " + strings.Join(issues, ", ")
	}

	return "Scoped"
}
