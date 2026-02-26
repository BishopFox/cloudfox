package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzAcrCommand = &cobra.Command{
	Use:     "acr",
	Aliases: []string{"acrs"},
	Short:   "Enumerate Azure Container Registries (ACR), repositories, and tags",
	Long: `
Enumerate ACR for a specific tenant:
  ./cloudfox az acr --tenant TENANT_ID

Enumerate ACR for a specific subscription:
  ./cloudfox az acr --subscription SUBSCRIPTION_ID`,
	Run: ListAcr,
}

// ------------------------------
// Module struct (AWS pattern with embedded BaseAzureModule)
// ------------------------------
type AcrModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	AcrRows       [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

type AcrInfo struct {
	TenantName       string // NEW: for multi-tenant support
	TenantID         string // NEW: for multi-tenant support
	SubscriptionID   string
	SubscriptionName string
	ResourceGroup    string
	Region           string
	RegistryName     string
	Repository       string
	Tag              string
	Digest           string
	AdminEnabled     string
	AdminUsername    string
	SystemAssignedID string
	UserAssignedIDs  string
}

// ------------------------------
// Output struct
// ------------------------------
type AcrOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o AcrOutput) TableFiles() []internal.TableFile { return o.Table }
func (o AcrOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListAcr(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_ACR_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &AcrModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		AcrRows:         [][]string{},
		LootMap: map[string]*internal.LootFile{
			"acr-commands":           {Name: "acr-commands", Contents: ""},
			"acr-managed-identities": {Name: "acr-managed-identities", Contents: ""},
			"acr-task-templates":     {Name: "acr-task-templates", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintAcr(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *AcrModule) PrintAcr(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_ACR_MODULE_NAME)

		// Process each tenant independently
		for _, tenantCtx := range m.Tenants {
			// Temporarily set module tenant context for row creation
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_ACR_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_ACR_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating ACR for %d subscription(s)", len(m.Subscriptions)), globals.AZ_ACR_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_ACR_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *AcrModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get token for ACR client
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get ARM token: %v", err), globals.AZ_ACR_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}
	cred := &azinternal.StaticTokenCredential{Token: token}

	regClient, err := armcontainerregistry.NewRegistriesClient(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create registries client: %v", err), globals.AZ_ACR_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Process resource groups concurrently for better performance
	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10) // Limit to 10 concurrent RGs

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, regClient, cred, &rgWg, rgSemaphore, logger)
	}

	rgWg.Wait()

	// ==================== ACR MANAGED IDENTITY TOKEN EXTRACTION ====================
	// Enumerate ACRs with managed identities (Invoke-AzACRTokenGenerator functionality)
	m.enumerateACRManagedIdentities(ctx, subID, subName, resourceGroups, logger)
}

// ------------------------------
// Process single resource group (extracted for RG-level concurrency)
// ------------------------------
func (m *AcrModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, regClient *armcontainerregistry.RegistriesClient, cred *azinternal.StaticTokenCredential, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region using helper function
	region := azinternal.GetResourceGroupLocation(m.Session, subID, rgName)

	// List registries
	pager := regClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to get registries in RG %s: %v", rgName, err), globals.AZ_ACR_MODULE_NAME)
			m.CommandCounter.Error++
			continue
		}

		for _, reg := range page.Value {
			m.processRegistry(ctx, reg, subID, subName, rgName, region, cred, logger)
		}
	}
}

// ------------------------------
// Process single registry
// ------------------------------
func (m *AcrModule) processRegistry(ctx context.Context, reg *armcontainerregistry.Registry, subID, subName, rgName, region string, cred *azinternal.StaticTokenCredential, logger internal.Logger) {
	regName := azinternal.SafeStringPtr(reg.Name)
	loginServer := "N/A"
	adminEnabled := "No"
	adminUsername := "N/A"

	if reg.Properties != nil {
		if reg.Properties.LoginServer != nil {
			loginServer = *reg.Properties.LoginServer
			if loginServer != "" && !strings.HasPrefix(loginServer, "https://") {
				loginServer = "https://" + loginServer
			}
		}
		if reg.Properties.AdminUserEnabled != nil && *reg.Properties.AdminUserEnabled {
			adminEnabled = "Yes"
			adminUsername = "admin"
		}
	}

	// Extract managed identity information
	var systemAssignedIDs []string
	var userAssignedIDs []string

	if reg.Identity != nil {
		// System-assigned identity
		if reg.Identity.PrincipalID != nil {
			principalID := *reg.Identity.PrincipalID
			systemAssignedIDs = append(systemAssignedIDs, principalID)
		}

		// User-assigned identities
		if reg.Identity.UserAssignedIdentities != nil {
			for uaID := range reg.Identity.UserAssignedIdentities {
				userAssignedIDs = append(userAssignedIDs, uaID)
			}
		}
	}

	// Format identity fields
	systemIDsStr := "N/A"
	if len(systemAssignedIDs) > 0 {
		systemIDsStr = strings.Join(systemAssignedIDs, ", ")
	}

	userIDsStr := "N/A"
	if len(userAssignedIDs) > 0 {
		userIDsStr = strings.Join(userAssignedIDs, ", ")
	}

	// Cannot enumerate if no login server
	if loginServer == "" || loginServer == "N/A" {
		m.addAcrRow(AcrInfo{
			TenantName:       m.TenantName, // NEW: for multi-tenant support
			TenantID:         m.TenantID,   // NEW: for multi-tenant support
			SubscriptionID:   subID,
			SubscriptionName: subName,
			ResourceGroup:    rgName,
			Region:           region,
			RegistryName:     regName,
			Repository:       "UNKNOWN / INTERNAL RESOURCE",
			Tag:              "UNKNOWN / INTERNAL RESOURCE",
			Digest:           "UNKNOWN / INTERNAL RESOURCE",
			AdminEnabled:     adminEnabled,
			AdminUsername:    adminUsername,
			SystemAssignedID: systemIDsStr,
			UserAssignedIDs:  userIDsStr,
		})
		m.addFallbackLoot(subID, regName, "")
		return
	}

	// Create ACR client
	acrClient, err := azcontainerregistry.NewClient(loginServer, cred, nil)
	if err != nil {
		m.addAcrRow(AcrInfo{
			TenantName:       m.TenantName, // NEW: for multi-tenant support
			TenantID:         m.TenantID,   // NEW: for multi-tenant support
			SubscriptionID:   subID,
			SubscriptionName: subName,
			ResourceGroup:    rgName,
			Region:           region,
			RegistryName:     regName,
			Repository:       "UNKNOWN / INTERNAL RESOURCE",
			Tag:              "UNKNOWN / INTERNAL RESOURCE",
			Digest:           "UNKNOWN / INTERNAL RESOURCE",
			AdminEnabled:     adminEnabled,
			AdminUsername:    adminUsername,
			SystemAssignedID: systemIDsStr,
			UserAssignedIDs:  userIDsStr,
		})
		m.addFallbackLoot(subID, regName, "")
		return
	}

	// Enumerate repositories
	repoFound := false
	repoPager := acrClient.NewListRepositoriesPager(nil)
	for repoPager.More() {
		repoPage, err := repoPager.NextPage(ctx)
		if err != nil {
			m.addAcrRow(AcrInfo{
				TenantName:       m.TenantName, // NEW: for multi-tenant support
				TenantID:         m.TenantID,   // NEW: for multi-tenant support
				SubscriptionID:   subID,
				SubscriptionName: subName,
				ResourceGroup:    rgName,
				Region:           region,
				RegistryName:     regName,
				Repository:       "UNKNOWN / INTERNAL RESOURCE",
				Tag:              "UNKNOWN / INTERNAL RESOURCE",
				Digest:           "UNKNOWN / INTERNAL RESOURCE",
				AdminEnabled:     adminEnabled,
				AdminUsername:    adminUsername,
				SystemAssignedID: systemIDsStr,
				UserAssignedIDs:  userIDsStr,
			})
			m.addFallbackLoot(subID, regName, "")
			break
		}

		for _, repoPtr := range repoPage.Names {
			repo := safeResourceName(repoPtr)
			cleanRepo := cleanRepoName(repo)

			// Enumerate tags
			tagPager := acrClient.NewListTagsPager(repo, nil)
			for tagPager.More() {
				tagPage, err := tagPager.NextPage(ctx)
				if err != nil {
					m.addAcrRow(AcrInfo{
						TenantName:       m.TenantName, // NEW: for multi-tenant support
						TenantID:         m.TenantID,   // NEW: for multi-tenant support
						SubscriptionID:   subID,
						SubscriptionName: subName,
						ResourceGroup:    rgName,
						Region:           region,
						RegistryName:     regName,
						Repository:       repo,
						Tag:              "UNKNOWN / INTERNAL RESOURCE",
						Digest:           "UNKNOWN / INTERNAL RESOURCE",
						AdminEnabled:     adminEnabled,
						AdminUsername:    adminUsername,
						SystemAssignedID: systemIDsStr,
						UserAssignedIDs:  userIDsStr,
					})
					m.addFallbackLoot(subID, regName, repo)
					break
				}

				for _, tag := range tagPage.Tags {
					tagName := safeResourceName(tag.Name)
					digest := safeResourceName(tag.Digest)

					m.addAcrRow(AcrInfo{
						TenantName:       m.TenantName, // NEW: for multi-tenant support
						TenantID:         m.TenantID,   // NEW: for multi-tenant support
						SubscriptionID:   subID,
						SubscriptionName: subName,
						ResourceGroup:    rgName,
						Region:           region,
						RegistryName:     regName,
						Repository:       repo,
						Tag:              tagName,
						Digest:           digest,
						AdminEnabled:     adminEnabled,
						AdminUsername:    adminUsername,
						SystemAssignedID: systemIDsStr,
						UserAssignedIDs:  userIDsStr,
					})

					m.addDockerLoot(subID, regName, repo, tagName, cleanRepo)
					repoFound = true
				}
			}
		}
	}

	// If no repositories found
	if !repoFound {
		m.addAcrRow(AcrInfo{
			TenantName:       m.TenantName, // NEW: for multi-tenant support
			TenantID:         m.TenantID,   // NEW: for multi-tenant support
			SubscriptionID:   subID,
			SubscriptionName: subName,
			ResourceGroup:    rgName,
			Region:           region,
			RegistryName:     regName,
			Repository:       "UNKNOWN / INTERNAL RESOURCE",
			Tag:              "UNKNOWN / INTERNAL RESOURCE",
			Digest:           "UNKNOWN / INTERNAL RESOURCE",
			AdminEnabled:     adminEnabled,
			AdminUsername:    adminUsername,
			SystemAssignedID: systemIDsStr,
			UserAssignedIDs:  userIDsStr,
		})
	}
}

// ------------------------------
// Add ACR row (thread-safe)
// ------------------------------
func (m *AcrModule) addAcrRow(info AcrInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.AcrRows = append(m.AcrRows, []string{
		info.TenantName, // NEW: for multi-tenant support
		info.TenantID,   // NEW: for multi-tenant support
		info.SubscriptionID,
		info.SubscriptionName,
		info.ResourceGroup,
		info.Region,
		info.RegistryName,
		info.Repository,
		info.Tag,
		info.Digest,
		info.AdminEnabled,
		info.AdminUsername,
		info.SystemAssignedID,
		info.UserAssignedIDs,
	})
}

// ------------------------------
// Add Docker loot (thread-safe)
// ------------------------------
func (m *AcrModule) addDockerLoot(subID, regName, repo, tagName, cleanRepo string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	lf := m.LootMap["acr-commands"]
	lf.Contents += fmt.Sprintf(
		"## Docker Authentication for %s/%s:%s\n"+
			"az account set --subscription %s\n"+
			"# Login to ACR and pull image\n"+
			"az acr login --name %s --expose-token --output tsv --query accessToken | docker login %s.azurecr.io --username 00000000-0000-0000-0000-000000000000 --password-stdin\n"+
			"\n"+
			"# Pull image\n"+
			"docker pull %s.azurecr.io/%s:%s\n"+
			"\n"+
			"# Save image to tar file\n"+
			"docker save %s.azurecr.io/%s:%s -o %s_%s_%s.tar\n"+
			"\n"+
			"# Run interactive container\n"+
			"docker run -it --rm %s.azurecr.io/%s:%s /bin/sh\n\n",
		regName, repo, tagName,
		subID,
		regName,
		regName,
		regName, repo, tagName,
		regName, repo, tagName, regName, cleanRepo, tagName,
		regName, repo, tagName,
	)
}

// ------------------------------
// Add fallback loot (thread-safe)
// ------------------------------
func (m *AcrModule) addFallbackLoot(subID, regName, repoName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if regName == "" {
		regName = "UNKNOWN"
	}
	if repoName == "" {
		repoName = "UNKNOWN"
	}

	lf := m.LootMap["acr-commands"]
	if regName != "UNKNOWN" && repoName != "UNKNOWN" {
		lf.Contents += fmt.Sprintf(
			"## No image tags found for %s/%s\n"+
				"az account set --subscription %s\n"+
				"az acr repository show-tags --name %s --repository %s -o tsv\n"+
				"az acr login --name %s\n"+
				"docker pull %s.azurecr.io/%s:<TAG>\n\n",
			regName, repoName,
			subID,
			regName, repoName,
			regName,
			regName, repoName,
		)
	} else if regName != "UNKNOWN" {
		lf.Contents += fmt.Sprintf(
			"## No repositories found for registry: %s\n"+
				"az account set --subscription %s\n"+
				"az acr repository list --name %s -o tsv\n"+
				"az acr login --name %s\n\n",
			regName,
			subID,
			regName,
			regName,
		)
	}
}

// ------------------------------
// Enumerate ACR Managed Identities (Invoke-AzACRTokenGenerator)
// ------------------------------
func (m *AcrModule) enumerateACRManagedIdentities(ctx context.Context, subID, subName string, resourceGroups []string, logger internal.Logger) {
	// Get all ACRs with managed identities
	acrIdentities, err := azinternal.GetACRsWithManagedIdentities(m.Session, subID, resourceGroups)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to enumerate ACR managed identities for subscription %s: %v", subID, err), globals.AZ_ACR_MODULE_NAME)
		}
		return
	}

	if len(acrIdentities) == 0 {
		return
	}

	// Generate loot content
	m.mu.Lock()
	defer m.mu.Unlock()

	identitiesLoot := m.LootMap["acr-managed-identities"]
	templatesLoot := m.LootMap["acr-task-templates"]

	identitiesLoot.Contents += fmt.Sprintf("\n## Subscription: %s (%s)\n\n", subName, subID)
	templatesLoot.Contents += fmt.Sprintf("\n## Subscription: %s (%s)\n\n", subName, subID)

	// Process each ACR with managed identity
	for _, acr := range acrIdentities {
		// Document the identity
		identitiesLoot.Contents += fmt.Sprintf("### ACR: %s (Resource Group: %s)\n", acr.RegistryName, acr.ResourceGroup)
		identitiesLoot.Contents += fmt.Sprintf("- **Location**: %s\n", acr.Location)
		identitiesLoot.Contents += fmt.Sprintf("- **Identity Type**: %s\n", acr.IdentityType)

		if acr.SystemAssigned {
			identitiesLoot.Contents += "- **System-Assigned Identity**: Enabled\n"
		}

		if len(acr.UserAssignedIDs) > 0 {
			identitiesLoot.Contents += fmt.Sprintf("- **User-Assigned Identities**: %d\n", len(acr.UserAssignedIDs))
			for _, uami := range acr.UserAssignedIDs {
				identitiesLoot.Contents += fmt.Sprintf("  - Resource ID: %s\n", uami.ResourceID)
				identitiesLoot.Contents += fmt.Sprintf("    Client ID: %s\n", uami.ClientID)
				identitiesLoot.Contents += fmt.Sprintf("    Principal ID: %s\n", uami.PrincipalID)
			}
		}
		identitiesLoot.Contents += "\n"

		// Generate task templates for token extraction
		tokenScopes := []string{
			"https://management.azure.com/",
			"https://graph.microsoft.com/",
			"https://vault.azure.net/",
		}

		for _, scope := range tokenScopes {
			templates := azinternal.GenerateACRTaskTemplates(acr, scope)

			for _, template := range templates {
				templatesLoot.Contents += fmt.Sprintf("### ACR: %s - %s Identity - Scope: %s\n\n", template.RegistryName, template.IdentityType, template.TokenScope)
				templatesLoot.Contents += "**Step 1: Create ACR Task**\n\n"
				templatesLoot.Contents += fmt.Sprintf("```bash\n# Create task: %s\n", template.TaskName)
				templatesLoot.Contents += fmt.Sprintf("curl -X PUT \\\n")
				templatesLoot.Contents += fmt.Sprintf("  \"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s/tasks/%s?api-version=2019-04-01\" \\\n",
					subID, acr.ResourceGroup, template.RegistryName, template.TaskName)
				templatesLoot.Contents += "  -H \"Authorization: Bearer ${ACCESS_TOKEN}\" \\\n"
				templatesLoot.Contents += "  -H \"Content-Type: application/json\" \\\n"
				templatesLoot.Contents += "  -d '\n"
				templatesLoot.Contents += template.TaskJSON + "\n'\n```\n\n"

				templatesLoot.Contents += "**Step 2: Execute ACR Task**\n\n"
				templatesLoot.Contents += "```bash\n# Run the task\n"
				templatesLoot.Contents += fmt.Sprintf("curl -X POST \\\n")
				templatesLoot.Contents += fmt.Sprintf("  \"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s/scheduleRun?api-version=2019-04-01\" \\\n",
					subID, acr.ResourceGroup, template.RegistryName)
				templatesLoot.Contents += "  -H \"Authorization: Bearer ${ACCESS_TOKEN}\" \\\n"
				templatesLoot.Contents += "  -H \"Content-Type: application/json\" \\\n"
				templatesLoot.Contents += "  -d '\n"
				templatesLoot.Contents += template.RunJSON + "\n'\n```\n\n"

				templatesLoot.Contents += "**Step 3: Get Task Logs**\n\n"
				templatesLoot.Contents += "```bash\n# Get log SAS URL (replace {runId} with the run ID from step 2 response)\n"
				templatesLoot.Contents += fmt.Sprintf("curl -X POST \\\n")
				templatesLoot.Contents += fmt.Sprintf("  \"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s/runs/{runId}/listLogSasUrl?api-version=2019-04-01\" \\\n",
					subID, acr.ResourceGroup, template.RegistryName)
				templatesLoot.Contents += "  -H \"Authorization: Bearer ${ACCESS_TOKEN}\" \\\n"
				templatesLoot.Contents += "  -H \"Content-Type: application/json\"\n\n"
				templatesLoot.Contents += "# Download the log from the SAS URL returned above\n"
				templatesLoot.Contents += "# The log will contain the access token JSON\n```\n\n"

				templatesLoot.Contents += "**Step 4: Delete Task (cleanup)**\n\n"
				templatesLoot.Contents += "```bash\n# Delete the task\n"
				templatesLoot.Contents += fmt.Sprintf("curl -X DELETE \\\n")
				templatesLoot.Contents += fmt.Sprintf("  \"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s/tasks/%s?api-version=2019-04-01\" \\\n",
					subID, acr.ResourceGroup, template.RegistryName, template.TaskName)
				templatesLoot.Contents += "  -H \"Authorization: Bearer ${ACCESS_TOKEN}\"\n```\n\n"

				// Add Azure CLI alternative
				templatesLoot.Contents += "**Alternative: Using Azure CLI**\n\n"
				templatesLoot.Contents += "```bash\n"
				templatesLoot.Contents += fmt.Sprintf("# Set subscription context\n")
				templatesLoot.Contents += fmt.Sprintf("az account set --subscription %s\n\n", subID)
				templatesLoot.Contents += fmt.Sprintf("# The ACR task approach requires manual REST API calls\n")
				templatesLoot.Contents += fmt.Sprintf("# See the curl commands above for the complete workflow\n")
				templatesLoot.Contents += "```\n\n"
				templatesLoot.Contents += "---\n\n"
			}
		}
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *AcrModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.AcrRows) == 0 {
		logger.InfoM("No ACR registries found", globals.AZ_ACR_MODULE_NAME)
		return
	}

	// Build headers
	headers := []string{
		"Tenant Name", // NEW: for multi-tenant support
		"Tenant ID",   // NEW: for multi-tenant support
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"ACR Name",
		"Repository",
		"Tag",
		"Digest",
		"Admin User Enabled",
		"Admin Username",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant (multi-tenant mode)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		// Split into separate tenant directories
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.AcrRows,
			headers,
			"acr",
			globals.AZ_ACR_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.AcrRows, headers,
			"acr", globals.AZ_ACR_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// Create output
	output := AcrOutput{
		Table: []internal.TableFile{{
			Name:   "acr",
			Header: headers,
			Body:   m.AcrRows,
		}},
		Loot: loot,
	}

	// Determine output scope (single subscription vs tenant-wide consolidation)
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output using HandleOutputSmart (automatic streaming for large datasets)
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_ACR_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d ACR entries across %d subscription(s)", len(m.AcrRows), len(m.Subscriptions)), globals.AZ_ACR_MODULE_NAME)
}

// ------------------------------
// Helper functions
// ------------------------------
func safeResourceName(name *string) string {
	if name == nil || *name == "" {
		return "UNKNOWN / INTERNAL RESOURCE"
	}
	return *name
}

func cleanRepoName(repo string) string {
	return strings.ReplaceAll(repo, "/", "_")
}
