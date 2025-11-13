package commands

import (
	"context"
	"fmt"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzLoadTestingCommand = &cobra.Command{
	Use:     "load-testing",
	Aliases: []string{"loadtest", "lt"},
	Short:   "Enumerate Azure Load Testing resources, tests, and managed identities",
	Long: `
Enumerate Azure Load Testing resources for a specific tenant:
  ./cloudfox az load-testing --tenant TENANT_ID

Enumerate Azure Load Testing resources for a specific subscription:
  ./cloudfox az load-testing --subscription SUBSCRIPTION_ID`,
	Run: ListLoadTesting,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type LoadTestingModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	Subscriptions   []string
	LoadTestingRows [][]string
	LootMap         map[string]*internal.LootFile
	mu              sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type LoadTestingOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LoadTestingOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LoadTestingOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListLoadTesting(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_LOAD_TESTING_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &LoadTestingModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		LoadTestingRows: [][]string{},
		LootMap: map[string]*internal.LootFile{
			"load-testing-commands":          {Name: "load-testing-commands", Contents: ""},
			"load-testing-tests":             {Name: "load-testing-tests", Contents: ""},
			"load-testing-identities":        {Name: "load-testing-identities", Contents: ""},
			"load-testing-extraction-jmx":    {Name: "load-testing-extraction-jmx", Contents: ""},
			"load-testing-extraction-locust": {Name: "load-testing-extraction-locust", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintLoadTesting(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *LoadTestingModule) PrintLoadTesting(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_LOAD_TESTING_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_LOAD_TESTING_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_LOAD_TESTING_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating load testing resources for %d subscription(s)", len(m.Subscriptions)), globals.AZ_LOAD_TESTING_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_LOAD_TESTING_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *LoadTestingModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Get all Load Testing resources
	loadTestResources, err := azinternal.GetLoadTestingResources(m.Session, subID, resourceGroups)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Load Testing resources for subscription %s: %v", subID, err), globals.AZ_LOAD_TESTING_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Process each Load Testing resource concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit to 5 concurrent resources

	for _, resource := range loadTestResources {
		wg.Add(1)
		go m.processLoadTestResource(ctx, subID, subName, resource, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single Load Testing resource
// ------------------------------
func (m *LoadTestingModule) processLoadTestResource(ctx context.Context, subID, subName string, resource azinternal.LoadTestResource, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get tests for this resource
	tests, _ := azinternal.GetLoadTestsForResource(m.Session, resource.DataPlaneURI)

	// Count Key Vault references
	secretCount := 0
	certCount := 0
	for _, test := range tests {
		secretCount += len(test.Secrets)
		if test.Certificate != nil {
			certCount++
		}
	}

	// Thread-safe append - main resource row
	m.mu.Lock()
	m.LoadTestingRows = append(m.LoadTestingRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		resource.ResourceGroup,
		resource.Location,
		resource.Name,
		"LoadTestResource",
		resource.IdentityType,
		fmt.Sprintf("%d", len(tests)),
		fmt.Sprintf("%d", secretCount),
		fmt.Sprintf("%d", certCount),
		resource.DataPlaneURI,
		resource.PrincipalID,
		resource.UserAssignedIDs,
	})

	// Add per-test rows
	for _, test := range tests {
		m.LoadTestingRows = append(m.LoadTestingRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			resource.ResourceGroup,
			resource.Location,
			resource.Name,
			fmt.Sprintf("Test: %s", test.DisplayName),
			test.KeyVaultReferenceIdentity,
			test.Kind,
			fmt.Sprintf("%d", len(test.Secrets)),
			fmt.Sprintf("%d vars", len(test.EnvironmentVariables)),
			test.TestScriptFileName,
			"",
			"",
		})
	}
	m.mu.Unlock()

	// Generate loot
	m.generateLoot(subID, subName, resource, tests)
}

// ------------------------------
// Generate loot files
// ------------------------------
func (m *LoadTestingModule) generateLoot(subID, subName string, resource azinternal.LoadTestResource, tests []azinternal.LoadTest) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Commands loot
	if lf, ok := m.LootMap["load-testing-commands"]; ok {
		lf.Contents += fmt.Sprintf("## Load Testing Resource: %s (Resource Group: %s)\n", resource.Name, resource.ResourceGroup)
		lf.Contents += fmt.Sprintf("az account set --subscription %s\n", subID)
		lf.Contents += fmt.Sprintf("# List Load Testing resources\n")
		lf.Contents += fmt.Sprintf("az load test list --resource-group %s -o table\n\n", resource.ResourceGroup)
		lf.Contents += fmt.Sprintf("# Show Load Testing resource details\n")
		lf.Contents += fmt.Sprintf("az load test show --name %s --resource-group %s\n\n", resource.Name, resource.ResourceGroup)
		lf.Contents += fmt.Sprintf("# List tests (requires data plane access)\n")
		lf.Contents += fmt.Sprintf("# Data Plane URI: %s\n", resource.DataPlaneURI)
		lf.Contents += fmt.Sprintf("# Get access token: az account get-access-token --resource https://cnt-prod.loadtesting.azure.com/\n\n")
	}

	// Tests loot
	if lf, ok := m.LootMap["load-testing-tests"]; ok && len(tests) > 0 {
		lf.Contents += fmt.Sprintf("\n## Load Testing Resource: %s\n", resource.Name)
		lf.Contents += fmt.Sprintf("# Resource Group: %s, Subscription: %s (%s)\n", resource.ResourceGroup, subName, subID)
		lf.Contents += fmt.Sprintf("# Data Plane URI: %s\n\n", resource.DataPlaneURI)

		for _, test := range tests {
			lf.Contents += fmt.Sprintf("### Test: %s (ID: %s)\n", test.DisplayName, test.TestID)
			lf.Contents += fmt.Sprintf("- **Type**: %s\n", test.Kind)
			lf.Contents += fmt.Sprintf("- **Description**: %s\n", test.Description)
			lf.Contents += fmt.Sprintf("- **Script File**: %s\n", test.TestScriptFileName)
			lf.Contents += fmt.Sprintf("- **KeyVault Reference Identity**: %s\n", test.KeyVaultReferenceIdentity)

			if len(test.Secrets) > 0 {
				lf.Contents += fmt.Sprintf("- **Secrets** (%d):\n", len(test.Secrets))
				for name, secret := range test.Secrets {
					lf.Contents += fmt.Sprintf("  - %s: %s\n", name, secret.URL)
				}
			}

			if test.Certificate != nil {
				lf.Contents += fmt.Sprintf("- **Certificate**: %s -> %s\n", test.Certificate.Name, test.Certificate.URL)
			}

			if len(test.EnvironmentVariables) > 0 {
				lf.Contents += fmt.Sprintf("- **Environment Variables** (%d):\n", len(test.EnvironmentVariables))
				for name, value := range test.EnvironmentVariables {
					lf.Contents += fmt.Sprintf("  - %s=%s\n", name, value)
				}
			}
			lf.Contents += "\n"
		}
	}

	// Identities loot
	if lf, ok := m.LootMap["load-testing-identities"]; ok {
		if resource.IdentityType != "" && resource.IdentityType != "None" {
			lf.Contents += fmt.Sprintf("\n## Load Testing Resource: %s\n", resource.Name)
			lf.Contents += fmt.Sprintf("# Resource Group: %s, Subscription: %s (%s)\n", resource.ResourceGroup, subName, subID)
			lf.Contents += fmt.Sprintf("- **Identity Type**: %s\n", resource.IdentityType)

			if resource.SystemAssigned {
				lf.Contents += "- **System-Assigned Identity**: Enabled\n"
				lf.Contents += fmt.Sprintf("  - Principal ID: %s\n", resource.PrincipalID)
			}

			if resource.UserAssignedIDs != "" && resource.UserAssignedIDs != "N/A" {
				lf.Contents += fmt.Sprintf("- **User-Assigned Identities**: %s\n", resource.UserAssignedIDs)
			}
			lf.Contents += "\n"
		}
	}

	// Generate extraction templates if resource has managed identity
	if resource.IdentityType != "" && resource.IdentityType != "None" {
		// JMX template
		if lf, ok := m.LootMap["load-testing-extraction-jmx"]; ok {
			template := azinternal.GenerateLoadTestExtractionTemplate(resource, tests, "JMX")
			lf.Contents += template
		}

		// Locust template
		if lf, ok := m.LootMap["load-testing-extraction-locust"]; ok {
			template := azinternal.GenerateLoadTestExtractionTemplate(resource, tests, "Locust")
			lf.Contents += template
		}
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *LoadTestingModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.LoadTestingRows) == 0 {
		logger.InfoM("No Load Testing resources found", globals.AZ_LOAD_TESTING_MODULE_NAME)
		return
	}

	// Build headers
	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Resource Name",
		"Type",
		"Identity Type / KV Ref Identity",
		"Test Count / Test Kind",
		"Secret Count",
		"Cert Count / Env Vars",
		"Data Plane URI / Script File",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant (multi-tenant takes precedence)
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.LoadTestingRows, headers,
			"load-testing", globals.AZ_LOAD_TESTING_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Otherwise, check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.LoadTestingRows, headers,
			"load-testing", globals.AZ_LOAD_TESTING_MODULE_NAME,
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
	output := LoadTestingOutput{
		Table: []internal.TableFile{{
			Name:   "load-testing",
			Header: headers,
			Body:   m.LoadTestingRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_LOAD_TESTING_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Load Testing resource(s) across %d subscription(s)", len(m.LoadTestingRows), len(m.Subscriptions)), globals.AZ_LOAD_TESTING_MODULE_NAME)
}
