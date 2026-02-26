package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/streamanalytics/armstreamanalytics/v2"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzStreamAnalyticsCommand = &cobra.Command{
	Use:     "streamanalytics",
	Aliases: []string{"stream-analytics", "asa"},
	Short:   "Enumerate Azure Stream Analytics jobs",
	Long: `
Enumerate Azure Stream Analytics for a specific tenant:
  ./cloudfox az streamanalytics --tenant TENANT_ID

Enumerate Azure Stream Analytics for a specific subscription:
  ./cloudfox az streamanalytics --subscription SUBSCRIPTION_ID`,
	Run: ListStreamAnalytics,
}

// ------------------------------
// Module struct
// ------------------------------
type StreamAnalyticsModule struct {
	azinternal.BaseAzureModule

	Subscriptions []string
	SARows        [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type StreamAnalyticsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o StreamAnalyticsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o StreamAnalyticsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListStreamAnalytics(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_STREAMANALYTICS_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &StreamAnalyticsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		SARows:          [][]string{},
		LootMap: map[string]*internal.LootFile{
			"streamanalytics-commands":   {Name: "streamanalytics-commands", Contents: ""},
			"streamanalytics-queries":    {Name: "streamanalytics-queries", Contents: "# Azure Stream Analytics Queries\n\n"},
			"streamanalytics-identities": {Name: "streamanalytics-identities", Contents: "# Azure Stream Analytics Managed Identities\n\n"},
		},
	}

	module.PrintStreamAnalytics(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *StreamAnalyticsModule) PrintStreamAnalytics(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_STREAMANALYTICS_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_STREAMANALYTICS_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *StreamAnalyticsModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups using BaseAzureModule helper
	rgNames := m.ResolveResourceGroups(subID)
	if len(rgNames) == 0 {
		return
	}

	// Create Stream Analytics client
	saClient, err := azinternal.GetStreamAnalyticsClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Stream Analytics client for subscription %s: %v", subID, err), globals.AZ_STREAMANALYTICS_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Create Inputs client (for input enumeration)
	inputsClient, err := azinternal.GetStreamAnalyticsInputsClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Stream Analytics Inputs client for subscription %s: %v", subID, err), globals.AZ_STREAMANALYTICS_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Create Outputs client (for output enumeration)
	outputsClient, err := azinternal.GetStreamAnalyticsOutputsClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Stream Analytics Outputs client for subscription %s: %v", subID, err), globals.AZ_STREAMANALYTICS_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Process each resource group
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, rgName := range rgNames {
		wg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, saClient, inputsClient, outputsClient, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *StreamAnalyticsModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, saClient *armstreamanalytics.StreamingJobsClient, inputsClient *armstreamanalytics.InputsClient, outputsClient *armstreamanalytics.OutputsClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region using helper function
	region := azinternal.GetResourceGroupLocation(m.Session, subID, rgName)

	// List Stream Analytics jobs in resource group
	pager := saClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list Stream Analytics jobs in %s/%s: %v", subID, rgName, err), globals.AZ_STREAMANALYTICS_MODULE_NAME)
			}
			m.CommandCounter.Error++
			continue
		}

		for _, job := range page.Value {
			m.processJob(ctx, subID, subName, rgName, region, job, inputsClient, outputsClient, logger)
		}
	}
}

// ------------------------------
// Process single Stream Analytics job
// ------------------------------
func (m *StreamAnalyticsModule) processJob(ctx context.Context, subID, subName, rgName, region string, job *armstreamanalytics.StreamingJob, inputsClient *armstreamanalytics.InputsClient, outputsClient *armstreamanalytics.OutputsClient, logger internal.Logger) {
	if job == nil || job.Name == nil {
		return
	}

	jobName := *job.Name

	// Extract job properties
	jobState := "N/A"
	if job.Properties != nil && job.Properties.JobState != nil {
		jobState = *job.Properties.JobState
	}

	provisioningState := "N/A"
	if job.Properties != nil && job.Properties.ProvisioningState != nil {
		provisioningState = *job.Properties.ProvisioningState
	}

	jobType := "N/A"
	if job.Properties != nil && job.Properties.JobType != nil {
		jobType = string(*job.Properties.JobType)
	}

	createdDate := "N/A"
	if job.Properties != nil && job.Properties.CreatedDate != nil {
		createdDate = job.Properties.CreatedDate.Format("2006-01-02 15:04:05")
	}

	lastOutputEventTime := "N/A"
	if job.Properties != nil && job.Properties.LastOutputEventTime != nil {
		lastOutputEventTime = job.Properties.LastOutputEventTime.Format("2006-01-02 15:04:05")
	}

	// SKU information
	skuName := "N/A"
	if job.Properties != nil && job.Properties.SKU != nil && job.Properties.SKU.Name != nil {
		skuName = string(*job.Properties.SKU.Name)
	}

	// Streaming units (from transformation)
	streamingUnits := "N/A"
	query := "N/A"
	if job.Properties != nil && job.Properties.Transformation != nil {
		if job.Properties.Transformation.Properties != nil {
			if job.Properties.Transformation.Properties.StreamingUnits != nil {
				streamingUnits = fmt.Sprintf("%d", *job.Properties.Transformation.Properties.StreamingUnits)
			}
			if job.Properties.Transformation.Properties.Query != nil {
				query = *job.Properties.Transformation.Properties.Query
			}
		}
	}

	// Compatibility level
	compatibilityLevel := "N/A"
	if job.Properties != nil && job.Properties.CompatibilityLevel != nil {
		compatibilityLevel = string(*job.Properties.CompatibilityLevel)
	}

	// Managed identity
	systemAssignedID := "N/A"
	userAssignedIDs := "N/A"
	identityType := "None"
	if job.Identity != nil {
		if job.Identity.Type != nil {
			identityType = *job.Identity.Type
		}
		if job.Identity.PrincipalID != nil {
			systemAssignedID = *job.Identity.PrincipalID
		}
		// Extract user-assigned identities
		if job.Identity.UserAssignedIdentities != nil && len(job.Identity.UserAssignedIdentities) > 0 {
			uaIDs := []string{}
			for uaID := range job.Identity.UserAssignedIdentities {
				uaIDs = append(uaIDs, azinternal.ExtractResourceName(uaID))
			}
			if len(uaIDs) > 0 {
				userAssignedIDs = strings.Join(uaIDs, "\n")
			}
		}
	}

	// EntraID Centralized Auth - Stream Analytics uses AAD authentication by default
	entraIDAuth := "Enabled" // Stream Analytics always uses Azure AD for authentication

	// Count inputs
	inputCount := 0
	inputNames := []string{}
	if job.Properties != nil && job.Properties.Inputs != nil {
		inputCount = len(job.Properties.Inputs)
		for _, input := range job.Properties.Inputs {
			if input.Name != nil {
				inputNames = append(inputNames, *input.Name)
			}
		}
	} else {
		// Enumerate inputs separately if not in properties
		inputPager := inputsClient.NewListByStreamingJobPager(rgName, jobName, nil)
		for inputPager.More() {
			inputPage, err := inputPager.NextPage(ctx)
			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("Failed to list inputs for job %s: %v", jobName, err), globals.AZ_STREAMANALYTICS_MODULE_NAME)
				}
				break
			}
			for _, input := range inputPage.Value {
				inputCount++
				if input.Name != nil {
					inputNames = append(inputNames, *input.Name)
				}
			}
		}
	}

	inputNamesStr := strings.Join(inputNames, ", ")
	if inputNamesStr == "" {
		inputNamesStr = "N/A"
	}

	// Count outputs
	outputCount := 0
	outputNames := []string{}
	if job.Properties != nil && job.Properties.Outputs != nil {
		outputCount = len(job.Properties.Outputs)
		for _, output := range job.Properties.Outputs {
			if output.Name != nil {
				outputNames = append(outputNames, *output.Name)
			}
		}
	} else {
		// Enumerate outputs separately if not in properties
		outputPager := outputsClient.NewListByStreamingJobPager(rgName, jobName, nil)
		for outputPager.More() {
			outputPage, err := outputPager.NextPage(ctx)
			if err != nil {
				if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
					logger.ErrorM(fmt.Sprintf("Failed to list outputs for job %s: %v", jobName, err), globals.AZ_STREAMANALYTICS_MODULE_NAME)
				}
				break
			}
			for _, output := range outputPage.Value {
				outputCount++
				if output.Name != nil {
					outputNames = append(outputNames, *output.Name)
				}
			}
		}
	}

	outputNamesStr := strings.Join(outputNames, ", ")
	if outputNamesStr == "" {
		outputNamesStr = "N/A"
	}

	// Build row
	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		jobName,
		jobType,
		jobState,
		provisioningState,
		skuName,
		streamingUnits,
		compatibilityLevel,
		fmt.Sprintf("%d", inputCount),
		inputNamesStr,
		fmt.Sprintf("%d", outputCount),
		outputNamesStr,
		createdDate,
		lastOutputEventTime,
		entraIDAuth,
		identityType,
		systemAssignedID,
		userAssignedIDs,
	}

	m.mu.Lock()
	m.SARows = append(m.SARows, row)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Generate loot
	m.generateLoot(subID, subName, rgName, jobName, jobType, jobState, inputNamesStr, outputNamesStr, systemAssignedID, identityType, query)
}

// ------------------------------
// Generate loot
// ------------------------------
func (m *StreamAnalyticsModule) generateLoot(subID, subName, rgName, jobName, jobType, jobState, inputs, outputs, systemAssignedID, identityType, query string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Azure CLI commands
	m.LootMap["streamanalytics-commands"].Contents += fmt.Sprintf("# Stream Analytics Job: %s (Resource Group: %s)\n", jobName, rgName)
	m.LootMap["streamanalytics-commands"].Contents += fmt.Sprintf("az account set --subscription %s\n", subID)
	m.LootMap["streamanalytics-commands"].Contents += fmt.Sprintf("az stream-analytics job show --name %s --resource-group %s\n", jobName, rgName)
	m.LootMap["streamanalytics-commands"].Contents += fmt.Sprintf("az stream-analytics input list --job-name %s --resource-group %s -o table\n", jobName, rgName)
	m.LootMap["streamanalytics-commands"].Contents += fmt.Sprintf("az stream-analytics output list --job-name %s --resource-group %s -o table\n", jobName, rgName)
	m.LootMap["streamanalytics-commands"].Contents += fmt.Sprintf("az stream-analytics transformation show --job-name %s --resource-group %s\n\n", jobName, rgName)

	// Queries for review
	if query != "N/A" && query != "" {
		m.LootMap["streamanalytics-queries"].Contents += fmt.Sprintf("# Job: %s/%s\n", rgName, jobName)
		m.LootMap["streamanalytics-queries"].Contents += fmt.Sprintf("Subscription: %s\n", subName)
		m.LootMap["streamanalytics-queries"].Contents += fmt.Sprintf("Job Type: %s\n", jobType)
		m.LootMap["streamanalytics-queries"].Contents += fmt.Sprintf("Job State: %s\n", jobState)
		m.LootMap["streamanalytics-queries"].Contents += fmt.Sprintf("Inputs: %s\n", inputs)
		m.LootMap["streamanalytics-queries"].Contents += fmt.Sprintf("Outputs: %s\n", outputs)
		m.LootMap["streamanalytics-queries"].Contents += "\nQuery:\n"
		m.LootMap["streamanalytics-queries"].Contents += "```sql\n"
		m.LootMap["streamanalytics-queries"].Contents += query + "\n"
		m.LootMap["streamanalytics-queries"].Contents += "```\n\n"
		m.LootMap["streamanalytics-queries"].Contents += "---\n\n"
	}

	// Managed identities for identity tracking
	if systemAssignedID != "N/A" && identityType != "None" {
		m.LootMap["streamanalytics-identities"].Contents += fmt.Sprintf("# Job: %s/%s\n", rgName, jobName)
		m.LootMap["streamanalytics-identities"].Contents += fmt.Sprintf("Subscription: %s\n", subName)
		m.LootMap["streamanalytics-identities"].Contents += fmt.Sprintf("Identity Type: %s\n", identityType)
		if systemAssignedID != "N/A" {
			m.LootMap["streamanalytics-identities"].Contents += fmt.Sprintf("System Assigned Identity: %s\n", systemAssignedID)
		}
		m.LootMap["streamanalytics-identities"].Contents += "\n"
	}
}

// ------------------------------
// Write output
// ------------------------------
func (m *StreamAnalyticsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.SARows) == 0 {
		logger.InfoM("No Azure Stream Analytics jobs found", globals.AZ_STREAMANALYTICS_MODULE_NAME)
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
		"Job Name",
		"Job Type",
		"Job State",
		"Provisioning State",
		"SKU",
		"Streaming Units",
		"Compatibility Level",
		"Input Count",
		"Inputs",
		"Output Count",
		"Outputs",
		"Created Date",
		"Last Output Event",
		"EntraID Centralized Auth",
		"Identity Type",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.SARows, headers,
			"streamanalytics", globals.AZ_STREAMANALYTICS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.SARows, headers,
			"streamanalytics", globals.AZ_STREAMANALYTICS_MODULE_NAME,
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
	output := StreamAnalyticsOutput{
		Table: []internal.TableFile{{
			Name:   "streamanalytics",
			Header: headers,
			Body:   m.SARows,
		}},
		Loot: loot,
	}

	// Determine output scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output using HandleOutputSmart
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_STREAMANALYTICS_MODULE_NAME)
		return
	}

	// Print summary
	logger.InfoM(fmt.Sprintf("Found %d Azure Stream Analytics jobs across %d subscriptions", len(m.SARows), len(m.Subscriptions)), globals.AZ_STREAMANALYTICS_MODULE_NAME)
}
