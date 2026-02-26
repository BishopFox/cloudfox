package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/signalr/armsignalr"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzSignalRCommand = &cobra.Command{
	Use:     "signalr",
	Aliases: []string{"signal"},
	Short:   "Enumerate Azure SignalR Service instances",
	Long: `
Enumerate Azure SignalR for a specific tenant:
  ./cloudfox az signalr --tenant TENANT_ID

Enumerate Azure SignalR for a specific subscription:
  ./cloudfox az signalr --subscription SUBSCRIPTION_ID`,
	Run: ListSignalR,
}

// ------------------------------
// Module struct
// ------------------------------
type SignalRModule struct {
	azinternal.BaseAzureModule

	Subscriptions []string
	SignalRRows   [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type SignalROutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o SignalROutput) TableFiles() []internal.TableFile { return o.Table }
func (o SignalROutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListSignalR(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_SIGNALR_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &SignalRModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		SignalRRows:     [][]string{},
		LootMap: map[string]*internal.LootFile{
			"signalr-commands": {Name: "signalr-commands", Contents: ""},
		},
	}

	module.PrintSignalR(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *SignalRModule) PrintSignalR(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_SIGNALR_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_SIGNALR_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *SignalRModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups using BaseAzureModule helper
	rgNames := m.ResolveResourceGroups(subID)
	if len(rgNames) == 0 {
		return
	}

	// Create SignalR client
	signalrClient, err := azinternal.GetSignalRClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create SignalR client for subscription %s: %v", subID, err), globals.AZ_SIGNALR_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Process each resource group
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, rgName := range rgNames {
		wg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, signalrClient, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *SignalRModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, signalrClient *armsignalr.Client, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region using helper function
	region := azinternal.GetResourceGroupLocation(m.Session, subID, rgName)

	// List SignalR services in resource group
	pager := signalrClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list SignalR in %s/%s: %v", subID, rgName, err), globals.AZ_SIGNALR_MODULE_NAME)
			}
			m.CommandCounter.Error++
			continue
		}

		for _, signalr := range page.Value {
			m.processSignalR(ctx, subID, subName, rgName, region, signalr, logger)
		}
	}
}

// ------------------------------
// Process single SignalR service
// ------------------------------
func (m *SignalRModule) processSignalR(ctx context.Context, subID, subName, rgName, region string, signalr *armsignalr.ResourceInfo, logger internal.Logger) {
	if signalr == nil || signalr.Name == nil {
		return
	}

	signalrName := *signalr.Name

	// Extract service properties
	hostname := "N/A"
	externalIP := "N/A"
	provisioningState := "N/A"
	publicPort := "N/A"
	serverPort := "N/A"

	if signalr.Properties != nil {
		if signalr.Properties.HostName != nil {
			hostname = *signalr.Properties.HostName
		}
		if signalr.Properties.ExternalIP != nil {
			externalIP = *signalr.Properties.ExternalIP
		}
		if signalr.Properties.ProvisioningState != nil {
			provisioningState = string(*signalr.Properties.ProvisioningState)
		}
		if signalr.Properties.PublicPort != nil {
			publicPort = fmt.Sprintf("%d", *signalr.Properties.PublicPort)
		}
		if signalr.Properties.ServerPort != nil {
			serverPort = fmt.Sprintf("%d", *signalr.Properties.ServerPort)
		}
	}

	// Public/Private network access
	publicNetworkAccess := "Enabled"
	if signalr.Properties != nil && signalr.Properties.PublicNetworkAccess != nil {
		publicNetworkAccess = *signalr.Properties.PublicNetworkAccess
	}

	// Authentication settings
	localAuthDisabled := "false"
	aadAuthDisabled := "false"
	if signalr.Properties != nil {
		if signalr.Properties.DisableLocalAuth != nil && *signalr.Properties.DisableLocalAuth {
			localAuthDisabled = "true"
		}
		if signalr.Properties.DisableAADAuth != nil && *signalr.Properties.DisableAADAuth {
			aadAuthDisabled = "true"
		}
	}

	// EntraID Centralized Auth - enabled when local auth is disabled
	entraIDAuth := "Disabled"
	if localAuthDisabled == "true" {
		entraIDAuth = "Enabled (Enforced)"
	} else if aadAuthDisabled == "false" {
		entraIDAuth = "Enabled (Optional)"
	}

	// TLS settings
	tlsVersion := "N/A"
	if signalr.Properties != nil && signalr.Properties.TLS != nil && signalr.Properties.TLS.ClientCertEnabled != nil {
		if *signalr.Properties.TLS.ClientCertEnabled {
			tlsVersion = "Client Cert Enabled"
		} else {
			tlsVersion = "Client Cert Disabled"
		}
	}

	// Service kind (SignalR or RawWebSockets)
	serviceKind := "SignalR"
	if signalr.Kind != nil {
		serviceKind = string(*signalr.Kind)
	}

	// SKU
	sku := "N/A"
	tier := "N/A"
	if signalr.SKU != nil {
		if signalr.SKU.Name != nil {
			sku = *signalr.SKU.Name
		}
		if signalr.SKU.Tier != nil {
			tier = string(*signalr.SKU.Tier)
		}
	}

	// Managed identity
	identityType := "None"
	systemAssignedID := "N/A"
	userAssignedIDs := "N/A"

	if signalr.Identity != nil {
		if signalr.Identity.Type != nil {
			identityType = string(*signalr.Identity.Type)
		}
		if signalr.Identity.PrincipalID != nil {
			systemAssignedID = *signalr.Identity.PrincipalID
		}
		if signalr.Identity.UserAssignedIdentities != nil && len(signalr.Identity.UserAssignedIdentities) > 0 {
			uaIDs := []string{}
			for uaID := range signalr.Identity.UserAssignedIdentities {
				uaIDs = append(uaIDs, azinternal.ExtractResourceName(uaID))
			}
			userAssignedIDs = strings.Join(uaIDs, ", ")
		}
	}

	// Private endpoint connections
	privateEndpointCount := 0
	if signalr.Properties != nil && signalr.Properties.PrivateEndpointConnections != nil {
		privateEndpointCount = len(signalr.Properties.PrivateEndpointConnections)
	}

	// Build row
	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		signalrName,
		hostname,
		externalIP,
		publicPort,
		serverPort,
		provisioningState,
		publicNetworkAccess,
		fmt.Sprintf("%d", privateEndpointCount),
		localAuthDisabled,
		aadAuthDisabled,
		entraIDAuth,
		tlsVersion,
		serviceKind,
		tier,
		sku,
		identityType,
		systemAssignedID,
		userAssignedIDs,
	}

	m.mu.Lock()
	m.SignalRRows = append(m.SignalRRows, row)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Generate loot
	m.generateLoot(subID, subName, rgName, signalrName, hostname, publicNetworkAccess, localAuthDisabled)
}

// ------------------------------
// Generate loot
// ------------------------------
func (m *SignalRModule) generateLoot(subID, subName, rgName, signalrName, hostname, publicNetworkAccess, localAuthDisabled string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	lf := m.LootMap["signalr-commands"]
	lf.Contents += fmt.Sprintf("## SignalR Service: %s (Resource Group: %s)\n", signalrName, rgName)
	lf.Contents += fmt.Sprintf("# Set subscription context\n")
	lf.Contents += fmt.Sprintf("az account set --subscription %s\n\n", subID)
	lf.Contents += fmt.Sprintf("# Show SignalR service details\n")
	lf.Contents += fmt.Sprintf("az signalr show --name %s --resource-group %s\n\n", signalrName, rgName)
	lf.Contents += fmt.Sprintf("# List keys (if local auth not disabled)\n")
	if localAuthDisabled != "true" {
		lf.Contents += fmt.Sprintf("az signalr key list --name %s --resource-group %s\n\n", signalrName, rgName)
	} else {
		lf.Contents += fmt.Sprintf("# Local auth disabled - use Azure AD authentication\n\n")
	}
	lf.Contents += fmt.Sprintf("# Show CORS settings\n")
	lf.Contents += fmt.Sprintf("az signalr cors list --name %s --resource-group %s\n\n", signalrName, rgName)
	lf.Contents += fmt.Sprintf("# Show network ACLs\n")
	lf.Contents += fmt.Sprintf("az signalr network-rule show --name %s --resource-group %s\n\n", signalrName, rgName)
	lf.Contents += fmt.Sprintf("# List upstream settings (if in serverless mode)\n")
	lf.Contents += fmt.Sprintf("az signalr upstream list --name %s --resource-group %s\n\n", signalrName, rgName)
	lf.Contents += fmt.Sprintf("# PowerShell equivalent:\n")
	lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId %s\n", subID)
	lf.Contents += fmt.Sprintf("Get-AzSignalR -Name %s -ResourceGroupName %s\n\n", signalrName, rgName)
	lf.Contents += "---\n\n"
}

// ------------------------------
// Write output
// ------------------------------
func (m *SignalRModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.SignalRRows) == 0 {
		logger.InfoM("No Azure SignalR services found", globals.AZ_SIGNALR_MODULE_NAME)
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
		"SignalR Name",
		"Hostname",
		"External IP",
		"Public Port",
		"Server Port",
		"Provisioning State",
		"Public Network Access",
		"Private Endpoint Count",
		"Local Auth Disabled",
		"AAD Auth Disabled",
		"EntraID Centralized Auth",
		"TLS Client Cert",
		"Service Kind",
		"Tier",
		"SKU",
		"Identity Type",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.SignalRRows, headers,
			"signalr", globals.AZ_SIGNALR_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.SignalRRows, headers,
			"signalr", globals.AZ_SIGNALR_MODULE_NAME,
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
	output := SignalROutput{
		Table: []internal.TableFile{{
			Name:   "signalr",
			Header: headers,
			Body:   m.SignalRRows,
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_SIGNALR_MODULE_NAME)
		return
	}

	// Print summary
	logger.InfoM(fmt.Sprintf("Found %d Azure SignalR service(s) across %d subscription(s)", len(m.SignalRRows), len(m.Subscriptions)), globals.AZ_SIGNALR_MODULE_NAME)
}
