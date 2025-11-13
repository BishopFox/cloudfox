package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/iothub/armiothub"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzIoTHubCommand = &cobra.Command{
	Use:     "iothub",
	Aliases: []string{"iot", "iot-hub"},
	Short:   "Enumerate Azure IoT Hub instances",
	Long: `
Enumerate Azure IoT Hub for a specific tenant:
  ./cloudfox az iothub --tenant TENANT_ID

Enumerate IoT Hub for a specific subscription:
  ./cloudfox az iothub --subscription SUBSCRIPTION_ID`,
	Run: ListIoTHub,
}

// ------------------------------
// Module struct
// ------------------------------
type IoTHubModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	Subscriptions []string
	IoTHubRows    [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

type IoTHubInfo struct {
	SubscriptionID   string
	SubscriptionName string
	ResourceGroup    string
	Region           string
	HubName          string
	Hostname         string
	SKU              string
	PublicPrivate    string
	EventHubEndpoint string
	ConnectionString string
	SystemAssignedID string
	UserAssignedIDs  string
}

// ------------------------------
// Output struct
// ------------------------------
type IoTHubOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o IoTHubOutput) TableFiles() []internal.TableFile { return o.Table }
func (o IoTHubOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListIoTHub(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_IOTHUB_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &IoTHubModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		IoTHubRows:      [][]string{},
		LootMap: map[string]*internal.LootFile{
			"iothub-commands":           {Name: "iothub-commands", Contents: ""},
			"iothub-connection-strings": {Name: "iothub-connection-strings", Contents: ""},
		},
	}

	module.PrintIoTHub(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *IoTHubModule) PrintIoTHub(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_IOTHUB_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_IOTHUB_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *IoTHubModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get ARM token: %v", err), globals.AZ_IOTHUB_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}
	cred := &azinternal.StaticTokenCredential{Token: token}

	iotClient, err := armiothub.NewResourceClient(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create IoT Hub client: %v", err), globals.AZ_IOTHUB_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	resourceGroups := m.ResolveResourceGroups(subID)

	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10)

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, iotClient, &rgWg, rgSemaphore, logger)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *IoTHubModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, iotClient *armiothub.ResourceClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region
	region := ""
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	for _, r := range rgs {
		if r.Name != nil && *r.Name == rgName && r.Location != nil {
			region = *r.Location
			break
		}
	}

	pager := iotClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to list IoT Hubs in RG %s: %v", rgName, err), globals.AZ_IOTHUB_MODULE_NAME)
			m.CommandCounter.Error++
			continue
		}

		for _, hub := range page.Value {
			m.processIoTHub(ctx, hub, subID, subName, rgName, region, iotClient, logger)
		}
	}
}

// ------------------------------
// Process single IoT Hub
// ------------------------------
func (m *IoTHubModule) processIoTHub(ctx context.Context, hub *armiothub.Description, subID, subName, rgName, region string, iotClient *armiothub.ResourceClient, logger internal.Logger) {
	hubName := azinternal.SafeStringPtr(hub.Name)
	hostname := "N/A"
	sku := "N/A"
	publicPrivate := "Unknown"
	eventHubEndpoint := "N/A"
	connectionString := "N/A"

	if hub.Properties != nil {
		if hub.Properties.HostName != nil {
			hostname = *hub.Properties.HostName
		}

		// Extract Event Hub-compatible endpoint
		if hub.Properties.EventHubEndpoints != nil {
			if eventsEndpoint, ok := hub.Properties.EventHubEndpoints["events"]; ok {
				if eventsEndpoint.Endpoint != nil {
					eventHubEndpoint = *eventsEndpoint.Endpoint
				}
			}
		}

		// Determine public/private
		if hub.Properties.PublicNetworkAccess != nil {
			if *hub.Properties.PublicNetworkAccess == armiothub.PublicNetworkAccessEnabled {
				publicPrivate = "Public"
			} else {
				publicPrivate = "Private"
			}
		}
	}

	// Extract SKU
	if hub.SKU != nil {
		skuParts := []string{}
		if hub.SKU.Name != nil {
			skuParts = append(skuParts, string(*hub.SKU.Name))
		}
		if hub.SKU.Capacity != nil {
			skuParts = append(skuParts, fmt.Sprintf("Units: %d", *hub.SKU.Capacity))
		}
		if len(skuParts) > 0 {
			sku = strings.Join(skuParts, " ")
		}
	}

	// Get connection string (using iothubowner policy)
	keysResp, err := iotClient.GetKeysForKeyName(ctx, rgName, hubName, "iothubowner", nil)
	if err == nil && keysResp.SharedAccessSignatureAuthorizationRule.PrimaryKey != nil {
		primaryKey := *keysResp.SharedAccessSignatureAuthorizationRule.PrimaryKey
		connectionString = fmt.Sprintf("HostName=%s;SharedAccessKeyName=iothubowner;SharedAccessKey=%s", hostname, primaryKey)
	}

	// Extract managed identity information
	var systemAssignedIDs []string
	var userAssignedIDs []string

	if hub.Identity != nil {
		if hub.Identity.PrincipalID != nil {
			principalID := *hub.Identity.PrincipalID
			systemAssignedIDs = append(systemAssignedIDs, principalID)
		}

		if hub.Identity.UserAssignedIdentities != nil {
			for uaID := range hub.Identity.UserAssignedIdentities {
				userAssignedIDs = append(userAssignedIDs, uaID)
			}
		}
	}

	// Format identity fields
	sysID := "N/A"
	if len(systemAssignedIDs) > 0 {
		sysID = strings.Join(systemAssignedIDs, "\n")
	}
	userIDs := "N/A"
	if len(userAssignedIDs) > 0 {
		userIDs = strings.Join(userAssignedIDs, "\n")
	}

	// Build row
	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		hubName,
		hostname,
		sku,
		publicPrivate,
		eventHubEndpoint,
		"See iothub-connection-strings loot file",
		sysID,
		userIDs,
	}

	m.mu.Lock()
	m.IoTHubRows = append(m.IoTHubRows, row)
	m.mu.Unlock()

	m.CommandCounter.Total++

	// Generate loot
	m.generateIoTHubCommands(subID, rgName, hubName, hostname)
	m.generateIoTHubConnectionStrings(hubName, hostname, connectionString, eventHubEndpoint)
}

// ------------------------------
// Generate IoT Hub commands loot
// ------------------------------
func (m *IoTHubModule) generateIoTHubCommands(subID, rgName, hubName, hostname string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["iothub-commands"].Contents += fmt.Sprintf(
		"## IoT Hub: %s (Resource Group: %s)\n"+
			"# Set subscription context\n"+
			"az account set --subscription %s\n"+
			"\n"+
			"# Get IoT Hub details\n"+
			"az iot hub show \\\n"+
			"  --resource-group %s \\\n"+
			"  --name %s \\\n"+
			"  --output table\n"+
			"\n"+
			"# List IoT Hub connection strings\n"+
			"az iot hub connection-string show \\\n"+
			"  --resource-group %s \\\n"+
			"  --hub-name %s\n"+
			"\n"+
			"# List all devices registered to the hub\n"+
			"az iot hub device-identity list \\\n"+
			"  --hub-name %s \\\n"+
			"  --output table\n"+
			"\n"+
			"# Get device connection string (replace <device-id> with actual device ID)\n"+
			"az iot hub device-identity connection-string show \\\n"+
			"  --hub-name %s \\\n"+
			"  --device-id <device-id>\n"+
			"\n"+
			"# Monitor device-to-cloud messages\n"+
			"az iot hub monitor-events \\\n"+
			"  --hub-name %s\n"+
			"\n"+
			"## PowerShell equivalents\n"+
			"Set-AzContext -SubscriptionId %s\n"+
			"\n"+
			"# Get IoT Hub\n"+
			"Get-AzIotHub -ResourceGroupName %s -Name %s\n"+
			"\n"+
			"# Get IoT Hub connection string\n"+
			"Get-AzIotHubConnectionString -ResourceGroupName %s -Name %s\n\n",
		hubName, rgName,
		subID,
		rgName, hubName,
		rgName, hubName,
		hubName,
		hubName,
		hubName,
		subID,
		rgName, hubName,
		rgName, hubName,
	)
}

// ------------------------------
// Generate IoT Hub connection strings loot
// ------------------------------
func (m *IoTHubModule) generateIoTHubConnectionStrings(hubName, hostname, connectionString, eventHubEndpoint string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["iothub-connection-strings"].Contents += fmt.Sprintf(
		"## IoT Hub: %s\n"+
			"Hostname: %s\n"+
			"\n"+
			"# IoT Hub Owner Connection String (full permissions)\n"+
			"%s\n"+
			"\n"+
			"# Event Hub-compatible endpoint (for reading device telemetry)\n"+
			"%s\n"+
			"\n"+
			"# Note: To get device-specific connection strings, use:\n"+
			"# az iot hub device-identity connection-string show --hub-name %s --device-id <device-id>\n"+
			"\n",
		hubName,
		hostname,
		connectionString,
		eventHubEndpoint,
		hubName,
	)
}

// ------------------------------
// Write output
// ------------------------------
func (m *IoTHubModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.IoTHubRows) == 0 {
		logger.InfoM("No IoT Hubs found", globals.AZ_IOTHUB_MODULE_NAME)
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
		"IoT Hub Name",
		"Hostname",
		"SKU",
		"Public/Private",
		"Event Hub Endpoint",
		"Connection String",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.IoTHubRows, headers,
			"iothub", globals.AZ_IOTHUB_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.IoTHubRows, headers,
			"iothub", globals.AZ_IOTHUB_MODULE_NAME,
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
	output := IoTHubOutput{
		Table: []internal.TableFile{{
			Name:   "iothub",
			Header: headers,
			Body:   m.IoTHubRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_IOTHUB_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d IoT Hubs across %d subscription(s)", len(m.IoTHubRows), len(m.Subscriptions)), globals.AZ_IOTHUB_MODULE_NAME)
}
