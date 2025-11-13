package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzPrivateLinkCommand = &cobra.Command{
	Use:     "privatelink",
	Aliases: []string{"private-endpoints", "pe"},
	Short:   "Enumerate Azure Private Endpoints",
	Long: `
Enumerate Private Endpoints for a specific tenant:
  ./cloudfox az privatelink --tenant TENANT_ID

Enumerate Private Endpoints for a specific subscription:
  ./cloudfox az privatelink --subscription SUBSCRIPTION_ID`,
	Run: ListPrivateEndpoints,
}

// ------------------------------
// Module struct
// ------------------------------
type PrivateLinkModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	Subscriptions       []string
	PrivateEndpointRows [][]string
	LootMap             map[string]*internal.LootFile
	mu                  sync.Mutex
}

type PrivateEndpointInfo struct {
	SubscriptionID    string
	SubscriptionName  string
	ResourceGroup     string
	Region            string
	EndpointName      string
	ConnectedResource string
	ResourceType      string
	PrivateIPs        string
	Subnet            string
	VNet              string
	ConnectionState   string
}

// ------------------------------
// Output struct
// ------------------------------
type PrivateLinkOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PrivateLinkOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PrivateLinkOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListPrivateEndpoints(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_PRIVATELINK_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &PrivateLinkModule{
		BaseAzureModule:     azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:       cmdCtx.Subscriptions,
		PrivateEndpointRows: [][]string{},
		LootMap: map[string]*internal.LootFile{
			"privatelink-commands": {Name: "privatelink-commands", Contents: ""},
		},
	}

	module.PrintPrivateEndpoints(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *PrivateLinkModule) PrintPrivateEndpoints(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_PRIVATELINK_MODULE_NAME)

		for _, tenantCtx := range m.Tenants {
			// Save current tenant context
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			// Set tenant context for this iteration
			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_PRIVATELINK_MODULE_NAME, m.processSubscription)

			// Restore original tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_PRIVATELINK_MODULE_NAME, m.processSubscription)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *PrivateLinkModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get ARM token: %v", err), globals.AZ_PRIVATELINK_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}
	cred := &azinternal.StaticTokenCredential{Token: token}

	peClient, err := armnetwork.NewPrivateEndpointsClient(subID, cred, nil)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Private Endpoints client: %v", err), globals.AZ_PRIVATELINK_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	resourceGroups := m.ResolveResourceGroups(subID)

	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10)

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, peClient, &rgWg, rgSemaphore, logger)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *PrivateLinkModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, peClient *armnetwork.PrivateEndpointsClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
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

	pager := peClient.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to list Private Endpoints in RG %s: %v", rgName, err), globals.AZ_PRIVATELINK_MODULE_NAME)
			m.CommandCounter.Error++
			continue
		}

		for _, pe := range page.Value {
			m.processPrivateEndpoint(ctx, pe, subID, subName, rgName, region, logger)
		}
	}
}

// ------------------------------
// Process single Private Endpoint
// ------------------------------
func (m *PrivateLinkModule) processPrivateEndpoint(ctx context.Context, pe *armnetwork.PrivateEndpoint, subID, subName, rgName, region string, logger internal.Logger) {
	endpointName := azinternal.SafeStringPtr(pe.Name)
	connectedResource := "N/A"
	resourceType := "N/A"
	connectionState := "N/A"
	vnetName := "N/A"
	subnetName := "N/A"
	privateIPs := []string{}

	// Extract connected resource information
	if pe.Properties != nil {
		// Extract private link service connections
		if pe.Properties.PrivateLinkServiceConnections != nil && len(pe.Properties.PrivateLinkServiceConnections) > 0 {
			for _, conn := range pe.Properties.PrivateLinkServiceConnections {
				if conn.Properties != nil {
					if conn.Properties.PrivateLinkServiceID != nil {
						connectedResource = *conn.Properties.PrivateLinkServiceID
						// Extract resource type from ID
						// Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
						parts := strings.Split(connectedResource, "/")
						if len(parts) >= 8 {
							resourceType = parts[6] + "/" + parts[7]
						}
					}
					if conn.Properties.PrivateLinkServiceConnectionState != nil && conn.Properties.PrivateLinkServiceConnectionState.Status != nil {
						connectionState = *conn.Properties.PrivateLinkServiceConnectionState.Status
					}
				}
			}
		}

		// Extract manual private link service connections
		if pe.Properties.ManualPrivateLinkServiceConnections != nil && len(pe.Properties.ManualPrivateLinkServiceConnections) > 0 {
			for _, conn := range pe.Properties.ManualPrivateLinkServiceConnections {
				if conn.Properties != nil {
					if conn.Properties.PrivateLinkServiceID != nil && connectedResource == "N/A" {
						connectedResource = *conn.Properties.PrivateLinkServiceID
						// Extract resource type from ID
						parts := strings.Split(connectedResource, "/")
						if len(parts) >= 8 {
							resourceType = parts[6] + "/" + parts[7]
						}
					}
					if conn.Properties.PrivateLinkServiceConnectionState != nil && conn.Properties.PrivateLinkServiceConnectionState.Status != nil && connectionState == "N/A" {
						connectionState = *conn.Properties.PrivateLinkServiceConnectionState.Status
					}
				}
			}
		}

		// Extract subnet and VNet information
		if pe.Properties.Subnet != nil && pe.Properties.Subnet.ID != nil {
			subnetID := *pe.Properties.Subnet.ID
			// Subnet ID format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}
			parts := strings.Split(subnetID, "/")
			if len(parts) >= 11 {
				vnetName = parts[8]
				subnetName = parts[10]
			}
		}

		// Extract private IP addresses
		if pe.Properties.NetworkInterfaces != nil {
			for _, nic := range pe.Properties.NetworkInterfaces {
				if nic.ID != nil {
					// Note: We only have the NIC ID here, not the full NIC object with IP configs
					// In a real implementation, we might want to fetch the NIC details
					// For now, we'll note that the IP is available via the NIC
					privateIPs = append(privateIPs, fmt.Sprintf("NIC: %s", *nic.ID))
				}
			}
		}

		// Try to get custom DNS configs which contain private IPs
		if pe.Properties.CustomDNSConfigs != nil {
			for _, dnsConfig := range pe.Properties.CustomDNSConfigs {
				if dnsConfig.IPAddresses != nil {
					for _, ip := range dnsConfig.IPAddresses {
						if ip != nil {
							privateIPs = append(privateIPs, *ip)
						}
					}
				}
			}
		}
	}

	// Format private IPs
	privateIPsStr := "N/A"
	if len(privateIPs) > 0 {
		privateIPsStr = strings.Join(privateIPs, "\n")
	}

	// Extract resource name from connected resource ID
	resourceName := "N/A"
	if connectedResource != "N/A" {
		parts := strings.Split(connectedResource, "/")
		if len(parts) > 0 {
			resourceName = parts[len(parts)-1]
		}
	}

	// Build row
	row := []string{
		m.TenantName, // NEW: for multi-tenant support
		m.TenantID,   // NEW: for multi-tenant support
		subID,
		subName,
		rgName,
		region,
		endpointName,
		resourceName,
		resourceType,
		privateIPsStr,
		fmt.Sprintf("%s/%s", vnetName, subnetName),
		connectionState,
	}

	m.mu.Lock()
	m.PrivateEndpointRows = append(m.PrivateEndpointRows, row)
	m.mu.Unlock()

	m.CommandCounter.Total++

	// Generate loot
	m.generatePrivateLinkCommands(subID, rgName, endpointName, resourceName, resourceType, connectionState)
}

// ------------------------------
// Generate Private Link commands loot
// ------------------------------
func (m *PrivateLinkModule) generatePrivateLinkCommands(subID, rgName, endpointName, resourceName, resourceType, connectionState string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["privatelink-commands"].Contents += fmt.Sprintf(
		"## Private Endpoint: %s (Resource Group: %s)\n"+
			"Connected to: %s (%s)\n"+
			"Connection State: %s\n"+
			"\n"+
			"# Set subscription context\n"+
			"az account set --subscription %s\n"+
			"\n"+
			"# Get Private Endpoint details\n"+
			"az network private-endpoint show \\\n"+
			"  --resource-group %s \\\n"+
			"  --name %s \\\n"+
			"  --output table\n"+
			"\n"+
			"# List all private DNS zone groups for this endpoint\n"+
			"az network private-endpoint dns-zone-group list \\\n"+
			"  --resource-group %s \\\n"+
			"  --endpoint-name %s \\\n"+
			"  --output table\n"+
			"\n"+
			"# Get effective routes for the private endpoint NIC\n"+
			"# (First get the NIC ID, then show effective routes)\n"+
			"NIC_ID=$(az network private-endpoint show \\\n"+
			"  --resource-group %s \\\n"+
			"  --name %s \\\n"+
			"  --query 'networkInterfaces[0].id' -o tsv)\n"+
			"\n"+
			"az network nic show-effective-route-table \\\n"+
			"  --ids $NIC_ID \\\n"+
			"  --output table\n"+
			"\n"+
			"## PowerShell equivalents\n"+
			"Set-AzContext -SubscriptionId %s\n"+
			"\n"+
			"# Get Private Endpoint\n"+
			"Get-AzPrivateEndpoint -ResourceGroupName %s -Name %s\n"+
			"\n"+
			"# Get Private Endpoint connection\n"+
			"Get-AzPrivateEndpointConnection -PrivateEndpointName %s -ResourceGroupName %s\n\n",
		endpointName, rgName,
		resourceName, resourceType,
		connectionState,
		subID,
		rgName, endpointName,
		rgName, endpointName,
		rgName, endpointName,
		subID,
		rgName, endpointName,
		endpointName, rgName,
	)
}

// ------------------------------
// Write output
// ------------------------------
func (m *PrivateLinkModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.PrivateEndpointRows) == 0 {
		logger.InfoM("No Private Endpoints found", globals.AZ_PRIVATELINK_MODULE_NAME)
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
		"Endpoint Name",
		"Connected Resource Name",
		"Resource Type",
		"Private IP(s)",
		"VNet/Subnet",
		"Connection State",
	}

	// Check if we should split output by tenant first, then subscription
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.PrivateEndpointRows, headers,
			"privatelink", globals.AZ_PRIVATELINK_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.PrivateEndpointRows, headers,
			"privatelink", globals.AZ_PRIVATELINK_MODULE_NAME,
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
	output := PrivateLinkOutput{
		Table: []internal.TableFile{{
			Name:   "privatelink",
			Header: headers,
			Body:   m.PrivateEndpointRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_PRIVATELINK_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Private Endpoints across %d subscription(s)", len(m.PrivateEndpointRows), len(m.Subscriptions)), globals.AZ_PRIVATELINK_MODULE_NAME)
}
