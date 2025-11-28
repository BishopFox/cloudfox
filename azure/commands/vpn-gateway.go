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
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzVPNGatewayCommand = &cobra.Command{
	Use:     "vpn-gateway",
	Aliases: []string{"vpn", "vpngw"},
	Short:   "Enumerate VPN Gateways and their security configurations",
	Long: `
Enumerate VPN Gateways for a specific tenant:
./cloudfox az vpn-gateway --tenant TENANT_ID

Enumerate VPN Gateways for a specific subscription:
./cloudfox az vpn-gateway --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]

Analyzes VPN Gateway configurations including:
- Gateway SKU and type (RouteBased, PolicyBased)
- Point-to-Site (P2S) VPN configuration
- Site-to-Site (S2S) VPN connections
- BGP configuration and peering
- Active-Active high availability
- VPN protocols and authentication methods
`,
	Run: ListVPNGateways,
}

// ------------------------------
// Module struct
// ------------------------------
type VPNGatewayModule struct {
	azinternal.BaseAzureModule

	Subscriptions  []string
	VPNGatewayRows [][]string
	P2SConfigRows  [][]string
	ConnectionRows [][]string
	LootMap        map[string]*internal.LootFile
	mu             sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type VPNGatewayOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o VPNGatewayOutput) TableFiles() []internal.TableFile { return o.Table }
func (o VPNGatewayOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListVPNGateways(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_VPN_GATEWAY_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &VPNGatewayModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		VPNGatewayRows:  [][]string{},
		P2SConfigRows:   [][]string{},
		ConnectionRows:  [][]string{},
		LootMap: map[string]*internal.LootFile{
			"vpn-gateway-commands": {Name: "vpn-gateway-commands", Contents: "# VPN Gateway Commands\n\n"},
			"vpn-gateway-risks":    {Name: "vpn-gateway-risks", Contents: "# VPN Gateway Security Risks\n\n"},
			"vpn-gateway-p2s":      {Name: "vpn-gateway-p2s", Contents: "# Point-to-Site VPN Configurations\n\n"},
		},
	}

	module.PrintVPNGateways(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *VPNGatewayModule) PrintVPNGateways(ctx context.Context, logger internal.Logger) {
	// Multi-tenant support
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_VPN_GATEWAY_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_VPN_GATEWAY_MODULE_NAME, m.processSubscription)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *VPNGatewayModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)
	resourceGroups := m.ResolveResourceGroups(subID)

	for _, rgName := range resourceGroups {
		m.processResourceGroup(ctx, subID, subName, rgName, logger)
	}
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *VPNGatewayModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, logger internal.Logger) {
	vpnGateways, err := azinternal.GetVPNGatewaysPerResourceGroup(ctx, m.Session, subID, rgName)
	if err != nil {
		return
	}

	for _, vpn := range vpnGateways {
		m.processVPNGateway(ctx, subID, subName, rgName, vpn, logger)
	}
}

// ------------------------------
// Process single VPN Gateway
// ------------------------------
func (m *VPNGatewayModule) processVPNGateway(ctx context.Context, subID, subName, rgName string, vpn *armnetwork.VirtualNetworkGateway, logger internal.Logger) {
	if vpn == nil || vpn.Name == nil || vpn.Properties == nil {
		return
	}

	vpnName := *vpn.Name
	location := azinternal.SafeStringPtr(vpn.Location)

	// Gateway type
	gatewayType := "Unknown"
	if vpn.Properties.GatewayType != nil {
		gatewayType = string(*vpn.Properties.GatewayType)
	}

	// VPN type
	vpnType := "Unknown"
	if vpn.Properties.VPNType != nil {
		vpnType = string(*vpn.Properties.VPNType)
	}

	// SKU
	sku := "Unknown"
	skuTier := "Unknown"
	if vpn.Properties.SKU != nil {
		if vpn.Properties.SKU.Name != nil {
			sku = string(*vpn.Properties.SKU.Name)
		}
		if vpn.Properties.SKU.Tier != nil {
			skuTier = string(*vpn.Properties.SKU.Tier)
		}
	}

	// Active-Active mode
	activeActive := "No"
	if vpn.Properties.Active != nil && *vpn.Properties.Active {
		activeActive = "✓ Yes"
	}

	// BGP enabled
	bgpEnabled := "No"
	bgpASN := "N/A"
	if vpn.Properties.EnableBgp != nil && *vpn.Properties.EnableBgp {
		bgpEnabled = "✓ Yes"
		if vpn.Properties.BgpSettings != nil {
			if vpn.Properties.BgpSettings.Asn != nil {
				bgpASN = fmt.Sprintf("%d", *vpn.Properties.BgpSettings.Asn)
			}
		}
	}

	// Get public IPs
	publicIPs := []string{}
	if vpn.Properties.IPConfigurations != nil {
		for _, ipConfig := range vpn.Properties.IPConfigurations {
			if ipConfig.Properties != nil && ipConfig.Properties.PublicIPAddress != nil && ipConfig.Properties.PublicIPAddress.ID != nil {
				ipID := *ipConfig.Properties.PublicIPAddress.ID
				ipName := azinternal.ExtractResourceName(ipID)
				publicIPs = append(publicIPs, ipName)
			}
		}
	}
	publicIPsStr := strings.Join(publicIPs, ", ")
	if publicIPsStr == "" {
		publicIPsStr = "N/A"
	}

	// Point-to-Site configuration
	p2sEnabled := "No"
	p2sProtocols := "N/A"
	p2sAuthMethods := "N/A"
	p2sAddressPool := "N/A"

	if vpn.Properties.VPNClientConfiguration != nil {
		p2sConfig := vpn.Properties.VPNClientConfiguration

		// P2S enabled if address pool exists
		if p2sConfig.VPNClientAddressPool != nil && p2sConfig.VPNClientAddressPool.AddressPrefixes != nil && len(p2sConfig.VPNClientAddressPool.AddressPrefixes) > 0 {
			p2sEnabled = "✓ Yes"
			p2sAddressPool = strings.Join(azinternal.SafeStringSlice(p2sConfig.VPNClientAddressPool.AddressPrefixes), ", ")
		}

		// P2S protocols
		if p2sConfig.VPNClientProtocols != nil && len(p2sConfig.VPNClientProtocols) > 0 {
			protocols := []string{}
			for _, proto := range p2sConfig.VPNClientProtocols {
				if proto != nil {
					protocols = append(protocols, string(*proto))
				}
			}
			p2sProtocols = strings.Join(protocols, ", ")
		}

		// P2S authentication methods
		if p2sConfig.VPNAuthenticationTypes != nil && len(p2sConfig.VPNAuthenticationTypes) > 0 {
			authMethods := []string{}
			for _, auth := range p2sConfig.VPNAuthenticationTypes {
				if auth != nil {
					authMethods = append(authMethods, string(*auth))
				}
			}
			p2sAuthMethods = strings.Join(authMethods, ", ")
		}

		// Check for weak authentication
		if strings.Contains(p2sAuthMethods, "Certificate") && !strings.Contains(p2sAuthMethods, "AAD") {
			m.mu.Lock()
			m.LootMap["vpn-gateway-risks"].Contents += fmt.Sprintf("⚠️  P2S VPN using certificate-only authentication: %s/%s\n", rgName, vpnName)
			m.LootMap["vpn-gateway-risks"].Contents += fmt.Sprintf("  Consider enabling Azure AD authentication for better security\n")
			m.LootMap["vpn-gateway-risks"].Contents += fmt.Sprintf("  Subscription: %s\n\n", subName)
			m.mu.Unlock()
		}

		// P2S details for separate table
		if p2sEnabled == "✓ Yes" {
			p2sRow := []string{
				m.TenantName,
				m.TenantID,
				subID,
				subName,
				rgName,
				location,
				vpnName,
				p2sAddressPool,
				p2sProtocols,
				p2sAuthMethods,
				publicIPsStr,
			}
			m.mu.Lock()
			m.P2SConfigRows = append(m.P2SConfigRows, p2sRow)
			m.mu.Unlock()

			// Add to P2S loot file
			m.mu.Lock()
			m.LootMap["vpn-gateway-p2s"].Contents += fmt.Sprintf("Gateway: %s/%s\n", rgName, vpnName)
			m.LootMap["vpn-gateway-p2s"].Contents += fmt.Sprintf("  Address Pool: %s\n", p2sAddressPool)
			m.LootMap["vpn-gateway-p2s"].Contents += fmt.Sprintf("  Protocols: %s\n", p2sProtocols)
			m.LootMap["vpn-gateway-p2s"].Contents += fmt.Sprintf("  Authentication: %s\n", p2sAuthMethods)
			m.LootMap["vpn-gateway-p2s"].Contents += fmt.Sprintf("  Public IPs: %s\n\n", publicIPsStr)
			m.mu.Unlock()
		}
	}

	// Get VPN connections (Site-to-Site)
	connectionCount := 0
	if vpn.ID != nil {
		connections, err := m.getVPNConnections(ctx, subID, rgName)
		if err == nil {
			for _, conn := range connections {
				if conn.Properties != nil && conn.Properties.VirtualNetworkGateway1 != nil && conn.Properties.VirtualNetworkGateway1.ID != nil {
					if *conn.Properties.VirtualNetworkGateway1.ID == *vpn.ID {
						connectionCount++
						m.processVPNConnection(ctx, subID, subName, rgName, location, vpnName, conn)
					}
				}
			}
		}
	}

	// Main VPN Gateway row
	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		location,
		vpnName,
		gatewayType,
		vpnType,
		sku,
		skuTier,
		activeActive,
		bgpEnabled,
		bgpASN,
		publicIPsStr,
		p2sEnabled,
		p2sProtocols,
		p2sAuthMethods,
		fmt.Sprintf("%d", connectionCount),
	}

	m.mu.Lock()
	m.VPNGatewayRows = append(m.VPNGatewayRows, row)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Add to loot commands
	m.mu.Lock()
	m.LootMap["vpn-gateway-commands"].Contents += fmt.Sprintf("# VPN Gateway: %s (Resource Group: %s)\n", vpnName, rgName)
	m.LootMap["vpn-gateway-commands"].Contents += fmt.Sprintf("az account set --subscription %s\n", subID)
	m.LootMap["vpn-gateway-commands"].Contents += fmt.Sprintf("az network vnet-gateway show --name %s --resource-group %s\n", vpnName, rgName)
	if p2sEnabled == "✓ Yes" {
		m.LootMap["vpn-gateway-commands"].Contents += fmt.Sprintf("az network vnet-gateway vpn-client generate --name %s --resource-group %s\n", vpnName, rgName)
	}
	if connectionCount > 0 {
		m.LootMap["vpn-gateway-commands"].Contents += fmt.Sprintf("az network vpn-connection list --resource-group %s\n", rgName)
	}
	m.LootMap["vpn-gateway-commands"].Contents += "\n"
	m.mu.Unlock()
}

// ------------------------------
// Get VPN Connections
// ------------------------------
func (m *VPNGatewayModule) getVPNConnections(ctx context.Context, subID, rgName string) ([]*armnetwork.VirtualNetworkGatewayConnection, error) {
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}

	cred := azinternal.NewStaticTokenCredential(token)
	connClient, err := armnetwork.NewVirtualNetworkGatewayConnectionsClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	var connections []*armnetwork.VirtualNetworkGatewayConnection
	pager := connClient.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		connections = append(connections, page.Value...)
	}

	return connections, nil
}

// ------------------------------
// Process VPN Connection
// ------------------------------
func (m *VPNGatewayModule) processVPNConnection(ctx context.Context, subID, subName, rgName, location, vpnName string, conn *armnetwork.VirtualNetworkGatewayConnection) {
	if conn == nil || conn.Name == nil || conn.Properties == nil {
		return
	}

	connName := *conn.Name

	// Connection type
	connType := "Unknown"
	if conn.Properties.ConnectionType != nil {
		connType = string(*conn.Properties.ConnectionType)
	}

	// Connection status
	connStatus := "Unknown"
	if conn.Properties.ConnectionStatus != nil {
		connStatus = string(*conn.Properties.ConnectionStatus)
	}

	// Shared key configured
	sharedKeyConfigured := "Unknown"
	if conn.Properties.SharedKey != nil && *conn.Properties.SharedKey != "" {
		sharedKeyConfigured = "✓ Yes"
	} else {
		sharedKeyConfigured = "No"
	}

	// IPsec policies
	ipsecPolicies := "Default"
	if conn.Properties.IPSecPolicies != nil && len(conn.Properties.IPSecPolicies) > 0 {
		ipsecPolicies = fmt.Sprintf("%d custom policies", len(conn.Properties.IPSecPolicies))
	}

	// Remote endpoint
	remoteEndpoint := "N/A"
	if connType == "IPsec" && conn.Properties.LocalNetworkGateway2 != nil && conn.Properties.LocalNetworkGateway2.ID != nil {
		remoteEndpoint = azinternal.ExtractResourceName(*conn.Properties.LocalNetworkGateway2.ID)
	} else if connType == "Vnet2Vnet" && conn.Properties.VirtualNetworkGateway2 != nil && conn.Properties.VirtualNetworkGateway2.ID != nil {
		remoteEndpoint = azinternal.ExtractResourceName(*conn.Properties.VirtualNetworkGateway2.ID)
	}

	// Use BGP
	useBgp := "No"
	if conn.Properties.UsePolicyBasedTrafficSelectors != nil && *conn.Properties.UsePolicyBasedTrafficSelectors {
		useBgp = "✓ Yes"
	}

	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		location,
		vpnName,
		connName,
		connType,
		connStatus,
		remoteEndpoint,
		sharedKeyConfigured,
		ipsecPolicies,
		useBgp,
	}

	m.mu.Lock()
	m.ConnectionRows = append(m.ConnectionRows, row)
	m.mu.Unlock()

	// Check for security risks
	if connStatus == "Connected" && sharedKeyConfigured == "No" {
		m.mu.Lock()
		m.LootMap["vpn-gateway-risks"].Contents += fmt.Sprintf("⚠️  VPN Connection without shared key: %s/%s → %s\n", rgName, vpnName, connName)
		m.LootMap["vpn-gateway-risks"].Contents += fmt.Sprintf("  Connection Type: %s, Status: %s\n", connType, connStatus)
		m.LootMap["vpn-gateway-risks"].Contents += fmt.Sprintf("  Subscription: %s\n\n", subName)
		m.mu.Unlock()
	}
}

// ------------------------------
// Write output
// ------------------------------
func (m *VPNGatewayModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.VPNGatewayRows) == 0 {
		logger.InfoM("No VPN Gateways found", globals.AZ_VPN_GATEWAY_MODULE_NAME)
		return
	}

	// Main VPN Gateway headers
	gatewayHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Location",
		"Gateway Name",
		"Gateway Type",
		"VPN Type",
		"SKU",
		"SKU Tier",
		"Active-Active",
		"BGP Enabled",
		"BGP ASN",
		"Public IPs",
		"P2S Enabled",
		"P2S Protocols",
		"P2S Auth Methods",
		"S2S Connection Count",
	}

	// P2S Configuration headers
	p2sHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Location",
		"Gateway Name",
		"Address Pool",
		"Protocols",
		"Auth Methods",
		"Public IPs",
	}

	// Connection headers
	connectionHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Location",
		"Gateway Name",
		"Connection Name",
		"Connection Type",
		"Connection Status",
		"Remote Endpoint",
		"Shared Key Configured",
		"IPsec Policies",
		"Use BGP",
	}

	// Build tables
	tables := []internal.TableFile{{
		Name:   "vpn-gateways",
		Header: gatewayHeaders,
		Body:   m.VPNGatewayRows,
	}}

	if len(m.P2SConfigRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "vpn-gateway-p2s",
			Header: p2sHeaders,
			Body:   m.P2SConfigRows,
		})
	}

	if len(m.ConnectionRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "vpn-gateway-connections",
			Header: connectionHeaders,
			Body:   m.ConnectionRows,
		})
	}

	// Check if we should split output by tenant
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		// Split main gateway table
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.VPNGatewayRows,
			gatewayHeaders,
			"vpn-gateways",
			globals.AZ_VPN_GATEWAY_MODULE_NAME,
		); err != nil {
			return
		}

		// Split P2S table if exists
		if len(m.P2SConfigRows) > 0 {
			m.FilterAndWritePerTenantAuto(
				ctx,
				logger,
				m.Tenants,
				m.P2SConfigRows,
				p2sHeaders,
				"vpn-gateway-p2s",
				globals.AZ_VPN_GATEWAY_MODULE_NAME,
			)
		}

		// Split connections table if exists
		if len(m.ConnectionRows) > 0 {
			m.FilterAndWritePerTenantAuto(
				ctx,
				logger,
				m.Tenants,
				m.ConnectionRows,
				connectionHeaders,
				"vpn-gateway-connections",
				globals.AZ_VPN_GATEWAY_MODULE_NAME,
			)
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.VPNGatewayRows, gatewayHeaders,
			"vpn-gateways", globals.AZ_VPN_GATEWAY_MODULE_NAME,
		); err != nil {
			return
		}

		if len(m.P2SConfigRows) > 0 {
			m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.P2SConfigRows, p2sHeaders,
				"vpn-gateway-p2s", globals.AZ_VPN_GATEWAY_MODULE_NAME,
			)
		}

		if len(m.ConnectionRows) > 0 {
			m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.ConnectionRows, connectionHeaders,
				"vpn-gateway-connections", globals.AZ_VPN_GATEWAY_MODULE_NAME,
			)
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

	output := VPNGatewayOutput{
		Table: tables,
		Loot:  loot,
	}

	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_VPN_GATEWAY_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d VPN Gateways, %d P2S configurations, %d connections across %d subscriptions",
		len(m.VPNGatewayRows), len(m.P2SConfigRows), len(m.ConnectionRows), len(m.Subscriptions)), globals.AZ_VPN_GATEWAY_MODULE_NAME)
}
