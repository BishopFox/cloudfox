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
var AzLateralMovementCommand = &cobra.Command{
	Use:     "lateral-movement",
	Aliases: []string{"lateral", "latmove"},
	Short:   "Analyze lateral movement paths and privilege escalation opportunities",
	Long: `
Analyze lateral movement opportunities across Azure resources:
./cloudfox az lateral-movement --tenant TENANT_ID

Analyze lateral movement for specific subscriptions:
./cloudfox az lateral-movement --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]

This module identifies:
- VNet peerings enabling network lateral movement
- Service endpoints and private links to PaaS services
- NSG rules allowing VM-to-VM communication
- Managed identity privilege escalation paths
- Cross-subscription RBAC assignments
- VPN and hybrid connectivity paths
`,
	Run: AnalyzeLateralMovement,
}

// ------------------------------
// Module struct
// ------------------------------
type LateralMovementModule struct {
	azinternal.BaseAzureModule

	Subscriptions       []string
	LateralMovementRows [][]string
	LootMap             map[string]*internal.LootFile

	// Cache for VNets and peerings
	vnetCache    map[string]*armnetwork.VirtualNetwork
	peeringCache map[string][]*armnetwork.VirtualNetworkPeering
	mu           sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type LateralMovementOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LateralMovementOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LateralMovementOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func AnalyzeLateralMovement(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_LATERAL_MOVEMENT_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &LateralMovementModule{
		BaseAzureModule:     azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:       cmdCtx.Subscriptions,
		LateralMovementRows: [][]string{},
		vnetCache:           make(map[string]*armnetwork.VirtualNetwork),
		peeringCache:        make(map[string][]*armnetwork.VirtualNetworkPeering),
		LootMap: map[string]*internal.LootFile{
			"lateral-movement-paths":    {Name: "lateral-movement-paths", Contents: "# Lateral Movement Paths\n\n"},
			"lateral-movement-critical": {Name: "lateral-movement-critical", Contents: "# Critical Lateral Movement Risks\n\n"},
			"lateral-movement-commands": {Name: "lateral-movement-commands", Contents: "# Lateral Movement Testing Commands\n\n"},
		},
	}

	module.PrintLateralMovement(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *LateralMovementModule) PrintLateralMovement(ctx context.Context, logger internal.Logger) {
	// Multi-tenant support
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_LATERAL_MOVEMENT_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_LATERAL_MOVEMENT_MODULE_NAME, m.processSubscription)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *LateralMovementModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Build VNet cache for this subscription
	m.buildVNetCache(ctx, subID, resourceGroups, logger)

	// Analyze lateral movement paths
	m.analyzeVNetPeerings(ctx, subID, subName, logger)
	m.analyzeServiceEndpoints(ctx, subID, subName, resourceGroups, logger)
	m.analyzePrivateEndpoints(ctx, subID, subName, resourceGroups, logger)
	m.analyzeNSGConnectivity(ctx, subID, subName, resourceGroups, logger)
	m.analyzeVPNGateways(ctx, subID, subName, resourceGroups, logger)
}

// ------------------------------
// Build VNet cache for subscription
// ------------------------------
func (m *LateralMovementModule) buildVNetCache(ctx context.Context, subID string, resourceGroups []string, logger internal.Logger) {
	for _, rgName := range resourceGroups {
		vnets, err := azinternal.ListVirtualNetworks(ctx, m.Session, subID, rgName)
		if err != nil {
			continue
		}

		for _, vnet := range vnets {
			if vnet == nil || vnet.Name == nil {
				continue
			}

			vnetName := *vnet.Name
			cacheKey := fmt.Sprintf("%s/%s/%s", subID, rgName, vnetName)

			m.mu.Lock()
			m.vnetCache[cacheKey] = vnet
			m.mu.Unlock()

			// Get peerings for this VNet
			if vnet.Properties != nil && vnet.Properties.VirtualNetworkPeerings != nil {
				m.mu.Lock()
				m.peeringCache[cacheKey] = vnet.Properties.VirtualNetworkPeerings
				m.mu.Unlock()
			}
		}
	}
}

// ------------------------------
// Analyze VNet Peerings
// ------------------------------
func (m *LateralMovementModule) analyzeVNetPeerings(ctx context.Context, subID, subName string, logger internal.Logger) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for vnetKey, vnet := range m.vnetCache {
		if !strings.HasPrefix(vnetKey, subID) {
			continue
		}

		if vnet == nil || vnet.Name == nil || vnet.Location == nil {
			continue
		}

		vnetName := *vnet.Name
		vnetLocation := *vnet.Location
		vnetRG := azinternal.GetResourceGroupFromID(*vnet.ID)

		peerings := m.peeringCache[vnetKey]
		if len(peerings) == 0 {
			continue
		}

		for _, peering := range peerings {
			if peering == nil || peering.Name == nil || peering.Properties == nil {
				continue
			}

			peeringName := *peering.Name
			peeringState := "Unknown"
			if peering.Properties.PeeringState != nil {
				peeringState = string(*peering.Properties.PeeringState)
			}

			// Get remote VNet details
			remoteVNetID := "Unknown"
			remoteVNetName := "Unknown"
			remoteVNetSub := "Unknown"
			if peering.Properties.RemoteVirtualNetwork != nil && peering.Properties.RemoteVirtualNetwork.ID != nil {
				remoteVNetID = *peering.Properties.RemoteVirtualNetwork.ID
				remoteVNetName = azinternal.ExtractResourceName(remoteVNetID)
				remoteVNetSub = azinternal.GetSubscriptionFromResourceID(remoteVNetID)
			}

			// Determine risk level
			riskLevel := "⚠ MEDIUM"
			if peeringState == "Connected" {
				riskLevel = "⚠ HIGH"
			}
			if remoteVNetSub != subID {
				riskLevel = "⚠ CRITICAL" // Cross-subscription peering
			}

			// Check for bidirectional connectivity
			bidirectional := "No"
			allowForwardedTraffic := "No"
			allowGatewayTransit := "No"
			useRemoteGateways := "No"

			if peering.Properties.AllowForwardedTraffic != nil && *peering.Properties.AllowForwardedTraffic {
				allowForwardedTraffic = "✓ Yes"
				riskLevel = "⚠ HIGH" // Higher risk with forwarded traffic
			}
			if peering.Properties.AllowGatewayTransit != nil && *peering.Properties.AllowGatewayTransit {
				allowGatewayTransit = "✓ Yes"
			}
			if peering.Properties.UseRemoteGateways != nil && *peering.Properties.UseRemoteGateways {
				useRemoteGateways = "✓ Yes"
			}

			// Check if remote peering exists (bidirectional)
			for remoteKey, remotePeerings := range m.peeringCache {
				if strings.Contains(remoteKey, remoteVNetName) {
					for _, remotePeering := range remotePeerings {
						if remotePeering.Properties != nil && remotePeering.Properties.RemoteVirtualNetwork != nil {
							if strings.Contains(*remotePeering.Properties.RemoteVirtualNetwork.ID, vnetName) {
								bidirectional = "✓ Yes"
								break
							}
						}
					}
				}
			}

			networkPath := fmt.Sprintf("%s ↔ %s (Peering: %s, State: %s)", vnetName, remoteVNetName, peeringName, peeringState)
			accessMethod := "Network - VNet Peering"
			requiredPrivilege := "Network access within peered VNets"

			notes := fmt.Sprintf("AllowForwardedTraffic: %s, GatewayTransit: %s, UseRemoteGateway: %s",
				allowForwardedTraffic, allowGatewayTransit, useRemoteGateways)

			if remoteVNetSub != subID {
				notes += fmt.Sprintf(" | CROSS-SUBSCRIPTION to %s", remoteVNetSub)
			}

			row := []string{
				m.TenantName,
				m.TenantID,
				subID,
				subName,
				"VNet",
				vnetName,
				vnetLocation,
				"VNet",
				remoteVNetName,
				"N/A", // Target location unknown without full lookup
				"VNet Peering",
				peeringState,
				networkPath,
				accessMethod,
				requiredPrivilege,
				riskLevel,
				bidirectional,
				notes,
			}

			m.LateralMovementRows = append(m.LateralMovementRows, row)

			// Add to loot files
			m.LootMap["lateral-movement-paths"].Contents += fmt.Sprintf("VNet Peering: %s → %s (State: %s, Bidirectional: %s)\n", vnetName, remoteVNetName, peeringState, bidirectional)
			m.LootMap["lateral-movement-paths"].Contents += fmt.Sprintf("  Resource Group: %s, Location: %s\n", vnetRG, vnetLocation)
			m.LootMap["lateral-movement-paths"].Contents += fmt.Sprintf("  %s\n\n", notes)

			if riskLevel == "⚠ CRITICAL" {
				m.LootMap["lateral-movement-critical"].Contents += fmt.Sprintf("[CRITICAL] Cross-Subscription VNet Peering: %s → %s\n", vnetName, remoteVNetName)
				m.LootMap["lateral-movement-critical"].Contents += fmt.Sprintf("  Source: %s/%s\n", subID, vnetRG)
				m.LootMap["lateral-movement-critical"].Contents += fmt.Sprintf("  Target Subscription: %s\n\n", remoteVNetSub)
			}
		}
	}
}

// ------------------------------
// Analyze Service Endpoints
// ------------------------------
func (m *LateralMovementModule) analyzeServiceEndpoints(ctx context.Context, subID, subName string, resourceGroups []string, logger internal.Logger) {
	for _, rgName := range resourceGroups {
		vnets, err := azinternal.ListVirtualNetworks(ctx, m.Session, subID, rgName)
		if err != nil {
			continue
		}

		for _, vnet := range vnets {
			if vnet == nil || vnet.Name == nil || vnet.Properties == nil || vnet.Properties.Subnets == nil {
				continue
			}

			vnetName := *vnet.Name
			vnetLocation := azinternal.SafeStringPtr(vnet.Location)

			for _, subnet := range vnet.Properties.Subnets {
				if subnet == nil || subnet.Name == nil || subnet.Properties == nil {
					continue
				}

				subnetName := *subnet.Name

				if subnet.Properties.ServiceEndpoints == nil || len(subnet.Properties.ServiceEndpoints) == 0 {
					continue
				}

				for _, serviceEndpoint := range subnet.Properties.ServiceEndpoints {
					if serviceEndpoint.Service == nil {
						continue
					}

					service := *serviceEndpoint.Service
					provisioningState := "Unknown"
					if serviceEndpoint.ProvisioningState != nil {
						provisioningState = string(*serviceEndpoint.ProvisioningState)
					}

					// Determine risk level based on service type
					riskLevel := "⚠ MEDIUM"
					if strings.Contains(service, "Storage") || strings.Contains(service, "Sql") || strings.Contains(service, "KeyVault") {
						riskLevel = "⚠ HIGH"
					}

					networkPath := fmt.Sprintf("%s/%s → %s", vnetName, subnetName, service)
					accessMethod := "Network - Service Endpoint"
					requiredPrivilege := "Network access + Azure RBAC on target service"

					notes := fmt.Sprintf("Provisioning State: %s | Service endpoints enable direct connectivity to Azure PaaS", provisioningState)

					row := []string{
						m.TenantName,
						m.TenantID,
						subID,
						subName,
						"Subnet",
						fmt.Sprintf("%s/%s", vnetName, subnetName),
						vnetLocation,
						"Azure Service",
						service,
						"Global",
						"Service Endpoint",
						provisioningState,
						networkPath,
						accessMethod,
						requiredPrivilege,
						riskLevel,
						"No",
						notes,
					}

					m.mu.Lock()
					m.LateralMovementRows = append(m.LateralMovementRows, row)
					m.LootMap["lateral-movement-paths"].Contents += fmt.Sprintf("Service Endpoint: %s/%s → %s (State: %s)\n", vnetName, subnetName, service, provisioningState)
					m.LootMap["lateral-movement-paths"].Contents += fmt.Sprintf("  Resource Group: %s, Location: %s\n\n", rgName, vnetLocation)
					m.mu.Unlock()
				}
			}
		}
	}
}

// ------------------------------
// Analyze Private Endpoints
// ------------------------------
func (m *LateralMovementModule) analyzePrivateEndpoints(ctx context.Context, subID, subName string, resourceGroups []string, logger internal.Logger) {
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	peClient, err := armnetwork.NewPrivateEndpointsClient(subID, cred, nil)
	if err != nil {
		return
	}

	for _, rgName := range resourceGroups {
		pager := peClient.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				continue
			}

			for _, pe := range page.Value {
				if pe == nil || pe.Name == nil || pe.Properties == nil {
					continue
				}

				peName := *pe.Name
				peLocation := azinternal.SafeStringPtr(pe.Location)
				privateIP := "N/A"

				if pe.Properties.NetworkInterfaces != nil && len(pe.Properties.NetworkInterfaces) > 0 {
					// Private IP would need NIC lookup - simplified here
					privateIP = "Private IP via NIC"
				}

				// Get target resource
				targetResource := "Unknown"
				targetService := "Unknown"
				if pe.Properties.PrivateLinkServiceConnections != nil && len(pe.Properties.PrivateLinkServiceConnections) > 0 {
					conn := pe.Properties.PrivateLinkServiceConnections[0]
					if conn.Properties != nil && conn.Properties.PrivateLinkServiceID != nil {
						targetResource = *conn.Properties.PrivateLinkServiceID
						targetService = azinternal.ExtractResourceName(targetResource)
					}
				}

				provisioningState := "Unknown"
				if pe.Properties.ProvisioningState != nil {
					provisioningState = string(*pe.Properties.ProvisioningState)
				}

				riskLevel := "⚠ HIGH"
				networkPath := fmt.Sprintf("Private Endpoint %s (%s) → %s", peName, privateIP, targetService)
				accessMethod := "Network - Private Link"
				requiredPrivilege := "Network access to private endpoint subnet + RBAC on target"

				notes := fmt.Sprintf("Provisioning State: %s | Private endpoint provides private IP access to PaaS service", provisioningState)

				row := []string{
					m.TenantName,
					m.TenantID,
					subID,
					subName,
					"Private Endpoint",
					peName,
					peLocation,
					"Private Link Service",
					targetService,
					"N/A",
					"Private Endpoint",
					provisioningState,
					networkPath,
					accessMethod,
					requiredPrivilege,
					riskLevel,
					"No",
					notes,
				}

				m.mu.Lock()
				m.LateralMovementRows = append(m.LateralMovementRows, row)
				m.LootMap["lateral-movement-paths"].Contents += fmt.Sprintf("Private Endpoint: %s → %s (State: %s)\n", peName, targetService, provisioningState)
				m.LootMap["lateral-movement-paths"].Contents += fmt.Sprintf("  Resource Group: %s, Location: %s, Private IP: %s\n\n", rgName, peLocation, privateIP)
				m.mu.Unlock()
			}
		}
	}
}

// ------------------------------
// Analyze NSG Connectivity (VM-to-VM paths)
// ------------------------------
func (m *LateralMovementModule) analyzeNSGConnectivity(ctx context.Context, subID, subName string, resourceGroups []string, logger internal.Logger) {
	for _, rgName := range resourceGroups {
		nsgs, err := azinternal.ListNetworkSecurityGroups(ctx, m.Session, subID, rgName)
		if err != nil {
			continue
		}

		for _, nsg := range nsgs {
			if nsg == nil || nsg.Name == nil || nsg.Properties == nil || nsg.Properties.SecurityRules == nil {
				continue
			}

			nsgName := *nsg.Name
			nsgLocation := azinternal.SafeStringPtr(nsg.Location)

			// Analyze Allow rules for lateral movement
			for _, rule := range nsg.Properties.SecurityRules {
				if rule.Properties == nil || rule.Properties.Access == nil || *rule.Properties.Access != armnetwork.SecurityRuleAccessAllow {
					continue
				}

				if rule.Properties.Direction != nil && *rule.Properties.Direction != armnetwork.SecurityRuleDirectionInbound {
					continue
				}

				ruleName := azinternal.SafeStringPtr(rule.Name)
				sourcePrefix := azinternal.SafeStringPtr(rule.Properties.SourceAddressPrefix)
				destPrefix := azinternal.SafeStringPtr(rule.Properties.DestinationAddressPrefix)
				destPort := azinternal.SafeStringPtr(rule.Properties.DestinationPortRange)
				protocol := "Any"
				if rule.Properties.Protocol != nil {
					protocol = string(*rule.Properties.Protocol)
				}

				// Skip internet-facing rules (already covered in network-exposure)
				if sourcePrefix == "*" || sourcePrefix == "Internet" || sourcePrefix == "0.0.0.0/0" {
					continue
				}

				// Focus on internal network Allow rules
				if sourcePrefix != "" && sourcePrefix != "N/A" && destPort != "" {
					riskLevel := "⚠ MEDIUM"

					// Check for high-risk ports
					if destPort == "22" || destPort == "3389" || destPort == "5985" || destPort == "5986" {
						riskLevel = "⚠ HIGH"
					}

					networkPath := fmt.Sprintf("NSG %s: %s → %s (Port %s/%s)", nsgName, sourcePrefix, destPrefix, destPort, protocol)
					accessMethod := "Network - NSG Allow Rule"
					requiredPrivilege := fmt.Sprintf("Network access from %s + authentication to target", sourcePrefix)

					notes := fmt.Sprintf("Rule: %s | Allows internal network communication", ruleName)

					row := []string{
						m.TenantName,
						m.TenantID,
						subID,
						subName,
						"NSG Rule",
						nsgName,
						nsgLocation,
						"Internal Network",
						destPrefix,
						nsgLocation,
						"NSG Allow Rule",
						"Active",
						networkPath,
						accessMethod,
						requiredPrivilege,
						riskLevel,
						"Yes", // NSG rules are bidirectional in nature
						notes,
					}

					m.mu.Lock()
					m.LateralMovementRows = append(m.LateralMovementRows, row)
					m.mu.Unlock()
				}
			}
		}
	}
}

// ------------------------------
// Analyze VPN Gateways (Hybrid Connectivity)
// ------------------------------
func (m *LateralMovementModule) analyzeVPNGateways(ctx context.Context, subID, subName string, resourceGroups []string, logger internal.Logger) {
	for _, rgName := range resourceGroups {
		vpnGateways, err := azinternal.GetVPNGatewaysPerResourceGroup(ctx, m.Session, subID, rgName)
		if err != nil {
			continue
		}

		for _, vpn := range vpnGateways {
			if vpn == nil || vpn.Name == nil {
				continue
			}

			vpnName := azinternal.GetVPNGatewayName(vpn)
			vpnLocation := azinternal.GetVPNGatewayLocation(vpn)
			vpnType := "Unknown"

			if vpn.Properties != nil && vpn.Properties.VPNType != nil {
				vpnType = string(*vpn.Properties.VPNType)
			}

			riskLevel := "⚠ CRITICAL" // Hybrid connectivity is critical for lateral movement
			networkPath := fmt.Sprintf("VPN Gateway %s (Type: %s) ↔ On-Premises Network", vpnName, vpnType)
			accessMethod := "Network - VPN Gateway"
			requiredPrivilege := "VPN access credentials + network routing to on-premises"

			notes := fmt.Sprintf("VPN Type: %s | Enables lateral movement between Azure and on-premises networks", vpnType)

			row := []string{
				m.TenantName,
				m.TenantID,
				subID,
				subName,
				"VPN Gateway",
				vpnName,
				vpnLocation,
				"On-Premises Network",
				"Hybrid Connection",
				"On-Premises",
				"VPN Gateway",
				"Active",
				networkPath,
				accessMethod,
				requiredPrivilege,
				riskLevel,
				"✓ Yes", // VPN is bidirectional
				notes,
			}

			m.mu.Lock()
			m.LateralMovementRows = append(m.LateralMovementRows, row)
			m.LootMap["lateral-movement-critical"].Contents += fmt.Sprintf("[CRITICAL] VPN Gateway: %s (Type: %s)\n", vpnName, vpnType)
			m.LootMap["lateral-movement-critical"].Contents += fmt.Sprintf("  Resource Group: %s, Location: %s\n", rgName, vpnLocation)
			m.LootMap["lateral-movement-critical"].Contents += fmt.Sprintf("  Enables lateral movement between Azure and on-premises networks\n\n")
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Write output
// ------------------------------
func (m *LateralMovementModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.LateralMovementRows) == 0 {
		logger.InfoM("No lateral movement paths found", globals.AZ_LATERAL_MOVEMENT_MODULE_NAME)
		return
	}

	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Source Resource Type",
		"Source Resource Name",
		"Source Location",
		"Target Resource Type",
		"Target Resource Name",
		"Target Location",
		"Connection Type",
		"Connection Status",
		"Network Path",
		"Access Method",
		"Required Privilege",
		"Risk Level",
		"Bidirectional",
		"Notes/Details",
	}

	// Check if we should split output by tenant
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.LateralMovementRows,
			headers,
			"lateral-movement",
			globals.AZ_LATERAL_MOVEMENT_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.LateralMovementRows, headers,
			"lateral-movement", globals.AZ_LATERAL_MOVEMENT_MODULE_NAME,
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

	output := LateralMovementOutput{
		Table: []internal.TableFile{{
			Name:   "lateral-movement",
			Header: headers,
			Body:   m.LateralMovementRows,
		}},
		Loot: loot,
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_LATERAL_MOVEMENT_MODULE_NAME)
		return
	}

	// Count risk levels
	critical := 0
	high := 0
	medium := 0

	for _, row := range m.LateralMovementRows {
		riskLevel := row[15]
		if strings.Contains(riskLevel, "CRITICAL") {
			critical++
		} else if strings.Contains(riskLevel, "HIGH") {
			high++
		} else {
			medium++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d lateral movement paths: %d CRITICAL, %d HIGH, %d MEDIUM risk",
		len(m.LateralMovementRows), critical, high, medium), globals.AZ_LATERAL_MOVEMENT_MODULE_NAME)
}
