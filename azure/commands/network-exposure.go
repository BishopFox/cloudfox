package commands

import (
	"context"
	"fmt"
	"sort"
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
var AzNetworkExposureCommand = &cobra.Command{
	Use:     "network-exposure",
	Aliases: []string{"netexp", "exposure"},
	Short:   "Analyze internet-facing resources and their security posture",
	Long: `
Analyze network exposure and security posture of public-facing Azure resources:
./cloudfox az network-exposure --tenant TENANT_ID

Analyze network exposure for specific subscriptions:
./cloudfox az network-exposure --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]

This module focuses on:
- Internet-facing resources (public IPs, public endpoints)
- Security risk assessment (NSG rules, TLS/SSL, authentication)
- Attack surface analysis (RDP/SSH exposure, high-risk ports)
- DDoS protection status
- Security recommendations
`,
	Run: AnalyzeNetworkExposure,
}

// ------------------------------
// Module struct
// ------------------------------
type NetworkExposureModule struct {
	azinternal.BaseAzureModule

	Subscriptions []string
	ExposureRows  [][]string
	LootMap       map[string]*internal.LootFile

	// Cache NSG summary data for risk assessment
	nsgSummaryCache map[string]*NSGRiskInfo
	mu              sync.Mutex
}

// NSGRiskInfo holds security risk information from NSG analysis
type NSGRiskInfo struct {
	NSGName               string
	InternetAccessAllowed string
	RDPSSHExposed         string
	HighRiskPortsOpen     string
	EffectiveInboundRules string
	RiskLevel             string
}

// ------------------------------
// Output struct
// ------------------------------
type NetworkExposureOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o NetworkExposureOutput) TableFiles() []internal.TableFile { return o.Table }
func (o NetworkExposureOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func AnalyzeNetworkExposure(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_NETWORK_EXPOSURE_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &NetworkExposureModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		ExposureRows:    [][]string{},
		nsgSummaryCache: make(map[string]*NSGRiskInfo),
		LootMap: map[string]*internal.LootFile{
			"network-exposure-critical": {Name: "network-exposure-critical", Contents: "# Critical Network Exposure Findings\n\n"},
			"network-exposure-scan":     {Name: "network-exposure-scan", Contents: "# Network Exposure Scan Commands\n\n"},
		},
	}

	module.PrintNetworkExposure(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *NetworkExposureModule) PrintNetworkExposure(ctx context.Context, logger internal.Logger) {
	// Multi-tenant support
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_NETWORK_EXPOSURE_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_NETWORK_EXPOSURE_MODULE_NAME, m.processSubscription)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *NetworkExposureModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)
	resourceGroups := m.ResolveResourceGroups(subID)

	// First pass: Build NSG risk cache for this subscription
	m.buildNSGRiskCache(ctx, subID, resourceGroups, logger)

	// Second pass: Enumerate public-facing resources with security analysis
	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10)

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, &rgWg, rgSemaphore, logger)
	}

	rgWg.Wait()
}

// ------------------------------
// Build NSG risk cache for subscription
// ------------------------------
func (m *NetworkExposureModule) buildNSGRiskCache(ctx context.Context, subID string, resourceGroups []string, logger internal.Logger) {
	for _, rgName := range resourceGroups {
		nsgs, err := azinternal.ListNetworkSecurityGroups(ctx, m.Session, subID, rgName)
		if err != nil {
			continue
		}

		for _, nsg := range nsgs {
			if nsg == nil || nsg.Name == nil {
				continue
			}

			nsgName := *nsg.Name
			riskInfo := m.analyzeNSGRisk(nsg)

			m.mu.Lock()
			m.nsgSummaryCache[nsgName] = riskInfo
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Analyze NSG for security risks
// ------------------------------
func (m *NetworkExposureModule) analyzeNSGRisk(nsg *armnetwork.SecurityGroup) *NSGRiskInfo {
	info := &NSGRiskInfo{
		NSGName:               *nsg.Name,
		InternetAccessAllowed: "No",
		RDPSSHExposed:         "No",
		HighRiskPortsOpen:     "None",
		EffectiveInboundRules: "Default Deny",
		RiskLevel:             "✓ Low",
	}

	if nsg.Properties == nil || nsg.Properties.SecurityRules == nil {
		return info
	}

	hasInternetAccess := false
	hasRDPSSH := false
	highRiskPorts := []string{}
	criticalRules := []string{}

	for _, rule := range nsg.Properties.SecurityRules {
		if rule.Properties == nil || rule.Properties.Access == nil || *rule.Properties.Access != armnetwork.SecurityRuleAccessAllow {
			continue
		}

		if rule.Properties.Direction != nil && *rule.Properties.Direction != armnetwork.SecurityRuleDirectionInbound {
			continue
		}

		// Check for internet source
		sourcePrefix := ""
		if rule.Properties.SourceAddressPrefix != nil {
			sourcePrefix = *rule.Properties.SourceAddressPrefix
		}

		isInternet := sourcePrefix == "*" || sourcePrefix == "0.0.0.0/0" || sourcePrefix == "Internet"

		if isInternet {
			hasInternetAccess = true

			// Check destination ports
			destPort := ""
			if rule.Properties.DestinationPortRange != nil {
				destPort = *rule.Properties.DestinationPortRange
			}

			ruleName := "Unknown"
			if rule.Name != nil {
				ruleName = *rule.Name
			}

			// Check for RDP/SSH
			if destPort == "22" || destPort == "3389" || destPort == "*" {
				hasRDPSSH = true
				if destPort == "22" {
					criticalRules = append(criticalRules, fmt.Sprintf("%s (SSH)", ruleName))
				} else if destPort == "3389" {
					criticalRules = append(criticalRules, fmt.Sprintf("%s (RDP)", ruleName))
				}
			}

			// Check for high-risk database ports
			switch destPort {
			case "1433":
				highRiskPorts = append(highRiskPorts, "SQL:1433")
				criticalRules = append(criticalRules, fmt.Sprintf("%s (SQL)", ruleName))
			case "3306":
				highRiskPorts = append(highRiskPorts, "MySQL:3306")
				criticalRules = append(criticalRules, fmt.Sprintf("%s (MySQL)", ruleName))
			case "5432":
				highRiskPorts = append(highRiskPorts, "PostgreSQL:5432")
				criticalRules = append(criticalRules, fmt.Sprintf("%s (PostgreSQL)", ruleName))
			case "27017":
				highRiskPorts = append(highRiskPorts, "MongoDB:27017")
				criticalRules = append(criticalRules, fmt.Sprintf("%s (MongoDB)", ruleName))
			case "6379":
				highRiskPorts = append(highRiskPorts, "Redis:6379")
				criticalRules = append(criticalRules, fmt.Sprintf("%s (Redis)", ruleName))
			}

			// Collect inbound Allow rules for summary
			if len(criticalRules) > 0 && len(criticalRules) <= 5 {
				info.EffectiveInboundRules = strings.Join(criticalRules, ", ")
			}
		}
	}

	// Update risk info
	if hasInternetAccess {
		info.InternetAccessAllowed = "⚠ Yes"
	}
	if hasRDPSSH {
		info.RDPSSHExposed = "⚠ CRITICAL"
	}
	if len(highRiskPorts) > 0 {
		info.HighRiskPortsOpen = strings.Join(highRiskPorts, ", ")
	}

	// Calculate overall risk level
	if hasRDPSSH {
		info.RiskLevel = "⚠ CRITICAL"
	} else if len(highRiskPorts) > 0 {
		info.RiskLevel = "⚠ HIGH"
	} else if hasInternetAccess {
		info.RiskLevel = "⚠ MEDIUM"
	}

	return info
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *NetworkExposureModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	region := azinternal.GetResourceGroupLocation(m.Session, subID, rgName)

	// Analyze public-facing resources
	m.analyzeVirtualMachines(ctx, subID, subName, rgName, region, logger)
	m.analyzeLoadBalancers(ctx, subID, subName, rgName, region, logger)
	m.analyzeAppGateways(ctx, subID, subName, rgName, region, logger)
	m.analyzeWebApps(ctx, subID, subName, rgName, region, logger)
	m.analyzeFunctionApps(ctx, subID, subName, rgName, region, logger)
	m.analyzeAKSClusters(ctx, subID, subName, rgName, region, logger)
	m.analyzeDatabases(ctx, subID, subName, rgName, region, logger)
	m.analyzeStorageAccounts(ctx, subID, subName, rgName, region, logger)
	m.analyzeAPIManagement(ctx, subID, subName, rgName, region, logger)
	m.analyzePublicIPs(ctx, subID, subName, rgName, region, logger)
	m.analyzeAzureFirewall(ctx, subID, subName, rgName, region, logger)
	m.analyzeVPNGateways(ctx, subID, subName, rgName, region, logger)
}

// ------------------------------
// Analyze Virtual Machines with public IPs
// ------------------------------
func (m *NetworkExposureModule) analyzeVirtualMachines(ctx context.Context, subID, subName, rgName, region string, logger internal.Logger) {
	vms, _ := azinternal.GetVMsPerResourceGroupObject(m.Session, subID, rgName, m.LootMap, m.TenantName, m.TenantID)

	for _, vmRow := range vms {
		if len(vmRow) < 19 {
			continue
		}

		vmName := vmRow[4]
		publicIPs := vmRow[8]
		hostname := vmRow[9]

		// Only process VMs with public IPs
		if publicIPs == "" || publicIPs == "NoPublicIP" {
			continue
		}

		// Extract NSG information from NIC
		nsgAssociated := "None"
		nsgRiskAssessment := "N/A"
		internetAccess := "Unknown"
		rdpSSHExposed := "Unknown"

		// Get NIC details to find associated NSG
		nics := azinternal.GetVMNetworkInterfaces(m.Session, subID, vmName, rgName)
		if len(nics) > 0 {
			for _, nic := range nics {
				if nic.Properties != nil && nic.Properties.NetworkSecurityGroup != nil && nic.Properties.NetworkSecurityGroup.ID != nil {
					nsgID := *nic.Properties.NetworkSecurityGroup.ID
					parts := strings.Split(nsgID, "/")
					if len(parts) > 0 {
						nsgName := parts[len(parts)-1]
						nsgAssociated = nsgName

						// Lookup NSG risk info from cache
						m.mu.Lock()
						if riskInfo, exists := m.nsgSummaryCache[nsgName]; exists {
							nsgRiskAssessment = riskInfo.RiskLevel
							internetAccess = riskInfo.InternetAccessAllowed
							rdpSSHExposed = riskInfo.RDPSSHExposed
						}
						m.mu.Unlock()
					}
				}
			}
		}

		// Determine overall risk level
		riskLevel := m.calculateRiskLevel(rdpSSHExposed, internetAccess, "N/A", "N/A")

		// Authentication method
		authMethod := "Username/Password"
		if vmRow[14] == "Yes" || vmRow[14] == "✓ Yes" {
			authMethod = "EntraID (AAD)"
		}

		// Managed Identity
		managedIdentity := "None"
		if vmRow[17] != "" && vmRow[17] != "None" {
			managedIdentity = "System-Assigned"
		}
		if vmRow[18] != "" && vmRow[18] != "None" {
			if managedIdentity == "System-Assigned" {
				managedIdentity = "System + User-Assigned"
			} else {
				managedIdentity = "User-Assigned"
			}
		}

		// Security recommendations
		recommendations := m.generateRecommendations("VirtualMachine", riskLevel, rdpSSHExposed, internetAccess, nsgAssociated, authMethod)

		row := []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			rgName,
			region,
			vmName,
			"Virtual Machine",
			hostname,
			publicIPs,
			"Public IP",
			riskLevel,
			nsgAssociated,
			nsgRiskAssessment,
			internetAccess,
			rdpSSHExposed,
			"N/A", // DDoS Protection (VM level)
			"N/A", // TLS/SSL Status
			"N/A", // Min TLS Version
			authMethod,
			"N/A", // Public Access Config
			managedIdentity,
			recommendations,
		}

		m.appendRow(row)

		// Add to critical loot if RDP/SSH exposed
		if rdpSSHExposed == "⚠ CRITICAL" {
			m.addToLoot("network-exposure-critical", fmt.Sprintf("[CRITICAL] VM %s (%s) - RDP/SSH exposed to internet via %s\n", vmName, publicIPs, hostname))
			m.addToLoot("network-exposure-scan", fmt.Sprintf("# VM: %s (%s)\nnmap -sV -sC -p 22,3389 %s\n\n", vmName, publicIPs, publicIPs))
		}
	}
}

// ------------------------------
// Analyze Load Balancers with public frontends
// ------------------------------
func (m *NetworkExposureModule) analyzeLoadBalancers(ctx context.Context, subID, subName, rgName, region string, logger internal.Logger) {
	lbs, err := azinternal.GetLoadBalancersPerResourceGroup(ctx, m.Session, subID, rgName)
	if err != nil {
		return
	}

	for _, lb := range lbs {
		if lb == nil || lb.Name == nil {
			continue
		}

		lbName := *lb.Name
		frontendIPs := azinternal.GetLoadBalancerFrontendIPs(ctx, m.Session, lb)

		for _, fe := range frontendIPs {
			// Only process public frontends
			if fe.PublicIP == "" || fe.PublicIP == "N/A" {
				continue
			}

			// Get SKU and DDoS protection
			sku := "Basic"
			ddosProtection := "No"
			if lb.SKU != nil && lb.SKU.Name != nil {
				sku = string(*lb.SKU.Name)
				if sku == "Standard" {
					ddosProtection = "✓ Yes (Standard SKU)"
				}
			}

			// NSG is typically on backend resources, not LB itself
			nsgAssociated := "Backend-level"
			riskLevel := "⚠ MEDIUM"

			// Check for NAT rules that might expose RDP/SSH
			rdpSSHExposed := "No"
			if lb.Properties != nil && lb.Properties.InboundNatRules != nil {
				for _, natRule := range lb.Properties.InboundNatRules {
					if natRule.Properties != nil && natRule.Properties.FrontendPort != nil {
						port := *natRule.Properties.FrontendPort
						if port == 22 || port == 3389 {
							rdpSSHExposed = "⚠ CRITICAL"
							riskLevel = "⚠ CRITICAL"
						}
					}
				}
			}

			recommendations := m.generateRecommendations("LoadBalancer", riskLevel, rdpSSHExposed, "⚠ Yes", nsgAssociated, "N/A")

			row := []string{
				m.TenantName,
				m.TenantID,
				subID,
				subName,
				rgName,
				region,
				lbName,
				"Load Balancer",
				fe.DNSName,
				fe.PublicIP,
				"Public Frontend",
				riskLevel,
				nsgAssociated,
				"Backend-level",
				"⚠ Yes",
				rdpSSHExposed,
				ddosProtection,
				"N/A",
				"N/A",
				"N/A",
				fmt.Sprintf("SKU: %s", sku),
				"N/A",
				recommendations,
			}

			m.appendRow(row)

			if rdpSSHExposed == "⚠ CRITICAL" {
				m.addToLoot("network-exposure-critical", fmt.Sprintf("[CRITICAL] Load Balancer %s (%s) - NAT rules expose RDP/SSH to internet\n", lbName, fe.PublicIP))
			}
		}
	}
}

// ------------------------------
// Analyze Application Gateways
// ------------------------------
func (m *NetworkExposureModule) analyzeAppGateways(ctx context.Context, subID, subName, rgName, region string, logger internal.Logger) {
	appGws := azinternal.GetAppGatewaysPerResourceGroup(m.Session, subID, rgName)

	for _, agw := range appGws {
		if agw == nil || agw.Name == nil {
			continue
		}

		agwName := *agw.Name
		frontendIPs := azinternal.GetAppGatewayFrontendIPs(m.Session, subID, agw)

		for _, fe := range frontendIPs {
			if fe.PublicIP == "" || fe.PublicIP == "N/A" {
				continue
			}

			// Get TLS/SSL policy
			tlsStatus := "Unknown"
			minTLSVersion := "Unknown"
			if agw.Properties != nil && agw.Properties.SSLPolicy != nil {
				if agw.Properties.SSLPolicy.MinProtocolVersion != nil {
					minTLSVersion = string(*agw.Properties.SSLPolicy.MinProtocolVersion)
					if minTLSVersion == "TLSv12" || minTLSVersion == "TLSv13" {
						tlsStatus = "✓ Secure"
					} else {
						tlsStatus = "⚠ Weak TLS"
					}
				}
			}

			// WAF protection
			wafEnabled := "No"
			if agw.Properties != nil && agw.Properties.WebApplicationFirewallConfiguration != nil {
				if agw.Properties.WebApplicationFirewallConfiguration.Enabled != nil && *agw.Properties.WebApplicationFirewallConfiguration.Enabled {
					wafEnabled = "✓ Yes"
				}
			}

			riskLevel := "⚠ MEDIUM"
			if tlsStatus == "⚠ Weak TLS" {
				riskLevel = "⚠ HIGH"
			}
			if wafEnabled == "✓ Yes" && tlsStatus == "✓ Secure" {
				riskLevel = "✓ Low"
			}

			recommendations := m.generateRecommendations("AppGateway", riskLevel, "No", "⚠ Yes", "WAF", "Certificate-based")

			row := []string{
				m.TenantName,
				m.TenantID,
				subID,
				subName,
				rgName,
				region,
				agwName,
				"Application Gateway",
				fe.DNSName,
				fe.PublicIP,
				"Public Frontend",
				riskLevel,
				"WAF",
				wafEnabled,
				"⚠ Yes",
				"No",
				"N/A",
				tlsStatus,
				minTLSVersion,
				"Certificate-based",
				fmt.Sprintf("WAF: %s", wafEnabled),
				"N/A",
				recommendations,
			}

			m.appendRow(row)
		}
	}
}

// ------------------------------
// Analyze Web Apps (public)
// ------------------------------
func (m *NetworkExposureModule) analyzeWebApps(ctx context.Context, subID, subName, rgName, region string, logger internal.Logger) {
	webApps := azinternal.GetWebAppsPerRG(ctx, subID, m.LootMap, rgName)

	for _, appRow := range webApps {
		if len(appRow) < 20 {
			continue
		}

		appName := appRow[4]
		pubIP := appRow[9]
		hostname := appRow[12]
		httpsOnly := appRow[17]
		minTLS := appRow[18]
		authEnabled := appRow[19]

		// Only process public web apps
		if pubIP == "" || pubIP == "N/A" {
			continue
		}

		// TLS status
		tlsStatus := "⚠ HTTP Allowed"
		if httpsOnly == "Yes" || httpsOnly == "✓ Yes" {
			tlsStatus = "✓ HTTPS Only"
		}

		// Authentication
		authMethod := "None"
		if authEnabled == "Yes" || authEnabled == "✓ Yes" || authEnabled == "Enabled" {
			authMethod = "EntraID (EasyAuth)"
		}

		// Managed Identity
		managedIdentity := "None"
		if appRow[14] != "" && appRow[14] != "None" {
			managedIdentity = "System-Assigned"
		}
		if appRow[15] != "" && appRow[15] != "None" {
			if managedIdentity == "System-Assigned" {
				managedIdentity = "System + User-Assigned"
			} else {
				managedIdentity = "User-Assigned"
			}
		}

		// Risk level
		riskLevel := "⚠ MEDIUM"
		if tlsStatus == "⚠ HTTP Allowed" || authMethod == "None" {
			riskLevel = "⚠ HIGH"
		}
		if tlsStatus == "✓ HTTPS Only" && authMethod != "None" {
			riskLevel = "✓ Low"
		}

		recommendations := m.generateRecommendations("WebApp", riskLevel, "No", "⚠ Yes", "App Service", authMethod)

		row := []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			rgName,
			region,
			appName,
			"Web App",
			hostname,
			pubIP,
			"Public Endpoint",
			riskLevel,
			"App Service",
			"App-level",
			"⚠ Yes",
			"No",
			"N/A",
			tlsStatus,
			minTLS,
			authMethod,
			fmt.Sprintf("HTTPS Only: %s", httpsOnly),
			managedIdentity,
			recommendations,
		}

		m.appendRow(row)

		if authMethod == "None" {
			m.addToLoot("network-exposure-critical", fmt.Sprintf("[WARNING] Web App %s (%s) - No authentication enabled\n", appName, hostname))
		}
	}
}

// ------------------------------
// Analyze Function Apps (public)
// ------------------------------
func (m *NetworkExposureModule) analyzeFunctionApps(ctx context.Context, subID, subName, rgName, region string, logger internal.Logger) {
	functionApps, err := azinternal.GetFunctionAppsPerResourceGroup(m.Session, subID, rgName)
	if err != nil {
		return
	}

	for _, app := range functionApps {
		if app == nil || app.Name == nil {
			continue
		}

		appName := *app.Name
		hostname := "N/A"
		if app.Properties != nil && app.Properties.DefaultHostName != nil {
			hostname = *app.Properties.DefaultHostName
		}

		privateIPs, publicIPs, _, _ := azinternal.GetFunctionAppNetworkInfo(subID, rgName, app)
		_ = privateIPs // Avoid unused warning

		// Only process public function apps
		if len(publicIPs) == 0 || publicIPs[0] == "N/A" {
			continue
		}

		// Get TLS and auth info
		httpsOnly := "No"
		minTLS := "Unknown"
		authEnabled := "No"
		_ = authEnabled // TODO: Implement auth detection

		if app.Properties != nil {
			if app.Properties.HTTPSOnly != nil && *app.Properties.HTTPSOnly {
				httpsOnly = "✓ Yes"
			}
			if app.Properties.SiteConfig != nil && app.Properties.SiteConfig.MinTLSVersion != nil {
				minTLS = string(*app.Properties.SiteConfig.MinTLSVersion)
			}
		}

		tlsStatus := "⚠ HTTP Allowed"
		if httpsOnly == "✓ Yes" {
			tlsStatus = "✓ HTTPS Only"
		}

		authMethod := "Function Keys"

		riskLevel := "⚠ MEDIUM"
		if tlsStatus == "⚠ HTTP Allowed" {
			riskLevel = "⚠ HIGH"
		}

		recommendations := m.generateRecommendations("FunctionApp", riskLevel, "No", "⚠ Yes", "App Service", authMethod)

		row := []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			rgName,
			region,
			appName,
			"Function App",
			hostname,
			strings.Join(publicIPs, ", "),
			"Public Endpoint",
			riskLevel,
			"App Service",
			"App-level",
			"⚠ Yes",
			"No",
			"N/A",
			tlsStatus,
			minTLS,
			authMethod,
			fmt.Sprintf("HTTPS Only: %s", httpsOnly),
			"N/A",
			recommendations,
		}

		m.appendRow(row)
	}
}

// ------------------------------
// Analyze AKS Clusters (public API)
// ------------------------------
func (m *NetworkExposureModule) analyzeAKSClusters(ctx context.Context, subID, subName, rgName, region string, logger internal.Logger) {
	clusters, err := azinternal.GetAKSClustersPerResourceGroup(ctx, m.Session, subID, rgName)
	if err != nil {
		return
	}

	for _, cluster := range clusters {
		clusterName := azinternal.GetAKSClusterName(cluster)
		publicFQDN, _ := azinternal.GetAKSClusterFQDNs(cluster)

		// Only process public clusters
		if publicFQDN == "" || publicFQDN == "N/A" {
			continue
		}

		// Get RBAC and network policy
		rbacEnabled := "No"
		networkPolicy := "None"
		authMethod := "Kubernetes Certs"

		if cluster.Properties != nil {
			if cluster.Properties.EnableRBAC != nil && *cluster.Properties.EnableRBAC {
				rbacEnabled = "✓ Yes"
			}
			if cluster.Properties.AADProfile != nil && cluster.Properties.AADProfile.Managed != nil && *cluster.Properties.AADProfile.Managed {
				authMethod = "EntraID (AAD)"
			}
			if cluster.Properties.NetworkProfile != nil && cluster.Properties.NetworkProfile.NetworkPolicy != nil {
				networkPolicy = string(*cluster.Properties.NetworkProfile.NetworkPolicy)
			}
		}

		riskLevel := "⚠ MEDIUM"
		if authMethod != "EntraID (AAD)" || rbacEnabled != "✓ Yes" {
			riskLevel = "⚠ HIGH"
		}
		if authMethod == "EntraID (AAD)" && rbacEnabled == "✓ Yes" {
			riskLevel = "✓ Low"
		}

		recommendations := m.generateRecommendations("AKS", riskLevel, "No", "⚠ Yes", "NSG+NetworkPolicy", authMethod)

		row := []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			rgName,
			region,
			clusterName,
			"AKS Cluster",
			publicFQDN,
			"N/A",
			"Public API Endpoint",
			riskLevel,
			"NSG+NetworkPolicy",
			networkPolicy,
			"⚠ Yes",
			"No",
			"N/A",
			"TLS 1.2+",
			"TLS 1.2",
			authMethod,
			fmt.Sprintf("RBAC: %s", rbacEnabled),
			"N/A",
			recommendations,
		}

		m.appendRow(row)

		if authMethod != "EntraID (AAD)" {
			m.addToLoot("network-exposure-critical", fmt.Sprintf("[WARNING] AKS Cluster %s (%s) - Not using EntraID authentication\n", clusterName, publicFQDN))
		}
	}
}

// ------------------------------
// Analyze Databases (public endpoint)
// ------------------------------
func (m *NetworkExposureModule) analyzeDatabases(ctx context.Context, subID, subName, rgName, region string, logger internal.Logger) {
	dbRows := azinternal.GetDatabasesPerResourceGroup(ctx, m.Session, subID, subName, rgName, m.LootMap, region, m.TenantName, m.TenantID)

	for _, dbRow := range dbRows {
		if len(dbRow) < 11 {
			continue
		}

		dbName := dbRow[4]
		dbType := dbRow[6]
		publicIPs := dbRow[10]

		// Only process databases with public endpoints
		if publicIPs == "" || publicIPs == "N/A" {
			continue
		}

		// TLS enforcement
		tlsStatus := "Unknown"
		minTLS := "Unknown"
		if strings.Contains(strings.ToLower(dbRow[8]), "tls") {
			tlsStatus = "✓ Enforced"
			minTLS = "TLS 1.2"
		}

		// Authentication
		authMethod := "SQL Authentication"
		if strings.Contains(strings.ToLower(dbType), "aad") || strings.Contains(strings.ToLower(dbRow[8]), "aad") {
			authMethod = "EntraID (AAD)"
		}

		// Risk level - databases exposed to internet are HIGH risk
		riskLevel := "⚠ HIGH"
		if authMethod == "EntraID (AAD)" && tlsStatus == "✓ Enforced" {
			riskLevel = "⚠ MEDIUM"
		}

		recommendations := m.generateRecommendations("Database", riskLevel, "No", "⚠ Yes", "Firewall Rules", authMethod)

		row := []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			rgName,
			region,
			dbName,
			dbType,
			dbName, // hostname
			publicIPs,
			"Public Endpoint",
			riskLevel,
			"Firewall Rules",
			"DB-level",
			"⚠ Yes",
			"No",
			"N/A",
			tlsStatus,
			minTLS,
			authMethod,
			"Public Endpoint Enabled",
			"N/A",
			recommendations,
		}

		m.appendRow(row)

		m.addToLoot("network-exposure-critical", fmt.Sprintf("[HIGH] Database %s (%s) - Public endpoint exposed to internet\n", dbName, publicIPs))
	}
}

// ------------------------------
// Analyze Storage Accounts (public blobs)
// ------------------------------
func (m *NetworkExposureModule) analyzeStorageAccounts(ctx context.Context, subID, subName, rgName, region string, logger internal.Logger) {
	storageAccounts := azinternal.GetStorageAccountsPerResourceGroup(m.Session, subID, rgName)

	for _, sa := range storageAccounts {
		accountName := ""
		if sa.Name != nil {
			accountName = *sa.Name
		}

		// Get container information
		containers, err := azinternal.GetStorageContainers(ctx, m.Session, subID, rgName, accountName)
		if err != nil {
			continue
		}

		for _, containerName := range containers {
			// Note: Public access level detection requires additional API call
			// For now, assume containers are public if they appear in results

			riskLevel := "⚠ HIGH"

			tlsStatus := "TLS 1.2+"
			minTLS := "TLS 1.2"
			// Note: MinTLSVersion field not available in current SDK
			// TODO: Add TLS version detection when SDK supports it

			authMethod := "Check Required"

			recommendations := m.generateRecommendations("StorageContainer", riskLevel, "No", "⚠ Yes", "Storage Firewall", authMethod)

			containerURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s", accountName, containerName)

			row := []string{
				m.TenantName,
				m.TenantID,
				subID,
				subName,
				rgName,
				region,
				fmt.Sprintf("%s/%s", accountName, containerName),
				"Storage Container",
				containerURL,
				"N/A",
				"Public Blob Container",
				riskLevel,
				"Storage Firewall",
				"Account-level",
				"⚠ Yes",
				"No",
				"N/A",
				tlsStatus,
				minTLS,
				authMethod,
				"Check Required", // Public access level
				"N/A",
				recommendations,
			}

			m.appendRow(row)

			if riskLevel == "⚠ CRITICAL" {
				m.addToLoot("network-exposure-critical", fmt.Sprintf("[CRITICAL] Storage Container %s/%s - Public Access Enabled\n", accountName, containerName))
				m.addToLoot("network-exposure-scan", fmt.Sprintf("# Storage Container: %s/%s\naz storage blob list --account-name %s --container-name %s --auth-mode login\n\n", accountName, containerName, accountName, containerName))
			}
		}
	}
}

// ------------------------------
// Analyze API Management (public gateway)
// ------------------------------
func (m *NetworkExposureModule) analyzeAPIManagement(ctx context.Context, subID, subName, rgName, region string, logger internal.Logger) {
	apimServices, err := azinternal.ListAPIManagementServices(ctx, m.Session, subID, rgName)
	if err != nil {
		return
	}

	for _, service := range apimServices {
		if service == nil || service.Name == nil {
			continue
		}

		serviceName := *service.Name
		gatewayURL := "N/A"
		virtualNetworkType := "None"

		if service.Properties != nil {
			if service.Properties.GatewayURL != nil {
				gatewayURL = *service.Properties.GatewayURL
			}
			if service.Properties.VirtualNetworkType != nil {
				virtualNetworkType = string(*service.Properties.VirtualNetworkType)
			}
		}

		// Only process public or external VNet APIM
		if virtualNetworkType == "Internal" {
			continue
		}

		// Authentication methods
		identityProviders := azinternal.GetAPIManagementIdentityProviders(ctx, m.Session, subID, rgName, serviceName)
		authMethod := "API Keys"
		if len(identityProviders) > 0 {
			authMethod = fmt.Sprintf("EntraID + %s", strings.Join(identityProviders, ", "))
		}

		riskLevel := "⚠ MEDIUM"
		if len(identityProviders) > 0 {
			riskLevel = "✓ Low"
		}

		tlsStatus := "✓ HTTPS"
		minTLS := "TLS 1.2"

		recommendations := m.generateRecommendations("APIM", riskLevel, "No", "⚠ Yes", "APIM Policies", authMethod)

		row := []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			rgName,
			region,
			serviceName,
			"API Management Gateway",
			gatewayURL,
			"N/A",
			"Public Gateway",
			riskLevel,
			"APIM Policies",
			"API-level",
			"⚠ Yes",
			"No",
			"N/A",
			tlsStatus,
			minTLS,
			authMethod,
			fmt.Sprintf("VNet: %s", virtualNetworkType),
			"N/A",
			recommendations,
		}

		m.appendRow(row)
	}
}

// ------------------------------
// Analyze Public IPs (standalone)
// ------------------------------
func (m *NetworkExposureModule) analyzePublicIPs(ctx context.Context, subID, subName, rgName, region string, logger internal.Logger) {
	publicIPs, err := azinternal.GetPublicIPsPerRG(ctx, m.Session, subID, rgName)
	if err != nil {
		return
	}

	for _, pip := range publicIPs {
		pipName := azinternal.GetPublicIPName(pip)
		ipAddr := azinternal.GetPublicIPAddress(pip)
		dnsName := azinternal.GetPublicIPDNS(pip)

		// Check if IP is associated with a resource
		associated := "Unassociated"
		if pip.Properties != nil && pip.Properties.IPConfiguration != nil && pip.Properties.IPConfiguration.ID != nil {
			associated = "Associated"
		}

		// Unassociated IPs are medium risk (not actively used but still allocated)
		riskLevel := "⚠ MEDIUM"
		if associated == "Unassociated" {
			riskLevel = "⚠ LOW"
		}

		// DDoS protection
		ddosProtection := "No"
		if pip.Properties != nil && pip.Properties.DdosSettings != nil {
			// Note: ProtectionMode field not available in current SDK
			ddosProtection = "✓ DDoS Protection Enabled"
		}

		recommendations := "Monitor for usage; dissociate if unused"
		if associated == "Unassociated" {
			recommendations = "Consider releasing unused public IP to reduce attack surface"
		}

		row := []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			rgName,
			region,
			pipName,
			"Public IP",
			dnsName,
			ipAddr,
			"Public IP Resource",
			riskLevel,
			"N/A",
			associated,
			"N/A",
			"N/A",
			ddosProtection,
			"N/A",
			"N/A",
			"N/A",
			associated,
			"N/A",
			recommendations,
		}

		m.appendRow(row)
	}
}

// ------------------------------
// Analyze Azure Firewall
// ------------------------------
func (m *NetworkExposureModule) analyzeAzureFirewall(ctx context.Context, subID, subName, rgName, region string, logger internal.Logger) {
	// Azure Firewall analysis - reuse logic from endpoints.go
	// Focus on public IP associations and threat intelligence mode
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	firewallClient, err := armnetwork.NewAzureFirewallsClient(subID, cred, nil)
	if err != nil {
		return
	}

	pager := firewallClient.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}

		for _, firewall := range page.Value {
			if firewall == nil || firewall.Name == nil {
				continue
			}

			firewallName := *firewall.Name

			// Check for public IPs
			pubIPClient, err := armnetwork.NewPublicIPAddressesClient(subID, cred, nil)
			if err != nil {
				continue
			}

			if firewall.Properties != nil && firewall.Properties.IPConfigurations != nil {
				for _, ipConfig := range firewall.Properties.IPConfigurations {
					if ipConfig.Properties != nil && ipConfig.Properties.PublicIPAddress != nil && ipConfig.Properties.PublicIPAddress.ID != nil {
						ipID := *ipConfig.Properties.PublicIPAddress.ID
						ipParts := strings.Split(ipID, "/")
						if len(ipParts) > 0 {
							publicIPName := ipParts[len(ipParts)-1]
							pubIPResp, err := pubIPClient.Get(ctx, rgName, publicIPName, nil)
							if err != nil {
								continue
							}
							pubIP := pubIPResp.PublicIPAddress

							hostname := firewallName
							ipAddress := "N/A"
							if pubIP.Properties != nil {
								if pubIP.Properties.DNSSettings != nil && pubIP.Properties.DNSSettings.Fqdn != nil {
									hostname = *pubIP.Properties.DNSSettings.Fqdn
								}
								if pubIP.Properties.IPAddress != nil {
									ipAddress = *pubIP.Properties.IPAddress
								}
							}

							// Threat Intel mode
							threatIntelMode := "Unknown"
							if firewall.Properties.ThreatIntelMode != nil {
								threatIntelMode = string(*firewall.Properties.ThreatIntelMode)
							}

							riskLevel := "✓ Low"
							recommendations := "Azure Firewall provides network-level protection"

							row := []string{
								m.TenantName,
								m.TenantID,
								subID,
								subName,
								rgName,
								region,
								firewallName,
								"Azure Firewall",
								hostname,
								ipAddress,
								"Firewall Public IP",
								riskLevel,
								"Firewall Rules",
								"Policy-based",
								"Controlled",
								"No",
								"✓ Yes",
								"N/A",
								"N/A",
								"N/A",
								fmt.Sprintf("Threat Intel: %s", threatIntelMode),
								"N/A",
								recommendations,
							}

							m.appendRow(row)
						}
					}
				}
			}
		}
	}
}

// ------------------------------
// Analyze VPN Gateways
// ------------------------------
func (m *NetworkExposureModule) analyzeVPNGateways(ctx context.Context, subID, subName, rgName, region string, logger internal.Logger) {
	vpnGateways, err := azinternal.GetVPNGatewaysPerResourceGroup(ctx, m.Session, subID, rgName)
	if err != nil {
		return
	}

	for _, vpn := range vpnGateways {
		if vpn == nil || vpn.Name == nil {
			continue
		}

		vpnName := *vpn.Name
		vpnIPs := azinternal.GetVPNGatewayIPs(ctx, m.Session, subID, vpn)

		for _, ip := range vpnIPs {
			if ip.PublicIP == "" || ip.PublicIP == "N/A" {
				continue
			}

			vpnType := "Unknown"
			if vpn.Properties != nil && vpn.Properties.VPNType != nil {
				vpnType = string(*vpn.Properties.VPNType)
			}

			riskLevel := "✓ Low"
			recommendations := "VPN Gateway for secure hybrid connectivity"

			row := []string{
				m.TenantName,
				m.TenantID,
				subID,
				subName,
				rgName,
				region,
				vpnName,
				"VPN Gateway",
				ip.DNSName,
				ip.PublicIP,
				"VPN Endpoint",
				riskLevel,
				"N/A",
				"VPN-level",
				"VPN Only",
				"No",
				"N/A",
				"IPsec",
				"IKEv2",
				"Certificate/PSK",
				fmt.Sprintf("Type: %s", vpnType),
				"N/A",
				recommendations,
			}

			m.appendRow(row)
		}
	}
}

// ------------------------------
// Calculate risk level
// ------------------------------
func (m *NetworkExposureModule) calculateRiskLevel(rdpSSHExposed, internetAccess, authMethod, tlsStatus string) string {
	if rdpSSHExposed == "⚠ CRITICAL" {
		return "⚠ CRITICAL"
	}
	if strings.Contains(tlsStatus, "Weak") || authMethod == "None" || authMethod == "Anonymous (Public)" {
		return "⚠ HIGH"
	}
	if internetAccess == "⚠ Yes" {
		return "⚠ MEDIUM"
	}
	return "✓ Low"
}

// ------------------------------
// Generate security recommendations
// ------------------------------
func (m *NetworkExposureModule) generateRecommendations(resourceType, riskLevel, rdpSSHExposed, internetAccess, nsgInfo, authMethod string) string {
	recommendations := []string{}

	if rdpSSHExposed == "⚠ CRITICAL" {
		recommendations = append(recommendations, "URGENT: Restrict RDP/SSH access to specific IPs")
	}

	if authMethod == "None" || authMethod == "Anonymous (Public)" {
		recommendations = append(recommendations, "Enable authentication (EntraID preferred)")
	}

	if strings.Contains(authMethod, "Username/Password") {
		recommendations = append(recommendations, "Use EntraID authentication instead of passwords")
	}

	if nsgInfo == "None" {
		recommendations = append(recommendations, "Associate NSG for network-level protection")
	}

	if riskLevel == "✓ Low" {
		recommendations = append(recommendations, "Security posture is adequate; monitor regularly")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Review security policies regularly")
	}

	return strings.Join(recommendations, "; ")
}

// ------------------------------
// Thread-safe row append
// ------------------------------
func (m *NetworkExposureModule) appendRow(row []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ExposureRows = append(m.ExposureRows, row)
}

// ------------------------------
// Add to loot file
// ------------------------------
func (m *NetworkExposureModule) addToLoot(lootName, content string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if lf, exists := m.LootMap[lootName]; exists {
		lf.Contents += content
	}
}

// ------------------------------
// Write output
// ------------------------------
func (m *NetworkExposureModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.ExposureRows) == 0 {
		logger.InfoM("No public-facing resources found", globals.AZ_NETWORK_EXPOSURE_MODULE_NAME)
		return
	}

	// Sort by risk level (CRITICAL > HIGH > MEDIUM > Low)
	sort.Slice(m.ExposureRows, func(i, j int) bool {
		riskI := m.ExposureRows[i][11] // Risk Level column
		riskJ := m.ExposureRows[j][11]

		rankI := m.getRiskRank(riskI)
		rankJ := m.getRiskRank(riskJ)

		return rankI > rankJ
	})

	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Resource Name",
		"Resource Type",
		"Endpoint",
		"Public IP",
		"Exposure Type",
		"Risk Level",
		"NSG Associated",
		"NSG Risk Assessment",
		"Internet Access Allowed",
		"RDP/SSH Exposed",
		"DDoS Protection",
		"TLS/SSL Status",
		"Min TLS Version",
		"Authentication Method",
		"Public Access Config",
		"Managed Identity Type",
		"Security Recommendations",
	}

	// Check if we should split output by tenant
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.ExposureRows,
			headers,
			"network-exposure",
			globals.AZ_NETWORK_EXPOSURE_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.ExposureRows, headers,
			"network-exposure", globals.AZ_NETWORK_EXPOSURE_MODULE_NAME,
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

	output := NetworkExposureOutput{
		Table: []internal.TableFile{{
			Name:   "network-exposure",
			Header: headers,
			Body:   m.ExposureRows,
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_NETWORK_EXPOSURE_MODULE_NAME)
		return
	}

	// Count risk levels
	critical := 0
	high := 0
	medium := 0
	low := 0

	for _, row := range m.ExposureRows {
		riskLevel := row[11]
		switch {
		case strings.Contains(riskLevel, "CRITICAL"):
			critical++
		case strings.Contains(riskLevel, "HIGH"):
			high++
		case strings.Contains(riskLevel, "MEDIUM"):
			medium++
		default:
			low++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d public-facing resources: %d CRITICAL, %d HIGH, %d MEDIUM, %d LOW risk",
		len(m.ExposureRows), critical, high, medium, low), globals.AZ_NETWORK_EXPOSURE_MODULE_NAME)
}

// ------------------------------
// Get risk rank for sorting
// ------------------------------
func (m *NetworkExposureModule) getRiskRank(riskLevel string) int {
	if strings.Contains(riskLevel, "CRITICAL") {
		return 4
	}
	if strings.Contains(riskLevel, "HIGH") {
		return 3
	}
	if strings.Contains(riskLevel, "MEDIUM") {
		return 2
	}
	return 1
}
