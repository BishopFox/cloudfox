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
var AzFirewallCommand = &cobra.Command{
	Use:     "firewall",
	Aliases: []string{"firewalls", "azfw"},
	Short:   "Enumerate Azure Firewalls and firewall rules",
	Long: `
Enumerate Azure Firewalls for a specific tenant:
./cloudfox az firewall --tenant TENANT_ID

Enumerate Azure Firewalls for a specific subscription:
./cloudfox az firewall --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListFirewall,
}

// ------------------------------
// Module struct
// ------------------------------
type FirewallModule struct {
	azinternal.BaseAzureModule

	Subscriptions []string
	FirewallRows  [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type FirewallOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o FirewallOutput) TableFiles() []internal.TableFile { return o.Table }
func (o FirewallOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListFirewall(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_FIREWALL_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &FirewallModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		FirewallRows:    [][]string{},
		LootMap: map[string]*internal.LootFile{
			"firewall-commands":       {Name: "firewall-commands", Contents: ""},
			"firewall-nat-rules":      {Name: "firewall-nat-rules", Contents: "# Azure Firewall NAT Rules (Public-Facing Services)\n\n"},
			"firewall-network-rules":  {Name: "firewall-network-rules", Contents: "# Azure Firewall Network Rules\n\n"},
			"firewall-app-rules":      {Name: "firewall-app-rules", Contents: "# Azure Firewall Application Rules\n\n"},
			"firewall-risks":          {Name: "firewall-risks", Contents: "# Azure Firewall Security Risks\n\n"},
			"firewall-targeted-scans": {Name: "firewall-targeted-scans", Contents: "# Targeted Scanning Commands Based on Firewall NAT Rules\n\n# These commands target public-facing services exposed via Azure Firewall DNAT rules.\n# Replace <TARGET_IP> with the firewall's public IP.\n\n"},
		},
	}

	module.PrintFirewall(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *FirewallModule) PrintFirewall(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_FIREWALL_MODULE_NAME)

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
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_FIREWALL_MODULE_NAME, m.processSubscription)

			// Restore original tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_FIREWALL_MODULE_NAME, m.processSubscription)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *FirewallModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	if len(rgs) == 0 {
		return
	}

	// Create Firewall client
	fwClient, err := azinternal.GetFirewallClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Firewall client for subscription %s: %v", subID, err), globals.AZ_FIREWALL_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Process each resource group
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, rg := range rgs {
		if rg.Name == nil {
			continue
		}
		rgName := *rg.Name

		wg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, fwClient, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *FirewallModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, fwClient *armnetwork.AzureFirewallsClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
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

	// List Firewalls in resource group
	pager := fwClient.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list Firewalls in %s/%s: %v", subID, rgName, err), globals.AZ_FIREWALL_MODULE_NAME)
			}
			m.CommandCounter.Error++
			continue
		}

		for _, fw := range page.Value {
			m.processFirewall(ctx, subID, subName, rgName, region, fw, logger)
		}
	}
}

// ------------------------------
// Process single Firewall
// ------------------------------
func (m *FirewallModule) processFirewall(ctx context.Context, subID, subName, rgName, region string, fw *armnetwork.AzureFirewall, logger internal.Logger) {
	if fw == nil || fw.Name == nil {
		return
	}

	fwName := *fw.Name

	// Get firewall SKU tier
	tier := "N/A"
	isPremium := false
	if fw.Properties != nil && fw.Properties.SKU != nil && fw.Properties.SKU.Tier != nil {
		tier = string(*fw.Properties.SKU.Tier)
		isPremium = (tier == "Premium")
	}

	// Get firewall policy ID
	policyID := "N/A"
	policyRGName := rgName // Default to same RG
	if fw.Properties != nil && fw.Properties.FirewallPolicy != nil && fw.Properties.FirewallPolicy.ID != nil {
		policyID = *fw.Properties.FirewallPolicy.ID
		// Extract policy resource group from ID if different
		// Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/firewallPolicies/{name}
		parts := strings.Split(policyID, "/")
		for i, part := range parts {
			if part == "resourceGroups" && i+1 < len(parts) {
				policyRGName = parts[i+1]
				break
			}
		}
	}

	// Get threat intel mode
	threatIntelMode := "N/A"
	if fw.Properties != nil && fw.Properties.ThreatIntelMode != nil {
		threatIntelMode = string(*fw.Properties.ThreatIntelMode)
	}

	// Initialize Premium feature fields
	idpsMode := "N/A"
	idpsSignatureOverrides := "N/A"
	tlsInspectionEnabled := "No"
	dnsProxyEnabled := "No"
	premiumFeatures := "None"

	// Fetch firewall policy for Premium features (IDPS, TLS Inspection, DNS Proxy)
	if policyID != "N/A" {
		policyName := azinternal.ExtractResourceName(policyID)
		if policyName != "" {
			policy, err := m.getFirewallPolicy(ctx, subID, policyRGName, policyName)
			if err == nil && policy != nil && policy.Properties != nil {
				// IDPS Mode
				if policy.Properties.IntrusionDetection != nil {
					if policy.Properties.IntrusionDetection.Mode != nil {
						idpsMode = string(*policy.Properties.IntrusionDetection.Mode)
					}
					// IDPS Signature Overrides
					if policy.Properties.IntrusionDetection.Configuration != nil && policy.Properties.IntrusionDetection.Configuration.SignatureOverrides != nil {
						overrideCount := len(policy.Properties.IntrusionDetection.Configuration.SignatureOverrides)
						if overrideCount > 0 {
							idpsSignatureOverrides = fmt.Sprintf("%d overrides", overrideCount)
						} else {
							idpsSignatureOverrides = "Default signatures"
						}
					}
				}

				// TLS Inspection
				if policy.Properties.TransportSecurity != nil && policy.Properties.TransportSecurity.CertificateAuthority != nil {
					tlsInspectionEnabled = "✓ Yes"
				}

				// DNS Proxy
				if policy.Properties.DNSSettings != nil && policy.Properties.DNSSettings.EnableProxy != nil {
					if *policy.Properties.DNSSettings.EnableProxy {
						dnsProxyEnabled = "✓ Yes"
					}
				}

				// Premium Features Summary
				premiumFeaturesArr := []string{}
				if idpsMode != "N/A" && idpsMode != "Off" {
					premiumFeaturesArr = append(premiumFeaturesArr, fmt.Sprintf("IDPS:%s", idpsMode))
				}
				if tlsInspectionEnabled == "✓ Yes" {
					premiumFeaturesArr = append(premiumFeaturesArr, "TLS Inspection")
				}
				if dnsProxyEnabled == "✓ Yes" {
					premiumFeaturesArr = append(premiumFeaturesArr, "DNS Proxy")
				}
				if len(premiumFeaturesArr) > 0 {
					premiumFeatures = strings.Join(premiumFeaturesArr, ", ")
				}
			}
		}
	}

	// Check if Premium SKU but not using Premium features
	if isPremium && premiumFeatures == "None" {
		m.mu.Lock()
		m.LootMap["firewall-risks"].Contents += fmt.Sprintf("⚠️  CONFIGURATION WARNING: Firewall %s/%s\n", rgName, fwName)
		m.LootMap["firewall-risks"].Contents += fmt.Sprintf("  Premium SKU but no Premium features enabled (IDPS, TLS Inspection, DNS Proxy)\n")
		m.LootMap["firewall-risks"].Contents += fmt.Sprintf("  Consider downgrading to Standard SKU to reduce costs, or enable Premium features\n")
		m.LootMap["firewall-risks"].Contents += fmt.Sprintf("  Subscription: %s\n\n", subName)
		m.mu.Unlock()
	}

	// Get public IPs
	publicIPs := []string{}
	if fw.Properties != nil && fw.Properties.IPConfigurations != nil {
		for _, ipConfig := range fw.Properties.IPConfigurations {
			if ipConfig != nil && ipConfig.Properties != nil && ipConfig.Properties.PublicIPAddress != nil && ipConfig.Properties.PublicIPAddress.ID != nil {
				publicIPs = append(publicIPs, *ipConfig.Properties.PublicIPAddress.ID)
			}
		}
	}
	publicIPsStr := strings.Join(publicIPs, ", ")
	if publicIPsStr == "" {
		publicIPsStr = "N/A"
	}

	// Process NAT rules (Classic rules - deprecated but still in use)
	natRuleCount := 0
	if fw.Properties != nil && fw.Properties.NatRuleCollections != nil {
		natRuleCount = len(fw.Properties.NatRuleCollections)
		m.processNATRules(subID, subName, rgName, fwName, fw.Properties.NatRuleCollections)
	}

	// Process network rules (Classic rules)
	networkRuleCount := 0
	if fw.Properties != nil && fw.Properties.NetworkRuleCollections != nil {
		networkRuleCount = len(fw.Properties.NetworkRuleCollections)
		m.processNetworkRules(subID, subName, rgName, fwName, fw.Properties.NetworkRuleCollections)
	}

	// Process application rules (Classic rules)
	appRuleCount := 0
	if fw.Properties != nil && fw.Properties.ApplicationRuleCollections != nil {
		appRuleCount = len(fw.Properties.ApplicationRuleCollections)
		m.processApplicationRules(subID, subName, rgName, fwName, fw.Properties.ApplicationRuleCollections)
	}

	row := []string{
		m.TenantName, // NEW: for multi-tenant support
		m.TenantID,   // NEW: for multi-tenant support
		subID,
		subName,
		rgName,
		region,
		fwName,
		tier,
		policyID,
		threatIntelMode,
		publicIPsStr,
		fmt.Sprintf("%d", natRuleCount),
		fmt.Sprintf("%d", networkRuleCount),
		fmt.Sprintf("%d", appRuleCount),
		idpsMode,               // NEW: IDPS Mode
		idpsSignatureOverrides, // NEW: IDPS Signature Overrides
		tlsInspectionEnabled,   // NEW: TLS Inspection
		dnsProxyEnabled,        // NEW: DNS Proxy
		premiumFeatures,        // NEW: Premium Features Summary
	}

	m.mu.Lock()
	m.FirewallRows = append(m.FirewallRows, row)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Generate Azure CLI commands
	m.mu.Lock()
	m.LootMap["firewall-commands"].Contents += fmt.Sprintf("# Firewall: %s (Resource Group: %s, Tier: %s)\n", fwName, rgName, tier)
	m.LootMap["firewall-commands"].Contents += fmt.Sprintf("az account set --subscription %s\n", subID)
	m.LootMap["firewall-commands"].Contents += fmt.Sprintf("az network firewall show --name %s --resource-group %s\n", fwName, rgName)
	if policyID != "N/A" {
		policyName := azinternal.ExtractResourceName(policyID)
		if policyName != "" {
			m.LootMap["firewall-commands"].Contents += fmt.Sprintf("az network firewall policy show --name %s --resource-group %s\n", policyName, policyRGName)
			if isPremium {
				m.LootMap["firewall-commands"].Contents += fmt.Sprintf("# Premium Features:\n")
				m.LootMap["firewall-commands"].Contents += fmt.Sprintf("az network firewall policy intrusion-detection list --policy-name %s --resource-group %s\n", policyName, policyRGName)
			}
		}
	}
	m.LootMap["firewall-commands"].Contents += "\n"
	m.mu.Unlock()
}

// ------------------------------
// Get Firewall Policy for Premium features analysis
// ------------------------------
func (m *FirewallModule) getFirewallPolicy(ctx context.Context, subID, rgName, policyName string) (*armnetwork.FirewallPolicy, error) {
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return nil, err
	}

	cred := &azinternal.StaticTokenCredential{Token: token}
	policyClient, err := armnetwork.NewFirewallPoliciesClient(subID, cred, nil)
	if err != nil {
		return nil, err
	}

	resp, err := policyClient.Get(ctx, rgName, policyName, &armnetwork.FirewallPoliciesClientGetOptions{
		Expand: nil,
	})
	if err != nil {
		return nil, err
	}

	return &resp.FirewallPolicy, nil
}

// ------------------------------
// Process NAT rules
// ------------------------------
func (m *FirewallModule) processNATRules(subID, subName, rgName, fwName string, collections []*armnetwork.AzureFirewallNatRuleCollection) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, coll := range collections {
		if coll == nil || coll.Name == nil || coll.Properties == nil || coll.Properties.Rules == nil {
			continue
		}

		collName := *coll.Name
		priority := "N/A"
		if coll.Properties.Priority != nil {
			priority = fmt.Sprintf("%d", *coll.Properties.Priority)
		}

		for _, rule := range coll.Properties.Rules {
			if rule == nil || rule.Name == nil {
				continue
			}

			ruleName := *rule.Name
			sourceAddrs := strings.Join(azinternal.SafeStringSlice(rule.SourceAddresses), ", ")
			destAddrs := strings.Join(azinternal.SafeStringSlice(rule.DestinationAddresses), ", ")
			destPorts := strings.Join(azinternal.SafeStringSlice(rule.DestinationPorts), ", ")
			protocols := []string{}
			for _, p := range rule.Protocols {
				if p != nil {
					protocols = append(protocols, string(*p))
				}
			}
			protocolsStr := strings.Join(protocols, ", ")
			translatedAddr := azinternal.SafeStringPtr(rule.TranslatedAddress)
			translatedPort := azinternal.SafeStringPtr(rule.TranslatedPort)

			m.LootMap["firewall-nat-rules"].Contents += fmt.Sprintf("Firewall: %s/%s\n", rgName, fwName)
			m.LootMap["firewall-nat-rules"].Contents += fmt.Sprintf("  Collection: %s (Priority: %s)\n", collName, priority)
			m.LootMap["firewall-nat-rules"].Contents += fmt.Sprintf("  Rule: %s\n", ruleName)
			m.LootMap["firewall-nat-rules"].Contents += fmt.Sprintf("  Source: %s\n", sourceAddrs)
			m.LootMap["firewall-nat-rules"].Contents += fmt.Sprintf("  Destination: %s:%s\n", destAddrs, destPorts)
			m.LootMap["firewall-nat-rules"].Contents += fmt.Sprintf("  Protocols: %s\n", protocolsStr)
			m.LootMap["firewall-nat-rules"].Contents += fmt.Sprintf("  Translated To: %s:%s\n", translatedAddr, translatedPort)
			m.LootMap["firewall-nat-rules"].Contents += fmt.Sprintf("  Subscription: %s\n\n", subName)

			// Check for security risks
			if sourceAddrs == "*" || strings.Contains(sourceAddrs, "0.0.0.0/0") {
				m.LootMap["firewall-risks"].Contents += fmt.Sprintf("🚨 HIGH RISK: NAT Rule %s/%s - %s/%s\n", rgName, fwName, collName, ruleName)
				m.LootMap["firewall-risks"].Contents += fmt.Sprintf("  ⚠️  Allows traffic from ANY source (Internet)\n")
				m.LootMap["firewall-risks"].Contents += fmt.Sprintf("  Destination: %s:%s → %s:%s\n", destAddrs, destPorts, translatedAddr, translatedPort)
				m.LootMap["firewall-risks"].Contents += fmt.Sprintf("  Subscription: %s\n\n", subName)
			}

			// Generate targeted scanning commands for NAT rules (public-facing services)
			m.generateNATTargetedScans(fwName, ruleName, destAddrs, destPorts, translatedPort)
		}
	}
}

// ------------------------------
// Generate targeted scanning commands for NAT rules
// ------------------------------
func (m *FirewallModule) generateNATTargetedScans(fwName, ruleName, publicIP, publicPorts, translatedPort string) {
	m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("# Firewall: %s - NAT Rule: %s\n", fwName, ruleName)
	m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("# Public IP: %s | Public Ports: %s | Backend Port: %s\n", publicIP, publicPorts, translatedPort)

	// Parse ports
	ports := strings.Split(publicPorts, ",")
	for _, p := range ports {
		port := strings.TrimSpace(p)

		switch port {
		case "22":
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("# SSH via Firewall NAT (Port 22)\n")
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("ssh <username>@%s\n", publicIP)
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("nmap -p 22 -sV --script ssh-auth-methods,ssh-hostkey %s\n\n", publicIP)

		case "3389":
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("# RDP via Firewall NAT (Port 3389)\n")
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("xfreerdp /v:%s /u:<username>\n", publicIP)
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("nmap -p 3389 -sV --script rdp-enum-encryption %s\n\n", publicIP)

		case "80":
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("# HTTP via Firewall NAT (Port 80)\n")
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("curl -i http://%s\n", publicIP)
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("nmap -p 80 -sV --script http-enum,http-headers %s\n\n", publicIP)

		case "443":
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("# HTTPS via Firewall NAT (Port 443)\n")
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("curl -ik https://%s\n", publicIP)
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("nmap -p 443 -sV --script ssl-cert,ssl-enum-ciphers %s\n\n", publicIP)

		case "1433", "3306", "5432", "27017":
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("# DATABASE via Firewall NAT (Port %s) - HIGH RISK\n", port)
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("nmap -p %s -sV %s\n", port, publicIP)
			m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("# ⚠️  Database port exposed via firewall - investigate immediately!\n\n")

		default:
			if port != "" && port != "N/A" {
				m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("# Port %s via Firewall NAT\n", port)
				m.LootMap["firewall-targeted-scans"].Contents += fmt.Sprintf("nmap -p %s -sV -sC %s\n\n", port, publicIP)
			}
		}
	}
}

// ------------------------------
// Process Network rules
// ------------------------------
func (m *FirewallModule) processNetworkRules(subID, subName, rgName, fwName string, collections []*armnetwork.AzureFirewallNetworkRuleCollection) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, coll := range collections {
		if coll == nil || coll.Name == nil || coll.Properties == nil || coll.Properties.Rules == nil {
			continue
		}

		collName := *coll.Name
		priority := "N/A"
		if coll.Properties.Priority != nil {
			priority = fmt.Sprintf("%d", *coll.Properties.Priority)
		}

		action := "N/A"
		if coll.Properties.Action != nil && coll.Properties.Action.Type != nil {
			action = string(*coll.Properties.Action.Type)
		}

		for _, rule := range coll.Properties.Rules {
			if rule == nil || rule.Name == nil {
				continue
			}

			ruleName := *rule.Name
			sourceAddrs := strings.Join(azinternal.SafeStringSlice(rule.SourceAddresses), ", ")
			destAddrs := strings.Join(azinternal.SafeStringSlice(rule.DestinationAddresses), ", ")
			destPorts := strings.Join(azinternal.SafeStringSlice(rule.DestinationPorts), ", ")
			protocols := []string{}
			for _, p := range rule.Protocols {
				if p != nil {
					protocols = append(protocols, string(*p))
				}
			}
			protocolsStr := strings.Join(protocols, ", ")

			m.LootMap["firewall-network-rules"].Contents += fmt.Sprintf("Firewall: %s/%s\n", rgName, fwName)
			m.LootMap["firewall-network-rules"].Contents += fmt.Sprintf("  Collection: %s (Priority: %s, Action: %s)\n", collName, priority, action)
			m.LootMap["firewall-network-rules"].Contents += fmt.Sprintf("  Rule: %s\n", ruleName)
			m.LootMap["firewall-network-rules"].Contents += fmt.Sprintf("  Source: %s\n", sourceAddrs)
			m.LootMap["firewall-network-rules"].Contents += fmt.Sprintf("  Destination: %s:%s\n", destAddrs, destPorts)
			m.LootMap["firewall-network-rules"].Contents += fmt.Sprintf("  Protocols: %s\n", protocolsStr)
			m.LootMap["firewall-network-rules"].Contents += fmt.Sprintf("  Subscription: %s\n\n", subName)

			// Check for overly permissive rules
			if action == "Allow" && (sourceAddrs == "*" || strings.Contains(sourceAddrs, "0.0.0.0/0")) && (destPorts == "*" || destAddrs == "*") {
				m.LootMap["firewall-risks"].Contents += fmt.Sprintf("🚨 MEDIUM RISK: Network Rule %s/%s - %s/%s\n", rgName, fwName, collName, ruleName)
				m.LootMap["firewall-risks"].Contents += fmt.Sprintf("  ⚠️  Overly permissive rule (ANY source to ANY destination/port)\n")
				m.LootMap["firewall-risks"].Contents += fmt.Sprintf("  Source: %s → Destination: %s:%s\n", sourceAddrs, destAddrs, destPorts)
				m.LootMap["firewall-risks"].Contents += fmt.Sprintf("  Subscription: %s\n\n", subName)
			}
		}
	}
}

// ------------------------------
// Process Application rules
// ------------------------------
func (m *FirewallModule) processApplicationRules(subID, subName, rgName, fwName string, collections []*armnetwork.AzureFirewallApplicationRuleCollection) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, coll := range collections {
		if coll == nil || coll.Name == nil || coll.Properties == nil || coll.Properties.Rules == nil {
			continue
		}

		collName := *coll.Name
		priority := "N/A"
		if coll.Properties.Priority != nil {
			priority = fmt.Sprintf("%d", *coll.Properties.Priority)
		}

		action := "N/A"
		if coll.Properties.Action != nil && coll.Properties.Action.Type != nil {
			action = string(*coll.Properties.Action.Type)
		}

		for _, rule := range coll.Properties.Rules {
			if rule == nil || rule.Name == nil {
				continue
			}

			ruleName := *rule.Name
			sourceAddrs := strings.Join(azinternal.SafeStringSlice(rule.SourceAddresses), ", ")

			protocols := []string{}
			if rule.Protocols != nil {
				for _, p := range rule.Protocols {
					if p != nil && p.ProtocolType != nil {
						port := "N/A"
						if p.Port != nil {
							port = fmt.Sprintf("%d", *p.Port)
						}
						protocols = append(protocols, fmt.Sprintf("%s:%s", string(*p.ProtocolType), port))
					}
				}
			}
			protocolsStr := strings.Join(protocols, ", ")

			targetFQDNs := strings.Join(azinternal.SafeStringSlice(rule.TargetFqdns), ", ")

			m.LootMap["firewall-app-rules"].Contents += fmt.Sprintf("Firewall: %s/%s\n", rgName, fwName)
			m.LootMap["firewall-app-rules"].Contents += fmt.Sprintf("  Collection: %s (Priority: %s, Action: %s)\n", collName, priority, action)
			m.LootMap["firewall-app-rules"].Contents += fmt.Sprintf("  Rule: %s\n", ruleName)
			m.LootMap["firewall-app-rules"].Contents += fmt.Sprintf("  Source: %s\n", sourceAddrs)
			m.LootMap["firewall-app-rules"].Contents += fmt.Sprintf("  Target FQDNs: %s\n", targetFQDNs)
			m.LootMap["firewall-app-rules"].Contents += fmt.Sprintf("  Protocols: %s\n", protocolsStr)
			m.LootMap["firewall-app-rules"].Contents += fmt.Sprintf("  Subscription: %s\n\n", subName)

			// Check for wildcard FQDNs
			if action == "Allow" && (strings.Contains(targetFQDNs, "*") || targetFQDNs == "") {
				m.LootMap["firewall-risks"].Contents += fmt.Sprintf("🚨 MEDIUM RISK: Application Rule %s/%s - %s/%s\n", rgName, fwName, collName, ruleName)
				m.LootMap["firewall-risks"].Contents += fmt.Sprintf("  ⚠️  Wildcard or empty FQDN target\n")
				m.LootMap["firewall-risks"].Contents += fmt.Sprintf("  Target: %s\n", targetFQDNs)
				m.LootMap["firewall-risks"].Contents += fmt.Sprintf("  Subscription: %s\n\n", subName)
			}
		}
	}
}

// ------------------------------
// Write output
// ------------------------------
func (m *FirewallModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.FirewallRows) == 0 {
		logger.InfoM("No Azure Firewalls found", globals.AZ_FIREWALL_MODULE_NAME)
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
		"Firewall Name",
		"SKU Tier",
		"Firewall Policy ID",
		"Threat Intel Mode",
		"Public IPs",
		"NAT Rule Collections",
		"Network Rule Collections",
		"App Rule Collections",
		"IDPS Mode",                // NEW: Intrusion Detection/Prevention mode
		"IDPS Signature Overrides", // NEW: Custom IDPS signatures
		"TLS Inspection",           // NEW: TLS/SSL inspection enabled
		"DNS Proxy",                // NEW: DNS proxy enabled
		"Premium Features",         // NEW: Summary of Premium features
	}

	// Check if we should split output by tenant first, then subscription
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.FirewallRows, headers,
			"firewall", globals.AZ_FIREWALL_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.FirewallRows, headers,
			"firewall", globals.AZ_FIREWALL_MODULE_NAME,
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
	output := FirewallOutput{
		Table: []internal.TableFile{{
			Name:   "firewall",
			Header: headers,
			Body:   m.FirewallRows,
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_FIREWALL_MODULE_NAME)
		return
	}

	// Print summary
	logger.InfoM(fmt.Sprintf("Found %d Azure Firewalls across %d subscriptions", len(m.FirewallRows), len(m.Subscriptions)), globals.AZ_FIREWALL_MODULE_NAME)
}
