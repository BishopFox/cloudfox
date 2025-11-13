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
var AzNSGCommand = &cobra.Command{
	Use:     "nsg",
	Aliases: []string{"network-security-groups", "nsgs"},
	Short:   "Enumerate Azure Network Security Groups and rules",
	Long: `
Enumerate Azure Network Security Groups for a specific tenant:
./cloudfox az nsg --tenant TENANT_ID

Enumerate Azure Network Security Groups for a specific subscription:
./cloudfox az nsg --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListNSG,
}

// ------------------------------
// Module struct
// ------------------------------
type NSGModule struct {
	azinternal.BaseAzureModule

	Subscriptions  []string
	NSGRows        [][]string
	NSGSummaryRows [][]string // NEW: Per-NSG summary with effective rules
	LootMap        map[string]*internal.LootFile
	mu             sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type NSGOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o NSGOutput) TableFiles() []internal.TableFile { return o.Table }
func (o NSGOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListNSG(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_NSG_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &NSGModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		NSGRows:         [][]string{},
		NSGSummaryRows:  [][]string{}, // NEW: Effective rules summary
		LootMap: map[string]*internal.LootFile{
			"nsg-commands":        {Name: "nsg-commands", Contents: ""},
			"nsg-open-ports":      {Name: "nsg-open-ports", Contents: "# NSG Rules Allowing Inbound Traffic\n\n"},
			"nsg-security-risks":  {Name: "nsg-security-risks", Contents: "# NSG Security Risks\n\n"},
			"nsg-targeted-scans":  {Name: "nsg-targeted-scans", Contents: "# Targeted Network Scanning Commands Based on NSG Rules\n\n# Use these commands to scan specific open ports discovered in NSG rules.\n# Replace <TARGET_IP> with the actual public IP or hostname.\n\n"},
			"nsg-effective-rules": {Name: "nsg-effective-rules", Contents: "# NSG Effective Security Rules Analysis\n\n"}, // NEW
		},
	}

	module.PrintNSG(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *NSGModule) PrintNSG(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_NSG_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_NSG_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_NSG_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating Network Security Groups for %d subscription(s)", len(m.Subscriptions)), globals.AZ_NSG_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_NSG_MODULE_NAME, m.processSubscription)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *NSGModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	if len(rgs) == 0 {
		return
	}

	// Create NSG client
	nsgClient, err := azinternal.GetNSGClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create NSG client for subscription %s: %v", subID, err), globals.AZ_NSG_MODULE_NAME)
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
		go m.processResourceGroup(ctx, subID, subName, rgName, nsgClient, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *NSGModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, nsgClient *armnetwork.SecurityGroupsClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
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

	// List NSGs in resource group
	pager := nsgClient.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list NSGs in %s/%s: %v", subID, rgName, err), globals.AZ_NSG_MODULE_NAME)
			}
			m.CommandCounter.Error++
			continue
		}

		for _, nsg := range page.Value {
			m.processNSG(ctx, subID, subName, rgName, region, nsg, logger)
		}
	}
}

// ------------------------------
// Process single NSG
// ------------------------------
func (m *NSGModule) processNSG(ctx context.Context, subID, subName, rgName, region string, nsg *armnetwork.SecurityGroup, logger internal.Logger) {
	if nsg == nil || nsg.Name == nil {
		return
	}

	nsgName := *nsg.Name

	// Process security rules
	if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
		for _, rule := range nsg.Properties.SecurityRules {
			if rule == nil || rule.Name == nil || rule.Properties == nil {
				continue
			}

			ruleName := *rule.Name
			priority := "N/A"
			if rule.Properties.Priority != nil {
				priority = fmt.Sprintf("%d", *rule.Properties.Priority)
			}

			direction := "N/A"
			if rule.Properties.Direction != nil {
				direction = string(*rule.Properties.Direction)
			}

			access := "N/A"
			if rule.Properties.Access != nil {
				access = string(*rule.Properties.Access)
			}

			protocol := "N/A"
			if rule.Properties.Protocol != nil {
				protocol = string(*rule.Properties.Protocol)
			}

			srcPrefix := azinternal.SafeStringPtr(rule.Properties.SourceAddressPrefix)
			srcPort := azinternal.SafeStringPtr(rule.Properties.SourcePortRange)
			dstPrefix := azinternal.SafeStringPtr(rule.Properties.DestinationAddressPrefix)
			dstPort := azinternal.SafeStringPtr(rule.Properties.DestinationPortRange)

			// Handle source address prefixes (array)
			if rule.Properties.SourceAddressPrefixes != nil && len(rule.Properties.SourceAddressPrefixes) > 0 {
				srcPrefix = strings.Join(azinternal.SafeStringSlice(rule.Properties.SourceAddressPrefixes), ", ")
			}

			// Handle destination address prefixes (array)
			if rule.Properties.DestinationAddressPrefixes != nil && len(rule.Properties.DestinationAddressPrefixes) > 0 {
				dstPrefix = strings.Join(azinternal.SafeStringSlice(rule.Properties.DestinationAddressPrefixes), ", ")
			}

			// Handle source port ranges (array)
			if rule.Properties.SourcePortRanges != nil && len(rule.Properties.SourcePortRanges) > 0 {
				srcPort = strings.Join(azinternal.SafeStringSlice(rule.Properties.SourcePortRanges), ", ")
			}

			// Handle destination port ranges (array)
			if rule.Properties.DestinationPortRanges != nil && len(rule.Properties.DestinationPortRanges) > 0 {
				dstPort = strings.Join(azinternal.SafeStringSlice(rule.Properties.DestinationPortRanges), ", ")
			}

			row := []string{
				m.TenantName, // NEW: for multi-tenant support
				m.TenantID,   // NEW: for multi-tenant support
				subID,
				subName,
				rgName,
				region,
				nsgName,
				ruleName,
				priority,
				direction,
				access,
				protocol,
				srcPrefix,
				srcPort,
				dstPrefix,
				dstPort,
			}

			m.mu.Lock()
			m.NSGRows = append(m.NSGRows, row)
			m.mu.Unlock()
			m.CommandCounter.Total++

			// Generate loot for open ports and security risks
			m.generateLoot(subID, subName, rgName, nsgName, ruleName, direction, access, protocol, srcPrefix, dstPrefix, dstPort)
		}
	}

	// Generate Azure CLI commands
	m.mu.Lock()
	m.LootMap["nsg-commands"].Contents += fmt.Sprintf("# NSG: %s (Resource Group: %s)\n", nsgName, rgName)
	m.LootMap["nsg-commands"].Contents += fmt.Sprintf("az account set --subscription %s\n", subID)
	m.LootMap["nsg-commands"].Contents += fmt.Sprintf("az network nsg show --name %s --resource-group %s\n", nsgName, rgName)
	m.LootMap["nsg-commands"].Contents += fmt.Sprintf("az network nsg rule list --nsg-name %s --resource-group %s -o table\n\n", nsgName, rgName)
	m.mu.Unlock()

	// NEW: Analyze effective security rules for this NSG
	m.analyzeEffectiveRules(ctx, subID, subName, rgName, region, nsg, logger)
}

// ------------------------------
// Generate loot
// ------------------------------
func (m *NSGModule) generateLoot(subID, subName, rgName, nsgName, ruleName, direction, access, protocol, srcPrefix, dstPrefix, dstPort string) {
	// Only process inbound allow rules
	if direction != "Inbound" || access != "Allow" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Track open ports
	m.LootMap["nsg-open-ports"].Contents += fmt.Sprintf("NSG: %s/%s\n", rgName, nsgName)
	m.LootMap["nsg-open-ports"].Contents += fmt.Sprintf("  Rule: %s\n", ruleName)
	m.LootMap["nsg-open-ports"].Contents += fmt.Sprintf("  Protocol: %s\n", protocol)
	m.LootMap["nsg-open-ports"].Contents += fmt.Sprintf("  Source: %s\n", srcPrefix)
	m.LootMap["nsg-open-ports"].Contents += fmt.Sprintf("  Destination: %s\n", dstPrefix)
	m.LootMap["nsg-open-ports"].Contents += fmt.Sprintf("  Ports: %s\n\n", dstPort)

	// Identify security risks
	risks := []string{}

	// Check for overly permissive source
	if srcPrefix == "*" || srcPrefix == "Internet" || srcPrefix == "0.0.0.0/0" {
		risks = append(risks, "Allows traffic from ANY source (Internet)")
	}

	// Check for wide port ranges
	if dstPort == "*" {
		risks = append(risks, "Allows ALL ports")
	}

	// Check for common risky ports from Internet
	if (srcPrefix == "*" || srcPrefix == "Internet" || srcPrefix == "0.0.0.0/0") &&
		(strings.Contains(dstPort, "22") || strings.Contains(dstPort, "3389") ||
			strings.Contains(dstPort, "1433") || strings.Contains(dstPort, "3306") ||
			strings.Contains(dstPort, "5432") || strings.Contains(dstPort, "27017")) {
		risks = append(risks, fmt.Sprintf("Exposes management/database port %s to Internet", dstPort))
	}

	if len(risks) > 0 {
		m.LootMap["nsg-security-risks"].Contents += fmt.Sprintf("🚨 HIGH RISK: NSG %s/%s - Rule %s\n", rgName, nsgName, ruleName)
		m.LootMap["nsg-security-risks"].Contents += fmt.Sprintf("  Protocol: %s | Source: %s | Ports: %s\n", protocol, srcPrefix, dstPort)
		for _, risk := range risks {
			m.LootMap["nsg-security-risks"].Contents += fmt.Sprintf("  ⚠️  %s\n", risk)
		}
		m.LootMap["nsg-security-risks"].Contents += fmt.Sprintf("  Subscription: %s\n", subName)
		m.LootMap["nsg-security-risks"].Contents += fmt.Sprintf("  Command: az network nsg rule show --nsg-name %s --resource-group %s --name %s\n\n", nsgName, rgName, ruleName)
	}

	// Generate targeted scanning commands based on ports
	m.generateTargetedScans(rgName, nsgName, ruleName, protocol, dstPort)
}

// ------------------------------
// Generate targeted scanning commands
// ------------------------------
func (m *NSGModule) generateTargetedScans(rgName, nsgName, ruleName, protocol, dstPort string) {
	// Skip if all ports (too broad for targeted commands)
	if dstPort == "*" {
		return
	}

	m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# NSG: %s/%s - Rule: %s\n", rgName, nsgName, ruleName)

	// Generate specific commands based on common ports
	ports := strings.Split(dstPort, ",")
	for _, p := range ports {
		port := strings.TrimSpace(p)

		switch port {
		case "22":
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# SSH Access (Port 22)\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("ssh <username>@<TARGET_IP>\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nmap -p 22 -sV --script ssh-auth-methods,ssh-hostkey <TARGET_IP>\n\n")

		case "3389":
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# RDP Access (Port 3389)\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("xfreerdp /v:<TARGET_IP> /u:<username>\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nmap -p 3389 -sV --script rdp-enum-encryption,rdp-vuln-ms12-020 <TARGET_IP>\n\n")

		case "80":
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# HTTP Access (Port 80)\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("curl -i http://<TARGET_IP>\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nmap -p 80 -sV --script http-enum,http-headers,http-methods <TARGET_IP>\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nikto -h http://<TARGET_IP>\n\n")

		case "443":
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# HTTPS Access (Port 443)\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("curl -ik https://<TARGET_IP>\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nmap -p 443 -sV --script ssl-cert,ssl-enum-ciphers,http-enum <TARGET_IP>\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nikto -h https://<TARGET_IP>\n\n")

		case "1433":
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# SQL Server (Port 1433)\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nmap -p 1433 -sV --script ms-sql-info,ms-sql-empty-password,ms-sql-brute <TARGET_IP>\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# Warning: SQL Server should NOT be exposed to the Internet\n\n")

		case "3306":
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# MySQL (Port 3306)\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nmap -p 3306 -sV --script mysql-info,mysql-empty-password,mysql-brute <TARGET_IP>\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("mysql -h <TARGET_IP> -u <username> -p\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# Warning: MySQL should NOT be exposed to the Internet\n\n")

		case "5432":
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# PostgreSQL (Port 5432)\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nmap -p 5432 -sV --script pgsql-brute <TARGET_IP>\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("psql -h <TARGET_IP> -U <username>\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# Warning: PostgreSQL should NOT be exposed to the Internet\n\n")

		case "27017":
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# MongoDB (Port 27017)\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nmap -p 27017 -sV --script mongodb-info,mongodb-databases <TARGET_IP>\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("mongosh mongodb://<TARGET_IP>:27017\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# Warning: MongoDB should NOT be exposed to the Internet\n\n")

		case "21":
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# FTP (Port 21)\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nmap -p 21 -sV --script ftp-anon,ftp-bounce,ftp-syst <TARGET_IP>\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("ftp <TARGET_IP>\n\n")

		case "25":
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# SMTP (Port 25)\n")
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nmap -p 25 -sV --script smtp-commands,smtp-enum-users,smtp-open-relay <TARGET_IP>\n\n")

		case "8080", "8000", "8888":
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# HTTP Alt Port (%s)\n", port)
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("curl -i http://<TARGET_IP>:%s\n", port)
			m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nmap -p %s -sV --script http-enum,http-headers <TARGET_IP>\n\n", port)

		default:
			// Generic port scan
			if port != "" && port != "N/A" {
				m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("# Port %s\n", port)
				m.LootMap["nsg-targeted-scans"].Contents += fmt.Sprintf("nmap -p %s -sV -sC <TARGET_IP>\n\n", port)
			}
		}
	}
}

// ------------------------------
// Analyze effective security rules (NEW)
// ------------------------------
func (m *NSGModule) analyzeEffectiveRules(ctx context.Context, subID, subName, rgName, region string, nsg *armnetwork.SecurityGroup, logger internal.Logger) {
	if nsg == nil || nsg.Name == nil {
		return
	}

	nsgName := *nsg.Name

	// Get associated NICs
	var associatedNICs []string
	var associatedSubnets []string

	if nsg.Properties != nil {
		// NICs
		if nsg.Properties.NetworkInterfaces != nil {
			for _, nic := range nsg.Properties.NetworkInterfaces {
				if nic.ID != nil {
					nicName := azinternal.GetNameFromID(*nic.ID)
					if nicName != "N/A" {
						associatedNICs = append(associatedNICs, nicName)
					}
				}
			}
		}

		// Subnets
		if nsg.Properties.Subnets != nil {
			for _, subnet := range nsg.Properties.Subnets {
				if subnet.ID != nil {
					subnetName := azinternal.GetNameFromID(*subnet.ID)
					if subnetName != "N/A" {
						associatedSubnets = append(associatedSubnets, subnetName)
					}
				}
			}
		}
	}

	associatedNICsStr := "None"
	if len(associatedNICs) > 0 {
		associatedNICsStr = strings.Join(associatedNICs, ", ")
	}

	associatedSubnetsStr := "None"
	if len(associatedSubnets) > 0 {
		associatedSubnetsStr = strings.Join(associatedSubnets, ", ")
	}

	// Analyze rules for security posture
	internetAccessAllowed := "No"
	rdpSshExposed := "No"
	highRiskPortsOpen := "None"
	effectiveInboundSummary := "Default Deny"
	effectiveOutboundSummary := "Default Allow"

	var inboundAllowRules []string
	var outboundAllowRules []string
	var highRiskPorts []string

	if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
		for _, rule := range nsg.Properties.SecurityRules {
			if rule == nil || rule.Properties == nil {
				continue
			}

			// Only analyze Allow rules
			if rule.Properties.Access == nil || *rule.Properties.Access != armnetwork.SecurityRuleAccessAllow {
				continue
			}

			direction := ""
			if rule.Properties.Direction != nil {
				direction = string(*rule.Properties.Direction)
			}

			srcPrefix := azinternal.SafeStringPtr(rule.Properties.SourceAddressPrefix)
			dstPort := azinternal.SafeStringPtr(rule.Properties.DestinationPortRange)

			// Handle destination port ranges (array)
			if rule.Properties.DestinationPortRanges != nil && len(rule.Properties.DestinationPortRanges) > 0 {
				dstPort = strings.Join(azinternal.SafeStringSlice(rule.Properties.DestinationPortRanges), ", ")
			}

			// Check for internet access (inbound from Internet or outbound to Internet)
			if srcPrefix == "*" || srcPrefix == "Internet" || srcPrefix == "0.0.0.0/0" {
				if direction == "Inbound" {
					internetAccessAllowed = "⚠ Yes (Inbound from Internet)"
				}
			}

			// Check for RDP/SSH exposure
			if direction == "Inbound" && (srcPrefix == "*" || srcPrefix == "Internet" || srcPrefix == "0.0.0.0/0") {
				if strings.Contains(dstPort, "22") {
					rdpSshExposed = "⚠ CRITICAL (SSH exposed to Internet)"
				} else if strings.Contains(dstPort, "3389") {
					if rdpSshExposed == "No" || !strings.Contains(rdpSshExposed, "SSH") {
						rdpSshExposed = "⚠ CRITICAL (RDP exposed to Internet)"
					} else {
						rdpSshExposed = "⚠ CRITICAL (SSH + RDP exposed to Internet)"
					}
				}

				// Check for high-risk database ports
				if strings.Contains(dstPort, "1433") && !contains(highRiskPorts, "SQL Server:1433") {
					highRiskPorts = append(highRiskPorts, "SQL Server:1433")
				}
				if strings.Contains(dstPort, "3306") && !contains(highRiskPorts, "MySQL:3306") {
					highRiskPorts = append(highRiskPorts, "MySQL:3306")
				}
				if strings.Contains(dstPort, "5432") && !contains(highRiskPorts, "PostgreSQL:5432") {
					highRiskPorts = append(highRiskPorts, "PostgreSQL:5432")
				}
				if strings.Contains(dstPort, "27017") && !contains(highRiskPorts, "MongoDB:27017") {
					highRiskPorts = append(highRiskPorts, "MongoDB:27017")
				}
				if strings.Contains(dstPort, "6379") && !contains(highRiskPorts, "Redis:6379") {
					highRiskPorts = append(highRiskPorts, "Redis:6379")
				}
			}

			// Build effective rules summary
			ruleName := "N/A"
			if rule.Name != nil {
				ruleName = *rule.Name
			}

			protocol := "Any"
			if rule.Properties.Protocol != nil {
				protocol = string(*rule.Properties.Protocol)
			}

			if direction == "Inbound" {
				summary := fmt.Sprintf("%s: %s %s→%s", ruleName, protocol, srcPrefix, dstPort)
				if len(inboundAllowRules) < 5 { // Limit to top 5 for readability
					inboundAllowRules = append(inboundAllowRules, summary)
				}
			} else if direction == "Outbound" {
				summary := fmt.Sprintf("%s: %s %s", ruleName, protocol, dstPort)
				if len(outboundAllowRules) < 5 { // Limit to top 5
					outboundAllowRules = append(outboundAllowRules, summary)
				}
			}
		}
	}

	// Build effective rules summaries
	if len(inboundAllowRules) > 0 {
		effectiveInboundSummary = strings.Join(inboundAllowRules, "; ")
	}

	if len(outboundAllowRules) > 0 {
		effectiveOutboundSummary = strings.Join(outboundAllowRules, "; ")
	}

	if len(highRiskPorts) > 0 {
		highRiskPortsOpen = "⚠ " + strings.Join(highRiskPorts, ", ")
	}

	// Add summary row
	summaryRow := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		nsgName,
		associatedNICsStr,
		associatedSubnetsStr,
		internetAccessAllowed,
		rdpSshExposed,
		highRiskPortsOpen,
		effectiveInboundSummary,
		effectiveOutboundSummary,
	}

	m.mu.Lock()
	m.NSGSummaryRows = append(m.NSGSummaryRows, summaryRow)

	// Generate loot file entry for effective rules
	if len(associatedNICs) > 0 || len(associatedSubnets) > 0 {
		m.LootMap["nsg-effective-rules"].Contents += fmt.Sprintf("## NSG: %s (Resource Group: %s)\n", nsgName, rgName)
		m.LootMap["nsg-effective-rules"].Contents += fmt.Sprintf("Subscription: %s\n", subName)
		m.LootMap["nsg-effective-rules"].Contents += fmt.Sprintf("Associated NICs: %s\n", associatedNICsStr)
		m.LootMap["nsg-effective-rules"].Contents += fmt.Sprintf("Associated Subnets: %s\n", associatedSubnetsStr)
		m.LootMap["nsg-effective-rules"].Contents += fmt.Sprintf("Internet Access: %s\n", internetAccessAllowed)
		m.LootMap["nsg-effective-rules"].Contents += fmt.Sprintf("RDP/SSH Exposure: %s\n", rdpSshExposed)
		m.LootMap["nsg-effective-rules"].Contents += fmt.Sprintf("High-Risk Ports: %s\n", highRiskPortsOpen)
		m.LootMap["nsg-effective-rules"].Contents += fmt.Sprintf("Effective Inbound (Top 5): %s\n", effectiveInboundSummary)
		m.LootMap["nsg-effective-rules"].Contents += fmt.Sprintf("Effective Outbound (Top 5): %s\n\n", effectiveOutboundSummary)
	}
	m.mu.Unlock()
}

// Helper function to check if slice contains string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// ------------------------------
// Write output
// ------------------------------
func (m *NSGModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.NSGRows) == 0 && len(m.NSGSummaryRows) == 0 {
		logger.InfoM("No Network Security Groups found", globals.AZ_NSG_MODULE_NAME)
		return
	}

	// Build headers for detailed rules table
	rulesHeaders := []string{
		"Tenant Name", // NEW: for multi-tenant support
		"Tenant ID",   // NEW: for multi-tenant support
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"NSG Name",
		"Rule Name",
		"Priority",
		"Direction",
		"Access",
		"Protocol",
		"Source Address",
		"Source Port",
		"Destination Address",
		"Destination Port",
	}

	// Build headers for effective rules summary table
	summaryHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"NSG Name",
		"Associated NICs",
		"Associated Subnets",
		"Internet Access Allowed",
		"RDP/SSH Exposed",
		"High-Risk Ports Open",
		"Effective Inbound Summary (Top 5)",
		"Effective Outbound Summary (Top 5)",
	}

	// Check if we should split output by tenant (multi-tenant mode)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		// Split into separate tenant directories
		if err := m.FilterAndWritePerTenantAuto(
			ctx,
			logger,
			m.Tenants,
			m.NSGRows,
			rulesHeaders,
			"nsg-rules",
			globals.AZ_NSG_MODULE_NAME,
		); err != nil {
			return
		}

		if len(m.NSGSummaryRows) > 0 {
			if err := m.FilterAndWritePerTenantAuto(
				ctx,
				logger,
				m.Tenants,
				m.NSGSummaryRows,
				summaryHeaders,
				"nsg-summary",
				globals.AZ_NSG_MODULE_NAME,
			); err != nil {
				return
			}
		}
		return
	}

	// Check if we should split output by subscription (multiple subs WITHOUT --tenant flag, single tenant)
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.NSGRows, rulesHeaders,
			"nsg-rules", globals.AZ_NSG_MODULE_NAME,
		); err != nil {
			return
		}

		if len(m.NSGSummaryRows) > 0 {
			if err := m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.NSGSummaryRows, summaryHeaders,
				"nsg-summary", globals.AZ_NSG_MODULE_NAME,
			); err != nil {
				return
			}
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

	// Create output with both tables
	tables := []internal.TableFile{{
		Name:   "nsg-rules",
		Header: rulesHeaders,
		Body:   m.NSGRows,
	}}

	// Add summary table if we have summary data
	if len(m.NSGSummaryRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "nsg-summary",
			Header: summaryHeaders,
			Body:   m.NSGSummaryRows,
		})
	}

	output := NSGOutput{
		Table: tables,
		Loot:  loot,
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_NSG_MODULE_NAME)
		return
	}

	// Print summary
	logger.InfoM(fmt.Sprintf("Found %d NSG rules and %d NSG summaries across %d subscriptions", len(m.NSGRows), len(m.NSGSummaryRows), len(m.Subscriptions)), globals.AZ_NSG_MODULE_NAME)
}
