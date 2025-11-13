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
var AzNetworkInterfacesCommand = &cobra.Command{
	Use:     "network-interfaces",
	Aliases: []string{"nics"},
	Short:   "Enumerate Azure Network Interfaces",
	Long: `
Enumerate Azure Network Interfaces for a specific tenant:
./cloudfox az nics --tenant TENANT_ID

Enumerate Azure Network Interfaces for a specific subscription:
./cloudfox az nics --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListNetworkInterfaces,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type NetworkInterfacesModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions        []string
	NetworkInterfaceRows [][]string
	LootMap              map[string]*internal.LootFile
	mu                   sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type NetworkInterfacesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o NetworkInterfacesOutput) TableFiles() []internal.TableFile { return o.Table }
func (o NetworkInterfacesOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListNetworkInterfaces(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_NIC_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &NetworkInterfacesModule{
		BaseAzureModule:      azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:        cmdCtx.Subscriptions,
		NetworkInterfaceRows: [][]string{},
		LootMap: map[string]*internal.LootFile{
			"network-interface-commands":    {Name: "network-interface-commands", Contents: ""},
			"network-interfaces-PrivateIPs": {Name: "network-interfaces-PrivateIPs", Contents: ""},
			"network-interfaces-PublicIPs":  {Name: "network-interfaces-PublicIPs", Contents: ""},
			"network-scanning-commands":     {Name: "network-scanning-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintNetworkInterfaces(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *NetworkInterfacesModule) PrintNetworkInterfaces(ctx context.Context, logger internal.Logger) {
	// Multi-tenant support: iterate over tenants if enabled
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			// Save current tenant context
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			// Switch to current tenant
			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			// Process this tenant's subscriptions
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_NIC_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single-tenant mode
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_NIC_MODULE_NAME, m.processSubscription)
	}

	// Generate network scanning commands
	m.generateNetworkScanningLoot()

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *NetworkInterfacesModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Process resource groups concurrently for better performance
	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10) // Limit to 10 concurrent RGs

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, &rgWg, rgSemaphore)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group (extracted for RG-level concurrency)
// ------------------------------
func (m *NetworkInterfacesModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()
	nics, _ := azinternal.ListNetworkInterfaces(ctx, m.Session, subID, rgName)
	for _, nic := range nics {
		nicType := "Standard"
		if nic.Properties != nil && nic.Properties.EnableAcceleratedNetworking != nil && *nic.Properties.EnableAcceleratedNetworking {
			nicType = "Accelerated"
		}
		internalIP := "N/A"
		externalIP := "N/A"
		vpcID := "N/A"
		attachedResource := "N/A"
		description := "N/A"
		nsgName := "N/A"
		ipForwarding := "Disabled"
		nicid := azinternal.GetResourceGroupFromID(*nic.ID)

		if nic.Properties != nil {
			if nic.Properties.IPConfigurations != nil && len(nic.Properties.IPConfigurations) > 0 {
				ipConf := nic.Properties.IPConfigurations[0]
				if ipConf.Properties != nil {
					if ipConf.Properties.PrivateIPAddress != nil {
						internalIP = *ipConf.Properties.PrivateIPAddress
					}
					if ipConf.Properties.PublicIPAddress != nil && ipConf.Properties.PublicIPAddress.ID != nil {
						externalIP, _ = azinternal.GetPublicIPByID(ctx, m.Session, *ipConf.Properties.PublicIPAddress.ID)
					}
					if ipConf.Properties.Subnet != nil && ipConf.Properties.Subnet.ID != nil {
						vpcID = *ipConf.Properties.Subnet.ID
					}
				}
			}
			if nic.Properties.VirtualMachine != nil && nic.Properties.VirtualMachine.ID != nil {
				attachedResource = *nic.Properties.VirtualMachine.ID
			}
			if nic.Tags != nil {
				if d, ok := nic.Tags["Description"]; ok {
					description = *d
				}
			}

			// Check for Network Security Group
			if nic.Properties.NetworkSecurityGroup != nil && nic.Properties.NetworkSecurityGroup.ID != nil {
				nsgName = azinternal.GetResourceNameFromID(*nic.Properties.NetworkSecurityGroup.ID)
			}

			// Check IP forwarding status
			if nic.Properties.EnableIPForwarding != nil && *nic.Properties.EnableIPForwarding {
				ipForwarding = "Enabled"
			}
		}

		// Thread-safe append
		m.mu.Lock()
		m.NetworkInterfaceRows = append(m.NetworkInterfaceRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			rgName,
			azinternal.SafeStringPtr(nic.Location),
			azinternal.SafeStringPtr(nic.Name),
			azinternal.SafeString(nicid),
			nicType,
			externalIP,
			internalIP,
			azinternal.GetResourceGroupFromID(vpcID),
			azinternal.GetResourceGroupFromID(attachedResource),
			azinternal.GetResourceTypeFromID(attachedResource),
			nsgName,
			ipForwarding,
			description,
		})

		// Add to loot
		m.LootMap["network-interfaces-PrivateIPs"].Contents += fmt.Sprintf("%s\n", internalIP)
		m.LootMap["network-interfaces-PublicIPs"].Contents += fmt.Sprintf("%s\n", externalIP)
		m.LootMap["network-interface-commands"].Contents += fmt.Sprintf(
			"az account set --subscription %s\naz network nic list --resource-group %s\n"+
				"Get-AzNetworkInterface -ResourceGroupName %s\n\n",
			subID, rgName, rgName)
		m.mu.Unlock()
	}
}

// ------------------------------
// Generate network scanning commands
// ------------------------------
func (m *NetworkInterfacesModule) generateNetworkScanningLoot() {
	lf := m.LootMap["network-scanning-commands"]

	// Check if we have any IPs to scan
	hasPublicIPs := m.LootMap["network-interfaces-PublicIPs"].Contents != ""
	hasPrivateIPs := m.LootMap["network-interfaces-PrivateIPs"].Contents != ""

	if !hasPublicIPs && !hasPrivateIPs {
		return
	}

	// Generate comprehensive network scanning guide
	lf.Contents += fmt.Sprintf("# Azure Network Scanning Guide\n\n")
	lf.Contents += fmt.Sprintf("This guide provides network scanning commands for discovered Azure network interfaces.\n")
	lf.Contents += fmt.Sprintf("Use these commands to discover open ports, services, and potential vulnerabilities.\n\n")

	lf.Contents += fmt.Sprintf("## Prerequisites\n")
	lf.Contents += fmt.Sprintf("- nmap: https://nmap.org/download.html\n")
	lf.Contents += fmt.Sprintf("- masscan: https://github.com/robertdavidgraham/masscan\n")
	lf.Contents += fmt.Sprintf("- For private IP scanning: access to Azure VM or network with connectivity to private network\n\n")

	lf.Contents += fmt.Sprintf("## Table of Contents\n")
	lf.Contents += fmt.Sprintf("1. Public IP Scanning with Nmap\n")
	lf.Contents += fmt.Sprintf("2. Private IP Scanning with Nmap\n")
	lf.Contents += fmt.Sprintf("3. Fast Port Discovery with Masscan\n")
	lf.Contents += fmt.Sprintf("4. DNS Enumeration\n")
	lf.Contents += fmt.Sprintf("5. Azure-Specific Scanning Tips\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Section 1: Public IP Scanning
	if hasPublicIPs {
		lf.Contents += fmt.Sprintf("## 1. Public IP Scanning with Nmap\n\n")

		lf.Contents += fmt.Sprintf("The file 'network-interfaces-PublicIPs.txt' contains all public IPs found in Azure.\n\n")

		lf.Contents += fmt.Sprintf("### Basic Nmap Scan (Service Version Detection)\n\n")
		lf.Contents += fmt.Sprintf("# Scan top 1000 ports with service version detection\n")
		lf.Contents += fmt.Sprintf("nmap -sV -sC -oA public-scan -iL network-interfaces-PublicIPs.txt\n\n")

		lf.Contents += fmt.Sprintf("# Explanation:\n")
		lf.Contents += fmt.Sprintf("#   -sV: Probe open ports to determine service/version info\n")
		lf.Contents += fmt.Sprintf("#   -sC: Run default NSE scripts for additional enumeration\n")
		lf.Contents += fmt.Sprintf("#   -oA public-scan: Output in all formats (normal, XML, grepable)\n")
		lf.Contents += fmt.Sprintf("#   -iL: Input from file\n\n")

		lf.Contents += fmt.Sprintf("### Comprehensive Nmap Scan (All Ports)\n\n")
		lf.Contents += fmt.Sprintf("# Full port scan with OS detection (slower but thorough)\n")
		lf.Contents += fmt.Sprintf("nmap -p- -sV -sC -O -oA public-scan-full -iL network-interfaces-PublicIPs.txt\n\n")

		lf.Contents += fmt.Sprintf("# Explanation:\n")
		lf.Contents += fmt.Sprintf("#   -p-: Scan all 65535 ports\n")
		lf.Contents += fmt.Sprintf("#   -O: Enable OS detection\n\n")

		lf.Contents += fmt.Sprintf("### Aggressive Nmap Scan\n\n")
		lf.Contents += fmt.Sprintf("# Aggressive scan with timing optimization\n")
		lf.Contents += fmt.Sprintf("nmap -A -T4 -oA public-scan-aggressive -iL network-interfaces-PublicIPs.txt\n\n")

		lf.Contents += fmt.Sprintf("# Explanation:\n")
		lf.Contents += fmt.Sprintf("#   -A: Enable OS detection, version detection, script scanning, and traceroute\n")
		lf.Contents += fmt.Sprintf("#   -T4: Faster timing template (aggressive)\n\n")

		lf.Contents += fmt.Sprintf("### Scan Specific Common Ports\n\n")
		lf.Contents += fmt.Sprintf("# Scan common Azure service ports\n")
		lf.Contents += fmt.Sprintf("nmap -p 22,80,443,445,1433,1521,3306,3389,5432,5985,5986,8080,8443,27017 \\\n")
		lf.Contents += fmt.Sprintf("  -sV -sC -oA public-scan-common-ports -iL network-interfaces-PublicIPs.txt\n\n")

		lf.Contents += fmt.Sprintf("# Common Azure ports:\n")
		lf.Contents += fmt.Sprintf("#   22: SSH\n")
		lf.Contents += fmt.Sprintf("#   80/443: HTTP/HTTPS\n")
		lf.Contents += fmt.Sprintf("#   445: SMB\n")
		lf.Contents += fmt.Sprintf("#   1433: SQL Server\n")
		lf.Contents += fmt.Sprintf("#   1521: Oracle\n")
		lf.Contents += fmt.Sprintf("#   3306: MySQL\n")
		lf.Contents += fmt.Sprintf("#   3389: RDP\n")
		lf.Contents += fmt.Sprintf("#   5432: PostgreSQL\n")
		lf.Contents += fmt.Sprintf("#   5985/5986: WinRM (HTTP/HTTPS)\n")
		lf.Contents += fmt.Sprintf("#   8080/8443: Alternative HTTP/HTTPS\n")
		lf.Contents += fmt.Sprintf("#   27017: MongoDB\n\n")

		lf.Contents += fmt.Sprintf("### Stealth Scan (SYN Scan)\n\n")
		lf.Contents += fmt.Sprintf("# Stealthier scan using SYN packets (requires root)\n")
		lf.Contents += fmt.Sprintf("sudo nmap -sS -p- -oA public-scan-stealth -iL network-interfaces-PublicIPs.txt\n\n")

		lf.Contents += fmt.Sprintf("# Explanation:\n")
		lf.Contents += fmt.Sprintf("#   -sS: SYN scan (half-open scan, less likely to be logged)\n\n")

		lf.Contents += fmt.Sprintf("################################################################################\n\n")
	}

	// Section 2: Private IP Scanning
	if hasPrivateIPs {
		lf.Contents += fmt.Sprintf("## 2. Private IP Scanning with Nmap\n\n")

		lf.Contents += fmt.Sprintf("The file 'network-interfaces-PrivateIPs.txt' contains all private IPs found in Azure.\n")
		lf.Contents += fmt.Sprintf("These IPs are only accessible from within the Azure virtual network or via VPN/ExpressRoute.\n\n")

		lf.Contents += fmt.Sprintf("### Prerequisites for Private IP Scanning\n\n")
		lf.Contents += fmt.Sprintf("You need access to the Azure virtual network to scan private IPs. Options:\n")
		lf.Contents += fmt.Sprintf("1. Compromise a VM in the same VNet\n")
		lf.Contents += fmt.Sprintf("2. Use Azure Bastion or VPN Gateway\n")
		lf.Contents += fmt.Sprintf("3. Use Azure Virtual Network peering\n")
		lf.Contents += fmt.Sprintf("4. Deploy a scanning VM in the target VNet\n\n")

		lf.Contents += fmt.Sprintf("### Basic Private Network Scan\n\n")
		lf.Contents += fmt.Sprintf("# From compromised Azure VM or VPN connection\n")
		lf.Contents += fmt.Sprintf("nmap -sV -sC -oA private-scan -iL network-interfaces-PrivateIPs.txt\n\n")

		lf.Contents += fmt.Sprintf("### Full Private Network Scan\n\n")
		lf.Contents += fmt.Sprintf("# Comprehensive scan of private network\n")
		lf.Contents += fmt.Sprintf("nmap -p- -sV -sC -O -oA private-scan-full -iL network-interfaces-PrivateIPs.txt\n\n")

		lf.Contents += fmt.Sprintf("### Scan Private Network for Azure Services\n\n")
		lf.Contents += fmt.Sprintf("# Focus on common internal Azure services\n")
		lf.Contents += fmt.Sprintf("nmap -p 22,80,135,139,443,445,1433,3306,3389,5432,5985,5986,8080 \\\n")
		lf.Contents += fmt.Sprintf("  -sV -sC -oA private-scan-services -iL network-interfaces-PrivateIPs.txt\n\n")

		lf.Contents += fmt.Sprintf("### Fast Internal Network Discovery\n\n")
		lf.Contents += fmt.Sprintf("# Quick host discovery (ping scan)\n")
		lf.Contents += fmt.Sprintf("nmap -sn -oA private-scan-discovery -iL network-interfaces-PrivateIPs.txt\n\n")

		lf.Contents += fmt.Sprintf("# Explanation:\n")
		lf.Contents += fmt.Sprintf("#   -sn: Ping scan (no port scan), just host discovery\n\n")

		lf.Contents += fmt.Sprintf("################################################################################\n\n")
	}

	// Section 3: Masscan
	if hasPublicIPs || hasPrivateIPs {
		lf.Contents += fmt.Sprintf("## 3. Fast Port Discovery with Masscan\n\n")

		lf.Contents += fmt.Sprintf("Masscan is extremely fast for large-scale port scanning.\n")
		lf.Contents += fmt.Sprintf("Use it for initial discovery, then use nmap for detailed enumeration.\n\n")

		if hasPublicIPs {
			lf.Contents += fmt.Sprintf("### Masscan for Public IPs\n\n")

			lf.Contents += fmt.Sprintf("# Scan all ports on public IPs (fast)\n")
			lf.Contents += fmt.Sprintf("masscan -p1-65535 --rate=1000 -iL network-interfaces-PublicIPs.txt -oL masscan-public-results.txt\n\n")

			lf.Contents += fmt.Sprintf("# Explanation:\n")
			lf.Contents += fmt.Sprintf("#   -p1-65535: Scan all ports\n")
			lf.Contents += fmt.Sprintf("#   --rate=1000: Send 1000 packets/second (adjust based on your bandwidth)\n")
			lf.Contents += fmt.Sprintf("#   -oL: Output in list format\n\n")

			lf.Contents += fmt.Sprintf("# Scan top 100 ports (even faster)\n")
			lf.Contents += fmt.Sprintf("masscan --top-ports 100 --rate=10000 -iL network-interfaces-PublicIPs.txt -oL masscan-public-top100.txt\n\n")

			lf.Contents += fmt.Sprintf("# Scan common web ports only\n")
			lf.Contents += fmt.Sprintf("masscan -p80,443,8080,8443 --rate=10000 -iL network-interfaces-PublicIPs.txt -oL masscan-public-web.txt\n\n")
		}

		if hasPrivateIPs {
			lf.Contents += fmt.Sprintf("### Masscan for Private IPs\n\n")

			lf.Contents += fmt.Sprintf("# Scan all ports on private IPs (from inside Azure network)\n")
			lf.Contents += fmt.Sprintf("masscan -p1-65535 --rate=10000 -iL network-interfaces-PrivateIPs.txt -oL masscan-private-results.txt\n\n")

			lf.Contents += fmt.Sprintf("# Note: Higher rate possible on internal network due to lower latency\n\n")
		}

		lf.Contents += fmt.Sprintf("### Convert Masscan Output for Nmap\n\n")
		lf.Contents += fmt.Sprintf("# Parse masscan results and scan discovered ports with nmap\n")
		lf.Contents += fmt.Sprintf("# Extract unique IP:port combinations\n")
		lf.Contents += fmt.Sprintf("cat masscan-public-results.txt | grep open | awk '{print $4,$3}' | \\\n")
		lf.Contents += fmt.Sprintf("  sed 's!/tcp!!g' | sort -u > discovered-ports.txt\n\n")

		lf.Contents += fmt.Sprintf("# Then scan those specific ports with nmap for detailed info\n")
		lf.Contents += fmt.Sprintf("# (You'll need to create a script to parse and scan each IP:port combination)\n\n")

		lf.Contents += fmt.Sprintf("################################################################################\n\n")
	}

	// Section 4: DNS Enumeration
	lf.Contents += fmt.Sprintf("## 4. DNS Enumeration\n\n")

	lf.Contents += fmt.Sprintf("Enumerate Azure DNS zones and records to discover additional infrastructure.\n\n")

	lf.Contents += fmt.Sprintf("### List Azure DNS Zones\n\n")
	lf.Contents += fmt.Sprintf("# List all DNS zones in subscription\n")
	lf.Contents += fmt.Sprintf("SUBSCRIPTION_ID=<SUBSCRIPTION-ID>\n")
	lf.Contents += fmt.Sprintf("az account set --subscription $SUBSCRIPTION_ID\n")
	lf.Contents += fmt.Sprintf("az network dns zone list -o table\n\n")

	lf.Contents += fmt.Sprintf("### List DNS Records for a Zone\n\n")
	lf.Contents += fmt.Sprintf("RESOURCE_GROUP=<RESOURCE-GROUP>\n")
	lf.Contents += fmt.Sprintf("DNS_ZONE=<DNS-ZONE-NAME>\n\n")

	lf.Contents += fmt.Sprintf("# List all record sets\n")
	lf.Contents += fmt.Sprintf("az network dns record-set list --resource-group $RESOURCE_GROUP --zone-name $DNS_ZONE -o table\n\n")

	lf.Contents += fmt.Sprintf("# List A records only\n")
	lf.Contents += fmt.Sprintf("az network dns record-set a list --resource-group $RESOURCE_GROUP --zone-name $DNS_ZONE\n\n")

	lf.Contents += fmt.Sprintf("# List CNAME records\n")
	lf.Contents += fmt.Sprintf("az network dns record-set cname list --resource-group $RESOURCE_GROUP --zone-name $DNS_ZONE\n\n")

	lf.Contents += fmt.Sprintf("### Extract IP Addresses from DNS\n\n")
	lf.Contents += fmt.Sprintf("# Get all A record IPs\n")
	lf.Contents += fmt.Sprintf("az network dns record-set a list --resource-group $RESOURCE_GROUP --zone-name $DNS_ZONE \\\n")
	lf.Contents += fmt.Sprintf("  --query '[].aRecords[].ipv4Address' -o tsv > dns-ips.txt\n\n")

	lf.Contents += fmt.Sprintf("### DNS Brute Force (External)\n\n")
	lf.Contents += fmt.Sprintf("# Use tools like dnsrecon or fierce for subdomain discovery\n")
	lf.Contents += fmt.Sprintf("dnsrecon -d $DNS_ZONE -t brt -D /usr/share/wordlists/dnsmap.txt\n\n")

	lf.Contents += fmt.Sprintf("# Using fierce\n")
	lf.Contents += fmt.Sprintf("fierce --domain $DNS_ZONE\n\n")

	lf.Contents += fmt.Sprintf("### Azure-specific DNS patterns\n\n")
	lf.Contents += fmt.Sprintf("# Common Azure DNS patterns to check:\n")
	lf.Contents += fmt.Sprintf("#   <app-name>.azurewebsites.net\n")
	lf.Contents += fmt.Sprintf("#   <storage-account>.blob.core.windows.net\n")
	lf.Contents += fmt.Sprintf("#   <storage-account>.file.core.windows.net\n")
	lf.Contents += fmt.Sprintf("#   <keyvault>.vault.azure.net\n")
	lf.Contents += fmt.Sprintf("#   <service>.cloudapp.azure.com\n")
	lf.Contents += fmt.Sprintf("#   <aks-cluster>.<region>.azmk8s.io\n\n")

	lf.Contents += fmt.Sprintf("################################################################################\n\n")

	// Section 5: Azure-Specific Tips
	lf.Contents += fmt.Sprintf("## 5. Azure-Specific Scanning Tips\n\n")

	lf.Contents += fmt.Sprintf("### Network Security Groups (NSGs)\n\n")
	lf.Contents += fmt.Sprintf("Azure NSGs may block scans. If you have NSG information from enumeration:\n")
	lf.Contents += fmt.Sprintf("- Focus on allowed ports from NSG rules\n")
	lf.Contents += fmt.Sprintf("- Source IP restrictions may apply\n")
	lf.Contents += fmt.Sprintf("- Consider scanning from allowed source IPs\n\n")

	lf.Contents += fmt.Sprintf("### Azure Firewall\n\n")
	lf.Contents += fmt.Sprintf("If Azure Firewall is in use:\n")
	lf.Contents += fmt.Sprintf("- Scans may be logged and trigger alerts\n")
	lf.Contents += fmt.Sprintf("- Rate limiting may apply\n")
	lf.Contents += fmt.Sprintf("- Use slower scan rates to avoid detection\n\n")

	lf.Contents += fmt.Sprintf("### Best Practices\n\n")
	lf.Contents += fmt.Sprintf("1. **Start with masscan** for quick port discovery\n")
	lf.Contents += fmt.Sprintf("2. **Use nmap** for detailed service enumeration on discovered ports\n")
	lf.Contents += fmt.Sprintf("3. **Scan from Azure VM** for private IPs to avoid VPN/network issues\n")
	lf.Contents += fmt.Sprintf("4. **Respect NSG rules** - scan allowed ports first\n")
	lf.Contents += fmt.Sprintf("5. **Use slower timing** (-T2 or -T3) to avoid triggering security alerts\n")
	lf.Contents += fmt.Sprintf("6. **Scan during business hours** to blend in with normal traffic\n")
	lf.Contents += fmt.Sprintf("7. **Check Azure Security Center** alerts if you have access\n\n")

	lf.Contents += fmt.Sprintf("### Security Considerations\n\n")
	lf.Contents += fmt.Sprintf("- Port scans are logged by Azure NSGs and Azure Firewall\n")
	lf.Contents += fmt.Sprintf("- Azure Security Center may detect and alert on scanning activity\n")
	lf.Contents += fmt.Sprintf("- DDoS Protection may rate-limit aggressive scans\n")
	lf.Contents += fmt.Sprintf("- Some Azure services have built-in rate limiting\n")
	lf.Contents += fmt.Sprintf("- Always have authorization before scanning\n\n")

	lf.Contents += fmt.Sprintf("### Post-Scan Analysis\n\n")
	lf.Contents += fmt.Sprintf("After scanning, prioritize targets:\n")
	lf.Contents += fmt.Sprintf("1. **High-value services**: Databases (1433, 3306, 5432, 27017)\n")
	lf.Contents += fmt.Sprintf("2. **Management ports**: SSH (22), RDP (3389), WinRM (5985/5986)\n")
	lf.Contents += fmt.Sprintf("3. **Web services**: HTTP/HTTPS (80, 443, 8080, 8443)\n")
	lf.Contents += fmt.Sprintf("4. **File shares**: SMB (445), NFS (2049)\n")
	lf.Contents += fmt.Sprintf("5. **Uncommon ports**: May indicate custom applications\n\n")
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *NetworkInterfacesModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.NetworkInterfaceRows) == 0 {
		logger.InfoM("No Network Interfaces found", globals.AZ_NIC_MODULE_NAME)
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
		"NIC ID",
		"NIC Type",
		"External IP",
		"Internal IP",
		"VPC ID",
		"Attached Resource",
		"Attached Resource Type",
		"NSG Name",
		"IP Forwarding",
		"Description",
	}

	// Check if we should split output by tenant (takes precedence over subscription split)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.NetworkInterfaceRows, headers,
			"network-interfaces", globals.AZ_NIC_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.NetworkInterfaceRows, headers,
			"network-interfaces", globals.AZ_NIC_MODULE_NAME,
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
	output := NetworkInterfacesOutput{
		Table: []internal.TableFile{{
			Name:   "network-interfaces",
			Header: headers,
			Body:   m.NetworkInterfaceRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_NIC_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Network Interface(s) across %d subscription(s)", len(m.NetworkInterfaceRows), len(m.Subscriptions)), globals.AZ_NIC_MODULE_NAME)
}
