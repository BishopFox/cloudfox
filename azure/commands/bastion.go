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
var AzBastionCommand = &cobra.Command{
	Use:     "bastion",
	Aliases: []string{"bas"},
	Short:   "Enumerate Azure Bastion hosts with security analysis",
	Long: `
Enumerate Azure Bastion (secure RDP/SSH gateway) for a specific tenant:
./cloudfox az bastion --tenant TENANT_ID

Enumerate Azure Bastion for a specific subscription:
./cloudfox az bastion --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]

SECURITY FEATURES ANALYZED:
- Bastion host SKU (Basic, Standard, Premium)
- VNet protection coverage analysis
- Scale unit configuration (Premium SKU)
- Native client support enablement
- Copy/paste functionality
- File transfer capabilities
- IP-based connection support
- Session recording configuration
- Shareable link feature status`,
	Run: ListBastion,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type BastionModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields - 2 tables for comprehensive analysis
	Subscriptions   []string
	BastionRows     [][]string      // Bastion hosts with configuration
	VNetCoverageMap map[string]bool // Track which VNets have Bastion
	AllVNets        []string        // All VNets for coverage analysis
	CoverageRows    [][]string      // VNet coverage summary
	LootMap         map[string]*internal.LootFile
	mu              sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type BastionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o BastionOutput) TableFiles() []internal.TableFile { return o.Table }
func (o BastionOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListBastion(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_BASTION_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &BastionModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		BastionRows:     [][]string{},
		VNetCoverageMap: make(map[string]bool),
		AllVNets:        []string{},
		CoverageRows:    [][]string{},
		LootMap: map[string]*internal.LootFile{
			"unprotected-vnets": {Name: "unprotected-vnets", Contents: "# VNets without Bastion protection\n\n"},
			"premium-features":  {Name: "premium-features", Contents: "# Bastion hosts with Premium features\n\n"},
			"shareable-links":   {Name: "shareable-links", Contents: "# Bastion hosts with shareable link feature\n\n"},
			"file-transfer":     {Name: "file-transfer", Contents: "# Bastion hosts with file transfer enabled\n\n"},
			"bastion-commands":  {Name: "bastion-commands", Contents: "# Azure Bastion enumeration commands\n\n"},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintBastion(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *BastionModule) PrintBastion(ctx context.Context, logger internal.Logger) {
	// Step 1: Enumerate all Bastion hosts and VNets
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_BASTION_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_BASTION_MODULE_NAME, m.processSubscription)
	}

	// Step 2: Analyze VNet coverage
	m.analyzeVNetCoverage()

	// Step 3: Generate output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *BastionModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Process resource groups concurrently
	var rgWg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10)

	for _, rgName := range resourceGroups {
		rgWg.Add(1)
		go m.processResourceGroup(ctx, subID, subName, rgName, &rgWg, rgSemaphore)
	}

	rgWg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *BastionModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get token and create clients
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil {
		return
	}

	cred := &azinternal.StaticTokenCredential{Token: token}

	// Enumerate Bastion hosts
	bastionClient, err := armnetwork.NewBastionHostsClient(subID, cred, nil)
	if err != nil {
		return
	}

	pager := bastionClient.NewListByResourceGroupPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			continue
		}

		for _, bastion := range page.Value {
			if bastion == nil || bastion.Name == nil {
				continue
			}

			m.processBastionHost(ctx, subID, subName, rgName, bastion)
		}
	}

	// Also enumerate VNets for coverage analysis
	vnetClient, err := armnetwork.NewVirtualNetworksClient(subID, cred, nil)
	if err != nil {
		return
	}

	vnetPager := vnetClient.NewListPager(rgName, nil)
	for vnetPager.More() {
		vnetPage, err := vnetPager.NextPage(ctx)
		if err != nil {
			continue
		}

		for _, vnet := range vnetPage.Value {
			if vnet == nil || vnet.Name == nil || vnet.ID == nil {
				continue
			}

			m.mu.Lock()
			m.AllVNets = append(m.AllVNets, *vnet.ID)
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Process single Bastion host
// ------------------------------
func (m *BastionModule) processBastionHost(ctx context.Context, subID, subName, rgName string, bastion *armnetwork.BastionHost) {
	bastionName := azinternal.SafeStringPtr(bastion.Name)
	region := azinternal.SafeStringPtr(bastion.Location)

	// Extract SKU
	sku := "N/A"
	skuName := "N/A"
	if bastion.SKU != nil && bastion.SKU.Name != nil {
		skuName = string(*bastion.SKU.Name)
		sku = skuName
	}

	// Extract provisioning state
	provisioningState := "N/A"
	if bastion.Properties != nil && bastion.Properties.ProvisioningState != nil {
		provisioningState = string(*bastion.Properties.ProvisioningState)
	}

	// Extract VNet and subnet info
	vnetName := "N/A"
	vnetID := "N/A"
	subnetID := "N/A"
	ipConfigCount := 0

	if bastion.Properties != nil && bastion.Properties.IPConfigurations != nil {
		ipConfigCount = len(bastion.Properties.IPConfigurations)
		for _, ipConfig := range bastion.Properties.IPConfigurations {
			if ipConfig.Properties != nil && ipConfig.Properties.Subnet != nil && ipConfig.Properties.Subnet.ID != nil {
				subnetID = *ipConfig.Properties.Subnet.ID
				// Extract VNet ID from subnet ID
				// Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}
				parts := strings.Split(subnetID, "/")
				for i, part := range parts {
					if part == "virtualNetworks" && i+1 < len(parts) {
						vnetName = parts[i+1]
						// Reconstruct VNet ID
						vnetID = strings.Join(parts[:i+2], "/")
						break
					}
				}

				// Track VNet coverage
				if vnetID != "N/A" {
					m.mu.Lock()
					m.VNetCoverageMap[vnetID] = true
					m.mu.Unlock()
				}
			}
		}
	}

	// Extract DNS name
	dnsName := "N/A"
	if bastion.Properties != nil && bastion.Properties.DNSName != nil {
		dnsName = *bastion.Properties.DNSName
	}

	// Extract scale units (Premium SKU feature)
	scaleUnits := "N/A"
	if bastion.Properties != nil && bastion.Properties.ScaleUnits != nil {
		scaleUnits = fmt.Sprintf("%d", *bastion.Properties.ScaleUnits)
	}

	// Extract feature flags
	enableTunneling := "N/A"
	disableCopyPaste := "N/A"
	enableFileCopy := "N/A"
	enableIPConnect := "N/A"
	enableShareableLink := "N/A"
	enableKerberos := "N/A"

	if bastion.Properties != nil {
		if bastion.Properties.EnableTunneling != nil {
			enableTunneling = fmt.Sprintf("%t", *bastion.Properties.EnableTunneling)
		}
		if bastion.Properties.DisableCopyPaste != nil {
			disableCopyPaste = fmt.Sprintf("%t", *bastion.Properties.DisableCopyPaste)
		}
		if bastion.Properties.EnableFileCopy != nil {
			enableFileCopy = fmt.Sprintf("%t", *bastion.Properties.EnableFileCopy)
		}
		if bastion.Properties.EnableIPConnect != nil {
			enableIPConnect = fmt.Sprintf("%t", *bastion.Properties.EnableIPConnect)
		}
		if bastion.Properties.EnableShareableLink != nil {
			enableShareableLink = fmt.Sprintf("%t", *bastion.Properties.EnableShareableLink)
		}
		// Note: EnableKerberos field not available in current SDK version
		// if bastion.Properties.EnableKerberos != nil {
		// 	enableKerberos = fmt.Sprintf("%t", *bastion.Properties.EnableKerberos)
		// }
		enableKerberos = "N/A" // SDK does not expose this field
	}

	// Determine risk level
	risk := "INFO"
	riskReasons := []string{}

	if provisioningState != "Succeeded" && provisioningState != "N/A" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, fmt.Sprintf("Provisioning state: %s", provisioningState))
	}
	if enableShareableLink == "true" {
		risk = "MEDIUM"
		riskReasons = append(riskReasons, "Shareable links enabled (potential unauthorized access)")
	}
	if disableCopyPaste == "false" {
		// Copy/paste is enabled by default, which might be a concern for data exfiltration
		riskReasons = append(riskReasons, "Copy/paste enabled")
	}
	if enableFileCopy == "true" {
		riskReasons = append(riskReasons, "File transfer enabled")
	}

	riskNote := strings.Join(riskReasons, "; ")
	if riskNote == "" {
		riskNote = "Standard configuration"
	}

	// Thread-safe append
	m.mu.Lock()
	m.BastionRows = append(m.BastionRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		bastionName,
		sku,
		skuName,
		provisioningState,
		vnetName,
		dnsName,
		fmt.Sprintf("%d", ipConfigCount),
		scaleUnits,
		enableTunneling,
		disableCopyPaste,
		enableFileCopy,
		enableIPConnect,
		enableShareableLink,
		enableKerberos,
		risk,
		riskNote,
	})

	// Add to loot files
	if sku == "Premium" {
		m.LootMap["premium-features"].Contents += fmt.Sprintf("Bastion: %s (Subscription: %s, RG: %s)\n", bastionName, subName, rgName)
		m.LootMap["premium-features"].Contents += fmt.Sprintf("  SKU: %s\n", sku)
		m.LootMap["premium-features"].Contents += fmt.Sprintf("  Scale Units: %s\n", scaleUnits)
		m.LootMap["premium-features"].Contents += fmt.Sprintf("  Native Tunneling: %s\n", enableTunneling)
		m.LootMap["premium-features"].Contents += fmt.Sprintf("  IP Connect: %s\n", enableIPConnect)
		m.LootMap["premium-features"].Contents += fmt.Sprintf("  Kerberos: %s\n\n", enableKerberos)
	}
	if enableShareableLink == "true" {
		m.LootMap["shareable-links"].Contents += fmt.Sprintf("Bastion: %s (Subscription: %s, RG: %s)\n", bastionName, subName, rgName)
		m.LootMap["shareable-links"].Contents += fmt.Sprintf("  Risk: Shareable links enabled - potential unauthorized access\n")
		m.LootMap["shareable-links"].Contents += fmt.Sprintf("  VNet: %s\n", vnetName)
		m.LootMap["shareable-links"].Contents += fmt.Sprintf("  Recommendation: Disable shareable links unless required for external access\n")
		m.LootMap["shareable-links"].Contents += fmt.Sprintf("  Command: az network bastion update --name %s --resource-group %s --enable-shareable-link false\n\n", bastionName, rgName)
	}
	if enableFileCopy == "true" {
		m.LootMap["file-transfer"].Contents += fmt.Sprintf("Bastion: %s (Subscription: %s, RG: %s)\n", bastionName, subName, rgName)
		m.LootMap["file-transfer"].Contents += fmt.Sprintf("  File Transfer: Enabled\n")
		m.LootMap["file-transfer"].Contents += fmt.Sprintf("  Risk: Data exfiltration via file transfer\n")
		m.LootMap["file-transfer"].Contents += fmt.Sprintf("  VNet: %s\n\n", vnetName)
	}

	// Add enumeration commands
	m.LootMap["bastion-commands"].Contents += fmt.Sprintf("# Bastion: %s\n", bastionName)
	m.LootMap["bastion-commands"].Contents += fmt.Sprintf("az network bastion show --name %s --resource-group %s\n", bastionName, rgName)
	m.LootMap["bastion-commands"].Contents += fmt.Sprintf("# Connect to VM via Bastion:\n")
	m.LootMap["bastion-commands"].Contents += fmt.Sprintf("az network bastion rdp --name %s --resource-group %s --target-resource-id <VM_RESOURCE_ID>\n", bastionName, rgName)
	m.LootMap["bastion-commands"].Contents += fmt.Sprintf("az network bastion ssh --name %s --resource-group %s --target-resource-id <VM_RESOURCE_ID> --auth-type AAD\n\n", bastionName, rgName)
	m.mu.Unlock()
}

// ------------------------------
// Analyze VNet coverage
// ------------------------------
func (m *BastionModule) analyzeVNetCoverage() {
	totalVNets := len(m.AllVNets)
	protectedVNets := len(m.VNetCoverageMap)
	unprotectedVNets := totalVNets - protectedVNets

	coveragePercent := 0
	if totalVNets > 0 {
		coveragePercent = (protectedVNets * 100) / totalVNets
	}

	// Add to coverage rows
	m.CoverageRows = append(m.CoverageRows, []string{
		m.TenantName,
		m.TenantID,
		fmt.Sprintf("%d", totalVNets),
		fmt.Sprintf("%d", protectedVNets),
		fmt.Sprintf("%d", unprotectedVNets),
		fmt.Sprintf("%d%%", coveragePercent),
		fmt.Sprintf("%d", len(m.BastionRows)),
	})

	// Identify unprotected VNets
	for _, vnetID := range m.AllVNets {
		if !m.VNetCoverageMap[vnetID] {
			// Extract VNet name from ID
			parts := strings.Split(vnetID, "/")
			vnetName := "Unknown"
			if len(parts) > 0 {
				vnetName = parts[len(parts)-1]
			}

			m.LootMap["unprotected-vnets"].Contents += fmt.Sprintf("VNet: %s\n", vnetName)
			m.LootMap["unprotected-vnets"].Contents += fmt.Sprintf("  VNet ID: %s\n", vnetID)
			m.LootMap["unprotected-vnets"].Contents += fmt.Sprintf("  Risk: No Bastion protection - VMs require public IPs for RDP/SSH\n")
			m.LootMap["unprotected-vnets"].Contents += fmt.Sprintf("  Recommendation: Deploy Azure Bastion for secure access\n\n")
		}
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *BastionModule) writeOutput(ctx context.Context, logger internal.Logger) {
	totalRows := len(m.BastionRows) + len(m.CoverageRows)
	if totalRows == 0 {
		logger.InfoM("No Bastion hosts found", globals.AZ_BASTION_MODULE_NAME)
		return
	}

	// Define headers
	coverageHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Total VNets",
		"Protected VNets",
		"Unprotected VNets",
		"Coverage %",
		"Bastion Host Count",
	}

	bastionHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Bastion Name",
		"SKU",
		"SKU Name",
		"Provisioning State",
		"VNet Name",
		"DNS Name",
		"IP Config Count",
		"Scale Units",
		"Native Tunneling",
		"Disable Copy/Paste",
		"File Copy",
		"IP Connect",
		"Shareable Link",
		"Kerberos",
		"Risk",
		"Risk Note",
	}

	// -------------------- Check for multi-tenant splitting FIRST --------------------
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if len(m.CoverageRows) > 0 {
			if err := m.FilterAndWritePerTenantAuto(ctx, logger, m.Tenants, m.CoverageRows,
				coverageHeaders, "bastion-vnet-coverage", globals.AZ_BASTION_MODULE_NAME); err != nil {
				logger.ErrorM(fmt.Sprintf("Error writing per-tenant coverage: %v", err), globals.AZ_BASTION_MODULE_NAME)
			}
		}
		if len(m.BastionRows) > 0 {
			if err := m.FilterAndWritePerTenantAuto(ctx, logger, m.Tenants, m.BastionRows,
				bastionHeaders, "bastion-hosts", globals.AZ_BASTION_MODULE_NAME); err != nil {
				logger.ErrorM(fmt.Sprintf("Error writing per-tenant bastion hosts: %v", err), globals.AZ_BASTION_MODULE_NAME)
			}
		}
		logger.SuccessM(fmt.Sprintf("Bastion enumeration complete: %d hosts, %d coverage rows (split by tenant)",
			len(m.BastionRows), len(m.CoverageRows)), globals.AZ_BASTION_MODULE_NAME)
		return
	}

	// -------------------- Check for multi-subscription splitting SECOND --------------------
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if len(m.CoverageRows) > 0 {
			if err := m.FilterAndWritePerSubscriptionAuto(ctx, logger, m.Subscriptions, m.CoverageRows,
				coverageHeaders, "bastion-vnet-coverage", globals.AZ_BASTION_MODULE_NAME); err != nil {
				logger.ErrorM(fmt.Sprintf("Error writing per-subscription coverage: %v", err), globals.AZ_BASTION_MODULE_NAME)
			}
		}
		if len(m.BastionRows) > 0 {
			if err := m.FilterAndWritePerSubscriptionAuto(ctx, logger, m.Subscriptions, m.BastionRows,
				bastionHeaders, "bastion-hosts", globals.AZ_BASTION_MODULE_NAME); err != nil {
				logger.ErrorM(fmt.Sprintf("Error writing per-subscription bastion hosts: %v", err), globals.AZ_BASTION_MODULE_NAME)
			}
		}
		logger.SuccessM(fmt.Sprintf("Bastion enumeration complete: %d hosts, %d coverage rows (split by subscription)",
			len(m.BastionRows), len(m.CoverageRows)), globals.AZ_BASTION_MODULE_NAME)
		return
	}

	// -------------------- Build tables --------------------
	tables := []internal.TableFile{}

	if len(m.CoverageRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "bastion-vnet-coverage",
			Header: coverageHeaders,
			Body:   m.CoverageRows,
		})
	}

	if len(m.BastionRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "bastion-hosts",
			Header: bastionHeaders,
			Body:   m.BastionRows,
		})
	}

	// -------------------- Convert loot map to slice --------------------
	var loot []internal.LootFile
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// -------------------- Generate output --------------------
	output := BastionOutput{
		Table: tables,
		Loot:  loot,
	}

	// -------------------- Determine scope for output --------------------
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(
		m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// -------------------- Write output using HandleOutputSmart --------------------
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_BASTION_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// -------------------- Success summary --------------------
	logger.SuccessM(fmt.Sprintf("Bastion enumeration complete: %d hosts, %d coverage rows",
		len(m.BastionRows), len(m.CoverageRows)), globals.AZ_BASTION_MODULE_NAME)
}
