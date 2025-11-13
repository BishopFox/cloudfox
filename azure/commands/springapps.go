package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appplatform/armappplatform"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzSpringAppsCommand = &cobra.Command{
	Use:     "spring-apps",
	Aliases: []string{"springapps", "spring"},
	Short:   "Enumerate Azure Spring Apps services and applications",
	Long: `
Enumerate Azure Spring Apps for a specific tenant:
  ./cloudfox az spring-apps --tenant TENANT_ID

Enumerate Azure Spring Apps for a specific subscription:
  ./cloudfox az spring-apps --subscription SUBSCRIPTION_ID`,
	Run: ListSpringApps,
}

// ------------------------------
// Module struct
// ------------------------------
type SpringAppsModule struct {
	azinternal.BaseAzureModule

	Subscriptions []string
	ServiceRows   [][]string
	AppRows       [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type SpringAppsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o SpringAppsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o SpringAppsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListSpringApps(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_SPRINGAPPS_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &SpringAppsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		ServiceRows:     [][]string{},
		AppRows:         [][]string{},
		LootMap: map[string]*internal.LootFile{
			"springapps-commands": {Name: "springapps-commands", Contents: ""},
			"springapps-apps":     {Name: "springapps-apps", Contents: "# Azure Spring Apps Applications\n\n"},
		},
	}

	module.PrintSpringApps(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *SpringAppsModule) PrintSpringApps(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_SPRINGAPPS_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_SPRINGAPPS_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *SpringAppsModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups
	rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
	if len(rgs) == 0 {
		return
	}

	// Create Spring Apps client
	springClient, err := azinternal.GetSpringAppsClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Spring Apps client for subscription %s: %v", subID, err), globals.AZ_SPRINGAPPS_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Create Apps client
	appsClient, err := azinternal.GetSpringAppsAppsClient(m.Session, subID)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Spring Apps Apps client for subscription %s: %v", subID, err), globals.AZ_SPRINGAPPS_MODULE_NAME)
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
		go m.processResourceGroup(ctx, subID, subName, rgName, springClient, appsClient, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *SpringAppsModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, springClient *armappplatform.ServicesClient, appsClient *armappplatform.AppsClient, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
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

	// List Spring Apps services in resource group
	pager := springClient.NewListPager(rgName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list Spring Apps in %s/%s: %v", subID, rgName, err), globals.AZ_SPRINGAPPS_MODULE_NAME)
			}
			m.CommandCounter.Error++
			continue
		}

		for _, service := range page.Value {
			m.processService(ctx, subID, subName, rgName, region, service, appsClient, logger)
		}
	}
}

// ------------------------------
// Process single Spring Apps service
// ------------------------------
func (m *SpringAppsModule) processService(ctx context.Context, subID, subName, rgName, region string, service *armappplatform.ServiceResource, appsClient *armappplatform.AppsClient, logger internal.Logger) {
	if service == nil || service.Name == nil {
		return
	}

	serviceName := *service.Name

	// Extract service properties
	fqdn := "N/A"
	provisioningState := "N/A"
	zoneRedundant := "false"

	if service.Properties != nil {
		if service.Properties.Fqdn != nil {
			fqdn = *service.Properties.Fqdn
		}
		if service.Properties.ProvisioningState != nil {
			provisioningState = string(*service.Properties.ProvisioningState)
		}
		if service.Properties.ZoneRedundant != nil && *service.Properties.ZoneRedundant {
			zoneRedundant = "true"
		}
	}

	// Network profile
	publicNetworkAccess := "Enabled"
	vnetInjected := "No"
	outboundIPs := "N/A"
	appSubnetID := "N/A"
	serviceRuntimeSubnetID := "N/A"

	if service.Properties != nil && service.Properties.NetworkProfile != nil {
		np := service.Properties.NetworkProfile

		// VNet injection
		if np.AppSubnetID != nil && *np.AppSubnetID != "" {
			vnetInjected = "Yes"
			appSubnetID = azinternal.ExtractResourceName(*np.AppSubnetID)
		}
		if np.ServiceRuntimeSubnetID != nil && *np.ServiceRuntimeSubnetID != "" {
			serviceRuntimeSubnetID = azinternal.ExtractResourceName(*np.ServiceRuntimeSubnetID)
		}

		// Outbound IPs
		if np.OutboundIPs != nil && np.OutboundIPs.PublicIPs != nil && len(np.OutboundIPs.PublicIPs) > 0 {
			ips := []string{}
			for _, ip := range np.OutboundIPs.PublicIPs {
				if ip != nil {
					ips = append(ips, *ip)
				}
			}
			outboundIPs = strings.Join(ips, ", ")
		}

		// Determine public network access based on VNet injection
		if vnetInjected == "Yes" {
			publicNetworkAccess = "VNet Only"
		}
	}

	// SKU
	sku := "N/A"
	tier := "N/A"
	if service.SKU != nil {
		if service.SKU.Name != nil {
			sku = *service.SKU.Name
		}
		if service.SKU.Tier != nil {
			tier = *service.SKU.Tier
		}
	}

	// EntraID Centralized Auth - Spring Apps supports managed identities
	entraIDAuth := "Enabled" // Spring Apps uses Azure AD for management

	// Build service row
	// Spring Apps services don't support managed identities at the service level (only apps do)
	systemAssignedID := "N/A"
	userAssignedID := "N/A"

	serviceRow := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		serviceName,
		fqdn,
		provisioningState,
		publicNetworkAccess,
		vnetInjected,
		outboundIPs,
		appSubnetID,
		serviceRuntimeSubnetID,
		zoneRedundant,
		tier,
		sku,
		entraIDAuth,
		systemAssignedID,
		userAssignedID,
	}

	m.mu.Lock()
	m.ServiceRows = append(m.ServiceRows, serviceRow)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Enumerate applications within the service
	m.enumerateApps(ctx, subID, subName, rgName, serviceName, fqdn, appsClient, logger)

	// Generate loot
	m.generateServiceLoot(subID, subName, rgName, serviceName, fqdn, publicNetworkAccess)
}

// ------------------------------
// Enumerate applications within Spring Apps service
// ------------------------------
func (m *SpringAppsModule) enumerateApps(ctx context.Context, subID, subName, rgName, serviceName, serviceFqdn string, appsClient *armappplatform.AppsClient, logger internal.Logger) {
	appPager := appsClient.NewListPager(rgName, serviceName, nil)
	for appPager.More() {
		appPage, err := appPager.NextPage(ctx)
		if err != nil {
			if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Failed to list apps in Spring service %s: %v", serviceName, err), globals.AZ_SPRINGAPPS_MODULE_NAME)
			}
			continue
		}

		for _, app := range appPage.Value {
			m.processApp(ctx, subID, subName, rgName, serviceName, serviceFqdn, app)
		}
	}
}

// ------------------------------
// Process single application
// ------------------------------
func (m *SpringAppsModule) processApp(ctx context.Context, subID, subName, rgName, serviceName, serviceFqdn string, app *armappplatform.AppResource) {
	if app == nil || app.Name == nil {
		return
	}

	appName := *app.Name

	// Extract app properties
	publicEndpointEnabled := "false"
	httpsOnly := "false"
	appURL := "N/A"
	provisioningState := "N/A"

	if app.Properties != nil {
		if app.Properties.Public != nil && *app.Properties.Public {
			publicEndpointEnabled = "true"
		}
		if app.Properties.HTTPSOnly != nil && *app.Properties.HTTPSOnly {
			httpsOnly = "true"
		}
		if app.Properties.URL != nil {
			appURL = *app.Properties.URL
		}
		if app.Properties.ProvisioningState != nil {
			provisioningState = string(*app.Properties.ProvisioningState)
		}
	}

	// Managed identity
	identityType := "None"
	systemAssignedID := "N/A"
	userAssignedID := "N/A" // Not supported in current SDK

	if app.Identity != nil {
		if app.Identity.Type != nil {
			identityType = string(*app.Identity.Type)
		}
		if app.Identity.PrincipalID != nil {
			systemAssignedID = *app.Identity.PrincipalID
		}
	}

	// Build app row
	appRow := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		serviceName,
		appName,
		appURL,
		publicEndpointEnabled,
		httpsOnly,
		provisioningState,
		identityType,
		systemAssignedID,
		userAssignedID,
	}

	m.mu.Lock()
	m.AppRows = append(m.AppRows, appRow)
	m.mu.Unlock()

	// Generate app loot
	m.generateAppLoot(subID, subName, rgName, serviceName, appName, appURL, publicEndpointEnabled)
}

// ------------------------------
// Generate service loot
// ------------------------------
func (m *SpringAppsModule) generateServiceLoot(subID, subName, rgName, serviceName, fqdn, publicNetworkAccess string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	lf := m.LootMap["springapps-commands"]
	lf.Contents += fmt.Sprintf("## Spring Apps Service: %s (Resource Group: %s)\n", serviceName, rgName)
	lf.Contents += fmt.Sprintf("# Set subscription context\n")
	lf.Contents += fmt.Sprintf("az account set --subscription %s\n\n", subID)
	lf.Contents += fmt.Sprintf("# Show Spring Apps service details\n")
	lf.Contents += fmt.Sprintf("az spring show --name %s --resource-group %s\n\n", serviceName, rgName)
	lf.Contents += fmt.Sprintf("# List applications in Spring service\n")
	lf.Contents += fmt.Sprintf("az spring app list --service %s --resource-group %s -o table\n\n", serviceName, rgName)
	lf.Contents += fmt.Sprintf("# Show service configuration\n")
	lf.Contents += fmt.Sprintf("az spring config-server show --name %s --resource-group %s\n\n", serviceName, rgName)
	lf.Contents += fmt.Sprintf("# List test endpoints (if public access enabled)\n")
	lf.Contents += fmt.Sprintf("az spring test-endpoint list --name %s --resource-group %s\n\n", serviceName, rgName)
	lf.Contents += fmt.Sprintf("# PowerShell equivalent:\n")
	lf.Contents += fmt.Sprintf("Set-AzContext -SubscriptionId %s\n", subID)
	lf.Contents += fmt.Sprintf("Get-AzSpringService -Name %s -ResourceGroupName %s\n\n", serviceName, rgName)
	lf.Contents += "---\n\n"
}

// ------------------------------
// Generate app loot
// ------------------------------
func (m *SpringAppsModule) generateAppLoot(subID, subName, rgName, serviceName, appName, appURL, publicEndpointEnabled string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	lf := m.LootMap["springapps-apps"]
	lf.Contents += fmt.Sprintf("## App: %s (Service: %s, RG: %s)\n", appName, serviceName, rgName)
	lf.Contents += fmt.Sprintf("Subscription: %s\n", subName)
	if appURL != "N/A" {
		lf.Contents += fmt.Sprintf("URL: %s\n", appURL)
	}
	lf.Contents += fmt.Sprintf("Public Endpoint: %s\n", publicEndpointEnabled)
	lf.Contents += fmt.Sprintf("\n# Az CLI Commands:\n")
	lf.Contents += fmt.Sprintf("az spring app show --name %s --service %s --resource-group %s\n", appName, serviceName, rgName)
	lf.Contents += fmt.Sprintf("az spring app logs --name %s --service %s --resource-group %s --follow\n", appName, serviceName, rgName)
	lf.Contents += fmt.Sprintf("az spring app deployment list --app %s --service %s --resource-group %s\n\n", appName, serviceName, rgName)
}

// ------------------------------
// Write output
// ------------------------------
func (m *SpringAppsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.ServiceRows) == 0 {
		logger.InfoM("No Azure Spring Apps services found", globals.AZ_SPRINGAPPS_MODULE_NAME)
		return
	}

	// Define headers for both tables
	serviceHeader := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Service Name",
		"FQDN",
		"Provisioning State",
		"Public Network Access",
		"VNet Injected",
		"Outbound IPs",
		"App Subnet",
		"Service Runtime Subnet",
		"Zone Redundant",
		"Tier",
		"SKU",
		"EntraID Centralized Auth",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	appHeader := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Service Name",
		"App Name",
		"App URL",
		"Public Endpoint Enabled",
		"HTTPS Only",
		"Provisioning State",
		"Identity Type",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		if err := m.writePerTenant(ctx, logger, serviceHeader, appHeader); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.writePerSubscription(ctx, logger, serviceHeader, appHeader); err != nil {
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
	output := SpringAppsOutput{
		Table: []internal.TableFile{},
		Loot:  loot,
	}

	// Add Spring Apps services table
	output.Table = append(output.Table, internal.TableFile{
		Name:   "spring-apps",
		Header: serviceHeader,
		Body:   m.ServiceRows,
	})

	// Add applications table if we have apps
	if len(m.AppRows) > 0 {
		output.Table = append(output.Table, internal.TableFile{
			Name:   "spring-apps-applications",
			Header: appHeader,
			Body:   m.AppRows,
		})
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_SPRINGAPPS_MODULE_NAME)
		return
	}

	// Print summary
	totalResources := len(m.ServiceRows) + len(m.AppRows)
	logger.InfoM(fmt.Sprintf("Found %d Azure Spring Apps service(s) and %d application(s) (%d total) across %d subscription(s)", len(m.ServiceRows), len(m.AppRows), totalResources, len(m.Subscriptions)), globals.AZ_SPRINGAPPS_MODULE_NAME)
}

// ------------------------------
// Write per-tenant output (custom multi-table implementation)
// ------------------------------
func (m *SpringAppsModule) writePerTenant(ctx context.Context, logger internal.Logger, serviceHeader, appHeader []string) error {
	var lastErr error
	tenantColumnIndex := 1 // "Tenant ID" is at column 1 in both tables

	// Build loot array (same for all tenants in multi-tenant mode)
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	for _, tenantCtx := range m.Tenants {
		// Filter rows for this tenant
		filteredServices := m.filterRowsByTenant(m.ServiceRows, tenantColumnIndex, tenantCtx.TenantName, tenantCtx.TenantID)
		filteredApps := m.filterRowsByTenant(m.AppRows, tenantColumnIndex, tenantCtx.TenantName, tenantCtx.TenantID)

		// Skip if no data for this tenant
		if len(filteredServices) == 0 && len(filteredApps) == 0 {
			continue
		}

		// Build tables (only include non-empty ones)
		tables := []internal.TableFile{}
		if len(filteredServices) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "spring-apps",
				Header: serviceHeader,
				Body:   filteredServices,
			})
		}
		if len(filteredApps) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "spring-apps-applications",
				Header: appHeader,
				Body:   filteredApps,
			})
		}

		output := SpringAppsOutput{
			Table: tables,
			Loot:  loot,
		}

		// Create output for this single tenant
		scopeType := "tenant"
		scopeIDs := []string{tenantCtx.TenantID}
		scopeNames := []string{tenantCtx.TenantName}

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
			logger.ErrorM(fmt.Sprintf("Error writing output for tenant %s: %v", tenantCtx.TenantName, err), globals.AZ_SPRINGAPPS_MODULE_NAME)
			m.CommandCounter.Error++
			lastErr = err
		}
	}

	return lastErr
}

// ------------------------------
// Write per-subscription output (custom multi-table implementation)
// ------------------------------
func (m *SpringAppsModule) writePerSubscription(ctx context.Context, logger internal.Logger, serviceHeader, appHeader []string) error {
	var lastErr error
	subscriptionColumnIndex := 3 // "Subscription Name" is at column 3 in both tables (after Tenant Name and Tenant ID)

	// Build loot array (same for all subscriptions in multi-sub mode)
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	for _, subID := range m.Subscriptions {
		subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

		// Filter rows for this subscription
		filteredServices := m.filterRowsBySubscription(m.ServiceRows, subscriptionColumnIndex, subName, subID)
		filteredApps := m.filterRowsBySubscription(m.AppRows, subscriptionColumnIndex, subName, subID)

		// Skip if no data for this subscription
		if len(filteredServices) == 0 && len(filteredApps) == 0 {
			continue
		}

		// Build tables (only include non-empty ones)
		tables := []internal.TableFile{}
		if len(filteredServices) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "spring-apps",
				Header: serviceHeader,
				Body:   filteredServices,
			})
		}
		if len(filteredApps) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "spring-apps-applications",
				Header: appHeader,
				Body:   filteredApps,
			})
		}

		output := SpringAppsOutput{
			Table: tables,
			Loot:  loot,
		}

		// Create output for this single subscription
		scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput([]string{subID}, m.TenantID, m.TenantName, false)
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
			logger.ErrorM(fmt.Sprintf("Error writing output for subscription %s: %v", subName, err), globals.AZ_SPRINGAPPS_MODULE_NAME)
			m.CommandCounter.Error++
			lastErr = err
		}
	}

	return lastErr
}

// ------------------------------
// Filter rows by tenant
// ------------------------------
func (m *SpringAppsModule) filterRowsByTenant(rows [][]string, columnIndex int, tenantName, tenantID string) [][]string {
	var filtered [][]string
	for _, row := range rows {
		if len(row) > columnIndex {
			if row[columnIndex] == tenantName || row[columnIndex] == tenantID {
				filtered = append(filtered, row)
			}
		}
	}
	return filtered
}

// ------------------------------
// Filter rows by subscription
// ------------------------------
func (m *SpringAppsModule) filterRowsBySubscription(rows [][]string, columnIndex int, subName, subID string) [][]string {
	var filtered [][]string
	for _, row := range rows {
		if len(row) > columnIndex {
			if row[columnIndex] == subName || row[columnIndex] == subID {
				filtered = append(filtered, row)
			}
		}
	}
	return filtered
}
