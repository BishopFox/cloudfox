package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command definition
// ------------------------------
var AzEnterpriseAppsCommand = &cobra.Command{
	Use:     "enterprise-apps",
	Aliases: []string{"apps", "applications"},
	Short:   "Enumerate Azure Enterprise Applications",
	Long: `
Enumerate Azure Enterprise Applications for a specific tenant:
./cloudfox az apps --tenant TENANT_ID

Enumerate Azure Enterprise Applications for a specific subscription:
./cloudfox az apps --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListEnterpriseApps,
}

// ------------------------------
// Module struct (hybrid AWS/Azure pattern)
// ------------------------------
type EnterpriseAppsModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions []string
	AppRows       [][]string
	LootMap       map[string]*internal.LootFile

	// Cache for service principals (fetched once per tenant to avoid rate limits)
	allServicePrincipals []azinternal.PrincipalInfo
	spCacheMu            sync.Mutex
	spCacheLoaded        bool

	mu sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type EnterpriseAppsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o EnterpriseAppsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o EnterpriseAppsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListEnterpriseApps(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &EnterpriseAppsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		AppRows:         [][]string{},
		LootMap: map[string]*internal.LootFile{
			"enterprise-apps-commands": {Name: "enterprise-apps-commands", Contents: ""},
		},
	}

	// -------------------- Execute module (processes all subscriptions) --------------------
	module.PrintEnterpriseApps(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *EnterpriseAppsModule) PrintEnterpriseApps(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			// -------------------- Fetch service principals ONCE per tenant (avoid rate limits) --------------------
			logger.InfoM(fmt.Sprintf("Fetching all service principals from tenant %s (one-time operation)...", m.TenantName), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
			allSPs, err := azinternal.ListServicePrincipals(ctx, m.Session, m.TenantID)
			if err != nil {
				logger.ErrorM(fmt.Sprintf("Failed to list service principals for tenant %s: %v", m.TenantName, err), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
				m.TenantID = savedTenantID
				m.TenantName = savedTenantName
				m.TenantInfo = savedTenantInfo
				continue
			}
			m.allServicePrincipals = allSPs
			m.spCacheLoaded = true
			logger.InfoM(fmt.Sprintf("Cached %d service principals for tenant %s", len(allSPs), m.TenantName), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)

			// -------------------- Process all subscriptions for this tenant --------------------
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_ENTERPRISE_APPS_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// -------------------- Fetch service principals ONCE (avoid rate limits) --------------------
		logger.InfoM("Fetching all service principals from tenant (one-time operation)...", globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
		allSPs, err := azinternal.ListServicePrincipals(ctx, m.Session, m.TenantID)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Failed to list service principals: %v", err), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
			return
		}
		m.allServicePrincipals = allSPs
		m.spCacheLoaded = true
		logger.InfoM(fmt.Sprintf("Cached %d service principals", len(allSPs)), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)

		// -------------------- Process all subscriptions --------------------
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_ENTERPRISE_APPS_MODULE_NAME, m.processSubscription)
	}

	// -------------------- Write output --------------------
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *EnterpriseAppsModule) processSubscription(ctx context.Context, subscriptionID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subscriptionID)

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Enterprise Applications for subscription %s (%s)", subName, subscriptionID), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
	}

	// -------------------- Enumerate resource groups --------------------
	resourceGroups := m.ResolveResourceGroups(subscriptionID)

	// -------------------- Process resource groups concurrently --------------------
	var wg sync.WaitGroup
	rgSemaphore := make(chan struct{}, 10) // Limit to 10 concurrent RGs
	for _, rgName := range resourceGroups {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.processResourceGroup(ctx, subscriptionID, subName, rgName, &wg, rgSemaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single resource group
// ------------------------------
func (m *EnterpriseAppsModule) processResourceGroup(ctx context.Context, subscriptionID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating enterprise applications for resource group %s in subscription %s", rgName, subscriptionID), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
	}

	// Get region for this resource group
	var region string
	if rg := azinternal.GetResourceGroupIDFromName(m.Session, subscriptionID, rgName); rg != nil {
		rgs := azinternal.GetResourceGroupsPerSubscription(m.Session, subscriptionID)
		for _, r := range rgs {
			if r.Name != nil && *r.Name == rgName && r.Location != nil {
				region = *r.Location
				break
			}
		}
	}

	// -------------------- Enumerate enterprise applications --------------------
	apps := azinternal.GetEnterpriseAppsPerResourceGroup(ctx, m.Session, subscriptionID, rgName)

	var appWg sync.WaitGroup
	for _, app := range apps {
		appWg.Add(1)
		go m.processApp(ctx, subscriptionID, subName, rgName, region, app, &appWg, logger)
	}

	appWg.Wait()
}

// ------------------------------
// Process single enterprise application
// ------------------------------
func (m *EnterpriseAppsModule) processApp(ctx context.Context, subscriptionID, subName, rgName, region string, app azinternal.Application, wg *sync.WaitGroup, logger internal.Logger) {
	defer wg.Done()

	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating enterprise application %s", app.DisplayName), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
	}

	// -------------------- Use cached service principals (already fetched) --------------------
	// No need to lock here - we only read after cache is loaded

	// -------------------- Split into user vs system SPs based on tags --------------------
	var userSPs []*azinternal.ServicePrincipal
	var systemSPs []*azinternal.ServicePrincipal
	var allSPIDs []string

	for _, sp := range m.allServicePrincipals {
		if sp.AppID == app.ObjectID || sp.AppID == azinternal.SafeString(app.ObjectID) || sp.AppID == azinternal.SafeString(app.AppID) {
			spObj := &azinternal.ServicePrincipal{
				DisplayName: &sp.DisplayName,
				AppId:       &sp.AppID,
				ObjectId:    &sp.ObjectID,
				// Permissions removed - not displayed in output and causes Graph API rate limits
			}

			allSPIDs = append(allSPIDs, sp.ObjectID)

			// Treat system SPs by tag if available
			if sp.DisplayName != "" && strings.Contains(sp.DisplayName, "WindowsAzureActiveDirectoryIntegratedApp") {
				systemSPs = append(systemSPs, spObj)
			} else {
				userSPs = append(userSPs, spObj)
			}
		}
	}

	// -------------------- Get consent grants for service principals --------------------
	adminConsentCount := 0
	userConsentCount := 0
	riskyGrantsCount := 0
	topPermissions := "None"

	// Get consent grants for all service principals associated with this app
	for _, spID := range allSPIDs {
		grants, err := azinternal.GetConsentGrantsForClient(ctx, m.Session, spID)
		if err == nil && len(grants) > 0 {
			adminCount, userCount, riskyCount, topPerms := azinternal.FormatConsentGrantSummary(grants)
			adminConsentCount += adminCount
			userConsentCount += userCount
			riskyGrantsCount += riskyCount
			if topPerms != "None" {
				topPermissions = topPerms
			}
		}
	}

	// Format consent grant columns
	adminConsentStr := fmt.Sprintf("%d", adminConsentCount)
	userConsentStr := fmt.Sprintf("%d", userConsentCount)
	riskyGrantsStr := "None"
	if riskyGrantsCount > 0 {
		riskyGrantsStr = fmt.Sprintf("⚠ %d Risky Grants", riskyGrantsCount)
	}

	// -------------------- Get application owners --------------------
	ownerCount := 0
	ownersList := "None"
	orphanedApp := "No"
	if app.ObjectID != "" {
		owners, err := azinternal.GetApplicationOwners(ctx, m.Session, app.ObjectID)
		if err == nil {
			ownerCount = owners.OwnerCount
			if ownerCount > 0 {
				ownersList = strings.Join(owners.OwnerUPNs, ", ")
			} else {
				orphanedApp = "⚠ Yes (No Owners)"
			}
		}
	}
	ownerCountStr := fmt.Sprintf("%d", ownerCount)

	// -------------------- Get publisher verification status --------------------
	publisherStatus := "Unverified"
	publisherName := "N/A"
	if app.ObjectID != "" {
		verification, err := azinternal.GetPublisherVerification(ctx, m.Session, app.ObjectID)
		if err == nil {
			if verification.IsVerified {
				publisherStatus = "✓ Verified"
				if verification.VerifiedPublisher != "" {
					publisherName = verification.VerifiedPublisher
				}
			} else {
				publisherStatus = "⚠ Unverified"
			}
		}
	}

	// -------------------- Append to table rows (thread-safe) --------------------
	m.mu.Lock()
	m.AppRows = append(m.AppRows, []string{
		m.TenantName,
		m.TenantID,
		subscriptionID,
		subName,
		rgName,
		region,
		azinternal.SafeString(app.DisplayName),
		azinternal.SafeString(app.ObjectID),
		azinternal.SafeString(app.AppID),
		strings.Join(azinternal.ExtractSPNames(userSPs), ", "),
		strings.Join(azinternal.ExtractSPIDs(userSPs), ", "),
		strings.Join(azinternal.ExtractSPNames(systemSPs), ", "),
		strings.Join(azinternal.ExtractSPIDs(systemSPs), ", "),
		adminConsentStr,
		userConsentStr,
		riskyGrantsStr,
		topPermissions,
		ownerCountStr,   // Owner Count
		ownersList,      // Application Owners (UPNs)
		orphanedApp,     // Orphaned App (No Owners)
		publisherStatus, // Publisher Verification Status
		publisherName,   // Verified Publisher Name
	})

	// -------------------- Generate loot commands --------------------
	m.LootMap["enterprise-apps-commands"].Contents += fmt.Sprintf(
		"## Enterprise Application: %s\n"+
			"# Az CLI:\n"+
			"az account set --subscription %s\n"+
			"az ad app show --id %s\n"+
			"az ad sp list --filter \"appId eq '%s'\"\n"+
			"## PowerShell equivalent\n"+
			"Set-AzContext -SubscriptionId %s\n"+
			"Get-AzADApplication -ObjectId %s\n"+
			"Get-AzADServicePrincipal -ApplicationId %s\n\n",
		azinternal.SafeString(app.DisplayName),
		subscriptionID,
		azinternal.SafeString(app.ObjectID),
		azinternal.SafeString(app.AppID),
		subscriptionID,
		azinternal.SafeString(app.ObjectID),
		azinternal.SafeString(app.AppID),
	)
	m.mu.Unlock()
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *EnterpriseAppsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.AppRows) == 0 {
		logger.InfoM("No Enterprise Applications found", globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
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
		"Object ID",
		"Application ID",
		"User Managed SP Names",
		"User Assigned Identity ID",
		"System Managed SP Names",
		"System Assigned Identity ID",
		"Admin Consent Grants",
		"User Consent Grants",
		"Risky Grants",
		"Top Permissions",
		"Owner Count",
		"Application Owners",
		"Orphaned App (No Owners)",
		"Publisher Verification",
		"Verified Publisher Name",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.AppRows, headers,
			"enterprise-apps", globals.AZ_ENTERPRISE_APPS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.AppRows, headers,
			"enterprise-apps", globals.AZ_ENTERPRISE_APPS_MODULE_NAME,
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
	output := EnterpriseAppsOutput{
		Table: []internal.TableFile{{
			Name:   "enterprise-apps",
			Header: headers,
			Body:   m.AppRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Enterprise Application(s) across %d subscription(s)", len(m.AppRows), len(m.Subscriptions)), globals.AZ_ENTERPRISE_APPS_MODULE_NAME)
}
