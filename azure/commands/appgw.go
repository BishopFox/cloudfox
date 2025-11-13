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
// Cobra command
// ------------------------------
var AzAppGatewayCommand = &cobra.Command{
	Use:     "app-gateway",
	Aliases: []string{"appgw"},
	Short:   "Enumerate Azure Application Gateways",
	Long: `
Enumerate Azure Application Gateways for a specific tenant:
./cloudfox az app-gateway --tenant TENANT_ID

Enumerate Azure Application Gateways for a specific subscription:
./cloudfox az app-gateway --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListAppGateway,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type AppGatewayModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions  []string
	AppGatewayRows [][]string
	LootMap        map[string]*internal.LootFile
	mu             sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type AppGatewayOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o AppGatewayOutput) TableFiles() []internal.TableFile { return o.Table }
func (o AppGatewayOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListAppGateway(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_APPGATEWAY_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &AppGatewayModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		AppGatewayRows:  [][]string{},
		LootMap: map[string]*internal.LootFile{
			"app-gateway-commands": {Name: "app-gateway-commands", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintAppGateways(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *AppGatewayModule) PrintAppGateways(ctx context.Context, logger internal.Logger) {
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
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_APPGATEWAY_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single-tenant mode
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_APPGATEWAY_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *AppGatewayModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
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
func (m *AppGatewayModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	appGateways := azinternal.GetAppGatewaysPerResourceGroup(m.Session, subID, rgName)
	for _, agw := range appGateways {
		if agw == nil || agw.Name == nil {
			continue
		}

		name := azinternal.GetAppGatewayName(agw)
		region := azinternal.GetAppGatewayLocation(agw)

		// Extract managed identity information
		var systemAssignedIDs []string
		var userAssignedIDs []string

		if agw.Identity != nil {
			// System-assigned identity
			if agw.Identity.PrincipalID != nil {
				principalID := *agw.Identity.PrincipalID
				systemAssignedIDs = append(systemAssignedIDs, principalID)
			}

			// User-assigned identities
			if agw.Identity.UserAssignedIdentities != nil {
				for uaID := range agw.Identity.UserAssignedIdentities {
					userAssignedIDs = append(userAssignedIDs, uaID)
				}
			}
		}

		// Format identity fields
		systemIDsStr := "N/A"
		if len(systemAssignedIDs) > 0 {
			systemIDsStr = strings.Join(systemAssignedIDs, ", ")
		}

		userIDsStr := "N/A"
		if len(userAssignedIDs) > 0 {
			userIDsStr = strings.Join(userAssignedIDs, ", ")
		}

		// Extract Min TLS Version from SSL Policy
		minTlsVersion := "N/A"
		if agw.Properties != nil && agw.Properties.SSLPolicy != nil && agw.Properties.SSLPolicy.MinProtocolVersion != nil {
			minTlsVersion = string(*agw.Properties.SSLPolicy.MinProtocolVersion)
		}

		// Process frontend IPs
		for _, fe := range azinternal.GetAppGatewayFrontendIPs(m.Session, subID, agw) {
			protocol := "HTTP"
			if agw.Properties != nil && agw.Properties.SSLCertificates != nil && len(agw.Properties.SSLCertificates) > 0 {
				protocol = "HTTPS"
				if agw.Properties.FrontendPorts != nil && len(agw.Properties.FrontendPorts) > 0 {
					protocol = "HTTP & HTTPS"
				}
			}

			exposure := "Private"
			if fe.PublicIP != "" {
				exposure = "Public"
			}

			// Collect custom headers
			customHeaders := []string{}
			for _, rule := range agw.Properties.RequestRoutingRules {
				if rule.Properties != nil && rule.Properties.RewriteRuleSet != nil && rule.Properties.RewriteRuleSet.ID != nil {
					rrSet, err := azinternal.GetRewriteRuleSetByID(m.Session, subID, *rule.Properties.RewriteRuleSet.ID)
					if err == nil {
						for _, rhc := range rrSet.RequestHeaderConfigurations {
							customHeaders = append(customHeaders, rhc.HeaderName)
						}
					}
				}
			}

			headerString := "N/A"
			if len(customHeaders) > 0 {
				headerString = strings.Join(customHeaders, ", ")
			}

			secrets := "None"
			certExpiration := "N/A"
			if agw.Properties != nil && agw.Properties.SSLCertificates != nil && len(agw.Properties.SSLCertificates) > 0 {
				secrets = "SSL/TLS cert(s)"
				certExpiration = "Requires Cert Parsing"
			}

			// Thread-safe append
			m.mu.Lock()
			m.AppGatewayRows = append(m.AppGatewayRows, []string{
				m.TenantName,
				m.TenantID,
				subID,
				subName,
				rgName,
				region,
				name,
				protocol,
				fe.DNSName,
				fe.PrivateIP,
				fe.PublicIP,
				headerString,
				secrets,
				exposure,
				minTlsVersion,
				certExpiration,
				systemIDsStr,
				userIDsStr,
			})
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *AppGatewayModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.AppGatewayRows) == 0 {
		logger.InfoM("No Application Gateways found", globals.AZ_APPGATEWAY_MODULE_NAME)
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
		"Name",
		"Protocol",
		"Hostname/DNS",
		"Private IP",
		"Public IP",
		"Custom Headers",
		"Secrets",
		"Exposure",
		"Min TLS Version",
		"Certificate Expiration",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant (takes precedence over subscription split)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.AppGatewayRows, headers,
			"app-gateway", globals.AZ_APPGATEWAY_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.AppGatewayRows, headers,
			"app-gateway", globals.AZ_APPGATEWAY_MODULE_NAME,
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
	output := AppGatewayOutput{
		Table: []internal.TableFile{{
			Name:   "app-gateway",
			Header: headers,
			Body:   m.AppGatewayRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_APPGATEWAY_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Application Gateway(s) across %d subscription(s)", len(m.AppGatewayRows), len(m.Subscriptions)), globals.AZ_APPGATEWAY_MODULE_NAME)
}
