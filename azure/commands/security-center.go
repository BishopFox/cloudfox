package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzSecurityCenterCommand = &cobra.Command{
	Use:     "security-center",
	Aliases: []string{"defender", "mdc", "security"},
	Short:   "Enumerate Microsoft Defender for Cloud security posture",
	Long: `
Enumerate Microsoft Defender for Cloud security posture for a specific tenant:
./cloudfox az security-center --tenant TENANT_ID

Enumerate Microsoft Defender for Cloud security posture for a specific subscription:
./cloudfox az security-center --subscription SUBSCRIPTION_ID

This module enumerates:
- Defender for Cloud plans (enabled/disabled per subscription)
- Security recommendations (High/Medium/Low severity)
- Secure Score (overall security posture)
- Unhealthy resources requiring attention
- Compliance assessments

Security Analysis:
- HIGH: Critical security recommendations requiring immediate action
- MEDIUM: Important recommendations that should be addressed
- LOW: Best practice recommendations for hardening`,
	Run: ListSecurityCenter,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type SecurityCenterModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions      []string
	SecurityRows       [][]string
	RecommendationRows [][]string
	DefenderPlanRows   [][]string
	LootMap            map[string]*internal.LootFile
	mu                 sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type SecurityCenterOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o SecurityCenterOutput) TableFiles() []internal.TableFile { return o.Table }
func (o SecurityCenterOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListSecurityCenter(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_SECURITY_CENTER_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &SecurityCenterModule{
		BaseAzureModule:    azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:      cmdCtx.Subscriptions,
		SecurityRows:       [][]string{},
		RecommendationRows: [][]string{},
		DefenderPlanRows:   [][]string{},
		LootMap: map[string]*internal.LootFile{
			"security-high-severity":        {Name: "security-high-severity", Contents: ""},
			"security-medium-severity":      {Name: "security-medium-severity", Contents: ""},
			"security-unhealthy-resources":  {Name: "security-unhealthy-resources", Contents: ""},
			"security-remediation-commands": {Name: "security-remediation-commands", Contents: ""},
			"security-disabled-defenders":   {Name: "security-disabled-defenders", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintSecurityCenter(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *SecurityCenterModule) PrintSecurityCenter(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_SECURITY_CENTER_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_SECURITY_CENTER_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_SECURITY_CENTER_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating Defender for Cloud security posture for %d subscription(s)", len(m.Subscriptions)), globals.AZ_SECURITY_CENTER_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_SECURITY_CENTER_MODULE_NAME, m.processSubscription)
	}

	// Generate remediation commands loot
	m.generateRemediationLoot()

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *SecurityCenterModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Process in parallel:
	// 1. Defender plans (enabled/disabled)
	// 2. Security recommendations
	// 3. Secure score
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		m.processDefenderPlans(ctx, subID, subName, logger)
	}()

	go func() {
		defer wg.Done()
		m.processSecurityRecommendations(ctx, subID, subName, logger)
	}()

	go func() {
		defer wg.Done()
		m.processSecureScore(ctx, subID, subName, logger)
	}()

	wg.Wait()
}

// ------------------------------
// Process Defender for Cloud plans
// ------------------------------
func (m *SecurityCenterModule) processDefenderPlans(ctx context.Context, subID, subName string, logger internal.Logger) {
	// Get token for Azure Resource Manager
	token, err := m.Session.GetTokenForResource(azinternal.ResourceToScope("https://management.azure.com/"))
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for subscription %s: %v", subID, err), globals.AZ_SECURITY_CENTER_MODULE_NAME)
		}
		return
	}

	// Create credential from token
	cred := azinternal.NewStaticTokenCredential(token)

	// Create Security client
	client, err := armsecurity.NewPricingsClient(cred, nil)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Security client for subscription %s: %v", subID, err), globals.AZ_SECURITY_CENTER_MODULE_NAME)
		}
		return
	}

	// List all Defender plans
	scope := fmt.Sprintf("subscriptions/%s", subID)
	response, err := client.List(ctx, scope, nil)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing Defender plans for subscription %s: %v", subID, err), globals.AZ_SECURITY_CENTER_MODULE_NAME)
		}
		return
	}

	if response.Value != nil {
		for _, pricing := range response.Value {
			if pricing == nil || pricing.Name == nil {
				continue
			}

			planName := *pricing.Name
			pricingTier := "Free"
			subPlan := ""
			deprecated := "No"
			enabled := "No"
			replacedBy := ""

			if pricing.Properties != nil {
				if pricing.Properties.PricingTier != nil {
					pricingTier = string(*pricing.Properties.PricingTier)
					if pricingTier == "Standard" {
						enabled = "Yes"
					}
				}
				if pricing.Properties.SubPlan != nil {
					subPlan = *pricing.Properties.SubPlan
				}
				if pricing.Properties.Deprecated != nil && *pricing.Properties.Deprecated {
					deprecated = "Yes"
				}
				if pricing.Properties.ReplacedBy != nil && len(pricing.Properties.ReplacedBy) > 0 {
					replacedBy = strings.Join(azinternal.SafeStringSlice(pricing.Properties.ReplacedBy), ", ")
				}
			}

			// Determine risk level
			riskLevel := "INFO"
			if pricingTier == "Free" && deprecated == "No" {
				riskLevel = "MEDIUM"
			}

			// Build row
			row := []string{
				subID,
				subName,
				planName,
				pricingTier,
				enabled,
				subPlan,
				deprecated,
				replacedBy,
				riskLevel,
			}

			// Add tenant info if multi-tenant
			if m.IsMultiTenant {
				row = append([]string{m.TenantName, m.TenantID}, row...)
			}

			// Thread-safe append
			m.mu.Lock()
			m.DefenderPlanRows = append(m.DefenderPlanRows, row)

			// Add to loot if disabled
			if pricingTier == "Free" && deprecated == "No" {
				lootEntry := fmt.Sprintf("[DISABLED] Subscription: %s (%s), Plan: %s\n", subName, subID, planName)
				m.LootMap["security-disabled-defenders"].Contents += lootEntry
			}
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Process security recommendations (assessments)
// ------------------------------
func (m *SecurityCenterModule) processSecurityRecommendations(ctx context.Context, subID, subName string, logger internal.Logger) {
	// Get token for Azure Resource Manager
	token, err := m.Session.GetTokenForResource(azinternal.ResourceToScope("https://management.azure.com/"))
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for subscription %s: %v", subID, err), globals.AZ_SECURITY_CENTER_MODULE_NAME)
		}
		return
	}

	// Create credential from token
	cred := azinternal.NewStaticTokenCredential(token)

	// Create Assessments client
	client, err := armsecurity.NewAssessmentsClient(cred, nil)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Assessments client for subscription %s: %v", subID, err), globals.AZ_SECURITY_CENTER_MODULE_NAME)
		}
		return
	}

	// List all security assessments for the subscription scope
	scope := fmt.Sprintf("subscriptions/%s", subID)
	pager := client.NewListPager(scope, nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing security assessments for subscription %s: %v", subID, err), globals.AZ_SECURITY_CENTER_MODULE_NAME)
			}
			return
		}

		for _, assessment := range page.Value {
			if assessment == nil || assessment.Name == nil || assessment.Properties == nil {
				continue
			}

			assessmentID := *assessment.Name
			displayName := ""
			description := ""
			severity := "Unknown"
			status := "Unknown"
			category := ""
			unhealthyResources := "0"
			healthyResources := "0"
			notApplicableResources := "0"

			props := assessment.Properties

			if props.DisplayName != nil {
				displayName = *props.DisplayName
			}
			if props.Status != nil && props.Status.Code != nil {
				status = string(*props.Status.Code)
			}
			if props.Metadata != nil {
				if props.Metadata.Severity != nil {
					severity = string(*props.Metadata.Severity)
				}
				if props.Metadata.Description != nil {
					description = *props.Metadata.Description
				}
				if props.Metadata.Categories != nil && len(props.Metadata.Categories) > 0 {
					categories := make([]string, len(props.Metadata.Categories))
					for i, cat := range props.Metadata.Categories {
						categories[i] = string(*cat)
					}
					category = strings.Join(categories, ", ")
				}
			}

			// Extract resource counts from status
			if props.Status != nil {
				if props.Status.Cause != nil {
					// Status cause can indicate resource counts
				}
			}

			// For subscription-level assessments, try to get resource counts
			if props.AdditionalData != nil {
				// Additional data may contain unhealthy resource counts
				// Note: AdditionalData type varies by SDK version - may need parsing
			}

			// Determine risk level based on severity and status
			riskLevel := "INFO"
			if status == "Unhealthy" {
				switch severity {
				case "High":
					riskLevel = "HIGH"
				case "Medium":
					riskLevel = "MEDIUM"
				case "Low":
					riskLevel = "LOW"
				}
			}

			// Build row
			row := []string{
				subID,
				subName,
				displayName,
				assessmentID,
				severity,
				status,
				category,
				unhealthyResources,
				healthyResources,
				notApplicableResources,
				description,
				riskLevel,
			}

			// Add tenant info if multi-tenant
			if m.IsMultiTenant {
				row = append([]string{m.TenantName, m.TenantID}, row...)
			}

			// Thread-safe append
			m.mu.Lock()
			m.RecommendationRows = append(m.RecommendationRows, row)

			// Add to loot based on severity and status
			if status == "Unhealthy" {
				lootEntry := fmt.Sprintf("[%s] %s - %s (Subscription: %s)\n", severity, displayName, assessmentID, subName)

				switch severity {
				case "High":
					m.LootMap["security-high-severity"].Contents += lootEntry
				case "Medium":
					m.LootMap["security-medium-severity"].Contents += lootEntry
				}

				// Add to unhealthy resources list
				if unhealthyResources != "0" {
					unhealthyLoot := fmt.Sprintf("%s - %s unhealthy resources\n", displayName, unhealthyResources)
					m.LootMap["security-unhealthy-resources"].Contents += unhealthyLoot
				}
			}
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Process secure score
// ------------------------------
func (m *SecurityCenterModule) processSecureScore(ctx context.Context, subID, subName string, logger internal.Logger) {
	// Get token for Azure Resource Manager
	token, err := m.Session.GetTokenForResource(azinternal.ResourceToScope("https://management.azure.com/"))
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ARM token for subscription %s: %v", subID, err), globals.AZ_SECURITY_CENTER_MODULE_NAME)
		}
		return
	}

	// Create credential from token
	cred := azinternal.NewStaticTokenCredential(token)

	// Create Secure Scores client
	client, err := armsecurity.NewSecureScoresClient(subID, cred, nil)
	if err != nil {
		if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Secure Scores client for subscription %s: %v", subID, err), globals.AZ_SECURITY_CENTER_MODULE_NAME)
		}
		return
	}

	// List secure scores for subscription
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if m.Verbosity >= globals.AZ_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing secure scores for subscription %s: %v", subID, err), globals.AZ_SECURITY_CENTER_MODULE_NAME)
			}
			return
		}

		for _, score := range page.Value {
			if score == nil || score.Name == nil || score.Properties == nil {
				continue
			}

			scoreName := *score.Name
			currentScore := "0"
			maxScore := "0"
			percentage := "0%"
			weightInt := int64(0)

			if score.Properties.Score != nil {
				if score.Properties.Score.Current != nil {
					currentScore = fmt.Sprintf("%.2f", *score.Properties.Score.Current)
				}
				if score.Properties.Score.Max != nil {
					maxScore = fmt.Sprintf("%d", *score.Properties.Score.Max)
					// Calculate percentage
					if *score.Properties.Score.Max > 0 && score.Properties.Score.Current != nil {
						pct := (*score.Properties.Score.Current / float64(*score.Properties.Score.Max)) * 100
						percentage = fmt.Sprintf("%.1f%%", pct)
					}
				}
			}
			if score.Properties.Weight != nil {
				weightInt = *score.Properties.Weight
			}

			// Determine risk level based on percentage
			riskLevel := "INFO"
			if score.Properties.Score != nil && score.Properties.Score.Current != nil && score.Properties.Score.Max != nil {
				pct := (*score.Properties.Score.Current / float64(*score.Properties.Score.Max)) * 100
				if pct < 50 {
					riskLevel = "HIGH"
				} else if pct < 75 {
					riskLevel = "MEDIUM"
				} else if pct < 90 {
					riskLevel = "LOW"
				}
			}

			// Build row
			row := []string{
				subID,
				subName,
				scoreName,
				currentScore,
				maxScore,
				percentage,
				fmt.Sprintf("%d", weightInt),
				riskLevel,
			}

			// Add tenant info if multi-tenant
			if m.IsMultiTenant {
				row = append([]string{m.TenantName, m.TenantID}, row...)
			}

			// Thread-safe append
			m.mu.Lock()
			m.SecurityRows = append(m.SecurityRows, row)
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Generate remediation commands loot
// ------------------------------
func (m *SecurityCenterModule) generateRemediationLoot() {
	m.mu.Lock()
	defer m.mu.Unlock()

	var commands strings.Builder
	commands.WriteString("# Microsoft Defender for Cloud Remediation Commands\n\n")

	// Commands to enable Defender plans
	commands.WriteString("## Enable Defender Plans\n\n")
	seenSubs := make(map[string]bool)
	for _, row := range m.DefenderPlanRows {
		var subID, subName, planName, pricingTier string
		if m.IsMultiTenant {
			if len(row) >= 11 {
				subID, subName, planName, pricingTier = row[2], row[3], row[4], row[5]
			}
		} else {
			if len(row) >= 9 {
				subID, subName, planName, pricingTier = row[0], row[1], row[2], row[3]
			}
		}

		if pricingTier == "Free" {
			key := fmt.Sprintf("%s:%s", subID, planName)
			if !seenSubs[key] {
				seenSubs[key] = true
				commands.WriteString(fmt.Sprintf("# Enable %s plan for subscription %s (%s)\n", planName, subName, subID))
				commands.WriteString(fmt.Sprintf("az security pricing create --name %s --subscription %s --tier Standard\n\n", planName, subID))
			}
		}
	}

	// Commands to view detailed recommendations
	commands.WriteString("\n## View Detailed Security Recommendations\n\n")
	seenAssessments := make(map[string]bool)
	for _, row := range m.RecommendationRows {
		var subID, assessmentID, status string
		if m.IsMultiTenant {
			if len(row) >= 14 {
				subID, assessmentID, status = row[2], row[5], row[7]
			}
		} else {
			if len(row) >= 12 {
				subID, assessmentID, status = row[0], row[3], row[5]
			}
		}

		if status == "Unhealthy" {
			key := fmt.Sprintf("%s:%s", subID, assessmentID)
			if !seenAssessments[key] {
				seenAssessments[key] = true
				commands.WriteString(fmt.Sprintf("# View assessment %s\n", assessmentID))
				commands.WriteString(fmt.Sprintf("az security assessment show --name %s --subscription %s\n\n", assessmentID, subID))
			}
		}
	}

	m.LootMap["security-remediation-commands"].Contents = commands.String()
}

// ------------------------------
// Write output
// ------------------------------
func (m *SecurityCenterModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// -------------------- TABLE 1: Secure Score --------------------
	secureScoreHeader := []string{
		"Subscription ID",
		"Subscription Name",
		"Score Name",
		"Current Score",
		"Max Score",
		"Percentage",
		"Weight",
		"Risk Level",
	}
	if m.IsMultiTenant {
		secureScoreHeader = append([]string{"Tenant Name", "Tenant ID"}, secureScoreHeader...)
	}

	// Sort secure score rows by subscription
	sort.Slice(m.SecurityRows, func(i, j int) bool {
		iOffset, jOffset := 0, 0
		if m.IsMultiTenant {
			iOffset, jOffset = 2, 2
		}
		if len(m.SecurityRows[i]) > iOffset && len(m.SecurityRows[j]) > jOffset {
			return m.SecurityRows[i][iOffset] < m.SecurityRows[j][jOffset]
		}
		return false
	})

	secureScoreTable := internal.TableFile{
		Name:      "secure-score",
		Header:    secureScoreHeader,
		Body:      m.SecurityRows,
		TableCols: secureScoreHeader,
	}

	// -------------------- TABLE 2: Defender Plans --------------------
	defenderPlansHeader := []string{
		"Subscription ID",
		"Subscription Name",
		"Plan Name",
		"Pricing Tier",
		"Enabled",
		"Sub Plan",
		"Deprecated",
		"Replaced By",
		"Risk Level",
	}
	if m.IsMultiTenant {
		defenderPlansHeader = append([]string{"Tenant Name", "Tenant ID"}, defenderPlansHeader...)
	}

	// Sort defender plan rows by subscription and plan name
	sort.Slice(m.DefenderPlanRows, func(i, j int) bool {
		iOffset, jOffset := 0, 0
		if m.IsMultiTenant {
			iOffset, jOffset = 2, 2
		}
		if len(m.DefenderPlanRows[i]) > iOffset+2 && len(m.DefenderPlanRows[j]) > jOffset+2 {
			if m.DefenderPlanRows[i][iOffset] == m.DefenderPlanRows[j][jOffset] {
				return m.DefenderPlanRows[i][iOffset+2] < m.DefenderPlanRows[j][jOffset+2]
			}
			return m.DefenderPlanRows[i][iOffset] < m.DefenderPlanRows[j][jOffset]
		}
		return false
	})

	defenderPlansTable := internal.TableFile{
		Name:      "defender-plans",
		Header:    defenderPlansHeader,
		Body:      m.DefenderPlanRows,
		TableCols: defenderPlansHeader,
	}

	// -------------------- TABLE 3: Security Recommendations --------------------
	recommendationsHeader := []string{
		"Subscription ID",
		"Subscription Name",
		"Recommendation",
		"Assessment ID",
		"Severity",
		"Status",
		"Category",
		"Unhealthy Resources",
		"Healthy Resources",
		"Not Applicable",
		"Description",
		"Risk Level",
	}
	if m.IsMultiTenant {
		recommendationsHeader = append([]string{"Tenant Name", "Tenant ID"}, recommendationsHeader...)
	}

	// Sort recommendation rows by severity (High -> Medium -> Low) then by status
	sort.Slice(m.RecommendationRows, func(i, j int) bool {
		iOffset, jOffset := 0, 0
		if m.IsMultiTenant {
			iOffset, jOffset = 2, 2
		}
		if len(m.RecommendationRows[i]) > iOffset+4 && len(m.RecommendationRows[j]) > jOffset+4 {
			// Sort by severity first (High=0, Medium=1, Low=2)
			severityOrder := map[string]int{"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}
			iSev := severityOrder[m.RecommendationRows[i][iOffset+4]]
			jSev := severityOrder[m.RecommendationRows[j][jOffset+4]]
			if iSev != jSev {
				return iSev < jSev
			}
			// Then by status (Unhealthy first)
			if m.RecommendationRows[i][iOffset+5] != m.RecommendationRows[j][jOffset+5] {
				return m.RecommendationRows[i][iOffset+5] == "Unhealthy"
			}
			// Finally by recommendation name
			return m.RecommendationRows[i][iOffset+2] < m.RecommendationRows[j][jOffset+2]
		}
		return false
	})

	recommendationsTable := internal.TableFile{
		Name:      "security-recommendations",
		Header:    recommendationsHeader,
		Body:      m.RecommendationRows,
		TableCols: recommendationsHeader,
	}

	// -------------------- Combine tables --------------------
	tables := []internal.TableFile{
		secureScoreTable,
		defenderPlansTable,
		recommendationsTable,
	}

	// -------------------- Convert loot map to slice --------------------
	var loot []internal.LootFile
	lootOrder := []string{
		"security-high-severity",
		"security-medium-severity",
		"security-unhealthy-resources",
		"security-disabled-defenders",
		"security-remediation-commands",
	}
	for _, key := range lootOrder {
		if lootFile, exists := m.LootMap[key]; exists && lootFile.Contents != "" {
			loot = append(loot, *lootFile)
		}
	}

	// -------------------- Generate output --------------------
	output := SecurityCenterOutput{
		Table: tables,
		Loot:  loot,
	}

	// -------------------- Determine output scope --------------------
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// -------------------- Write output --------------------
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
		logger.ErrorM(fmt.Sprintf("Failed to write output: %v", err), globals.AZ_SECURITY_CENTER_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d Defender plans, %d recommendations, %d secure scores across %d subscriptions",
		len(m.DefenderPlanRows),
		len(m.RecommendationRows),
		len(m.SecurityRows),
		len(m.Subscriptions)), globals.AZ_SECURITY_CENTER_MODULE_NAME)
}
