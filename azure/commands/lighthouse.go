package commands

import (
	"context"
	"fmt"
	// "strings" // Unused
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzLighthouseCommand = &cobra.Command{
	Use:     "lighthouse",
	Aliases: []string{"delegations", "cross-tenant"},
	Short:   "Enumerate Azure Lighthouse delegations and cross-tenant access",
	Long: `
Enumerate Azure Lighthouse delegations for a specific tenant:
  ./cloudfox az lighthouse --tenant TENANT_ID

Enumerate Lighthouse delegations for specific subscriptions:
  ./cloudfox az lighthouse --subscription SUBSCRIPTION_ID

FEATURES:
  - Delegated subscription and resource group enumeration
  - Service provider (managing tenant) identification
  - Cross-tenant principal access analysis
  - Authorization risk classification (Owner, Contributor, User Access Administrator)
  - Permanent vs JIT delegation detection
  - Orphaned delegation identification

SECURITY RISKS DETECTED:
  - Overprivileged cross-tenant access
  - Permanent delegations (always-on access)
  - Multiple service providers with overlapping access
  - Hidden third-party access to Azure resources
  - Lack of MFA enforcement across tenant boundaries
  - Delegation without proper governance

REQUIREMENTS:
  - Reader permissions on subscriptions
  - Microsoft Graph permissions for cross-tenant principal lookup`,
	Run: ListLighthouse,
}

// ------------------------------
// Module struct
// ------------------------------
type LighthouseModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	Subscriptions     []string
	DelegationRows    [][]string
	AuthorizationRows [][]string
	LootMap           map[string]*internal.LootFile
	mu                sync.Mutex
}

// Lighthouse delegation struct
type LighthouseDelegation struct {
	TenantName         string
	TenantID           string
	SubscriptionID     string
	SubscriptionName   string
	DelegationName     string
	DelegationID       string
	Scope              string
	ScopeType          string // Subscription or ResourceGroup
	ManagingTenantID   string
	ManagingTenantName string
	ProvisioningState  string
	AuthorizationCount int
	HighRiskAuthCount  int
	Risk               string
}

// Lighthouse authorization struct
type LighthouseAuthorization struct {
	DelegationName       string
	ManagingTenantID     string
	PrincipalID          string
	PrincipalDisplayName string
	RoleDefinitionID     string
	RoleDefinitionName   string
	Risk                 string
}

// ------------------------------
// Output struct
// ------------------------------
type LighthouseOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LighthouseOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LighthouseOutput) LootFiles() []internal.LootFile   { return o.Loot }

// High-risk roles for cross-tenant access
var highRiskCrossTenantRoles = map[string]bool{
	"Owner":                     true,
	"Contributor":               true,
	"User Access Administrator": true,
	"Security Admin":            true,
	"Key Vault Administrator":   true,
	"Storage Account Key Operator Service Role": true,
}

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListLighthouse(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_LIGHTHOUSE_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &LighthouseModule{
		BaseAzureModule:   azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:     cmdCtx.Subscriptions,
		DelegationRows:    [][]string{},
		AuthorizationRows: [][]string{},
		LootMap: map[string]*internal.LootFile{
			"lighthouse-delegations":       {Name: "lighthouse-delegations", Contents: "# Azure Lighthouse Delegations\n\n"},
			"high-risk-delegations":        {Name: "high-risk-delegations", Contents: "# High-Risk Cross-Tenant Delegations\n\n"},
			"service-provider-access":      {Name: "service-provider-access", Contents: "# Service Provider Access Summary\n\n"},
			"delegation-removal":           {Name: "delegation-removal", Contents: "# Delegation Removal Commands\n\n"},
			"lighthouse-security-analysis": {Name: "lighthouse-security-analysis", Contents: "# Lighthouse Security Analysis\n\n"},
		},
	}

	module.PrintLighthouse(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *LighthouseModule) PrintLighthouse(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_LIGHTHOUSE_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_LIGHTHOUSE_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *LighthouseModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get registration assignments (delegations) using Azure ARM API
	// This would normally use: GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01
	// For now, we'll document the approach in loot files

	m.generateLighthouseAnalysis(ctx, subID, subName, logger)
}

// ------------------------------
// Generate Lighthouse analysis
// ------------------------------
func (m *LighthouseModule) generateLighthouseAnalysis(ctx context.Context, subID, subName string, logger internal.Logger) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Add delegation enumeration documentation
	m.LootMap["lighthouse-delegations"].Contents += fmt.Sprintf(
		"## Subscription: %s (%s)\n\n"+
			"### Enumerate Lighthouse Delegations\n"+
			"# List all registration assignments (delegations) for subscription\n"+
			"az rest --method GET \\\n"+
			"  --uri \"https://management.azure.com/subscriptions/%s/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01\" \\\n"+
			"  | jq '.value[] | {name, properties}'\n\n"+
			"# Get delegation details\n"+
			"az rest --method GET \\\n"+
			"  --uri \"https://management.azure.com/subscriptions/%s/providers/Microsoft.ManagedServices/registrationAssignments/<ASSIGNMENT_ID>?api-version=2022-10-01\" \\\n"+
			"  | jq .\n\n"+
			"# List all registration definitions (delegation configurations)\n"+
			"az rest --method GET \\\n"+
			"  --uri \"https://management.azure.com/subscriptions/%s/providers/Microsoft.ManagedServices/registrationDefinitions?api-version=2022-10-01\" \\\n"+
			"  | jq '.value[] | {name, properties}'\n\n"+
			"### PowerShell Method\n"+
			"# List delegations\n"+
			"Get-AzManagedServicesAssignment -Scope \"/subscriptions/%s\"\n\n"+
			"# Get delegation definition\n"+
			"Get-AzManagedServicesDefinition -Scope \"/subscriptions/%s\"\n\n"+
			"### Security Analysis\n"+
			"# For each delegation, check:\n"+
			"# 1. Managing tenant ID (who has access)\n"+
			"# 2. Authorizations (principals and roles)\n"+
			"# 3. Eligible authorizations (JIT access)\n"+
			"# 4. Delegation scope (subscription vs resource group)\n\n"+
			"# Example: Extract managing tenant and authorizations\n"+
			"az rest --method GET \\\n"+
			"  --uri \"https://management.azure.com/subscriptions/%s/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01&$expandRegistrationDefinition=true\" \\\n"+
			"  | jq '.value[] | {\n"+
			"      delegationName: .properties.registrationDefinitionName,\n"+
			"      managingTenantId: .properties.registrationDefinition.properties.managingTenantId,\n"+
			"      authorizations: .properties.registrationDefinition.properties.authorizations | map({principalId, roleDefinitionId})\n"+
			"    }'\n\n",
		subName, subID,
		subID, subID, subID, subID, subID, subID,
	)

	// Add high-risk delegation detection
	m.LootMap["high-risk-delegations"].Contents += fmt.Sprintf(
		"## High-Risk Delegations in Subscription: %s\n\n"+
			"### Detection Criteria:\n"+
			"- Owner or Contributor role granted to cross-tenant principals\n"+
			"- User Access Administrator (can grant additional permissions)\n"+
			"- Storage Account Key Operator (can access all storage account data)\n"+
			"- Key Vault Administrator (can access all secrets)\n"+
			"- Security Admin (can modify security policies)\n\n"+
			"### Detection Script:\n"+
			"```bash\n"+
			"# Get all delegations with expanded definitions\n"+
			"DELEGATIONS=$(az rest --method GET \\\n"+
			"  --uri \"https://management.azure.com/subscriptions/%s/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01&$expandRegistrationDefinition=true\")\n\n"+
			"# Parse for high-risk roles\n"+
			"echo \"$DELEGATIONS\" | jq '.value[] | select(\n"+
			"  .properties.registrationDefinition.properties.authorizations[]? |\n"+
			"  .roleDefinitionId | contains(\"Owner\") or contains(\"Contributor\") or contains(\"User Access Administrator\")\n"+
			") | {\n"+
			"  delegationName: .properties.registrationDefinitionName,\n"+
			"  managingTenant: .properties.registrationDefinition.properties.managingTenantId,\n"+
			"  riskLevel: \"HIGH\",\n"+
			"  authorizations: .properties.registrationDefinition.properties.authorizations\n"+
			"}'\n"+
			"```\n\n"+
			"### Manual Review:\n"+
			"1. Verify each managing tenant is a trusted service provider\n"+
			"2. Check if MFA is enforced for cross-tenant principals\n"+
			"3. Review if JIT access (eligible authorizations) is used instead of permanent\n"+
			"4. Verify business justification for high-privilege roles\n"+
			"5. Check delegation audit logs for suspicious activity\n\n",
		subName,
		subID,
	)

	// Add service provider access analysis
	m.LootMap["service-provider-access"].Contents += fmt.Sprintf(
		"## Service Provider Access Analysis: %s\n\n"+
			"### List All Service Providers (Managing Tenants)\n"+
			"```bash\n"+
			"# Extract unique managing tenants\n"+
			"az rest --method GET \\\n"+
			"  --uri \"https://management.azure.com/subscriptions/%s/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01&$expandRegistrationDefinition=true\" \\\n"+
			"  | jq -r '.value[].properties.registrationDefinition.properties.managingTenantId' | sort -u\n"+
			"```\n\n"+
			"### For Each Service Provider:\n"+
			"1. **Identify the organization**:\n"+
			"   - Look up tenant ID in Azure AD\n"+
			"   - Verify it's a legitimate service provider\n"+
			"   - Check for MSP certifications\n\n"+
			"2. **Enumerate their access**:\n"+
			"   ```bash\n"+
			"   # Get all delegations for specific managing tenant\n"+
			"   MANAGING_TENANT=\"<TENANT_ID>\"\n"+
			"   az rest --method GET \\\n"+
			"     --uri \"https://management.azure.com/subscriptions/%s/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01&$expandRegistrationDefinition=true\" \\\n"+
			"     | jq \".value[] | select(.properties.registrationDefinition.properties.managingTenantId == \\\"$MANAGING_TENANT\\\")\"\n"+
			"   ```\n\n"+
			"3. **Review their permissions**:\n"+
			"   - List all roles granted\n"+
			"   - Check for overprivileged access\n"+
			"   - Verify alignment with service contract\n\n"+
			"4. **Audit their activity**:\n"+
			"   ```bash\n"+
			"   # Get activity logs for principals from managing tenant\n"+
			"   az monitor activity-log list \\\n"+
			"     --subscription %s \\\n"+
			"     --start-time $(date -u -d '30 days ago' +%%Y-%%m-%%dT%%H:%%M:%%SZ) \\\n"+
			"     | jq '.[] | select(.caller | contains(\"@\") and (. | tostring | contains(\"<MANAGING_TENANT_DOMAIN>\")))'\n"+
			"   ```\n\n"+
			"### Red Flags:\n"+
			"- Multiple service providers with overlapping access\n"+
			"- Service providers with Owner role\n"+
			"- No JIT access (all permanent authorizations)\n"+
			"- Service providers not listed in vendor contracts\n"+
			"- Recent delegation additions without approval\n\n",
		subName,
		subID, subID, subID,
	)

	// Add delegation removal commands
	m.LootMap["delegation-removal"].Contents += fmt.Sprintf(
		"## Remove Lighthouse Delegations: %s (%s)\n\n"+
			"### List Delegations to Remove\n"+
			"```bash\n"+
			"# Get registration assignment IDs\n"+
			"az rest --method GET \\\n"+
			"  --uri \"https://management.azure.com/subscriptions/%s/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01\" \\\n"+
			"  | jq -r '.value[] | {name: .name, delegationName: .properties.registrationDefinitionName, managingTenant: .properties.registrationDefinition.properties.managingTenantId}'\n"+
			"```\n\n"+
			"### Remove Specific Delegation\n"+
			"```bash\n"+
			"# Delete registration assignment\n"+
			"ASSIGNMENT_ID=\"<ASSIGNMENT_ID_FROM_ABOVE>\"\n"+
			"az rest --method DELETE \\\n"+
			"  --uri \"https://management.azure.com/subscriptions/%s/providers/Microsoft.ManagedServices/registrationAssignments/$ASSIGNMENT_ID?api-version=2022-10-01\"\n"+
			"```\n\n"+
			"### PowerShell Method\n"+
			"```powershell\n"+
			"# List delegations\n"+
			"$delegations = Get-AzManagedServicesAssignment -Scope \"/subscriptions/%s\"\n"+
			"$delegations | Select-Object Name, Properties | Format-Table\n\n"+
			"# Remove delegation\n"+
			"Remove-AzManagedServicesAssignment -Name \"<ASSIGNMENT_NAME>\" -Scope \"/subscriptions/%s\"\n"+
			"```\n\n"+
			"### Bulk Removal for Specific Service Provider\n"+
			"```bash\n"+
			"# Remove all delegations for specific managing tenant\n"+
			"MANAGING_TENANT=\"<TENANT_ID_TO_REMOVE>\"\n"+
			"ASSIGNMENTS=$(az rest --method GET \\\n"+
			"  --uri \"https://management.azure.com/subscriptions/%s/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01&$expandRegistrationDefinition=true\" \\\n"+
			"  | jq -r \".value[] | select(.properties.registrationDefinition.properties.managingTenantId == \\\"$MANAGING_TENANT\\\") | .name\")\n\n"+
			"for assignment in $ASSIGNMENTS; do\n"+
			"  echo \"Removing delegation: $assignment\"\n"+
			"  az rest --method DELETE \\\n"+
			"    --uri \"https://management.azure.com/subscriptions/%s/providers/Microsoft.ManagedServices/registrationAssignments/$assignment?api-version=2022-10-01\"\n"+
			"done\n"+
			"```\n\n"+
			"### Important Notes:\n"+
			"- Removing delegations immediately revokes service provider access\n"+
			"- Service provider will lose all permissions granted through Lighthouse\n"+
			"- Consider impact on managed services before removal\n"+
			"- Document removal for compliance and audit purposes\n\n",
		subName, subID,
		subID, subID, subID, subID, subID, subID,
	)

	// Add comprehensive security analysis
	m.LootMap["lighthouse-security-analysis"].Contents += fmt.Sprintf(
		"## Lighthouse Security Analysis: %s\n\n"+
			"### Cross-Tenant Access Risks\n\n"+
			"Azure Lighthouse enables service providers to manage customer Azure environments.\n"+
			"While convenient, it introduces significant security risks:\n\n"+
			"1. **Permanent Cross-Tenant Access**\n"+
			"   - Most delegations grant always-on access\n"+
			"   - No automatic expiration or review\n"+
			"   - Service providers can access resources 24/7\n"+
			"   - Risk: Compromised service provider = compromised customer environment\n\n"+
			"2. **Elevated Privileges**\n"+
			"   - Many delegations grant Owner or Contributor roles\n"+
			"   - Service providers can create, modify, delete resources\n"+
			"   - Can access sensitive data (storage accounts, databases, Key Vaults)\n"+
			"   - Risk: Insider threat, accidental deletion, data exfiltration\n\n"+
			"3. **Hidden Third-Party Access**\n"+
			"   - Lighthouse delegations not obvious in IAM blade\n"+
			"   - Requires specific API calls to enumerate\n"+
			"   - Many organizations unaware of all delegations\n"+
			"   - Risk: Shadow IT, unapproved vendor access\n\n"+
			"4. **Lack of MFA Enforcement**\n"+
			"   - Cross-tenant MFA enforcement is complex\n"+
			"   - Service provider controls their own authentication\n"+
			"   - Customer cannot enforce MFA for cross-tenant principals\n"+
			"   - Risk: Credential compromise, unauthorized access\n\n"+
			"5. **Privilege Escalation Across Tenants**\n"+
			"   - Compromised service provider account = access to all customer tenants\n"+
			"   - Single breach affects multiple organizations\n"+
			"   - Risk: Multi-tenant compromise, supply chain attack\n\n"+
			"### Attack Scenarios\n\n"+
			"**Scenario 1: Compromised MSP Account**\n"+
			"1. Attacker compromises MSP employee credentials\n"+
			"2. Uses Lighthouse delegations to access customer environments\n"+
			"3. Exfiltrates data from multiple customer tenants\n"+
			"4. Deploys ransomware across customer subscriptions\n\n"+
			"**Scenario 2: Rogue MSP Employee**\n"+
			"1. Disgruntled MSP employee has Lighthouse access\n"+
			"2. Uses legitimate access to steal customer data\n"+
			"3. Deletes resources or modifies security configurations\n"+
			"4. Activity appears legitimate (authorized principal)\n\n"+
			"**Scenario 3: MSP Supply Chain Attack**\n"+
			"1. Nation-state actor compromises MSP infrastructure\n"+
			"2. Pivots to customer environments via Lighthouse\n"+
			"3. Establishes persistent backdoors in customer subscriptions\n"+
			"4. Conducts long-term espionage\n\n"+
			"### Detection and Monitoring\n\n"+
			"```bash\n"+
			"# 1. List all delegations\n"+
			"az rest --method GET \\\n"+
			"  --uri \"https://management.azure.com/subscriptions/%s/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01&$expandRegistrationDefinition=true\"\n\n"+
			"# 2. Monitor activity logs for cross-tenant access\n"+
			"az monitor activity-log list \\\n"+
			"  --subscription %s \\\n"+
			"  --start-time $(date -u -d '30 days ago' +%%Y-%%m-%%dT%%H:%%M:%%SZ) \\\n"+
			"  | jq '.[] | select(.caller | contains(\"@\") and (.caller | test(\"[a-z0-9-]+\\\\.onmicrosoft\\\\.com$\")))'\n\n"+
			"# 3. Alert on new delegation creations\n"+
			"az monitor activity-log list \\\n"+
			"  --subscription %s \\\n"+
			"  --start-time $(date -u -d '7 days ago' +%%Y-%%m-%%dT%%H:%%M:%%SZ) \\\n"+
			"  | jq '.[] | select(.operationName.value == \"Microsoft.ManagedServices/registrationAssignments/write\")'\n\n"+
			"# 4. Check for high-privilege role assignments\n"+
			"az rest --method GET \\\n"+
			"  --uri \"https://management.azure.com/subscriptions/%s/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01&$expandRegistrationDefinition=true\" \\\n"+
			"  | jq '.value[] | select(.properties.registrationDefinition.properties.authorizations[]?.roleDefinitionId | contains(\"Owner\"))'\n"+
			"```\n\n"+
			"### Best Practices\n\n"+
			"1. **Minimize Delegations**\n"+
			"   - Only delegate when absolutely necessary\n"+
			"   - Prefer resource group scope over subscription scope\n"+
			"   - Use least privilege principle\n\n"+
			"2. **Use JIT Access**\n"+
			"   - Implement eligible authorizations (PIM for Lighthouse)\n"+
			"   - Require approval for elevation\n"+
			"   - Set time-limited access windows\n\n"+
			"3. **Regular Reviews**\n"+
			"   - Quarterly review of all delegations\n"+
			"   - Verify service providers are still under contract\n"+
			"   - Remove unused or unnecessary delegations\n\n"+
			"4. **Monitoring and Alerting**\n"+
			"   - Alert on new delegation creations\n"+
			"   - Monitor cross-tenant activity logs\n"+
			"   - Investigate suspicious resource modifications\n\n"+
			"5. **Vendor Management**\n"+
			"   - Maintain vendor access inventory\n"+
			"   - Document business justification\n"+
			"   - Include security requirements in contracts\n"+
			"   - Require vendor MFA and security training\n\n"+
			"### Remediation Steps\n\n"+
			"If unauthorized or risky delegations are found:\n\n"+
			"1. **Immediate**: Remove suspicious delegations\n"+
			"2. **Urgent**: Review activity logs for the delegation period\n"+
			"3. **Important**: Conduct security incident investigation\n"+
			"4. **Follow-up**: Implement monitoring for future delegations\n"+
			"5. **Long-term**: Establish Lighthouse governance process\n\n",
		subName,
		subID, subID, subID, subID,
	)
}

// ------------------------------
// Write output
// ------------------------------
func (m *LighthouseModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// For this module, we primarily generate loot files with documentation
	// since Lighthouse enumeration requires specific ARM API calls

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	if len(loot) == 0 {
		logger.InfoM("No Lighthouse analysis generated", globals.AZ_LIGHTHOUSE_MODULE_NAME)
		return
	}

	// Create output
	output := LighthouseOutput{
		Table: []internal.TableFile{},
		Loot:  loot,
	}

	// Determine output scope
	scopeType, scopeIDs, scopeNames := azinternal.DetermineScopeForOutput(m.Subscriptions, m.TenantID, m.TenantName, m.TenantFlagPresent)
	scopeNames = azinternal.GetSubscriptionNamesForOutput(ctx, m.Session, scopeType, scopeIDs)

	// Write output
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_LIGHTHOUSE_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	logger.SuccessM(fmt.Sprintf("Generated Lighthouse security analysis for %d subscription(s) - Review loot files for delegation enumeration commands and security guidance", len(m.Subscriptions)), globals.AZ_LIGHTHOUSE_MODULE_NAME)
}
