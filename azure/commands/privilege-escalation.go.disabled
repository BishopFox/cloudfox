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
var AzPrivilegeEscalationCommand = &cobra.Command{
	Use:     "privilege-escalation",
	Aliases: []string{"privesc", "escalation-paths"},
	Short:   "Detect privilege escalation paths through RBAC and resource permissions",
	Long: `
Enumerate privilege escalation paths for a specific tenant:
  ./cloudfox az privilege-escalation --tenant TENANT_ID

Enumerate for specific subscriptions:
  ./cloudfox az privilege-escalation --subscription SUBSCRIPTION_ID

FEATURES:
  - High-risk role assignment detection (Owner, Contributor, User Access Administrator)
  - Automation Account privilege escalation paths
  - Key Vault access privilege escalation
  - VM command execution privilege escalation
  - Managed identity impersonation paths
  - Service principal credential access paths
  - Dangerous permission combinations

ESCALATION VECTORS DETECTED:
  1. Owner/Contributor on Automation Account → Execute runbooks with privileged managed identity
  2. Contributor on Key Vault → Access secrets and certificates
  3. User Access Administrator → Grant additional roles
  4. VM Contributor → Execute commands on VMs with managed identity
  5. Key Vault Contributor → Modify access policies
  6. Managed Identity Operator → Impersonate managed identities
  7. Website Contributor → Deploy malicious code to web apps with managed identity
  8. Storage Account Key Operator Service Role → Access storage account keys

REQUIREMENTS:
  - Reader permissions on subscriptions
  - Microsoft Graph permissions for Azure AD role assignments`,
	Run: ListPrivilegeEscalation,
}

// ------------------------------
// Module struct
// ------------------------------
type PrivilegeEscalationModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	Subscriptions    []string
	EscalationRows   [][]string
	DangerousRoleMap map[string][]string // Maps dangerous roles to escalation techniques
	LootMap          map[string]*internal.LootFile
	mu               sync.Mutex
}

// Escalation path struct
type EscalationPath struct {
	TenantName       string
	TenantID         string
	SubscriptionID   string
	SubscriptionName string
	PrincipalName    string
	PrincipalID      string
	PrincipalType    string
	RoleName         string
	Scope            string
	ScopeType        string // Subscription, ResourceGroup, Resource
	ResourceType     string // Automation, KeyVault, VM, etc.
	EscalationVector string
	Risk             string
	Technique        string
}

// ------------------------------
// Output struct
// ------------------------------
type PrivilegeEscalationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PrivilegeEscalationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PrivilegeEscalationOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Dangerous role definitions
// ------------------------------
var dangerousRoles = map[string][]string{
	"Owner": {
		"Full control over all resources",
		"Can grant roles to others",
		"Access to all resource secrets and keys",
		"Execute code on Automation/VMs/Functions",
	},
	"Contributor": {
		"Can create/modify/delete resources",
		"Execute code on Automation/VMs/Functions",
		"Access resource configurations",
		"Cannot grant roles (unless combined with other roles)",
	},
	"User Access Administrator": {
		"Grant any role to any principal",
		"Instant privilege escalation to Owner",
		"Modify role assignments",
	},
	"Automation Account Contributor": {
		"Create/modify Automation runbooks",
		"Execute runbooks with account's managed identity",
		"Potential code execution as privileged identity",
	},
	"Automation Account Operator": {
		"Start/stop runbooks",
		"Execute existing runbooks",
		"Limited escalation if runbooks are privileged",
	},
	"Key Vault Contributor": {
		"Modify Key Vault access policies",
		"Grant yourself access to all secrets",
		"Access certificates and keys",
	},
	"Virtual Machine Contributor": {
		"Execute commands on VMs",
		"Access VM configurations",
		"Potential credential theft from VMs",
		"Impersonate VM managed identity",
	},
	"Managed Identity Operator": {
		"Assign managed identities to resources",
		"Impersonate managed identities",
		"Lateral movement via identity assumption",
	},
	"Website Contributor": {
		"Deploy code to web apps",
		"Execute code with app's managed identity",
		"Access app configuration and secrets",
	},
	"Storage Account Key Operator Service Role": {
		"List storage account keys",
		"Access all storage account data",
		"Potential credential and data theft",
	},
	"Azure Kubernetes Service Contributor Role": {
		"Modify AKS cluster configurations",
		"Access cluster credentials",
		"Execute code in cluster",
		"Impersonate cluster managed identity",
	},
	"Logic App Contributor": {
		"Create/modify Logic Apps",
		"Execute code with app's managed identity",
		"Access app configurations",
	},
}

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListPrivilegeEscalation(cmd *cobra.Command, args []string) {
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_PRIVILEGE_ESCALATION_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	module := &PrivilegeEscalationModule{
		BaseAzureModule:  azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:    cmdCtx.Subscriptions,
		EscalationRows:   [][]string{},
		DangerousRoleMap: dangerousRoles,
		LootMap: map[string]*internal.LootFile{
			"privilege-escalation-paths":    {Name: "privilege-escalation-paths", Contents: "# Privilege Escalation Paths\n\n"},
			"high-risk-assignments":         {Name: "high-risk-assignments", Contents: "# High-Risk Role Assignments\n\n"},
			"escalation-techniques":         {Name: "escalation-techniques", Contents: "# Privilege Escalation Techniques\n\n"},
			"remediation-recommendations":   {Name: "remediation-recommendations", Contents: "# Remediation Recommendations\n\n"},
			"privilege-escalation-commands": {Name: "privilege-escalation-commands", Contents: "# Privilege Escalation Commands\n\n"},
		},
	}

	module.PrintPrivilegeEscalation(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *PrivilegeEscalationModule) PrintPrivilegeEscalation(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_PRIVILEGE_ESCALATION_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_PRIVILEGE_ESCALATION_MODULE_NAME, m.processSubscription)
	}
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *PrivilegeEscalationModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get all role assignments for the subscription
	roleAssignments, err := azinternal.GetRoleAssignmentsForSubscription(ctx, m.Session, subID)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to get role assignments: %v", err), globals.AZ_PRIVILEGE_ESCALATION_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Analyze each role assignment for privilege escalation paths
	for _, assignment := range roleAssignments {
		m.analyzeRoleAssignment(ctx, subID, subName, assignment, logger)
	}
}

// ------------------------------
// Analyze role assignment
// ------------------------------
func (m *PrivilegeEscalationModule) analyzeRoleAssignment(ctx context.Context, subID, subName string, assignment azinternal.RoleAssignment, logger internal.Logger) {
	roleName := assignment.RoleName
	principalName := assignment.PrincipalName
	principalID := assignment.PrincipalID
	principalType := assignment.PrincipalType
	scope := assignment.Scope

	// Determine if this is a dangerous role
	techniques, isDangerous := m.DangerousRoleMap[roleName]
	if !isDangerous {
		// Check for partial matches (e.g., "Contributor" in "Storage Account Contributor")
		for dangerousRole := range m.DangerousRoleMap {
			if strings.Contains(roleName, dangerousRole) {
				techniques = m.DangerousRoleMap[dangerousRole]
				isDangerous = true
				break
			}
		}
	}

	if !isDangerous {
		return
	}

	// Determine scope type and resource type
	scopeType, resourceType := m.analyzeScopeAndResourceType(scope)

	// Determine risk level
	risk := m.calculateRiskLevel(roleName, scopeType, resourceType)

	// Build escalation vector description
	escalationVector := m.buildEscalationVector(roleName, scopeType, resourceType, techniques)

	// Add row
	row := []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		principalName,
		principalID,
		principalType,
		roleName,
		scope,
		scopeType,
		resourceType,
		escalationVector,
		risk,
		strings.Join(techniques, "; "),
	}

	m.mu.Lock()
	m.EscalationRows = append(m.EscalationRows, row)
	m.mu.Unlock()
	m.CommandCounter.Total++

	// Add to loot files
	if risk == "HIGH" || risk == "CRITICAL" {
		m.addEscalationLoot(subID, subName, principalName, principalID, principalType, roleName, scope, scopeType, resourceType, escalationVector, risk, techniques)
	}
}

// ------------------------------
// Analyze scope and resource type
// ------------------------------
func (m *PrivilegeEscalationModule) analyzeScopeAndResourceType(scope string) (string, string) {
	scopeType := "Subscription"
	resourceType := "N/A"

	parts := strings.Split(scope, "/")
	if len(parts) >= 5 && parts[3] == "resourceGroups" {
		scopeType = "ResourceGroup"
	}
	if len(parts) >= 7 && parts[5] == "providers" {
		scopeType = "Resource"
		if len(parts) >= 8 {
			resourceTypeFull := parts[6] + "/" + parts[7]
			// Simplify resource type
			switch {
			case strings.Contains(resourceTypeFull, "Automation"):
				resourceType = "Automation Account"
			case strings.Contains(resourceTypeFull, "KeyVault"):
				resourceType = "Key Vault"
			case strings.Contains(resourceTypeFull, "VirtualMachines"):
				resourceType = "Virtual Machine"
			case strings.Contains(resourceTypeFull, "Web/sites"):
				resourceType = "Web App"
			case strings.Contains(resourceTypeFull, "Storage/storageAccounts"):
				resourceType = "Storage Account"
			case strings.Contains(resourceTypeFull, "ContainerService"):
				resourceType = "AKS Cluster"
			case strings.Contains(resourceTypeFull, "Logic/workflows"):
				resourceType = "Logic App"
			default:
				resourceType = resourceTypeFull
			}
		}
	}

	return scopeType, resourceType
}

// ------------------------------
// Calculate risk level
// ------------------------------
func (m *PrivilegeEscalationModule) calculateRiskLevel(roleName, scopeType, resourceType string) string {
	// CRITICAL: High-privilege roles at subscription level
	if scopeType == "Subscription" {
		if roleName == "Owner" || roleName == "User Access Administrator" {
			return "CRITICAL"
		}
		if roleName == "Contributor" {
			return "HIGH"
		}
	}

	// HIGH: Dangerous roles on sensitive resource types
	if scopeType == "Resource" {
		switch resourceType {
		case "Automation Account", "Key Vault", "Virtual Machine":
			return "HIGH"
		case "Web App", "AKS Cluster", "Logic App":
			return "HIGH"
		}
	}

	// MEDIUM: Dangerous roles at resource group level
	if scopeType == "ResourceGroup" {
		return "MEDIUM"
	}

	return "MEDIUM"
}

// ------------------------------
// Build escalation vector
// ------------------------------
func (m *PrivilegeEscalationModule) buildEscalationVector(roleName, scopeType, resourceType string, techniques []string) string {
	vector := fmt.Sprintf("%s on %s", roleName, scopeType)
	if resourceType != "N/A" {
		vector = fmt.Sprintf("%s on %s (%s)", roleName, scopeType, resourceType)
	}

	// Add primary technique
	if len(techniques) > 0 {
		vector += " → " + techniques[0]
	}

	return vector
}

// ------------------------------
// Add escalation loot
// ------------------------------
func (m *PrivilegeEscalationModule) addEscalationLoot(subID, subName, principalName, principalID, principalType, roleName, scope, scopeType, resourceType, escalationVector, risk string, techniques []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["privilege-escalation-paths"].Contents += fmt.Sprintf(
		"## %s: %s on %s\n"+
			"Principal: %s (%s) - %s\n"+
			"Subscription: %s (%s)\n"+
			"Role: %s\n"+
			"Scope: %s\n"+
			"Escalation Vector: %s\n"+
			"Risk Level: %s\n\n"+
			"Techniques:\n",
		risk, principalName, scopeType,
		principalName, principalID, principalType,
		subName, subID,
		roleName,
		scope,
		escalationVector,
		risk,
	)

	for _, technique := range techniques {
		m.LootMap["privilege-escalation-paths"].Contents += fmt.Sprintf("  - %s\n", technique)
	}
	m.LootMap["privilege-escalation-paths"].Contents += "\n"

	m.LootMap["high-risk-assignments"].Contents += fmt.Sprintf(
		"## HIGH RISK: %s\n"+
			"Principal: %s (%s)\n"+
			"Principal Type: %s\n"+
			"Role: %s\n"+
			"Scope: %s\n"+
			"Resource Type: %s\n"+
			"Risk: %s\n\n",
		principalName,
		principalName, principalID,
		principalType,
		roleName,
		scope,
		resourceType,
		risk,
	)

	// Add specific technique documentation
	m.LootMap["escalation-techniques"].Contents += fmt.Sprintf(
		"## %s via %s\n\n"+
			"### Attack Scenario\n"+
			"Principal: %s (%s)\n"+
			"Role: %s on %s\n\n"+
			"### Exploitation Steps:\n",
		roleName, resourceType,
		principalName, principalID,
		roleName, scopeType,
	)

	// Add role-specific exploitation steps
	switch roleName {
	case "Owner", "Contributor":
		if resourceType == "Automation Account" {
			m.LootMap["escalation-techniques"].Contents += `
1. List Automation Accounts in scope
2. Create new runbook or modify existing
3. Add PowerShell/Python code to access secrets or elevate privileges
4. Execute runbook with Automation Account's managed identity
5. Access resources with elevated privileges

Commands:
# List Automation Accounts
az automation account list --subscription ` + subID + `

# Create runbook
az automation runbook create --automation-account-name <ACCOUNT> --resource-group <RG> --name escalate --type PowerShell

# Publish and execute
az automation runbook publish --automation-account-name <ACCOUNT> --resource-group <RG> --name escalate
az automation runbook start --automation-account-name <ACCOUNT> --resource-group <RG> --name escalate

`
		} else if resourceType == "Virtual Machine" {
			m.LootMap["escalation-techniques"].Contents += `
1. List VMs in scope
2. Use VM run command to execute code
3. Access VM's managed identity token
4. Use token to access Azure resources
5. Escalate to Owner/Contributor via managed identity permissions

Commands:
# List VMs
az vm list --subscription ` + subID + `

# Execute command on VM
az vm run-command invoke --command-id RunPowerShellScript --name <VM_NAME> --resource-group <RG> \
  --scripts "Invoke-RestMethod -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -Headers @{'Metadata'='true'}"

`
		}
	case "User Access Administrator":
		m.LootMap["escalation-techniques"].Contents += fmt.Sprintf(`
1. Grant yourself Owner role at subscription level
2. Access all resources with Owner permissions
3. Exfiltrate data, create backdoors, etc.

Commands:
# Grant Owner role to yourself
az role assignment create --role "Owner" --assignee "%s" --scope "/subscriptions/%s"

# Verify assignment
az role assignment list --assignee "%s" --scope "/subscriptions/%s"

`, principalID, subID, principalID, subID)

	case "Key Vault Contributor":
		m.LootMap["escalation-techniques"].Contents += `
1. Modify Key Vault access policies
2. Grant yourself GET permissions on secrets
3. List and download all secrets
4. Use secrets to access other resources

Commands:
# Set Key Vault access policy
az keyvault set-policy --name <VAULT_NAME> --object-id ` + principalID + ` --secret-permissions get list

# List secrets
az keyvault secret list --vault-name <VAULT_NAME>

# Get secret value
az keyvault secret show --vault-name <VAULT_NAME> --name <SECRET_NAME>

`
	}

	m.LootMap["escalation-techniques"].Contents += "\n"

	// Add remediation recommendation
	m.LootMap["remediation-recommendations"].Contents += fmt.Sprintf(
		"## Remediation: %s on %s\n\n"+
			"### Current Assignment:\n"+
			"Principal: %s (%s) - %s\n"+
			"Role: %s\n"+
			"Scope: %s\n"+
			"Risk: %s\n\n"+
			"### Recommended Actions:\n"+
			"1. Review if principal requires this level of access\n"+
			"2. Apply principle of least privilege\n"+
			"3. Consider using more restrictive built-in roles\n"+
			"4. If necessary, create custom role with minimal required permissions\n"+
			"5. Implement JIT (Just-In-Time) access using PIM\n"+
			"6. Enable monitoring and alerting for this principal's activities\n\n"+
			"### Remove Assignment:\n"+
			"```bash\n"+
			"az role assignment delete --assignee %s --role \"%s\" --scope \"%s\"\n"+
			"```\n\n",
		roleName, scopeType,
		principalName, principalID, principalType,
		roleName,
		scope,
		risk,
		principalID, roleName, scope,
	)

	// Add investigation commands
	m.LootMap["privilege-escalation-commands"].Contents += fmt.Sprintf(
		"## Investigation: %s (%s)\n\n"+
			"# List all role assignments for principal\n"+
			"az role assignment list --assignee %s --all --output table\n\n"+
			"# Get principal details\n"+
			"az ad sp show --id %s 2>/dev/null || az ad user show --id %s 2>/dev/null\n\n"+
			"# List resources in scope\n"+
			"az resource list --subscription %s --output table\n\n"+
			"# Check activity logs for principal\n"+
			"az monitor activity-log list --subscription %s \\\n"+
			"  --caller %s \\\n"+
			"  --start-time $(date -u -d '7 days ago' +%%Y-%%m-%%dT%%H:%%M:%%SZ) \\\n"+
			"  --output table\n\n",
		principalName, principalID,
		principalID,
		principalID, principalID,
		subID,
		subID,
		principalName,
	)
}

// ------------------------------
// Write output
// ------------------------------
func (m *PrivilegeEscalationModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.EscalationRows) == 0 {
		logger.InfoM("No privilege escalation paths detected", globals.AZ_PRIVILEGE_ESCALATION_MODULE_NAME)
		return
	}

	// Build headers
	headers := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Principal Name",
		"Principal ID",
		"Principal Type",
		"Role Name",
		"Scope",
		"Scope Type",
		"Resource Type",
		"Escalation Vector",
		"Risk",
		"Techniques",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.EscalationRows, headers,
			"privilege-escalation", globals.AZ_PRIVILEGE_ESCALATION_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.EscalationRows, headers,
			"privilege-escalation", globals.AZ_PRIVILEGE_ESCALATION_MODULE_NAME,
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
	output := PrivilegeEscalationOutput{
		Table: []internal.TableFile{{
			Name:   "privilege-escalation",
			Header: headers,
			Body:   m.EscalationRows,
		}},
		Loot: loot,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_PRIVILEGE_ESCALATION_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	// Count risk levels
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	for _, row := range m.EscalationRows {
		risk := row[12] // Risk column
		switch risk {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d privilege escalation paths (%d CRITICAL, %d HIGH, %d MEDIUM) across %d subscription(s)",
		len(m.EscalationRows), criticalCount, highCount, mediumCount, len(m.Subscriptions)), globals.AZ_PRIVILEGE_ESCALATION_MODULE_NAME)
}
