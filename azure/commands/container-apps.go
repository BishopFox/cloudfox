package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/BishopFox/cloudfox/internal/azure/sdk"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzContainerJobsCommand = &cobra.Command{
	Use:     "container-apps",
	Aliases: []string{"containerapps", "ca"},
	Short:   "Enumerate Azure Container Apps and Instances",
	Long: `
Enumerate Azure Container Instances (ACI), Container Apps Jobs, and discover related templates and identities:
./cloudfox az container-apps --tenant TENANT_ID

Enumerate for specific subscriptions:
./cloudfox az container-apps --subscription SUBSCRIPTION_ID[,SUBSCRIPTION_ID2,...]`,
	Run: ListContainerJobs,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type ContainerJobsModule struct {
	azinternal.BaseAzureModule // Embed common fields (15 fields)

	// Module-specific fields
	Subscriptions    []string
	ContainerJobRows [][]string
	LootMap          map[string]*internal.LootFile
	mu               sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type ContainerJobsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

// ManagedIdentity holds the principal ID of a user-assigned managed identity
type ManagedIdentity struct {
	Name        string
	Type        string
	Roles       []string
	ClientID    string
	PrincipalID string
}

func (o ContainerJobsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ContainerJobsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListContainerJobs(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_CONTAINER_JOBS_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &ContainerJobsModule{
		BaseAzureModule:  azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:    cmdCtx.Subscriptions,
		ContainerJobRows: [][]string{},
		LootMap: map[string]*internal.LootFile{
			"container-jobs-commands":  {Name: "container-jobs-commands", Contents: ""},
			"container-jobs-templates": {Name: "container-jobs-templates", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintContainerJobs(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *ContainerJobsModule) PrintContainerJobs(ctx context.Context, logger internal.Logger) {
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
			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_CONTAINER_JOBS_MODULE_NAME, m.processSubscription)

			// Restore tenant context
			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		// Single-tenant mode
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_CONTAINER_JOBS_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *ContainerJobsModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
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
func (m *ContainerJobsModule) processResourceGroup(ctx context.Context, subID, subName, rgName string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Get region
	region := ""
	if rg := azinternal.GetResourceGroupIDFromName(m.Session, subID, rgName); rg != nil {
		rgs := sdk.CachedGetResourceGroupsPerSubscription(m.Session, subID)
		for _, r := range rgs {
			if r.Name != nil && *r.Name == rgName && r.Location != nil {
				region = *r.Location
				break
			}
		}
	}

	// -------------------- 1) Container Instances (ACI) --------------------
	aciList := azinternal.ListContainerInstances(m.Session, subID, rgName)
	for _, aci := range aciList {
		clusterName := ""
		clusterType := "ACI"
		publicIP := azinternal.SafeStringPtr(aci.PublicIPAddress)
		privateIP := azinternal.SafeStringPtr(aci.PrivateIPAddress)
		fqdn := azinternal.SafeStringPtr(aci.FQDN)
		ports := azinternal.SafeStringPtr(aci.Ports)

		var userAssignedIDs []string
		var systemAssignedIDs []string

		// Iterate user-assigned managed identities
		for _, ua := range aci.UserAssignedIdentities {
			if ua.PrincipalID != "" {
				userAssignedIDs = append(userAssignedIDs, ua.PrincipalID)
			}
		}

		// System-assigned identity
		for _, sa := range aci.SystemAssignedIdentities {
			if sa.PrincipalID != "" {
				systemAssignedIDs = append(systemAssignedIDs, sa.PrincipalID)
			}
		}

		// Format identity fields (use "N/A" if empty)
		systemIDsStr := "N/A"
		if len(systemAssignedIDs) > 0 {
			systemIDsStr = strings.Join(systemAssignedIDs, ", ")
		}
		userIDsStr := "N/A"
		if len(userAssignedIDs) > 0 {
			userIDsStr = strings.Join(userAssignedIDs, ", ")
		}

		// Thread-safe append
		m.mu.Lock()
		m.ContainerJobRows = append(m.ContainerJobRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			rgName,
			region,
			azinternal.SafeStringPtr(aci.Name),
			clusterName,
			clusterType,
			publicIP,
			privateIP,
			fqdn,
			ports,
			systemIDsStr,
			userIDsStr,
		})

		m.LootMap["container-jobs-commands"].Contents += fmt.Sprintf(
			"## Resource Group: %s - ACI: %s\n"+
				"# Set subscription context\n"+
				"az account set --subscription %s\n"+
				"\n"+
				"# Show container instance details\n"+
				"az container show --resource-group %s --name %s --output table\n"+
				"\n"+
				"# Get container logs\n"+
				"az container logs --resource-group %s --name %s\n"+
				"\n"+
				"# Get container logs for specific container (if multi-container group)\n"+
				"az container logs --resource-group %s --name %s --container-name <CONTAINER-NAME>\n"+
				"\n"+
				"# Execute commands in running container\n"+
				"az container exec --resource-group %s --name %s --exec-command \"/bin/bash\"\n"+
				"\n"+
				"# List environment variables\n"+
				"az container show --resource-group %s --name %s --query 'containers[].environmentVariables' -o json\n"+
				"\n"+
				"# Export container group definition\n"+
				"az container export --resource-group %s --name %s --file %s-export.yaml\n"+
				"\n"+
				"## Network Access\n",
			rgName, azinternal.SafeStringPtr(aci.Name),
			subID,
			rgName, azinternal.SafeStringPtr(aci.Name),
			rgName, azinternal.SafeStringPtr(aci.Name),
			rgName, azinternal.SafeStringPtr(aci.Name),
			rgName, azinternal.SafeStringPtr(aci.Name),
			rgName, azinternal.SafeStringPtr(aci.Name),
			rgName, azinternal.SafeStringPtr(aci.Name),
			azinternal.SafeStringPtr(aci.Name),
		)

		// Add network access information
		if fqdn != "" && fqdn != "N/A" {
			m.LootMap["container-jobs-commands"].Contents += fmt.Sprintf("# Access via FQDN: %s\n", fqdn)
			if ports != "" && ports != "N/A" {
				m.LootMap["container-jobs-commands"].Contents += fmt.Sprintf("# Exposed Ports: %s\n", ports)
				m.LootMap["container-jobs-commands"].Contents += fmt.Sprintf("# Test connectivity\n")
				m.LootMap["container-jobs-commands"].Contents += fmt.Sprintf("curl http://%s\n", fqdn)
				m.LootMap["container-jobs-commands"].Contents += fmt.Sprintf("nmap -p %s %s\n", strings.Split(ports, "/")[0], fqdn)
			}
		} else if publicIP != "" && publicIP != "N/A" {
			m.LootMap["container-jobs-commands"].Contents += fmt.Sprintf("# Access via Public IP: %s\n", publicIP)
			if ports != "" && ports != "N/A" {
				m.LootMap["container-jobs-commands"].Contents += fmt.Sprintf("# Exposed Ports: %s\n", ports)
				m.LootMap["container-jobs-commands"].Contents += fmt.Sprintf("# Test connectivity\n")
				m.LootMap["container-jobs-commands"].Contents += fmt.Sprintf("curl http://%s\n", publicIP)
				m.LootMap["container-jobs-commands"].Contents += fmt.Sprintf("nmap -p %s %s\n", strings.Split(ports, "/")[0], publicIP)
			}
		}

		m.LootMap["container-jobs-commands"].Contents += fmt.Sprintf(
			"\n## PowerShell Commands\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"\n"+
				"# Get container instance\n"+
				"Get-AzContainerGroup -ResourceGroupName %s -Name %s | ConvertTo-Json -Depth 10\n"+
				"\n"+
				"# Get container logs\n"+
				"Get-AzContainerInstanceLog -ResourceGroupName %s -ContainerGroupName %s\n"+
				"\n"+
				"# Restart container group\n"+
				"Restart-AzContainerGroup -ResourceGroupName %s -Name %s\n\n",
			subID,
			rgName, azinternal.SafeStringPtr(aci.Name),
			rgName, azinternal.SafeStringPtr(aci.Name),
			rgName, azinternal.SafeStringPtr(aci.Name),
		)

		if tpl := azinternal.GetTemplatesForResource(azinternal.SafeStringPtr(aci.ID)); tpl != "" {
			m.LootMap["container-jobs-templates"].Contents += fmt.Sprintf("## ACI: %s (%s)\n%s\n\n", azinternal.SafeStringPtr(aci.Name), azinternal.SafeStringPtr(aci.ID), tpl)
		}
		m.mu.Unlock()
	}

	// -------------------- 2) Container Apps Jobs --------------------
	caJobs := azinternal.ListContainerAppsJobs(m.Session, subID, rgName)
	for _, job := range caJobs {
		clusterName := azinternal.SafeStringPtr(job.Environment)
		clusterType := "Container Apps"
		publicIP := azinternal.SafeStringPtr(job.PublicIP)
		privateIP := azinternal.SafeStringPtr(job.PrivateIP)

		var userAssignedIDs []string
		var systemAssignedIDs []string

		// Iterate user-assigned managed identities
		for _, ua := range job.UserAssignedIdentities {
			if ua.PrincipalID != "" {
				userAssignedIDs = append(userAssignedIDs, ua.PrincipalID)
			}
		}

		// System-assigned identity
		for _, sa := range job.SystemAssignedIdentities {
			if sa.PrincipalID != "" {
				systemAssignedIDs = append(systemAssignedIDs, sa.PrincipalID)
			}
		}

		// Format identity fields (use "N/A" if empty)
		systemIDsStr := "N/A"
		if len(systemAssignedIDs) > 0 {
			systemIDsStr = strings.Join(systemAssignedIDs, ", ")
		}
		userIDsStr := "N/A"
		if len(userAssignedIDs) > 0 {
			userIDsStr = strings.Join(userAssignedIDs, ", ")
		}

		// Thread-safe append
		m.mu.Lock()
		m.ContainerJobRows = append(m.ContainerJobRows, []string{
			m.TenantName,
			m.TenantID,
			subID,
			subName,
			rgName,
			region,
			azinternal.SafeStringPtr(job.Name),
			clusterName,
			clusterType,
			publicIP,
			privateIP,
			"N/A", // FQDN (not applicable for Container Apps Jobs)
			"N/A", // Ports (not applicable for Container Apps Jobs)
			systemIDsStr,
			userIDsStr,
		})

		m.LootMap["container-jobs-commands"].Contents += fmt.Sprintf(
			"## Resource Group: %s - Container App Job: %s\n"+
				"az account set --subscription %s\n"+
				"az containerapp job show --name %s --resource-group %s\n"+
				"az containerapp job logs --name %s --resource-group %s\n"+
				"# PowerShell (generic resource call)\n"+
				"Set-AzContext -SubscriptionId %s\n"+
				"Get-AzResource -ResourceId %s | ConvertTo-Json -Depth 10\n\n",
			rgName, azinternal.SafeStringPtr(job.Name),
			subID,
			azinternal.SafeStringPtr(job.Name), rgName,
			azinternal.SafeStringPtr(job.Name), rgName,
			subID,
			azinternal.SafeStringPtr(job.ID),
		)

		if tpl := azinternal.GetTemplatesForResource(azinternal.SafeStringPtr(job.ID)); tpl != "" {
			m.LootMap["container-jobs-templates"].Contents += fmt.Sprintf("## Container App Job: %s (%s)\n%s\n\n", azinternal.SafeStringPtr(job.Name), azinternal.SafeStringPtr(job.ID), tpl)
		}
		m.mu.Unlock()
	}
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *ContainerJobsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.ContainerJobRows) == 0 {
		logger.InfoM("No Container Apps found", globals.AZ_CONTAINER_JOBS_MODULE_NAME)
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
		"Cluster Name",
		"Cluster Type",
		"External IP",
		"Internal IP",
		"FQDN",
		"Ports",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Check if we should split output by tenant (takes precedence over subscription split)
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if err := m.FilterAndWritePerTenantAuto(
			ctx, logger, m.Tenants, m.ContainerJobRows, headers,
			"container-jobs", globals.AZ_CONTAINER_JOBS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		if err := m.FilterAndWritePerSubscriptionAuto(
			ctx, logger, m.Subscriptions, m.ContainerJobRows, headers,
			"container-jobs", globals.AZ_CONTAINER_JOBS_MODULE_NAME,
		); err != nil {
			return
		}
		return
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if strings.TrimSpace(lf.Contents) != "" {
			loot = append(loot, *lf)
		}
	}

	// Create output
	output := ContainerJobsOutput{
		Table: []internal.TableFile{{
			Name:   "container-jobs",
			Header: headers,
			Body:   m.ContainerJobRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_CONTAINER_JOBS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d Container App(s) across %d subscription(s)", len(m.ContainerJobRows), len(m.Subscriptions)), globals.AZ_CONTAINER_JOBS_MODULE_NAME)
}
