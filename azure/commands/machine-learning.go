package commands

import (
	"context"
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/machinelearning/armmachinelearning"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzMachineLearningCommand = &cobra.Command{
	Use:     "machine-learning",
	Aliases: []string{"ml", "machinelearning"},
	Short:   "Enumerate Azure Machine Learning workspaces and extract datastore credentials",
	Long: `
Enumerate ML workspaces for a specific tenant:
  ./cloudfox az machine-learning --tenant TENANT_ID

Enumerate ML workspaces for a specific subscription:
  ./cloudfox az machine-learning --subscription SUBSCRIPTION_ID`,
	Run: ListMachineLearning,
}

// ------------------------------
// Module struct (AWS pattern)
// ------------------------------
type MachineLearningModule struct {
	azinternal.BaseAzureModule // Embed common fields

	// Module-specific fields
	Subscriptions   []string
	MLRows          [][]string
	WorkspaceRows   [][]string // Workspace-level security config
	LootMap         map[string]*internal.LootFile
	mu              sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type MachineLearningOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o MachineLearningOutput) TableFiles() []internal.TableFile { return o.Table }
func (o MachineLearningOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListMachineLearning(cmd *cobra.Command, args []string) {
	// -------------------- Use InitializeCommandContext helper --------------------
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_MACHINE_LEARNING_MODULE_NAME)
	if err != nil {
		return // error already logged by helper
	}
	defer cmdCtx.Session.StopMonitoring()

	// -------------------- Initialize module --------------------
	module := &MachineLearningModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		MLRows:          [][]string{},
		WorkspaceRows:   [][]string{},
		LootMap: map[string]*internal.LootFile{
			"ml-credentials": {Name: "ml-credentials", Contents: ""},
			"ml-computes":    {Name: "ml-computes", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintMachineLearning(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *MachineLearningModule) PrintMachineLearning(ctx context.Context, logger internal.Logger) {
	if m.IsMultiTenant {
		for _, tenantCtx := range m.Tenants {
			savedTenantID := m.TenantID
			savedTenantName := m.TenantName
			savedTenantInfo := m.TenantInfo

			m.TenantID = tenantCtx.TenantID
			m.TenantName = tenantCtx.TenantName
			m.TenantInfo = tenantCtx.TenantInfo

			m.RunSubscriptionEnumeration(ctx, logger, tenantCtx.Subscriptions, globals.AZ_MACHINE_LEARNING_MODULE_NAME, m.processSubscription)

			m.TenantID = savedTenantID
			m.TenantName = savedTenantName
			m.TenantInfo = savedTenantInfo
		}
	} else {
		m.RunSubscriptionEnumeration(ctx, logger, m.Subscriptions, globals.AZ_MACHINE_LEARNING_MODULE_NAME, m.processSubscription)
	}

	// Generate and write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Process single subscription
// ------------------------------
func (m *MachineLearningModule) processSubscription(ctx context.Context, subID string, logger internal.Logger) {
	// Get subscription name
	subName := azinternal.GetSubscriptionNameFromID(ctx, m.Session, subID)

	// Get resource groups (CACHED)
	resourceGroups := m.ResolveResourceGroups(subID)

	// Get all ML workspaces
	workspaces, err := azinternal.GetMLWorkspaces(m.Session, subID, resourceGroups)
	if err != nil {
		if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to get ML workspaces for subscription %s: %v", subID, err), globals.AZ_MACHINE_LEARNING_MODULE_NAME)
		}
		m.CommandCounter.Error++
		return
	}

	// Process each workspace
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit to 5 concurrent workspaces

	for _, workspace := range workspaces {
		wg.Add(1)
		go m.processWorkspace(ctx, subID, subName, workspace, &wg, semaphore, logger)
	}

	wg.Wait()
}

// ------------------------------
// Process single workspace
// ------------------------------
func (m *MachineLearningModule) processWorkspace(ctx context.Context, subID, subName string, workspace interface{}, wg *sync.WaitGroup, semaphore chan struct{}, logger internal.Logger) {
	defer wg.Done()

	// Acquire semaphore
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	// Type assert to actual SDK type
	ws, ok := workspace.(*armmachinelearning.Workspace)
	if !ok {
		return
	}

	// Extract workspace details using helper functions
	workspaceName := azinternal.SafeStringPtr(ws.Name)
	rgName := azinternal.GetResourceGroupFromID(azinternal.SafeStringPtr(ws.ID))
	region := azinternal.SafeStringPtr(ws.Location)
	workspaceID := azinternal.SafeStringPtr(ws.ID)

	if workspaceName == "" {
		return
	}

	// Extract workspace-level security properties
	publicNetworkAccess := "Enabled"
	hbiWorkspace := "No"
	allowPublicAccessBehindVnet := "Yes"
	imageBuildCompute := "N/A"
	encryptionKeyVaultID := "N/A"
	encryptionKeyID := "N/A"
	sku := "N/A"

	if ws.Properties != nil {
		// Public Network Access
		if ws.Properties.PublicNetworkAccess != nil {
			publicNetworkAccess = string(*ws.Properties.PublicNetworkAccess)
		}

		// High Business Impact workspace
		if ws.Properties.HbiWorkspace != nil && *ws.Properties.HbiWorkspace {
			hbiWorkspace = "Yes"
		}

		// Allow public access when behind VNet
		if ws.Properties.AllowPublicAccessWhenBehindVnet != nil && !*ws.Properties.AllowPublicAccessWhenBehindVnet {
			allowPublicAccessBehindVnet = "No"
		}

		// Image build compute target
		if ws.Properties.ImageBuildCompute != nil && *ws.Properties.ImageBuildCompute != "" {
			imageBuildCompute = *ws.Properties.ImageBuildCompute
		}

		// Encryption settings (CMK)
		if ws.Properties.Encryption != nil {
			if ws.Properties.Encryption.KeyVaultProperties != nil {
				if ws.Properties.Encryption.KeyVaultProperties.KeyVaultArmID != nil {
					encryptionKeyVaultID = *ws.Properties.Encryption.KeyVaultProperties.KeyVaultArmID
				}
				if ws.Properties.Encryption.KeyVaultProperties.KeyIdentifier != nil {
					encryptionKeyID = *ws.Properties.Encryption.KeyVaultProperties.KeyIdentifier
				}
			}
		}
	}

	// Get SKU
	if ws.SKU != nil && ws.SKU.Name != nil {
		sku = *ws.SKU.Name
	}

	// Extract managed identity information for the workspace
	var systemAssignedIDs []string
	var userAssignedIDs []string

	if ws.Identity != nil {
		// System-assigned identity
		if ws.Identity.PrincipalID != nil {
			principalID := *ws.Identity.PrincipalID
			systemAssignedIDs = append(systemAssignedIDs, principalID)
		}

		// User-assigned identities
		if ws.Identity.UserAssignedIdentities != nil {
			for uaID := range ws.Identity.UserAssignedIdentities {
				userAssignedIDs = append(userAssignedIDs, uaID)
			}
		}
	}

	// Format identity fields
	systemIDsStr := "N/A"
	if len(systemAssignedIDs) > 0 {
		systemIDsStr = ""
		for i, id := range systemAssignedIDs {
			if i > 0 {
				systemIDsStr += ", "
			}
			systemIDsStr += id
		}
	}

	userIDsStr := "N/A"
	if len(userAssignedIDs) > 0 {
		userIDsStr = ""
		for i, id := range userAssignedIDs {
			if i > 0 {
				userIDsStr += ", "
			}
			userIDsStr += id
		}
	}

	// Add workspace security row
	m.mu.Lock()
	m.WorkspaceRows = append(m.WorkspaceRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		rgName,
		region,
		workspaceName,
		sku,
		publicNetworkAccess,
		hbiWorkspace,
		allowPublicAccessBehindVnet,
		imageBuildCompute,
		encryptionKeyVaultID,
		encryptionKeyID,
		systemIDsStr,
		userIDsStr,
	})
	m.mu.Unlock()

	// Extract datastore credentials
	datastoreCreds := azinternal.GetMLDatastoreCredentials(m.Session, subID, rgName, workspaceName, region)
	for _, cred := range datastoreCreds {
		m.addDatastoreRow(subID, subName, cred, systemIDsStr, userIDsStr)
	}

	// Extract compute instances
	computes := azinternal.GetMLComputeInstances(m.Session, subID, rgName, workspaceName)
	for _, compute := range computes {
		m.addComputeRow(subID, subName, compute)
	}

	// Extract connections
	connections := azinternal.GetMLConnections(m.Session, subID, rgName, workspaceName)
	for _, conn := range connections {
		m.addConnectionRow(subID, subName, conn, systemIDsStr, userIDsStr)
	}

	_ = ctx
	_ = logger
	_ = workspaceID
}

// ------------------------------
// Add datastore credential row
// ------------------------------
func (m *MachineLearningModule) addDatastoreRow(subID, subName string, cred azinternal.MLDatastoreCredential, systemIDsStr, userIDsStr string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Determine credential display
	credValue := "N/A"
	if cred.Password != "" {
		credValue = cred.Password
	} else if cred.ClientSecret != "" {
		credValue = cred.ClientSecret
	} else if cred.SASToken != "" {
		credValue = cred.SASToken
	}

	m.MLRows = append(m.MLRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		cred.ResourceGroup,
		cred.Region,
		cred.WorkspaceName,
		cred.ServiceType,
		cred.CredentialType,
		cred.StorageAccount + cred.Server, // Resource name
		cred.Username + cred.ClientID,     // Identity
		credValue,
		systemIDsStr,
		userIDsStr,
	})

	// Add to loot file
	if cred.ServiceType == "AzureSQLDatabase" || cred.ServiceType == "MySQLDatabase" || cred.ServiceType == "PostgreSQLDatabase" {
		m.LootMap["ml-credentials"].Contents += fmt.Sprintf(
			"## ML Workspace: %s, Database: %s\n"+
				"# Service: %s, Server: %s, Database: %s\n"+
				"# Credential Type: %s\n"+
				"# Username: %s\n"+
				"# Password: %s\n"+
				"# ClientID: %s, ClientSecret: %s, TenantID: %s\n\n",
			cred.WorkspaceName, cred.Database,
			cred.ServiceType, cred.Server, cred.Database,
			cred.CredentialType,
			cred.Username,
			cred.Password,
			cred.ClientID, cred.ClientSecret, cred.TenantID,
		)
	} else if cred.ServiceType == "StorageAccount" || cred.ServiceType == "DataLakeGen1" || cred.ServiceType == "DataLakeGen2" {
		m.LootMap["ml-credentials"].Contents += fmt.Sprintf(
			"## ML Workspace: %s, Storage: %s\n"+
				"# Service: %s, Account: %s, Container: %s\n"+
				"# SAS Token: %s\n"+
				"# ClientID: %s, ClientSecret: %s, TenantID: %s\n\n",
			cred.WorkspaceName, cred.StorageAccount,
			cred.ServiceType, cred.StorageAccount, cred.Container,
			cred.SASToken,
			cred.ClientID, cred.ClientSecret, cred.TenantID,
		)
	}
}

// ------------------------------
// Add compute instance row
// ------------------------------
func (m *MachineLearningModule) addComputeRow(subID, subName string, compute azinternal.MLComputeInstance) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["ml-computes"].Contents += fmt.Sprintf(
		"## ML Compute: %s\n"+
			"# Workspace: %s, Resource Group: %s\n"+
			"# Type: %s, VM Size: %s, State: %s\n"+
			"# SSH Public Access: %s, Admin User: %s, SSH Port: %s\n"+
			"# Public IP: %s, Private IP: %s\n\n",
		compute.ComputeName,
		compute.WorkspaceName, compute.ResourceGroup,
		compute.ComputeType, compute.VMSize, compute.State,
		compute.SSHPublicAccess, compute.SSHAdminUser, compute.SSHPort,
		compute.PublicIPAddress, compute.PrivateIPAddress,
	)
}

// ------------------------------
// Add connection row
// ------------------------------
func (m *MachineLearningModule) addConnectionRow(subID, subName string, conn azinternal.MLConnection, systemIDsStr, userIDsStr string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.MLRows = append(m.MLRows, []string{
		m.TenantName,
		m.TenantID,
		subID,
		subName,
		conn.ResourceGroup,
		conn.WorkspaceName,
		"Connection",
		conn.ConnectionType,
		conn.ConnectionName,
		"Connection Key",
		conn.Secret,
		systemIDsStr,
		userIDsStr,
	})

	m.LootMap["ml-credentials"].Contents += fmt.Sprintf(
		"## ML Connection: %s\n"+
			"# Workspace: %s, Type: %s\n"+
			"# Secret: %s\n\n",
		conn.ConnectionName,
		conn.WorkspaceName, conn.ConnectionType,
		conn.Secret,
	)
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *MachineLearningModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if len(m.MLRows) == 0 && len(m.WorkspaceRows) == 0 {
		logger.InfoM("No Machine Learning resources found", globals.AZ_MACHINE_LEARNING_MODULE_NAME)
		return
	}

	// Credentials table headers
	credentialsHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Workspace Name",
		"Service Type",
		"Credential Type",
		"Resource Name",
		"Identity",
		"Credential/Secret",
		"System Assigned Identity ID",
		"User Assigned Identity ID",
	}

	// Workspace security config table headers
	workspaceHeaders := []string{
		"Tenant Name",
		"Tenant ID",
		"Subscription ID",
		"Subscription Name",
		"Resource Group",
		"Region",
		"Workspace Name",
		"SKU",
		"Public Network Access",
		"High Business Impact",
		"Public Access Behind VNet",
		"Image Build Compute",
		"Encryption Key Vault",
		"Encryption Key ID",
		"System Assigned ID",
		"User Assigned ID",
	}

	// Check if we should split output by tenant
	if m.IsMultiTenant {
		// Write credentials table
		if len(m.MLRows) > 0 {
			if err := m.FilterAndWritePerTenantAuto(
				ctx, logger, m.Tenants, m.MLRows, credentialsHeaders,
				"machine-learning", globals.AZ_MACHINE_LEARNING_MODULE_NAME,
			); err != nil {
				return
			}
		}
		// Write workspace security table
		if len(m.WorkspaceRows) > 0 {
			if err := m.FilterAndWritePerTenantAuto(
				ctx, logger, m.Tenants, m.WorkspaceRows, workspaceHeaders,
				"machine-learning-workspaces", globals.AZ_MACHINE_LEARNING_MODULE_NAME,
			); err != nil {
				return
			}
		}
		return
	}

	// Check if we should split output by subscription
	if azinternal.ShouldSplitBySubscription(m.Subscriptions, m.TenantFlagPresent) {
		// Write credentials table
		if len(m.MLRows) > 0 {
			if err := m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.MLRows, credentialsHeaders,
				"machine-learning", globals.AZ_MACHINE_LEARNING_MODULE_NAME,
			); err != nil {
				return
			}
		}
		// Write workspace security table
		if len(m.WorkspaceRows) > 0 {
			if err := m.FilterAndWritePerSubscriptionAuto(
				ctx, logger, m.Subscriptions, m.WorkspaceRows, workspaceHeaders,
				"machine-learning-workspaces", globals.AZ_MACHINE_LEARNING_MODULE_NAME,
			); err != nil {
				return
			}
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

	// Build tables array
	tables := []internal.TableFile{}
	if len(m.MLRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "machine-learning",
			Header: credentialsHeaders,
			Body:   m.MLRows,
		})
	}
	if len(m.WorkspaceRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "machine-learning-workspaces",
			Header: workspaceHeaders,
			Body:   m.WorkspaceRows,
		})
	}

	// Create output
	output := MachineLearningOutput{
		Table: tables,
		Loot:  loot,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_MACHINE_LEARNING_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d ML workspaces and %d credentials across %d subscription(s)", len(m.WorkspaceRows), len(m.MLRows), len(m.Subscriptions)), globals.AZ_MACHINE_LEARNING_MODULE_NAME)
}
