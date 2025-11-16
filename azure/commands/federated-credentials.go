package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzFederatedCredentialsCommand = &cobra.Command{
	Use:     "federated-credentials",
	Aliases: []string{"workload-identity", "oidc-credentials"},
	Short:   "Enumerate Azure AD Federated Identity Credentials and DevOps service connections",
	Long: `
Enumerate Azure AD Federated Identity Credentials (Workload Identity Federation) and
Azure DevOps service connections to identify authentication mechanisms used by pipelines.

This module shows the COMPLETE ATTACK PATH:
  Azure DevOps Agent → Service Connection → Federated Credential → Service Principal → Azure Resources

Key Security Risks:
- Service principals still using client secrets (should migrate to OIDC)
- Overpermissive federated credentials (broad subject scopes)
- Service connections accessible by all pipelines in a project
- Self-hosted agents with access to production service principals

Requires Azure authentication (az login) for Graph API access.
Optionally requires AZURE_DEVOPS_ORGANIZATION and AZDO_PAT for DevOps enumeration.

Generates table output and seven loot files:
- fedcreds-secrets: Service principals using client secrets (MIGRATE TO OIDC)
- fedcreds-devops: Federated credentials for Azure DevOps (issuer: vstoken)
- fedcreds-github: Federated credentials for GitHub Actions (issuer: token.actions)
- fedcreds-service-connections: Azure DevOps service connection mappings
- fedcreds-attack-paths: Complete attack path from agents to Azure resources
- fedcreds-overpermissive: Broad subject scopes (security risk)
- fedcreds-summary: Overall security analysis`,
	Run: ListFederatedCredentials,
}

// ListFederatedCredentials is the main entry point
func ListFederatedCredentials(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := azinternal.InitializeCommandContext(cmd, globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
	if err != nil {
		return
	}
	defer cmdCtx.Session.StopMonitoring()

	// Test Graph API access
	if globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		cmdCtx.Logger.InfoM("Testing Graph API access...", globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
		if err := azinternal.TestGraphAPIAccess(cmdCtx.Ctx, cmdCtx.Session, cmdCtx.TenantID); err != nil {
			cmdCtx.Logger.ErrorM(fmt.Sprintf("Graph API test failed: %v", err), globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
			cmdCtx.Logger.InfoM("Ensure you have granted Microsoft Graph permissions: Application.Read.All", globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
		}
	}

	// Initialize module
	module := &FederatedCredentialsModule{
		BaseAzureModule: azinternal.NewBaseAzureModule(cmdCtx, 5),
		Subscriptions:   cmdCtx.Subscriptions,
		TableData:       []map[string]interface{}{},
		LootMap:         make(map[string]*internal.LootFile),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute module
	module.execute(cmdCtx.Ctx)

	// Generate and write output
	module.writeOutput(cmdCtx.Logger)
}

// FederatedCredentialsModule handles enumeration
type FederatedCredentialsModule struct {
	azinternal.BaseAzureModule

	Subscriptions []string
	TableData     []map[string]interface{}
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type FederatedCredentialsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o FederatedCredentialsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o FederatedCredentialsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ServicePrincipalData holds service principal information
type ServicePrincipalData struct {
	DisplayName          string
	AppID                string
	ObjectID             string
	HasClientSecrets     bool
	HasCertificates      bool
	HasFederatedCreds    bool
	FederatedCredentials []FederatedCredential
	RBACRoles            []string
	Subscriptions        []string
}

// FederatedCredential holds federated credential details
type FederatedCredential struct {
	Name        string
	Issuer      string
	Subject     string
	Audiences   []string
	Description string
	CreatedDate string
}

// ServiceConnection holds Azure DevOps service connection details
type ServiceConnection struct {
	Name               string
	Type               string
	AuthScheme         string
	ProjectName        string
	ServicePrincipalID string
	SubscriptionID     string
	SubscriptionName   string
	CreatedBy          string
	IsReady            bool
	IsShared           bool
}

// initializeLootFiles creates the loot file structure
func (m *FederatedCredentialsModule) initializeLootFiles() {
	m.LootMap["fedcreds-secrets"] = &internal.LootFile{
		Name: "fedcreds-secrets.txt",
		Contents: "# Service Principals Using Client Secrets\n" +
			"# SECURITY RECOMMENDATION: Migrate to Federated Identity Credentials (OIDC)\n" +
			"# Client secrets are less secure than workload identity federation\n\n",
	}

	m.LootMap["fedcreds-devops"] = &internal.LootFile{
		Name: "fedcreds-devops.txt",
		Contents: "# Azure DevOps Federated Identity Credentials\n" +
			"# Issuer: https://vstoken.dev.azure.com/{orgId}\n\n",
	}

	m.LootMap["fedcreds-github"] = &internal.LootFile{
		Name: "fedcreds-github.txt",
		Contents: "# GitHub Actions Federated Identity Credentials\n" +
			"# Issuer: https://token.actions.githubusercontent.com\n\n",
	}

	m.LootMap["fedcreds-service-connections"] = &internal.LootFile{
		Name: "fedcreds-service-connections.txt",
		Contents: "# Azure DevOps Service Connections\n" +
			"# Maps service connections to service principals and subscriptions\n\n",
	}

	m.LootMap["fedcreds-attack-paths"] = &internal.LootFile{
		Name: "fedcreds-attack-paths.txt",
		Contents: "# Complete Attack Paths\n" +
			"# Shows: Agent → Service Connection → Federated Credential → Service Principal → Azure Resources\n\n",
	}

	m.LootMap["fedcreds-overpermissive"] = &internal.LootFile{
		Name: "fedcreds-overpermissive.txt",
		Contents: "# Overpermissive Federated Credentials\n" +
			"# Broad subject scopes that allow multiple pipelines/repos to authenticate\n\n",
	}

	m.LootMap["fedcreds-summary"] = &internal.LootFile{
		Name: "fedcreds-summary.txt",
		Contents: "# Federated Credentials Security Summary\n" +
			"# Generated: " + time.Now().Format(time.RFC3339) + "\n\n",
	}
}

// execute runs the enumeration
func (m *FederatedCredentialsModule) execute(ctx context.Context) {
	logger := internal.NewLogger()
	logger.InfoM("Enumerating service principals with federated credentials...", globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)

	// Step 1: Enumerate all service principals
	servicePrincipals := m.enumerateServicePrincipals(ctx, logger)
	logger.InfoM(fmt.Sprintf("Found %d service principals", len(servicePrincipals)), globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)

	// Step 2: For each service principal, get federated credentials
	for spID, sp := range servicePrincipals {
		m.enumerateFederatedCredentials(ctx, spID, &sp)
		m.checkAuthenticationMethods(ctx, spID, &sp)
		m.getRBACRoles(ctx, spID, &sp)

		// Update the service principal data
		servicePrincipals[spID] = sp
	}

	// Step 3: Enumerate Azure DevOps service connections (if credentials available)
	devopsOrg := os.Getenv("AZURE_DEVOPS_ORGANIZATION")
	devopsPAT := os.Getenv("AZDO_PAT")
	var serviceConnections []ServiceConnection
	if devopsOrg != "" && devopsPAT != "" {
		logger.InfoM("Enumerating Azure DevOps service connections...", globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
		serviceConnections = m.enumerateDevOpsServiceConnections(devopsOrg, devopsPAT)
		logger.InfoM(fmt.Sprintf("Found %d service connections", len(serviceConnections)), globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
	} else {
		logger.InfoM("Skipping Azure DevOps enumeration (set AZURE_DEVOPS_ORGANIZATION and AZDO_PAT to enable)", globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
	}

	// Step 4: Cross-reference with devops-agents loot files (if they exist)
	m.crossReferenceWithAgents(devopsOrg, serviceConnections, servicePrincipals, logger)

	// Step 5: Generate security analysis
	m.generateSecurityAnalysis(servicePrincipals, serviceConnections)

	// Step 6: Build table data
	m.buildTableData(servicePrincipals, serviceConnections)
}

// enumerateServicePrincipals fetches all service principals
func (m *FederatedCredentialsModule) enumerateServicePrincipals(ctx context.Context, logger internal.Logger) map[string]ServicePrincipalData {
	result := make(map[string]ServicePrincipalData)

	// Get token for Microsoft Graph
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[1]) // Microsoft Graph
	if err != nil || token == "" {
		logger.ErrorM("Failed to get Graph API token", globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
		return result
	}

	// Fetch service principals
	spURL := "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName"
	body, err := azinternal.GraphAPIRequestWithRetry(ctx, "GET", spURL, token)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to fetch service principals: %v", err), globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
		return result
	}

	var data struct {
		Value []map[string]interface{} `json:"value"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to parse service principals: %v", err), globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
		return result
	}

	for _, sp := range data.Value {
		objectID := azinternal.SafeValueString(sp["id"])
		if objectID == "" {
			continue
		}

		result[objectID] = ServicePrincipalData{
			DisplayName:          azinternal.SafeValueString(sp["displayName"]),
			AppID:                azinternal.SafeValueString(sp["appId"]),
			ObjectID:             objectID,
			FederatedCredentials: []FederatedCredential{},
			RBACRoles:            []string{},
			Subscriptions:        []string{},
		}
	}

	return result
}

// enumerateFederatedCredentials fetches federated credentials for a service principal
func (m *FederatedCredentialsModule) enumerateFederatedCredentials(ctx context.Context, spID string, sp *ServicePrincipalData) {
	// Get token for Microsoft Graph
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[1])
	if err != nil || token == "" {
		return
	}

	// Fetch federated credentials
	fedCredURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s/federatedIdentityCredentials", spID)
	body, err := azinternal.GraphAPIRequestWithRetry(ctx, "GET", fedCredURL, token)
	if err != nil {
		// Not all service principals have federated credentials, so this is expected
		return
	}

	var data struct {
		Value []map[string]interface{} `json:"value"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return
	}

	for _, fc := range data.Value {
		audiences := []string{}
		if aud, ok := fc["audiences"].([]interface{}); ok {
			for _, a := range aud {
				if audStr, ok := a.(string); ok {
					audiences = append(audiences, audStr)
				}
			}
		}

		fedCred := FederatedCredential{
			Name:        azinternal.SafeValueString(fc["name"]),
			Issuer:      azinternal.SafeValueString(fc["issuer"]),
			Subject:     azinternal.SafeValueString(fc["subject"]),
			Audiences:   audiences,
			Description: azinternal.SafeValueString(fc["description"]),
		}

		sp.FederatedCredentials = append(sp.FederatedCredentials, fedCred)
	}

	if len(sp.FederatedCredentials) > 0 {
		sp.HasFederatedCreds = true
	}
}

// checkAuthenticationMethods checks if SP has client secrets or certificates
func (m *FederatedCredentialsModule) checkAuthenticationMethods(ctx context.Context, spID string, sp *ServicePrincipalData) {
	// Get token for Microsoft Graph
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[1])
	if err != nil || token == "" {
		return
	}

	// Fetch the full service principal details to check for secrets/certs
	spURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s?$select=id,passwordCredentials,keyCredentials", spID)
	body, err := azinternal.GraphAPIRequestWithRetry(ctx, "GET", spURL, token)
	if err != nil {
		return
	}

	var spData map[string]interface{}
	if err := json.Unmarshal(body, &spData); err != nil {
		return
	}

	// Check for password credentials (client secrets)
	if passwords, ok := spData["passwordCredentials"].([]interface{}); ok && len(passwords) > 0 {
		sp.HasClientSecrets = true
	}

	// Check for key credentials (certificates)
	if keys, ok := spData["keyCredentials"].([]interface{}); ok && len(keys) > 0 {
		sp.HasCertificates = true
	}
}

// getRBACRoles gets RBAC role assignments for the service principal
func (m *FederatedCredentialsModule) getRBACRoles(ctx context.Context, spID string, sp *ServicePrincipalData) {
	// Get roles across all subscriptions
	for _, subID := range m.Subscriptions {
		roles := m.getRolesForSubscription(ctx, spID, subID)
		sp.RBACRoles = append(sp.RBACRoles, roles...)
		if len(roles) > 0 {
			sp.Subscriptions = append(sp.Subscriptions, subID)
		}
	}
}

// getRolesForSubscription gets RBAC roles for a specific subscription
func (m *FederatedCredentialsModule) getRolesForSubscription(ctx context.Context, principalID, subscriptionID string) []string {
	roles := []string{}

	// Use ARM API to get role assignments
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0]) // ARM
	if err != nil || token == "" {
		return roles
	}

	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?$filter=principalId eq '%s'&api-version=2022-04-01",
		subscriptionID, principalID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return roles
	}

	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return roles
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return roles
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return roles
	}

	var data struct {
		Value []map[string]interface{} `json:"value"`
	}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		return roles
	}

	for _, assignment := range data.Value {
		if props, ok := assignment["properties"].(map[string]interface{}); ok {
			if roleDefID, ok := props["roleDefinitionId"].(string); ok {
				// Extract role name from ID (last segment)
				parts := strings.Split(roleDefID, "/")
				if len(parts) > 0 {
					roleID := parts[len(parts)-1]
					roleName := m.getRoleName(ctx, subscriptionID, roleID)
					if roleName != "" {
						roles = append(roles, roleName)
					}
				}
			}
		}
	}

	return roles
}

// getRoleName resolves a role definition ID to a role name
func (m *FederatedCredentialsModule) getRoleName(ctx context.Context, subscriptionID, roleID string) string {
	token, err := m.Session.GetTokenForResource(globals.CommonScopes[0])
	if err != nil || token == "" {
		return roleID
	}

	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s?api-version=2022-04-01",
		subscriptionID, roleID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return roleID
	}

	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return roleID
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return roleID
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return roleID
	}

	var data map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		return roleID
	}

	if props, ok := data["properties"].(map[string]interface{}); ok {
		if roleName, ok := props["roleName"].(string); ok {
			return roleName
		}
	}

	return roleID
}

// enumerateDevOpsServiceConnections fetches Azure DevOps service connections
func (m *FederatedCredentialsModule) enumerateDevOpsServiceConnections(org, pat string) []ServiceConnection {
	var connections []ServiceConnection

	// First, get all projects
	projects := m.getDevOpsProjects(org, pat)

	// For each project, get service connections
	for _, project := range projects {
		projectConnections := m.getProjectServiceConnections(org, pat, project)
		connections = append(connections, projectConnections...)
	}

	return connections
}

// getDevOpsProjects fetches all projects in the organization
func (m *FederatedCredentialsModule) getDevOpsProjects(org, pat string) []string {
	var projects []string

	url := fmt.Sprintf("https://dev.azure.com/%s/_apis/projects?api-version=7.1", org)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return projects
	}

	req.SetBasicAuth("", pat)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return projects
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return projects
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return projects
	}

	var data struct {
		Value []map[string]interface{} `json:"value"`
	}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		return projects
	}

	for _, proj := range data.Value {
		if name, ok := proj["name"].(string); ok {
			projects = append(projects, name)
		}
	}

	return projects
}

// getProjectServiceConnections fetches service connections for a project
func (m *FederatedCredentialsModule) getProjectServiceConnections(org, pat, project string) []ServiceConnection {
	var connections []ServiceConnection

	url := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/serviceendpoint/endpoints?api-version=7.1", org, project)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return connections
	}

	req.SetBasicAuth("", pat)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return connections
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return connections
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return connections
	}

	var data struct {
		Value []map[string]interface{} `json:"value"`
	}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		return connections
	}

	for _, conn := range data.Value {
		connection := ServiceConnection{
			Name:        azinternal.SafeValueString(conn["name"]),
			Type:        azinternal.SafeValueString(conn["type"]),
			ProjectName: project,
		}

		// Extract authentication details
		if auth, ok := conn["authorization"].(map[string]interface{}); ok {
			connection.AuthScheme = azinternal.SafeValueString(auth["scheme"])

			if params, ok := auth["parameters"].(map[string]interface{}); ok {
				if spID, ok := params["serviceprincipalid"].(string); ok {
					connection.ServicePrincipalID = spID
				}
			}
		}

		// Extract subscription details
		if data, ok := conn["data"].(map[string]interface{}); ok {
			if subID, ok := data["subscriptionId"].(string); ok {
				connection.SubscriptionID = subID
			}
			if subName, ok := data["subscriptionName"].(string); ok {
				connection.SubscriptionName = subName
			}
		}

		// Check if ready
		if isReady, ok := conn["isReady"].(bool); ok {
			connection.IsReady = isReady
		}

		// Check if shared
		if isShared, ok := conn["isShared"].(bool); ok {
			connection.IsShared = isShared
		}

		// Extract creator
		if createdBy, ok := conn["createdBy"].(map[string]interface{}); ok {
			connection.CreatedBy = azinternal.SafeValueString(createdBy["displayName"])
		}

		connections = append(connections, connection)
	}

	return connections
}

// crossReferenceWithAgents reads devops-agents loot files and links to service principals
func (m *FederatedCredentialsModule) crossReferenceWithAgents(devopsOrg string, serviceConnections []ServiceConnection, servicePrincipals map[string]ServicePrincipalData, logger internal.Logger) {
	if devopsOrg == "" {
		return
	}

	// Build path to devops-agents loot files
	lootDir := fmt.Sprintf("./cloudfox-output/azure-%s/loot", devopsOrg)

	// Check if self-hosted agents file exists
	agentsFile := filepath.Join(lootDir, "agents-self-hosted.txt")
	if _, err := os.Stat(agentsFile); os.IsNotExist(err) {
		logger.InfoM("No devops-agents loot files found (run 'cloudfox azure devops-agents' first to see complete attack paths)", globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
		return
	}

	logger.InfoM("Found devops-agents loot files, generating complete attack paths...", globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)

	// Read self-hosted agents file
	agentsContent, err := os.ReadFile(agentsFile)
	if err != nil {
		return
	}

	// Parse agent information from loot file
	// Format: "## Agent: {name} (Pool: {pool})"
	agentLines := strings.Split(string(agentsContent), "\n")
	var currentAgent string
	var currentPool string

	m.mu.Lock()
	m.LootMap["fedcreds-attack-paths"].Contents += "# COMPLETE ATTACK PATHS: Azure DevOps Agents → Azure Resources\n\n"

	for _, line := range agentLines {
		if strings.HasPrefix(line, "## Agent:") {
			// Extract agent and pool name
			parts := strings.Split(line, "(Pool:")
			if len(parts) == 2 {
				agentPart := strings.TrimPrefix(parts[0], "## Agent:")
				currentAgent = strings.TrimSpace(agentPart)
				currentPool = strings.TrimSuffix(strings.TrimSpace(parts[1]), ")")

				// Generate attack path for this agent
				m.LootMap["fedcreds-attack-paths"].Contents += fmt.Sprintf("\n=== ATTACK PATH ===\n")
				m.LootMap["fedcreds-attack-paths"].Contents += fmt.Sprintf("Self-Hosted Agent: %s\n", currentAgent)
				m.LootMap["fedcreds-attack-paths"].Contents += fmt.Sprintf("Agent Pool: %s\n", currentPool)
				m.LootMap["fedcreds-attack-paths"].Contents += fmt.Sprintf("\nPotential Service Connections Accessible:\n")

				// Find service connections accessible by pipelines using this agent
				for _, sc := range serviceConnections {
					if sc.ServicePrincipalID != "" {
						// Find the service principal
						for _, sp := range servicePrincipals {
							if sp.AppID == sc.ServicePrincipalID || sp.ObjectID == sc.ServicePrincipalID {
								m.LootMap["fedcreds-attack-paths"].Contents += fmt.Sprintf("  ├─> Service Connection: %s (%s)\n", sc.Name, sc.ProjectName)
								m.LootMap["fedcreds-attack-paths"].Contents += fmt.Sprintf("  │   ├─> Service Principal: %s\n", sp.DisplayName)

								if sp.HasFederatedCreds {
									m.LootMap["fedcreds-attack-paths"].Contents += fmt.Sprintf("  │   ├─> Auth Method: Workload Identity Federation (OIDC)\n")
									for _, fc := range sp.FederatedCredentials {
										m.LootMap["fedcreds-attack-paths"].Contents += fmt.Sprintf("  │   │   └─> Subject: %s\n", fc.Subject)
									}
								} else if sp.HasClientSecrets {
									m.LootMap["fedcreds-attack-paths"].Contents += fmt.Sprintf("  │   ├─> Auth Method: Client Secret (LEGACY - HIGH RISK)\n")
								}

								m.LootMap["fedcreds-attack-paths"].Contents += fmt.Sprintf("  │   └─> Azure Access:\n")
								if len(sp.RBACRoles) > 0 {
									for _, role := range sp.RBACRoles {
										m.LootMap["fedcreds-attack-paths"].Contents += fmt.Sprintf("  │       └─> Role: %s\n", role)
									}
								} else {
									m.LootMap["fedcreds-attack-paths"].Contents += fmt.Sprintf("  │       └─> No RBAC roles found\n")
								}
								m.LootMap["fedcreds-attack-paths"].Contents += fmt.Sprintf("\n")
							}
						}
					}
				}

				m.LootMap["fedcreds-attack-paths"].Contents += "\nATTACK SCENARIO:\n"
				m.LootMap["fedcreds-attack-paths"].Contents += "1. Submit malicious pipeline to run on this self-hosted agent\n"
				m.LootMap["fedcreds-attack-paths"].Contents += "2. Pipeline uses service connection to authenticate to Azure\n"
				m.LootMap["fedcreds-attack-paths"].Contents += "3. Harvest OIDC token or service principal credentials from pipeline\n"
				m.LootMap["fedcreds-attack-paths"].Contents += "4. Use stolen credentials to access Azure resources outside pipeline\n"
				m.LootMap["fedcreds-attack-paths"].Contents += "\n" + strings.Repeat("=", 80) + "\n\n"
			}
		}
	}
	m.mu.Unlock()
}

// generateSecurityAnalysis generates security findings
func (m *FederatedCredentialsModule) generateSecurityAnalysis(servicePrincipals map[string]ServicePrincipalData, serviceConnections []ServiceConnection) {
	secretCount := 0
	devopsCount := 0
	githubCount := 0
	overpermissiveCount := 0

	for _, sp := range servicePrincipals {
		// Check for client secrets (legacy authentication)
		if sp.HasClientSecrets && !sp.HasFederatedCreds {
			secretCount++
			m.mu.Lock()
			m.LootMap["fedcreds-secrets"].Contents += fmt.Sprintf("## Service Principal: %s\n", sp.DisplayName)
			m.LootMap["fedcreds-secrets"].Contents += fmt.Sprintf("App ID: %s\n", sp.AppID)
			m.LootMap["fedcreds-secrets"].Contents += "Authentication: Client Secret (LEGACY)\n"
			m.LootMap["fedcreds-secrets"].Contents += "RECOMMENDATION: Migrate to Workload Identity Federation (OIDC)\n"
			m.LootMap["fedcreds-secrets"].Contents += "Benefits:\n"
			m.LootMap["fedcreds-secrets"].Contents += "  - No secrets to rotate or manage\n"
			m.LootMap["fedcreds-secrets"].Contents += "  - Reduced risk of credential leakage\n"
			m.LootMap["fedcreds-secrets"].Contents += "  - Better audit trail with OIDC tokens\n"
			m.LootMap["fedcreds-secrets"].Contents += "\n" + strings.Repeat("-", 80) + "\n\n"
			m.mu.Unlock()
		}

		// Analyze federated credentials
		for _, fc := range sp.FederatedCredentials {
			// Check for Azure DevOps credentials
			if strings.Contains(fc.Issuer, "vstoken.dev.azure.com") {
				devopsCount++
				m.mu.Lock()
				m.LootMap["fedcreds-devops"].Contents += fmt.Sprintf("## Service Principal: %s\n", sp.DisplayName)
				m.LootMap["fedcreds-devops"].Contents += fmt.Sprintf("App ID: %s\n", sp.AppID)
				m.LootMap["fedcreds-devops"].Contents += fmt.Sprintf("Credential Name: %s\n", fc.Name)
				m.LootMap["fedcreds-devops"].Contents += fmt.Sprintf("Subject: %s\n", fc.Subject)
				m.LootMap["fedcreds-devops"].Contents += fmt.Sprintf("Issuer: %s\n", fc.Issuer)
				m.LootMap["fedcreds-devops"].Contents += fmt.Sprintf("Audiences: %s\n", strings.Join(fc.Audiences, ", "))
				if len(sp.RBACRoles) > 0 {
					m.LootMap["fedcreds-devops"].Contents += fmt.Sprintf("RBAC Roles: %s\n", strings.Join(sp.RBACRoles, ", "))
				}
				m.LootMap["fedcreds-devops"].Contents += "\n" + strings.Repeat("-", 80) + "\n\n"
				m.mu.Unlock()
			}

			// Check for GitHub Actions credentials
			if strings.Contains(fc.Issuer, "token.actions.githubusercontent.com") {
				githubCount++
				m.mu.Lock()
				m.LootMap["fedcreds-github"].Contents += fmt.Sprintf("## Service Principal: %s\n", sp.DisplayName)
				m.LootMap["fedcreds-github"].Contents += fmt.Sprintf("App ID: %s\n", sp.AppID)
				m.LootMap["fedcreds-github"].Contents += fmt.Sprintf("Credential Name: %s\n", fc.Name)
				m.LootMap["fedcreds-github"].Contents += fmt.Sprintf("Subject: %s\n", fc.Subject)
				m.LootMap["fedcreds-github"].Contents += fmt.Sprintf("Issuer: %s\n", fc.Issuer)
				m.LootMap["fedcreds-github"].Contents += fmt.Sprintf("Audiences: %s\n", strings.Join(fc.Audiences, ", "))
				if len(sp.RBACRoles) > 0 {
					m.LootMap["fedcreds-github"].Contents += fmt.Sprintf("RBAC Roles: %s\n", strings.Join(sp.RBACRoles, ", "))
				}
				m.LootMap["fedcreds-github"].Contents += "\n" + strings.Repeat("-", 80) + "\n\n"
				m.mu.Unlock()
			}

			// Check for overpermissive subject scopes
			if m.isOverpermissiveSubject(fc.Subject) {
				overpermissiveCount++
				m.mu.Lock()
				m.LootMap["fedcreds-overpermissive"].Contents += fmt.Sprintf("## Service Principal: %s\n", sp.DisplayName)
				m.LootMap["fedcreds-overpermissive"].Contents += fmt.Sprintf("App ID: %s\n", sp.AppID)
				m.LootMap["fedcreds-overpermissive"].Contents += fmt.Sprintf("Credential Name: %s\n", fc.Name)
				m.LootMap["fedcreds-overpermissive"].Contents += fmt.Sprintf("Subject: %s\n", fc.Subject)
				m.LootMap["fedcreds-overpermissive"].Contents += fmt.Sprintf("Risk: %s\n", m.getSubjectRisk(fc.Subject))
				m.LootMap["fedcreds-overpermissive"].Contents += "RECOMMENDATION: Narrow the subject scope to specific branches or environments\n"
				m.LootMap["fedcreds-overpermissive"].Contents += "\n" + strings.Repeat("-", 80) + "\n\n"
				m.mu.Unlock()
			}
		}
	}

	// Generate service connections loot
	for _, sc := range serviceConnections {
		m.mu.Lock()
		m.LootMap["fedcreds-service-connections"].Contents += fmt.Sprintf("## Service Connection: %s\n", sc.Name)
		m.LootMap["fedcreds-service-connections"].Contents += fmt.Sprintf("Project: %s\n", sc.ProjectName)
		m.LootMap["fedcreds-service-connections"].Contents += fmt.Sprintf("Type: %s\n", sc.Type)
		m.LootMap["fedcreds-service-connections"].Contents += fmt.Sprintf("Auth Scheme: %s\n", sc.AuthScheme)
		if sc.ServicePrincipalID != "" {
			m.LootMap["fedcreds-service-connections"].Contents += fmt.Sprintf("Service Principal ID: %s\n", sc.ServicePrincipalID)
		}
		if sc.SubscriptionID != "" {
			m.LootMap["fedcreds-service-connections"].Contents += fmt.Sprintf("Subscription: %s (%s)\n", sc.SubscriptionName, sc.SubscriptionID)
		}
		m.LootMap["fedcreds-service-connections"].Contents += fmt.Sprintf("Is Ready: %v\n", sc.IsReady)
		m.LootMap["fedcreds-service-connections"].Contents += fmt.Sprintf("Is Shared: %v\n", sc.IsShared)
		m.LootMap["fedcreds-service-connections"].Contents += "\n" + strings.Repeat("-", 80) + "\n\n"
		m.mu.Unlock()
	}

	// Generate summary
	m.mu.Lock()
	m.LootMap["fedcreds-summary"].Contents += fmt.Sprintf("Total Service Principals Analyzed: %d\n", len(servicePrincipals))
	m.LootMap["fedcreds-summary"].Contents += fmt.Sprintf("Service Principals Using Client Secrets: %d\n", secretCount)
	m.LootMap["fedcreds-summary"].Contents += fmt.Sprintf("Azure DevOps Federated Credentials: %d\n", devopsCount)
	m.LootMap["fedcreds-summary"].Contents += fmt.Sprintf("GitHub Actions Federated Credentials: %d\n", githubCount)
	m.LootMap["fedcreds-summary"].Contents += fmt.Sprintf("Overpermissive Federated Credentials: %d\n", overpermissiveCount)
	m.LootMap["fedcreds-summary"].Contents += fmt.Sprintf("Azure DevOps Service Connections: %d\n", len(serviceConnections))
	m.LootMap["fedcreds-summary"].Contents += "\n"

	if secretCount > 0 {
		m.LootMap["fedcreds-summary"].Contents += "⚠ WARNING: Service principals using client secrets detected\n"
		m.LootMap["fedcreds-summary"].Contents += "   Recommendation: Migrate to Workload Identity Federation (OIDC)\n\n"
	}

	if overpermissiveCount > 0 {
		m.LootMap["fedcreds-summary"].Contents += "⚠ WARNING: Overpermissive federated credentials detected\n"
		m.LootMap["fedcreds-summary"].Contents += "   Recommendation: Narrow subject scopes to specific branches/environments\n\n"
	}
	m.mu.Unlock()
}

// isOverpermissiveSubject checks if a subject scope is too broad
func (m *FederatedCredentialsModule) isOverpermissiveSubject(subject string) bool {
	// GitHub Actions patterns
	if strings.Contains(subject, ":pull_request") {
		return true // PRs can authenticate (HIGH RISK)
	}
	if strings.Contains(subject, ":ref:refs/heads/*") {
		return true // Any branch can authenticate
	}

	// Azure DevOps patterns (need to analyze org-specific patterns)
	if strings.Contains(subject, "/*") {
		return true // Wildcard subjects
	}

	return false
}

// getSubjectRisk returns a risk description for a subject scope
func (m *FederatedCredentialsModule) getSubjectRisk(subject string) string {
	if strings.Contains(subject, ":pull_request") {
		return "CRITICAL - Pull requests can authenticate to Azure (external contributors in public repos)"
	}
	if strings.Contains(subject, ":ref:refs/heads/*") {
		return "HIGH - Any branch can authenticate to Azure"
	}
	if strings.Contains(subject, "/*") {
		return "MEDIUM - Wildcard subject allows multiple pipelines/repos"
	}
	return "LOW - Subject is appropriately scoped"
}

// buildTableData builds the table data for output
func (m *FederatedCredentialsModule) buildTableData(servicePrincipals map[string]ServicePrincipalData, serviceConnections []ServiceConnection) {
	for _, sp := range servicePrincipals {
		// Only include SPs that have authentication configured OR are used by service connections
		isUsedByDevOps := false
		for _, sc := range serviceConnections {
			if sc.ServicePrincipalID == sp.AppID || sc.ServicePrincipalID == sp.ObjectID {
				isUsedByDevOps = true
				break
			}
		}

		if !sp.HasClientSecrets && !sp.HasCertificates && !sp.HasFederatedCreds && !isUsedByDevOps {
			continue // Skip SPs with no authentication configured
		}

		authMethod := "None"
		if sp.HasFederatedCreds {
			authMethod = "Federated Identity (OIDC)"
		} else if sp.HasClientSecrets {
			authMethod = "Client Secret"
		} else if sp.HasCertificates {
			authMethod = "Certificate"
		}

		issuerType := "N/A"
		subjectScope := "N/A"
		if len(sp.FederatedCredentials) > 0 {
			fc := sp.FederatedCredentials[0] // Show first credential
			if strings.Contains(fc.Issuer, "vstoken") {
				issuerType = "Azure DevOps"
			} else if strings.Contains(fc.Issuer, "token.actions") {
				issuerType = "GitHub Actions"
			}
			subjectScope = fc.Subject
			if len(sp.FederatedCredentials) > 1 {
				subjectScope += fmt.Sprintf(" (+%d more)", len(sp.FederatedCredentials)-1)
			}
		}

		rbacRoles := "None"
		if len(sp.RBACRoles) > 0 {
			rbacRoles = strings.Join(sp.RBACRoles[:min(2, len(sp.RBACRoles))], ", ")
			if len(sp.RBACRoles) > 2 {
				rbacRoles += fmt.Sprintf(" (+%d more)", len(sp.RBACRoles)-2)
			}
		}

		devOpsUsage := "No"
		if isUsedByDevOps {
			devOpsUsage = "Yes"
		}

		securityRisks := []string{}
		if sp.HasClientSecrets && !sp.HasFederatedCreds {
			securityRisks = append(securityRisks, "Using client secrets (migrate to OIDC)")
		}
		if len(sp.FederatedCredentials) > 0 {
			for _, fc := range sp.FederatedCredentials {
				if m.isOverpermissiveSubject(fc.Subject) {
					securityRisks = append(securityRisks, "Overpermissive subject scope")
					break
				}
			}
		}
		securityRisksStr := "None"
		if len(securityRisks) > 0 {
			securityRisksStr = strings.Join(securityRisks, "; ")
		}

		m.TableData = append(m.TableData, map[string]interface{}{
			"displayName":   sp.DisplayName,
			"appID":         sp.AppID,
			"authMethod":    authMethod,
			"issuerType":    issuerType,
			"subjectScope":  subjectScope,
			"rbacRoles":     rbacRoles,
			"subscriptions": len(sp.Subscriptions),
			"devOpsUsage":   devOpsUsage,
			"securityRisks": securityRisksStr,
			"hasSecrets":    sp.HasClientSecrets,
			"hasFedCreds":   sp.HasFederatedCreds,
		})
	}

	// Sort by risk (secrets first, then overpermissive)
	sort.Slice(m.TableData, func(i, j int) bool {
		iHasSecrets := m.TableData[i]["hasSecrets"].(bool)
		jHasSecrets := m.TableData[j]["hasSecrets"].(bool)
		if iHasSecrets != jHasSecrets {
			return iHasSecrets
		}
		return m.TableData[i]["displayName"].(string) < m.TableData[j]["displayName"].(string)
	})
}

// writeOutput writes the results using HandleOutputSmart
func (m *FederatedCredentialsModule) writeOutput(logger internal.Logger) {
	if len(m.TableData) == 0 {
		logger.InfoM("No federated credentials found", globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
		return
	}

	// Define headers (add TenantName and TenantID as first two columns)
	headers := []string{
		"Tenant Name", "Tenant ID", "Service Principal", "App ID", "Auth Method",
		"Issuer Type", "Subject Scope", "RBAC Roles", "Subscriptions",
		"DevOps Usage", "Security Risks",
	}

	// Convert TableData to standard [][]string rows
	var rows [][]string
	secretCount := 0
	fedCredCount := 0

	for _, row := range m.TableData {
		rows = append(rows, []string{
			m.TenantName,
			m.TenantID,
			row["displayName"].(string),
			row["appID"].(string),
			row["authMethod"].(string),
			row["issuerType"].(string),
			row["subjectScope"].(string),
			row["rbacRoles"].(string),
			fmt.Sprintf("%d", row["subscriptions"].(int)),
			row["devOpsUsage"].(string),
			row["securityRisks"].(string),
		})

		// Count stats for summary
		if row["hasSecrets"].(bool) {
			secretCount++
		}
		if row["hasFedCreds"].(bool) {
			fedCredCount++
		}
	}

	// Convert loot map to slice
	var lootFiles []internal.LootFile
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			lootFiles = append(lootFiles, *lf)
		}
	}

	// -------------------- Check for split by tenant (FIRST) --------------------
	if azinternal.ShouldSplitByTenant(m.IsMultiTenant, m.Tenants) {
		if len(rows) > 0 {
			// Split by tenant
			ctx := context.Background()
			if err := m.FilterAndWritePerTenantAuto(
				ctx, logger, m.Tenants, rows, headers,
				"federated-credentials", globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME,
			); err != nil {
				logger.ErrorM("Failed to write per-tenant federated credentials", globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
			}
		}
		// Write loot files separately (not split)
		if len(lootFiles) > 0 {
			output := FederatedCredentialsOutput{
				Table: []internal.TableFile{},
				Loot:  lootFiles,
			}
			scopeType := "tenant"
			scopeIDs := []string{m.TenantID}
			scopeNames := []string{m.TenantName}
			if err := internal.HandleOutputSmart(
				"Azure", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
				scopeType, scopeIDs, scopeNames, m.UserUPN, output,
			); err != nil {
				logger.ErrorM(fmt.Sprintf("Error writing loot output: %v", err), globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
			}
		}
		logger.SuccessM(fmt.Sprintf("Found %d Service Principals (OIDC: %d, Secrets: %d)",
			len(m.TableData), fedCredCount, secretCount), globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
		if secretCount > 0 {
			logger.InfoM("WARNING: Service principals using client secrets detected - Migrate to Workload Identity Federation (OIDC)", globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
		}
		return
	}

	// -------------------- Non-split case --------------------
	output := FederatedCredentialsOutput{
		Table: []internal.TableFile{
			{
				Header: headers,
				Body:   rows,
				Name:   "federated-credentials",
			},
		},
		Loot: lootFiles,
	}

	// Determine scope for output (tenant-level for Graph API)
	scopeType := "tenant"
	scopeIDs := []string{m.TenantID}
	scopeNames := []string{m.TenantName}

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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d Service Principals (OIDC: %d, Secrets: %d)",
		len(m.TableData), fedCredCount, secretCount), globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
	if secretCount > 0 {
		logger.InfoM("WARNING: Service principals using client secrets detected - Migrate to Workload Identity Federation (OIDC)", globals.AZ_FEDERATED_CREDENTIALS_MODULE_NAME)
	}
}

