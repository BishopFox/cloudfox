package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
var AzDevOpsAgentsCommand = &cobra.Command{
	Use:     "devops-agents",
	Aliases: []string{"devops-runners"},
	Short:   "Enumerate Azure DevOps Agents and analyze security posture",
	Long: `
Enumerate Azure DevOps Agents (pipeline runners) and analyze their security posture.
Self-hosted agents are HIGH RISK targets as they often contain production credentials.

Authentication (in order of priority):
1. Personal Access Token: Set AZDO_PAT environment variable
2. Azure AD (fallback): Uses 'az login' session automatically

Requires an organization (--org or $AZURE_DEVOPS_ORGANIZATION).

Generates table output and five loot files:
- agents-self-hosted: Self-hosted agents (HIGH RISK credential targets)
- agents-security-summary: Security analysis for all agents
- agents-outdated: Agents running outdated versions (CVE risk)
- agents-job-history: Recent pipeline executions per agent
- agents-permissions: Agent pool permission assignments`,
	Run: ListDevOpsAgents,
}

var (
	azDevOpsAgentsOrg string
)

func init() {
	AzDevOpsAgentsCommand.Flags().StringVarP(&azDevOpsAgentsOrg, "org", "o", "", "Azure DevOps organization name")
}

var logger = internal.NewLogger()

// ListDevOpsAgents is the main entry point for the devops-agents command
func ListDevOpsAgents(cmd *cobra.Command, args []string) {
	var err error

	// Get organization from flag or environment variable
	organization := azDevOpsAgentsOrg
	if organization == "" {
		organization = os.Getenv("AZURE_DEVOPS_ORGANIZATION")
	}

	if organization == "" {
		logger.ErrorM("Organization is required. Use --org flag or set AZURE_DEVOPS_ORGANIZATION environment variable.", globals.AZ_DEVOPS_AGENTS_MODULE_NAME)
		return
	}

	// Get authentication token (PAT or Azure AD)
	pat, authMethod, err := azinternal.GetDevOpsAuthTokenSimple()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Authentication failed: %v", err), globals.AZ_DEVOPS_AGENTS_MODULE_NAME)
		logger.InfoM("Set AZDO_PAT environment variable or run 'az login' to authenticate", globals.AZ_DEVOPS_AGENTS_MODULE_NAME)
		return
	}

	// Log authentication method
	if authMethod == "Azure AD" {
		logger.InfoM("Using Azure AD authentication (az login)", globals.AZ_DEVOPS_AGENTS_MODULE_NAME)
	} else {
		logger.InfoM("Using Personal Access Token (AZDO_PAT)", globals.AZ_DEVOPS_AGENTS_MODULE_NAME)
	}

	// Get output directory
	outputDirectory := "./cloudfox-output/azure-" + organization
	if err = os.MkdirAll(outputDirectory, 0755); err != nil {
		logger.ErrorM(fmt.Sprintf("Error creating output directory: %s", err), globals.AZ_DEVOPS_AGENTS_MODULE_NAME)
		return
	}

	verbosity := globals.AZ_VERBOSITY

	// Run the command
	RunDevOpsAgentsCommand(organization, pat, verbosity, outputDirectory)
}

// DevOpsAgentsModule handles enumeration of Azure DevOps Agents (pipeline runners)
type DevOpsAgentsModule struct {
	Organization string
	PAT          string
	AzureClient  *azinternal.AzureClient

	CommandCounter azinternal.CommandCounter
	LootMap        map[string]azinternal.AzureLoot
	mu             sync.Mutex
	verbosity      int
}

// PrintHelp displays help information for the devops-agents command
func (m *DevOpsAgentsModule) PrintHelp() {
	fmt.Println("Usage: cloudfox azure devops-agents")
	fmt.Println("")
	fmt.Println("This command enumerates Azure DevOps Agents (pipeline runners) and analyzes")
	fmt.Println("their security posture. Self-hosted agents are high-value targets as they:")
	fmt.Println("  - Often have access to production secrets and credentials")
	fmt.Println("  - Can execute arbitrary code from pipelines")
	fmt.Println("  - May have corporate network access for lateral movement")
	fmt.Println("  - Store agent registration tokens (persistent access)")
	fmt.Println("")
	fmt.Println("Enumeration includes:")
	fmt.Println("  - Agent pools (organization and project-scoped)")
	fmt.Println("  - Agent details (type, version, status, capabilities)")
	fmt.Println("  - Self-hosted agent detection (HIGH RISK)")
	fmt.Println("  - Agent capabilities (OS, software, custom)")
	fmt.Println("  - Agent pool permissions")
	fmt.Println("  - Recent job execution history")
	fmt.Println("  - Outdated agent versions (CVE risk)")
	fmt.Println("  - Authentication mechanisms (service principal, workload identity)")
	fmt.Println("")
	fmt.Println("Required Environment Variables:")
	fmt.Println("  AZURE_DEVOPS_PAT          - Personal Access Token with Agent Pools (Read) scope")
	fmt.Println("  AZURE_DEVOPS_ORGANIZATION - Organization name (e.g., 'contoso')")
	fmt.Println("")
	fmt.Println("Optional Parameters:")
	fmt.Println("  -v, --verbosity           - Set verbosity level (2-5, default: 2)")
	fmt.Println("")
}

// RunDevOpsAgentsCommand executes the devops-agents command
func RunDevOpsAgentsCommand(organization, pat string, verbosity int, outputDirectory string) {
	var header []string
	var body [][]string

	// Initialize module
	module := &DevOpsAgentsModule{
		Organization: organization,
		PAT:          pat,
		verbosity:    verbosity,
		LootMap:      make(map[string]azinternal.AzureLoot),
	}

	// Validate inputs
	if organization == "" || pat == "" {
		logrus.Error("Organization and PAT are required. Set AZURE_DEVOPS_ORGANIZATION and AZURE_DEVOPS_PAT environment variables.")
		return
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Enumerate agent pools and agents
	logrus.Info("Enumerating Azure DevOps Agents across all agent pools...")
	module.enumerateAgentPools()

	// Generate table output
	header, body = module.generateTableOutput()

	// Save loot files
	timestamp := time.Now().Format("2006-01-02-15-04-05")
	lootDir := fmt.Sprintf("%s/loot", outputDirectory)
	azinternal.SaveDevOpsLootFiles(module.LootMap, lootDir, timestamp, module.Organization)

	// Print table
	fmt.Println()
	globals.PrintTableFromStructs(header, body)
	fmt.Println()

	// Print summary
	module.printSummary(len(body))
}

// initializeLootFiles creates the loot file structure
func (m *DevOpsAgentsModule) initializeLootFiles() {
	m.LootMap["agents-self-hosted"] = azinternal.AzureLoot{
		Name:        "agents-self-hosted.txt",
		Description: "Self-hosted agents (HIGH RISK - credential harvesting targets)",
		Contents: "# Self-Hosted Azure DevOps Agents\n" +
			"# These agents are HIGH RISK targets for attackers:\n" +
			"#  - May have access to production credentials and secrets\n" +
			"#  - Can execute arbitrary code from malicious pipelines\n" +
			"#  - Often have corporate network access for lateral movement\n" +
			"#  - Store agent registration tokens for persistent access\n\n",
	}

	m.LootMap["agents-security-summary"] = azinternal.AzureLoot{
		Name:        "agents-security-summary.txt",
		Description: "Security summary for all agent pools",
		Contents: "# Azure DevOps Agents - Security Summary\n" +
			"# Generated: " + time.Now().Format(time.RFC3339) + "\n\n",
	}

	m.LootMap["agents-outdated"] = azinternal.AzureLoot{
		Name:        "agents-outdated.txt",
		Description: "Agents running outdated versions (CVE risk)",
		Contents: "# Outdated Azure DevOps Agents\n" +
			"# These agents may be vulnerable to known CVEs\n" +
			"# Recommendation: Update to latest agent version\n\n",
	}

	m.LootMap["agents-job-history"] = azinternal.AzureLoot{
		Name:        "agents-job-history.txt",
		Description: "Recent job execution history per agent",
		Contents: "# Azure DevOps Agents - Recent Job History\n" +
			"# Shows which agents are actively executing pipelines\n\n",
	}

	m.LootMap["agents-permissions"] = azinternal.AzureLoot{
		Name:        "agents-permissions.txt",
		Description: "Agent pool permissions and security roles",
		Contents: "# Azure DevOps Agent Pool Permissions\n" +
			"# Identifies who can manage agent pools and register agents\n\n",
	}
}

// enumerateAgentPools enumerates all agent pools and their agents
func (m *DevOpsAgentsModule) enumerateAgentPools() {
	// Enumerate organization-level agent pools
	url := fmt.Sprintf("https://dev.azure.com/%s/_apis/distributedtask/pools?api-version=7.1", m.Organization)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logrus.WithError(err).Error("Failed to create request for agent pools")
		return
	}

	req.SetBasicAuth("", m.PAT)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logrus.WithError(err).Error("Failed to fetch agent pools")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		logrus.Errorf("Failed to fetch agent pools. Status: %d, Body: %s", resp.StatusCode, string(bodyBytes))
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.WithError(err).Error("Failed to read agent pools response")
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		logrus.WithError(err).Error("Failed to parse agent pools response")
		return
	}

	pools, ok := result["value"].([]interface{})
	if !ok {
		logrus.Error("Unexpected agent pools response format")
		return
	}

	logrus.Infof("Found %d agent pools", len(pools))

	// Process each pool
	for _, poolItem := range pools {
		pool, ok := poolItem.(map[string]interface{})
		if !ok {
			continue
		}

		poolID := int(pool["id"].(float64))
		poolName := pool["name"].(string)

		logrus.Debugf("Processing agent pool: %s (ID: %d)", poolName, poolID)

		// Enumerate agents in this pool
		m.enumerateAgentsInPool(poolID, poolName)

		// Enumerate pool permissions
		m.enumeratePoolPermissions(poolID, poolName)
	}
}

// enumerateAgentsInPool enumerates all agents in a specific pool
func (m *DevOpsAgentsModule) enumerateAgentsInPool(poolID int, poolName string) {
	url := fmt.Sprintf("https://dev.azure.com/%s/_apis/distributedtask/pools/%d/agents?includeCapabilities=true&includeLastCompletedRequest=true&api-version=7.1",
		m.Organization, poolID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to create request for agents in pool %s", poolName)
		return
	}

	req.SetBasicAuth("", m.PAT)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to fetch agents in pool %s", poolName)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		logrus.Debugf("Failed to fetch agents in pool %s. Status: %d, Body: %s", poolName, resp.StatusCode, string(bodyBytes))
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to read agents response for pool %s", poolName)
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		logrus.WithError(err).Errorf("Failed to parse agents response for pool %s", poolName)
		return
	}

	agents, ok := result["value"].([]interface{})
	if !ok {
		logrus.Debugf("No agents found in pool %s", poolName)
		return
	}

	logrus.Infof("Found %d agents in pool '%s'", len(agents), poolName)

	// Process each agent
	for _, agentItem := range agents {
		agent, ok := agentItem.(map[string]interface{})
		if !ok {
			continue
		}

		m.processAgent(agent, poolID, poolName)
	}
}

// processAgent processes a single agent and performs security analysis
func (m *DevOpsAgentsModule) processAgent(agent map[string]interface{}, poolID int, poolName string) {
	// Extract agent details
	agentID := int(agent["id"].(float64))
	agentName := agent["name"].(string)

	status := "unknown"
	if s, ok := agent["status"].(string); ok {
		status = s
	}

	enabled := "No"
	if e, ok := agent["enabled"].(bool); ok && e {
		enabled = "Yes"
	}

	version := "unknown"
	if v, ok := agent["version"].(string); ok {
		version = v
	}

	// Determine if agent is self-hosted (Microsoft-hosted agents have specific naming patterns)
	agentType := "Self-hosted"
	isHighRisk := true
	if strings.Contains(strings.ToLower(poolName), "azure pipelines") ||
		strings.Contains(strings.ToLower(poolName), "hosted") ||
		strings.Contains(strings.ToLower(agentName), "hosted") {
		agentType = "Microsoft-hosted"
		isHighRisk = false
	}

	// Extract capabilities
	capabilities := make(map[string]string)
	if caps, ok := agent["systemCapabilities"].(map[string]interface{}); ok {
		for k, v := range caps {
			if vStr, ok := v.(string); ok {
				capabilities[k] = vStr
			}
		}
	}

	// Extract OS information from capabilities
	osInfo := "Unknown"
	if osName, ok := capabilities["OSName"]; ok {
		osInfo = osName
	} else if osVersion, ok := capabilities["OSVersion"]; ok {
		osInfo = osVersion
	} else if agent_os, ok := capabilities["Agent.OS"]; ok {
		osInfo = agent_os
	}

	// Extract last completed job information
	lastJobDate := "Never"
	lastJobResult := "N/A"
	if lastRequest, ok := agent["lastCompletedRequest"].(map[string]interface{}); ok {
		if finishTime, ok := lastRequest["finishTime"].(string); ok && finishTime != "" {
			if t, err := time.Parse(time.RFC3339, finishTime); err == nil {
				lastJobDate = t.Format("2006-01-02 15:04")
			}
		}
		if result, ok := lastRequest["result"].(string); ok {
			lastJobResult = result
		}
	}

	// Security risk assessment
	securityRisks := []string{}

	if isHighRisk {
		securityRisks = append(securityRisks, "Self-hosted (credential exposure risk)")
	}

	if enabled == "Yes" && status == "offline" {
		securityRisks = append(securityRisks, "Enabled but offline (potential compromise)")
	}

	// Check for outdated agent version (example: flag versions older than 3.x)
	if version != "unknown" && !strings.HasPrefix(version, "3.") && !strings.HasPrefix(version, "4.") {
		securityRisks = append(securityRisks, "Outdated agent version (CVE risk)")
	}

	// Extract installed software capabilities
	installedSoftware := []string{}
	for capName := range capabilities {
		// Common capability patterns that indicate installed software
		if strings.Contains(capName, "docker") ||
			strings.Contains(capName, "git") ||
			strings.Contains(capName, "node") ||
			strings.Contains(capName, "python") ||
			strings.Contains(capName, "java") ||
			strings.Contains(capName, "dotnet") ||
			strings.Contains(capName, "kubectl") ||
			strings.Contains(capName, "az") {
			installedSoftware = append(installedSoftware, capName)
		}
	}
	softwareList := "None detected"
	if len(installedSoftware) > 0 {
		softwareList = strings.Join(installedSoftware[:min(3, len(installedSoftware))], ", ")
		if len(installedSoftware) > 3 {
			softwareList += fmt.Sprintf(" (+%d more)", len(installedSoftware)-3)
		}
	}

	// ==================== LOOT FILE GENERATION ====================

	// Add to self-hosted agents loot file if high risk
	if isHighRisk {
		m.mu.Lock()
		m.LootMap["agents-self-hosted"].Contents += fmt.Sprintf(
			"## Agent: %s (Pool: %s)\n"+
				"Agent ID: %d\n"+
				"Agent Type: %s\n"+
				"Status: %s | Enabled: %s\n"+
				"Version: %s\n"+
				"OS: %s\n"+
				"Last Job: %s (%s)\n"+
				"Installed Software: %s\n"+
				"Security Risks:\n",
			agentName, poolName, agentID, agentType, status, enabled, version, osInfo, lastJobDate, lastJobResult, softwareList,
		)
		for _, risk := range securityRisks {
			m.LootMap["agents-self-hosted"].Contents += fmt.Sprintf("  - %s\n", risk)
		}
		m.LootMap["agents-self-hosted"].Contents += "\nAttack Scenarios:\n"
		m.LootMap["agents-self-hosted"].Contents += "  1. Submit malicious pipeline to harvest credentials from agent\n"
		m.LootMap["agents-self-hosted"].Contents += "  2. Exploit agent for corporate network lateral movement\n"
		m.LootMap["agents-self-hosted"].Contents += "  3. Extract agent registration token for persistent access\n"
		m.LootMap["agents-self-hosted"].Contents += "  4. Use agent as pivot point for cloud resource access\n\n"
		m.LootMap["agents-self-hosted"].Contents += strings.Repeat("-", 80) + "\n\n"
		m.mu.Unlock()
	}

	// Add to outdated agents loot file
	if version != "unknown" && !strings.HasPrefix(version, "3.") && !strings.HasPrefix(version, "4.") {
		m.mu.Lock()
		m.LootMap["agents-outdated"].Contents += fmt.Sprintf(
			"Agent: %s (Pool: %s)\n"+
				"Version: %s\n"+
				"Recommendation: Update to latest version (3.x or 4.x)\n"+
				"CVE Check: https://github.com/microsoft/azure-pipelines-agent/security/advisories\n\n",
			agentName, poolName, version,
		)
		m.mu.Unlock()
	}

	// Add to job history loot file
	if lastJobDate != "Never" {
		m.mu.Lock()
		m.LootMap["agents-job-history"].Contents += fmt.Sprintf(
			"Agent: %s (Pool: %s)\n"+
				"Last Job: %s\n"+
				"Result: %s\n"+
				"Type: %s\n\n",
			agentName, poolName, lastJobDate, lastJobResult, agentType,
		)
		m.mu.Unlock()
	}

	// Generate security summary for this agent
	m.generateAgentSecuritySummary(agentName, poolName, agentType, status, enabled, version, osInfo, securityRisks)

	// Add to table data (will be collected in generateTableOutput)
	m.mu.Lock()
	m.CommandCounter.Total++
	m.CommandCounter.Executing++
	m.mu.Unlock()

	// Store agent data for table generation (using a temporary structure)
	agentData := map[string]interface{}{
		"poolName":        poolName,
		"agentName":       agentName,
		"agentType":       agentType,
		"status":          status,
		"enabled":         enabled,
		"version":         version,
		"osInfo":          osInfo,
		"lastJobDate":     lastJobDate,
		"lastJobResult":   lastJobResult,
		"softwareList":    softwareList,
		"securityRisks":   strings.Join(securityRisks, "; "),
		"isHighRisk":      isHighRisk,
		"capabilityCount": len(capabilities),
	}

	// Store in a module-level slice for table generation
	// (We'll need to add a field to the struct to collect these)
	m.mu.Lock()
	if m.LootMap["_tableData"] == (azinternal.AzureLoot{}) {
		m.LootMap["_tableData"] = azinternal.AzureLoot{
			Name:     "_internal",
			Contents: "[]", // JSON array
		}
	}

	// Append to JSON array
	var tableData []map[string]interface{}
	json.Unmarshal([]byte(m.LootMap["_tableData"].Contents), &tableData)
	tableData = append(tableData, agentData)
	jsonBytes, _ := json.Marshal(tableData)
	m.LootMap["_tableData"] = azinternal.AzureLoot{
		Name:     "_internal",
		Contents: string(jsonBytes),
	}
	m.mu.Unlock()
}

// enumeratePoolPermissions enumerates permissions for an agent pool
func (m *DevOpsAgentsModule) enumeratePoolPermissions(poolID int, poolName string) {
	// Note: Agent pool permissions require specific security namespace access
	// This is a simplified implementation - full implementation would require
	// querying the security namespace for agent pool permissions

	url := fmt.Sprintf("https://dev.azure.com/%s/_apis/securityroles/scopes/distributedtask.agentqueuerole/roleassignments/resources/%s_%d?api-version=7.1-preview.1",
		m.Organization, m.Organization, poolID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logrus.WithError(err).Debugf("Failed to create request for pool permissions")
		return
	}

	req.SetBasicAuth("", m.PAT)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logrus.WithError(err).Debugf("Failed to fetch pool permissions")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Permissions endpoint may not be accessible with all PAT scopes
		logrus.Debugf("Could not fetch permissions for pool %s (Status: %d)", poolName, resp.StatusCode)
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return
	}

	// Extract role assignments
	roleAssignments, ok := result["value"].([]interface{})
	if !ok || len(roleAssignments) == 0 {
		return
	}

	m.mu.Lock()
	m.LootMap["agents-permissions"].Contents += fmt.Sprintf("## Agent Pool: %s (ID: %d)\n", poolName, poolID)
	m.LootMap["agents-permissions"].Contents += fmt.Sprintf("Role Assignments (%d):\n", len(roleAssignments))

	for _, raItem := range roleAssignments {
		ra, ok := raItem.(map[string]interface{})
		if !ok {
			continue
		}

		identity := "Unknown"
		if id, ok := ra["identity"].(map[string]interface{}); ok {
			if displayName, ok := id["displayName"].(string); ok {
				identity = displayName
			}
		}

		role := "Unknown"
		if r, ok := ra["role"].(map[string]interface{}); ok {
			if roleName, ok := r["name"].(string); ok {
				role = roleName
			}
		}

		m.LootMap["agents-permissions"].Contents += fmt.Sprintf("  - %s: %s\n", identity, role)
	}
	m.LootMap["agents-permissions"].Contents += "\n"
	m.mu.Unlock()
}

// generateAgentSecuritySummary generates security summary for an agent
func (m *DevOpsAgentsModule) generateAgentSecuritySummary(agentName, poolName, agentType, status, enabled, version, osInfo string, securityRisks []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["agents-security-summary"].Contents += fmt.Sprintf(
		"## Agent: %s (Pool: %s)\n"+
			"Type: %s\n"+
			"Status: %s | Enabled: %s\n"+
			"Version: %s\n"+
			"OS: %s\n",
		agentName, poolName, agentType, status, enabled, version, osInfo,
	)

	if len(securityRisks) > 0 {
		m.LootMap["agents-security-summary"].Contents += "Security Risks:\n"
		for _, risk := range securityRisks {
			m.LootMap["agents-security-summary"].Contents += fmt.Sprintf("  ⚠ %s\n", risk)
		}
	} else {
		m.LootMap["agents-security-summary"].Contents += "Security Risks: None identified\n"
	}

	// Recommendations
	m.LootMap["agents-security-summary"].Contents += "Recommendations:\n"
	if agentType == "Self-hosted" {
		m.LootMap["agents-security-summary"].Contents += "  - Ensure agent has minimal privileges\n"
		m.LootMap["agents-security-summary"].Contents += "  - Use workload identity federation instead of service principals\n"
		m.LootMap["agents-security-summary"].Contents += "  - Isolate agent in dedicated network segment\n"
		m.LootMap["agents-security-summary"].Contents += "  - Enable audit logging for all pipeline executions\n"
		m.LootMap["agents-security-summary"].Contents += "  - Rotate agent registration tokens regularly\n"
	}
	if version != "unknown" && !strings.HasPrefix(version, "3.") && !strings.HasPrefix(version, "4.") {
		m.LootMap["agents-security-summary"].Contents += "  - Update agent to latest version immediately\n"
	}
	if status == "offline" && enabled == "Yes" {
		m.LootMap["agents-security-summary"].Contents += "  - Investigate why agent is offline (potential compromise)\n"
	}

	m.LootMap["agents-security-summary"].Contents += "\n" + strings.Repeat("-", 80) + "\n\n"
}

// generateTableOutput generates the table output for display
func (m *DevOpsAgentsModule) generateTableOutput() ([]string, [][]string) {
	header := []string{
		"Pool Name",
		"Agent Name",
		"Type",
		"Status",
		"Enabled",
		"Version",
		"OS",
		"Last Job",
		"Job Result",
		"Capabilities",
		"Security Risks",
	}

	var body [][]string

	// Retrieve table data from temporary storage
	var tableData []map[string]interface{}
	if loot, ok := m.LootMap["_tableData"]; ok {
		json.Unmarshal([]byte(loot.Contents), &tableData)
	}

	// Sort by high risk first, then by pool name
	sort.Slice(tableData, func(i, j int) bool {
		iRisk := tableData[i]["isHighRisk"].(bool)
		jRisk := tableData[j]["isHighRisk"].(bool)
		if iRisk != jRisk {
			return iRisk // High risk first
		}
		return tableData[i]["poolName"].(string) < tableData[j]["poolName"].(string)
	})

	// Convert to table rows
	for _, data := range tableData {
		row := []string{
			data["poolName"].(string),
			data["agentName"].(string),
			data["agentType"].(string),
			data["status"].(string),
			data["enabled"].(string),
			data["version"].(string),
			data["osInfo"].(string),
			data["lastJobDate"].(string),
			data["lastJobResult"].(string),
			fmt.Sprintf("%d", int(data["capabilityCount"].(float64))),
			data["securityRisks"].(string),
		}
		body = append(body, row)
	}

	return header, body
}

// printSummary prints a summary of findings
func (m *DevOpsAgentsModule) printSummary(totalAgents int) {
	fmt.Println("=== Azure DevOps Agents Enumeration Summary ===")
	fmt.Printf("Total Agents Enumerated: %d\n", totalAgents)

	// Count self-hosted agents from table data
	var tableData []map[string]interface{}
	if loot, ok := m.LootMap["_tableData"]; ok {
		json.Unmarshal([]byte(loot.Contents), &tableData)
	}

	selfHostedCount := 0
	offlineCount := 0
	outdatedCount := 0

	for _, data := range tableData {
		if data["isHighRisk"].(bool) {
			selfHostedCount++
		}
		if data["status"].(string) == "offline" {
			offlineCount++
		}
		if risks := data["securityRisks"].(string); strings.Contains(risks, "Outdated") {
			outdatedCount++
		}
	}

	fmt.Printf("Self-Hosted Agents: %d (HIGH RISK)\n", selfHostedCount)
	fmt.Printf("Offline Agents: %d\n", offlineCount)
	fmt.Printf("Outdated Agents: %d\n", outdatedCount)

	fmt.Println()
	fmt.Println("Security Recommendations:")
	if selfHostedCount > 0 {
		fmt.Println("  ⚠ Self-hosted agents detected - review loot/agents-self-hosted.txt for attack scenarios")
		fmt.Println("  ⚠ Ensure self-hosted agents use workload identity federation (not service principals)")
	}
	if outdatedCount > 0 {
		fmt.Println("  ⚠ Outdated agents detected - review loot/agents-outdated.txt and update immediately")
	}
	if offlineCount > 0 {
		fmt.Println("  ⚠ Offline agents detected - investigate for potential compromise")
	}

	fmt.Println()
	fmt.Println("Attack Surface:")
	fmt.Println("  - Submit malicious pipeline YAML to harvest secrets from self-hosted agents")
	fmt.Println("  - Exploit agent pool permissions to register rogue agents")
	fmt.Println("  - Use compromised agents as pivot points for lateral movement")
	fmt.Println("  - Extract agent registration tokens for persistent access")
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
