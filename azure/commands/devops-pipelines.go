package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
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
var AzDevOpsPipelinesCommand = &cobra.Command{
	Use:     "devops-pipelines",
	Aliases: []string{"devops-pl"},
	Short:   "Enumerate Azure DevOps Pipelines with security analysis (variables, service connections, secrets)",
	Long: `
Enumerate Azure DevOps pipelines with comprehensive security analysis.
Requires an organization (--org) and a Personal Access Token (PAT) set in $AZDO_PAT.

Generates table output with 13 columns and 7 loot files:
- pipeline-commands: CLI commands to enumerate pipelines
- pipeline-templates: Downloaded YAML definitions
- pipeline-variables: Pipeline variables with values (SECURITY-SENSITIVE)
- pipeline-service-connections: Service connections (Azure SP credentials)
- pipeline-variable-groups: Shared variable groups
- pipeline-inline-scripts: Extracted inline script content
- pipeline-secure-files: Secure files (certificates, SSH keys)
- pipeline-secrets-detected: Detected secrets with remediation advice`,
	Run: ListDevOpsPipelines,
}

func init() {
	AzDevOpsPipelinesCommand.Flags().StringVar(&azinternal.OrgFlag, "org", "", "Azure DevOps organization URL (required)")
	AzDevOpsPipelinesCommand.Flags().StringVar(&azinternal.PatFlag, "pat", "", "Azure DevOps Personal Access Token (required)")
}

// ------------------------------
// Module struct (simplified for DevOps)
// ------------------------------
type DevOpsPipelinesModule struct {
	// DevOps context
	Organization string
	PAT          string

	// User context
	DisplayName string
	Email       string

	// Configuration
	Verbosity       int
	WrapTable       bool
	OutputDirectory string
	Format          string

	// AWS-style progress tracking
	CommandCounter internal.CommandCounter
	Goroutines     int

	// Data collection
	PipelineRows [][]string
	LootMap      map[string]*internal.LootFile
	mu           sync.Mutex

	// Cache for project-level resources (fetched once per project)
	projectServiceConnections map[string][]map[string]interface{} // projName -> connections
	projectVariableGroups     map[string][]map[string]interface{} // projName -> groups
	projectSecureFiles        map[string][]map[string]interface{} // projName -> files
	cacheMu                   sync.RWMutex
}

// ------------------------------
// Output struct
// ------------------------------
type PipelinesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PipelinesOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PipelinesOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListDevOpsPipelines(cmd *cobra.Command, args []string) {
	logger := internal.NewLogger()

	// -------------------- Extract flags --------------------
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	if azinternal.OrgFlag == "" {
		logger.ErrorM("You must provide the organization URL via --org", globals.AZ_DEVOPS_PIPELINES_MODULE_NAME)
		cmd.Help()
		os.Exit(1)
	}

	// Get authentication token (PAT or Azure AD)
	pat, authMethod, err := azinternal.GetDevOpsAuthTokenSimple()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Authentication failed: %v", err), globals.AZ_DEVOPS_PIPELINES_MODULE_NAME)
		logger.InfoM("Set AZDO_PAT environment variable or run 'az login' to authenticate", globals.AZ_DEVOPS_PIPELINES_MODULE_NAME)
		cmd.Help()
		os.Exit(1)
	}

	// Log authentication method
	if authMethod == "Azure AD" {
		logger.InfoM("Using Azure AD authentication (az login)", globals.AZ_DEVOPS_PIPELINES_MODULE_NAME)
	}

	// -------------------- Get current user --------------------
	displayName, email, err := azinternal.FetchCurrentUser(pat)
	if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Failed to fetch current user: %v", err), globals.AZ_DEVOPS_PIPELINES_MODULE_NAME)
		displayName = "unknown"
		email = "unknown"
	}

	// -------------------- Initialize module --------------------
	module := &DevOpsPipelinesModule{
		Organization:              azinternal.OrgFlag,
		PAT:                       pat,
		DisplayName:               displayName,
		Email:                     email,
		Verbosity:                 verbosity,
		WrapTable:                 wrap,
		OutputDirectory:           outputDirectory,
		Format:                    format,
		Goroutines:                5,
		PipelineRows:              [][]string{},
		projectServiceConnections: make(map[string][]map[string]interface{}),
		projectVariableGroups:     make(map[string][]map[string]interface{}),
		projectSecureFiles:        make(map[string][]map[string]interface{}),
		LootMap: map[string]*internal.LootFile{
			"pipeline-commands":            {Name: "pipeline-commands", Contents: ""},
			"pipeline-templates":           {Name: "pipeline-templates", Contents: ""},
			"pipeline-variables":           {Name: "pipeline-variables", Contents: ""},
			"pipeline-service-connections": {Name: "pipeline-service-connections", Contents: ""},
			"pipeline-variable-groups":     {Name: "pipeline-variable-groups", Contents: ""},
			"pipeline-inline-scripts":      {Name: "pipeline-inline-scripts", Contents: ""},
			"pipeline-secure-files":        {Name: "pipeline-secure-files", Contents: ""},
			"pipeline-secrets-detected":    {Name: "pipeline-secrets-detected", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintDevOpsPipelines(logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *DevOpsPipelinesModule) PrintDevOpsPipelines(logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Enumerating DevOps Pipelines for organization: %s", m.Organization), globals.AZ_DEVOPS_PIPELINES_MODULE_NAME)

	// Add Azure DevOps CLI extension install at the top
	m.LootMap["pipeline-commands"].Contents += "# Install Azure DevOps CLI extension (required)\naz extension add --name azure-devops\n\n"

	// Fetch projects
	projects := azinternal.FetchProjects(m.Organization, m.PAT)
	if len(projects) == 0 {
		logger.InfoM("No projects found in organization", globals.AZ_DEVOPS_PIPELINES_MODULE_NAME)
		return
	}

	// Process projects concurrently
	var wg sync.WaitGroup
	for _, proj := range projects {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.processProject(proj, &wg, logger)
	}

	wg.Wait()

	// Generate and write output
	m.writeOutput(logger)
}

// ------------------------------
// Process single project
// ------------------------------
func (m *DevOpsPipelinesModule) processProject(proj map[string]interface{}, wg *sync.WaitGroup, logger internal.Logger) {
	defer wg.Done()

	projName := proj["name"].(string)
	projID := proj["id"].(string)

	// Add project commands
	m.mu.Lock()
	m.LootMap["pipeline-commands"].Contents += fmt.Sprintf(
		"# Configure defaults for project %s\naz devops configure --defaults organization=%s project=%s\n\n",
		projName, m.Organization, projName,
	)
	m.mu.Unlock()

	// ==================== FETCH PROJECT-LEVEL RESOURCES (ONCE PER PROJECT) ====================
	// Service Connections
	serviceConnections := azinternal.FetchServiceConnections(m.Organization, m.PAT, projName)
	m.cacheMu.Lock()
	m.projectServiceConnections[projName] = serviceConnections
	m.cacheMu.Unlock()

	// Variable Groups
	variableGroups := azinternal.FetchVariableGroups(m.Organization, m.PAT, projName)
	m.cacheMu.Lock()
	m.projectVariableGroups[projName] = variableGroups
	m.cacheMu.Unlock()

	// Secure Files
	secureFiles := azinternal.FetchSecureFiles(m.Organization, m.PAT, projName)
	m.cacheMu.Lock()
	m.projectSecureFiles[projName] = secureFiles
	m.cacheMu.Unlock()

	// Generate loot for project-level resources
	m.generateProjectLoot(projName, serviceConnections, variableGroups, secureFiles)

	// Fetch and process pipelines
	pipelines := azinternal.FetchPipelines(m.Organization, m.PAT, projName)
	var pipelineWg sync.WaitGroup
	for _, pl := range pipelines {
		pipelineWg.Add(1)
		go m.processPipeline(projID, projName, pl, &pipelineWg, logger)
	}

	pipelineWg.Wait()
}

// ------------------------------
// Process single pipeline
// ------------------------------
func (m *DevOpsPipelinesModule) processPipeline(projID, projName string, pl map[string]interface{}, wg *sync.WaitGroup, logger internal.Logger) {
	defer wg.Done()

	pipeID := int(pl["id"].(float64))
	pipeName := pl["name"].(string)
	repo := ""
	defaultBranch := ""

	if configuration, ok := pl["configuration"].(map[string]interface{}); ok {
		if cfgType, ok := configuration["type"].(string); ok && cfgType == "yaml" {
			if repoObj, ok := configuration["repository"].(map[string]interface{}); ok {
				if r, ok := repoObj["name"].(string); ok {
					repo = r
				}
				if b, ok := repoObj["defaultBranch"].(string); ok {
					defaultBranch = b
				}
			}
		}
	}

	// ==================== FETCH PIPELINE DEFINITION (FULL) ====================
	pipelineDef := azinternal.FetchPipelineDefinition(m.Organization, m.PAT, projName, pipeID)

	// Extract pipeline variables
	variableCount := 0
	variables := []map[string]interface{}{}
	if pipelineDef != nil {
		if vars, ok := pipelineDef["variables"].(map[string]interface{}); ok {
			variableCount = len(vars)
			for varName, varValue := range vars {
				variables = append(variables, map[string]interface{}{
					"name":  varName,
					"value": varValue,
				})
			}
		}
	}

	// Extract variable groups referenced in pipeline
	varGroupsReferenced := []string{}
	if pipelineDef != nil {
		if varGroups, ok := pipelineDef["variableGroups"].([]interface{}); ok {
			for _, vg := range varGroups {
				if vgMap, ok := vg.(map[string]interface{}); ok {
					if name, ok := vgMap["name"].(string); ok {
						varGroupsReferenced = append(varGroupsReferenced, name)
					}
				}
			}
		}
	}
	varGroupsStr := "None"
	if len(varGroupsReferenced) > 0 {
		varGroupsStr = strings.Join(varGroupsReferenced, ", ")
	}

	// Extract service connections used in pipeline
	serviceConnectionsUsed := extractServiceConnections(pipelineDef)
	serviceConnectionsStr := "None"
	if len(serviceConnectionsUsed) > 0 {
		serviceConnectionsStr = strings.Join(serviceConnectionsUsed, ", ")
	}

	// ==================== FETCH PIPELINE YAML ====================
	yamlContent := azinternal.FetchPipelineYAML(m.Organization, m.PAT, projName, pipeID)

	// Extract inline scripts from YAML
	inlineScriptCount := 0
	inlineScripts := []string{}
	if yamlContent != "" {
		inlineScripts = extractInlineScripts(yamlContent)
		inlineScriptCount = len(inlineScripts)
	}

	// ==================== SECRET SCANNING ====================
	var secretMatches []azinternal.SecretMatch

	// Scan YAML content
	if yamlContent != "" {
		yamlSecrets := azinternal.ScanYAMLContent(yamlContent, fmt.Sprintf("%s/%s", projName, pipeName))
		secretMatches = append(secretMatches, yamlSecrets...)
	}

	// Scan inline scripts
	for i, script := range inlineScripts {
		scriptSecrets := azinternal.ScanScriptContent(script, fmt.Sprintf("%s/%s [inline-script-%d]", projName, pipeName, i+1), "inline-script")
		secretMatches = append(secretMatches, scriptSecrets...)
	}

	// ==================== FETCH LAST RUN ====================
	lastRunDate := "Never"
	lastRunStatus := "N/A"
	runs := azinternal.FetchPipelineRuns(m.Organization, m.PAT, projName, pipeID, 1)
	if len(runs) > 0 {
		run := runs[0]
		if finishTime, ok := run["finishTime"].(string); ok {
			lastRunDate = finishTime
		}
		if status, ok := run["status"].(string); ok {
			lastRunStatus = status
		}
		if result, ok := run["result"].(string); ok {
			lastRunStatus = fmt.Sprintf("%s (%s)", lastRunStatus, result)
		}
	}

	// ==================== APPROVAL REQUIRED ====================
	approvalRequired := "Unknown"
	// Note: Approval configuration is complex in Azure DevOps (environments, checks, approvals)
	// For now, mark as "Unknown" unless we detect environment deployment
	if yamlContent != "" && strings.Contains(yamlContent, "environment:") {
		approvalRequired = "Possibly (Uses Environments)"
	} else {
		approvalRequired = "No"
	}

	// ==================== SECURE FILES COUNT ====================
	// Get from cached project secure files
	m.cacheMu.RLock()
	secureFilesCount := len(m.projectSecureFiles[projName])
	m.cacheMu.RUnlock()
	secureFilesStr := fmt.Sprintf("%d file(s)", secureFilesCount)

	// ==================== BUILD TABLE ROW ====================
	m.mu.Lock()
	m.PipelineRows = append(m.PipelineRows, []string{
		projName,
		pipeName,
		fmt.Sprintf("%d", pipeID),
		repo,
		defaultBranch,
		fmt.Sprintf("%d", variableCount),     // NEW: Variable Count
		varGroupsStr,                         // NEW: Variable Groups
		serviceConnectionsStr,                // NEW: Service Connections
		fmt.Sprintf("%d", inlineScriptCount), // NEW: Inline Script Count
		secureFilesStr,                       // NEW: Secure Files Count
		approvalRequired,                     // NEW: Approval Required
		lastRunDate,                          // NEW: Last Run Date
		lastRunStatus,                        // NEW: Last Run Status
	})

	// ==================== GENERATE LOOT ====================

	// Loot: pipeline commands
	m.LootMap["pipeline-commands"].Contents += fmt.Sprintf(
		"# Pipeline: %s (%s)\n# List pipeline YAML:\naz pipelines show --id %d --project %s --org %s --query configuration\n\n",
		pipeName, projName, pipeID, projName, m.Organization,
	)

	// Loot: pipeline templates (YAML)
	if yamlContent != "" {
		m.LootMap["pipeline-templates"].Contents += fmt.Sprintf(
			"## Project: %s, Pipeline: %s\n%s\n\n",
			projName, pipeName, yamlContent,
		)
	}

	// Loot: pipeline variables
	if len(variables) > 0 {
		m.LootMap["pipeline-variables"].Contents += fmt.Sprintf(
			"\n"+strings.Repeat("=", 80)+"\n"+
				"PROJECT: %s, PIPELINE: %s (ID: %d)\n"+
				strings.Repeat("=", 80)+"\n\n",
			projName, pipeName, pipeID,
		)
		for _, v := range variables {
			varName := v["name"]
			varValue := v["value"]

			// Check if it's a secret variable (value may be masked)
			isSecret := false
			if valMap, ok := varValue.(map[string]interface{}); ok {
				if isSecretVal, ok := valMap["isSecret"].(bool); ok && isSecretVal {
					isSecret = true
				}
			}

			secretIndicator := ""
			if isSecret {
				secretIndicator = " [SECRET]"
			}

			m.LootMap["pipeline-variables"].Contents += fmt.Sprintf(
				"Variable: %s%s\nValue: %v\n\n",
				varName, secretIndicator, varValue,
			)
		}
	}

	// Loot: inline scripts
	if len(inlineScripts) > 0 {
		m.LootMap["pipeline-inline-scripts"].Contents += fmt.Sprintf(
			"\n"+strings.Repeat("=", 80)+"\n"+
				"PROJECT: %s, PIPELINE: %s (ID: %d)\n"+
				strings.Repeat("=", 80)+"\n\n",
			projName, pipeName, pipeID,
		)
		for i, script := range inlineScripts {
			m.LootMap["pipeline-inline-scripts"].Contents += fmt.Sprintf(
				"## Inline Script %d\n"+
					"```\n%s\n```\n\n",
				i+1, script,
			)
		}
	}

	// Loot: secrets detected
	if len(secretMatches) > 0 {
		m.LootMap["pipeline-secrets-detected"].Contents += fmt.Sprintf(
			"\n"+strings.Repeat("=", 80)+"\n"+
				"PIPELINE: %s/%s - %d SECRET(S) DETECTED\n"+
				strings.Repeat("=", 80)+"\n",
			projName, pipeName, len(secretMatches),
		)
		m.LootMap["pipeline-secrets-detected"].Contents += azinternal.FormatSecretMatchesForLoot(secretMatches)
	}

	m.mu.Unlock()
}

// ------------------------------
// Generate project-level loot
// ------------------------------
func (m *DevOpsPipelinesModule) generateProjectLoot(projName string, serviceConnections, variableGroups, secureFiles []map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// ==================== SERVICE CONNECTIONS ====================
	if len(serviceConnections) > 0 {
		m.LootMap["pipeline-service-connections"].Contents += fmt.Sprintf(
			"\n"+strings.Repeat("=", 80)+"\n"+
				"PROJECT: %s - SERVICE CONNECTIONS\n"+
				strings.Repeat("=", 80)+"\n\n",
			projName,
		)

		for _, conn := range serviceConnections {
			connName := "Unknown"
			if name, ok := conn["name"].(string); ok {
				connName = name
			}

			connType := "Unknown"
			if cType, ok := conn["type"].(string); ok {
				connType = cType
			}

			connID := "Unknown"
			if id, ok := conn["id"].(string); ok {
				connID = id
			}

			// Extract authorization details (if available - may be masked)
			authScheme := "Unknown"
			if auth, ok := conn["authorization"].(map[string]interface{}); ok {
				if scheme, ok := auth["scheme"].(string); ok {
					authScheme = scheme
				}

				// For Azure service principals
				if scheme, ok := auth["scheme"].(string); ok && scheme == "ServicePrincipal" {
					if params, ok := auth["parameters"].(map[string]interface{}); ok {
						m.LootMap["pipeline-service-connections"].Contents += fmt.Sprintf(
							"## Service Connection: %s\n"+
								"Type: %s\n"+
								"ID: %s\n"+
								"Auth Scheme: %s\n"+
								"Service Principal Details:\n",
							connName, connType, connID, authScheme,
						)

						if tenantID, ok := params["tenantid"].(string); ok {
							m.LootMap["pipeline-service-connections"].Contents += fmt.Sprintf("  Tenant ID: %s\n", tenantID)
						}
						if servicePrincipalID, ok := params["serviceprincipalid"].(string); ok {
							m.LootMap["pipeline-service-connections"].Contents += fmt.Sprintf("  Service Principal ID: %s\n", servicePrincipalID)
						}
						if authenticationType, ok := params["authenticationType"].(string); ok {
							m.LootMap["pipeline-service-connections"].Contents += fmt.Sprintf("  Authentication Type: %s\n", authenticationType)
						}

						m.LootMap["pipeline-service-connections"].Contents += "\nNOTE: Service principal secret is not accessible via API (masked).\n"
						m.LootMap["pipeline-service-connections"].Contents += "If you have appropriate permissions, you can view the secret in Azure DevOps UI:\n"
						m.LootMap["pipeline-service-connections"].Contents += fmt.Sprintf("  %s/%s/_settings/adminservices?resourceId=%s\n\n", m.Organization, projName, connID)
					}
				} else {
					m.LootMap["pipeline-service-connections"].Contents += fmt.Sprintf(
						"## Service Connection: %s\n"+
							"Type: %s\n"+
							"ID: %s\n"+
							"Auth Scheme: %s\n\n",
						connName, connType, connID, authScheme,
					)
				}
			}
		}
	}

	// ==================== VARIABLE GROUPS ====================
	if len(variableGroups) > 0 {
		m.LootMap["pipeline-variable-groups"].Contents += fmt.Sprintf(
			"\n"+strings.Repeat("=", 80)+"\n"+
				"PROJECT: %s - VARIABLE GROUPS\n"+
				strings.Repeat("=", 80)+"\n\n",
			projName,
		)

		for _, group := range variableGroups {
			groupName := "Unknown"
			if name, ok := group["name"].(string); ok {
				groupName = name
			}

			groupID := "Unknown"
			if id, ok := group["id"].(float64); ok {
				groupID = fmt.Sprintf("%.0f", id)
			}

			m.LootMap["pipeline-variable-groups"].Contents += fmt.Sprintf(
				"## Variable Group: %s (ID: %s)\n",
				groupName, groupID,
			)

			// Extract variables from group
			if vars, ok := group["variables"].(map[string]interface{}); ok {
				m.LootMap["pipeline-variable-groups"].Contents += "Variables:\n"
				for varName, varValue := range vars {
					isSecret := false
					actualValue := varValue

					// Check if it's a map with value and isSecret fields
					if valMap, ok := varValue.(map[string]interface{}); ok {
						if val, ok := valMap["value"].(string); ok {
							actualValue = val
						}
						if isSecretVal, ok := valMap["isSecret"].(bool); ok && isSecretVal {
							isSecret = true
							actualValue = "[SECRET - MASKED]"
						}
					}

					secretIndicator := ""
					if isSecret {
						secretIndicator = " [SECRET]"
					}

					m.LootMap["pipeline-variable-groups"].Contents += fmt.Sprintf(
						"  %s%s: %v\n",
						varName, secretIndicator, actualValue,
					)
				}
			}

			m.LootMap["pipeline-variable-groups"].Contents += "\n"
		}
	}

	// ==================== SECURE FILES ====================
	if len(secureFiles) > 0 {
		m.LootMap["pipeline-secure-files"].Contents += fmt.Sprintf(
			"\n"+strings.Repeat("=", 80)+"\n"+
				"PROJECT: %s - SECURE FILES\n"+
				strings.Repeat("=", 80)+"\n\n",
			projName,
		)

		for _, file := range secureFiles {
			fileName := "Unknown"
			if name, ok := file["name"].(string); ok {
				fileName = name
			}

			fileID := "Unknown"
			if id, ok := file["id"].(string); ok {
				fileID = id
			}

			m.LootMap["pipeline-secure-files"].Contents += fmt.Sprintf(
				"## Secure File: %s\n"+
					"ID: %s\n"+
					"Type: Certificate/SSH Key/Config File\n\n",
				fileName, fileID,
			)

			m.LootMap["pipeline-secure-files"].Contents += "NOTE: Secure file content is not accessible via API (encrypted).\n"
			m.LootMap["pipeline-secure-files"].Contents += "If you have appropriate permissions, download using:\n"
			m.LootMap["pipeline-secure-files"].Contents += fmt.Sprintf("  az pipelines secure-file download --id %s --project %s --org %s\n\n", fileID, projName, m.Organization)
		}
	}
}

// ------------------------------
// Helper: Extract service connections from pipeline definition
// ------------------------------
func extractServiceConnections(pipelineDef map[string]interface{}) []string {
	connections := []string{}

	// Convert to JSON string for regex searching (simple approach)
	jsonBytes, err := json.Marshal(pipelineDef)
	if err != nil {
		return connections
	}
	jsonStr := string(jsonBytes)

	// Look for service connection references
	// Common patterns: "serviceConnection": "name" or "azureSubscription": "name"
	patterns := []string{
		`"serviceConnection"\s*:\s*"([^"]+)"`,
		`"azureSubscription"\s*:\s*"([^"]+)"`,
		`"connectedServiceName"\s*:\s*"([^"]+)"`,
	}

	connectionSet := make(map[string]bool)
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(jsonStr, -1)
		for _, match := range matches {
			if len(match) > 1 {
				connectionSet[match[1]] = true
			}
		}
	}

	for conn := range connectionSet {
		connections = append(connections, conn)
	}

	return connections
}

// ------------------------------
// Helper: Extract inline scripts from YAML
// ------------------------------
func extractInlineScripts(yamlContent string) []string {
	scripts := []string{}

	// Look for inline scripts in YAML
	// Pattern 1: script: | or script: >
	scriptPattern1 := regexp.MustCompile(`(?m)^[\s-]*(?:inline)?[Ss]cript\s*:\s*[|>][\s]*\n((?:[\s]+.+\n)+)`)
	matches1 := scriptPattern1.FindAllStringSubmatch(yamlContent, -1)
	for _, match := range matches1 {
		if len(match) > 1 {
			scripts = append(scripts, strings.TrimSpace(match[1]))
		}
	}

	// Pattern 2: script: 'single line'
	scriptPattern2 := regexp.MustCompile(`(?m)^[\s-]*(?:inline)?[Ss]cript\s*:\s*['"](.+)['"]`)
	matches2 := scriptPattern2.FindAllStringSubmatch(yamlContent, -1)
	for _, match := range matches2 {
		if len(match) > 1 {
			scripts = append(scripts, strings.TrimSpace(match[1]))
		}
	}

	return scripts
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *DevOpsPipelinesModule) writeOutput(logger internal.Logger) {
	if len(m.PipelineRows) == 0 {
		logger.InfoM("No DevOps Pipelines found", globals.AZ_DEVOPS_PIPELINES_MODULE_NAME)
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
	output := PipelinesOutput{
		Table: []internal.TableFile{{
			Name: "pipelines",
			Header: []string{
				"Project Name",
				"Pipeline Name",
				"Pipeline ID",
				"Repository",
				"Default Branch",
				"Variable Count",      // NEW
				"Variable Groups",     // NEW
				"Service Connections", // NEW
				"Inline Script Count", // NEW
				"Secure Files Count",  // NEW
				"Approval Required",   // NEW
				"Last Run Date",       // NEW
				"Last Run Status",     // NEW
			},
			Body: m.PipelineRows,
		}},
		Loot: loot,
	}

	// Determine scope for output (organization-level for DevOps)
	scopeType := "organization"
	scopeIDs := []string{m.Organization}
	scopeNames := []string{m.Organization}

	// Write output using HandleOutputSmart
	if err := internal.HandleOutputSmart(
		"AzureDevOps",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		scopeType,
		scopeIDs,
		scopeNames,
		m.Email,
		output,
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_DEVOPS_PIPELINES_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d DevOps Pipeline(s) for organization: %s", len(m.PipelineRows), m.Organization), globals.AZ_DEVOPS_PIPELINES_MODULE_NAME)
}
