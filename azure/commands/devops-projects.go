package commands

import (
	"fmt"
	"os"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/spf13/cobra"
)

// ------------------------------
// Cobra command
// ------------------------------
var AzDevOpsProjectsCommand = &cobra.Command{
	Use:     "devops-projects",
	Aliases: []string{"devops-projs"},
	Short:   "Enumerate Azure DevOps Projects and Repos (fetch YAMLs)",
	Long: `
Enumerate Azure DevOps projects and their repositories.
Requires an organization (--org) and a Personal Access Token (PAT) set in $AZDO_PAT.
Generates table output and two loot files:
- project-commands: commands to enumerate projects and repos
- project-repos: downloaded repository YAML definitions`,
	Run: ListDevOpsProjects,
}

func init() {
	AzDevOpsProjectsCommand.Flags().StringVar(&azinternal.OrgFlag, "org", "", "Azure DevOps organization URL (required)")
	AzDevOpsProjectsCommand.Flags().StringVar(&azinternal.PatFlag, "pat", "", "Azure DevOps Personal Access Token (optional; falls back to $AZDO_PAT)")
}

// ------------------------------
// Module struct (simplified for DevOps)
// ------------------------------
type DevOpsProjectsModule struct {
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
	ProjectRows [][]string
	LootMap     map[string]*internal.LootFile
	mu          sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type ProjectsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ProjectsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ProjectsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListDevOpsProjects(cmd *cobra.Command, args []string) {
	logger := internal.NewLogger()

	// -------------------- Extract flags --------------------
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	if azinternal.OrgFlag == "" {
		logger.ErrorM("You must provide the organization URL via --org", globals.AZ_DEVOPS_PROJECTS_MODULE_NAME)
		cmd.Help()
		os.Exit(1)
	}

	// Get authentication token (PAT or Azure AD)
	pat, authMethod, err := azinternal.GetDevOpsAuthTokenSimple()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Authentication failed: %v", err), globals.AZ_DEVOPS_PROJECTS_MODULE_NAME)
		logger.InfoM("Set AZDO_PAT environment variable or run 'az login' to authenticate", globals.AZ_DEVOPS_PROJECTS_MODULE_NAME)
		cmd.Help()
		os.Exit(1)
	}

	// Log authentication method
	if authMethod == "Azure AD" {
		logger.InfoM("Using Azure AD authentication (az login)", globals.AZ_DEVOPS_PROJECTS_MODULE_NAME)
	}

	// -------------------- Get current user --------------------
	displayName, email, err := azinternal.FetchCurrentUser(pat)
	if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Failed to fetch current user: %v", err), globals.AZ_DEVOPS_PROJECTS_MODULE_NAME)
		displayName = "unknown"
		email = "unknown"
	}

	// -------------------- Initialize module --------------------
	module := &DevOpsProjectsModule{
		Organization:    azinternal.OrgFlag,
		PAT:             pat,
		DisplayName:     displayName,
		Email:           email,
		Verbosity:       verbosity,
		WrapTable:       wrap,
		OutputDirectory: outputDirectory,
		Format:          format,
		Goroutines:      5,
		ProjectRows:     [][]string{},
		LootMap: map[string]*internal.LootFile{
			"project-commands":            {Name: "project-commands", Contents: ""},
			"project-repos":               {Name: "project-repos", Contents: ""},
			"project-service-connections": {Name: "project-service-connections", Contents: ""},
			"project-variable-groups":     {Name: "project-variable-groups", Contents: ""},
			"project-policies":            {Name: "project-policies", Contents: ""},
			"project-secrets-detected":    {Name: "project-secrets-detected", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintDevOpsProjects(logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *DevOpsProjectsModule) PrintDevOpsProjects(logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Enumerating DevOps Projects for organization: %s", m.Organization), globals.AZ_DEVOPS_PROJECTS_MODULE_NAME)

	// Add Azure DevOps CLI extension install at the top
	m.LootMap["project-commands"].Contents += "az extension add --name azure-devops\n\n"

	// Fetch projects
	projects := azinternal.FetchProjects(m.Organization, m.PAT)
	if len(projects) == 0 {
		logger.InfoM("No projects found in organization", globals.AZ_DEVOPS_PROJECTS_MODULE_NAME)
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
func (m *DevOpsProjectsModule) processProject(proj map[string]interface{}, wg *sync.WaitGroup, logger internal.Logger) {
	defer wg.Done()

	projName := proj["name"].(string)
	projID := proj["id"].(string)
	visibility := proj["visibility"].(string)
	description := ""

	if d, ok := proj["description"].(string); ok {
		description = d
	}

	projectURL := ""
	if urlObj, ok := proj["_links"].(map[string]interface{}); ok {
		if webObj, ok := urlObj["web"].(map[string]interface{}); ok {
			if href, ok := webObj["href"].(string); ok {
				projectURL = href
			}
		}
	}

	// Add project commands
	m.mu.Lock()
	m.LootMap["project-commands"].Contents += fmt.Sprintf(
		"# Configure defaults for project %s\naz devops configure --defaults organization=%s project=%s\n\n",
		projName, m.Organization, projName,
	)
	m.mu.Unlock()

	// ==================== FETCH PROJECT-LEVEL RESOURCES ====================

	// Fetch service connections for this project
	serviceConnections := azinternal.FetchServiceConnections(m.Organization, m.PAT, projName)

	// Fetch variable groups for this project
	variableGroups := azinternal.FetchVariableGroups(m.Organization, m.PAT, projName)

	// Fetch repository policies for this project
	policies := azinternal.FetchRepositoryPolicies(m.Organization, m.PAT, projName)

	// Generate project-level loot
	m.generateProjectLoot(projName, projID, serviceConnections, variableGroups, policies)

	// Fetch and process repositories
	repos := azinternal.FetchRepos(m.Organization, m.PAT, projName)
	var repoWg sync.WaitGroup
	for _, r := range repos {
		repoWg.Add(1)
		go m.processRepo(projID, projName, visibility, projectURL, description, r, serviceConnections, variableGroups, policies, &repoWg, logger)
	}

	repoWg.Wait()
}

// ------------------------------
// Process single repository
// ------------------------------
func (m *DevOpsProjectsModule) processRepo(projID, projName, visibility, projectURL, description string, r map[string]interface{}, serviceConnections, variableGroups, policies []map[string]interface{}, wg *sync.WaitGroup, logger internal.Logger) {
	defer wg.Done()

	repoName := r["name"].(string)
	repoID := r["id"].(string)
	repoURL := r["webUrl"].(string)

	// Count project-level resources
	serviceConnectionCount := len(serviceConnections)
	variableGroupCount := len(variableGroups)
	policyCount := len(policies)

	// Fetch YAML files in repo and scan for secrets
	yamlFiles := azinternal.FetchRepoYAMLFiles(m.Organization, m.PAT, projName, repoName)
	yamlFileCount := len(yamlFiles)
	secretCount := 0

	// SECRET SCANNING
	for _, yf := range yamlFiles {
		// Scan YAML content for secrets
		secretMatches := azinternal.ScanYAMLContent(yf.Content, fmt.Sprintf("%s/%s [%s]", projName, repoName, yf.Path))
		secretCount += len(secretMatches)

		// Add YAML file to loot
		m.mu.Lock()
		m.LootMap["project-repos"].Contents += fmt.Sprintf(
			"## Project: %s, Repo: %s, File: %s\n%s\n\n",
			projName, repoName, yf.Path, yf.Content,
		)

		// If secrets detected, add to secrets loot file
		if len(secretMatches) > 0 {
			m.LootMap["project-secrets-detected"].Contents += fmt.Sprintf(
				"## Repository: %s/%s\n"+
					"File: %s\n"+
					"Secrets Detected: %d\n\n",
				projName, repoName, yf.Path, len(secretMatches),
			)
			m.LootMap["project-secrets-detected"].Contents += azinternal.FormatSecretMatchesForLoot(secretMatches)
		}
		m.mu.Unlock()
	}

	// Security recommendations
	securityRisks := []string{}
	if visibility == "public" {
		securityRisks = append(securityRisks, "Public repo")
	}
	if secretCount > 0 {
		securityRisks = append(securityRisks, fmt.Sprintf("%d secrets detected", secretCount))
	}
	if policyCount == 0 {
		securityRisks = append(securityRisks, "No branch policies")
	}

	securityRisksStr := "None"
	if len(securityRisks) > 0 {
		securityRisksStr = fmt.Sprintf("%s", securityRisks[0])
		if len(securityRisks) > 1 {
			securityRisksStr += fmt.Sprintf(" (+%d more)", len(securityRisks)-1)
		}
	}

	// Thread-safe append - table row
	m.mu.Lock()
	m.ProjectRows = append(m.ProjectRows, []string{
		projID,
		projName,
		visibility,
		projectURL,
		description,
		repoName,
		repoID,
		repoURL,
		// NEW COLUMNS
		fmt.Sprintf("%d", serviceConnectionCount),
		fmt.Sprintf("%d", variableGroupCount),
		fmt.Sprintf("%d", yamlFileCount),
		fmt.Sprintf("%d", secretCount),
		fmt.Sprintf("%d", policyCount),
		securityRisksStr,
	})

	// Loot: repo commands
	m.LootMap["project-repos"].Contents += fmt.Sprintf(
		"# Project: %s, Repo: %s\naz repos show --repository %s --project %s --org %s\n\n",
		projName, repoName, repoName, projName, m.Organization,
	)
	m.mu.Unlock()
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *DevOpsProjectsModule) writeOutput(logger internal.Logger) {
	if len(m.ProjectRows) == 0 {
		logger.InfoM("No DevOps Projects found", globals.AZ_DEVOPS_PROJECTS_MODULE_NAME)
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
	output := ProjectsOutput{
		Table: []internal.TableFile{{
			Name: "projects",
			Header: []string{
				"Project ID",
				"Project Name",
				"Visibility",
				"URL",
				"Description",
				"Repository Name",
				"Repository ID",
				"Repository URL",
				// NEW COLUMNS
				"Service Connections",
				"Variable Groups",
				"YAML Files",
				"Secrets Detected",
				"Branch Policies",
				"Security Risks",
			},
			Body: m.ProjectRows,
		}},
		Loot: loot,
	}

	// Write output
	if err := internal.HandleOutput(
		"AzureDevOps",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		m.Organization,
		m.Email,
		m.Organization,
		output,
	); err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_DEVOPS_PROJECTS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d DevOps Project/Repo(s) for organization: %s", len(m.ProjectRows), m.Organization), globals.AZ_DEVOPS_PROJECTS_MODULE_NAME)
}

// ------------------------------
// Generate project-level loot
// ------------------------------
func (m *DevOpsProjectsModule) generateProjectLoot(projName, projID string, serviceConnections, variableGroups, policies []map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// ==================== SERVICE CONNECTIONS LOOT ====================
	if len(serviceConnections) > 0 {
		m.LootMap["project-service-connections"].Contents += fmt.Sprintf("## Project: %s (ID: %s)\n", projName, projID)
		m.LootMap["project-service-connections"].Contents += fmt.Sprintf("Service Connection Count: %d\n\n", len(serviceConnections))

		for _, conn := range serviceConnections {
			connName := "unknown"
			if name, ok := conn["name"].(string); ok {
				connName = name
			}

			connType := "unknown"
			if ctype, ok := conn["type"].(string); ok {
				connType = ctype
			}

			connID := "unknown"
			if id, ok := conn["id"].(string); ok {
				connID = id
			}

			m.LootMap["project-service-connections"].Contents += fmt.Sprintf("### Service Connection: %s\n", connName)
			m.LootMap["project-service-connections"].Contents += fmt.Sprintf("Type: %s\n", connType)
			m.LootMap["project-service-connections"].Contents += fmt.Sprintf("ID: %s\n", connID)

			// Check for Azure service principal details
			if auth, ok := conn["authorization"].(map[string]interface{}); ok {
				if scheme, ok := auth["scheme"].(string); ok {
					m.LootMap["project-service-connections"].Contents += fmt.Sprintf("Auth Scheme: %s\n", scheme)

					if scheme == "ServicePrincipal" {
						if params, ok := auth["parameters"].(map[string]interface{}); ok {
							if tenantID, ok := params["tenantid"].(string); ok {
								m.LootMap["project-service-connections"].Contents += fmt.Sprintf("  Tenant ID: %s\n", tenantID)
							}
							if spID, ok := params["serviceprincipalid"].(string); ok {
								m.LootMap["project-service-connections"].Contents += fmt.Sprintf("  Service Principal ID: %s\n", spID)
							}
							if subID, ok := params["subscriptionid"].(string); ok {
								m.LootMap["project-service-connections"].Contents += fmt.Sprintf("  Subscription ID: %s\n", subID)
							}
						}
						m.LootMap["project-service-connections"].Contents += "  ⚠️ SECURITY RISK: Service principal with subscription access\n"
					}
				}
			}

			m.LootMap["project-service-connections"].Contents += "\n"
		}
		m.LootMap["project-service-connections"].Contents += "---\n\n"
	}

	// ==================== VARIABLE GROUPS LOOT ====================
	if len(variableGroups) > 0 {
		m.LootMap["project-variable-groups"].Contents += fmt.Sprintf("## Project: %s (ID: %s)\n", projName, projID)
		m.LootMap["project-variable-groups"].Contents += fmt.Sprintf("Variable Group Count: %d\n\n", len(variableGroups))

		for _, group := range variableGroups {
			groupName := "unknown"
			if name, ok := group["name"].(string); ok {
				groupName = name
			}

			groupID := "unknown"
			if id, ok := group["id"].(float64); ok {
				groupID = fmt.Sprintf("%.0f", id)
			}

			m.LootMap["project-variable-groups"].Contents += fmt.Sprintf("### Variable Group: %s (ID: %s)\n", groupName, groupID)

			if vars, ok := group["variables"].(map[string]interface{}); ok {
				m.LootMap["project-variable-groups"].Contents += fmt.Sprintf("Variables: %d\n", len(vars))
				for varName, varData := range vars {
					if varMap, ok := varData.(map[string]interface{}); ok {
						isSecret := false
						if secret, ok := varMap["isSecret"].(bool); ok && secret {
							isSecret = true
						}

						if isSecret {
							m.LootMap["project-variable-groups"].Contents += fmt.Sprintf("  - %s = [MASKED - SECRET]\n", varName)
						} else if val, ok := varMap["value"].(string); ok {
							m.LootMap["project-variable-groups"].Contents += fmt.Sprintf("  - %s = %s\n", varName, val)

							// Scan for secrets in variable values
							secretMatches := azinternal.ScanScriptContent(val, fmt.Sprintf("%s/%s [%s]", projName, groupName, varName), "variable-value")
							if len(secretMatches) > 0 {
								m.LootMap["project-variable-groups"].Contents += "    ⚠️ SECRET DETECTED IN VALUE\n"
							}
						}
					}
				}
			}

			m.LootMap["project-variable-groups"].Contents += "\n"
		}
		m.LootMap["project-variable-groups"].Contents += "---\n\n"
	}

	// ==================== POLICIES LOOT ====================
	if len(policies) > 0 {
		m.LootMap["project-policies"].Contents += fmt.Sprintf("## Project: %s (ID: %s)\n", projName, projID)
		m.LootMap["project-policies"].Contents += fmt.Sprintf("Policy Count: %d\n\n", len(policies))

		for _, policy := range policies {
			policyID := "unknown"
			if id, ok := policy["id"].(float64); ok {
				policyID = fmt.Sprintf("%.0f", id)
			}

			policyType := "unknown"
			if ptype, ok := policy["type"].(map[string]interface{}); ok {
				if displayName, ok := ptype["displayName"].(string); ok {
					policyType = displayName
				}
			}

			isEnabled := "false"
			if enabled, ok := policy["isEnabled"].(bool); ok && enabled {
				isEnabled = "true"
			}

			isBlocking := "false"
			if blocking, ok := policy["isBlocking"].(bool); ok && blocking {
				isBlocking = "true"
			}

			m.LootMap["project-policies"].Contents += fmt.Sprintf("### Policy: %s (ID: %s)\n", policyType, policyID)
			m.LootMap["project-policies"].Contents += fmt.Sprintf("Enabled: %s\n", isEnabled)
			m.LootMap["project-policies"].Contents += fmt.Sprintf("Blocking: %s\n\n", isBlocking)

			if isEnabled == "false" {
				m.LootMap["project-policies"].Contents += "⚠️ WARNING: Policy is disabled\n\n"
			} else if isBlocking == "false" {
				m.LootMap["project-policies"].Contents += "⚠️ WARNING: Policy is not blocking (can be bypassed)\n\n"
			}
		}
		m.LootMap["project-policies"].Contents += "---\n\n"
	} else {
		// No policies = security risk
		m.LootMap["project-policies"].Contents += fmt.Sprintf("## Project: %s (ID: %s)\n", projName, projID)
		m.LootMap["project-policies"].Contents += "Policy Count: 0\n\n"
		m.LootMap["project-policies"].Contents += "⚠️ SECURITY RISK: No branch protection policies configured\n"
		m.LootMap["project-policies"].Contents += "Recommendations:\n"
		m.LootMap["project-policies"].Contents += "- Enable branch protection on main/master branches\n"
		m.LootMap["project-policies"].Contents += "- Require pull request reviews before merge\n"
		m.LootMap["project-policies"].Contents += "- Enable build validation policies\n\n"
		m.LootMap["project-policies"].Contents += "---\n\n"
	}
}
