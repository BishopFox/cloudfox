package commands

import (
	"fmt"
	"os"
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
var AzDevOpsSecurityCommand = &cobra.Command{
	Use:     "devops-security",
	Aliases: []string{"devops-sec"},
	Short:   "Comprehensive Azure DevOps security posture analysis",
	Long: `
Comprehensive Azure DevOps security analysis across all projects:
- Service connections (Azure service principal credentials)
- Variable groups (shared secrets across pipelines)
- Secure files (certificates, SSH keys, config files)
- Extensions (installed extensions with organization access)
- Repository policies (branch protection, required reviewers)
- Security scoring and risk classification

Requires an organization (--org) and a Personal Access Token (PAT) set in $AZDO_PAT.
Generates comprehensive table output and 6 loot files with security findings.`,
	Run: ListDevOpsSecurity,
}

func init() {
	AzDevOpsSecurityCommand.Flags().StringVar(&azinternal.OrgFlag, "org", "", "Azure DevOps organization URL (required)")
	AzDevOpsSecurityCommand.Flags().StringVar(&azinternal.PatFlag, "pat", "", "Azure DevOps Personal Access Token (optional; falls back to $AZDO_PAT)")
}

// ------------------------------
// Module struct
// ------------------------------
type DevOpsSecurityModule struct {
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
	ServiceConnectionRows [][]string
	VariableGroupRows     [][]string
	SecureFileRows        [][]string
	ExtensionRows         [][]string
	PolicyRows            [][]string
	LootMap               map[string]*internal.LootFile
	mu                    sync.Mutex

	// Security scoring
	TotalFindings      int
	CriticalFindings   int
	HighFindings       int
	MediumFindings     int
	LowFindings        int
	TotalSecrets       int
	UnprotectedSecrets int
	WeakPolicies       int
	RiskyExtensions    int
}

// ------------------------------
// Output struct
// ------------------------------
type DevOpsSecurityOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DevOpsSecurityOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DevOpsSecurityOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point
// ------------------------------
func ListDevOpsSecurity(cmd *cobra.Command, args []string) {
	logger := internal.NewLogger()

	// -------------------- Extract flags --------------------
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	if azinternal.OrgFlag == "" {
		logger.ErrorM("You must provide the organization URL via --org", globals.AZ_DEVOPS_SECURITY_MODULE_NAME)
		cmd.Help()
		os.Exit(1)
	}

	// Get authentication token (PAT or Azure AD)
	pat, authMethod, err := azinternal.GetDevOpsAuthTokenSimple()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Authentication failed: %v", err), globals.AZ_DEVOPS_SECURITY_MODULE_NAME)
		logger.InfoM("Set AZDO_PAT environment variable or run 'az login' to authenticate", globals.AZ_DEVOPS_SECURITY_MODULE_NAME)
		cmd.Help()
		os.Exit(1)
	}

	// Log authentication method
	if authMethod == "Azure AD" {
		logger.InfoM("Using Azure AD authentication (az login)", globals.AZ_DEVOPS_SECURITY_MODULE_NAME)
	}

	// -------------------- Get current user --------------------
	displayName, email, err := azinternal.FetchCurrentUser(pat)
	if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Failed to fetch current user: %v", err), globals.AZ_DEVOPS_SECURITY_MODULE_NAME)
		displayName = "unknown"
		email = "unknown"
	}

	// -------------------- Initialize module --------------------
	module := &DevOpsSecurityModule{
		Organization:          azinternal.OrgFlag,
		PAT:                   pat,
		DisplayName:           displayName,
		Email:                 email,
		Verbosity:             verbosity,
		WrapTable:             wrap,
		OutputDirectory:       outputDirectory,
		Format:                format,
		Goroutines:            5,
		ServiceConnectionRows: [][]string{},
		VariableGroupRows:     [][]string{},
		SecureFileRows:        [][]string{},
		ExtensionRows:         [][]string{},
		PolicyRows:            [][]string{},
		LootMap: map[string]*internal.LootFile{
			"devops-service-connections":   {Name: "devops-service-connections", Contents: ""},
			"devops-variable-groups":       {Name: "devops-variable-groups", Contents: ""},
			"devops-secure-files":          {Name: "devops-secure-files", Contents: ""},
			"devops-extensions":            {Name: "devops-extensions", Contents: ""},
			"devops-security-summary":      {Name: "devops-security-summary", Contents: ""},
			"devops-credential-extraction": {Name: "devops-credential-extraction", Contents: ""},
		},
	}

	// -------------------- Execute module --------------------
	module.PrintDevOpsSecurity(logger)
}

// ------------------------------
// Main module method
// ------------------------------
func (m *DevOpsSecurityModule) PrintDevOpsSecurity(logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Analyzing DevOps Security for organization: %s", m.Organization), globals.AZ_DEVOPS_SECURITY_MODULE_NAME)

	// Add Azure DevOps CLI extension install at the top
	m.LootMap["devops-credential-extraction"].Contents += "# Azure DevOps Security Analysis - Credential Extraction Commands\n\n"
	m.LootMap["devops-credential-extraction"].Contents += "az extension add --name azure-devops\n\n"

	// Fetch projects
	projects := azinternal.FetchProjects(m.Organization, m.PAT)
	if len(projects) == 0 {
		logger.InfoM("No projects found in organization", globals.AZ_DEVOPS_SECURITY_MODULE_NAME)
		return
	}

	logger.InfoM(fmt.Sprintf("Found %d projects, analyzing security posture...", len(projects)), globals.AZ_DEVOPS_SECURITY_MODULE_NAME)

	// Process projects concurrently
	var wg sync.WaitGroup
	for _, proj := range projects {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.processProject(proj, &wg, logger)
	}

	wg.Wait()

	// Fetch organization-level resources
	logger.InfoM("Analyzing organization-level extensions...", globals.AZ_DEVOPS_SECURITY_MODULE_NAME)
	m.processExtensions(logger)

	// Generate security summary
	m.generateSecuritySummary(logger)

	// Generate and write output
	m.writeOutput(logger)
}

// ------------------------------
// Process single project
// ------------------------------
func (m *DevOpsSecurityModule) processProject(proj map[string]interface{}, wg *sync.WaitGroup, logger internal.Logger) {
	defer wg.Done()

	projName := proj["name"].(string)
	projID := proj["id"].(string)

	// Add project section to credential extraction
	m.mu.Lock()
	m.LootMap["devops-credential-extraction"].Contents += fmt.Sprintf(
		"# ========================================\n"+
			"# Project: %s (ID: %s)\n"+
			"# ========================================\n\n"+
			"az devops configure --defaults organization=%s project=%s\n\n",
		projName, projID, m.Organization, projName,
	)
	m.mu.Unlock()

	// Fetch and process service connections
	serviceConnections := azinternal.FetchServiceConnections(m.Organization, m.PAT, projName)
	m.processServiceConnections(projName, projID, serviceConnections, logger)

	// Fetch and process variable groups
	variableGroups := azinternal.FetchVariableGroups(m.Organization, m.PAT, projName)
	m.processVariableGroups(projName, projID, variableGroups, logger)

	// Fetch and process secure files
	secureFiles := azinternal.FetchSecureFiles(m.Organization, m.PAT, projName)
	m.processSecureFiles(projName, projID, secureFiles, logger)

	// Fetch and process repository policies
	policies := azinternal.FetchRepositoryPolicies(m.Organization, m.PAT, projName)
	m.processPolicies(projName, projID, policies, logger)
}

// ------------------------------
// Process service connections
// ------------------------------
func (m *DevOpsSecurityModule) processServiceConnections(projName, projID string, connections []map[string]interface{}, logger internal.Logger) {
	if len(connections) == 0 {
		return
	}

	for _, conn := range connections {
		connName := ""
		if name, ok := conn["name"].(string); ok {
			connName = name
		}

		connID := ""
		if id, ok := conn["id"].(string); ok {
			connID = id
		}

		connType := ""
		if ctype, ok := conn["type"].(string); ok {
			connType = ctype
		}

		isShared := "false"
		if shared, ok := conn["isShared"].(bool); ok && shared {
			isShared = "true"
		}

		isReady := "false"
		if ready, ok := conn["isReady"].(bool); ok && ready {
			isReady = "true"
		}

		authScheme := ""
		tenantID := ""
		servicePrincipalID := ""
		subscriptionID := ""
		subscriptionName := ""
		riskLevel := "MEDIUM"

		if auth, ok := conn["authorization"].(map[string]interface{}); ok {
			if scheme, ok := auth["scheme"].(string); ok {
				authScheme = scheme
			}

			if params, ok := auth["parameters"].(map[string]interface{}); ok {
				if tid, ok := params["tenantid"].(string); ok {
					tenantID = tid
				}
				if spid, ok := params["serviceprincipalid"].(string); ok {
					servicePrincipalID = spid
				}
				if subid, ok := params["subscriptionid"].(string); ok {
					subscriptionID = subid
				}
				if subname, ok := params["subscriptionname"].(string); ok {
					subscriptionName = subname
				}
			}
		}

		// Risk assessment
		if authScheme == "ServicePrincipal" && subscriptionID != "" {
			riskLevel = "CRITICAL" // Service principal with subscription access
			m.mu.Lock()
			m.CriticalFindings++
			m.mu.Unlock()
		} else if connType == "github" || connType == "azurerm" {
			riskLevel = "HIGH"
			m.mu.Lock()
			m.HighFindings++
			m.mu.Unlock()
		}

		// Add to table rows
		m.mu.Lock()
		m.ServiceConnectionRows = append(m.ServiceConnectionRows, []string{
			projName,
			projID,
			connName,
			connID,
			connType,
			authScheme,
			isShared,
			isReady,
			tenantID,
			servicePrincipalID,
			subscriptionID,
			subscriptionName,
			riskLevel,
		})
		m.mu.Unlock()

		// Generate loot file content
		m.mu.Lock()
		m.LootMap["devops-service-connections"].Contents += fmt.Sprintf(
			"## Service Connection: %s\n"+
				"Project: %s\n"+
				"Connection ID: %s\n"+
				"Type: %s\n"+
				"Auth Scheme: %s\n"+
				"Is Shared: %s\n"+
				"Is Ready: %s\n"+
				"Risk Level: %s\n\n",
			connName, projName, connID, connType, authScheme, isShared, isReady, riskLevel,
		)

		if authScheme == "ServicePrincipal" {
			m.LootMap["devops-service-connections"].Contents += fmt.Sprintf(
				"Azure Service Principal Details:\n"+
					"  Tenant ID: %s\n"+
					"  Service Principal ID: %s\n"+
					"  Subscription ID: %s\n"+
					"  Subscription Name: %s\n\n"+
					"NOTE: Service principal secret is not accessible via API (masked).\n"+
					"If you have appropriate permissions, you can view the secret in Azure DevOps UI:\n"+
					"  %s/%s/_settings/adminservices?resourceId=%s\n\n"+
					"⚠️ SECURITY RISK: This service connection grants access to Azure subscription.\n"+
					"   If compromised, attacker can deploy resources, access data, and pivot to Azure.\n\n",
				tenantID, servicePrincipalID, subscriptionID, subscriptionName,
				m.Organization, projName, connID,
			)

			// Add extraction command
			m.LootMap["devops-credential-extraction"].Contents += fmt.Sprintf(
				"# Service Connection: %s (Type: %s)\n"+
					"az devops service-endpoint list --project %s --org %s --query \"[?name=='%s']\" -o json\n\n",
				connName, connType, projName, m.Organization, connName,
			)
		}

		m.LootMap["devops-service-connections"].Contents += "---\n\n"
		m.mu.Unlock()
	}
}

// ------------------------------
// Process variable groups
// ------------------------------
func (m *DevOpsSecurityModule) processVariableGroups(projName, projID string, groups []map[string]interface{}, logger internal.Logger) {
	if len(groups) == 0 {
		return
	}

	for _, group := range groups {
		groupName := ""
		if name, ok := group["name"].(string); ok {
			groupName = name
		}

		groupID := ""
		if id, ok := group["id"].(float64); ok {
			groupID = fmt.Sprintf("%.0f", id)
		}

		varCount := 0
		secretCount := 0
		variables := ""

		if vars, ok := group["variables"].(map[string]interface{}); ok {
			varCount = len(vars)
			varList := []string{}
			for varName, varData := range vars {
				if varMap, ok := varData.(map[string]interface{}); ok {
					isSecret := false
					if secret, ok := varMap["isSecret"].(bool); ok && secret {
						isSecret = true
						secretCount++
						m.mu.Lock()
						m.TotalSecrets++
						m.UnprotectedSecrets++ // Variable groups expose secrets to all pipelines
						m.mu.Unlock()
					}

					value := ""
					if val, ok := varMap["value"].(string); ok && !isSecret {
						value = val
					} else if isSecret {
						value = "[MASKED]"
					}

					varList = append(varList, fmt.Sprintf("%s=%s", varName, value))
				}
			}
			variables = strings.Join(varList, "; ")
		}

		riskLevel := "LOW"
		if secretCount > 0 {
			riskLevel = "HIGH"
			m.mu.Lock()
			m.HighFindings++
			m.mu.Unlock()
		} else if varCount > 0 {
			riskLevel = "MEDIUM"
			m.mu.Lock()
			m.MediumFindings++
			m.mu.Unlock()
		}

		// Add to table rows
		m.mu.Lock()
		m.VariableGroupRows = append(m.VariableGroupRows, []string{
			projName,
			projID,
			groupName,
			groupID,
			fmt.Sprintf("%d", varCount),
			fmt.Sprintf("%d", secretCount),
			variables,
			riskLevel,
		})
		m.mu.Unlock()

		// Generate loot file content
		m.mu.Lock()
		m.LootMap["devops-variable-groups"].Contents += fmt.Sprintf(
			"## Variable Group: %s\n"+
				"Project: %s\n"+
				"Group ID: %s\n"+
				"Variable Count: %d\n"+
				"Secret Count: %d\n"+
				"Risk Level: %s\n\n",
			groupName, projName, groupID, varCount, secretCount, riskLevel,
		)

		if varCount > 0 {
			m.LootMap["devops-variable-groups"].Contents += "Variables:\n"
			for varName, varData := range group["variables"].(map[string]interface{}) {
				if varMap, ok := varData.(map[string]interface{}); ok {
					isSecret := false
					if secret, ok := varMap["isSecret"].(bool); ok && secret {
						isSecret = true
					}

					value := ""
					if val, ok := varMap["value"].(string); ok && !isSecret {
						value = val

						// Scan non-secret variables for hardcoded secrets
						secretMatches := azinternal.ScanScriptContent(value, fmt.Sprintf("%s/%s [var: %s]", projName, groupName, varName), "variable-value")
						if len(secretMatches) > 0 {
							m.LootMap["devops-variable-groups"].Contents += fmt.Sprintf("  ⚠️ %s = %s [DETECTED SECRET IN VALUE]\n", varName, value)
							m.mu.Lock()
							m.TotalSecrets += len(secretMatches)
							m.mu.Unlock()
						} else {
							m.LootMap["devops-variable-groups"].Contents += fmt.Sprintf("  %s = %s\n", varName, value)
						}
					} else if isSecret {
						m.LootMap["devops-variable-groups"].Contents += fmt.Sprintf("  %s = [MASKED - SECRET]\n", varName)
					}
				}
			}
		}

		m.LootMap["devops-variable-groups"].Contents += "\n"

		if secretCount > 0 {
			m.LootMap["devops-variable-groups"].Contents += fmt.Sprintf(
				"⚠️ SECURITY RISK: This variable group contains %d secret(s).\n"+
					"   Secrets are shared across all pipelines that reference this group.\n"+
					"   Ensure least privilege access and audit pipeline usage.\n\n",
				secretCount,
			)
		}

		// Add extraction command
		m.LootMap["devops-credential-extraction"].Contents += fmt.Sprintf(
			"# Variable Group: %s (%d variables, %d secrets)\n"+
				"az pipelines variable-group list --project %s --org %s --query \"[?name=='%s']\" -o json\n\n",
			groupName, varCount, secretCount, projName, m.Organization, groupName,
		)

		m.LootMap["devops-variable-groups"].Contents += "---\n\n"
		m.mu.Unlock()
	}
}

// ------------------------------
// Process secure files
// ------------------------------
func (m *DevOpsSecurityModule) processSecureFiles(projName, projID string, files []map[string]interface{}, logger internal.Logger) {
	if len(files) == 0 {
		return
	}

	for _, file := range files {
		fileName := ""
		if name, ok := file["name"].(string); ok {
			fileName = name
		}

		fileID := ""
		if id, ok := file["id"].(string); ok {
			fileID = id
		}

		modifiedBy := ""
		if modified, ok := file["modifiedBy"].(map[string]interface{}); ok {
			if displayName, ok := modified["displayName"].(string); ok {
				modifiedBy = displayName
			}
		}

		modifiedOn := ""
		if modified, ok := file["modifiedOn"].(string); ok {
			modifiedOn = modified
		}

		fileType := "Unknown"
		riskLevel := "MEDIUM"

		// Determine file type and risk
		if strings.HasSuffix(fileName, ".pfx") || strings.HasSuffix(fileName, ".p12") {
			fileType = "Certificate (PFX/P12)"
			riskLevel = "HIGH"
			m.mu.Lock()
			m.HighFindings++
			m.mu.Unlock()
		} else if strings.HasSuffix(fileName, ".pem") {
			fileType = "Certificate (PEM)"
			riskLevel = "HIGH"
			m.mu.Lock()
			m.HighFindings++
			m.mu.Unlock()
		} else if strings.Contains(fileName, "key") || strings.HasSuffix(fileName, ".key") {
			fileType = "Private Key"
			riskLevel = "CRITICAL"
			m.mu.Lock()
			m.CriticalFindings++
			m.mu.Unlock()
		} else if strings.HasSuffix(fileName, ".json") {
			fileType = "JSON Config"
			riskLevel = "MEDIUM"
			m.mu.Lock()
			m.MediumFindings++
			m.mu.Unlock()
		} else if strings.HasSuffix(fileName, ".xml") || strings.HasSuffix(fileName, ".config") {
			fileType = "Config File"
			riskLevel = "MEDIUM"
			m.mu.Lock()
			m.MediumFindings++
			m.mu.Unlock()
		}

		// Add to table rows
		m.mu.Lock()
		m.SecureFileRows = append(m.SecureFileRows, []string{
			projName,
			projID,
			fileName,
			fileID,
			fileType,
			modifiedBy,
			modifiedOn,
			riskLevel,
		})
		m.mu.Unlock()

		// Generate loot file content
		m.mu.Lock()
		m.LootMap["devops-secure-files"].Contents += fmt.Sprintf(
			"## Secure File: %s\n"+
				"Project: %s\n"+
				"File ID: %s\n"+
				"File Type: %s\n"+
				"Modified By: %s\n"+
				"Modified On: %s\n"+
				"Risk Level: %s\n\n"+
				"NOTE: Secure files are encrypted at rest and not accessible via API.\n"+
				"Content can only be accessed during pipeline runs via DownloadSecureFile task.\n"+
				"If you have appropriate permissions, you can download the file from Azure DevOps UI:\n"+
				"  %s/%s/_library?itemType=SecureFiles\n\n",
			fileName, projName, fileID, fileType, modifiedBy, modifiedOn, riskLevel,
			m.Organization, projName,
		)

		if riskLevel == "CRITICAL" || riskLevel == "HIGH" {
			m.LootMap["devops-secure-files"].Contents += fmt.Sprintf(
				"⚠️ SECURITY RISK: This secure file contains sensitive credentials (%s).\n"+
					"   If pipeline is compromised, file can be exfiltrated during build.\n"+
					"   Monitor pipeline usage and restrict access to authorized pipelines only.\n\n",
				fileType,
			)
		}

		// Add extraction command
		m.LootMap["devops-credential-extraction"].Contents += fmt.Sprintf(
			"# Secure File: %s (Type: %s)\n"+
				"# Note: Secure files cannot be downloaded via CLI, only via pipeline DownloadSecureFile task\n"+
				"# List secure files:\n"+
				"az devops invoke --area distributedtask --resource securefiles --org %s --project %s --api-version 7.1\n\n",
			fileName, fileType, m.Organization, projName,
		)

		m.LootMap["devops-secure-files"].Contents += "---\n\n"
		m.mu.Unlock()
	}
}

// ------------------------------
// Process repository policies
// ------------------------------
func (m *DevOpsSecurityModule) processPolicies(projName, projID string, policies []map[string]interface{}, logger internal.Logger) {
	if len(policies) == 0 {
		// No policies = weak security posture
		m.mu.Lock()
		m.WeakPolicies++
		m.MediumFindings++

		m.PolicyRows = append(m.PolicyRows, []string{
			projName,
			projID,
			"No Policies",
			"-",
			"-",
			"false",
			"No branch protection policies configured",
			"MEDIUM",
		})
		m.mu.Unlock()
		return
	}

	for _, policy := range policies {
		policyID := ""
		if id, ok := policy["id"].(float64); ok {
			policyID = fmt.Sprintf("%.0f", id)
		}

		policyType := ""
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

		settings := ""
		if settingsMap, ok := policy["settings"].(map[string]interface{}); ok {
			settingsList := []string{}
			for k, v := range settingsMap {
				settingsList = append(settingsList, fmt.Sprintf("%s=%v", k, v))
			}
			settings = strings.Join(settingsList, "; ")
		}

		riskLevel := "LOW"
		if !strings.EqualFold(isEnabled, "true") {
			riskLevel = "MEDIUM"
			m.mu.Lock()
			m.WeakPolicies++
			m.MediumFindings++
			m.mu.Unlock()
		} else if !strings.EqualFold(isBlocking, "true") && strings.Contains(policyType, "approval") {
			riskLevel = "MEDIUM"
			m.mu.Lock()
			m.WeakPolicies++
			m.MediumFindings++
			m.mu.Unlock()
		}

		// Add to table rows
		m.mu.Lock()
		m.PolicyRows = append(m.PolicyRows, []string{
			projName,
			projID,
			policyType,
			policyID,
			isEnabled,
			isBlocking,
			settings,
			riskLevel,
		})
		m.mu.Unlock()
	}
}

// ------------------------------
// Process extensions
// ------------------------------
func (m *DevOpsSecurityModule) processExtensions(logger internal.Logger) {
	extensions := azinternal.FetchExtensions(m.Organization, m.PAT)
	if len(extensions) == 0 {
		return
	}

	for _, ext := range extensions {
		extName := ""
		if name, ok := ext["extensionName"].(string); ok {
			extName = name
		}

		publisher := ""
		if pub, ok := ext["publisherName"].(string); ok {
			publisher = pub
		}

		version := ""
		if ver, ok := ext["version"].(string); ok {
			version = ver
		}

		installState := ""
		if state, ok := ext["installState"].(map[string]interface{}); ok {
			if flags, ok := state["flags"].(string); ok {
				installState = flags
			}
		}

		lastPublished := ""
		if pub, ok := ext["lastPublished"].(string); ok {
			lastPublished = pub
		}

		flags := ""
		if flagsArray, ok := ext["flags"].([]interface{}); ok {
			flagsList := []string{}
			for _, f := range flagsArray {
				if flagStr, ok := f.(string); ok {
					flagsList = append(flagsList, flagStr)
				}
			}
			flags = strings.Join(flagsList, ", ")
		}

		// Risk assessment for extensions
		riskLevel := "LOW"
		if publisher != "Microsoft" && publisher != "ms" && publisher != "ms-devlabs" {
			riskLevel = "MEDIUM"
			m.mu.Lock()
			m.RiskyExtensions++
			m.MediumFindings++
			m.mu.Unlock()
		}

		// Specific high-risk extensions
		riskyExtensions := []string{"ssh", "terraform", "aws", "ansible", "kubernetes"}
		for _, risky := range riskyExtensions {
			if strings.Contains(strings.ToLower(extName), risky) {
				riskLevel = "HIGH"
				m.mu.Lock()
				m.RiskyExtensions++
				m.HighFindings++
				m.mu.Unlock()
				break
			}
		}

		// Add to table rows
		m.mu.Lock()
		m.ExtensionRows = append(m.ExtensionRows, []string{
			extName,
			publisher,
			version,
			installState,
			lastPublished,
			flags,
			riskLevel,
		})
		m.mu.Unlock()

		// Generate loot file content
		m.mu.Lock()
		m.LootMap["devops-extensions"].Contents += fmt.Sprintf(
			"## Extension: %s\n"+
				"Publisher: %s\n"+
				"Version: %s\n"+
				"Install State: %s\n"+
				"Last Published: %s\n"+
				"Flags: %s\n"+
				"Risk Level: %s\n\n",
			extName, publisher, version, installState, lastPublished, flags, riskLevel,
		)

		if riskLevel == "HIGH" || riskLevel == "MEDIUM" {
			m.LootMap["devops-extensions"].Contents += fmt.Sprintf(
				"⚠️ SECURITY RISK: This extension has elevated permissions.\n" +
					"   Extensions can access organization data, pipelines, and repositories.\n" +
					"   Review extension permissions and usage carefully.\n\n",
			)
		}

		m.LootMap["devops-extensions"].Contents += "---\n\n"
		m.mu.Unlock()
	}
}

// ------------------------------
// Generate security summary
// ------------------------------
func (m *DevOpsSecurityModule) generateSecuritySummary(logger internal.Logger) {
	// Calculate total findings
	m.TotalFindings = m.CriticalFindings + m.HighFindings + m.MediumFindings + m.LowFindings

	// Calculate security score (0-100)
	securityScore := 100
	securityScore -= m.CriticalFindings * 15
	securityScore -= m.HighFindings * 10
	securityScore -= m.MediumFindings * 5
	securityScore -= m.LowFindings * 2

	if securityScore < 0 {
		securityScore = 0
	}

	// Security posture rating
	posture := "EXCELLENT"
	if securityScore < 30 {
		posture = "CRITICAL"
	} else if securityScore < 50 {
		posture = "POOR"
	} else if securityScore < 70 {
		posture = "FAIR"
	} else if securityScore < 85 {
		posture = "GOOD"
	}

	// Generate summary
	m.LootMap["devops-security-summary"].Contents = fmt.Sprintf(
		"# Azure DevOps Security Summary\n"+
			"# Organization: %s\n"+
			"# Generated: %s\n\n"+
			"## Security Score: %d/100 (%s)\n\n"+
			"## Summary Statistics:\n"+
			"- Total Findings: %d\n"+
			"  - CRITICAL: %d\n"+
			"  - HIGH: %d\n"+
			"  - MEDIUM: %d\n"+
			"  - LOW: %d\n\n"+
			"## Resource Summary:\n"+
			"- Service Connections: %d\n"+
			"- Variable Groups: %d\n"+
			"- Secure Files: %d\n"+
			"- Extensions: %d\n"+
			"- Repository Policies: %d\n\n"+
			"## Security Risks:\n"+
			"- Total Secrets Found: %d\n"+
			"- Unprotected Secrets: %d\n"+
			"- Weak Policies: %d\n"+
			"- Risky Extensions: %d\n\n",
		m.Organization, time.Now().Format(time.RFC3339),
		securityScore, posture,
		m.TotalFindings, m.CriticalFindings, m.HighFindings, m.MediumFindings, m.LowFindings,
		len(m.ServiceConnectionRows), len(m.VariableGroupRows), len(m.SecureFileRows), len(m.ExtensionRows), len(m.PolicyRows),
		m.TotalSecrets, m.UnprotectedSecrets, m.WeakPolicies, m.RiskyExtensions,
	)

	// Add recommendations
	m.LootMap["devops-security-summary"].Contents += "## Security Recommendations:\n\n"

	if m.CriticalFindings > 0 {
		m.LootMap["devops-security-summary"].Contents += fmt.Sprintf(
			"🔴 CRITICAL (%d findings):\n"+
				"- Review all service connections with Azure subscription access\n"+
				"- Rotate service principal credentials regularly\n"+
				"- Implement least privilege for service connections\n"+
				"- Monitor for unauthorized usage of secure files\n\n",
			m.CriticalFindings,
		)
	}

	if m.HighFindings > 0 {
		m.LootMap["devops-security-summary"].Contents += fmt.Sprintf(
			"🟠 HIGH (%d findings):\n"+
				"- Audit variable groups for exposed secrets\n"+
				"- Implement secret scanning in pipelines\n"+
				"- Review certificate and key management\n"+
				"- Restrict access to sensitive secure files\n\n",
			m.HighFindings,
		)
	}

	if m.WeakPolicies > 0 {
		m.LootMap["devops-security-summary"].Contents += fmt.Sprintf(
			"🟡 MEDIUM (%d weak policies):\n"+
				"- Enable branch protection policies on main branches\n"+
				"- Require pull request reviews before merge\n"+
				"- Implement mandatory approval gates for production deployments\n"+
				"- Enable build validation policies\n\n",
			m.WeakPolicies,
		)
	}

	if m.RiskyExtensions > 0 {
		m.LootMap["devops-security-summary"].Contents += fmt.Sprintf(
			"🟡 EXTENSIONS (%d risky extensions):\n"+
				"- Review third-party extension permissions\n"+
				"- Remove unused extensions\n"+
				"- Monitor extension activity logs\n"+
				"- Prefer Microsoft-published extensions when available\n\n",
			m.RiskyExtensions,
		)
	}

	// Add best practices
	m.LootMap["devops-security-summary"].Contents += "## Security Best Practices:\n\n" +
		"1. **Secret Management:**\n" +
		"   - Use Azure Key Vault for storing secrets instead of variable groups\n" +
		"   - Enable secret scanning in repositories\n" +
		"   - Rotate credentials every 90 days\n" +
		"   - Use managed identities where possible\n\n" +
		"2. **Access Control:**\n" +
		"   - Implement least privilege access for service connections\n" +
		"   - Use project-scoped service connections (not organization-wide)\n" +
		"   - Audit PAT usage and expiration\n" +
		"   - Enable MFA for all users\n\n" +
		"3. **Pipeline Security:**\n" +
		"   - Require approval gates for production deployments\n" +
		"   - Implement environment protection rules\n" +
		"   - Restrict pipeline permissions to specific resources\n" +
		"   - Monitor pipeline run history for anomalies\n\n" +
		"4. **Repository Security:**\n" +
		"   - Enable branch protection on main/master branches\n" +
		"   - Require pull request reviews (minimum 2 reviewers)\n" +
		"   - Enable build validation before merge\n" +
		"   - Scan commits for secrets using pre-commit hooks\n\n"
}

// ------------------------------
// Write output
// ------------------------------
func (m *DevOpsSecurityModule) writeOutput(logger internal.Logger) {
	totalRows := len(m.ServiceConnectionRows) + len(m.VariableGroupRows) + len(m.SecureFileRows) + len(m.ExtensionRows) + len(m.PolicyRows)

	if totalRows == 0 {
		logger.InfoM("No DevOps security resources found", globals.AZ_DEVOPS_SECURITY_MODULE_NAME)
		return
	}

	// Build loot array
	loot := []internal.LootFile{}
	for _, lf := range m.LootMap {
		if lf.Contents != "" {
			loot = append(loot, *lf)
		}
	}

	// Create output with multiple tables
	tables := []internal.TableFile{}

	// Table 1: Service Connections
	if len(m.ServiceConnectionRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "service-connections",
			Header: []string{
				"Project Name", "Project ID", "Connection Name", "Connection ID", "Type", "Auth Scheme",
				"Is Shared", "Is Ready", "Tenant ID", "Service Principal ID", "Subscription ID", "Subscription Name", "Risk Level",
			},
			Body: m.ServiceConnectionRows,
		})
	}

	// Table 2: Variable Groups
	if len(m.VariableGroupRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "variable-groups",
			Header: []string{
				"Project Name", "Project ID", "Group Name", "Group ID", "Variable Count", "Secret Count", "Variables", "Risk Level",
			},
			Body: m.VariableGroupRows,
		})
	}

	// Table 3: Secure Files
	if len(m.SecureFileRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "secure-files",
			Header: []string{
				"Project Name", "Project ID", "File Name", "File ID", "File Type", "Modified By", "Modified On", "Risk Level",
			},
			Body: m.SecureFileRows,
		})
	}

	// Table 4: Extensions
	if len(m.ExtensionRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "extensions",
			Header: []string{
				"Extension Name", "Publisher", "Version", "Install State", "Last Published", "Flags", "Risk Level",
			},
			Body: m.ExtensionRows,
		})
	}

	// Table 5: Policies
	if len(m.PolicyRows) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "policies",
			Header: []string{
				"Project Name", "Project ID", "Policy Type", "Policy ID", "Is Enabled", "Is Blocking", "Settings", "Risk Level",
			},
			Body: m.PolicyRows,
		})
	}

	output := DevOpsSecurityOutput{
		Table: tables,
		Loot:  loot,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_DEVOPS_SECURITY_MODULE_NAME)
		m.CommandCounter.Error++
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d security resources (%d CRITICAL, %d HIGH, %d MEDIUM findings) for organization: %s",
		totalRows, m.CriticalFindings, m.HighFindings, m.MediumFindings, m.Organization), globals.AZ_DEVOPS_SECURITY_MODULE_NAME)
}
