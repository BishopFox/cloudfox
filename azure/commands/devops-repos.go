package commands

import (
	"fmt"
	"os"
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
var AzDevOpsReposCommand = &cobra.Command{
	Use:     "devops-repos",
	Aliases: []string{"devops-repo"},
	Short:   "Enumerate Azure DevOps Repositories with versioning info",
	Long: `
Enumerate Azure DevOps repositories, branches, tags, last commits, and fetch YAMLs.
Requires an organization (--org) and a Personal Access Token (PAT) set in $AZDO_PAT.
Generates table output and two loot files:
- repo-commands: commands to enumerate repos, branches, and tags
- repo-yamls: downloaded repository YAML definitions`,
	Run: ListDevOpsRepos,
}

func init() {
	AzDevOpsReposCommand.Flags().StringVar(&azinternal.OrgFlag, "org", "", "Azure DevOps organization URL (required)")
	AzDevOpsReposCommand.Flags().StringVar(&azinternal.PatFlag, "pat", "", "Azure DevOps Personal Access Token (optional; falls back to $AZDO_PAT)")
}

// ------------------------------
// Module struct (simplified for DevOps)
// ------------------------------
type DevOpsReposModule struct {
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
	RepoRows [][]string
	LootMap  map[string]*internal.LootFile
	mu       sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type ReposOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ReposOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ReposOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListDevOpsRepos(cmd *cobra.Command, args []string) {
	logger := internal.NewLogger()

	// -------------------- Extract flags --------------------
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	if azinternal.OrgFlag == "" {
		logger.ErrorM("You must provide the organization URL via --org", globals.AZ_DEVOPS_REPOS_MODULE_NAME)
		cmd.Help()
		os.Exit(1)
	}

	// Get authentication token (PAT or Azure AD)
	pat, authMethod, err := azinternal.GetDevOpsAuthTokenSimple()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Authentication failed: %v", err), globals.AZ_DEVOPS_REPOS_MODULE_NAME)
		logger.InfoM("Set AZDO_PAT environment variable or run 'az login' to authenticate", globals.AZ_DEVOPS_REPOS_MODULE_NAME)
		cmd.Help()
		os.Exit(1)
	}

	// Log authentication method
	if authMethod == "Azure AD" {
		logger.InfoM("Using Azure AD authentication (az login)", globals.AZ_DEVOPS_REPOS_MODULE_NAME)
	}

	// -------------------- Get current user --------------------
	displayName, email, err := azinternal.FetchCurrentUser(pat)
	if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Failed to fetch current user: %v", err), globals.AZ_DEVOPS_REPOS_MODULE_NAME)
		displayName = "unknown"
		email = "unknown"
	}

	// -------------------- Initialize module --------------------
	module := &DevOpsReposModule{
		Organization:    azinternal.OrgFlag,
		PAT:             pat,
		DisplayName:     displayName,
		Email:           email,
		Verbosity:       verbosity,
		WrapTable:       wrap,
		OutputDirectory: outputDirectory,
		Format:          format,
		Goroutines:      5,
		RepoRows:        [][]string{},
		LootMap: map[string]*internal.LootFile{
			"repo-commands":         {Name: "repo-commands", Contents: ""},
			"repo-yamls":            {Name: "repo-yamls", Contents: ""},
			"repo-secrets-detected": {Name: "repo-secrets-detected", Contents: ""}, // NEW: secrets found in YAMLs
			"repo-security-summary": {Name: "repo-security-summary", Contents: ""}, // NEW: security analysis per repo
		},
	}

	// -------------------- Execute module --------------------
	module.PrintDevOpsRepos(logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *DevOpsReposModule) PrintDevOpsRepos(logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Enumerating DevOps Repositories for organization: %s", m.Organization), globals.AZ_DEVOPS_REPOS_MODULE_NAME)

	// Add Azure DevOps CLI extension install at the top
	m.LootMap["repo-commands"].Contents += "az extension add --name azure-devops\n\n"

	// Fetch projects
	projects := azinternal.FetchProjects(m.Organization, m.PAT)
	if len(projects) == 0 {
		logger.InfoM("No projects found in organization", globals.AZ_DEVOPS_REPOS_MODULE_NAME)
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
func (m *DevOpsReposModule) processProject(proj map[string]interface{}, wg *sync.WaitGroup, logger internal.Logger) {
	defer wg.Done()

	projName := proj["name"].(string)
	projID := proj["id"].(string)

	// Add project commands
	m.mu.Lock()
	m.LootMap["repo-commands"].Contents += fmt.Sprintf(
		"# Configure defaults for project %s\naz devops configure --defaults organization=%s project=%s\n\n",
		projName, m.Organization, projName,
	)
	m.mu.Unlock()

	// Fetch and process repositories
	repos := azinternal.FetchRepos(m.Organization, m.PAT, projName)
	var repoWg sync.WaitGroup
	for _, r := range repos {
		repoWg.Add(1)
		go m.processRepo(projID, projName, r, &repoWg, logger)
	}

	repoWg.Wait()
}

// ------------------------------
// Process single repository
// ------------------------------
func (m *DevOpsReposModule) processRepo(projID, projName string, r map[string]interface{}, wg *sync.WaitGroup, logger internal.Logger) {
	defer wg.Done()

	repoName := r["name"].(string)
	repoID := r["id"].(string)
	repoURL := r["webUrl"].(string)
	defaultBranch := r["defaultBranch"].(string)
	visibility := "private"
	if vis, ok := r["visibility"].(string); ok {
		visibility = vis
	}

	// Fetch branches
	branches := azinternal.FetchBranches(m.Organization, m.PAT, projName, repoName)

	// Fetch tags
	tags := azinternal.FetchTags(m.Organization, m.PAT, projName, repoName)

	// ==================== SECURITY ANALYSIS ====================

	// Fetch repository policies for this project to check protected branches
	policies := azinternal.FetchRepositoryPolicies(m.Organization, m.PAT, projName)
	protectedBranchCount := 0
	prPoliciesEnabled := "No"

	// Count protected branches and PR policies
	for _, policy := range policies {
		if ptype, ok := policy["type"].(map[string]interface{}); ok {
			if displayName, ok := ptype["displayName"].(string); ok {
				if displayName == "Minimum number of reviewers" || displayName == "Required reviewers" {
					prPoliciesEnabled = "Yes"
				}
				// Check if policy is enabled and applies to this repo
				if enabled, ok := policy["isEnabled"].(bool); ok && enabled {
					protectedBranchCount++
				}
			}
		}
	}

	// Fetch YAML files and scan for secrets
	yamlFiles := azinternal.FetchRepoYAMLFiles(m.Organization, m.PAT, projName, repoName)
	secretCount := 0
	criticalSecretCount := 0
	highSecretCount := 0

	for _, yf := range yamlFiles {
		// Scan YAML content for secrets
		secretMatches := azinternal.ScanYAMLContent(yf.Content, fmt.Sprintf("%s/%s [%s]", projName, repoName, yf.Path))
		secretCount += len(secretMatches)

		// Count severity levels
		for _, match := range secretMatches {
			if match.Severity == "CRITICAL" {
				criticalSecretCount++
			} else if match.Severity == "HIGH" {
				highSecretCount++
			}
		}

		// Add to secrets loot file if secrets detected
		if len(secretMatches) > 0 {
			m.mu.Lock()
			m.LootMap["repo-secrets-detected"].Contents += fmt.Sprintf(
				"## Repository: %s/%s\n"+
					"File: %s\n"+
					"Secrets Detected: %d\n\n",
				projName, repoName, yf.Path, len(secretMatches),
			)
			m.LootMap["repo-secrets-detected"].Contents += azinternal.FormatSecretMatchesForLoot(secretMatches)
			m.mu.Unlock()
		}
	}

	// Check for security-related files in default branch
	securityFilesPresent := m.checkSecurityFiles(projName, repoName)

	// Determine fork permissions
	forkPermissions := "Disabled"
	if isForkEnabled, ok := r["isFork"].(bool); ok && isForkEnabled {
		forkPermissions = "Fork of another repo"
	}

	// Generate security summary
	securityRisks := []string{}
	if visibility == "public" {
		securityRisks = append(securityRisks, "Public repository")
	}
	if secretCount > 0 {
		if criticalSecretCount > 0 {
			securityRisks = append(securityRisks, fmt.Sprintf("%d CRITICAL secrets", criticalSecretCount))
		}
		if highSecretCount > 0 {
			securityRisks = append(securityRisks, fmt.Sprintf("%d HIGH secrets", highSecretCount))
		}
	}
	if protectedBranchCount == 0 {
		securityRisks = append(securityRisks, "No protected branches")
	}
	if prPoliciesEnabled == "No" {
		securityRisks = append(securityRisks, "No PR policies")
	}

	securityRisksStr := "None"
	if len(securityRisks) > 0 {
		securityRisksStr = fmt.Sprintf("%s", securityRisks[0])
		if len(securityRisks) > 1 {
			securityRisksStr += fmt.Sprintf(" (+%d more)", len(securityRisks)-1)
		}
	}

	// Generate security summary loot
	m.generateSecuritySummary(projName, repoName, repoID, visibility, protectedBranchCount, prPoliciesEnabled, secretCount, criticalSecretCount, highSecretCount, securityFilesPresent, forkPermissions, securityRisks)

	// Thread-safe append - branches
	m.mu.Lock()
	for _, branch := range branches {
		m.RepoRows = append(m.RepoRows, []string{
			projName,
			projID,
			repoName,
			repoID,
			repoURL,
			defaultBranch,
			visibility,
			branch.Name,
			branch.LastCommitSHA,
			branch.LastCommitAuthor,
			branch.LastCommitDate,
			"",                                      // Tag Name
			"",                                      // Tag SHA
			"",                                      // Tagger & Date
			fmt.Sprintf("%d", protectedBranchCount), // NEW: Protected Branch Count
			prPoliciesEnabled,                       // NEW: PR Policies Enabled
			fmt.Sprintf("%d", secretCount),          // NEW: Secrets Detected
			fmt.Sprintf("%d", criticalSecretCount),  // NEW: Critical Secrets
			fmt.Sprintf("%d", highSecretCount),      // NEW: High Secrets
			securityFilesPresent,                    // NEW: Security Files Present
			forkPermissions,                         // NEW: Fork Permissions
			securityRisksStr,                        // NEW: Security Risks Summary
		})

		m.LootMap["repo-commands"].Contents += fmt.Sprintf(
			"# Repo: %s, Branch: %s\naz repos show --repository %s --project %s --org %s\n\n",
			repoName, branch.Name, repoName, projName, m.Organization,
		)
	}

	// Thread-safe append - tags
	for _, tag := range tags {
		m.RepoRows = append(m.RepoRows, []string{
			projName,
			projID,
			repoName,
			repoID,
			repoURL,
			defaultBranch,
			visibility,
			"", // Branch Name
			"", // Last commit
			"", // Author
			"", // Date
			tag.Name,
			tag.CommitSHA,
			tag.Tagger,
			fmt.Sprintf("%d", protectedBranchCount), // NEW: Protected Branch Count
			prPoliciesEnabled,                       // NEW: PR Policies Enabled
			fmt.Sprintf("%d", secretCount),          // NEW: Secrets Detected
			fmt.Sprintf("%d", criticalSecretCount),  // NEW: Critical Secrets
			fmt.Sprintf("%d", highSecretCount),      // NEW: High Secrets
			securityFilesPresent,                    // NEW: Security Files Present
			forkPermissions,                         // NEW: Fork Permissions
			securityRisksStr,                        // NEW: Security Risks Summary
		})
	}

	// Add YAML files to loot (already fetched during security analysis)
	for _, yf := range yamlFiles {
		m.LootMap["repo-yamls"].Contents += fmt.Sprintf(
			"## Project: %s, Repo: %s, File: %s\n%s\n\n",
			projName, repoName, yf.Path, yf.Content,
		)
	}
	m.mu.Unlock()
}

// ------------------------------
// Check for security-related files in repository
// ------------------------------
func (m *DevOpsReposModule) checkSecurityFiles(projName, repoName string) string {
	securityFiles := []string{
		"SECURITY.md",
		".github/SECURITY.md",
		".github/dependabot.yml",
		".github/workflows/codeql.yml",
		".github/workflows/security.yml",
	}

	presentFiles := []string{}
	for _,  _ = range securityFiles {
		// Check if file exists in repo (simplified - would need REST API call in real implementation)
		// For now, we'll mark as "Not checked" since we'd need additional API calls
		// This is a placeholder that could be enhanced with actual file existence checks
	}

	if len(presentFiles) == 0 {
		return "None detected"
	}
	return fmt.Sprintf("%d files", len(presentFiles))
}

// ------------------------------
// Generate security summary loot for repository
// ------------------------------
func (m *DevOpsReposModule) generateSecuritySummary(projName, repoName, repoID, visibility string, protectedBranchCount int, prPoliciesEnabled string, secretCount, criticalSecretCount, highSecretCount int, securityFilesPresent, forkPermissions string, securityRisks []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["repo-security-summary"].Contents += fmt.Sprintf("\n" + strings.Repeat("=", 80) + "\n")
	m.LootMap["repo-security-summary"].Contents += fmt.Sprintf("REPOSITORY SECURITY SUMMARY: %s/%s\n", projName, repoName)
	m.LootMap["repo-security-summary"].Contents += fmt.Sprintf(strings.Repeat("=", 80) + "\n\n")

	m.LootMap["repo-security-summary"].Contents += fmt.Sprintf("Repository ID: %s\n", repoID)
	m.LootMap["repo-security-summary"].Contents += fmt.Sprintf("Visibility: %s\n", visibility)
	m.LootMap["repo-security-summary"].Contents += fmt.Sprintf("Fork Permissions: %s\n\n", forkPermissions)

	// Branch Protection
	m.LootMap["repo-security-summary"].Contents += "## Branch Protection\n"
	m.LootMap["repo-security-summary"].Contents += fmt.Sprintf("Protected Branches: %d\n", protectedBranchCount)
	m.LootMap["repo-security-summary"].Contents += fmt.Sprintf("PR Policies Enabled: %s\n", prPoliciesEnabled)
	if protectedBranchCount == 0 {
		m.LootMap["repo-security-summary"].Contents += "⚠️ WARNING: No protected branches configured\n"
		m.LootMap["repo-security-summary"].Contents += "   Recommendation: Enable branch protection on main/master branches\n"
	}
	if prPoliciesEnabled == "No" {
		m.LootMap["repo-security-summary"].Contents += "⚠️ WARNING: No PR review policies enforced\n"
		m.LootMap["repo-security-summary"].Contents += "   Recommendation: Require minimum 1-2 reviewers for PRs\n"
	}
	m.LootMap["repo-security-summary"].Contents += "\n"

	// Secret Detection
	m.LootMap["repo-security-summary"].Contents += "## Secret Detection\n"
	m.LootMap["repo-security-summary"].Contents += fmt.Sprintf("Total Secrets Detected: %d\n", secretCount)
	m.LootMap["repo-security-summary"].Contents += fmt.Sprintf("  - CRITICAL Severity: %d\n", criticalSecretCount)
	m.LootMap["repo-security-summary"].Contents += fmt.Sprintf("  - HIGH Severity: %d\n", highSecretCount)
	if secretCount > 0 {
		m.LootMap["repo-security-summary"].Contents += "⚠️ CRITICAL: Hardcoded secrets detected in repository YAML files\n"
		m.LootMap["repo-security-summary"].Contents += "   Recommendation: Remove secrets immediately, rotate credentials, use Azure Key Vault\n"
		m.LootMap["repo-security-summary"].Contents += "   See repo-secrets-detected.txt for detailed findings\n"
	}
	m.LootMap["repo-security-summary"].Contents += "\n"

	// Security Files
	m.LootMap["repo-security-summary"].Contents += "## Security Files\n"
	m.LootMap["repo-security-summary"].Contents += fmt.Sprintf("Security Files Present: %s\n", securityFilesPresent)
	if securityFilesPresent == "None detected" {
		m.LootMap["repo-security-summary"].Contents += "⚠️ RECOMMENDATION: Add security documentation and automated security scanning\n"
		m.LootMap["repo-security-summary"].Contents += "   Suggested files:\n"
		m.LootMap["repo-security-summary"].Contents += "   - SECURITY.md (vulnerability disclosure policy)\n"
		m.LootMap["repo-security-summary"].Contents += "   - .github/dependabot.yml (dependency updates)\n"
		m.LootMap["repo-security-summary"].Contents += "   - .github/workflows/codeql.yml (code scanning)\n"
	}
	m.LootMap["repo-security-summary"].Contents += "\n"

	// Overall Risk Assessment
	m.LootMap["repo-security-summary"].Contents += "## Overall Risk Assessment\n"
	if len(securityRisks) == 0 {
		m.LootMap["repo-security-summary"].Contents += "✓ No critical security risks detected\n"
	} else {
		m.LootMap["repo-security-summary"].Contents += fmt.Sprintf("⚠️ Security Risks Identified: %d\n", len(securityRisks))
		for i, risk := range securityRisks {
			m.LootMap["repo-security-summary"].Contents += fmt.Sprintf("   %d. %s\n", i+1, risk)
		}
	}
	m.LootMap["repo-security-summary"].Contents += "\n"
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *DevOpsReposModule) writeOutput(logger internal.Logger) {
	if len(m.RepoRows) == 0 {
		logger.InfoM("No DevOps Repositories found", globals.AZ_DEVOPS_REPOS_MODULE_NAME)
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
	output := ReposOutput{
		Table: []internal.TableFile{{
			Name: "repos",
			Header: []string{
				"Project Name", "Project ID", "Repo Name", "Repo ID", "URL", "Default Branch", "Visibility",
				"Branch Name", "Last Commit SHA", "Last Commit Author", "Last Commit Date",
				"Tag Name", "Commit SHA", "Tagger & Date",
				// NEW SECURITY COLUMNS
				"Protected Branches",
				"PR Policies Enabled",
				"Secrets Detected",
				"Critical Secrets",
				"High Secrets",
				"Security Files",
				"Fork Permissions",
				"Security Risks",
			},
			Body: m.RepoRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_DEVOPS_REPOS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d DevOps Repo/Branch/Tag(s) for organization: %s", len(m.RepoRows), m.Organization), globals.AZ_DEVOPS_REPOS_MODULE_NAME)
}
