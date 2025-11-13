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
var AzDevOpsArtifactsCommand = &cobra.Command{
	Use:     "devops-artifacts",
	Aliases: []string{"devops-feeds"},
	Short:   "Enumerate Azure Artifacts feeds and packages",
	Long: `
Enumerate Azure DevOps Artifacts feeds and their packages.

Authentication (in order of priority):
1. Personal Access Token: Set AZDO_PAT environment variable or use --pat flag
2. Azure AD (fallback): Uses 'az login' session automatically

Requires an organization (--org).

Generates table output and loot files with security analysis.`,
	Run: ListDevOpsArtifacts,
}

func init() {
	AzDevOpsArtifactsCommand.Flags().StringVar(&azinternal.OrgFlag, "org", "", "Azure DevOps organization URL (required)")
	AzDevOpsArtifactsCommand.Flags().StringVar(&azinternal.PatFlag, "pat", "", "Azure DevOps Personal Access Token (optional; falls back to $AZDO_PAT)")
}

// ------------------------------
// Module struct (simplified for DevOps)
// ------------------------------
type DevOpsArtifactsModule struct {
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
	ArtifactRows [][]string
	LootMap      map[string]*internal.LootFile
	mu           sync.Mutex
}

// ------------------------------
// Output struct
// ------------------------------
type ArtifactsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ArtifactsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ArtifactsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Cobra command entry point (thin wrapper)
// ------------------------------
func ListDevOpsArtifacts(cmd *cobra.Command, args []string) {
	logger := internal.NewLogger()

	// -------------------- Extract flags --------------------
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	if azinternal.OrgFlag == "" {
		logger.ErrorM("You must provide the organization URL via --org", globals.AZ_DEVOPS_ARTIFACTS_MODULE_NAME)
		cmd.Help()
		os.Exit(1)
	}

	// Get authentication token (PAT or Azure AD)
	pat, authMethod, err := azinternal.GetDevOpsAuthTokenSimple()
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Authentication failed: %v", err), globals.AZ_DEVOPS_ARTIFACTS_MODULE_NAME)
		logger.InfoM("Set AZDO_PAT environment variable or run 'az login' to authenticate", globals.AZ_DEVOPS_ARTIFACTS_MODULE_NAME)
		cmd.Help()
		os.Exit(1)
	}

	// Log authentication method
	if authMethod == "Azure AD" {
		logger.InfoM("Using Azure AD authentication (az login)", globals.AZ_DEVOPS_ARTIFACTS_MODULE_NAME)
	}

	// -------------------- Get current user --------------------
	displayName, email, err := azinternal.FetchCurrentUser(pat)
	if err != nil && globals.AZ_VERBOSITY >= globals.AZ_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Failed to fetch current user: %v", err), globals.AZ_DEVOPS_ARTIFACTS_MODULE_NAME)
		displayName = "unknown"
		email = "unknown"
	}

	// -------------------- Initialize module --------------------
	module := &DevOpsArtifactsModule{
		Organization:    azinternal.OrgFlag,
		PAT:             pat,
		DisplayName:     displayName,
		Email:           email,
		Verbosity:       verbosity,
		WrapTable:       wrap,
		OutputDirectory: outputDirectory,
		Format:          format,
		Goroutines:      5,
		ArtifactRows:    [][]string{},
		LootMap: map[string]*internal.LootFile{
			"artifacts-commands":         {Name: "artifacts-commands", Contents: ""},
			"artifacts-packages":         {Name: "artifacts-packages", Contents: ""},
			"artifacts-security-summary": {Name: "artifacts-security-summary", Contents: ""}, // NEW: security analysis per feed
			"artifacts-public-exposure":  {Name: "artifacts-public-exposure", Contents: ""},  // NEW: publicly accessible feeds
			"artifacts-permissions":      {Name: "artifacts-permissions", Contents: ""},      // NEW: feed permissions analysis
		},
	}

	// -------------------- Execute module --------------------
	module.PrintDevOpsArtifacts(logger)
}

// ------------------------------
// Main module method (AWS-style)
// ------------------------------
func (m *DevOpsArtifactsModule) PrintDevOpsArtifacts(logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Enumerating DevOps Artifacts for organization: %s", m.Organization), globals.AZ_DEVOPS_ARTIFACTS_MODULE_NAME)

	// Add Azure DevOps CLI extension install at the top
	m.LootMap["artifacts-commands"].Contents += "az extension add --name azure-devops\n\n"

	// Fetch feeds
	feeds := azinternal.FetchFeeds(m.Organization, m.PAT)
	if len(feeds) == 0 {
		logger.InfoM("No feeds found in organization", globals.AZ_DEVOPS_ARTIFACTS_MODULE_NAME)
		return
	}

	// Process feeds concurrently
	var wg sync.WaitGroup
	for _, feed := range feeds {
		m.CommandCounter.Total++
		wg.Add(1)
		go m.processFeed(feed, &wg, logger)
	}

	wg.Wait()

	// Generate and write output
	m.writeOutput(logger)
}

// ------------------------------
// Process single feed
// ------------------------------
func (m *DevOpsArtifactsModule) processFeed(feed map[string]interface{}, wg *sync.WaitGroup, logger internal.Logger) {
	defer wg.Done()

	feedName := feed["name"].(string)
	feedID := feed["id"].(string)
	feedVisibility := feed["visibility"].(string)

	// Add feed commands
	m.mu.Lock()
	m.LootMap["artifacts-commands"].Contents += fmt.Sprintf(
		"# Configure defaults for feed %s\naz devops configure --defaults organization=%s\n\n",
		feedName, m.Organization,
	)
	m.mu.Unlock()

	// ==================== SECURITY ANALYSIS - FEED LEVEL ====================

	// Analyze feed visibility and exposure
	publicExposure := "No"
	if feedVisibility == "public" || feedVisibility == "organization" {
		publicExposure = "Yes"
	}

	// Extract feed permissions (if available in feed object)
	upstreamSources := "None"
	if upstreams, ok := feed["upstreamSources"].([]interface{}); ok && len(upstreams) > 0 {
		upstreamSources = fmt.Sprintf("%d sources", len(upstreams))
	}

	// Check for retention policies (default is usually unlimited)
	retentionPolicy := "Default"
	if retention, ok := feed["retentionPolicy"].(map[string]interface{}); ok {
		if daysToKeep, ok := retention["daysToKeepRecentlyDownloadedPackages"].(float64); ok {
			retentionPolicy = fmt.Sprintf("%d days", int(daysToKeep))
		}
	}

	// Fetch and process packages
	packages := azinternal.FetchFeedPackages(m.Organization, m.PAT, feedName)
	packageCount := len(packages)

	// Security risk assessment
	securityRisks := []string{}
	if publicExposure == "Yes" {
		securityRisks = append(securityRisks, "Public or org-wide exposure")
	}
	if retentionPolicy == "Default" {
		securityRisks = append(securityRisks, "No retention policy (unlimited storage)")
	}
	if upstreamSources != "None" {
		securityRisks = append(securityRisks, "External upstream sources enabled")
	}

	// Generate feed security summary
	m.generateFeedSecuritySummary(feedName, feedID, feedVisibility, publicExposure, upstreamSources, retentionPolicy, packageCount, securityRisks)

	// Process packages with security analysis
	var pkgWg sync.WaitGroup
	for _, pkg := range packages {
		pkgWg.Add(1)
		go m.processPackage(feedName, feedID, feedVisibility, publicExposure, upstreamSources, retentionPolicy, pkg, &pkgWg, logger)
	}

	pkgWg.Wait()
}

// ------------------------------
// Process single package
// ------------------------------
func (m *DevOpsArtifactsModule) processPackage(feedName, feedID, feedVisibility, publicExposure, upstreamSources, retentionPolicy string, pkg map[string]interface{}, wg *sync.WaitGroup, logger internal.Logger) {
	defer wg.Done()

	pkgName := pkg["name"].(string)
	pkgID := pkg["id"].(string)
	version := pkg["version"].(string)

	// ==================== SECURITY ANALYSIS - PACKAGE LEVEL ====================

	// Analyze package name for suspicious patterns (typosquatting, malicious patterns)
	namingRisk := m.analyzePackageName(pkgName)

	// Analyze version for suspicious patterns
	versionRisk := m.analyzePackageVersion(version)

	// Check package source (upstream vs internal)
	packageSource := "Internal"
	if upstreamSources != "None" {
		packageSource = "Potentially upstream"
	}

	// Extract package metadata if available
	publishDate := "Unknown"
	if published, ok := pkg["publishDate"].(string); ok {
		publishDate = published
	}

	author := "Unknown"
	if pkg_author, ok := pkg["author"].(string); ok {
		author = pkg_author
	}

	// Consolidated security risk for this package
	packageRisks := []string{}
	if publicExposure == "Yes" {
		packageRisks = append(packageRisks, "Public feed")
	}
	if namingRisk != "None" {
		packageRisks = append(packageRisks, namingRisk)
	}
	if versionRisk != "None" {
		packageRisks = append(packageRisks, versionRisk)
	}

	packageRisksStr := "None"
	if len(packageRisks) > 0 {
		packageRisksStr = fmt.Sprintf("%s", packageRisks[0])
		if len(packageRisks) > 1 {
			packageRisksStr += fmt.Sprintf(" (+%d more)", len(packageRisks)-1)
		}
	}

	// Thread-safe append - table row with NEW security columns
	m.mu.Lock()
	m.ArtifactRows = append(m.ArtifactRows, []string{
		feedName,
		feedID,
		feedVisibility,
		pkgName,
		pkgID,
		version,
		publicExposure,  // NEW: Public Exposure
		packageSource,   // NEW: Package Source
		upstreamSources, // NEW: Upstream Sources
		retentionPolicy, // NEW: Retention Policy
		publishDate,     // NEW: Publish Date
		author,          // NEW: Author
		packageRisksStr, // NEW: Security Risks
	})

	// Loot: package commands
	m.LootMap["artifacts-commands"].Contents += fmt.Sprintf(
		"# Feed: %s, Package: %s\naz artifacts universal download --feed %s --name %s --version %s --path ./downloads\n\n",
		feedName, pkgName, feedName, pkgName, version,
	)

	// Log public exposure to dedicated loot file
	if publicExposure == "Yes" {
		m.LootMap["artifacts-public-exposure"].Contents += fmt.Sprintf(
			"Feed: %s (Visibility: %s)\n"+
				"Package: %s\n"+
				"Version: %s\n"+
				"⚠️ WARNING: This package is publicly accessible or organization-wide\n"+
				"Download Command: az artifacts universal download --feed %s --name %s --version %s --path ./downloads\n\n",
			feedName, feedVisibility, pkgName, version, feedName, pkgName, version,
		)
	}

	m.mu.Unlock()

	// Optional: Fetch YAML or metadata if available
	yamlContent := azinternal.FetchPackageYAML(m.Organization, m.PAT, feedName, pkgName, version)
	if yamlContent != "" {
		m.mu.Lock()
		m.LootMap["artifacts-packages"].Contents += fmt.Sprintf(
			"## Feed: %s, Package: %s, Version: %s\n%s\n\n",
			feedName, pkgName, version, yamlContent,
		)
		m.mu.Unlock()
	}
}

// ------------------------------
// Analyze package name for suspicious patterns
// ------------------------------
func (m *DevOpsArtifactsModule) analyzePackageName(pkgName string) string {
	// Check for common typosquatting patterns and suspicious naming
	suspiciousPatterns := map[string]string{
		"test":     "Test package",
		"temp":     "Temporary package",
		"sample":   "Sample/demo package",
		"exploit":  "Potentially malicious name",
		"malware":  "Potentially malicious name",
		"backdoor": "Potentially malicious name",
	}

	pkgLower := strings.ToLower(pkgName)
	for pattern, risk := range suspiciousPatterns {
		if strings.Contains(pkgLower, pattern) {
			return risk
		}
	}

	// Check for unusually short names (potential typosquatting)
	if len(pkgName) <= 2 {
		return "Very short name (typosquatting risk)"
	}

	return "None"
}

// ------------------------------
// Analyze package version for suspicious patterns
// ------------------------------
func (m *DevOpsArtifactsModule) analyzePackageVersion(version string) string {
	// Check for pre-release/beta versions in production
	if strings.Contains(version, "beta") || strings.Contains(version, "alpha") || strings.Contains(version, "rc") {
		return "Pre-release version"
	}

	// Check for development versions
	if strings.Contains(version, "dev") || strings.Contains(version, "snapshot") {
		return "Development version"
	}

	// Check for unusually high version numbers (potential malicious package)
	if strings.HasPrefix(version, "999") || strings.HasPrefix(version, "9999") {
		return "Suspicious version number"
	}

	return "None"
}

// ------------------------------
// Generate feed security summary
// ------------------------------
func (m *DevOpsArtifactsModule) generateFeedSecuritySummary(feedName, feedID, feedVisibility, publicExposure, upstreamSources, retentionPolicy string, packageCount int, securityRisks []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["artifacts-security-summary"].Contents += fmt.Sprintf("\n" + strings.Repeat("=", 80) + "\n")
	m.LootMap["artifacts-security-summary"].Contents += fmt.Sprintf("FEED SECURITY SUMMARY: %s\n", feedName)
	m.LootMap["artifacts-security-summary"].Contents += fmt.Sprintf(strings.Repeat("=", 80) + "\n\n")

	m.LootMap["artifacts-security-summary"].Contents += fmt.Sprintf("Feed ID: %s\n", feedID)
	m.LootMap["artifacts-security-summary"].Contents += fmt.Sprintf("Visibility: %s\n", feedVisibility)
	m.LootMap["artifacts-security-summary"].Contents += fmt.Sprintf("Public Exposure: %s\n", publicExposure)
	m.LootMap["artifacts-security-summary"].Contents += fmt.Sprintf("Package Count: %d\n\n", packageCount)

	// Upstream Sources
	m.LootMap["artifacts-security-summary"].Contents += "## Upstream Sources\n"
	m.LootMap["artifacts-security-summary"].Contents += fmt.Sprintf("Configured Upstream Sources: %s\n", upstreamSources)
	if upstreamSources != "None" {
		m.LootMap["artifacts-security-summary"].Contents += "⚠️ WARNING: External upstream sources enabled\n"
		m.LootMap["artifacts-security-summary"].Contents += "   Risk: Packages from upstream sources may introduce vulnerabilities\n"
		m.LootMap["artifacts-security-summary"].Contents += "   Recommendation: Validate all upstream packages before use\n"
	}
	m.LootMap["artifacts-security-summary"].Contents += "\n"

	// Retention Policy
	m.LootMap["artifacts-security-summary"].Contents += "## Retention Policy\n"
	m.LootMap["artifacts-security-summary"].Contents += fmt.Sprintf("Retention Policy: %s\n", retentionPolicy)
	if retentionPolicy == "Default" {
		m.LootMap["artifacts-security-summary"].Contents += "⚠️ RECOMMENDATION: Configure retention policy to limit storage costs\n"
		m.LootMap["artifacts-security-summary"].Contents += "   Default policy keeps packages indefinitely\n"
	}
	m.LootMap["artifacts-security-summary"].Contents += "\n"

	// Public Exposure Analysis
	if publicExposure == "Yes" {
		m.LootMap["artifacts-security-summary"].Contents += "## Public Exposure Analysis\n"
		m.LootMap["artifacts-security-summary"].Contents += "⚠️ CRITICAL: Feed is publicly accessible or organization-wide\n"
		m.LootMap["artifacts-security-summary"].Contents += "   Risk: Private/proprietary packages may be exposed\n"
		m.LootMap["artifacts-security-summary"].Contents += "   Recommendation:\n"
		m.LootMap["artifacts-security-summary"].Contents += "   1. Review feed permissions and limit to specific teams/projects\n"
		m.LootMap["artifacts-security-summary"].Contents += "   2. Audit all packages for sensitive data exposure\n"
		m.LootMap["artifacts-security-summary"].Contents += "   3. Consider using project-scoped feeds for sensitive packages\n"
		m.LootMap["artifacts-security-summary"].Contents += fmt.Sprintf("   4. See artifacts-public-exposure.txt for package list (%d packages)\n", packageCount)
		m.LootMap["artifacts-security-summary"].Contents += "\n"

		// Add to permissions loot file
		m.LootMap["artifacts-permissions"].Contents += fmt.Sprintf("## Feed: %s (ID: %s)\n", feedName, feedID)
		m.LootMap["artifacts-permissions"].Contents += fmt.Sprintf("Visibility: %s\n", feedVisibility)
		m.LootMap["artifacts-permissions"].Contents += fmt.Sprintf("Public Exposure: %s\n", publicExposure)
		m.LootMap["artifacts-permissions"].Contents += fmt.Sprintf("Package Count: %d\n", packageCount)
		m.LootMap["artifacts-permissions"].Contents += "⚠️ SECURITY RISK: This feed is publicly accessible\n"
		m.LootMap["artifacts-permissions"].Contents += "Review permissions with: az artifacts universal list --feed " + feedName + "\n\n"
		m.LootMap["artifacts-permissions"].Contents += "---\n\n"
	}

	// Overall Risk Assessment
	m.LootMap["artifacts-security-summary"].Contents += "## Overall Risk Assessment\n"
	if len(securityRisks) == 0 {
		m.LootMap["artifacts-security-summary"].Contents += "✓ No critical security risks detected\n"
	} else {
		m.LootMap["artifacts-security-summary"].Contents += fmt.Sprintf("⚠️ Security Risks Identified: %d\n", len(securityRisks))
		for i, risk := range securityRisks {
			m.LootMap["artifacts-security-summary"].Contents += fmt.Sprintf("   %d. %s\n", i+1, risk)
		}
	}
	m.LootMap["artifacts-security-summary"].Contents += "\n"
}

// ------------------------------
// Write output (AWS-style writeLoot pattern)
// ------------------------------
func (m *DevOpsArtifactsModule) writeOutput(logger internal.Logger) {
	if len(m.ArtifactRows) == 0 {
		logger.InfoM("No DevOps Artifacts found", globals.AZ_DEVOPS_ARTIFACTS_MODULE_NAME)
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
	output := ArtifactsOutput{
		Table: []internal.TableFile{{
			Name: "artifacts",
			Header: []string{
				"Feed Name", "Feed ID", "Visibility", "Package Name", "Package ID", "Version",
				// NEW SECURITY COLUMNS
				"Public Exposure",
				"Package Source",
				"Upstream Sources",
				"Retention Policy",
				"Publish Date",
				"Author",
				"Security Risks",
			},
			Body: m.ArtifactRows,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.AZ_DEVOPS_ARTIFACTS_MODULE_NAME)
		m.CommandCounter.Error++
	}

	logger.SuccessM(fmt.Sprintf("Found %d DevOps Artifact/Package(s) for organization: %s", len(m.ArtifactRows), m.Organization), globals.AZ_DEVOPS_ARTIFACTS_MODULE_NAME)
}
