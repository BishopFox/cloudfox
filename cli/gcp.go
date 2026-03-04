package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/gcp/commands"
	oauthservice "github.com/BishopFox/cloudfox/gcp/services/oauthService"
	orgsservice "github.com/BishopFox/cloudfox/gcp/services/organizationsService"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	// GCP resources filtering options
	GCPOrganization       string
	GCPProjectID          string
	GCPProjectIDsFilePath string
	GCPProjectIDs         []string
	GCPAllProjects        bool

	// Service account impersonation
	GCPImpersonateSA string

	// Service account key file authentication
	GCPKeyFile string

	// Raw access token authentication
	GCPAccessToken string

	// Project name mapping (ProjectID -> DisplayName)
	GCPProjectNames map[string]string

	// Output formatting options
	GCPOutputFormat    string
	GCPOutputDirectory string
	GCPVerbosity       int
	GCPWrapTable       bool
	GCPFlatOutput      bool
	GCPQuery           string
	GCPSQLQuery        string

	// Refresh cache flag - force re-enumeration even if cache exists
	GCPRefreshCache bool

	// misc options
	// GCPIgnoreCache		bool

	// logger
	GCPLogger = internal.NewLogger()

	// GCP root command
	GCPCommands = &cobra.Command{
		Use:     "gcp",
		Aliases: []string{"gcloud"},
		Long:    `See "Available Commands" for GCP Modules below`,
		Short:   "See \"Available Commands\" for GCP Modules below",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Reset project IDs and names to avoid accumulation across commands
			GCPProjectIDs = nil
			GCPProjectNames = make(map[string]string)

			// Create session based on auth flags.
			// Allowed combinations:
			//   --access-token                        (raw token)
			//   --key-file                            (SA key file)
			//   --impersonate-sa                      (impersonate over ADC)
			//   --access-token  + --impersonate-sa    (impersonate using token as base)
			//   --key-file      + --impersonate-sa    (impersonate using key as base)
			// Disallowed: --access-token + --key-file (both are base credentials)
			var gcpSession *gcpinternal.SafeSession

			if GCPAccessToken != "" && GCPKeyFile != "" {
				GCPLogger.FatalM("--access-token and --key-file cannot be used together (both are base credentials)", "gcp")
			}

			// Step 1: Create base session from access-token or key-file (if provided)
			var baseSession *gcpinternal.SafeSession
			if GCPAccessToken != "" {
				os.Unsetenv("GOOGLE_CLOUD_QUOTA_PROJECT")
				GCPLogger.InfoM("Authenticating with provided access token...", "gcp")
				var err error
				baseSession, err = gcpinternal.NewSafeSessionFromAccessToken(context.Background(), GCPAccessToken)
				if err != nil {
					GCPLogger.FatalM(fmt.Sprintf("Failed to authenticate with access token: %v", err), "gcp")
				}
				email := baseSession.GetEmail()
				if email != "" {
					GCPLogger.SuccessM(fmt.Sprintf("Authenticated as %s (from access token)", email), "gcp")
				} else {
					GCPLogger.SuccessM("Authenticated with access token (identity unknown)", "gcp")
				}
			} else if GCPKeyFile != "" {
				os.Unsetenv("GOOGLE_CLOUD_QUOTA_PROJECT")
				GCPLogger.InfoM(fmt.Sprintf("Authenticating with key file: %s", GCPKeyFile), "gcp")
				var err error
				baseSession, err = gcpinternal.NewSafeSessionFromKeyFile(context.Background(), GCPKeyFile)
				if err != nil {
					GCPLogger.FatalM(fmt.Sprintf("Failed to authenticate with key file %s: %v", GCPKeyFile, err), "gcp")
				}
				GCPLogger.SuccessM(fmt.Sprintf("Authenticated as %s (from key file)", baseSession.GetEmail()), "gcp")
			}

			// Step 2: Layer impersonation on top (if requested)
			if GCPImpersonateSA != "" {
				os.Unsetenv("GOOGLE_CLOUD_QUOTA_PROJECT")
				var baseTS oauth2.TokenSource
				if baseSession != nil {
					baseTS = baseSession.GetTokenSource()
					GCPLogger.InfoM(fmt.Sprintf("Impersonating %s using %s as base credential...", GCPImpersonateSA, baseSession.GetEmail()), "gcp")
				} else {
					GCPLogger.InfoM(fmt.Sprintf("Impersonating service account: %s", GCPImpersonateSA), "gcp")
				}
				var err error
				gcpSession, err = gcpinternal.NewSafeSessionWithImpersonation(context.Background(), GCPImpersonateSA, baseTS)
				if err != nil {
					GCPLogger.FatalM(fmt.Sprintf("Failed to impersonate %s: %v", GCPImpersonateSA, err), "gcp")
				}
				GCPLogger.SuccessM(fmt.Sprintf("Successfully impersonating %s", GCPImpersonateSA), "gcp")
			} else if baseSession != nil {
				// No impersonation, use the base session directly
				gcpSession = baseSession
			} else {
				// Set quota project for GCP API calls. ADC may reference a deleted
				// or inaccessible quota project, causing all API calls to fail with
				// 403/404. Override it with the target project when known.
				if GCPProjectID != "" {
					os.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", GCPProjectID)
				} else if GCPProjectIDsFilePath != "" {
					lines := internal.LoadFileLinesIntoArray(GCPProjectIDsFilePath)
					if len(lines) > 0 {
						os.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", lines[0])
					}
				} else if GCPAllProjects {
					// No target project yet. Validate the ADC quota project
					// and clear it if the project is inaccessible.
					validateADCQuotaProject()
				}
			}

			// Handle project discovery based on flags
			// Priority: -p (single project) > -l (project list) > -A (all projects)
			if GCPProjectID != "" {
				// Single project specified with -p/--project
				GCPProjectIDs = append(GCPProjectIDs, GCPProjectID)
				resolveProjectNames(GCPProjectIDs, gcpSession)
			} else if GCPProjectIDsFilePath != "" {
				// Project list specified with -l/--project-list
				rawProjectIDs := internal.LoadFileLinesIntoArray(GCPProjectIDsFilePath)
				GCPProjectIDs = deduplicateProjectIDs(rawProjectIDs)
				resolveProjectNames(GCPProjectIDs, gcpSession)
			} else if GCPAllProjects {
				// Discover all accessible projects with -A/--all-projects
				GCPLogger.InfoM("Discovering all accessible projects...", "gcp")
				orgsSvc := newOrgsService(gcpSession)
				var projects []orgsservice.ProjectInfo
				err := gcpinternal.RetryWithBackoff(GCPLogger, "gcp", 3, func() error {
					var searchErr error
					projects, searchErr = orgsSvc.SearchProjects("")
					return searchErr
				})
				if err != nil {
					GCPLogger.FatalM(fmt.Sprintf("Failed to discover projects: %v. Try using -p or -l flags instead.", err), "gcp")
				}
				for _, proj := range projects {
					if proj.State == "ACTIVE" {
						GCPProjectIDs = append(GCPProjectIDs, proj.ProjectID)
						GCPProjectNames[proj.ProjectID] = proj.DisplayName
					}
				}
				if len(GCPProjectIDs) == 0 {
					GCPLogger.FatalM("No accessible projects found. Check your permissions.", "gcp")
				}
				GCPLogger.InfoM(fmt.Sprintf("Discovered %d project(s)", len(GCPProjectIDs)), "gcp")
			} else {
				GCPLogger.InfoM("No project scope specified. Use -p, -l, or -A flag.", "gcp")
			}

			// Create a context with project IDs and names
			ctx := context.WithValue(context.Background(), "projectIDs", GCPProjectIDs)
			ctx = context.WithValue(ctx, "projectNames", GCPProjectNames)

			// Set default session so all services pick up impersonation
			if gcpSession != nil {
				gcpinternal.SetDefaultSession(gcpSession)
			}

			// Set global query filter if --query or --sqlquery flag is provided
			if GCPQuery != "" && GCPSQLQuery != "" {
				GCPLogger.FatalM("--query and --sqlquery cannot be used together", "gcp")
			}
			if GCPQuery != "" {
				internal.SetQueryFilter(GCPQuery)
			}
			if GCPSQLQuery != "" {
				internal.SetSQLQueryFilter(GCPSQLQuery)
			}

			// Authenticate and get account info.
			// Check impersonation first since it overrides the effective identity
			// even when combined with --access-token or --key-file.
			if GCPImpersonateSA != "" {
				ctx = context.WithValue(ctx, "account", GCPImpersonateSA)
			} else if GCPAccessToken != "" {
				email := gcpSession.GetEmail()
				if email == "" {
					email = "access-token-user"
				}
				ctx = context.WithValue(ctx, "account", email)
			} else if GCPKeyFile != "" {
				ctx = context.WithValue(ctx, "account", gcpSession.GetEmail())
			} else {
				os := oauthservice.NewOAuthService()
				principal, err := os.WhoAmI()
				if err != nil {
					GCPLogger.FatalM(fmt.Sprintf("could not determine default user credential with error %s.\n\nPlease use default application default credentials: https://cloud.google.com/docs/authentication/application-default-credentials\n\nTry: gcloud auth application-default login", err.Error()), "gcp")
				}
				ctx = context.WithValue(ctx, "account", principal.Email)
			}

			// Build scope hierarchy for hierarchical output (unless --flat-output is set)
			if !GCPFlatOutput && len(GCPProjectIDs) > 0 {
				GCPLogger.InfoM("Building scope hierarchy for hierarchical output...", "gcp")
				orgsSvc := newOrgsService(gcpSession)
				provider := orgsservice.NewHierarchyProvider(orgsSvc)
				hierarchy, err := gcpinternal.BuildScopeHierarchy(GCPProjectIDs, provider)
				if err != nil {
					GCPLogger.InfoM(fmt.Sprintf("Could not build hierarchy, using flat output: %v", err), "gcp")
				} else {
					ctx = context.WithValue(ctx, "hierarchy", hierarchy)
					// Log hierarchy summary
					if len(hierarchy.Organizations) > 0 {
						GCPLogger.InfoM(fmt.Sprintf("Detected %d organization(s), %d project(s)", len(hierarchy.Organizations), len(hierarchy.Projects)), "gcp")
					} else {
						GCPLogger.InfoM(fmt.Sprintf("Detected %d standalone project(s)", len(hierarchy.StandaloneProjs)), "gcp")
					}
				}
			}

			// Get account for cache operations
			account, _ := ctx.Value("account").(string)

			// Always try to load FoxMapper data for attack path analysis
			// This allows individual modules to show the Attack Paths column
			if len(GCPProjectIDs) > 0 {
				// Get org ID from hierarchy if available (GCPOrganization flag may be empty)
				orgID := GCPOrganization
				if orgID == "" {
					if hierarchy, ok := ctx.Value("hierarchy").(*gcpinternal.ScopeHierarchy); ok && hierarchy != nil {
						if len(hierarchy.Organizations) > 0 {
							orgID = hierarchy.Organizations[0].ID
						}
					}
				}

				foxMapperCache := gcpinternal.TryLoadFoxMapper(orgID, GCPProjectIDs)
				if foxMapperCache != nil && foxMapperCache.IsPopulated() {
					ctx = gcpinternal.SetFoxMapperCacheInContext(ctx, foxMapperCache)
					totalNodes, adminNodes, nodesWithPrivesc := foxMapperCache.GetStats()
					ageDays := foxMapperCache.GetDataAgeDays()

					if ageDays >= 30 {
						GCPLogger.WarnM(fmt.Sprintf("FoxMapper data is %d days old - consider running 'foxmapper gcp graph create' to refresh",
							ageDays), "gcp")
					} else {
						GCPLogger.InfoM(fmt.Sprintf("FoxMapper data is %d days old", ageDays), "gcp")
					}
					GCPLogger.SuccessM(fmt.Sprintf("FoxMapper data loaded: %d principals, %d admins, %d with privesc",
						totalNodes, adminNodes, nodesWithPrivesc), "gcp")
				}
			}

			// Always try to load org cache for cross-project analysis
			// Cache auto-refreshes after 24 hours
			// Force refresh when running the organizations command to ensure fresh data
			refreshCache := GCPRefreshCache || cmd.Name() == "organizations"
			orgCache := loadOrPopulateOrgCache(account, refreshCache, gcpSession)
			if orgCache != nil && orgCache.IsPopulated() {
				ctx = gcpinternal.SetOrgCacheInContext(ctx, orgCache)
			}

			cmd.SetContext(ctx)
		},
	}
)

// newOrgsService creates an organizations service, using the impersonated session if provided
func newOrgsService(session *gcpinternal.SafeSession) *orgsservice.OrganizationsService {
	if session != nil {
		return orgsservice.NewWithSession(session)
	}
	return orgsservice.New()
}

// deduplicateProjectIDs removes duplicates, trims whitespace, and filters empty entries
func deduplicateProjectIDs(projectIDs []string) []string {
	seen := make(map[string]bool)
	var result []string
	duplicateCount := 0

	for _, id := range projectIDs {
		// Trim whitespace
		id = strings.TrimSpace(id)

		// Skip empty lines
		if id == "" {
			continue
		}

		// Skip duplicates
		if seen[id] {
			duplicateCount++
			continue
		}

		seen[id] = true
		result = append(result, id)
	}

	if duplicateCount > 0 {
		GCPLogger.InfoM(fmt.Sprintf("Removed %d duplicate project ID(s) from list", duplicateCount), "gcp")
	}

	return result
}

// validateADCQuotaProject reads the ADC file and checks whether the configured
// quota project is accessible. The Go SDK sends x-goog-user-project on every
// request based on the ADC's quota_project_id. If that project is deleted or
// inaccessible, ALL API calls will fail with 403/404. This function detects
// that condition and clears the quota project so the SDK doesn't send the
// broken header. The caller is responsible for setting a valid quota project
// once a working project is discovered.
func validateADCQuotaProject() {
	creds, err := google.FindDefaultCredentials(context.Background())
	if err != nil || creds.JSON == nil {
		return
	}

	var adcFile struct {
		QuotaProject string `json:"quota_project_id"`
	}
	if err := json.Unmarshal(creds.JSON, &adcFile); err != nil || adcFile.QuotaProject == "" {
		return
	}

	// Proactively clear the quota project via env var override. If the ADC
	// quota project is valid, the SearchProjects call below will succeed and
	// we'll restore it. If it's broken, we've already fixed the problem.
	os.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", "")

	orgsSvc := orgsservice.New()
	projects, err := orgsSvc.SearchProjects("")
	if err != nil {
		// Can't validate. Leave it cleared (better than a known-broken value).
		GCPLogger.WarnM(fmt.Sprintf("Could not validate ADC quota project '%s': %v", adcFile.QuotaProject, err), "gcp")
		return
	}

	// Check if the original quota project is among accessible active projects
	for _, p := range projects {
		if p.ProjectID == adcFile.QuotaProject && p.State == "ACTIVE" {
			// Original quota project is valid, restore it
			os.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", adcFile.QuotaProject)
			return
		}
	}

	// Original quota project is not accessible. Pick the first active project.
	GCPLogger.WarnM(fmt.Sprintf("ADC quota project '%s' is not accessible or has been deleted. Overriding with first available project.", adcFile.QuotaProject), "gcp")
	for _, p := range projects {
		if p.State == "ACTIVE" {
			os.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", p.ProjectID)
			return
		}
	}
}

// resolveProjectNames fetches display names for given project IDs
func resolveProjectNames(projectIDs []string, session *gcpinternal.SafeSession) {
	if len(projectIDs) == 0 {
		return
	}

	orgsSvc := newOrgsService(session)
	// Fetch all accessible projects and build lookup map
	var projects []orgsservice.ProjectInfo
	err := gcpinternal.RetryWithBackoff(GCPLogger, "gcp", 3, func() error {
		var searchErr error
		projects, searchErr = orgsSvc.SearchProjects("")
		return searchErr
	})
	if err != nil {
		// Non-fatal: we can continue without display names
		GCPLogger.InfoM("Could not resolve project names, using project IDs only", "gcp")
		for _, id := range projectIDs {
			GCPProjectNames[id] = id // fallback to using ID as name
		}
		return
	}

	// Build lookup from fetched projects
	projectLookup := make(map[string]string)
	for _, proj := range projects {
		projectLookup[proj.ProjectID] = proj.DisplayName
	}

	// Map our project IDs to names
	for _, id := range projectIDs {
		if name, ok := projectLookup[id]; ok {
			GCPProjectNames[id] = name
		} else {
			GCPProjectNames[id] = id // fallback to using ID as name
		}
	}
}

// New RunAllGCPCommands function to execute all child commands
var GCPAllChecksCommand = &cobra.Command{
	Use:   "all-checks",
	Short: "Runs all available GCP commands",
	Long:  `Executes all available GCP commands to collect and display information from all supported GCP services.`,
	Run: func(cmd *cobra.Command, args []string) {
		var executedModules []string
		startTime := time.Now()
		ctx := cmd.Context()
		account, _ := ctx.Value("account").(string)

		// Set all-checks mode - individual modules will skip saving cache
		// (we'll save consolidated cache at the end)
		ctx = gcpinternal.SetAllChecksMode(ctx, true)
		cmd.SetContext(ctx)

		// Get session from context for impersonation support
		var allChecksSession *gcpinternal.SafeSession
		if s, ok := ctx.Value("session").(*gcpinternal.SafeSession); ok {
			allChecksSession = s
		}

		// Load or populate org cache for cross-project modules
		existingOrgCache := gcpinternal.GetOrgCacheFromContext(ctx)
		if existingOrgCache == nil || !existingOrgCache.IsPopulated() {
			GCPLogger.InfoM("Loading/enumerating organization data for cross-project analysis...", "all-checks")
			orgCache := loadOrPopulateOrgCache(account, GCPRefreshCache, allChecksSession)
			if orgCache != nil && orgCache.IsPopulated() {
				ctx = gcpinternal.SetOrgCacheInContext(ctx, orgCache)
				cmd.SetContext(ctx)
			}
		} else {
			orgs, folders, projects := existingOrgCache.GetStats()
			GCPLogger.InfoM(fmt.Sprintf("Using existing org cache: %d org(s), %d folder(s), %d project(s)", orgs, folders, projects), "all-checks")
		}

		// Find the privesc command to run first
		var privescCmd *cobra.Command
		for _, childCmd := range GCPCommands.Commands() {
			if childCmd.Use == "privesc" {
				privescCmd = childCmd
				break
			}
		}

		// Run privesc command first (produces output) and load FoxMapper data for other modules
		if privescCmd != nil {
			GCPLogger.InfoM("Running privilege escalation analysis first...", "all-checks")
			privescCmd.Run(cmd, args)
			executedModules = append(executedModules, "privesc")

			// After running privesc, try to load FoxMapper data for other modules
			existingFoxMapper := gcpinternal.GetFoxMapperCacheFromContext(ctx)
			if existingFoxMapper != nil && existingFoxMapper.IsPopulated() {
				totalNodes, adminNodes, nodesWithPrivesc := existingFoxMapper.GetStats()
				GCPLogger.InfoM(fmt.Sprintf("Using existing FoxMapper cache: %d principals, %d admins, %d with privesc", totalNodes, adminNodes, nodesWithPrivesc), "all-checks")
			} else {
				// Get org ID from org cache if available (GCPOrganization flag may be empty)
				orgID := GCPOrganization
				if orgID == "" {
					if orgCache := gcpinternal.GetOrgCacheFromContext(ctx); orgCache != nil && len(orgCache.Organizations) > 0 {
						orgID = orgCache.Organizations[0].ID
					}
				}

				// Try to load FoxMapper data
				foxMapperCache := gcpinternal.TryLoadFoxMapper(orgID, GCPProjectIDs)
				if foxMapperCache != nil && foxMapperCache.IsPopulated() {
					ctx = gcpinternal.SetFoxMapperCacheInContext(ctx, foxMapperCache)
					cmd.SetContext(ctx)
					totalNodes, adminNodes, nodesWithPrivesc := foxMapperCache.GetStats()
					GCPLogger.SuccessM(fmt.Sprintf("FoxMapper data loaded: %d principals, %d admins, %d with privesc", totalNodes, adminNodes, nodesWithPrivesc), "all-checks")
				} else {
					GCPLogger.InfoM("No FoxMapper data found. Run 'foxmapper gcp graph create' for attack path analysis.", "all-checks")
				}
			}
			GCPLogger.InfoM("", "all-checks")
		}

		// Modules excluded from all-checks (run separately, not part of standard enumeration)
		excludeFromAllChecks := map[string]bool{
			"privesc":        true, // Already ran above
			"storage-enum":   true, // Sensitive data enum modules (run separately)
			"logging-enum":   true,
			"bigquery-enum":  true,
			"bigtable-enum":  true,
			"spanner-enum":   true,
			"access-tokens":  true, // Local-only, no API calls
		}

		// Count total modules to execute (excluding self, hidden, and excluded modules)
		var modulesToRun []*cobra.Command
		for _, childCmd := range GCPCommands.Commands() {
			if childCmd == cmd { // Skip the run-all command itself
				continue
			}
			if childCmd.Hidden { // Skip hidden commands
				continue
			}
			if excludeFromAllChecks[childCmd.Use] {
				continue
			}
			modulesToRun = append(modulesToRun, childCmd)
		}
		totalModules := len(modulesToRun)

		GCPLogger.InfoM(fmt.Sprintf("Starting execution of %d modules...", totalModules), "all-checks")
		GCPLogger.InfoM("", "all-checks")

		for i, childCmd := range modulesToRun {
			GCPLogger.InfoM(fmt.Sprintf("[%d/%d] Running: %s", i+1, totalModules, childCmd.Use), "all-checks")
			childCmd.Run(cmd, args)
			executedModules = append(executedModules, childCmd.Use)
		}

		// Print summary
		duration := time.Since(startTime)
		printExecutionSummary(executedModules, duration)
	},
}

// loadOrPopulateOrgCache loads org cache from disk if available, or enumerates and saves it
func loadOrPopulateOrgCache(account string, forceRefresh bool, session *gcpinternal.SafeSession) *gcpinternal.OrgCache {
	// Check if cache exists and we're not forcing refresh
	if !forceRefresh && gcpinternal.OrgCacheExists(GCPOutputDirectory, account) {
		// Check if cache is stale (older than 24 hours)
		if gcpinternal.IsCacheStale(GCPOutputDirectory, account, "org", gcpinternal.DefaultCacheExpiration) {
			age, _ := gcpinternal.GetCacheAge(GCPOutputDirectory, account, "org")
			GCPLogger.InfoM(fmt.Sprintf("Org cache is stale (age: %s > 24h), refreshing...", formatDuration(age)), "gcp")
		} else {
			cache, metadata, err := gcpinternal.LoadOrgCacheFromFile(GCPOutputDirectory, account)
			if err == nil && cache != nil {
				age, _ := gcpinternal.GetCacheAge(GCPOutputDirectory, account, "org")
				GCPLogger.InfoM(fmt.Sprintf("Loaded org cache from disk (age: %s, %d projects)",
					formatDuration(age), metadata.TotalProjects), "gcp")
				return cache
			}
			if err != nil {
				GCPLogger.InfoM(fmt.Sprintf("Could not load org cache: %v, re-enumerating...", err), "gcp")
				// Delete corrupted cache file
				gcpinternal.DeleteCache(GCPOutputDirectory, account, "org")
			}
		}
	}

	// Enumerate and create cache
	cache := enumerateAndCacheOrgs(account, session)
	return cache
}

// enumerateAndCacheOrgs enumerates all orgs/folders/projects and saves to disk
func enumerateAndCacheOrgs(account string, session *gcpinternal.SafeSession) *gcpinternal.OrgCache {
	cache := gcpinternal.NewOrgCache()

	orgsSvc := newOrgsService(session)

	// Get all organizations
	var orgs []orgsservice.OrganizationInfo
	err := gcpinternal.RetryWithBackoff(GCPLogger, "gcp", 3, func() error {
		var searchErr error
		orgs, searchErr = orgsSvc.SearchOrganizations()
		return searchErr
	})
	if err == nil {
		for _, org := range orgs {
			cache.AddOrganization(gcpinternal.CachedOrganization{
				ID:          org.Name[len("organizations/"):], // Strip prefix
				Name:        org.Name,
				DisplayName: org.DisplayName,
				DirectoryID: org.DirectoryID,
				State:       org.State,
			})
		}
	}

	// Get all folders
	var folders []orgsservice.FolderInfo
	err = gcpinternal.RetryWithBackoff(GCPLogger, "gcp", 3, func() error {
		var searchErr error
		folders, searchErr = orgsSvc.SearchAllFolders()
		return searchErr
	})
	if err == nil {
		for _, folder := range folders {
			cache.AddFolder(gcpinternal.CachedFolder{
				ID:          folder.Name[len("folders/"):], // Strip prefix
				Name:        folder.Name,
				DisplayName: folder.DisplayName,
				Parent:      folder.Parent,
				State:       folder.State,
			})
		}
	}

	// Get all projects
	var projects []orgsservice.ProjectInfo
	err = gcpinternal.RetryWithBackoff(GCPLogger, "gcp", 3, func() error {
		var searchErr error
		projects, searchErr = orgsSvc.SearchProjects("")
		return searchErr
	})
	if err == nil {
		for _, project := range projects {
			// Extract project number from Name (format: "projects/123456789")
			projectNumber := ""
			if strings.HasPrefix(project.Name, "projects/") {
				projectNumber = strings.TrimPrefix(project.Name, "projects/")
			}
			cache.AddProject(gcpinternal.CachedProject{
				ID:          project.ProjectID,
				Number:      projectNumber,
				Name:        project.Name,
				DisplayName: project.DisplayName,
				Parent:      project.Parent,
				State:       project.State,
			})
		}
	}

	cache.MarkPopulated()

	// Save to disk
	err = gcpinternal.SaveOrgCacheToFile(cache, GCPOutputDirectory, account, "2.0.0")
	if err != nil {
		GCPLogger.InfoM(fmt.Sprintf("Could not save org cache to disk: %v", err), "gcp")
	} else {
		cacheDir := gcpinternal.GetCacheDirectory(GCPOutputDirectory, account)
		GCPLogger.InfoM(fmt.Sprintf("Org cache saved to %s", cacheDir), "gcp")
	}

	orgsCount, foldersCount, projectsCount := cache.GetStats()
	GCPLogger.InfoM(fmt.Sprintf("Organization cache populated: %d org(s), %d folder(s), %d project(s)",
		orgsCount, foldersCount, projectsCount), "gcp")

	return cache
}

// printExecutionSummary prints a summary of all executed modules
func printExecutionSummary(modules []string, duration time.Duration) {
	GCPLogger.InfoM("", "all-checks") // blank line
	GCPLogger.InfoM("════════════════════════════════════════════════════════════", "all-checks")
	GCPLogger.InfoM("                    EXECUTION SUMMARY                        ", "all-checks")
	GCPLogger.InfoM("════════════════════════════════════════════════════════════", "all-checks")
	GCPLogger.InfoM(fmt.Sprintf("Total modules executed: %d", len(modules)), "all-checks")
	GCPLogger.InfoM(fmt.Sprintf("Total execution time:   %s", formatDuration(duration)), "all-checks")
	GCPLogger.InfoM("", "all-checks")
	GCPLogger.InfoM("Modules executed:", "all-checks")

	// Print modules in columns for better readability
	const columnsPerRow = 4
	for i := 0; i < len(modules); i += columnsPerRow {
		row := "  "
		for j := i; j < i+columnsPerRow && j < len(modules); j++ {
			row += fmt.Sprintf("%-20s", modules[j])
		}
		GCPLogger.InfoM(row, "all-checks")
	}

	GCPLogger.InfoM("", "all-checks")
	GCPLogger.InfoM(fmt.Sprintf("Output directory: %s", GCPOutputDirectory), "all-checks")
	GCPLogger.InfoM("════════════════════════════════════════════════════════════", "all-checks")
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1f seconds", d.Seconds())
	} else if d < time.Hour {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

func init() {
	// Globals flags for the GCP commands

	// Allow selection of non-default account to be used when accessing gcloud API
	// TODO

	// Resource filtering options
	// GCPCommands.PersistentFlags().StringVarP(&GCPOrganization, "organization", "o", "", "Organization name or number, repetable")
	GCPCommands.PersistentFlags().StringVarP(&GCPProjectID, "project", "p", "", "GCP project ID")
	GCPCommands.PersistentFlags().StringVarP(&GCPProjectIDsFilePath, "project-list", "l", "", "Path to a file containing a list of project IDs separated by newlines")
	GCPCommands.PersistentFlags().BoolVarP(&GCPAllProjects, "all-projects", "A", false, "Automatically discover and target all accessible projects")
	// GCPCommands.PersistentFlags().BoolVarP(&GCPConfirm, "yes", "y", false, "Non-interactive mode (like apt/yum)")
	// GCPCommands.PersistentFlags().StringVarP(&GCPOutputFormat, "output", "", "brief", "[\"brief\" | \"wide\" ]")
	GCPCommands.PersistentFlags().IntVarP(&Verbosity, "verbosity", "v", 2, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	// defaultOutputDir is defined in cli.aws
	GCPCommands.PersistentFlags().StringVar(&GCPOutputDirectory, "outdir", defaultOutputDir, "Output Directory ")
	// GCPCommands.PersistentFlags().IntVarP(&Goroutines, "max-goroutines", "g", 30, "Maximum number of concurrent goroutines")
	GCPCommands.PersistentFlags().BoolVarP(&GCPWrapTable, "wrap", "w", false, "Wrap table to fit in terminal (complicates grepping)")
	GCPCommands.PersistentFlags().BoolVar(&GCPFlatOutput, "flat-output", false, "Use legacy flat output structure instead of hierarchical per-project directories")
	GCPCommands.PersistentFlags().BoolVar(&GCPRefreshCache, "refresh-cache", false, "Force re-enumeration of cached data (cache auto-expires after 24 hours)")
	GCPCommands.PersistentFlags().StringVarP(&GCPImpersonateSA, "impersonate-sa", "i", "", "Service account email to impersonate (requires roles/iam.serviceAccountTokenCreator)")
	GCPCommands.PersistentFlags().StringVarP(&GCPKeyFile, "key-file", "k", "", "Path to a service account JSON key file for authentication")
	GCPCommands.PersistentFlags().StringVar(&GCPAccessToken, "access-token", "", "Raw GCP access token for authentication (non-refreshable)")
	GCPCommands.PersistentFlags().StringVarP(&GCPQuery, "query", "q", "", "Filter output rows by substring match (e.g. \"Role:owner,Principal:privesc02\" or plain \"privesc02\")")
	GCPCommands.PersistentFlags().StringVar(&GCPSQLQuery, "sqlquery", "", "Filter output with SQL-like syntax (e.g. \"Role CONTAINS owner AND Principal CONTAINS privesc02\")")

	// Available commands
	GCPCommands.AddCommand(
		// Core/existing commands
		commands.GCPStorageCommand,
		commands.GCPArtifactRegistryCommand,
		commands.GCPBigQueryCommand,
		commands.GCPSecretsCommand,
		commands.GCPIAMCommand,
		commands.GCPPermissionsCommand,
		commands.GCPResourceIAMCommand,
		commands.GCPInstancesCommand,
		commands.GCPWhoAmICommand,

		// Compute/serverless commands
		commands.GCPFunctionsCommand,
		commands.GCPCloudRunCommand,
		commands.GCPAppEngineCommand,
		commands.GCPGKECommand,
		commands.GCPCloudSQLCommand,

		// New infrastructure commands
		commands.GCPPubSubCommand,
		commands.GCPKMSCommand,
		commands.GCPLoggingCommand,
		commands.GCPSchedulerCommand,
		commands.GCPDNSCommand,
		commands.GCPFirewallCommand,
		commands.GCPServiceAccountsCommand,
		commands.GCPKeysCommand,
		commands.GCPEndpointsCommand,
		commands.GCPWorkloadIdentityCommand,
		commands.GCPIdentityFederationCommand,
		commands.GCPOrganizationsCommand,
		commands.GCPCloudBuildCommand,
		commands.GCPMemorystoreCommand,
		commands.GCPFilestoreCommand,
		commands.GCPSpannerCommand,
		commands.GCPBigtableCommand,

		// Data processing commands
		commands.GCPDataflowCommand,
		commands.GCPComposerCommand,

		// Security/Compliance commands
		commands.GCPVPCSCCommand,
		commands.GCPAssetInventoryCommand,
		commands.GCPSecurityCenterCommand,
		commands.GCPComplianceDashboardCommand,
		commands.GCPBackupInventoryCommand,
		commands.GCPCostSecurityCommand,
		commands.GCPMonitoringAlertsCommand,

		// Network/Infrastructure commands
		commands.GCPLoadBalancersCommand,
		commands.GCPVPCNetworksCommand,
		commands.GCPNetworkTopologyCommand,

		// ML/Data Science commands
		commands.GCPNotebooksCommand,
		commands.GCPDataprocCommand,

		// Zero Trust/Access commands
		commands.GCPIAPCommand,
		commands.GCPBeyondCorpCommand,
		commands.GCPAccessLevelsCommand,

		// Pentest/Exploitation commands
		commands.GCPAccessTokensCommand,
		commands.GCPPrivescCommand,
		commands.GCPOrgPoliciesCommand,
		commands.GCPStorageEnumCommand,
		commands.GCPLoggingEnumCommand,
		commands.GCPBigQueryEnumCommand,
		commands.GCPBigtableEnumCommand,
		commands.GCPSpannerEnumCommand,
		commands.GCPCrossProjectCommand,
		commands.GCPSourceReposCommand,
		commands.GCPServiceAgentsCommand,
		commands.GCPDomainWideDelegationCommand,
		commands.GCPPrivateServiceConnectCommand,
		commands.GCPCloudArmorCommand,
		commands.GCPCertManagerCommand,
		commands.GCPLateralMovementCommand,
		commands.GCPDataExfiltrationCommand,
		commands.GCPPublicAccessCommand,
		commands.GCPFoxMapperCommand,

		// Inventory command
		commands.GCPInventoryCommand,

		// Hidden admin commands
		commands.GCPHiddenAdminsCommand,

		// All checks (last)
		GCPAllChecksCommand,
	)
}
