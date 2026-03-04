package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	CloudRunService "github.com/BishopFox/cloudfox/gcp/services/cloudrunService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCloudRunCommand = &cobra.Command{
	Use:     globals.GCP_CLOUDRUN_MODULE_NAME,
	Aliases: []string{"run", "cr"},
	Short:   "Enumerate Cloud Run services and jobs with security analysis",
	Long: `Enumerate Cloud Run services and jobs across projects with security-relevant details.

Features:
- Lists all Cloud Run services and jobs
- Shows security configuration (ingress, VPC, service account)
- Identifies publicly invokable services (allUsers/allAuthenticatedUsers)
- Shows container image, resources, and scaling configuration
- Counts environment variables and secret references
- Generates gcloud commands for further analysis

Security Columns:
- Ingress: INGRESS_TRAFFIC_ALL (public), INTERNAL_ONLY, or INTERNAL_LOAD_BALANCER
- Public: Whether allUsers or allAuthenticatedUsers can invoke the service
- Service Account: The identity the service runs as
- SA Attack Paths: Privesc/exfil/lateral movement potential (run foxmapper first)
- VPC Access: Network connectivity to VPC resources
- Env Vars: Count of plain environment variables
- Secret Mgr: Count of env vars referencing Secret Manager (secure storage)
- Hardcoded: Detected secrets in env var VALUES (API keys, passwords, tokens)

Attack Surface:
- Public services with ALL ingress are internet-accessible
- Services with default service account may have excessive permissions
- VPC-connected services can access internal resources
- Container images may contain vulnerabilities or secrets
- Hardcoded secrets in env vars are a critical security risk

TIP: Run foxmapper first to populate the SA Attack Paths column.`,
	Run: runGCPCloudRunCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CloudRunModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields - per-project for hierarchical output
	ProjectServices map[string][]CloudRunService.ServiceInfo // projectID -> services
	ProjectJobs     map[string][]CloudRunService.JobInfo     // projectID -> jobs
	LootMap         map[string]map[string]*internal.LootFile // projectID -> loot files
	FoxMapperCache  *gcpinternal.FoxMapperCache              // FoxMapper graph data (preferred)
	mu              sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type CloudRunOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CloudRunOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CloudRunOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCloudRunCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CLOUDRUN_MODULE_NAME)
	if err != nil {
		return
	}

	module := &CloudRunModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectServices: make(map[string][]CloudRunService.ServiceInfo),
		ProjectJobs:     make(map[string][]CloudRunService.JobInfo),
		LootMap:         make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CloudRunModule) Execute(ctx context.Context, logger internal.Logger) {
	// Try to get FoxMapper cache (preferred - graph-based analysis)
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Using FoxMapper graph data for attack path analysis", globals.GCP_CLOUDRUN_MODULE_NAME)
	}

	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_CLOUDRUN_MODULE_NAME, m.processProject)

	// Get all resources for stats
	allServices := m.getAllServices()
	allJobs := m.getAllJobs()
	totalResources := len(allServices) + len(allJobs)
	if totalResources == 0 {
		logger.InfoM("No Cloud Run services or jobs found", globals.GCP_CLOUDRUN_MODULE_NAME)
		return
	}

	// Count public services
	publicCount := 0
	for _, svc := range allServices {
		if svc.IsPublic {
			publicCount++
		}
	}

	if publicCount > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d service(s), %d job(s), %d public", len(allServices), len(allJobs), publicCount), globals.GCP_CLOUDRUN_MODULE_NAME)
	} else {
		logger.SuccessM(fmt.Sprintf("Found %d service(s), %d job(s)", len(allServices), len(allJobs)), globals.GCP_CLOUDRUN_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// getAllServices returns all services from all projects (for statistics)
func (m *CloudRunModule) getAllServices() []CloudRunService.ServiceInfo {
	var all []CloudRunService.ServiceInfo
	for _, services := range m.ProjectServices {
		all = append(all, services...)
	}
	return all
}

// getAllJobs returns all jobs from all projects (for statistics)
func (m *CloudRunModule) getAllJobs() []CloudRunService.JobInfo {
	var all []CloudRunService.JobInfo
	for _, jobs := range m.ProjectJobs {
		all = append(all, jobs...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *CloudRunModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Cloud Run in project: %s", projectID), globals.GCP_CLOUDRUN_MODULE_NAME)
	}

	cs := CloudRunService.New()

	// Initialize loot for this project
	m.mu.Lock()
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["cloudrun-commands"] = &internal.LootFile{
			Name:     "cloudrun-commands",
			Contents: "# Cloud Run Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
		m.LootMap[projectID]["cloudrun-secret-refs"] = &internal.LootFile{
			Name:     "cloudrun-secret-refs",
			Contents: "# Cloud Run Secret Manager References\n# Generated by CloudFox\n# Use: gcloud secrets versions access VERSION --secret=SECRET_NAME --project=PROJECT\n\n",
		}
	}
	m.mu.Unlock()

	// Get services
	services, err := cs.Services(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDRUN_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Cloud Run services in project %s", projectID))
	} else {
		m.mu.Lock()
		m.ProjectServices[projectID] = services
		for _, svc := range services {
			m.addServiceToLoot(projectID, svc)
		}
		m.mu.Unlock()
	}

	// Get jobs
	jobs, err := cs.Jobs(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDRUN_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Cloud Run jobs in project %s", projectID))
	} else {
		m.mu.Lock()
		m.ProjectJobs[projectID] = jobs
		for _, job := range jobs {
			m.addJobToLoot(projectID, job)
		}
		m.mu.Unlock()
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d service(s), %d job(s) in project %s", len(services), len(jobs), projectID), globals.GCP_CLOUDRUN_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CloudRunModule) addServiceToLoot(projectID string, svc CloudRunService.ServiceInfo) {
	commandsLoot := m.LootMap[projectID]["cloudrun-commands"]
	secretRefsLoot := m.LootMap[projectID]["cloudrun-secret-refs"]

	if commandsLoot == nil {
		return
	}

	// All commands for this service
	commandsLoot.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# SERVICE: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s, Region: %s\n"+
			"# Image: %s\n"+
			"# Service Account: %s\n"+
			"# Public: %v\n"+
			"# URL: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe service:\n"+
			"gcloud run services describe %s --region=%s --project=%s\n"+
			"# Get IAM policy:\n"+
			"gcloud run services get-iam-policy %s --region=%s --project=%s\n"+
			"# List revisions:\n"+
			"gcloud run revisions list --service=%s --region=%s --project=%s\n\n"+
			"# === EXPLOIT COMMANDS ===\n\n"+
			"# Invoke the service (if you have run.routes.invoke):\n"+
			"curl -H \"Authorization: Bearer $(gcloud auth print-identity-token)\" %s\n\n",
		svc.Name, svc.ProjectID, svc.Region,
		svc.ContainerImage,
		svc.ServiceAccount,
		svc.IsPublic,
		svc.URL,
		svc.Name, svc.Region, svc.ProjectID,
		svc.Name, svc.Region, svc.ProjectID,
		svc.Name, svc.Region, svc.ProjectID,
		svc.URL,
	)

	// Add secret references to loot
	if len(svc.SecretRefs) > 0 && secretRefsLoot != nil {
		secretRefsLoot.Contents += fmt.Sprintf(
			"# =============================================================================\n"+
				"# SERVICE: %s (Project: %s, Region: %s)\n"+
				"# =============================================================================\n", svc.Name, svc.ProjectID, svc.Region)
		for _, ref := range svc.SecretRefs {
			if ref.Type == "env" {
				secretRefsLoot.Contents += fmt.Sprintf(
					"# Env var: %s\ngcloud secrets versions access %s --secret=%s --project=%s\n",
					ref.EnvVarName, ref.SecretVersion, ref.SecretName, svc.ProjectID,
				)
			} else {
				secretRefsLoot.Contents += fmt.Sprintf(
					"# Volume mount: %s\ngcloud secrets versions access latest --secret=%s --project=%s\n",
					ref.MountPath, ref.SecretName, svc.ProjectID,
				)
			}
		}
		secretRefsLoot.Contents += "\n"
	}
}

func (m *CloudRunModule) addJobToLoot(projectID string, job CloudRunService.JobInfo) {
	commandsLoot := m.LootMap[projectID]["cloudrun-commands"]
	secretRefsLoot := m.LootMap[projectID]["cloudrun-secret-refs"]

	if commandsLoot == nil {
		return
	}

	// All commands for this job
	commandsLoot.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# JOB: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s, Region: %s\n"+
			"# Image: %s\n"+
			"# Service Account: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe job:\n"+
			"gcloud run jobs describe %s --region=%s --project=%s\n"+
			"# List executions:\n"+
			"gcloud run jobs executions list --job=%s --region=%s --project=%s\n\n"+
			"# === EXPLOIT COMMANDS ===\n\n"+
			"# Execute the job (if you have run.jobs.run):\n"+
			"gcloud run jobs execute %s --region=%s --project=%s\n\n",
		job.Name, job.ProjectID, job.Region,
		job.ContainerImage,
		job.ServiceAccount,
		job.Name, job.Region, job.ProjectID,
		job.Name, job.Region, job.ProjectID,
		job.Name, job.Region, job.ProjectID,
	)

	// Add secret references to loot
	if len(job.SecretRefs) > 0 && secretRefsLoot != nil {
		secretRefsLoot.Contents += fmt.Sprintf(
			"# =============================================================================\n"+
				"# JOB: %s (Project: %s, Region: %s)\n"+
				"# =============================================================================\n", job.Name, job.ProjectID, job.Region)
		for _, ref := range job.SecretRefs {
			if ref.Type == "env" {
				secretRefsLoot.Contents += fmt.Sprintf(
					"# Env var: %s\ngcloud secrets versions access %s --secret=%s --project=%s\n",
					ref.EnvVarName, ref.SecretVersion, ref.SecretName, job.ProjectID,
				)
			} else {
				secretRefsLoot.Contents += fmt.Sprintf(
					"# Volume mount: %s\ngcloud secrets versions access latest --secret=%s --project=%s\n",
					ref.MountPath, ref.SecretName, job.ProjectID,
				)
			}
		}
		secretRefsLoot.Contents += "\n"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CloudRunModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// writeHierarchicalOutput writes output to per-project directories
func (m *CloudRunModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	// Build hierarchical output data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all project IDs that have data
	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectServices {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectJobs {
		projectsWithData[projectID] = true
	}

	// Build project-level outputs
	for projectID := range projectsWithData {
		services := m.ProjectServices[projectID]
		jobs := m.ProjectJobs[projectID]

		tables := m.buildTablesForProject(projectID, services, jobs)

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !isCloudRunEmptyLoot(loot.Contents) {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = CloudRunOutput{Table: tables, Loot: lootFiles}
	}

	// Create path builder using the module's hierarchy
	pathBuilder := m.BuildPathBuilder()

	// Write using hierarchical output
	err := internal.HandleHierarchicalOutputSmart(
		"gcp",
		m.Format,
		m.Verbosity,
		m.WrapTable,
		pathBuilder,
		outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_CLOUDRUN_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *CloudRunModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allServices := m.getAllServices()
	allJobs := m.getAllJobs()

	tables := m.buildTablesForProject("", allServices, allJobs)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !isCloudRunEmptyLoot(loot.Contents) {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := CloudRunOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CLOUDRUN_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// isCloudRunEmptyLoot checks if a loot file contains only the header
func isCloudRunEmptyLoot(contents string) bool {
	return strings.HasSuffix(contents, "# WARNING: Only use with proper authorization\n\n") ||
		strings.HasSuffix(contents, "# Use: gcloud secrets versions access VERSION --secret=SECRET_NAME --project=PROJECT\n\n")
}

// buildTablesForProject builds all tables for a given project's services and jobs
func (m *CloudRunModule) buildTablesForProject(projectID string, services []CloudRunService.ServiceInfo, jobs []CloudRunService.JobInfo) []internal.TableFile {
	tableFiles := []internal.TableFile{}

	// Services table
	servicesHeader := []string{
		"Project", "Type", "Name", "Region", "Status", "URL", "Ingress", "Public",
		"Service Account", "SA Attack Paths", "Default SA", "Image", "VPC Access",
		"Min/Max", "IAM Binding Role", "IAM Binding Principal",
	}

	var servicesBody [][]string
	for _, svc := range services {
		publicStatus := "No"
		if svc.IsPublic {
			publicStatus = "Yes"
		}
		defaultSA := "No"
		if svc.UsesDefaultSA {
			defaultSA = "Yes"
		}
		vpcAccess := "-"
		if svc.VPCAccess != "" {
			vpcAccess = extractName(svc.VPCAccess)
			if svc.VPCEgressSettings != "" {
				vpcAccess += fmt.Sprintf(" (%s)", strings.TrimPrefix(svc.VPCEgressSettings, "VPC_EGRESS_"))
			}
		}
		scaling := fmt.Sprintf("%d/%d", svc.MinInstances, svc.MaxInstances)

		status := svc.Status
		if status == "" {
			status = "-"
		}

		// Check attack paths (privesc/exfil/lateral) for the service account
		attackPaths := "run foxmapper"
		if svc.ServiceAccount != "" {
			attackPaths = gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, svc.ServiceAccount)
		} else if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
			attackPaths = "No SA"
		}

		// If service has IAM bindings, create one row per binding
		if len(svc.IAMBindings) > 0 {
			for _, binding := range svc.IAMBindings {
				servicesBody = append(servicesBody, []string{
					m.GetProjectName(svc.ProjectID), "Service", svc.Name, svc.Region, status, svc.URL,
					formatIngress(svc.IngressSettings), publicStatus, svc.ServiceAccount,
					attackPaths, defaultSA, svc.ContainerImage, vpcAccess, scaling,
					binding.Role, binding.Member,
				})
			}
		} else {
			// Service has no IAM bindings - single row
			servicesBody = append(servicesBody, []string{
				m.GetProjectName(svc.ProjectID), "Service", svc.Name, svc.Region, status, svc.URL,
				formatIngress(svc.IngressSettings), publicStatus, svc.ServiceAccount,
				attackPaths, defaultSA, svc.ContainerImage, vpcAccess, scaling,
				"-", "-",
			})
		}
	}

	if len(servicesBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_CLOUDRUN_MODULE_NAME + "-services",
			Header: servicesHeader,
			Body:   servicesBody,
		})
	}

	// Jobs table
	jobsHeader := []string{
		"Project", "Type", "Name", "Region", "Status", "Service Account", "SA Attack Paths", "Default SA",
		"Image", "VPC Access", "Tasks", "Parallelism", "Last Execution",
		"IAM Binding Role", "IAM Binding Principal",
	}

	var jobsBody [][]string
	for _, job := range jobs {
		defaultSA := "No"
		if job.UsesDefaultSA {
			defaultSA = "Yes"
		}
		lastExec := "-"
		if job.LastExecution != "" {
			lastExec = extractName(job.LastExecution)
		}

		status := job.Status
		if status == "" {
			status = "-"
		}

		vpcAccess := "-"
		if job.VPCAccess != "" {
			vpcAccess = extractName(job.VPCAccess)
			if job.VPCEgressSettings != "" {
				vpcAccess += fmt.Sprintf(" (%s)", strings.TrimPrefix(job.VPCEgressSettings, "VPC_EGRESS_"))
			}
		}

		// Check attack paths (privesc/exfil/lateral) for the service account
		jobAttackPaths := "run foxmapper"
		if job.ServiceAccount != "" {
			jobAttackPaths = gcpinternal.GetAttackSummaryFromCaches(m.FoxMapperCache, nil, job.ServiceAccount)
		} else if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
			jobAttackPaths = "No SA"
		}

		// If job has IAM bindings, create one row per binding
		if len(job.IAMBindings) > 0 {
			for _, binding := range job.IAMBindings {
				jobsBody = append(jobsBody, []string{
					m.GetProjectName(job.ProjectID), "Job", job.Name, job.Region, status,
					job.ServiceAccount, jobAttackPaths, defaultSA, job.ContainerImage, vpcAccess,
					fmt.Sprintf("%d", job.TaskCount), fmt.Sprintf("%d", job.Parallelism),
					lastExec, binding.Role, binding.Member,
				})
			}
		} else {
			// Job has no IAM bindings - single row
			jobsBody = append(jobsBody, []string{
				m.GetProjectName(job.ProjectID), "Job", job.Name, job.Region, status,
				job.ServiceAccount, jobAttackPaths, defaultSA, job.ContainerImage, vpcAccess,
				fmt.Sprintf("%d", job.TaskCount), fmt.Sprintf("%d", job.Parallelism),
				lastExec, "-", "-",
			})
		}
	}

	if len(jobsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_CLOUDRUN_MODULE_NAME + "-jobs",
			Header: jobsHeader,
			Body:   jobsBody,
		})
	}

	// Secrets table (includes hardcoded secrets and environment variables)
	secretsHeader := []string{
		"Project", "Resource Type", "Name", "Region", "Env Var", "Value/Type", "Source", "Sensitive",
	}

	var secretsBody [][]string

	// Add environment variables
	for _, svc := range services {
		for _, env := range svc.EnvVars {
			sensitive := isSensitiveEnvVar(env.Name)
			if env.Source == "direct" {
				secretsBody = append(secretsBody, []string{
					m.GetProjectName(svc.ProjectID), "Service",
					svc.Name, svc.Region, env.Name, env.Value, "EnvVar", sensitive,
				})
			} else {
				secretsBody = append(secretsBody, []string{
					m.GetProjectName(svc.ProjectID), "Service",
					svc.Name, svc.Region, env.Name, fmt.Sprintf("%s:%s", env.SecretName, env.SecretVersion), "SecretManager", sensitive,
				})
			}
		}
	}
	for _, job := range jobs {
		for _, env := range job.EnvVars {
			sensitive := isSensitiveEnvVar(env.Name)
			if env.Source == "direct" {
				secretsBody = append(secretsBody, []string{
					m.GetProjectName(job.ProjectID), "Job",
					job.Name, job.Region, env.Name, env.Value, "EnvVar", sensitive,
				})
			} else {
				secretsBody = append(secretsBody, []string{
					m.GetProjectName(job.ProjectID), "Job",
					job.Name, job.Region, env.Name, fmt.Sprintf("%s:%s", env.SecretName, env.SecretVersion), "SecretManager", sensitive,
				})
			}
		}
	}

	if len(secretsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_CLOUDRUN_MODULE_NAME + "-secrets",
			Header: secretsHeader,
			Body:   secretsBody,
		})
	}

	return tableFiles
}

// Helper functions

// formatIngress formats ingress settings for display
func formatIngress(ingress string) string {
	switch ingress {
	case "INGRESS_TRAFFIC_ALL":
		return "ALL (Public)"
	case "INGRESS_TRAFFIC_INTERNAL_ONLY":
		return "INTERNAL"
	case "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER":
		return "INT+LB"
	default:
		return ingress
	}
}

// extractName extracts just the name from a resource path
func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// sensitiveEnvVarPatterns contains patterns that indicate sensitive env vars
var sensitiveEnvVarPatterns = []string{
	"PASSWORD", "PASSWD", "SECRET", "API_KEY", "APIKEY", "API-KEY",
	"TOKEN", "ACCESS_TOKEN", "AUTH_TOKEN", "BEARER", "CREDENTIAL",
	"PRIVATE_KEY", "PRIVATEKEY", "CONNECTION_STRING", "CONN_STR",
	"DATABASE_URL", "DB_PASSWORD", "DB_PASS", "MYSQL_PASSWORD",
	"POSTGRES_PASSWORD", "REDIS_PASSWORD", "MONGODB_URI",
	"AWS_ACCESS_KEY", "AWS_SECRET", "AZURE_KEY", "GCP_KEY",
	"ENCRYPTION_KEY", "SIGNING_KEY", "JWT_SECRET", "SESSION_SECRET",
	"OAUTH", "CLIENT_SECRET",
}

// isSensitiveEnvVar checks if an environment variable name indicates sensitive data
func isSensitiveEnvVar(envName string) string {
	envNameUpper := strings.ToUpper(envName)
	for _, pattern := range sensitiveEnvVarPatterns {
		if strings.Contains(envNameUpper, pattern) {
			return "Yes"
		}
	}
	return "No"
}

