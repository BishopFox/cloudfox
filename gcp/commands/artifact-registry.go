package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	ArtifactRegistryService "github.com/BishopFox/cloudfox/gcp/services/artifactRegistryService"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPArtifactRegistryCommand = &cobra.Command{
	Use:     globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME,
	Aliases: []string{"ar", "artifacts", "gcr"},
	Short:   "Enumerate GCP Artifact Registry and Container Registry with security configuration",
	Long: `Enumerate GCP Artifact Registry and legacy Container Registry (gcr.io) with security-relevant details.

Features:
- Lists all Artifact Registry repositories with security configuration
- Shows Docker images and package artifacts with tags and digests
- Enumerates IAM policies per repository and identifies public repositories
- Shows encryption type (Google-managed vs CMEK)
- Shows repository mode (standard, virtual, remote)
- Generates gcloud commands for artifact enumeration
- Generates exploitation commands for artifact access
- Enumerates legacy Container Registry (gcr.io) locations

Security Columns:
- Public: Whether the repository has allUsers or allAuthenticatedUsers access
- Encryption: "Google-managed" or "CMEK" (customer-managed keys)
- Mode: STANDARD_REPOSITORY, VIRTUAL_REPOSITORY, or REMOTE_REPOSITORY
- RegistryType: "artifact-registry" or "container-registry" (legacy gcr.io)`,
	Run: runGCPArtifactRegistryCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type ArtifactRegistryModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	ProjectArtifacts    map[string][]ArtifactRegistryService.ArtifactInfo    // projectID -> artifacts
	ProjectRepositories map[string][]ArtifactRegistryService.RepositoryInfo // projectID -> repos
	LootMap             map[string]map[string]*internal.LootFile             // projectID -> loot files
	client              *artifactregistry.Client
	mu                  sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type ArtifactRegistryOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ArtifactRegistryOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ArtifactRegistryOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPArtifactRegistryCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create Artifact Registry client
	client, err := artifactregistry.NewClient(cmdCtx.Ctx)
	if err != nil {
		cmdCtx.Logger.ErrorM(fmt.Sprintf("Failed to create Artifact Registry client: %v", err), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		return
	}
	defer client.Close()

	// Create module instance
	module := &ArtifactRegistryModule{
		BaseGCPModule:       gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectArtifacts:    make(map[string][]ArtifactRegistryService.ArtifactInfo),
		ProjectRepositories: make(map[string][]ArtifactRegistryService.RepositoryInfo),
		LootMap:             make(map[string]map[string]*internal.LootFile),
		client:              client,
	}

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *ArtifactRegistryModule) Execute(ctx context.Context, logger internal.Logger) {
	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME, m.processProject)

	allRepos := m.getAllRepositories()
	allArtifacts := m.getAllArtifacts()

	// Check results
	if len(allRepos) == 0 && len(allArtifacts) == 0 {
		logger.InfoM("No artifact registries found", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d repository(ies) with %d artifact(s)", len(allRepos), len(allArtifacts)), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// getAllRepositories returns all repositories from all projects
func (m *ArtifactRegistryModule) getAllRepositories() []ArtifactRegistryService.RepositoryInfo {
	var all []ArtifactRegistryService.RepositoryInfo
	for _, repos := range m.ProjectRepositories {
		all = append(all, repos...)
	}
	return all
}

// getAllArtifacts returns all artifacts from all projects
func (m *ArtifactRegistryModule) getAllArtifacts() []ArtifactRegistryService.ArtifactInfo {
	var all []ArtifactRegistryService.ArtifactInfo
	for _, artifacts := range m.ProjectArtifacts {
		all = append(all, artifacts...)
	}
	return all
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *ArtifactRegistryModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating artifact registries in project: %s", projectID), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	}

	// Create service and fetch data
	ars := ArtifactRegistryService.New(m.client)
	result, err := ars.RepositoriesAndArtifacts(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate artifact registries in project %s", projectID))
		return
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectRepositories[projectID] = result.Repositories
	m.ProjectArtifacts[projectID] = result.Artifacts

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["artifact-registry-commands"] = &internal.LootFile{
			Name:     "artifact-registry-commands",
			Contents: "# GCP Artifact Registry Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	// Generate loot for each repository and artifact
	for _, repo := range result.Repositories {
		m.addRepositoryToLoot(projectID, repo)
	}
	for _, artifact := range result.Artifacts {
		m.addArtifactToLoot(projectID, artifact)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d repository(ies) and %d artifact(s) in project %s", len(result.Repositories), len(result.Artifacts), projectID), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *ArtifactRegistryModule) addRepositoryToLoot(projectID string, repo ArtifactRegistryService.RepositoryInfo) {
	lootFile := m.LootMap[projectID]["artifact-registry-commands"]
	if lootFile == nil {
		return
	}

	// Extract repo name from full path
	repoName := repo.Name
	parts := strings.Split(repo.Name, "/")
	if len(parts) > 0 {
		repoName = parts[len(parts)-1]
	}

	// Handle legacy Container Registry differently
	if repo.RegistryType == "container-registry" {
		lootFile.Contents += fmt.Sprintf(
			"# =============================================================================\n"+
				"# LEGACY CONTAINER REGISTRY: %s\n"+
				"# =============================================================================\n"+
				"# Project: %s\n"+
				"# Note: Consider migrating to Artifact Registry\n"+
				"# Configure Docker authentication:\n"+
				"gcloud auth configure-docker %s\n"+
				"# List images:\n"+
				"gcloud container images list --repository=%s/%s\n"+
				"# Check for public access (via storage bucket):\n"+
				"gsutil iam get gs://artifacts.%s.appspot.com\n\n",
			repo.Name, repo.ProjectID,
			strings.Split(repo.Name, "/")[0], // gcr.io hostname
			strings.Split(repo.Name, "/")[0], repo.ProjectID,
			repo.ProjectID,
		)
		return
	}

	// Repository header and enumeration commands
	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# REPOSITORY: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s, Location: %s\n"+
			"# Format: %s, Mode: %s, Encryption: %s, Public: %s\n\n"+
			"# === ENUMERATION COMMANDS ===\n\n"+
			"# Describe repository:\n"+
			"gcloud artifacts repositories describe %s --project=%s --location=%s\n"+
			"# Get IAM policy:\n"+
			"gcloud artifacts repositories get-iam-policy %s --project=%s --location=%s\n",
		repoName, repo.ProjectID, repo.Location,
		repo.Format, repo.Mode, repo.EncryptionType, repo.PublicAccess,
		repoName, repo.ProjectID, repo.Location,
		repoName, repo.ProjectID, repo.Location,
	)

	// Docker-specific commands
	if repo.Format == "DOCKER" {
		lootFile.Contents += fmt.Sprintf(
			"# Configure Docker authentication:\n"+
				"gcloud auth configure-docker %s-docker.pkg.dev\n"+
				"# List images:\n"+
				"gcloud artifacts docker images list %s-docker.pkg.dev/%s/%s\n"+
				"# List vulnerabilities:\n"+
				"gcloud artifacts docker images list %s-docker.pkg.dev/%s/%s --show-occurrences --occurrence-filter=\"kind=VULNERABILITY\"\n",
			repo.Location,
			repo.Location, repo.ProjectID, repoName,
			repo.Location, repo.ProjectID, repoName,
		)
	}

	lootFile.Contents += "\n"
}

func (m *ArtifactRegistryModule) addArtifactToLoot(projectID string, artifact ArtifactRegistryService.ArtifactInfo) {
	lootFile := m.LootMap[projectID]["artifact-registry-commands"]
	if lootFile == nil {
		return
	}

	// Exploitation commands for Docker images
	if artifact.Format == "DOCKER" {
		imageBase := fmt.Sprintf("%s-docker.pkg.dev/%s/%s/%s",
			artifact.Location, artifact.ProjectID, artifact.Repository, artifact.Name)

		lootFile.Contents += fmt.Sprintf(
			"# -----------------------------------------------------------------------------\n"+
				"# DOCKER IMAGE: %s\n"+
				"# -----------------------------------------------------------------------------\n"+
				"# Project: %s, Repository: %s, Location: %s\n"+
				"# Digest: %s\n",
			artifact.Name,
			artifact.ProjectID,
			artifact.Repository, artifact.Location,
			artifact.Digest,
		)

		lootFile.Contents += "\n# === EXPLOIT COMMANDS ===\n\n"
		// Generate commands for each tag
		if len(artifact.Tags) > 0 {
			for _, tag := range artifact.Tags {
				lootFile.Contents += fmt.Sprintf(
					"# Tag: %s\n"+
						"docker pull %s:%s\n"+
						"docker inspect %s:%s\n"+
						"docker run -it --entrypoint /bin/sh %s:%s\n\n",
					tag,
					imageBase, tag,
					imageBase, tag,
					imageBase, tag,
				)
			}
		} else {
			// No tags, use digest
			lootFile.Contents += fmt.Sprintf(
				"# No tags - use digest\n"+
					"docker pull %s@%s\n"+
					"docker inspect %s@%s\n"+
					"docker run -it --entrypoint /bin/sh %s@%s\n\n",
				imageBase, artifact.Digest,
				imageBase, artifact.Digest,
				imageBase, artifact.Digest,
			)
		}
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *ArtifactRegistryModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Count public repos for finding message
	publicCount := 0
	for _, repos := range m.ProjectRepositories {
		for _, repo := range repos {
			if repo.IsPublic {
				publicCount++
			}
		}
	}
	if publicCount > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d publicly accessible repository(ies)!", publicCount), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	}

	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// getRepoHeader returns the header for repository table
func (m *ArtifactRegistryModule) getRepoHeader() []string {
	return []string{
		"Project",
		"Name",
		"Format",
		"Location",
		"Mode",
		"Public",
		"Encryption",
		"IAM Binding Role",
		"Principal Type",
		"IAM Binding Principal",
	}
}

// getArtifactHeader returns the header for artifact table
func (m *ArtifactRegistryModule) getArtifactHeader() []string {
	return []string{
		"Project",
		"Name",
		"Repository",
		"Location",
		"Tags",
		"Digest",
		"Size",
		"Uploaded",
	}
}

// reposToTableBody converts repositories to table body rows
func (m *ArtifactRegistryModule) reposToTableBody(repos []ArtifactRegistryService.RepositoryInfo) [][]string {
	var body [][]string
	for _, repo := range repos {
		// Extract repo name from full path
		repoName := repo.Name
		parts := strings.Split(repo.Name, "/")
		if len(parts) > 0 {
			repoName = parts[len(parts)-1]
		}

		// Format public access display
		publicDisplay := ""
		if repo.IsPublic {
			publicDisplay = repo.PublicAccess
		}

		// Shorten mode for display
		mode := repo.Mode
		mode = strings.TrimPrefix(mode, "REPOSITORY_MODE_")
		mode = strings.TrimSuffix(mode, "_REPOSITORY")

		// One row per IAM member
		if len(repo.IAMBindings) > 0 {
			for _, binding := range repo.IAMBindings {
				for _, member := range binding.Members {
					memberType := ArtifactRegistryService.GetMemberType(member)
					body = append(body, []string{
						m.GetProjectName(repo.ProjectID),
						repoName,
						repo.Format,
						repo.Location,
						mode,
						publicDisplay,
						repo.EncryptionType,
						binding.Role,
						memberType,
						member,
					})
				}
			}
		} else {
			// Repository with no IAM bindings
			body = append(body, []string{
				m.GetProjectName(repo.ProjectID),
				repoName,
				repo.Format,
				repo.Location,
				mode,
				publicDisplay,
				repo.EncryptionType,
				"-",
				"-",
				"-",
			})
		}
	}
	return body
}

// artifactsToTableBody converts artifacts to table body rows
func (m *ArtifactRegistryModule) artifactsToTableBody(artifacts []ArtifactRegistryService.ArtifactInfo) [][]string {
	var body [][]string
	for _, artifact := range artifacts {
		// Format tags
		tags := "-"
		if len(artifact.Tags) > 0 {
			if len(artifact.Tags) <= 3 {
				tags = strings.Join(artifact.Tags, ", ")
			} else {
				tags = fmt.Sprintf("%s (+%d more)", strings.Join(artifact.Tags[:3], ", "), len(artifact.Tags)-3)
			}
		}

		body = append(body, []string{
			m.GetProjectName(artifact.ProjectID),
			artifact.Name,
			artifact.Repository,
			artifact.Location,
			tags,
			artifact.Digest,
			artifact.SizeBytes,
			artifact.Uploaded,
		})
	}
	return body
}

// buildTablesForProject builds table files for a project
func (m *ArtifactRegistryModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if repos, ok := m.ProjectRepositories[projectID]; ok && len(repos) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   fmt.Sprintf("%s-repos", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME),
			Header: m.getRepoHeader(),
			Body:   m.reposToTableBody(repos),
		})
	}

	if artifacts, ok := m.ProjectArtifacts[projectID]; ok && len(artifacts) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   fmt.Sprintf("%s-artifacts", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME),
			Header: m.getArtifactHeader(),
			Body:   m.artifactsToTableBody(artifacts),
		})
	}

	return tableFiles
}

// writeHierarchicalOutput writes output to per-project directories
func (m *ArtifactRegistryModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	for projectID := range m.ProjectRepositories {
		tableFiles := m.buildTablesForProject(projectID)

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = ArtifactRegistryOutput{Table: tableFiles, Loot: lootFiles}
	}

	// Also add projects that only have artifacts
	for projectID := range m.ProjectArtifacts {
		if _, exists := outputData.ProjectLevelData[projectID]; !exists {
			tableFiles := m.buildTablesForProject(projectID)

			var lootFiles []internal.LootFile
			if projectLoot, ok := m.LootMap[projectID]; ok {
				for _, loot := range projectLoot {
					if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n") {
						lootFiles = append(lootFiles, *loot)
					}
				}
			}

			outputData.ProjectLevelData[projectID] = ArtifactRegistryOutput{Table: tableFiles, Loot: lootFiles}
		}
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
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *ArtifactRegistryModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allRepos := m.getAllRepositories()
	allArtifacts := m.getAllArtifacts()

	// Build table files
	tableFiles := []internal.TableFile{{
		Name:   fmt.Sprintf("%s-repos", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME),
		Header: m.getRepoHeader(),
		Body:   m.reposToTableBody(allRepos),
	}}

	if len(allArtifacts) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   fmt.Sprintf("%s-artifacts", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME),
			Header: m.getArtifactHeader(),
			Body:   m.artifactsToTableBody(allArtifacts),
		})
	}

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := ArtifactRegistryOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	// Write output using HandleOutputSmart with scope support
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
