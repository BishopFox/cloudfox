package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	assetservice "github.com/BishopFox/cloudfox/gcp/services/assetService"
	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
	"google.golang.org/api/iterator"
)

var (
	assetTypes       []string
	showCounts       bool
	checkIAM         bool
	showDependencies bool
	showAll          bool
)

var GCPAssetInventoryCommand = &cobra.Command{
	Use:     globals.GCP_ASSET_INVENTORY_MODULE_NAME,
	Aliases: []string{"assets", "cai", "resource-graph"},
	Short:   "Deep asset analysis with IAM and dependencies (requires Cloud Asset API)",
	Long: `Deep resource analysis using Cloud Asset Inventory API.

USE THIS COMMAND WHEN:
- You need IAM policy analysis (public access detection)
- You want to analyze resource dependencies and cross-project relationships
- You need to filter by specific asset types
- Cloud Asset API is enabled in your projects

REQUIRES: Cloud Asset API (cloudasset.googleapis.com) to be enabled.
To enable: gcloud services enable cloudasset.googleapis.com --project=PROJECT_ID

If Cloud Asset API is not enabled, use 'inventory' command instead for a quick
overview that works without the API.

FEATURES:
- Lists all assets in a project (complete coverage via Asset API)
- Provides asset counts by type (--counts)
- Checks IAM policies for public access (--iam)
- Analyzes resource dependencies and cross-project relationships (--dependencies)
- Supports filtering by asset type (--types)
- Generates query templates for common security use cases

Flags can be combined to run multiple analyses in a single run.

Examples:
  cloudfox gcp asset-inventory -p my-project
  cloudfox gcp asset-inventory -p my-project --counts
  cloudfox gcp asset-inventory -p my-project --iam
  cloudfox gcp asset-inventory -p my-project --dependencies
  cloudfox gcp asset-inventory -p my-project --all
  cloudfox gcp asset-inventory -A --iam                    # All projects, check public access
  cloudfox gcp asset-inventory -p my-project --types compute.googleapis.com/Instance,storage.googleapis.com/Bucket`,
	Run: runGCPAssetInventoryCommand,
}

func init() {
	GCPAssetInventoryCommand.Flags().StringSliceVar(&assetTypes, "types", []string{}, "Filter by asset types (comma-separated)")
	GCPAssetInventoryCommand.Flags().BoolVar(&showCounts, "counts", false, "Show asset counts by type")
	GCPAssetInventoryCommand.Flags().BoolVar(&checkIAM, "iam", false, "Check IAM policies for public access")
	GCPAssetInventoryCommand.Flags().BoolVar(&showDependencies, "dependencies", false, "Analyze resource dependencies and cross-project relationships")
	GCPAssetInventoryCommand.Flags().BoolVar(&showAll, "all", false, "Run all analyses (counts, IAM, dependencies)")
}

// ResourceDependency represents a dependency between two resources
type ResourceDependency struct {
	SourceResource string
	SourceType     string
	TargetResource string
	TargetType     string
	DependencyType string // uses, references, contains
	ProjectID      string
}

// CrossProjectResource represents a resource accessed from multiple projects
type CrossProjectResource struct {
	ResourceName string
	ResourceType string
	OwnerProject string
	AccessedFrom []string
}

type AssetInventoryModule struct {
	gcpinternal.BaseGCPModule
	ProjectAssets       map[string][]assetservice.AssetInfo       // projectID -> assets
	ProjectTypeCounts   map[string][]assetservice.AssetTypeCount  // projectID -> counts
	ProjectDependencies map[string][]ResourceDependency          // projectID -> dependencies
	CrossProject        []CrossProjectResource                   // global (cross-project by nature)
	LootMap             map[string]map[string]*internal.LootFile // projectID -> loot files
	mu                  sync.Mutex
}

type AssetInventoryOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o AssetInventoryOutput) TableFiles() []internal.TableFile { return o.Table }
func (o AssetInventoryOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPAssetInventoryCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	if err != nil {
		return
	}

	module := &AssetInventoryModule{
		BaseGCPModule:       gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectAssets:       make(map[string][]assetservice.AssetInfo),
		ProjectTypeCounts:   make(map[string][]assetservice.AssetTypeCount),
		ProjectDependencies: make(map[string][]ResourceDependency),
		CrossProject:        []CrossProjectResource{},
		LootMap:             make(map[string]map[string]*internal.LootFile),
	}
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

func (m *AssetInventoryModule) getAllAssets() []assetservice.AssetInfo {
	var all []assetservice.AssetInfo
	for _, assets := range m.ProjectAssets {
		all = append(all, assets...)
	}
	return all
}

func (m *AssetInventoryModule) getAllTypeCounts() []assetservice.AssetTypeCount {
	// Merge counts from all projects
	countMap := make(map[string]int)
	for _, counts := range m.ProjectTypeCounts {
		for _, c := range counts {
			countMap[c.AssetType] += c.Count
		}
	}

	var all []assetservice.AssetTypeCount
	for assetType, count := range countMap {
		all = append(all, assetservice.AssetTypeCount{
			AssetType: assetType,
			Count:     count,
		})
	}
	return all
}

func (m *AssetInventoryModule) getAllDependencies() []ResourceDependency {
	var all []ResourceDependency
	for _, deps := range m.ProjectDependencies {
		all = append(all, deps...)
	}
	return all
}

func (m *AssetInventoryModule) initializeLootForProject(projectID string) {
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["asset-inventory-details"] = &internal.LootFile{
			Name:     "asset-inventory-details",
			Contents: "# Cloud Asset Inventory Details\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
		m.LootMap[projectID]["asset-inventory-commands"] = &internal.LootFile{
			Name:     "asset-inventory-commands",
			Contents: "# Cloud Asset Inventory Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}
}

func (m *AssetInventoryModule) Execute(ctx context.Context, logger internal.Logger) {
	// If --all is set, enable all flags
	if showAll {
		showCounts = true
		checkIAM = true
		showDependencies = true
	}

	// If no flags set, default to basic asset listing
	noFlagsSet := !showCounts && !checkIAM && !showDependencies

	// Run requested analyses
	if showCounts {
		m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ASSET_INVENTORY_MODULE_NAME, m.processProjectCounts)
	}

	if checkIAM {
		m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ASSET_INVENTORY_MODULE_NAME, m.processProjectIAM)
	} else if noFlagsSet {
		// Only run basic listing if no flags and IAM not requested (IAM includes basic info)
		m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ASSET_INVENTORY_MODULE_NAME, m.processProject)
	}

	if showDependencies {
		m.processProjectsDependencies(ctx, logger)
	}

	// Build summary message
	var summaryParts []string

	allTypeCounts := m.getAllTypeCounts()
	if len(allTypeCounts) > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d asset type(s)", len(allTypeCounts)))
	}

	allAssets := m.getAllAssets()
	if len(allAssets) > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d asset(s)", len(allAssets)))
	}

	if checkIAM {
		publicCount := 0
		for _, asset := range allAssets {
			if asset.PublicAccess {
				publicCount++
			}
		}
		if publicCount > 0 {
			summaryParts = append(summaryParts, fmt.Sprintf("%d with public access", publicCount))
		}
	}

	allDeps := m.getAllDependencies()
	if len(allDeps) > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d dependencies", len(allDeps)))
	}

	if len(m.CrossProject) > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d cross-project resources", len(m.CrossProject)))
	}

	if len(summaryParts) == 0 {
		logger.InfoM("No assets found", globals.GCP_ASSET_INVENTORY_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %s", strings.Join(summaryParts, ", ")), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	m.writeOutput(ctx, logger)
}

func (m *AssetInventoryModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating assets in project: %s", projectID), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	}

	m.mu.Lock()
	m.initializeLootForProject(projectID)
	m.mu.Unlock()

	svc := assetservice.New()
	assets, err := svc.ListAssets(projectID, assetTypes)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_ASSET_INVENTORY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate assets in project %s", projectID))
		return
	}

	m.mu.Lock()
	m.ProjectAssets[projectID] = append(m.ProjectAssets[projectID], assets...)
	for _, asset := range assets {
		m.addToLoot(projectID, asset)
	}
	m.mu.Unlock()
}

func (m *AssetInventoryModule) processProjectIAM(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating assets with IAM in project: %s", projectID), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	}

	m.mu.Lock()
	m.initializeLootForProject(projectID)
	m.mu.Unlock()

	svc := assetservice.New()
	assets, err := svc.ListAssetsWithIAM(projectID, assetTypes)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_ASSET_INVENTORY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate assets with IAM in project %s", projectID))
		return
	}

	m.mu.Lock()
	m.ProjectAssets[projectID] = append(m.ProjectAssets[projectID], assets...)
	for _, asset := range assets {
		m.addToLoot(projectID, asset)
	}
	m.mu.Unlock()
}

func (m *AssetInventoryModule) processProjectCounts(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Counting assets in project: %s", projectID), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	}

	m.mu.Lock()
	m.initializeLootForProject(projectID)
	m.mu.Unlock()

	svc := assetservice.New()
	counts, err := svc.GetAssetTypeCounts(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_ASSET_INVENTORY_MODULE_NAME,
			fmt.Sprintf("Could not count assets in project %s", projectID))
		return
	}

	m.mu.Lock()
	m.ProjectTypeCounts[projectID] = counts
	m.mu.Unlock()
}

// processProjectsDependencies analyzes assets with full dependency tracking
func (m *AssetInventoryModule) processProjectsDependencies(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Analyzing assets and dependencies...", globals.GCP_ASSET_INVENTORY_MODULE_NAME)

	assetClient, err := asset.NewClient(ctx)
	if err != nil {
		parsedErr := gcpinternal.ParseGCPError(err, "cloudasset.googleapis.com")
		gcpinternal.HandleGCPError(parsedErr, logger, globals.GCP_ASSET_INVENTORY_MODULE_NAME,
			"Could not create Cloud Asset client")
		return
	}
	defer assetClient.Close()

	var wg sync.WaitGroup
	for _, projectID := range m.ProjectIDs {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()
			m.processProjectWithDependencies(ctx, project, assetClient, logger)
		}(projectID)
	}
	wg.Wait()

	// Analyze cross-project dependencies
	m.analyzeCrossProjectResources()

	// Generate query templates
	m.generateQueryTemplates()
}

func (m *AssetInventoryModule) processProjectWithDependencies(ctx context.Context, projectID string, assetClient *asset.Client, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing dependencies in project: %s", projectID), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	}

	m.mu.Lock()
	m.initializeLootForProject(projectID)
	m.mu.Unlock()

	parent := fmt.Sprintf("projects/%s", projectID)
	req := &assetpb.ListAssetsRequest{
		Parent:      parent,
		ContentType: assetpb.ContentType_RESOURCE,
		PageSize:    500,
	}

	it := assetClient.ListAssets(ctx, req)

	for {
		assetItem, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			m.CommandCounter.Error++
			parsedErr := gcpinternal.ParseGCPError(err, "cloudasset.googleapis.com")
			gcpinternal.HandleGCPError(parsedErr, logger, globals.GCP_ASSET_INVENTORY_MODULE_NAME,
				fmt.Sprintf("Could not enumerate assets in project %s", projectID))
			break
		}

		// Convert to AssetInfo for consistency
		assetInfo := assetservice.AssetInfo{
			Name:      assetItem.Name,
			AssetType: assetItem.AssetType,
			ProjectID: projectID,
		}

		if assetItem.Resource != nil {
			assetInfo.Location = assetItem.Resource.Location
		}

		m.mu.Lock()
		m.ProjectAssets[projectID] = append(m.ProjectAssets[projectID], assetInfo)
		m.mu.Unlock()

		// Analyze dependencies
		m.analyzeAssetDependencies(assetItem, projectID)
	}
}

func (m *AssetInventoryModule) analyzeAssetDependencies(assetItem *assetpb.Asset, projectID string) {
	if assetItem.Resource == nil || assetItem.Resource.Data == nil {
		return
	}

	// Common dependency patterns
	dependencyFields := map[string]string{
		"network":        "uses",
		"subnetwork":     "uses",
		"serviceAccount": "uses",
		"disk":           "uses",
		"snapshot":       "references",
		"image":          "references",
		"keyRing":        "uses",
		"cryptoKey":      "uses",
		"topic":          "references",
		"subscription":   "references",
		"bucket":         "uses",
		"dataset":        "references",
		"cluster":        "contains",
	}

	for field, depType := range dependencyFields {
		if value, ok := assetItem.Resource.Data.Fields[field]; ok {
			targetResource := value.GetStringValue()
			if targetResource != "" {
				dependency := ResourceDependency{
					SourceResource: assetItem.Name,
					SourceType:     assetItem.AssetType,
					TargetResource: targetResource,
					TargetType:     m.inferResourceType(field),
					DependencyType: depType,
					ProjectID:      projectID,
				}

				m.mu.Lock()
				m.ProjectDependencies[projectID] = append(m.ProjectDependencies[projectID], dependency)
				m.mu.Unlock()
			}
		}
	}
}

func (m *AssetInventoryModule) inferResourceType(fieldName string) string {
	typeMap := map[string]string{
		"network":        "compute.googleapis.com/Network",
		"subnetwork":     "compute.googleapis.com/Subnetwork",
		"serviceAccount": "iam.googleapis.com/ServiceAccount",
		"disk":           "compute.googleapis.com/Disk",
		"snapshot":       "compute.googleapis.com/Snapshot",
		"image":          "compute.googleapis.com/Image",
		"keyRing":        "cloudkms.googleapis.com/KeyRing",
		"cryptoKey":      "cloudkms.googleapis.com/CryptoKey",
		"topic":          "pubsub.googleapis.com/Topic",
		"subscription":   "pubsub.googleapis.com/Subscription",
		"bucket":         "storage.googleapis.com/Bucket",
		"dataset":        "bigquery.googleapis.com/Dataset",
		"cluster":        "container.googleapis.com/Cluster",
	}

	if assetType, ok := typeMap[fieldName]; ok {
		return assetType
	}
	return "unknown"
}

func (m *AssetInventoryModule) analyzeCrossProjectResources() {
	m.mu.Lock()
	defer m.mu.Unlock()

	targetToSources := make(map[string][]string)
	targetToType := make(map[string]string)

	allDeps := m.getAllDependencies()
	for _, dep := range allDeps {
		targetProject := m.extractProjectFromResource(dep.TargetResource)
		if targetProject != "" && targetProject != dep.ProjectID {
			targetToSources[dep.TargetResource] = append(targetToSources[dep.TargetResource], dep.ProjectID)
			targetToType[dep.TargetResource] = dep.TargetType
		}
	}

	for target, sources := range targetToSources {
		crossProject := CrossProjectResource{
			ResourceName: target,
			ResourceType: targetToType[target],
			OwnerProject: m.extractProjectFromResource(target),
			AccessedFrom: sources,
		}

		m.CrossProject = append(m.CrossProject, crossProject)
	}
}

func (m *AssetInventoryModule) extractProjectFromResource(resource string) string {
	if strings.Contains(resource, "projects/") {
		parts := strings.Split(resource, "/")
		for i, part := range parts {
			if part == "projects" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

func (m *AssetInventoryModule) extractResourceName(resource string) string {
	parts := strings.Split(resource, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return resource
}

func (m *AssetInventoryModule) generateQueryTemplates() {
	templates := []struct {
		Name        string
		Description string
		Query       string
	}{
		{"Public Storage Buckets", "Find all public GCS buckets", `resource.type="storage.googleapis.com/Bucket" AND resource.data.iamConfiguration.uniformBucketLevelAccess.enabled=false`},
		{"VMs with External IPs", "Find compute instances with external IP addresses", `resource.type="compute.googleapis.com/Instance" AND resource.data.networkInterfaces.accessConfigs:*`},
		{"Service Account Keys", "Find all user-managed service account keys", `resource.type="iam.googleapis.com/ServiceAccountKey" AND resource.data.keyType="USER_MANAGED"`},
		{"Firewall Rules - Open to Internet", "Find firewall rules allowing 0.0.0.0/0", `resource.type="compute.googleapis.com/Firewall" AND resource.data.sourceRanges:"0.0.0.0/0"`},
		{"Cloud SQL - Public IPs", "Find Cloud SQL instances with public IP", `resource.type="sqladmin.googleapis.com/Instance" AND resource.data.settings.ipConfiguration.ipv4Enabled=true`},
		{"Unencrypted Disks", "Find disks without customer-managed encryption", `resource.type="compute.googleapis.com/Disk" AND NOT resource.data.diskEncryptionKey:*`},
		{"GKE Clusters - Legacy Auth", "Find GKE clusters with legacy authentication", `resource.type="container.googleapis.com/Cluster" AND resource.data.legacyAbac.enabled=true`},
	}

	// Add templates and export commands to each project's loot
	for _, projectID := range m.ProjectIDs {
		m.mu.Lock()
		m.initializeLootForProject(projectID)

		if lootFile := m.LootMap[projectID]["asset-inventory-commands"]; lootFile != nil {
			for _, t := range templates {
				lootFile.Contents += fmt.Sprintf(
					"# %s - %s\ngcloud asset search-all-resources --scope=projects/%s --query='%s'\n\n",
					t.Name, t.Description, projectID, t.Query,
				)
			}

			lootFile.Contents += "# Export complete asset inventory\n"
			lootFile.Contents += fmt.Sprintf(
				"gcloud asset export --project=%s --content-type=resource --output-path=gs://BUCKET_NAME/%s-assets.json\n",
				projectID, projectID,
			)
		}
		m.mu.Unlock()
	}
}

func (m *AssetInventoryModule) addToLoot(projectID string, asset assetservice.AssetInfo) {
	if lootFile := m.LootMap[projectID]["asset-inventory-details"]; lootFile != nil {
		lootFile.Contents += fmt.Sprintf(
			"# =============================================================================\n"+
				"# ASSET: %s\n"+
				"# =============================================================================\n"+
				"# Type: %s\n# Project: %s\n# Location: %s\n",
			asset.Name, asset.AssetType, asset.ProjectID, asset.Location)

		if asset.PublicAccess {
			lootFile.Contents += "# Public Access: Yes\n"
		}
		lootFile.Contents += "\n"
	}
}

func (m *AssetInventoryModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *AssetInventoryModule) buildCountsTable(counts []assetservice.AssetTypeCount) *internal.TableFile {
	if len(counts) == 0 {
		return nil
	}

	// Sort by count descending
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].Count > counts[j].Count
	})

	header := []string{"Asset Type", "Count"}
	var body [][]string
	for _, tc := range counts {
		body = append(body, []string{
			tc.AssetType,
			fmt.Sprintf("%d", tc.Count),
		})
	}

	return &internal.TableFile{
		Name:   "asset-counts",
		Header: header,
		Body:   body,
	}
}

func (m *AssetInventoryModule) buildAssetsTable(assets []assetservice.AssetInfo) []internal.TableFile {
	var tables []internal.TableFile
	if len(assets) == 0 {
		return tables
	}

	if checkIAM {
		header := []string{"Project", "Name", "Asset Type", "Location", "IAM Binding Role", "IAM Binding Principal", "Public"}
		var body [][]string
		for _, asset := range assets {
			publicAccess := "No"
			if asset.PublicAccess {
				publicAccess = "Yes"
			}

			if len(asset.IAMBindings) == 0 {
				body = append(body, []string{
					m.GetProjectName(asset.ProjectID),
					asset.Name,
					assetservice.ExtractAssetTypeShort(asset.AssetType),
					asset.Location,
					"-",
					"-",
					publicAccess,
				})
			} else {
				for _, binding := range asset.IAMBindings {
					for _, member := range binding.Members {
						body = append(body, []string{
							m.GetProjectName(asset.ProjectID),
							asset.Name,
							assetservice.ExtractAssetTypeShort(asset.AssetType),
							asset.Location,
							binding.Role,
							member,
							publicAccess,
						})
					}
				}
			}
		}
		tables = append(tables, internal.TableFile{
			Name:   "assets",
			Header: header,
			Body:   body,
		})

		// Public assets table
		var publicBody [][]string
		for _, asset := range assets {
			if asset.PublicAccess {
				for _, binding := range asset.IAMBindings {
					for _, member := range binding.Members {
						if shared.IsPublicPrincipal(member) {
							publicBody = append(publicBody, []string{
								m.GetProjectName(asset.ProjectID),
								asset.Name,
								asset.AssetType,
								binding.Role,
								member,
							})
						}
					}
				}
			}
		}

		if len(publicBody) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "public-assets",
				Header: []string{"Project", "Name", "Asset Type", "IAM Binding Role", "IAM Binding Principal"},
				Body:   publicBody,
			})
		}
	} else {
		header := []string{"Project", "Name", "Asset Type", "Location"}
		var body [][]string
		for _, asset := range assets {
			body = append(body, []string{
				m.GetProjectName(asset.ProjectID),
				asset.Name,
				assetservice.ExtractAssetTypeShort(asset.AssetType),
				asset.Location,
			})
		}
		tables = append(tables, internal.TableFile{
			Name:   "assets",
			Header: header,
			Body:   body,
		})
	}

	return tables
}

func (m *AssetInventoryModule) buildDependenciesTable(deps []ResourceDependency) *internal.TableFile {
	if len(deps) == 0 {
		return nil
	}

	depsHeader := []string{"Project", "Source", "Dependency Type", "Target", "Target Type"}
	var depsBody [][]string
	for _, d := range deps {
		depsBody = append(depsBody, []string{
			m.GetProjectName(d.ProjectID),
			m.extractResourceName(d.SourceResource),
			d.DependencyType,
			m.extractResourceName(d.TargetResource),
			assetservice.ExtractAssetTypeShort(d.TargetType),
		})
	}

	return &internal.TableFile{
		Name:   "asset-dependencies",
		Header: depsHeader,
		Body:   depsBody,
	}
}

func (m *AssetInventoryModule) buildCrossProjectTable() *internal.TableFile {
	if len(m.CrossProject) == 0 {
		return nil
	}

	crossHeader := []string{"Resource", "Type", "Owner Project", "Accessed From"}
	var crossBody [][]string
	for _, c := range m.CrossProject {
		crossBody = append(crossBody, []string{
			m.extractResourceName(c.ResourceName),
			assetservice.ExtractAssetTypeShort(c.ResourceType),
			c.OwnerProject,
			strings.Join(c.AccessedFrom, ", "),
		})
	}

	return &internal.TableFile{
		Name:   "cross-project-resources",
		Header: crossHeader,
		Body:   crossBody,
	}
}

func (m *AssetInventoryModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if counts, ok := m.ProjectTypeCounts[projectID]; ok {
		if table := m.buildCountsTable(counts); table != nil {
			tableFiles = append(tableFiles, *table)
		}
	}

	if assets, ok := m.ProjectAssets[projectID]; ok {
		tableFiles = append(tableFiles, m.buildAssetsTable(assets)...)
	}

	if deps, ok := m.ProjectDependencies[projectID]; ok {
		if table := m.buildDependenciesTable(deps); table != nil {
			tableFiles = append(tableFiles, *table)
		}
	}

	return tableFiles
}

func (m *AssetInventoryModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Get all project IDs that have data
	projectIDs := make(map[string]bool)
	for projectID := range m.ProjectAssets {
		projectIDs[projectID] = true
	}
	for projectID := range m.ProjectTypeCounts {
		projectIDs[projectID] = true
	}
	for projectID := range m.ProjectDependencies {
		projectIDs[projectID] = true
	}

	for projectID := range projectIDs {
		tableFiles := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = AssetInventoryOutput{Table: tableFiles, Loot: lootFiles}
	}

	// Add cross-project table at org level if we have hierarchy and cross-project data
	if crossTable := m.buildCrossProjectTable(); crossTable != nil && m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID := m.Hierarchy.Organizations[0].ID
		outputData.OrgLevelData[orgID] = AssetInventoryOutput{
			Table: []internal.TableFile{*crossTable},
			Loot:  nil,
		}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	}
}

func (m *AssetInventoryModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	var tables []internal.TableFile

	allCounts := m.getAllTypeCounts()
	if table := m.buildCountsTable(allCounts); table != nil {
		tables = append(tables, *table)
	}

	allAssets := m.getAllAssets()
	tables = append(tables, m.buildAssetsTable(allAssets)...)

	allDeps := m.getAllDependencies()
	if table := m.buildDependenciesTable(allDeps); table != nil {
		tables = append(tables, *table)
	}

	if table := m.buildCrossProjectTable(); table != nil {
		tables = append(tables, *table)
	}

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := AssetInventoryOutput{Table: tables, Loot: lootFiles}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}

	err := internal.HandleOutputSmart("gcp", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
		"project", m.ProjectIDs, scopeNames, m.Account, output)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	}
}
