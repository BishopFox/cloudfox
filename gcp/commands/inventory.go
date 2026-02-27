package commands

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	apikeysservice "github.com/BishopFox/cloudfox/gcp/services/apikeysService"
	artifactregistryservice "github.com/BishopFox/cloudfox/gcp/services/artifactRegistryService"
	assetservice "github.com/BishopFox/cloudfox/gcp/services/assetService"
	bigqueryservice "github.com/BishopFox/cloudfox/gcp/services/bigqueryService"
	bigtableservice "github.com/BishopFox/cloudfox/gcp/services/bigtableService"
	certmanagerservice "github.com/BishopFox/cloudfox/gcp/services/certManagerService"
	cloudarmorservice "github.com/BishopFox/cloudfox/gcp/services/cloudArmorService"
	cloudbuildservice "github.com/BishopFox/cloudfox/gcp/services/cloudbuildService"
	cloudrunservice "github.com/BishopFox/cloudfox/gcp/services/cloudrunService"
	cloudsqlservice "github.com/BishopFox/cloudfox/gcp/services/cloudsqlService"
	cloudstorageservice "github.com/BishopFox/cloudfox/gcp/services/cloudStorageService"
	composerservice "github.com/BishopFox/cloudfox/gcp/services/composerService"
	computeengineservice "github.com/BishopFox/cloudfox/gcp/services/computeEngineService"
	dataflowservice "github.com/BishopFox/cloudfox/gcp/services/dataflowService"
	dataprocservice "github.com/BishopFox/cloudfox/gcp/services/dataprocService"
	dnsservice "github.com/BishopFox/cloudfox/gcp/services/dnsService"
	filestoreservice "github.com/BishopFox/cloudfox/gcp/services/filestoreService"
	functionsservice "github.com/BishopFox/cloudfox/gcp/services/functionsService"
	gkeservice "github.com/BishopFox/cloudfox/gcp/services/gkeService"
	iamservice "github.com/BishopFox/cloudfox/gcp/services/iamService"
	kmsservice "github.com/BishopFox/cloudfox/gcp/services/kmsService"
	loggingservice "github.com/BishopFox/cloudfox/gcp/services/loggingService"
	memorystoreservice "github.com/BishopFox/cloudfox/gcp/services/memorystoreService"
	notebooksservice "github.com/BishopFox/cloudfox/gcp/services/notebooksService"
	pubsubservice "github.com/BishopFox/cloudfox/gcp/services/pubsubService"
	schedulerservice "github.com/BishopFox/cloudfox/gcp/services/schedulerService"
	secretsservice "github.com/BishopFox/cloudfox/gcp/services/secretsService"
	sourcereposservice "github.com/BishopFox/cloudfox/gcp/services/sourceReposService"
	spannerservice "github.com/BishopFox/cloudfox/gcp/services/spannerService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
	serviceusage "google.golang.org/api/serviceusage/v1"
)

const GCP_INVENTORY_MODULE_NAME = "inventory"

var GCPInventoryCommand = &cobra.Command{
	Use:     GCP_INVENTORY_MODULE_NAME,
	Aliases: []string{"inv", "resources"},
	Short:   "Quick resource inventory - works without Cloud Asset API",
	Long: `Quick resource inventory that works even when Cloud Asset API is not enabled.

USE THIS COMMAND WHEN:
- You want a quick overview of resources across projects
- Cloud Asset API is not enabled in your projects
- You need a fallback that always works

For deep analysis with IAM policies and resource dependencies, use 'asset-inventory' instead
(requires Cloud Asset API to be enabled).

HOW IT WORKS:
1. Tries Cloud Asset API first (if enabled) for complete coverage
2. Falls back to Service Usage API to identify enabled services
3. Always runs dedicated CloudFox enumeration for security-relevant resources

This ensures you get results even in restricted environments where the
Cloud Asset API (cloudasset.googleapis.com) is not enabled.

OUTPUT INCLUDES:
- Resource counts by type (Compute instances, GKE clusters, Cloud Functions, etc.)
- Regional distribution of resources
- CloudFox coverage analysis (identifies potential blind spots)
- Total resource counts per project

SUPPORTED RESOURCE TYPES:
- Compute: Instances, Disks, Snapshots, Images
- Containers: GKE Clusters, Cloud Run Services/Jobs
- Serverless: Cloud Functions, App Engine
- Storage: Buckets, Filestore, BigQuery Datasets
- Databases: Cloud SQL, Spanner, Bigtable, Memorystore
- Networking: DNS Zones
- Security: Service Accounts, KMS Keys, Secrets, API Keys
- DevOps: Cloud Build Triggers, Source Repos, Artifact Registry
- Data: Pub/Sub Topics, Dataflow Jobs, Dataproc Clusters
- AI/ML: Notebooks, Composer Environments

Examples:
  cloudfox gcp inventory -p my-project
  cloudfox gcp inventory -A                  # All accessible projects`,
	Run: runGCPInventoryCommand,
}

// ResourceCount tracks count of a resource type per region
type ResourceCount struct {
	ResourceType string
	Region       string
	Count        int
	ResourceIDs  []string // For loot file
}

// AssetTypeSummary holds Cloud Asset Inventory counts by type
type AssetTypeSummary struct {
	AssetType string
	Count     int
	Covered   bool // Whether CloudFox has a dedicated module for this type
}

// InventoryModule handles resource inventory enumeration
type InventoryModule struct {
	gcpinternal.BaseGCPModule

	// Resource tracking (from dedicated enumeration) - NOW PER PROJECT
	projectResourceCounts map[string]map[string]map[string]int      // projectID -> resourceType -> region -> count
	projectResourceIDs    map[string]map[string]map[string][]string // projectID -> resourceType -> region -> []resourceID
	projectRegions        map[string]map[string]bool                // projectID -> regions with resources
	mu                    sync.Mutex

	// Asset Inventory tracking (complete coverage)
	assetCounts         map[string]map[string]int // projectID -> assetType -> count
	assetAPIEnabled     bool                      // Whether any project had Asset API enabled
	assetAPIFailedProjs []string                  // Projects where Asset API failed

	// Service Usage tracking (fallback when Asset API not available)
	enabledServices map[string][]string // projectID -> list of enabled services

	// Totals (per project)
	projectTotalByType   map[string]map[string]int // projectID -> resourceType -> count
	projectTotalByRegion map[string]map[string]int // projectID -> region -> count
	projectGrandTotal    map[string]int            // projectID -> total count

	// Global totals
	grandTotal int

	// Asset totals
	assetGrandTotal int
}

// InventoryOutput implements CloudfoxOutput interface
type InventoryOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o InventoryOutput) TableFiles() []internal.TableFile { return o.Table }
func (o InventoryOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPInventoryCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_INVENTORY_MODULE_NAME)
	if err != nil {
		return
	}

	module := &InventoryModule{
		BaseGCPModule:         gcpinternal.NewBaseGCPModule(cmdCtx),
		projectResourceCounts: make(map[string]map[string]map[string]int),
		projectResourceIDs:    make(map[string]map[string]map[string][]string),
		projectRegions:        make(map[string]map[string]bool),
		projectTotalByType:    make(map[string]map[string]int),
		projectTotalByRegion:  make(map[string]map[string]int),
		projectGrandTotal:     make(map[string]int),
		assetCounts:           make(map[string]map[string]int),
		enabledServices:       make(map[string][]string),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

func (m *InventoryModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Starting resource inventory enumeration...", GCP_INVENTORY_MODULE_NAME)

	// Initialize resource type maps for each project
	for _, projectID := range m.ProjectIDs {
		m.initializeResourceTypesForProject(projectID)
	}

	// First, get complete asset counts from Cloud Asset Inventory API
	// This provides comprehensive coverage of ALL resources
	logger.InfoM("Querying Cloud Asset Inventory for complete resource coverage...", GCP_INVENTORY_MODULE_NAME)
	m.collectAssetInventory(ctx, logger)

	// If Asset Inventory API failed, try Service Usage API as a fallback
	// This shows which services are enabled (indicates potential resources)
	if !m.assetAPIEnabled {
		logger.InfoM("Falling back to Service Usage API to identify enabled services...", GCP_INVENTORY_MODULE_NAME)
		m.collectEnabledServices(ctx, logger)
	}

	// Then run detailed enumeration for security-relevant resources
	// This always runs as a backup and provides security metadata
	logger.InfoM("Running detailed enumeration for security analysis...", GCP_INVENTORY_MODULE_NAME)
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, GCP_INVENTORY_MODULE_NAME, m.processProject)

	// Calculate totals
	m.calculateTotals()

	if m.grandTotal == 0 && m.assetGrandTotal == 0 && len(m.enabledServices) == 0 {
		logger.InfoM("No resources found", GCP_INVENTORY_MODULE_NAME)
		return
	}

	// Show summary based on what data we got
	if m.assetAPIEnabled {
		logger.SuccessM(fmt.Sprintf("Cloud Asset Inventory: %d total resources across %d asset types",
			m.assetGrandTotal, m.countAssetTypes()), GCP_INVENTORY_MODULE_NAME)
	} else if len(m.enabledServices) > 0 {
		totalServices := 0
		for _, services := range m.enabledServices {
			totalServices += len(services)
		}
		logger.SuccessM(fmt.Sprintf("Service Usage API: %d enabled services detected (may contain resources CloudFox doesn't enumerate)",
			totalServices), GCP_INVENTORY_MODULE_NAME)
	}
	logger.SuccessM(fmt.Sprintf("CloudFox enumeration: %d resources across %d project(s) (with security metadata)",
		m.grandTotal, len(m.projectGrandTotal)), GCP_INVENTORY_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// initializeResourceTypes sets up the resource type maps for a project
func (m *InventoryModule) initializeResourceTypesForProject(projectID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.projectResourceCounts[projectID] != nil {
		return // Already initialized
	}

	m.projectResourceCounts[projectID] = make(map[string]map[string]int)
	m.projectResourceIDs[projectID] = make(map[string]map[string][]string)
	m.projectRegions[projectID] = make(map[string]bool)
	m.projectTotalByType[projectID] = make(map[string]int)
	m.projectTotalByRegion[projectID] = make(map[string]int)
}

// processProject enumerates all resources in a single project
func (m *InventoryModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating resources in project: %s", projectID), GCP_INVENTORY_MODULE_NAME)
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit concurrent API calls per project

	// Compute resources
	wg.Add(1)
	go m.enumComputeInstances(ctx, projectID, &wg, semaphore)

	// GKE
	wg.Add(1)
	go m.enumGKEClusters(ctx, projectID, &wg, semaphore)

	// Cloud Run
	wg.Add(1)
	go m.enumCloudRun(ctx, projectID, &wg, semaphore)

	// Cloud Functions
	wg.Add(1)
	go m.enumCloudFunctions(ctx, projectID, &wg, semaphore)

	// Storage
	wg.Add(1)
	go m.enumBuckets(ctx, projectID, &wg, semaphore)

	// BigQuery
	wg.Add(1)
	go m.enumBigQuery(ctx, projectID, &wg, semaphore)

	// Cloud SQL
	wg.Add(1)
	go m.enumCloudSQL(ctx, projectID, &wg, semaphore)

	// Spanner
	wg.Add(1)
	go m.enumSpanner(ctx, projectID, &wg, semaphore)

	// Bigtable
	wg.Add(1)
	go m.enumBigtable(ctx, projectID, &wg, semaphore)

	// Memorystore
	wg.Add(1)
	go m.enumMemorystore(ctx, projectID, &wg, semaphore)

	// Filestore
	wg.Add(1)
	go m.enumFilestore(ctx, projectID, &wg, semaphore)

	// Service Accounts
	wg.Add(1)
	go m.enumServiceAccounts(ctx, projectID, &wg, semaphore)

	// KMS
	wg.Add(1)
	go m.enumKMS(ctx, projectID, &wg, semaphore)

	// Secrets
	wg.Add(1)
	go m.enumSecrets(ctx, projectID, &wg, semaphore)

	// API Keys
	wg.Add(1)
	go m.enumAPIKeys(ctx, projectID, &wg, semaphore)

	// Pub/Sub
	wg.Add(1)
	go m.enumPubSub(ctx, projectID, &wg, semaphore)

	// DNS
	wg.Add(1)
	go m.enumDNS(ctx, projectID, &wg, semaphore)

	// Cloud Build
	wg.Add(1)
	go m.enumCloudBuild(ctx, projectID, &wg, semaphore)

	// Source Repos
	wg.Add(1)
	go m.enumSourceRepos(ctx, projectID, &wg, semaphore)

	// Artifact Registry
	wg.Add(1)
	go m.enumArtifactRegistry(ctx, projectID, &wg, semaphore)

	// Dataflow
	wg.Add(1)
	go m.enumDataflow(ctx, projectID, &wg, semaphore)

	// Dataproc
	wg.Add(1)
	go m.enumDataproc(ctx, projectID, &wg, semaphore)

	// Notebooks
	wg.Add(1)
	go m.enumNotebooks(ctx, projectID, &wg, semaphore)

	// Composer
	wg.Add(1)
	go m.enumComposer(ctx, projectID, &wg, semaphore)

	// Scheduler
	wg.Add(1)
	go m.enumScheduler(ctx, projectID, &wg, semaphore)

	// Logging Sinks
	wg.Add(1)
	go m.enumLoggingSinks(ctx, projectID, &wg, semaphore)

	// Cloud Armor
	wg.Add(1)
	go m.enumCloudArmor(ctx, projectID, &wg, semaphore)

	// SSL Certificates
	wg.Add(1)
	go m.enumSSLCertificates(ctx, projectID, &wg, semaphore)

	wg.Wait()
}

// Resource enumeration functions

func (m *InventoryModule) enumComputeInstances(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := computeengineservice.New()
	instances, err := svc.Instances(projectID)
	if err != nil {
		return
	}

	for _, inst := range instances {
		region := extractRegionFromZone(inst.Zone)
		m.addResource(projectID, "Compute Instances", region, fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, inst.Zone, inst.Name))
	}
}

func (m *InventoryModule) enumGKEClusters(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := gkeservice.New()
	clusters, _, err := svc.Clusters(projectID) // Returns clusters, nodePools, error
	if err != nil {
		return
	}

	for _, cluster := range clusters {
		m.addResource(projectID, "GKE Clusters", cluster.Location, fmt.Sprintf("projects/%s/locations/%s/clusters/%s", projectID, cluster.Location, cluster.Name))
	}
}

func (m *InventoryModule) enumCloudRun(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := cloudrunservice.New()
	services, err := svc.Services(projectID)
	if err == nil {
		for _, s := range services {
			m.addResource(projectID, "Cloud Run Services", s.Region, fmt.Sprintf("projects/%s/locations/%s/services/%s", projectID, s.Region, s.Name))
		}
	}

	jobs, err := svc.Jobs(projectID)
	if err == nil {
		for _, job := range jobs {
			m.addResource(projectID, "Cloud Run Jobs", job.Region, fmt.Sprintf("projects/%s/locations/%s/jobs/%s", projectID, job.Region, job.Name))
		}
	}
}

func (m *InventoryModule) enumCloudFunctions(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := functionsservice.New()
	functions, err := svc.Functions(projectID)
	if err != nil {
		return
	}

	for _, fn := range functions {
		m.addResource(projectID, "Cloud Functions", fn.Region, fmt.Sprintf("projects/%s/locations/%s/functions/%s", projectID, fn.Region, fn.Name))
	}
}

func (m *InventoryModule) enumBuckets(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := cloudstorageservice.New()
	buckets, err := svc.Buckets(projectID)
	if err != nil {
		return
	}

	for _, bucket := range buckets {
		m.addResource(projectID, "Cloud Storage Buckets", bucket.Location, fmt.Sprintf("gs://%s", bucket.Name))
	}
}

func (m *InventoryModule) enumBigQuery(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := bigqueryservice.New()
	datasets, err := svc.BigqueryDatasets(projectID)
	if err != nil {
		return
	}

	for _, ds := range datasets {
		m.addResource(projectID, "BigQuery Datasets", ds.Location, fmt.Sprintf("projects/%s/datasets/%s", projectID, ds.DatasetID))
	}
}

func (m *InventoryModule) enumCloudSQL(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := cloudsqlservice.New()
	instances, err := svc.Instances(projectID)
	if err != nil {
		return
	}

	for _, inst := range instances {
		m.addResource(projectID, "Cloud SQL Instances", inst.Region, fmt.Sprintf("projects/%s/instances/%s", projectID, inst.Name))
	}
}

func (m *InventoryModule) enumSpanner(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := spannerservice.New()
	result, err := svc.ListInstancesAndDatabases(projectID)
	if err != nil {
		return
	}

	for _, inst := range result.Instances {
		// Spanner config contains region info
		region := "global"
		if inst.Config != "" {
			region = inst.Config
		}
		m.addResource(projectID, "Spanner Instances", region, fmt.Sprintf("projects/%s/instances/%s", projectID, inst.Name))
	}
}

func (m *InventoryModule) enumBigtable(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := bigtableservice.New()
	result, err := svc.ListInstances(projectID)
	if err != nil {
		return
	}

	for _, inst := range result.Instances {
		// Use first cluster location as region
		region := "global"
		if len(inst.Clusters) > 0 {
			region = inst.Clusters[0].Location
		}
		m.addResource(projectID, "Bigtable Instances", region, fmt.Sprintf("projects/%s/instances/%s", projectID, inst.Name))
	}
}

func (m *InventoryModule) enumMemorystore(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := memorystoreservice.New()
	instances, err := svc.ListRedisInstances(projectID)
	if err != nil {
		return
	}

	for _, inst := range instances {
		m.addResource(projectID, "Memorystore Redis", inst.Location, fmt.Sprintf("projects/%s/locations/%s/instances/%s", projectID, inst.Location, inst.Name))
	}
}

func (m *InventoryModule) enumFilestore(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := filestoreservice.New()
	instances, err := svc.ListInstances(projectID)
	if err != nil {
		return
	}

	for _, inst := range instances {
		m.addResource(projectID, "Filestore Instances", inst.Location, fmt.Sprintf("projects/%s/locations/%s/instances/%s", projectID, inst.Location, inst.Name))
	}
}

func (m *InventoryModule) enumServiceAccounts(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := iamservice.New()
	// Use ServiceAccountsBasic to avoid querying keys (faster, fewer permissions needed)
	accounts, err := svc.ServiceAccountsBasic(projectID)
	if err != nil {
		return
	}

	for _, sa := range accounts {
		m.addResource(projectID, "Service Accounts", "global", sa.Email)
	}
}

func (m *InventoryModule) enumKMS(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := kmsservice.New()
	keyRings, err := svc.KeyRings(projectID)
	if err != nil {
		return
	}

	for _, kr := range keyRings {
		m.addResource(projectID, "KMS Key Rings", kr.Location, fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", projectID, kr.Location, kr.Name))
	}
}

func (m *InventoryModule) enumSecrets(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc, err := secretsservice.NewWithSession(nil)
	if err != nil {
		return
	}
	secrets, err := svc.Secrets(projectID)
	if err != nil {
		return
	}

	for _, secret := range secrets {
		// Secrets are global but may have regional replicas
		region := "global"
		if len(secret.ReplicaLocations) > 0 {
			region = secret.ReplicaLocations[0]
		}
		m.addResource(projectID, "Secrets", region, secret.Name)
	}
}

func (m *InventoryModule) enumAPIKeys(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := apikeysservice.New()
	keys, err := svc.ListAPIKeys(projectID)
	if err != nil {
		return
	}

	for _, key := range keys {
		m.addResource(projectID, "API Keys", "global", key.Name)
	}
}

func (m *InventoryModule) enumPubSub(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := pubsubservice.New()
	topics, err := svc.Topics(projectID)
	if err == nil {
		for _, topic := range topics {
			m.addResource(projectID, "Pub/Sub Topics", "global", fmt.Sprintf("projects/%s/topics/%s", projectID, topic.Name))
		}
	}

	subscriptions, err := svc.Subscriptions(projectID)
	if err == nil {
		for _, sub := range subscriptions {
			m.addResource(projectID, "Pub/Sub Subscriptions", "global", fmt.Sprintf("projects/%s/subscriptions/%s", projectID, sub.Name))
		}
	}
}

func (m *InventoryModule) enumDNS(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := dnsservice.New()
	zones, err := svc.Zones(projectID)
	if err != nil {
		return
	}

	for _, zone := range zones {
		m.addResource(projectID, "DNS Zones", "global", fmt.Sprintf("projects/%s/managedZones/%s", projectID, zone.Name))
	}
}

func (m *InventoryModule) enumCloudBuild(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := cloudbuildservice.New()
	triggers, err := svc.ListTriggers(projectID)
	if err != nil {
		return
	}

	for _, trigger := range triggers {
		region := "global"
		m.addResource(projectID, "Cloud Build Triggers", region, fmt.Sprintf("projects/%s/locations/%s/triggers/%s", projectID, region, trigger.Name))
	}
}

func (m *InventoryModule) enumSourceRepos(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := sourcereposservice.New()
	repos, err := svc.ListRepos(projectID)
	if err != nil {
		return
	}

	for _, repo := range repos {
		m.addResource(projectID, "Source Repositories", "global", fmt.Sprintf("projects/%s/repos/%s", projectID, repo.Name))
	}
}

func (m *InventoryModule) enumArtifactRegistry(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc, err := artifactregistryservice.NewWithSession(nil)
	if err != nil {
		return
	}
	repos, err := svc.Repositories(projectID)
	if err != nil {
		return
	}

	for _, repo := range repos {
		m.addResource(projectID, "Artifact Registries", repo.Location, fmt.Sprintf("projects/%s/locations/%s/repositories/%s", projectID, repo.Location, repo.Name))
	}
}

func (m *InventoryModule) enumDataflow(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := dataflowservice.New()
	jobs, err := svc.ListJobs(projectID)
	if err != nil {
		return
	}

	for _, job := range jobs {
		m.addResource(projectID, "Dataflow Jobs", job.Location, fmt.Sprintf("projects/%s/locations/%s/jobs/%s", projectID, job.Location, job.ID))
	}
}

func (m *InventoryModule) enumDataproc(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := dataprocservice.New()
	clusters, err := svc.ListClusters(projectID)
	if err != nil {
		return
	}

	for _, cluster := range clusters {
		m.addResource(projectID, "Dataproc Clusters", cluster.Region, fmt.Sprintf("projects/%s/regions/%s/clusters/%s", projectID, cluster.Region, cluster.Name))
	}
}

func (m *InventoryModule) enumNotebooks(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := notebooksservice.New()
	instances, err := svc.ListInstances(projectID)
	if err != nil {
		return
	}

	for _, inst := range instances {
		m.addResource(projectID, "Notebook Instances", inst.Location, fmt.Sprintf("projects/%s/locations/%s/instances/%s", projectID, inst.Location, inst.Name))
	}
}

func (m *InventoryModule) enumComposer(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := composerservice.New()
	envs, err := svc.ListEnvironments(projectID)
	if err != nil {
		return
	}

	for _, env := range envs {
		m.addResource(projectID, "Composer Environments", env.Location, fmt.Sprintf("projects/%s/locations/%s/environments/%s", projectID, env.Location, env.Name))
	}
}

func (m *InventoryModule) enumScheduler(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := schedulerservice.New()
	jobs, err := svc.Jobs(projectID)
	if err != nil {
		return
	}

	for _, job := range jobs {
		m.addResource(projectID, "Scheduler Jobs", job.Location, fmt.Sprintf("projects/%s/locations/%s/jobs/%s", projectID, job.Location, job.Name))
	}
}

func (m *InventoryModule) enumLoggingSinks(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := loggingservice.New()
	sinks, err := svc.Sinks(projectID)
	if err != nil {
		return
	}

	for _, sink := range sinks {
		m.addResource(projectID, "Log Sinks", "global", fmt.Sprintf("projects/%s/sinks/%s", projectID, sink.Name))
	}
}

func (m *InventoryModule) enumCloudArmor(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := cloudarmorservice.New()
	policies, err := svc.GetSecurityPolicies(projectID)
	if err != nil {
		return
	}

	for _, policy := range policies {
		m.addResource(projectID, "Cloud Armor Policies", "global", fmt.Sprintf("projects/%s/global/securityPolicies/%s", projectID, policy.Name))
	}
}

func (m *InventoryModule) enumSSLCertificates(ctx context.Context, projectID string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	svc := certmanagerservice.New()
	certs, err := svc.GetCertificates(projectID)
	if err != nil {
		return
	}

	for _, cert := range certs {
		m.addResource(projectID, "SSL Certificates", cert.Location, fmt.Sprintf("projects/%s/locations/%s/certificates/%s", projectID, cert.Location, cert.Name))
	}
}

// addResource safely adds a resource count for a specific project
func (m *InventoryModule) addResource(projectID, resourceType, region, resourceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Normalize region
	if region == "" {
		region = "global"
	}
	region = strings.ToLower(region)

	// Track region for this project
	if m.projectRegions[projectID] == nil {
		m.projectRegions[projectID] = make(map[string]bool)
	}
	m.projectRegions[projectID][region] = true

	// Increment count
	if m.projectResourceCounts[projectID] == nil {
		m.projectResourceCounts[projectID] = make(map[string]map[string]int)
	}
	if m.projectResourceCounts[projectID][resourceType] == nil {
		m.projectResourceCounts[projectID][resourceType] = make(map[string]int)
	}
	m.projectResourceCounts[projectID][resourceType][region]++

	// Track resource ID
	if m.projectResourceIDs[projectID] == nil {
		m.projectResourceIDs[projectID] = make(map[string]map[string][]string)
	}
	if m.projectResourceIDs[projectID][resourceType] == nil {
		m.projectResourceIDs[projectID][resourceType] = make(map[string][]string)
	}
	m.projectResourceIDs[projectID][resourceType][region] = append(m.projectResourceIDs[projectID][resourceType][region], resourceID)
}

// calculateTotals computes the total counts per project and globally
func (m *InventoryModule) calculateTotals() {
	for projectID, resourceCounts := range m.projectResourceCounts {
		if m.projectTotalByType[projectID] == nil {
			m.projectTotalByType[projectID] = make(map[string]int)
		}
		if m.projectTotalByRegion[projectID] == nil {
			m.projectTotalByRegion[projectID] = make(map[string]int)
		}

		for resourceType, regionCounts := range resourceCounts {
			for region, count := range regionCounts {
				m.projectTotalByType[projectID][resourceType] += count
				m.projectTotalByRegion[projectID][region] += count
				m.projectGrandTotal[projectID] += count
				m.grandTotal += count
			}
		}
	}
}

// collectAssetInventory queries Cloud Asset Inventory API for complete resource counts
func (m *InventoryModule) collectAssetInventory(ctx context.Context, logger internal.Logger) {
	svc := assetservice.New()

	for _, projectID := range m.ProjectIDs {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Querying asset inventory for project: %s", projectID), GCP_INVENTORY_MODULE_NAME)
		}

		counts, err := svc.GetAssetTypeCounts(projectID)
		if err != nil {
			m.mu.Lock()
			m.assetAPIFailedProjs = append(m.assetAPIFailedProjs, projectID)
			m.mu.Unlock()

			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				gcpinternal.HandleGCPError(err, logger, GCP_INVENTORY_MODULE_NAME,
					fmt.Sprintf("Could not query asset inventory for project %s (API may not be enabled)", projectID))
			}
			continue
		}

		m.mu.Lock()
		m.assetAPIEnabled = true // At least one project succeeded
		if m.assetCounts[projectID] == nil {
			m.assetCounts[projectID] = make(map[string]int)
		}
		for _, c := range counts {
			m.assetCounts[projectID][c.AssetType] = c.Count
			m.assetGrandTotal += c.Count
		}
		m.mu.Unlock()
	}

	// Show warning if Asset API failed for some/all projects
	if len(m.assetAPIFailedProjs) > 0 {
		if !m.assetAPIEnabled {
			logger.InfoM("WARNING: Cloud Asset Inventory API not enabled in any project.", GCP_INVENTORY_MODULE_NAME)
			logger.InfoM("To enable complete resource coverage, enable the Cloud Asset API:", GCP_INVENTORY_MODULE_NAME)
			logger.InfoM("  gcloud services enable cloudasset.googleapis.com --project=<PROJECT_ID>", GCP_INVENTORY_MODULE_NAME)
		} else {
			logger.InfoM(fmt.Sprintf("WARNING: Cloud Asset Inventory API failed for %d project(s): %s",
				len(m.assetAPIFailedProjs), strings.Join(m.assetAPIFailedProjs, ", ")), GCP_INVENTORY_MODULE_NAME)
			logger.InfoM("These projects will only show CloudFox enumerated resources (potential blind spots)", GCP_INVENTORY_MODULE_NAME)
		}
	}
}

// collectEnabledServices queries Service Usage API to find enabled services
// This is a fallback when Asset Inventory API is not available
func (m *InventoryModule) collectEnabledServices(ctx context.Context, logger internal.Logger) {
	svc, err := serviceusage.NewService(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Could not create Service Usage client: %v", err), GCP_INVENTORY_MODULE_NAME)
		}
		return
	}

	for _, projectID := range m.ProjectIDs {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Querying enabled services for project: %s", projectID), GCP_INVENTORY_MODULE_NAME)
		}

		parent := fmt.Sprintf("projects/%s", projectID)
		var enabledServices []string

		req := svc.Services.List(parent).Filter("state:ENABLED")
		err := req.Pages(ctx, func(page *serviceusage.ListServicesResponse) error {
			for _, service := range page.Services {
				// Extract service name from full path
				// Format: projects/123/services/compute.googleapis.com
				parts := strings.Split(service.Name, "/")
				serviceName := parts[len(parts)-1]
				enabledServices = append(enabledServices, serviceName)
			}
			return nil
		})

		if err != nil {
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				gcpinternal.HandleGCPError(err, logger, GCP_INVENTORY_MODULE_NAME,
					fmt.Sprintf("Could not query enabled services for project %s", projectID))
			}
			continue
		}

		m.mu.Lock()
		m.enabledServices[projectID] = enabledServices
		m.mu.Unlock()
	}
}

// getInterestingServices filters enabled services to show only those that likely contain resources
func getInterestingServices(services []string) []string {
	// Services that typically contain enumerable resources
	interestingPrefixes := []string{
		"compute.googleapis.com",
		"container.googleapis.com",
		"run.googleapis.com",
		"cloudfunctions.googleapis.com",
		"storage.googleapis.com",
		"bigquery.googleapis.com",
		"sqladmin.googleapis.com",
		"spanner.googleapis.com",
		"bigtable.googleapis.com",
		"redis.googleapis.com",
		"file.googleapis.com",
		"secretmanager.googleapis.com",
		"cloudkms.googleapis.com",
		"pubsub.googleapis.com",
		"cloudbuild.googleapis.com",
		"sourcerepo.googleapis.com",
		"artifactregistry.googleapis.com",
		"dataflow.googleapis.com",
		"dataproc.googleapis.com",
		"notebooks.googleapis.com",
		"composer.googleapis.com",
		"dns.googleapis.com",
		"apikeys.googleapis.com",
		"cloudscheduler.googleapis.com",
		"logging.googleapis.com",
		"aiplatform.googleapis.com",
		"ml.googleapis.com",
		"healthcare.googleapis.com",
		"firestore.googleapis.com",
		"appengine.googleapis.com",
	}

	var interesting []string
	for _, svc := range services {
		for _, prefix := range interestingPrefixes {
			if svc == prefix {
				interesting = append(interesting, svc)
				break
			}
		}
	}
	return interesting
}

// isServiceCoveredByCloudFox checks if CloudFox has dedicated enumeration for a service
func isServiceCoveredByCloudFox(serviceName string) bool {
	coveredServices := map[string]bool{
		"compute.googleapis.com":          true,
		"container.googleapis.com":        true,
		"run.googleapis.com":              true,
		"cloudfunctions.googleapis.com":   true,
		"storage.googleapis.com":          true,
		"bigquery.googleapis.com":         true,
		"sqladmin.googleapis.com":         true,
		"spanner.googleapis.com":          true,
		"bigtableadmin.googleapis.com":    true,
		"redis.googleapis.com":            true,
		"file.googleapis.com":             true,
		"secretmanager.googleapis.com":    true,
		"cloudkms.googleapis.com":         true,
		"pubsub.googleapis.com":           true,
		"cloudbuild.googleapis.com":       true,
		"sourcerepo.googleapis.com":       true,
		"artifactregistry.googleapis.com": true,
		"dataflow.googleapis.com":         true,
		"dataproc.googleapis.com":         true,
		"notebooks.googleapis.com":        true,
		"composer.googleapis.com":         true,
		"dns.googleapis.com":              true,
		"apikeys.googleapis.com":          true,
		"cloudscheduler.googleapis.com":   true,
		"logging.googleapis.com":          true,
		"iam.googleapis.com":              true,
	}
	return coveredServices[serviceName]
}

// isInterestingService checks if a service typically contains enumerable resources
func isInterestingService(serviceName string) bool {
	interestingServices := map[string]bool{
		"compute.googleapis.com":           true,
		"container.googleapis.com":         true,
		"run.googleapis.com":               true,
		"cloudfunctions.googleapis.com":    true,
		"storage.googleapis.com":           true,
		"storage-component.googleapis.com": true,
		"bigquery.googleapis.com":          true,
		"sqladmin.googleapis.com":          true,
		"spanner.googleapis.com":           true,
		"bigtableadmin.googleapis.com":     true,
		"redis.googleapis.com":             true,
		"file.googleapis.com":              true,
		"secretmanager.googleapis.com":     true,
		"cloudkms.googleapis.com":          true,
		"pubsub.googleapis.com":            true,
		"cloudbuild.googleapis.com":        true,
		"sourcerepo.googleapis.com":        true,
		"artifactregistry.googleapis.com":  true,
		"containerregistry.googleapis.com": true,
		"dataflow.googleapis.com":          true,
		"dataproc.googleapis.com":          true,
		"notebooks.googleapis.com":         true,
		"composer.googleapis.com":          true,
		"dns.googleapis.com":               true,
		"apikeys.googleapis.com":           true,
		"cloudscheduler.googleapis.com":    true,
		"logging.googleapis.com":           true,
		"iam.googleapis.com":               true,
		"aiplatform.googleapis.com":        true,
		"ml.googleapis.com":                true,
		"healthcare.googleapis.com":        true,
		"firestore.googleapis.com":         true,
		"appengine.googleapis.com":         true,
		"vpcaccess.googleapis.com":         true,
		"servicenetworking.googleapis.com": true,
		"memcache.googleapis.com":          true,
		"documentai.googleapis.com":        true,
		"dialogflow.googleapis.com":        true,
		"translate.googleapis.com":         true,
		"vision.googleapis.com":            true,
		"speech.googleapis.com":            true,
		"texttospeech.googleapis.com":      true,
		"videointelligence.googleapis.com": true,
		"automl.googleapis.com":            true,
		"datacatalog.googleapis.com":       true,
		"dataplex.googleapis.com":          true,
		"datastream.googleapis.com":        true,
		"eventarc.googleapis.com":          true,
		"workflows.googleapis.com":         true,
		"gameservices.googleapis.com":      true,
	}
	return interestingServices[serviceName]
}

// getServiceDescription returns a human-readable description of a GCP service
func getServiceDescription(serviceName string) string {
	descriptions := map[string]string{
		"compute.googleapis.com":           "VMs, Disks, Networks, Firewalls",
		"container.googleapis.com":         "GKE Clusters",
		"run.googleapis.com":               "Cloud Run Services/Jobs",
		"cloudfunctions.googleapis.com":    "Cloud Functions",
		"storage.googleapis.com":           "Cloud Storage Buckets",
		"bigquery.googleapis.com":          "BigQuery Datasets/Tables",
		"sqladmin.googleapis.com":          "Cloud SQL Instances",
		"spanner.googleapis.com":           "Spanner Instances",
		"bigtableadmin.googleapis.com":     "Bigtable Instances",
		"redis.googleapis.com":             "Memorystore Redis",
		"file.googleapis.com":              "Filestore Instances",
		"secretmanager.googleapis.com":     "Secret Manager Secrets",
		"cloudkms.googleapis.com":          "KMS Keys",
		"pubsub.googleapis.com":            "Pub/Sub Topics/Subscriptions",
		"cloudbuild.googleapis.com":        "Cloud Build Triggers",
		"sourcerepo.googleapis.com":        "Source Repositories",
		"artifactregistry.googleapis.com":  "Artifact Registry Repos",
		"containerregistry.googleapis.com": "Container Registry (gcr.io)",
		"dataflow.googleapis.com":          "Dataflow Jobs",
		"dataproc.googleapis.com":          "Dataproc Clusters",
		"notebooks.googleapis.com":         "AI Notebooks",
		"composer.googleapis.com":          "Cloud Composer (Airflow)",
		"dns.googleapis.com":               "Cloud DNS Zones",
		"apikeys.googleapis.com":           "API Keys",
		"cloudscheduler.googleapis.com":    "Cloud Scheduler Jobs",
		"logging.googleapis.com":           "Cloud Logging",
		"iam.googleapis.com":               "IAM Service Accounts",
		"aiplatform.googleapis.com":        "Vertex AI Resources",
		"ml.googleapis.com":                "AI Platform Models",
		"healthcare.googleapis.com":        "Healthcare API Datasets",
		"firestore.googleapis.com":         "Firestore Databases",
		"appengine.googleapis.com":         "App Engine Services",
		"vpcaccess.googleapis.com":         "VPC Access Connectors",
		"memcache.googleapis.com":          "Memorystore Memcached",
		"documentai.googleapis.com":        "Document AI Processors",
		"dialogflow.googleapis.com":        "Dialogflow Agents",
		"datacatalog.googleapis.com":       "Data Catalog Entries",
		"dataplex.googleapis.com":          "Dataplex Lakes",
		"datastream.googleapis.com":        "Datastream Streams",
		"eventarc.googleapis.com":          "Eventarc Triggers",
		"workflows.googleapis.com":         "Cloud Workflows",
	}
	if desc, ok := descriptions[serviceName]; ok {
		return desc
	}
	return "May contain resources"
}

// countAssetTypes returns the number of unique asset types found
func (m *InventoryModule) countAssetTypes() int {
	types := make(map[string]bool)
	for _, projectCounts := range m.assetCounts {
		for assetType := range projectCounts {
			types[assetType] = true
		}
	}
	return len(types)
}

// getAssetTypeTotals aggregates asset counts across all projects
func (m *InventoryModule) getAssetTypeTotals() map[string]int {
	totals := make(map[string]int)
	for _, projectCounts := range m.assetCounts {
		for assetType, count := range projectCounts {
			totals[assetType] += count
		}
	}
	return totals
}

// isCoveredAssetType checks if CloudFox has dedicated enumeration for an asset type
func isCoveredAssetType(assetType string) bool {
	coveredTypes := map[string]bool{
		"compute.googleapis.com/Instance":           true,
		"compute.googleapis.com/Disk":               true,
		"compute.googleapis.com/Snapshot":           true,
		"compute.googleapis.com/Image":              true,
		"container.googleapis.com/Cluster":          true,
		"run.googleapis.com/Service":                true,
		"run.googleapis.com/Job":                    true,
		"cloudfunctions.googleapis.com/Function":    true,
		"storage.googleapis.com/Bucket":             true,
		"bigquery.googleapis.com/Dataset":           true,
		"sqladmin.googleapis.com/Instance":          true,
		"spanner.googleapis.com/Instance":           true,
		"bigtableadmin.googleapis.com/Instance":     true,
		"redis.googleapis.com/Instance":             true,
		"file.googleapis.com/Instance":              true,
		"iam.googleapis.com/ServiceAccount":         true,
		"cloudkms.googleapis.com/KeyRing":           true,
		"secretmanager.googleapis.com/Secret":       true,
		"apikeys.googleapis.com/Key":                true,
		"pubsub.googleapis.com/Topic":               true,
		"pubsub.googleapis.com/Subscription":        true,
		"dns.googleapis.com/ManagedZone":            true,
		"cloudbuild.googleapis.com/BuildTrigger":    true,
		"sourcerepo.googleapis.com/Repo":            true,
		"artifactregistry.googleapis.com/Repository": true,
		"dataflow.googleapis.com/Job":               true,
		"dataproc.googleapis.com/Cluster":           true,
		"notebooks.googleapis.com/Instance":         true,
		"composer.googleapis.com/Environment":       true,
		"cloudscheduler.googleapis.com/Job":         true,
		"logging.googleapis.com/LogSink":            true,
		"compute.googleapis.com/SecurityPolicy":     true,
		"certificatemanager.googleapis.com/Certificate": true,
	}
	return coveredTypes[assetType]
}

// formatAssetType converts GCP asset type to human-readable name
func formatAssetType(assetType string) string {
	// Split by / and take the last part
	parts := strings.Split(assetType, "/")
	if len(parts) >= 2 {
		service := strings.TrimSuffix(parts[0], ".googleapis.com")
		resource := parts[len(parts)-1]
		return fmt.Sprintf("%s/%s", service, resource)
	}
	return assetType
}

// Helper function to extract region from zone (e.g., us-central1-a -> us-central1)
func extractRegionFromZone(zone string) string {
	parts := strings.Split(zone, "-")
	if len(parts) >= 3 {
		return strings.Join(parts[:len(parts)-1], "-")
	}
	return zone
}

// writeOutput generates the table and loot files per-project
func (m *InventoryModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Build hierarchical output data with per-project results
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Generate output for each project
	for _, projectID := range m.ProjectIDs {
		projectOutput := m.buildProjectOutput(projectID)
		if projectOutput != nil {
			outputData.ProjectLevelData[projectID] = projectOutput
		}
	}

	// Use hierarchical output to write to per-project directories
	pathBuilder := m.BuildPathBuilder()
	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_INVENTORY_MODULE_NAME)
	}
}

// buildProjectOutput generates output data for a single project
func (m *InventoryModule) buildProjectOutput(projectID string) internal.CloudfoxOutput {
	var tableFiles []internal.TableFile

	// Get project-specific asset counts
	projectAssets := m.assetCounts[projectID]
	projectAssetTotal := 0
	for _, count := range projectAssets {
		projectAssetTotal += count
	}

	// Get project-specific detailed resource counts
	projectResourceTotal := m.projectGrandTotal[projectID]

	// ========================================
	// Table 1: Complete Asset Inventory (from Cloud Asset API)
	// ========================================
	if projectAssetTotal > 0 {
		// Sort asset types by count (descending)
		var assetTypes []string
		for at := range projectAssets {
			assetTypes = append(assetTypes, at)
		}
		sort.Slice(assetTypes, func(i, j int) bool {
			return projectAssets[assetTypes[i]] > projectAssets[assetTypes[j]]
		})

		assetHeader := []string{"Asset Type", "Count", "CloudFox Coverage"}
		var assetBody [][]string

		// Add total row
		assetBody = append(assetBody, []string{"TOTAL", strconv.Itoa(projectAssetTotal), "-"})

		// Add uncovered assets first (these are areas CloudFox might miss)
		var uncoveredTypes []string
		var coveredTypes []string
		for _, at := range assetTypes {
			if isCoveredAssetType(at) {
				coveredTypes = append(coveredTypes, at)
			} else {
				uncoveredTypes = append(uncoveredTypes, at)
			}
		}

		// Uncovered types first (potential blind spots)
		for _, at := range uncoveredTypes {
			coverage := "NO - potential blind spot"
			assetBody = append(assetBody, []string{
				formatAssetType(at),
				strconv.Itoa(projectAssets[at]),
				coverage,
			})
		}

		// Then covered types
		for _, at := range coveredTypes {
			coverage := "Yes"
			assetBody = append(assetBody, []string{
				formatAssetType(at),
				strconv.Itoa(projectAssets[at]),
				coverage,
			})
		}

		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "inventory-complete",
			Header: assetHeader,
			Body:   assetBody,
		})
	} else if services, ok := m.enabledServices[projectID]; ok && len(services) > 0 {
		// ========================================
		// Table 1b: Enabled Services (fallback when Asset API not available)
		// ========================================
		serviceHeader := []string{"Service", "CloudFox Coverage", "Description"}
		var serviceBody [][]string

		// Filter to interesting services and sort
		var interestingServices []string
		for _, svc := range services {
			if isInterestingService(svc) {
				interestingServices = append(interestingServices, svc)
			}
		}
		sort.Strings(interestingServices)

		// Add uncovered services first (potential blind spots)
		var uncoveredServices []string
		var coveredServices []string
		for _, svc := range interestingServices {
			if isServiceCoveredByCloudFox(svc) {
				coveredServices = append(coveredServices, svc)
			} else {
				uncoveredServices = append(uncoveredServices, svc)
			}
		}

		for _, svc := range uncoveredServices {
			coverage := "NO - potential blind spot"
			desc := getServiceDescription(svc)
			serviceBody = append(serviceBody, []string{svc, coverage, desc})
		}

		for _, svc := range coveredServices {
			coverage := "Yes"
			desc := getServiceDescription(svc)
			serviceBody = append(serviceBody, []string{svc, coverage, desc})
		}

		if len(serviceBody) > 0 {
			tableFiles = append(tableFiles, internal.TableFile{
				Name:   "inventory-enabled-services",
				Header: serviceHeader,
				Body:   serviceBody,
			})
		}
	}

	// ========================================
	// Table 2: Detailed Enumeration by Region (from dedicated CloudFox modules)
	// Now uses per-project resource tracking
	// ========================================
	if projectResourceTotal > 0 {
		sortedRegions := m.getSortedRegionsForProject(projectID)

		// Build header: Resource Type, then regions
		header := []string{"Resource Type"}
		header = append(header, sortedRegions...)
		header = append(header, "Total")

		// Build body
		var body [][]string

		// Add total row first
		totalRow := []string{"TOTAL"}
		for _, region := range sortedRegions {
			totalRow = append(totalRow, strconv.Itoa(m.projectTotalByRegion[projectID][region]))
		}
		totalRow = append(totalRow, strconv.Itoa(projectResourceTotal))
		body = append(body, totalRow)

		// Sort resource types alphabetically
		var resourceTypes []string
		for rt := range m.projectTotalByType[projectID] {
			resourceTypes = append(resourceTypes, rt)
		}
		sort.Strings(resourceTypes)

		// Add row for each resource type (only if it has resources)
		for _, resourceType := range resourceTypes {
			if m.projectTotalByType[projectID][resourceType] == 0 {
				continue
			}

			row := []string{resourceType}
			for _, region := range sortedRegions {
				count := m.projectResourceCounts[projectID][resourceType][region]
				if count > 0 {
					row = append(row, strconv.Itoa(count))
				} else {
					row = append(row, "-")
				}
			}
			row = append(row, strconv.Itoa(m.projectTotalByType[projectID][resourceType]))
			body = append(body, row)
		}

		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "inventory-detailed",
			Header: header,
			Body:   body,
		})
	}

	// ========================================
	// Loot file: All resource identifiers
	// ========================================
	var lootContent strings.Builder
	lootContent.WriteString("# GCP Resource Inventory\n")
	lootContent.WriteString(fmt.Sprintf("# Project: %s\n", projectID))
	lootContent.WriteString("# Generated by CloudFox\n")
	lootContent.WriteString(fmt.Sprintf("# Total resources (Asset Inventory): %d\n", projectAssetTotal))
	lootContent.WriteString(fmt.Sprintf("# Total resources (Detailed): %d\n\n", projectResourceTotal))

	// Sort resource types
	var resourceTypes []string
	for rt := range m.projectTotalByType[projectID] {
		resourceTypes = append(resourceTypes, rt)
	}
	sort.Strings(resourceTypes)

	sortedRegions := m.getSortedRegionsForProject(projectID)
	for _, resourceType := range resourceTypes {
		if m.projectTotalByType[projectID][resourceType] == 0 {
			continue
		}
		lootContent.WriteString(fmt.Sprintf("## %s (%d)\n", resourceType, m.projectTotalByType[projectID][resourceType]))
		for _, region := range sortedRegions {
			if m.projectResourceIDs[projectID] != nil && m.projectResourceIDs[projectID][resourceType] != nil {
				for _, resourceID := range m.projectResourceIDs[projectID][resourceType][region] {
					lootContent.WriteString(fmt.Sprintf("%s\n", resourceID))
				}
			}
		}
		lootContent.WriteString("\n")
	}

	lootFiles := []internal.LootFile{{
		Name:     "inventory-resources",
		Contents: lootContent.String(),
	}}

	// Only return output if we have data
	if len(tableFiles) == 0 && lootContent.Len() == 0 {
		return nil
	}

	return InventoryOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}
}

// getSortedRegionsForProject returns regions sorted by count for a specific project, with "global" first
func (m *InventoryModule) getSortedRegionsForProject(projectID string) []string {
	var regions []string
	if m.projectRegions[projectID] == nil {
		return regions
	}
	for region := range m.projectRegions[projectID] {
		regions = append(regions, region)
	}

	// Sort by count descending
	sort.Slice(regions, func(i, j int) bool {
		// Global always first
		if regions[i] == "global" {
			return true
		}
		if regions[j] == "global" {
			return false
		}
		return m.projectTotalByRegion[projectID][regions[i]] > m.projectTotalByRegion[projectID][regions[j]]
	})

	return regions
}
