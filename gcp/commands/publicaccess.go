package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	bigqueryservice "github.com/BishopFox/cloudfox/gcp/services/bigqueryService"
	kmsservice "github.com/BishopFox/cloudfox/gcp/services/kmsService"
	pubsubservice "github.com/BishopFox/cloudfox/gcp/services/pubsubService"
	regionservice "github.com/BishopFox/cloudfox/gcp/services/regionService"
	spannerservice "github.com/BishopFox/cloudfox/gcp/services/spannerService"
	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	artifactregistry "google.golang.org/api/artifactregistry/v1"
	cloudfunctions "google.golang.org/api/cloudfunctions/v2"
	compute "google.golang.org/api/compute/v1"
	dataflow "google.golang.org/api/dataflow/v1b3"
	dataproc "google.golang.org/api/dataproc/v1"
	notebooks "google.golang.org/api/notebooks/v1"
	run "google.golang.org/api/run/v2"
	secretmanager "google.golang.org/api/secretmanager/v1"
	sourcerepo "google.golang.org/api/sourcerepo/v1"
	storage "google.golang.org/api/storage/v1"
)

var GCPPublicAccessCommand = &cobra.Command{
	Use:     globals.GCP_PUBLICACCESS_MODULE_NAME,
	Aliases: []string{"public", "allUsers", "public-resources"},
	Short:   "Find resources with allUsers or allAuthenticatedUsers access",
	Long: `Enumerate ALL GCP resources that have public access via allUsers or allAuthenticatedUsers.

This module checks IAM policies on resources across all supported GCP services to identify
resources that are publicly accessible to anyone on the internet.

Services Checked (16 total):
- Cloud Storage buckets
- BigQuery datasets and tables
- Compute Engine snapshots and images
- Cloud Run services
- Cloud Functions (v2)
- Pub/Sub topics and subscriptions
- Secret Manager secrets
- Artifact Registry repositories
- Cloud KMS crypto keys
- Cloud Spanner instances and databases
- Dataflow jobs
- Dataproc clusters
- Vertex AI Workbench notebooks
- Cloud Source Repositories

Access Levels:
- allUsers: Anyone on the internet (no authentication required)
- allAuthenticatedUsers: Anyone with a Google account (authenticated)

Both levels are considered "public" as allAuthenticatedUsers includes ANY Google account,
not just accounts in your organization.`,
	Run: runGCPPublicAccessCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type PublicResource struct {
	ResourceType   string // Service type (Storage, BigQuery, etc.)
	ResourceName   string // Resource identifier
	ProjectID      string // Project containing the resource
	Location       string // Region/zone if applicable
	AccessLevel    string // allUsers or allAuthenticatedUsers
	Role           string // IAM role granted publicly
	Size           string // Size if applicable
	AdditionalInfo string // Extra context
}

// ------------------------------
// Module Struct
// ------------------------------
type PublicAccessModule struct {
	gcpinternal.BaseGCPModule

	ProjectPublicResources map[string][]PublicResource
	LootMap                map[string]map[string]*internal.LootFile
	mu                     sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type PublicAccessOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PublicAccessOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PublicAccessOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPPublicAccessCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_PUBLICACCESS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &PublicAccessModule{
		BaseGCPModule:          gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectPublicResources: make(map[string][]PublicResource),
		LootMap:                make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *PublicAccessModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Enumerating public resources (allUsers/allAuthenticatedUsers)...", globals.GCP_PUBLICACCESS_MODULE_NAME)

	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_PUBLICACCESS_MODULE_NAME, m.processProject)

	allResources := m.getAllPublicResources()
	if len(allResources) == 0 {
		logger.InfoM("No public resources found", globals.GCP_PUBLICACCESS_MODULE_NAME)
		return
	}

	// Count by access level
	allUsersCount := 0
	allAuthCount := 0
	for _, r := range allResources {
		if r.AccessLevel == "allUsers" {
			allUsersCount++
		} else {
			allAuthCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d public resource(s): %d allUsers, %d allAuthenticatedUsers",
		len(allResources), allUsersCount, allAuthCount), globals.GCP_PUBLICACCESS_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *PublicAccessModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Checking public access in project: %s", projectID), globals.GCP_PUBLICACCESS_MODULE_NAME)
	}

	// Initialize loot for this project
	m.mu.Lock()
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
	}
	m.LootMap[projectID]["public-access-commands"] = &internal.LootFile{
		Name:     "public-access-commands",
		Contents: "# Public Access Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.mu.Unlock()

	// Check all services in parallel
	var wg sync.WaitGroup

	// 1. Cloud Storage buckets
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkStorageBuckets(ctx, projectID, logger)
	}()

	// 2. Compute Engine snapshots
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkComputeSnapshots(ctx, projectID, logger)
	}()

	// 3. Compute Engine images
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkComputeImages(ctx, projectID, logger)
	}()

	// 4. BigQuery datasets
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkBigQueryDatasets(ctx, projectID, logger)
	}()

	// 5. Cloud Run services
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkCloudRunServices(ctx, projectID, logger)
	}()

	// 6. Cloud Functions
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkCloudFunctions(ctx, projectID, logger)
	}()

	// 7. Pub/Sub topics
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkPubSubTopics(ctx, projectID, logger)
	}()

	// 8. Pub/Sub subscriptions
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkPubSubSubscriptions(ctx, projectID, logger)
	}()

	// 9. Secret Manager secrets
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkSecretManagerSecrets(ctx, projectID, logger)
	}()

	// 10. Artifact Registry repositories
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkArtifactRegistry(ctx, projectID, logger)
	}()

	// 11. Cloud KMS keys
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkKMSKeys(ctx, projectID, logger)
	}()

	// 12. Cloud Spanner instances/databases
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkSpanner(ctx, projectID, logger)
	}()

	// 13. Dataflow jobs
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkDataflowJobs(ctx, projectID, logger)
	}()

	// 14. Dataproc clusters
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkDataprocClusters(ctx, projectID, logger)
	}()

	// 15. Vertex AI Workbench (Notebooks)
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkNotebooks(ctx, projectID, logger)
	}()

	// 16. Source Repositories
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.checkSourceRepos(ctx, projectID, logger)
	}()

	wg.Wait()
}

// checkStorageBuckets checks Cloud Storage buckets for public access
func (m *PublicAccessModule) checkStorageBuckets(ctx context.Context, projectID string, logger internal.Logger) {
	storageService, err := storage.NewService(ctx)
	if err != nil {
		return
	}

	resp, err := storageService.Buckets.List(projectID).Do()
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list buckets in project %s", projectID))
		return
	}

	for _, bucket := range resp.Items {
		policy, err := storageService.Buckets.GetIamPolicy(bucket.Name).Do()
		if err != nil {
			continue
		}

		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				if shared.IsPublicPrincipal(member) {
					resource := PublicResource{
						ResourceType:   "Cloud Storage",
						ResourceName:   bucket.Name,
						ProjectID:      projectID,
						Location:       bucket.Location,
						AccessLevel:    member,
						Role:           binding.Role,
						AdditionalInfo: fmt.Sprintf("Storage class: %s", bucket.StorageClass),
					}
					m.addResource(resource)
				}
			}
		}
	}
}

// checkComputeSnapshots checks Compute Engine snapshots for public access
func (m *PublicAccessModule) checkComputeSnapshots(ctx context.Context, projectID string, logger internal.Logger) {
	computeService, err := compute.NewService(ctx)
	if err != nil {
		return
	}

	req := computeService.Snapshots.List(projectID)
	err = req.Pages(ctx, func(page *compute.SnapshotList) error {
		for _, snapshot := range page.Items {
			policy, err := computeService.Snapshots.GetIamPolicy(projectID, snapshot.Name).Do()
			if err != nil {
				continue
			}

			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						resource := PublicResource{
							ResourceType:   "Compute Snapshot",
							ResourceName:   snapshot.Name,
							ProjectID:      projectID,
							AccessLevel:    member,
							Role:           binding.Role,
							Size:           fmt.Sprintf("%d GB", snapshot.DiskSizeGb),
							AdditionalInfo: fmt.Sprintf("Source disk: %s", publicAccessExtractResourceName(snapshot.SourceDisk)),
						}
						m.addResource(resource)
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list snapshots in project %s", projectID))
	}
}

// checkComputeImages checks Compute Engine images for public access
func (m *PublicAccessModule) checkComputeImages(ctx context.Context, projectID string, logger internal.Logger) {
	computeService, err := compute.NewService(ctx)
	if err != nil {
		return
	}

	req := computeService.Images.List(projectID)
	err = req.Pages(ctx, func(page *compute.ImageList) error {
		for _, image := range page.Items {
			policy, err := computeService.Images.GetIamPolicy(projectID, image.Name).Do()
			if err != nil {
				continue
			}

			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						resource := PublicResource{
							ResourceType:   "Compute Image",
							ResourceName:   image.Name,
							ProjectID:      projectID,
							AccessLevel:    member,
							Role:           binding.Role,
							Size:           fmt.Sprintf("%d GB", image.DiskSizeGb),
							AdditionalInfo: fmt.Sprintf("Family: %s", image.Family),
						}
						m.addResource(resource)
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list images in project %s", projectID))
	}
}

// checkBigQueryDatasets checks BigQuery datasets for public access
func (m *PublicAccessModule) checkBigQueryDatasets(ctx context.Context, projectID string, logger internal.Logger) {
	bq := bigqueryservice.New()
	datasets, err := bq.BigqueryDatasets(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list BigQuery datasets in project %s", projectID))
		return
	}

	for _, dataset := range datasets {
		if dataset.IsPublic {
			resource := PublicResource{
				ResourceType:   "BigQuery Dataset",
				ResourceName:   dataset.DatasetID,
				ProjectID:      projectID,
				Location:       dataset.Location,
				AccessLevel:    dataset.PublicAccess,
				Role:           "Dataset Access",
				AdditionalInfo: fmt.Sprintf("Encryption: %s", dataset.EncryptionType),
			}
			m.addResource(resource)
		}
	}

	// Also check individual tables
	for _, dataset := range datasets {
		tables, err := bq.BigqueryTables(projectID, dataset.DatasetID)
		if err != nil {
			continue
		}

		for _, table := range tables {
			if table.IsPublic {
				resource := PublicResource{
					ResourceType:   "BigQuery Table",
					ResourceName:   fmt.Sprintf("%s.%s", dataset.DatasetID, table.TableID),
					ProjectID:      projectID,
					Location:       table.Location,
					AccessLevel:    table.PublicAccess,
					Role:           "Table Access",
					Size:           publicAccessFormatBytes(table.NumBytes),
					AdditionalInfo: fmt.Sprintf("Rows: %d, Type: %s", table.NumRows, table.TableType),
				}
				m.addResource(resource)
			}
		}
	}
}

// checkCloudRunServices checks Cloud Run services for public access
func (m *PublicAccessModule) checkCloudRunServices(ctx context.Context, projectID string, logger internal.Logger) {
	runService, err := run.NewService(ctx)
	if err != nil {
		return
	}

	// List all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	req := runService.Projects.Locations.Services.List(parent)
	err = req.Pages(ctx, func(page *run.GoogleCloudRunV2ListServicesResponse) error {
		for _, svc := range page.Services {
			// Get IAM policy
			resource := svc.Name
			policy, err := runService.Projects.Locations.Services.GetIamPolicy(resource).Do()
			if err != nil {
				continue
			}

			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						serviceName := publicAccessExtractResourceName(svc.Name)
						location := publicAccessExtractLocation(svc.Name)
						res := PublicResource{
							ResourceType:   "Cloud Run",
							ResourceName:   serviceName,
							ProjectID:      projectID,
							Location:       location,
							AccessLevel:    member,
							Role:           binding.Role,
							AdditionalInfo: fmt.Sprintf("URL: %s", svc.Uri),
						}
						m.addResource(res)
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list Cloud Run services in project %s", projectID))
	}
}

// checkCloudFunctions checks Cloud Functions for public access
func (m *PublicAccessModule) checkCloudFunctions(ctx context.Context, projectID string, logger internal.Logger) {
	cfService, err := cloudfunctions.NewService(ctx)
	if err != nil {
		return
	}

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	req := cfService.Projects.Locations.Functions.List(parent)
	err = req.Pages(ctx, func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, fn := range page.Functions {
			// Get IAM policy
			policy, err := cfService.Projects.Locations.Functions.GetIamPolicy(fn.Name).Do()
			if err != nil {
				continue
			}

			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						funcName := publicAccessExtractResourceName(fn.Name)
						location := publicAccessExtractLocation(fn.Name)

						// Get URL
						url := ""
						if fn.ServiceConfig != nil {
							url = fn.ServiceConfig.Uri
						}

						resource := PublicResource{
							ResourceType:   "Cloud Function",
							ResourceName:   funcName,
							ProjectID:      projectID,
							Location:       location,
							AccessLevel:    member,
							Role:           binding.Role,
							AdditionalInfo: fmt.Sprintf("URL: %s, Runtime: %s", url, fn.BuildConfig.Runtime),
						}
						m.addResource(resource)
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list Cloud Functions in project %s", projectID))
	}
}

// checkPubSubTopics checks Pub/Sub topics for public access
func (m *PublicAccessModule) checkPubSubTopics(ctx context.Context, projectID string, logger internal.Logger) {
	ps := pubsubservice.New()
	topics, err := ps.Topics(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list Pub/Sub topics in project %s", projectID))
		return
	}

	for _, topic := range topics {
		for _, binding := range topic.IAMBindings {
			if shared.IsPublicPrincipal(binding.Member) {
				resource := PublicResource{
					ResourceType:   "Pub/Sub Topic",
					ResourceName:   topic.Name,
					ProjectID:      projectID,
					AccessLevel:    binding.Member,
					Role:           binding.Role,
					AdditionalInfo: fmt.Sprintf("Subscriptions: %d", topic.SubscriptionCount),
				}
				m.addResource(resource)
			}
		}
	}
}

// checkPubSubSubscriptions checks Pub/Sub subscriptions for public access
func (m *PublicAccessModule) checkPubSubSubscriptions(ctx context.Context, projectID string, logger internal.Logger) {
	ps := pubsubservice.New()
	subs, err := ps.Subscriptions(projectID)
	if err != nil {
		return
	}

	for _, sub := range subs {
		for _, binding := range sub.IAMBindings {
			if shared.IsPublicPrincipal(binding.Member) {
				resource := PublicResource{
					ResourceType:   "Pub/Sub Subscription",
					ResourceName:   sub.Name,
					ProjectID:      projectID,
					AccessLevel:    binding.Member,
					Role:           binding.Role,
					AdditionalInfo: fmt.Sprintf("Topic: %s", sub.Topic),
				}
				m.addResource(resource)
			}
		}
	}
}

// checkSecretManagerSecrets checks Secret Manager secrets for public access
func (m *PublicAccessModule) checkSecretManagerSecrets(ctx context.Context, projectID string, logger internal.Logger) {
	smService, err := secretmanager.NewService(ctx)
	if err != nil {
		return
	}

	parent := fmt.Sprintf("projects/%s", projectID)
	req := smService.Projects.Secrets.List(parent)
	err = req.Pages(ctx, func(page *secretmanager.ListSecretsResponse) error {
		for _, secret := range page.Secrets {
			// Get IAM policy
			policy, err := smService.Projects.Secrets.GetIamPolicy(secret.Name).Do()
			if err != nil {
				continue
			}

			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						secretName := publicAccessExtractResourceName(secret.Name)
						resource := PublicResource{
							ResourceType:   "Secret Manager",
							ResourceName:   secretName,
							ProjectID:      projectID,
							AccessLevel:    member,
							Role:           binding.Role,
							AdditionalInfo: fmt.Sprintf("Replication: %v", secret.Replication),
						}
						m.addResource(resource)
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list secrets in project %s", projectID))
	}
}

// checkArtifactRegistry checks Artifact Registry repositories for public access
func (m *PublicAccessModule) checkArtifactRegistry(ctx context.Context, projectID string, logger internal.Logger) {
	arService, err := artifactregistry.NewService(ctx)
	if err != nil {
		return
	}

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	req := arService.Projects.Locations.Repositories.List(parent)
	err = req.Pages(ctx, func(page *artifactregistry.ListRepositoriesResponse) error {
		for _, repo := range page.Repositories {
			// Get IAM policy
			policy, err := arService.Projects.Locations.Repositories.GetIamPolicy(repo.Name).Do()
			if err != nil {
				continue
			}

			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						repoName := publicAccessExtractResourceName(repo.Name)
						location := publicAccessExtractLocation(repo.Name)
						resource := PublicResource{
							ResourceType:   "Artifact Registry",
							ResourceName:   repoName,
							ProjectID:      projectID,
							Location:       location,
							AccessLevel:    member,
							Role:           binding.Role,
							AdditionalInfo: fmt.Sprintf("Format: %s", repo.Format),
						}
						m.addResource(resource)
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list Artifact Registry repos in project %s", projectID))
	}
}

// checkKMSKeys checks Cloud KMS keys for public access
func (m *PublicAccessModule) checkKMSKeys(ctx context.Context, projectID string, logger internal.Logger) {
	kmsSvc := kmsservice.New()
	keys, err := kmsSvc.CryptoKeys(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list KMS keys in project %s", projectID))
		return
	}

	for _, key := range keys {
		for _, binding := range key.IAMBindings {
			if shared.IsPublicPrincipal(binding.Member) {
				resource := PublicResource{
					ResourceType:   "Cloud KMS",
					ResourceName:   key.Name,
					ProjectID:      projectID,
					Location:       key.Location,
					AccessLevel:    binding.Member,
					Role:           binding.Role,
					AdditionalInfo: fmt.Sprintf("KeyRing: %s, Purpose: %s, Protection: %s", key.KeyRing, key.Purpose, key.ProtectionLevel),
				}
				m.addResource(resource)
			}
		}
	}
}

// checkSpanner checks Cloud Spanner instances/databases for public access
func (m *PublicAccessModule) checkSpanner(ctx context.Context, projectID string, logger internal.Logger) {
	spannerSvc := spannerservice.New()
	result, err := spannerSvc.ListInstancesAndDatabases(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list Spanner in project %s", projectID))
		return
	}

	// Check instances
	for _, instance := range result.Instances {
		for _, binding := range instance.IAMBindings {
			if shared.IsPublicPrincipal(binding.Member) {
				resource := PublicResource{
					ResourceType:   "Spanner Instance",
					ResourceName:   instance.Name,
					ProjectID:      projectID,
					AccessLevel:    binding.Member,
					Role:           binding.Role,
					AdditionalInfo: fmt.Sprintf("Config: %s, Nodes: %d", instance.Config, instance.NodeCount),
				}
				m.addResource(resource)
			}
		}
	}

	// Check databases
	for _, db := range result.Databases {
		for _, binding := range db.IAMBindings {
			if shared.IsPublicPrincipal(binding.Member) {
				resource := PublicResource{
					ResourceType:   "Spanner Database",
					ResourceName:   db.Name,
					ProjectID:      projectID,
					AccessLevel:    binding.Member,
					Role:           binding.Role,
					AdditionalInfo: fmt.Sprintf("Instance: %s, Encryption: %s", db.InstanceName, db.EncryptionType),
				}
				m.addResource(resource)
			}
		}
	}
}

// checkDataflowJobs checks Dataflow jobs for public IAM access
func (m *PublicAccessModule) checkDataflowJobs(ctx context.Context, projectID string, logger internal.Logger) {
	dfService, err := dataflow.NewService(ctx)
	if err != nil {
		return
	}

	// List jobs across all regions
	req := dfService.Projects.Jobs.List(projectID)
	err = req.Pages(ctx, func(page *dataflow.ListJobsResponse) error {
		for _, job := range page.Jobs {
			// Get IAM policy for job (requires aggregated)
			// Note: Dataflow jobs don't have direct IAM policies, but we check job type
			// Jobs reading from public sources can be a concern
			if job.Type == "JOB_TYPE_STREAMING" || job.Type == "JOB_TYPE_BATCH" {
				// Check if job has public-facing inputs (like Pub/Sub with allUsers)
				// This is informational - jobs themselves don't have IAM
				// but we flag them if they have concerning configurations
				if hasPublicDataflowConfig(job) {
					resource := PublicResource{
						ResourceType:   "Dataflow Job",
						ResourceName:   job.Name,
						ProjectID:      projectID,
						Location:       job.Location,
						AccessLevel:    "allUsers", // Indicates public source/sink
						Role:           "dataflow.worker",
						AdditionalInfo: fmt.Sprintf("Type: %s, State: %s", job.Type, job.CurrentState),
					}
					m.addResource(resource)
				}
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list Dataflow jobs in project %s", projectID))
	}
}

// hasPublicDataflowConfig checks if a Dataflow job has public-facing configurations
func hasPublicDataflowConfig(job *dataflow.Job) bool {
	// Check job labels for signs of public data sources
	if job.Labels != nil {
		for key, value := range job.Labels {
			if strings.Contains(strings.ToLower(key), "public") ||
				strings.Contains(strings.ToLower(value), "public") {
				return true
			}
		}
	}
	// In practice, need to check the pipeline options for public sources
	// This is a placeholder - full implementation would parse job graph
	return false
}

// getClusterState safely extracts cluster state, handling nil Status
func getClusterState(cluster *dataproc.Cluster) string {
	if cluster.Status != nil {
		return cluster.Status.State
	}
	return "UNKNOWN"
}

// checkDataprocClusters checks Dataproc clusters for public access
func (m *PublicAccessModule) checkDataprocClusters(ctx context.Context, projectID string, logger internal.Logger) {
	dpService, err := dataproc.NewService(ctx)
	if err != nil {
		return
	}

	// Get regions from regionService (with automatic fallback)
	regions := regionservice.GetCachedRegionNames(ctx, projectID)
	for _, region := range regions {
		parent := fmt.Sprintf("projects/%s/regions/%s", projectID, region)
		req := dpService.Projects.Regions.Clusters.List(projectID, region)
		err := req.Pages(ctx, func(page *dataproc.ListClustersResponse) error {
			for _, cluster := range page.Clusters {
				// Get IAM policy for cluster
				policyReq := &dataproc.GetIamPolicyRequest{}
				policy, err := dpService.Projects.Regions.Clusters.GetIamPolicy(parent+"/clusters/"+cluster.ClusterName, policyReq).Do()
				if err != nil {
					continue
				}

				for _, binding := range policy.Bindings {
					for _, member := range binding.Members {
						if shared.IsPublicPrincipal(member) {
							resource := PublicResource{
								ResourceType:   "Dataproc Cluster",
								ResourceName:   cluster.ClusterName,
								ProjectID:      projectID,
								Location:       region,
								AccessLevel:    member,
								Role:           binding.Role,
								AdditionalInfo: fmt.Sprintf("Status: %s", getClusterState(cluster)),
							}
							m.addResource(resource)
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			// Don't fail on region errors, continue
			continue
		}
	}
}

// checkNotebooks checks Vertex AI Workbench notebooks for public access
func (m *PublicAccessModule) checkNotebooks(ctx context.Context, projectID string, logger internal.Logger) {
	nbService, err := notebooks.NewService(ctx)
	if err != nil {
		return
	}

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	req := nbService.Projects.Locations.Instances.List(parent)
	err = req.Pages(ctx, func(page *notebooks.ListInstancesResponse) error {
		for _, instance := range page.Instances {
			// Get IAM policy for notebook instance
			policy, err := nbService.Projects.Locations.Instances.GetIamPolicy(instance.Name).Do()
			if err != nil {
				continue
			}

			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						location := publicAccessExtractLocation(instance.Name)
						resource := PublicResource{
							ResourceType:   "Notebook Instance",
							ResourceName:   publicAccessExtractResourceName(instance.Name),
							ProjectID:      projectID,
							Location:       location,
							AccessLevel:    member,
							Role:           binding.Role,
							AdditionalInfo: fmt.Sprintf("State: %s, Machine: %s", instance.State, instance.MachineType),
						}
						m.addResource(resource)
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list notebooks in project %s", projectID))
	}
}

// checkSourceRepos checks Cloud Source Repositories for public access
func (m *PublicAccessModule) checkSourceRepos(ctx context.Context, projectID string, logger internal.Logger) {
	srService, err := sourcerepo.NewService(ctx)
	if err != nil {
		return
	}

	parent := fmt.Sprintf("projects/%s", projectID)
	req := srService.Projects.Repos.List(parent)
	err = req.Pages(ctx, func(page *sourcerepo.ListReposResponse) error {
		for _, repo := range page.Repos {
			// Get IAM policy for repo
			policy, err := srService.Projects.Repos.GetIamPolicy(repo.Name).Do()
			if err != nil {
				continue
			}

			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						resource := PublicResource{
							ResourceType:   "Source Repository",
							ResourceName:   publicAccessExtractResourceName(repo.Name),
							ProjectID:      projectID,
							AccessLevel:    member,
							Role:           binding.Role,
							AdditionalInfo: fmt.Sprintf("URL: %s", repo.Url),
						}
						m.addResource(resource)
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBLICACCESS_MODULE_NAME,
			fmt.Sprintf("Could not list source repos in project %s", projectID))
	}
}

// addResource adds a public resource to the list thread-safely
func (m *PublicAccessModule) addResource(resource PublicResource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ProjectPublicResources[resource.ProjectID] = append(m.ProjectPublicResources[resource.ProjectID], resource)
	m.addResourceToLoot(resource, resource.ProjectID)
}

// getAllPublicResources aggregates all public resources across projects
func (m *PublicAccessModule) getAllPublicResources() []PublicResource {
	var allResources []PublicResource
	for _, resources := range m.ProjectPublicResources {
		allResources = append(allResources, resources...)
	}
	return allResources
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *PublicAccessModule) addResourceToLoot(resource PublicResource, projectID string) {
	m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# [%s] %s: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s\n"+
			"# Access: %s\n"+
			"# Role: %s\n",
		resource.AccessLevel,
		resource.ResourceType,
		resource.ResourceName,
		resource.ProjectID,
		resource.AccessLevel,
		resource.Role,
	)

	// Add type-specific commands
	m.LootMap[projectID]["public-access-commands"].Contents += "\n# === EXPLOIT COMMANDS ===\n\n"
	switch resource.ResourceType {
	case "Cloud Storage":
		m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
			"gsutil ls gs://%s/\n"+
				"gsutil cp gs://%s/FILE ./\n\n",
			resource.ResourceName, resource.ResourceName)
	case "Compute Snapshot":
		m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
			"gcloud compute disks create exfil-disk --source-snapshot=projects/%s/global/snapshots/%s --zone=us-central1-a\n\n",
			resource.ProjectID, resource.ResourceName)
	case "Compute Image":
		m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
			"gcloud compute instances create exfil-vm --image=projects/%s/global/images/%s --zone=us-central1-a\n\n",
			resource.ProjectID, resource.ResourceName)
	case "BigQuery Dataset", "BigQuery Table":
		m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
			"bq query --use_legacy_sql=false 'SELECT * FROM `%s.%s` LIMIT 100'\n\n",
			resource.ProjectID, resource.ResourceName)
	case "Cloud Run":
		if strings.Contains(resource.AdditionalInfo, "URL:") {
			url := strings.TrimPrefix(resource.AdditionalInfo, "URL: ")
			m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
				"curl -v %s\n\n", url)
		}
	case "Cloud Function":
		if strings.Contains(resource.AdditionalInfo, "URL:") {
			parts := strings.Split(resource.AdditionalInfo, ",")
			if len(parts) > 0 {
				url := strings.TrimPrefix(parts[0], "URL: ")
				m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
					"curl -v %s\n\n", url)
			}
		}
	case "Pub/Sub Topic":
		m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
			"gcloud pubsub topics publish %s --message='test' --project=%s\n\n",
			resource.ResourceName, resource.ProjectID)
	case "Pub/Sub Subscription":
		m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
			"gcloud pubsub subscriptions pull %s --auto-ack --project=%s\n\n",
			resource.ResourceName, resource.ProjectID)
	case "Secret Manager":
		m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
			"gcloud secrets versions access latest --secret=%s --project=%s\n\n",
			resource.ResourceName, resource.ProjectID)
	case "Artifact Registry":
		m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
			"gcloud artifacts docker images list %s-docker.pkg.dev/%s/%s\n\n",
			resource.Location, resource.ProjectID, resource.ResourceName)
	case "Cloud KMS":
		m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
			"# WARNING: Public KMS key access!\n"+
				"gcloud kms keys describe %s --keyring=KEYRING --location=%s --project=%s\n"+
				"# If encrypt role: can encrypt data with this key\n"+
				"# If decrypt role: can decrypt data encrypted with this key\n\n",
			resource.ResourceName, resource.Location, resource.ProjectID)
	case "Spanner Instance", "Spanner Database":
		m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
			"# WARNING: Public Spanner access!\n"+
				"gcloud spanner databases list --instance=%s --project=%s\n"+
				"gcloud spanner databases execute-sql DATABASE --instance=%s --sql='SELECT * FROM TableName LIMIT 10' --project=%s\n\n",
			resource.ResourceName, resource.ProjectID, resource.ResourceName, resource.ProjectID)
	case "Dataproc Cluster":
		m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
			"# WARNING: Public Dataproc cluster!\n"+
				"gcloud dataproc clusters describe %s --region=%s --project=%s\n"+
				"gcloud dataproc jobs list --cluster=%s --region=%s --project=%s\n\n",
			resource.ResourceName, resource.Location, resource.ProjectID,
			resource.ResourceName, resource.Location, resource.ProjectID)
	case "Notebook Instance":
		m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
			"# WARNING: Public Notebook instance!\n"+
				"gcloud notebooks instances describe %s --location=%s --project=%s\n"+
				"# Get proxy URL to access notebook\n\n",
			resource.ResourceName, resource.Location, resource.ProjectID)
	case "Source Repository":
		m.LootMap[projectID]["public-access-commands"].Contents += fmt.Sprintf(
			"# WARNING: Public Source Repository!\n"+
				"gcloud source repos clone %s --project=%s\n"+
				"# Clone and examine source code\n\n",
			resource.ResourceName, resource.ProjectID)
	default:
		m.LootMap[projectID]["public-access-commands"].Contents += "\n"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *PublicAccessModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *PublicAccessModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	pathBuilder := m.BuildPathBuilder()

	// Build per-project output data
	projectLevelData := make(map[string]internal.CloudfoxOutput)

	for projectID, resources := range m.ProjectPublicResources {
		header := []string{
			"Resource Type",
			"Resource Name",
			"Location",
			"Access Level",
			"Public Role",
			"Size",
			"Additional Info",
		}

		var body [][]string
		for _, r := range resources {
			location := r.Location
			if location == "" {
				location = "global"
			}
			size := r.Size
			if size == "" {
				size = "-"
			}

			body = append(body, []string{
				r.ResourceType,
				r.ResourceName,
				location,
				r.AccessLevel,
				r.Role,
				size,
				r.AdditionalInfo,
			})
		}

		// Collect loot files for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		tables := []internal.TableFile{}
		if len(body) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "public-access",
				Header: header,
				Body:   body,
			})
		}

		projectLevelData[projectID] = PublicAccessOutput{
			Table: tables,
			Loot:  lootFiles,
		}
	}

	outputData := internal.HierarchicalOutputData{
		ProjectLevelData: projectLevelData,
	}

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_PUBLICACCESS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

func (m *PublicAccessModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allResources := m.getAllPublicResources()

	header := []string{
		"Project ID",
		"Project Name",
		"Resource Type",
		"Resource Name",
		"Location",
		"Access Level",
		"Public Role",
		"Size",
		"Additional Info",
	}

	var body [][]string
	for _, r := range allResources {
		location := r.Location
		if location == "" {
			location = "global"
		}
		size := r.Size
		if size == "" {
			size = "-"
		}

		body = append(body, []string{
			r.ProjectID,
			m.GetProjectName(r.ProjectID),
			r.ResourceType,
			r.ResourceName,
			location,
			r.AccessLevel,
			r.Role,
			size,
			r.AdditionalInfo,
		})
	}

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	tables := []internal.TableFile{}
	if len(body) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "public-access",
			Header: header,
			Body:   body,
		})
	}

	output := PublicAccessOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_PUBLICACCESS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// ------------------------------
// Helper Functions
// ------------------------------

func publicAccessExtractResourceName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

func publicAccessExtractLocation(fullName string) string {
	// Format: projects/PROJECT/locations/LOCATION/...
	parts := strings.Split(fullName, "/")
	for i, part := range parts {
		if part == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func publicAccessFormatBytes(bytes int64) string {
	if bytes == 0 {
		return "-"
	}
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
