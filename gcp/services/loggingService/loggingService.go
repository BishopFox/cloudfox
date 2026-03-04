package loggingservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	compute "google.golang.org/api/compute/v1"
	container "google.golang.org/api/container/v1"
	logging "google.golang.org/api/logging/v2"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
	storage "google.golang.org/api/storage/v1"
)

type LoggingService struct{
	session *gcpinternal.SafeSession
}

func New() *LoggingService {
	return &LoggingService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *LoggingService {
	return &LoggingService{
		session: session,
	}
}

// getService returns a Logging service client using cached session if available
func (ls *LoggingService) getService(ctx context.Context) (*logging.Service, error) {
	if ls.session != nil {
		return sdk.CachedGetLoggingService(ctx, ls.session)
	}
	return logging.NewService(ctx)
}

// SinkInfo holds Cloud Logging sink details with security-relevant information
type SinkInfo struct {
	Name              string
	ProjectID         string
	Description       string
	CreateTime        string
	UpdateTime        string

	// Destination configuration
	Destination       string  // Full destination resource name
	DestinationType   string  // bigquery, storage, pubsub, logging
	DestinationBucket string  // For storage destinations
	DestinationDataset string // For BigQuery destinations
	DestinationTopic  string  // For Pub/Sub destinations
	DestinationProject string // Project containing the destination

	// Filter
	Filter            string
	Disabled          bool

	// Export identity
	WriterIdentity    string  // Service account that writes to destination

	// Inclusion/exclusion
	ExclusionFilters  []string

	// Cross-project indicator
	IsCrossProject    bool
}

// MetricInfo holds log-based metric details
type MetricInfo struct {
	Name        string
	ProjectID   string
	Description string
	Filter      string
	CreateTime  string
	UpdateTime  string

	// Metric configuration
	MetricKind  string  // DELTA, GAUGE, CUMULATIVE
	ValueType   string  // INT64, DOUBLE, DISTRIBUTION

	// Labels extracted from logs
	LabelCount  int
}

// Sinks retrieves all logging sinks in a project
func (ls *LoggingService) Sinks(projectID string) ([]SinkInfo, error) {
	ctx := context.Background()

	service, err := ls.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "logging.googleapis.com")
	}

	var sinks []SinkInfo
	parent := fmt.Sprintf("projects/%s", projectID)

	call := service.Projects.Sinks.List(parent)
	err = call.Pages(ctx, func(page *logging.ListSinksResponse) error {
		for _, sink := range page.Sinks {
			info := parseSinkInfo(sink, projectID)
			sinks = append(sinks, info)
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "logging.googleapis.com")
	}

	return sinks, nil
}

// Metrics retrieves all log-based metrics in a project
func (ls *LoggingService) Metrics(projectID string) ([]MetricInfo, error) {
	ctx := context.Background()

	service, err := ls.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "logging.googleapis.com")
	}

	var metrics []MetricInfo
	parent := fmt.Sprintf("projects/%s", projectID)

	call := service.Projects.Metrics.List(parent)
	err = call.Pages(ctx, func(page *logging.ListLogMetricsResponse) error {
		for _, metric := range page.Metrics {
			info := parseMetricInfo(metric, projectID)
			metrics = append(metrics, info)
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "logging.googleapis.com")
	}

	return metrics, nil
}

// parseSinkInfo extracts relevant information from a logging sink
func parseSinkInfo(sink *logging.LogSink, projectID string) SinkInfo {
	info := SinkInfo{
		Name:           sink.Name,
		ProjectID:      projectID,
		Description:    sink.Description,
		CreateTime:     sink.CreateTime,
		UpdateTime:     sink.UpdateTime,
		Destination:    sink.Destination,
		Filter:         sink.Filter,
		Disabled:       sink.Disabled,
		WriterIdentity: sink.WriterIdentity,
	}

	// Parse destination type and details
	info.DestinationType, info.DestinationProject = parseDestination(sink.Destination)

	switch info.DestinationType {
	case "storage":
		info.DestinationBucket = extractBucketName(sink.Destination)
	case "bigquery":
		info.DestinationDataset = extractDatasetName(sink.Destination)
	case "pubsub":
		info.DestinationTopic = extractTopicName(sink.Destination)
	}

	// Check if cross-project
	if info.DestinationProject != "" && info.DestinationProject != projectID {
		info.IsCrossProject = true
	}

	// Parse exclusion filters
	for _, exclusion := range sink.Exclusions {
		if !exclusion.Disabled {
			info.ExclusionFilters = append(info.ExclusionFilters, exclusion.Filter)
		}
	}

	return info
}

// parseMetricInfo extracts relevant information from a log-based metric
func parseMetricInfo(metric *logging.LogMetric, projectID string) MetricInfo {
	info := MetricInfo{
		Name:        metric.Name,
		ProjectID:   projectID,
		Description: metric.Description,
		Filter:      metric.Filter,
		CreateTime:  metric.CreateTime,
		UpdateTime:  metric.UpdateTime,
	}

	if metric.MetricDescriptor != nil {
		info.MetricKind = metric.MetricDescriptor.MetricKind
		info.ValueType = metric.MetricDescriptor.ValueType
		info.LabelCount = len(metric.MetricDescriptor.Labels)
	}

	return info
}

// parseDestination parses the destination resource name
func parseDestination(destination string) (destType string, project string) {
	switch {
	case strings.HasPrefix(destination, "storage.googleapis.com/"):
		destType = "storage"
		// Format: storage.googleapis.com/bucket-name
		parts := strings.Split(destination, "/")
		if len(parts) >= 2 {
			// Bucket name might encode project, but typically doesn't
			project = ""
		}
	case strings.HasPrefix(destination, "bigquery.googleapis.com/"):
		destType = "bigquery"
		// Format: bigquery.googleapis.com/projects/PROJECT_ID/datasets/DATASET_ID
		if idx := strings.Index(destination, "/projects/"); idx >= 0 {
			remainder := destination[idx+len("/projects/"):]
			if slashIdx := strings.Index(remainder, "/"); slashIdx >= 0 {
				project = remainder[:slashIdx]
			}
		}
	case strings.HasPrefix(destination, "pubsub.googleapis.com/"):
		destType = "pubsub"
		// Format: pubsub.googleapis.com/projects/PROJECT_ID/topics/TOPIC_ID
		if idx := strings.Index(destination, "/projects/"); idx >= 0 {
			remainder := destination[idx+len("/projects/"):]
			if slashIdx := strings.Index(remainder, "/"); slashIdx >= 0 {
				project = remainder[:slashIdx]
			}
		}
	case strings.HasPrefix(destination, "logging.googleapis.com/"):
		destType = "logging"
		// Format: logging.googleapis.com/projects/PROJECT_ID/locations/LOCATION/buckets/BUCKET_ID
		if idx := strings.Index(destination, "/projects/"); idx >= 0 {
			remainder := destination[idx+len("/projects/"):]
			if slashIdx := strings.Index(remainder, "/"); slashIdx >= 0 {
				project = remainder[:slashIdx]
			}
		}
	default:
		destType = "unknown"
	}
	return
}

// extractBucketName extracts bucket name from storage destination
func extractBucketName(destination string) string {
	// Format: storage.googleapis.com/bucket-name
	parts := strings.SplitN(destination, "/", 2)
	if len(parts) >= 2 {
		return parts[1]
	}
	return destination
}

// extractDatasetName extracts dataset name from BigQuery destination
func extractDatasetName(destination string) string {
	// Format: bigquery.googleapis.com/projects/PROJECT_ID/datasets/DATASET_ID
	if idx := strings.Index(destination, "/datasets/"); idx >= 0 {
		remainder := destination[idx+len("/datasets/"):]
		if slashIdx := strings.Index(remainder, "/"); slashIdx >= 0 {
			return remainder[:slashIdx]
		}
		return remainder
	}
	return ""
}

// extractTopicName extracts topic name from Pub/Sub destination
func extractTopicName(destination string) string {
	// Format: pubsub.googleapis.com/projects/PROJECT_ID/topics/TOPIC_ID
	if idx := strings.Index(destination, "/topics/"); idx >= 0 {
		return destination[idx+len("/topics/"):]
	}
	return ""
}

// ============================================
// Logging Gaps - Resource Logging Configuration
// ============================================

// LoggingGap represents a resource with missing or incomplete logging
type LoggingGap struct {
	ResourceType  string   // bucket, subnet, gke, cloudsql, log-sink, project
	ResourceName  string
	ProjectID     string
	Location      string
	LoggingStatus string   // disabled, partial, enabled
	MissingLogs   []string // Which logs are missing
}

// getStorageService returns a Storage service client using cached session if available
func (ls *LoggingService) getStorageService(ctx context.Context) (*storage.Service, error) {
	if ls.session != nil {
		return sdk.CachedGetStorageService(ctx, ls.session)
	}
	return storage.NewService(ctx)
}

// getComputeService returns a Compute service client using cached session if available
func (ls *LoggingService) getComputeService(ctx context.Context) (*compute.Service, error) {
	if ls.session != nil {
		return sdk.CachedGetComputeService(ctx, ls.session)
	}
	return compute.NewService(ctx)
}

// getContainerService returns a Container service client using cached session if available
func (ls *LoggingService) getContainerService(ctx context.Context) (*container.Service, error) {
	if ls.session != nil {
		return sdk.CachedGetContainerService(ctx, ls.session)
	}
	return container.NewService(ctx)
}

// getSQLAdminService returns a SQL Admin service client using cached session if available
func (ls *LoggingService) getSQLAdminService(ctx context.Context) (*sqladmin.Service, error) {
	if ls.session != nil {
		return sdk.CachedGetSQLAdminServiceBeta(ctx, ls.session)
	}
	return sqladmin.NewService(ctx)
}

// LoggingGaps finds resources with logging gaps in a project
func (ls *LoggingService) LoggingGaps(projectID string) ([]LoggingGap, error) {
	var gaps []LoggingGap

	// Check various resource types for logging gaps
	if bucketGaps, err := ls.checkBucketLogging(projectID); err == nil {
		gaps = append(gaps, bucketGaps...)
	}

	if computeGaps, err := ls.checkSubnetLogging(projectID); err == nil {
		gaps = append(gaps, computeGaps...)
	}

	if gkeGaps, err := ls.checkGKELogging(projectID); err == nil {
		gaps = append(gaps, gkeGaps...)
	}

	if sqlGaps, err := ls.checkCloudSQLLogging(projectID); err == nil {
		gaps = append(gaps, sqlGaps...)
	}

	return gaps, nil
}

// checkBucketLogging checks GCS buckets for access logging configuration
func (ls *LoggingService) checkBucketLogging(projectID string) ([]LoggingGap, error) {
	ctx := context.Background()
	service, err := ls.getStorageService(ctx)
	if err != nil {
		return nil, err
	}

	var gaps []LoggingGap

	resp, err := service.Buckets.List(projectID).Do()
	if err != nil {
		return nil, err
	}

	for _, bucket := range resp.Items {
		missingLogs := []string{}
		loggingStatus := "enabled"

		// Check if bucket access logging is enabled
		if bucket.Logging == nil || bucket.Logging.LogBucket == "" {
			missingLogs = append(missingLogs, "Access logs disabled")
			loggingStatus = "disabled"
		}

		if len(missingLogs) > 0 {
			gap := LoggingGap{
				ResourceType:  "bucket",
				ResourceName:  bucket.Name,
				ProjectID:     projectID,
				Location:      bucket.Location,
				LoggingStatus: loggingStatus,
				MissingLogs:   missingLogs,
			}
			gaps = append(gaps, gap)
		}
	}

	return gaps, nil
}

// checkSubnetLogging checks VPC subnets for flow log configuration
func (ls *LoggingService) checkSubnetLogging(projectID string) ([]LoggingGap, error) {
	ctx := context.Background()
	service, err := ls.getComputeService(ctx)
	if err != nil {
		return nil, err
	}

	var gaps []LoggingGap

	// Check VPC flow logs on subnets
	req := service.Subnetworks.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.SubnetworkAggregatedList) error {
		for region, subnets := range page.Items {
			regionName := region
			if strings.HasPrefix(region, "regions/") {
				regionName = strings.TrimPrefix(region, "regions/")
			}

			for _, subnet := range subnets.Subnetworks {
				missingLogs := []string{}
				loggingStatus := "enabled"

				// Check if VPC flow logs are enabled
				if subnet.LogConfig == nil || !subnet.LogConfig.Enable {
					missingLogs = append(missingLogs, "VPC Flow Logs disabled")
					loggingStatus = "disabled"
				} else if subnet.LogConfig.AggregationInterval != "INTERVAL_5_SEC" {
					missingLogs = append(missingLogs, "VPC Flow Logs not at max granularity")
					loggingStatus = "partial"
				}

				if len(missingLogs) > 0 {
					gap := LoggingGap{
						ResourceType:  "subnet",
						ResourceName:  subnet.Name,
						ProjectID:     projectID,
						Location:      regionName,
						LoggingStatus: loggingStatus,
						MissingLogs:   missingLogs,
					}
					gaps = append(gaps, gap)
				}
			}
		}
		return nil
	})

	return gaps, err
}

// checkGKELogging checks GKE clusters for logging configuration
func (ls *LoggingService) checkGKELogging(projectID string) ([]LoggingGap, error) {
	ctx := context.Background()
	service, err := ls.getContainerService(ctx)
	if err != nil {
		return nil, err
	}

	var gaps []LoggingGap

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	resp, err := service.Projects.Locations.Clusters.List(parent).Do()
	if err != nil {
		return nil, err
	}

	for _, cluster := range resp.Clusters {
		missingLogs := []string{}
		loggingStatus := "enabled"

		// Check logging service
		if cluster.LoggingService == "" || cluster.LoggingService == "none" {
			missingLogs = append(missingLogs, "Cluster logging disabled")
			loggingStatus = "disabled"
		} else if cluster.LoggingService != "logging.googleapis.com/kubernetes" {
			missingLogs = append(missingLogs, "Not using Cloud Logging")
			loggingStatus = "partial"
		}

		// Check monitoring service
		if cluster.MonitoringService == "" || cluster.MonitoringService == "none" {
			missingLogs = append(missingLogs, "Cluster monitoring disabled")
		}

		// Check for specific logging components
		if cluster.LoggingConfig != nil && cluster.LoggingConfig.ComponentConfig != nil {
			components := cluster.LoggingConfig.ComponentConfig.EnableComponents
			hasSystemComponents := false
			hasWorkloads := false
			for _, comp := range components {
				if comp == "SYSTEM_COMPONENTS" {
					hasSystemComponents = true
				}
				if comp == "WORKLOADS" {
					hasWorkloads = true
				}
			}
			if !hasSystemComponents {
				missingLogs = append(missingLogs, "System component logs disabled")
			}
			if !hasWorkloads {
				missingLogs = append(missingLogs, "Workload logs disabled")
			}
		}

		if len(missingLogs) > 0 {
			gap := LoggingGap{
				ResourceType:  "gke",
				ResourceName:  cluster.Name,
				ProjectID:     projectID,
				Location:      cluster.Location,
				LoggingStatus: loggingStatus,
				MissingLogs:   missingLogs,
			}
			gaps = append(gaps, gap)
		}
	}

	return gaps, nil
}

// checkCloudSQLLogging checks Cloud SQL instances for logging configuration
func (ls *LoggingService) checkCloudSQLLogging(projectID string) ([]LoggingGap, error) {
	ctx := context.Background()
	service, err := ls.getSQLAdminService(ctx)
	if err != nil {
		return nil, err
	}

	var gaps []LoggingGap

	resp, err := service.Instances.List(projectID).Do()
	if err != nil {
		return nil, err
	}

	for _, instance := range resp.Items {
		missingLogs := []string{}
		loggingStatus := "enabled"

		// Check database flags for logging
		if instance.Settings != nil && instance.Settings.DatabaseFlags != nil {
			hasQueryLogging := false
			hasConnectionLogging := false

			for _, flag := range instance.Settings.DatabaseFlags {
				// MySQL flags
				if flag.Name == "general_log" && flag.Value == "on" {
					hasQueryLogging = true
				}
				// PostgreSQL flags
				if flag.Name == "log_statement" && flag.Value == "all" {
					hasQueryLogging = true
				}
				if flag.Name == "log_connections" && flag.Value == "on" {
					hasConnectionLogging = true
				}
			}

			if !hasQueryLogging {
				missingLogs = append(missingLogs, "Query logging not enabled")
				loggingStatus = "partial"
			}
			if !hasConnectionLogging {
				missingLogs = append(missingLogs, "Connection logging not enabled")
			}
		} else {
			missingLogs = append(missingLogs, "No logging flags configured")
			loggingStatus = "disabled"
		}

		if len(missingLogs) > 0 {
			gap := LoggingGap{
				ResourceType:  "cloudsql",
				ResourceName:  instance.Name,
				ProjectID:     projectID,
				Location:      instance.Region,
				LoggingStatus: loggingStatus,
				MissingLogs:   missingLogs,
			}
			gaps = append(gaps, gap)
		}
	}

	return gaps, nil
}
