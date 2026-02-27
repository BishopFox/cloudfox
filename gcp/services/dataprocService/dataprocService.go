package dataprocservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	regionservice "github.com/BishopFox/cloudfox/gcp/services/regionService"
	dataproc "google.golang.org/api/dataproc/v1"
)

type DataprocService struct {
	session *gcpinternal.SafeSession
}

func New() *DataprocService {
	return &DataprocService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *DataprocService {
	return &DataprocService{session: session}
}

// getService returns a Dataproc service client using cached session if available
func (s *DataprocService) getService(ctx context.Context) (*dataproc.Service, error) {
	if s.session != nil {
		return sdk.CachedGetDataprocService(ctx, s.session)
	}
	return dataproc.NewService(ctx)
}

// ClusterInfo represents a Dataproc cluster
type ClusterInfo struct {
	Name             string   `json:"name"`
	ProjectID        string   `json:"projectId"`
	Region           string   `json:"region"`
	State            string   `json:"state"`
	StateStartTime   string   `json:"stateStartTime"`
	ClusterUUID      string   `json:"clusterUuid"`

	// Config
	ConfigBucket     string   `json:"configBucket"`
	TempBucket       string   `json:"tempBucket"`
	ImageVersion     string   `json:"imageVersion"`
	ServiceAccount   string   `json:"serviceAccount"`

	// Master config
	MasterMachineType  string   `json:"masterMachineType"`
	MasterCount        int64    `json:"masterCount"`
	MasterDiskSizeGB   int64    `json:"masterDiskSizeGb"`
	MasterInstanceNames []string `json:"masterInstanceNames"`

	// Worker config
	WorkerMachineType string  `json:"workerMachineType"`
	WorkerCount       int64   `json:"workerCount"`
	WorkerDiskSizeGB  int64   `json:"workerDiskSizeGb"`

	// Network config
	Network           string   `json:"network"`
	Subnetwork        string   `json:"subnetwork"`
	InternalIPOnly    bool     `json:"internalIpOnly"`
	Zone              string   `json:"zone"`

	// Security config
	KerberosEnabled   bool     `json:"kerberosEnabled"`
	SecureBoot        bool     `json:"secureBoot"`

	// IAM bindings
	IAMBindings       []IAMBinding `json:"iamBindings"`
}

// IAMBinding represents a single IAM role binding
type IAMBinding struct {
	Role   string `json:"role"`
	Member string `json:"member"`
}

// JobInfo represents a Dataproc job
type JobInfo struct {
	JobID            string   `json:"jobId"`
	ProjectID        string   `json:"projectId"`
	Region           string   `json:"region"`
	ClusterName      string   `json:"clusterName"`
	Status           string   `json:"status"`
	JobType          string   `json:"jobType"`
	SubmittedBy      string   `json:"submittedBy"`
	StartTime        string   `json:"startTime"`
	EndTime          string   `json:"endTime"`
}

// ListClusters retrieves all Dataproc clusters
func (s *DataprocService) ListClusters(projectID string) ([]ClusterInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "dataproc.googleapis.com")
	}

	var clusters []ClusterInfo

	// Get regions from regionService (with automatic fallback)
	regions := regionservice.GetCachedRegionNames(ctx, projectID)

	// List across all regions
	for _, region := range regions {
		regionClusters, err := service.Projects.Regions.Clusters.List(projectID, region).Context(ctx).Do()
		if err != nil {
			continue // Skip regions with errors (API not enabled, no permissions, etc.)
		}

		for _, cluster := range regionClusters.Clusters {
			info := s.parseCluster(cluster, projectID, region, service, ctx)
			clusters = append(clusters, info)
		}
	}

	return clusters, nil
}

// ListJobs retrieves recent Dataproc jobs
func (s *DataprocService) ListJobs(projectID, region string) ([]JobInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "dataproc.googleapis.com")
	}

	var jobs []JobInfo

	resp, err := service.Projects.Regions.Jobs.List(projectID, region).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "dataproc.googleapis.com")
	}

	for _, job := range resp.Jobs {
		info := s.parseJob(job, projectID, region)
		jobs = append(jobs, info)
	}

	return jobs, nil
}

func (s *DataprocService) parseCluster(cluster *dataproc.Cluster, projectID, region string, service *dataproc.Service, ctx context.Context) ClusterInfo {
	info := ClusterInfo{
		Name:        cluster.ClusterName,
		ProjectID:   projectID,
		Region:      region,
		ClusterUUID: cluster.ClusterUuid,
		IAMBindings: []IAMBinding{},
	}

	if cluster.Status != nil {
		info.State = cluster.Status.State
		info.StateStartTime = cluster.Status.StateStartTime
	}

	if cluster.Config != nil {
		info.ConfigBucket = cluster.Config.ConfigBucket
		info.TempBucket = cluster.Config.TempBucket

		// Software config
		if cluster.Config.SoftwareConfig != nil {
			info.ImageVersion = cluster.Config.SoftwareConfig.ImageVersion
		}

		// GCE cluster config
		if cluster.Config.GceClusterConfig != nil {
			gcc := cluster.Config.GceClusterConfig
			info.ServiceAccount = gcc.ServiceAccount
			info.Network = extractName(gcc.NetworkUri)
			info.Subnetwork = extractName(gcc.SubnetworkUri)
			info.InternalIPOnly = gcc.InternalIpOnly
			info.Zone = extractName(gcc.ZoneUri)

			if gcc.ShieldedInstanceConfig != nil {
				info.SecureBoot = gcc.ShieldedInstanceConfig.EnableSecureBoot
			}
		}

		// Master config
		if cluster.Config.MasterConfig != nil {
			mc := cluster.Config.MasterConfig
			info.MasterMachineType = extractName(mc.MachineTypeUri)
			info.MasterCount = mc.NumInstances
			info.MasterInstanceNames = mc.InstanceNames
			if mc.DiskConfig != nil {
				info.MasterDiskSizeGB = mc.DiskConfig.BootDiskSizeGb
			}
		}

		// Worker config
		if cluster.Config.WorkerConfig != nil {
			wc := cluster.Config.WorkerConfig
			info.WorkerMachineType = extractName(wc.MachineTypeUri)
			info.WorkerCount = wc.NumInstances
			if wc.DiskConfig != nil {
				info.WorkerDiskSizeGB = wc.DiskConfig.BootDiskSizeGb
			}
		}

		// Security config
		if cluster.Config.SecurityConfig != nil && cluster.Config.SecurityConfig.KerberosConfig != nil {
			info.KerberosEnabled = true
		}
	}

	// Get IAM policy for the cluster
	info.IAMBindings = s.getClusterIAMBindings(service, ctx, projectID, region, cluster.ClusterName)

	return info
}

func (s *DataprocService) parseJob(job *dataproc.Job, projectID, region string) JobInfo {
	info := JobInfo{
		JobID:       job.Reference.JobId,
		ProjectID:   projectID,
		Region:      region,
		ClusterName: job.Placement.ClusterName,
	}

	if job.Status != nil {
		info.Status = job.Status.State
		info.StartTime = job.Status.StateStartTime
	}

	if job.StatusHistory != nil && len(job.StatusHistory) > 0 {
		for _, status := range job.StatusHistory {
			if status.State == "DONE" || status.State == "ERROR" || status.State == "CANCELLED" {
				info.EndTime = status.StateStartTime
				break
			}
		}
	}

	// Determine job type
	if job.HadoopJob != nil {
		info.JobType = "Hadoop"
	} else if job.SparkJob != nil {
		info.JobType = "Spark"
	} else if job.PysparkJob != nil {
		info.JobType = "PySpark"
	} else if job.HiveJob != nil {
		info.JobType = "Hive"
	} else if job.PigJob != nil {
		info.JobType = "Pig"
	} else if job.SparkRJob != nil {
		info.JobType = "SparkR"
	} else if job.SparkSqlJob != nil {
		info.JobType = "SparkSQL"
	} else if job.PrestoJob != nil {
		info.JobType = "Presto"
	} else {
		info.JobType = "Unknown"
	}

	return info
}

// getClusterIAMBindings retrieves IAM bindings for a Dataproc cluster
func (s *DataprocService) getClusterIAMBindings(service *dataproc.Service, ctx context.Context, projectID, region, clusterName string) []IAMBinding {
	var bindings []IAMBinding

	resource := fmt.Sprintf("projects/%s/regions/%s/clusters/%s", projectID, region, clusterName)
	policy, err := service.Projects.Regions.Clusters.GetIamPolicy(resource, &dataproc.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		// Return empty bindings if we can't get IAM policy
		return bindings
	}

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			bindings = append(bindings, IAMBinding{
				Role:   binding.Role,
				Member: member,
			})
		}
	}

	return bindings
}

func extractName(fullPath string) string {
	if fullPath == "" {
		return ""
	}
	parts := strings.Split(fullPath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullPath
}
