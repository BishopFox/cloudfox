package dataflowservice

import (
	"context"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	dataflow "google.golang.org/api/dataflow/v1b3"
)

type DataflowService struct {
	session *gcpinternal.SafeSession
}

func New() *DataflowService {
	return &DataflowService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *DataflowService {
	return &DataflowService{session: session}
}

// getService returns a Dataflow service client using cached session if available
func (s *DataflowService) getService(ctx context.Context) (*dataflow.Service, error) {
	if s.session != nil {
		return sdk.CachedGetDataflowService(ctx, s.session)
	}
	return dataflow.NewService(ctx)
}

// JobInfo represents a Dataflow job
type JobInfo struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	ProjectID         string   `json:"projectId"`
	Location          string   `json:"location"`
	Type              string   `json:"type"`              // JOB_TYPE_BATCH or JOB_TYPE_STREAMING
	State             string   `json:"state"`             // JOB_STATE_RUNNING, etc.
	CreateTime        string   `json:"createTime"`
	CurrentStateTime  string   `json:"currentStateTime"`
	ServiceAccount    string   `json:"serviceAccount"`
	Network           string   `json:"network"`
	Subnetwork        string   `json:"subnetwork"`
	TempLocation      string   `json:"tempLocation"`      // GCS temp location
	StagingLocation   string   `json:"stagingLocation"`   // GCS staging location
	WorkerRegion      string   `json:"workerRegion"`
	WorkerZone        string   `json:"workerZone"`
	NumWorkers        int64    `json:"numWorkers"`
	MachineType       string   `json:"machineType"`
	UsePublicIPs      bool     `json:"usePublicIps"`
	EnableStreamingEngine bool `json:"enableStreamingEngine"`
	// Security analysis
	RiskLevel         string   `json:"riskLevel"`
	RiskReasons       []string `json:"riskReasons"`
}

// TemplateInfo represents a Dataflow template
type TemplateInfo struct {
	Name        string `json:"name"`
	ProjectID   string `json:"projectId"`
	Description string `json:"description"`
	// Template metadata
}

// ListJobs retrieves all Dataflow jobs in a project
func (s *DataflowService) ListJobs(projectID string) ([]JobInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "dataflow.googleapis.com")
	}

	var jobs []JobInfo

	// List jobs across all locations
	req := service.Projects.Jobs.Aggregated(projectID)
	err = req.Pages(ctx, func(page *dataflow.ListJobsResponse) error {
		for _, job := range page.Jobs {
			info := s.parseJob(job, projectID)
			jobs = append(jobs, info)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "dataflow.googleapis.com")
	}

	return jobs, nil
}

// parseJob converts a Dataflow job to JobInfo
func (s *DataflowService) parseJob(job *dataflow.Job, projectID string) JobInfo {
	info := JobInfo{
		ID:               job.Id,
		Name:             job.Name,
		ProjectID:        projectID,
		Location:         job.Location,
		Type:             job.Type,
		State:            job.CurrentState,
		CreateTime:       job.CreateTime,
		CurrentStateTime: job.CurrentStateTime,
		RiskReasons:      []string{},
	}

	// Parse environment settings
	if job.Environment != nil {
		info.ServiceAccount = job.Environment.ServiceAccountEmail
		info.TempLocation = job.Environment.TempStoragePrefix
		info.WorkerRegion = job.Environment.WorkerRegion
		info.WorkerZone = job.Environment.WorkerZone

		// Check worker pools for network config
		if len(job.Environment.WorkerPools) > 0 {
			wp := job.Environment.WorkerPools[0]
			info.Network = wp.Network
			info.Subnetwork = wp.Subnetwork
			info.NumWorkers = wp.NumWorkers
			info.MachineType = wp.MachineType

			// Check for public IPs - default is true if not specified
			if wp.IpConfiguration == "WORKER_IP_PRIVATE" {
				info.UsePublicIPs = false
			} else {
				info.UsePublicIPs = true
			}
		}
	}

	// Security analysis
	info.RiskLevel, info.RiskReasons = s.analyzeJobRisk(info)

	return info
}

// analyzeJobRisk determines the risk level of a Dataflow job
func (s *DataflowService) analyzeJobRisk(job JobInfo) (string, []string) {
	var reasons []string
	score := 0

	// Public IPs increase exposure
	if job.UsePublicIPs {
		reasons = append(reasons, "Workers use public IP addresses")
		score += 2
	}

	// Default service account is often over-privileged
	if job.ServiceAccount == "" || strings.Contains(job.ServiceAccount, "compute@developer.gserviceaccount.com") {
		reasons = append(reasons, "Uses default Compute Engine service account")
		score += 2
	}

	// Check for external temp/staging locations
	if job.TempLocation != "" && !strings.Contains(job.TempLocation, job.ProjectID) {
		reasons = append(reasons, "Temp location may be in external project")
		score += 1
	}

	if score >= 3 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
