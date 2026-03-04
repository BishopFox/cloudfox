package serviceagentsservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
)

type ServiceAgentsService struct{
	session *gcpinternal.SafeSession
}

func New() *ServiceAgentsService {
	return &ServiceAgentsService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *ServiceAgentsService {
	return &ServiceAgentsService{
		session: session,
	}
}

// ServiceAgentInfo represents a Google-managed service agent
type ServiceAgentInfo struct {
	Email          string   `json:"email"`
	ProjectID      string   `json:"projectId"`
	SourceProject  string   `json:"sourceProject"` // Project the agent belongs to (extracted from email)
	ServiceName    string   `json:"serviceName"`
	AgentType      string   `json:"agentType"` // compute, gke, cloudbuild, etc.
	Roles          []string `json:"roles"`
	IsCrossProject bool     `json:"isCrossProject"`
	Description    string   `json:"description"`
}

// KnownServiceAgents maps service agent patterns to their descriptions
var KnownServiceAgents = map[string]struct {
	Service     string
	Description string
}{
	"@cloudservices.gserviceaccount.com": {
		Service:     "Google APIs",
		Description: "Google APIs Service Agent - manages resources on behalf of Google Cloud services",
	},
	"@compute-system.iam.gserviceaccount.com": {
		Service:     "Compute Engine",
		Description: "Compute Engine Service Agent - manages Compute Engine resources",
	},
	"@container-engine-robot.iam.gserviceaccount.com": {
		Service:     "GKE",
		Description: "Kubernetes Engine Service Agent - manages GKE clusters",
	},
	"@cloudbuild.gserviceaccount.com": {
		Service:     "Cloud Build",
		Description: "Cloud Build Service Account - runs build jobs",
	},
	"@gcp-sa-cloudbuild.iam.gserviceaccount.com": {
		Service:     "Cloud Build",
		Description: "Cloud Build Service Agent - manages Cloud Build resources",
	},
	"@cloudcomposer-accounts.iam.gserviceaccount.com": {
		Service:     "Composer",
		Description: "Cloud Composer Service Agent - manages Airflow environments",
	},
	"@dataflow-service-producer-prod.iam.gserviceaccount.com": {
		Service:     "Dataflow",
		Description: "Dataflow Service Agent - manages Dataflow jobs",
	},
	"@gcp-sa-dataproc.iam.gserviceaccount.com": {
		Service:     "Dataproc",
		Description: "Dataproc Service Agent - manages Dataproc clusters",
	},
	"@gcp-sa-pubsub.iam.gserviceaccount.com": {
		Service:     "Pub/Sub",
		Description: "Pub/Sub Service Agent - manages Pub/Sub resources",
	},
	"@serverless-robot-prod.iam.gserviceaccount.com": {
		Service:     "Cloud Run/Functions",
		Description: "Serverless Service Agent - manages serverless resources",
	},
	"@gcp-sa-cloudscheduler.iam.gserviceaccount.com": {
		Service:     "Cloud Scheduler",
		Description: "Cloud Scheduler Service Agent",
	},
	"@gcp-sa-bigquery.iam.gserviceaccount.com": {
		Service:     "BigQuery",
		Description: "BigQuery Service Agent - manages BigQuery resources",
	},
	"@gcp-sa-artifactregistry.iam.gserviceaccount.com": {
		Service:     "Artifact Registry",
		Description: "Artifact Registry Service Agent",
	},
	"@gcp-sa-secretmanager.iam.gserviceaccount.com": {
		Service:     "Secret Manager",
		Description: "Secret Manager Service Agent",
	},
	"@gcp-sa-firestore.iam.gserviceaccount.com": {
		Service:     "Firestore",
		Description: "Firestore Service Agent",
	},
	"@gcp-sa-cloud-sql.iam.gserviceaccount.com": {
		Service:     "Cloud SQL",
		Description: "Cloud SQL Service Agent",
	},
	"@gcp-sa-logging.iam.gserviceaccount.com": {
		Service:     "Cloud Logging",
		Description: "Cloud Logging Service Agent",
	},
	"@gcp-sa-monitoring.iam.gserviceaccount.com": {
		Service:     "Cloud Monitoring",
		Description: "Cloud Monitoring Service Agent",
	},
}

// getResourceManagerService returns a Cloud Resource Manager service client using cached session if available
func (s *ServiceAgentsService) getResourceManagerService(ctx context.Context) (*cloudresourcemanager.Service, error) {
	if s.session != nil {
		return sdk.CachedGetResourceManagerService(ctx, s.session)
	}
	return cloudresourcemanager.NewService(ctx)
}

// GetServiceAgents retrieves all service agents with IAM bindings.
// If orgCache is provided, it resolves project numbers to IDs for accurate cross-project detection.
func (s *ServiceAgentsService) GetServiceAgents(projectID string, orgCache ...*gcpinternal.OrgCache) ([]ServiceAgentInfo, error) {
	ctx := context.Background()
	service, err := s.getResourceManagerService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}

	// Get optional OrgCache
	var cache *gcpinternal.OrgCache
	if len(orgCache) > 0 {
		cache = orgCache[0]
	}

	var agents []ServiceAgentInfo

	// Get IAM policy
	policy, err := service.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}

	// Track which service agents we've seen
	seenAgents := make(map[string]*ServiceAgentInfo)

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if !strings.HasPrefix(member, "serviceAccount:") {
				continue
			}

			email := strings.TrimPrefix(member, "serviceAccount:")

			// Check if it's a service agent
			agentType, description := s.identifyServiceAgent(email)
			if agentType == "" {
				continue // Not a service agent
			}

			// Extract source project from email (may be a project number or ID)
			sourceProject := s.extractSourceProject(email)

			// Resolve project number to ID using OrgCache if available
			sourceProjectID := sourceProject
			if cache != nil && cache.IsPopulated() && sourceProject != "" {
				if resolved := cache.GetProjectIDByNumber(sourceProject); resolved != "" {
					sourceProjectID = resolved
				}
			}

			// Check for cross-project access using resolved ID
			isCrossProject := sourceProjectID != "" && sourceProjectID != projectID

			// Add or update agent
			if agent, exists := seenAgents[email]; exists {
				agent.Roles = append(agent.Roles, binding.Role)
			} else {
				agent := &ServiceAgentInfo{
					Email:          email,
					ProjectID:      projectID,
					SourceProject:  sourceProjectID,
					ServiceName:    agentType,
					AgentType:      agentType,
					Roles:          []string{binding.Role},
					IsCrossProject: isCrossProject,
					Description:    description,
				}
				seenAgents[email] = agent
			}
		}
	}

	// Convert to slice
	for _, agent := range seenAgents {
		agents = append(agents, *agent)
	}

	return agents, nil
}

// extractSourceProject extracts the source project ID/number from a service agent email
func (s *ServiceAgentsService) extractSourceProject(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}

	prefix := parts[0]
	domain := parts[1]

	// Pattern: PROJECT_NUMBER@cloudservices.gserviceaccount.com
	if domain == "cloudservices.gserviceaccount.com" {
		return prefix // This is the project number
	}

	// Pattern: PROJECT_NUMBER-compute@developer.gserviceaccount.com
	if strings.HasSuffix(domain, "developer.gserviceaccount.com") {
		if idx := strings.Index(prefix, "-compute"); idx > 0 {
			return prefix[:idx] // Project number
		}
	}

	// Pattern: PROJECT_ID@appspot.gserviceaccount.com
	if domain == "appspot.gserviceaccount.com" {
		return prefix // This is the project ID
	}

	// Pattern: service-PROJECT_NUMBER@gcp-sa-*.iam.gserviceaccount.com
	if strings.HasPrefix(domain, "gcp-sa-") && strings.HasSuffix(domain, ".iam.gserviceaccount.com") {
		if strings.HasPrefix(prefix, "service-") {
			return strings.TrimPrefix(prefix, "service-") // Project number
		}
		return prefix
	}

	// Pattern: PROJECT_NUMBER@compute-system.iam.gserviceaccount.com
	if strings.HasSuffix(domain, ".iam.gserviceaccount.com") {
		// Most service agents use project number as prefix
		if strings.HasPrefix(prefix, "service-") {
			return strings.TrimPrefix(prefix, "service-")
		}
		return prefix
	}

	// Pattern: PROJECT_NUMBER@cloudbuild.gserviceaccount.com
	if domain == "cloudbuild.gserviceaccount.com" {
		return prefix // Project number
	}

	// Pattern: PROJECT_NUMBER@container-engine-robot.iam.gserviceaccount.com
	if strings.Contains(domain, "container-engine-robot") {
		return prefix
	}

	// Pattern: PROJECT_NUMBER@serverless-robot-prod.iam.gserviceaccount.com
	if strings.Contains(domain, "serverless-robot-prod") {
		return prefix
	}

	return ""
}

func (s *ServiceAgentsService) identifyServiceAgent(email string) (string, string) {
	// Check known patterns
	for suffix, info := range KnownServiceAgents {
		if strings.HasSuffix(email, suffix) {
			return info.Service, info.Description
		}
	}

	// Check for generic service agent patterns
	if strings.Contains(email, "@gcp-sa-") {
		// Extract service name from gcp-sa-{service}
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			saPart := parts[1]
			if strings.HasPrefix(saPart, "gcp-sa-") {
				serviceName := strings.TrimPrefix(saPart, "gcp-sa-")
				serviceName = strings.Split(serviceName, ".")[0]
				return serviceName, fmt.Sprintf("%s Service Agent", serviceName)
			}
		}
	}

	// Check for project-specific service agents
	if strings.Contains(email, "-compute@developer.gserviceaccount.com") {
		return "Compute Engine", "Default Compute Engine service account"
	}

	if strings.Contains(email, "@appspot.gserviceaccount.com") {
		return "App Engine", "App Engine default service account"
	}

	return "", ""
}

// GetDefaultServiceAccounts returns the default service accounts for a project
func (s *ServiceAgentsService) GetDefaultServiceAccounts(projectID string, projectNumber string) []ServiceAgentInfo {
	var defaults []ServiceAgentInfo

	// Google APIs Service Agent
	defaults = append(defaults, ServiceAgentInfo{
		Email:       fmt.Sprintf("%s@cloudservices.gserviceaccount.com", projectNumber),
		ProjectID:   projectID,
		ServiceName: "Google APIs",
		AgentType:   "Google APIs",
		Description: "Google APIs Service Agent - automatically created, manages resources on behalf of Google Cloud services",
	})

	// Compute Engine default SA
	defaults = append(defaults, ServiceAgentInfo{
		Email:       fmt.Sprintf("%s-compute@developer.gserviceaccount.com", projectNumber),
		ProjectID:   projectID,
		ServiceName: "Compute Engine",
		AgentType:   "Compute Engine",
		Description: "Default Compute Engine service account - used by instances without explicit SA",
	})

	// App Engine default SA
	defaults = append(defaults, ServiceAgentInfo{
		Email:       fmt.Sprintf("%s@appspot.gserviceaccount.com", projectID),
		ProjectID:   projectID,
		ServiceName: "App Engine",
		AgentType:   "App Engine",
		Description: "App Engine default service account",
	})

	return defaults
}
