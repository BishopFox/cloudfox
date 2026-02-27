package functionsservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	cloudfunctions "google.golang.org/api/cloudfunctions/v2"
)

type FunctionsService struct{
	session *gcpinternal.SafeSession
}

func New() *FunctionsService {
	return &FunctionsService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *FunctionsService {
	return &FunctionsService{
		session: session,
	}
}

// FunctionInfo holds Cloud Function details with security-relevant information
type FunctionInfo struct {
	// Basic info
	Name        string
	ProjectID   string
	Region      string
	State       string
	Description string

	// Runtime info
	Runtime        string
	EntryPoint     string
	BuildID        string
	UpdateTime     string

	// Security-relevant configuration
	ServiceAccount       string
	IngressSettings      string  // ALL_TRAFFIC, INTERNAL_ONLY, INTERNAL_AND_GCLB
	VPCConnector         string
	VPCEgressSettings    string  // PRIVATE_RANGES_ONLY, ALL_TRAFFIC
	AllTrafficOnLatest   bool

	// Resource configuration (new enhancements)
	AvailableMemoryMB    int64   // Memory in MB
	AvailableCPU         string  // CPU (e.g., "1", "2")
	TimeoutSeconds       int64   // Timeout in seconds
	MaxInstanceCount     int64   // Max concurrent instances
	MinInstanceCount     int64   // Min instances (cold start prevention)
	MaxInstanceRequestConcurrency int64 // Max concurrent requests per instance

	// Trigger info
	TriggerType          string  // HTTP, Pub/Sub, Cloud Storage, etc.
	TriggerURL           string  // For HTTP functions
	TriggerEventType     string
	TriggerResource      string
	TriggerRetryPolicy   string  // RETRY_POLICY_RETRY, RETRY_POLICY_DO_NOT_RETRY

	// Environment variables
	EnvVarCount          int
	SecretEnvVarCount    int
	SecretVolumeCount    int

	// IAM (if retrieved)
	IAMBindings          []IAMBinding // All IAM bindings for this function
	IsPublic             bool         // allUsers or allAuthenticatedUsers can invoke

	// Detailed env var and secret info (like Cloud Run)
	EnvVars              []EnvVarInfo   // All environment variables with values
	SecretEnvVarNames    []string       // Names of secret env vars
	SecretVolumeNames    []string       // Names of secret volumes

	// Legacy fields (kept for compatibility)
	EnvVarNames          []string  // Names of env vars (may hint at secrets)
	SourceLocation       string    // GCS or repo source location
	SourceType           string    // GCS, Repository
}

// EnvVarInfo represents an environment variable configuration
type EnvVarInfo struct {
	Name          string
	Value         string // Direct value (may be empty if using secret ref)
	Source        string // "direct" or "secret-manager"
	SecretName    string // For Secret Manager references
	SecretVersion string // Version (e.g., "latest", "1")
}

// IAMBinding represents a single IAM role binding
type IAMBinding struct {
	Role   string
	Member string
}

// getService returns a Cloud Functions v2 service instance, using cached wrapper if session is available
func (fs *FunctionsService) getService(ctx context.Context) (*cloudfunctions.Service, error) {
	if fs.session != nil {
		return sdk.CachedGetCloudFunctionsServiceV2(ctx, fs.session)
	}
	return cloudfunctions.NewService(ctx)
}

// Functions retrieves all Cloud Functions in a project across all regions
func (fs *FunctionsService) Functions(projectID string) ([]FunctionInfo, error) {
	ctx := context.Background()

	service, err := fs.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudfunctions.googleapis.com")
	}

	var functions []FunctionInfo

	// List functions across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)

	call := service.Projects.Locations.Functions.List(parent)
	err = call.Pages(ctx, func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, fn := range page.Functions {
			info := parseFunctionInfo(fn, projectID)

			// Try to get IAM policy
			iamPolicy, iamErr := fs.getFunctionIAMPolicy(service, fn.Name)
			if iamErr == nil && iamPolicy != nil {
				info.IAMBindings, info.IsPublic = parseIAMBindings(iamPolicy)
			}

			functions = append(functions, info)
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudfunctions.googleapis.com")
	}

	return functions, nil
}

// parseFunctionInfo extracts relevant information from a Cloud Function
func parseFunctionInfo(fn *cloudfunctions.Function, projectID string) FunctionInfo {
	info := FunctionInfo{
		Name:      extractFunctionName(fn.Name),
		ProjectID: projectID,
		State:     fn.State,
	}

	// Extract region from function name
	// Format: projects/{project}/locations/{location}/functions/{name}
	parts := strings.Split(fn.Name, "/")
	if len(parts) >= 4 {
		info.Region = parts[3]
	}

	// Build configuration
	if fn.BuildConfig != nil {
		info.Runtime = fn.BuildConfig.Runtime
		info.EntryPoint = fn.BuildConfig.EntryPoint
		info.BuildID = fn.BuildConfig.Build

		// Extract source location (pentest-relevant)
		if fn.BuildConfig.Source != nil {
			if fn.BuildConfig.Source.StorageSource != nil {
				info.SourceType = "GCS"
				info.SourceLocation = fmt.Sprintf("gs://%s/%s",
					fn.BuildConfig.Source.StorageSource.Bucket,
					fn.BuildConfig.Source.StorageSource.Object)
			} else if fn.BuildConfig.Source.RepoSource != nil {
				info.SourceType = "Repository"
				info.SourceLocation = fmt.Sprintf("%s/%s@%s",
					fn.BuildConfig.Source.RepoSource.ProjectId,
					fn.BuildConfig.Source.RepoSource.RepoName,
					fn.BuildConfig.Source.RepoSource.BranchName)
			}
		}
	}

	// Service configuration
	if fn.ServiceConfig != nil {
		info.ServiceAccount = fn.ServiceConfig.ServiceAccountEmail
		info.IngressSettings = fn.ServiceConfig.IngressSettings
		info.VPCConnector = fn.ServiceConfig.VpcConnector
		info.VPCEgressSettings = fn.ServiceConfig.VpcConnectorEgressSettings
		info.AllTrafficOnLatest = fn.ServiceConfig.AllTrafficOnLatestRevision

		// Resource configuration (new enhancements)
		if fn.ServiceConfig.AvailableMemory != "" {
			// Parse memory string (e.g., "256M", "1G")
			memStr := fn.ServiceConfig.AvailableMemory
			if strings.HasSuffix(memStr, "M") {
				if val, err := parseMemoryMB(memStr); err == nil {
					info.AvailableMemoryMB = val
				}
			} else if strings.HasSuffix(memStr, "G") {
				if val, err := parseMemoryMB(memStr); err == nil {
					info.AvailableMemoryMB = val
				}
			}
		}
		info.AvailableCPU = fn.ServiceConfig.AvailableCpu
		info.TimeoutSeconds = fn.ServiceConfig.TimeoutSeconds
		info.MaxInstanceCount = fn.ServiceConfig.MaxInstanceCount
		info.MinInstanceCount = fn.ServiceConfig.MinInstanceCount
		info.MaxInstanceRequestConcurrency = fn.ServiceConfig.MaxInstanceRequestConcurrency

		// Extract environment variables with values
		if fn.ServiceConfig.EnvironmentVariables != nil {
			info.EnvVarCount = len(fn.ServiceConfig.EnvironmentVariables)
			for key, value := range fn.ServiceConfig.EnvironmentVariables {
				info.EnvVarNames = append(info.EnvVarNames, key)
				info.EnvVars = append(info.EnvVars, EnvVarInfo{
					Name:   key,
					Value:  value,
					Source: "direct",
				})
			}
		}

		// Extract secret environment variables
		if fn.ServiceConfig.SecretEnvironmentVariables != nil {
			info.SecretEnvVarCount = len(fn.ServiceConfig.SecretEnvironmentVariables)
			for _, secret := range fn.ServiceConfig.SecretEnvironmentVariables {
				if secret != nil {
					info.SecretEnvVarNames = append(info.SecretEnvVarNames, secret.Key)
					// Extract version from the secret reference
					version := "latest"
					if secret.Version != "" {
						version = secret.Version
					}
					info.EnvVars = append(info.EnvVars, EnvVarInfo{
						Name:          secret.Key,
						Source:        "secret-manager",
						SecretName:    secret.Secret,
						SecretVersion: version,
					})
				}
			}
		}

		// Extract secret volume names
		if fn.ServiceConfig.SecretVolumes != nil {
			info.SecretVolumeCount = len(fn.ServiceConfig.SecretVolumes)
			for _, vol := range fn.ServiceConfig.SecretVolumes {
				if vol != nil {
					info.SecretVolumeNames = append(info.SecretVolumeNames, vol.Secret)
				}
			}
		}

		// Get HTTP trigger URL from service config
		info.TriggerURL = fn.ServiceConfig.Uri
	}

	// Event trigger configuration
	if fn.EventTrigger != nil {
		info.TriggerType = "Event"
		info.TriggerEventType = fn.EventTrigger.EventType
		info.TriggerResource = fn.EventTrigger.PubsubTopic
		if info.TriggerResource == "" {
			info.TriggerResource = fn.EventTrigger.Channel
		}
	} else if info.TriggerURL != "" {
		info.TriggerType = "HTTP"
	}

	info.Description = fn.Description
	info.UpdateTime = fn.UpdateTime

	return info
}

// getFunctionIAMPolicy retrieves the IAM policy for a function
func (fs *FunctionsService) getFunctionIAMPolicy(service *cloudfunctions.Service, functionName string) (*cloudfunctions.Policy, error) {
	ctx := context.Background()

	policy, err := service.Projects.Locations.Functions.GetIamPolicy(functionName).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	return policy, nil
}

// parseIAMBindings extracts all IAM bindings and checks for public access
func parseIAMBindings(policy *cloudfunctions.Policy) ([]IAMBinding, bool) {
	var bindings []IAMBinding
	isPublic := false

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			bindings = append(bindings, IAMBinding{
				Role:   binding.Role,
				Member: member,
			})

			// Check for public access on invoker roles
			if (binding.Role == "roles/cloudfunctions.invoker" ||
				binding.Role == "roles/run.invoker") &&
				(member == "allUsers" || member == "allAuthenticatedUsers") {
				isPublic = true
			}
		}
	}

	return bindings, isPublic
}

// extractFunctionName extracts just the function name from the full resource name
func extractFunctionName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// parseMemoryMB parses a memory string like "256M" or "1G" to MB
func parseMemoryMB(memStr string) (int64, error) {
	memStr = strings.TrimSpace(memStr)
	if len(memStr) == 0 {
		return 0, fmt.Errorf("empty memory string")
	}

	unit := memStr[len(memStr)-1]
	valueStr := memStr[:len(memStr)-1]

	var value int64
	_, err := fmt.Sscanf(valueStr, "%d", &value)
	if err != nil {
		return 0, err
	}

	switch unit {
	case 'M', 'm':
		return value, nil
	case 'G', 'g':
		return value * 1024, nil
	case 'K', 'k':
		return value / 1024, nil
	default:
		return 0, fmt.Errorf("unknown unit: %c", unit)
	}
}
