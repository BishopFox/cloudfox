package cloudbuildservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	cloudbuild "google.golang.org/api/cloudbuild/v1"
)

type CloudBuildService struct {
	session *gcpinternal.SafeSession
}

// New creates a new CloudBuildService
func New() *CloudBuildService {
	return &CloudBuildService{}
}

// NewWithSession creates a CloudBuildService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) *CloudBuildService {
	return &CloudBuildService{session: session}
}

// getService returns a Cloud Build service client using cached session if available
func (s *CloudBuildService) getService(ctx context.Context) (*cloudbuild.Service, error) {
	if s.session != nil {
		return sdk.CachedGetCloudBuildService(ctx, s.session)
	}
	return cloudbuild.NewService(ctx)
}

// TriggerInfo represents a Cloud Build trigger
type TriggerInfo struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	ProjectID       string            `json:"projectId"`
	Disabled        bool              `json:"disabled"`
	CreateTime      string            `json:"createTime"`

	// Source configuration
	SourceType      string            `json:"sourceType"`      // github, cloud_source_repos, etc.
	RepoName        string            `json:"repoName"`
	BranchName      string            `json:"branchName"`
	TagName         string            `json:"tagName"`

	// Build configuration
	BuildConfigType string            `json:"buildConfigType"` // yaml, dockerfile, inline
	Filename        string            `json:"filename"`        // cloudbuild.yaml path
	ServiceAccount  string            `json:"serviceAccount"`  // SA used for builds
	Substitutions   map[string]string `json:"substitutions"`

	// Security analysis
	IsPublicRepo     bool `json:"isPublicRepo"`
	HasSecrets       bool `json:"hasSecrets"`
	PrivescPotential bool `json:"privescPotential"`
}

// BuildInfo represents a Cloud Build execution
type BuildInfo struct {
	ID              string     `json:"id"`
	ProjectID       string     `json:"projectId"`
	Status          string     `json:"status"`
	CreateTime      string     `json:"createTime"`
	StartTime       string     `json:"startTime"`
	FinishTime      string     `json:"finishTime"`
	TriggerID       string     `json:"triggerId"`
	Source          string     `json:"source"`
	ServiceAccount  string     `json:"serviceAccount"`
	LogsBucket      string     `json:"logsBucket"`
	Images          []string   `json:"images"`
	// Pentest-specific fields
	BuildSteps      []BuildStep `json:"buildSteps"`
	SecretEnvVars   []string    `json:"secretEnvVars"`
	Artifacts       []string    `json:"artifacts"`
}

// BuildStep represents a single step in a Cloud Build
type BuildStep struct {
	Name       string   `json:"name"`       // Container image
	Args       []string `json:"args"`       // Command arguments
	Entrypoint string   `json:"entrypoint"` // Custom entrypoint
	Env        []string `json:"env"`        // Environment variables
	SecretEnv  []string `json:"secretEnv"`  // Secret environment variables
	Volumes    []string `json:"volumes"`    // Mounted volumes
}

// TriggerSecurityAnalysis contains detailed security analysis
type TriggerSecurityAnalysis struct {
	TriggerName     string   `json:"triggerName"`
	ProjectID       string   `json:"projectId"`
	ServiceAccount  string   `json:"serviceAccount"`
	RiskLevel       string   `json:"riskLevel"`
	RiskReasons     []string `json:"riskReasons"`
	ExploitCommands []string `json:"exploitCommands"`
	PrivescPotential bool    `json:"privescPotential"`
}

// ListTriggers retrieves all Cloud Build triggers in a project
func (s *CloudBuildService) ListTriggers(projectID string) ([]TriggerInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudbuild.googleapis.com")
	}

	var triggers []TriggerInfo
	parent := fmt.Sprintf("projects/%s/locations/global", projectID)

	req := service.Projects.Locations.Triggers.List(parent)
	err = req.Pages(ctx, func(page *cloudbuild.ListBuildTriggersResponse) error {
		for _, trigger := range page.Triggers {
			info := s.parseTrigger(trigger, projectID)
			triggers = append(triggers, info)
		}
		return nil
	})
	if err != nil {
		// Try with just project ID (older API)
		req2 := service.Projects.Triggers.List(projectID)
		err2 := req2.Pages(ctx, func(page *cloudbuild.ListBuildTriggersResponse) error {
			for _, trigger := range page.Triggers {
				info := s.parseTrigger(trigger, projectID)
				triggers = append(triggers, info)
			}
			return nil
		})
		if err2 != nil {
			return nil, gcpinternal.ParseGCPError(err, "cloudbuild.googleapis.com")
		}
	}

	return triggers, nil
}

// ListBuilds retrieves recent Cloud Build executions
func (s *CloudBuildService) ListBuilds(projectID string, limit int64) ([]BuildInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudbuild.googleapis.com")
	}

	var builds []BuildInfo
	parent := fmt.Sprintf("projects/%s/locations/global", projectID)

	req := service.Projects.Locations.Builds.List(parent).PageSize(limit)
	resp, err := req.Do()
	if err != nil {
		// Try with just project ID
		req2 := service.Projects.Builds.List(projectID).PageSize(limit)
		resp, err = req2.Do()
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "cloudbuild.googleapis.com")
		}
	}

	for _, build := range resp.Builds {
		info := BuildInfo{
			ID:             build.Id,
			ProjectID:      projectID,
			Status:         build.Status,
			CreateTime:     build.CreateTime,
			StartTime:      build.StartTime,
			FinishTime:     build.FinishTime,
			ServiceAccount: build.ServiceAccount,
			LogsBucket:     build.LogsBucket,
			Images:         build.Images,
		}
		if build.BuildTriggerId != "" {
			info.TriggerID = build.BuildTriggerId
		}
		if build.Source != nil && build.Source.RepoSource != nil {
			info.Source = build.Source.RepoSource.RepoName
		}

		// Parse build steps for pentest analysis
		for _, step := range build.Steps {
			if step == nil {
				continue
			}
			bs := BuildStep{
				Name:       step.Name,
				Args:       step.Args,
				Entrypoint: step.Entrypoint,
				Env:        step.Env,
				SecretEnv:  step.SecretEnv,
			}
			for _, vol := range step.Volumes {
				if vol != nil {
					bs.Volumes = append(bs.Volumes, vol.Name+":"+vol.Path)
				}
			}
			info.BuildSteps = append(info.BuildSteps, bs)
			info.SecretEnvVars = append(info.SecretEnvVars, step.SecretEnv...)
		}

		// Parse artifacts
		if build.Artifacts != nil {
			info.Artifacts = build.Artifacts.Images
		}

		builds = append(builds, info)
	}

	return builds, nil
}

// AnalyzeTriggerForPrivesc performs detailed privesc analysis on a trigger
func (s *CloudBuildService) AnalyzeTriggerForPrivesc(trigger TriggerInfo, projectID string) TriggerSecurityAnalysis {
	analysis := TriggerSecurityAnalysis{
		TriggerName:    trigger.Name,
		ProjectID:      projectID,
		ServiceAccount: trigger.ServiceAccount,
		RiskReasons:    []string{},
	}

	score := 0

	// Check service account privileges
	if trigger.ServiceAccount == "" {
		analysis.RiskReasons = append(analysis.RiskReasons,
			"Uses default Cloud Build SA (often has broad permissions)")
		analysis.ExploitCommands = append(analysis.ExploitCommands,
			fmt.Sprintf("# Default SA often has: storage.admin, source.admin, artifactregistry.admin\n"+
				"gcloud builds submit --config=malicious.yaml --project=%s", projectID))
		score += 2
		analysis.PrivescPotential = true
	} else {
		analysis.ExploitCommands = append(analysis.ExploitCommands,
			fmt.Sprintf("# Build runs as: %s\n"+
				"# Check SA permissions:\n"+
				"gcloud projects get-iam-policy %s --flatten='bindings[].members' --filter='bindings.members:%s'",
				trigger.ServiceAccount, projectID, trigger.ServiceAccount))
	}

	// GitHub PR triggers are exploitable
	if trigger.SourceType == "github" && trigger.BranchName != "" {
		analysis.RiskReasons = append(analysis.RiskReasons,
			"GitHub trigger may execute code from pull requests")
		analysis.ExploitCommands = append(analysis.ExploitCommands,
			"# Fork repo, submit PR with malicious cloudbuild.yaml to trigger build")
		score += 2
	}

	// Inline build configs might leak secrets
	if trigger.BuildConfigType == "inline" {
		analysis.RiskReasons = append(analysis.RiskReasons,
			"Inline build config may contain hardcoded secrets or commands")
		score += 1
	}

	// Secrets in substitutions
	if trigger.HasSecrets {
		analysis.RiskReasons = append(analysis.RiskReasons,
			"Trigger uses substitution variables that may contain secrets")
		score += 1
	}

	// Add exploitation guidance
	analysis.ExploitCommands = append(analysis.ExploitCommands,
		fmt.Sprintf("# Trigger a build manually:\n"+
			"gcloud builds triggers run %s --project=%s --branch=%s",
			trigger.ID, projectID, trigger.BranchName))

	if score >= 3 {
		analysis.RiskLevel = "HIGH"
	} else if score >= 2 {
		analysis.RiskLevel = "MEDIUM"
	} else {
		analysis.RiskLevel = "LOW"
	}

	return analysis
}

// parseTrigger converts a trigger to TriggerInfo
func (s *CloudBuildService) parseTrigger(trigger *cloudbuild.BuildTrigger, projectID string) TriggerInfo {
	info := TriggerInfo{
		ID:            trigger.Id,
		Name:          trigger.Name,
		Description:   trigger.Description,
		ProjectID:     projectID,
		Disabled:      trigger.Disabled,
		CreateTime:    trigger.CreateTime,
		Substitutions: trigger.Substitutions,
	}

	// Parse source configuration
	if trigger.Github != nil {
		info.SourceType = "github"
		info.RepoName = fmt.Sprintf("%s/%s", trigger.Github.Owner, trigger.Github.Name)
		if trigger.Github.Push != nil {
			info.BranchName = trigger.Github.Push.Branch
			info.TagName = trigger.Github.Push.Tag
		}
		if trigger.Github.PullRequest != nil {
			info.BranchName = trigger.Github.PullRequest.Branch
		}
	} else if trigger.TriggerTemplate != nil {
		info.SourceType = "cloud_source_repos"
		info.RepoName = trigger.TriggerTemplate.RepoName
		info.BranchName = trigger.TriggerTemplate.BranchName
		info.TagName = trigger.TriggerTemplate.TagName
	}

	// Parse build configuration
	if trigger.Filename != "" {
		info.BuildConfigType = "yaml"
		info.Filename = trigger.Filename
	} else if trigger.Build != nil {
		info.BuildConfigType = "inline"
	}

	// Service account
	if trigger.ServiceAccount != "" {
		info.ServiceAccount = trigger.ServiceAccount
	}

	// Check for secrets in substitutions
	for key := range trigger.Substitutions {
		if containsSecretKeyword(key) {
			info.HasSecrets = true
			break
		}
	}

	// Determine privesc potential
	// Default SA is often over-privileged, GitHub triggers can execute untrusted code
	if info.ServiceAccount == "" {
		info.PrivescPotential = true
	}
	if info.SourceType == "github" && info.BranchName != "" {
		info.PrivescPotential = true
	}

	return info
}

// containsSecretKeyword checks if a key might contain secrets
func containsSecretKeyword(key string) bool {
	secretKeywords := []string{"SECRET", "PASSWORD", "TOKEN", "KEY", "CREDENTIAL", "AUTH"}
	for _, keyword := range secretKeywords {
		if containsIgnoreCase(key, keyword) {
			return true
		}
	}
	return false
}

func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToUpper(s), strings.ToUpper(substr))
}
