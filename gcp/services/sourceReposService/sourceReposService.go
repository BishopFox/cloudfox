package sourcereposservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	sourcerepo "google.golang.org/api/sourcerepo/v1"
)

type SourceReposService struct{
	session *gcpinternal.SafeSession
}

func New() *SourceReposService {
	return &SourceReposService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *SourceReposService {
	return &SourceReposService{
		session: session,
	}
}

// RepoInfo represents a Cloud Source Repository
type RepoInfo struct {
	Name          string       `json:"name"`
	ProjectID     string       `json:"projectId"`
	URL           string       `json:"url"`
	Size          int64        `json:"size"`
	MirrorConfig  bool         `json:"mirrorConfig"`
	MirrorURL     string       `json:"mirrorUrl"`
	PubsubConfigs int          `json:"pubsubConfigs"`
	IAMBindings   []IAMBinding `json:"iamBindings"`
}

// IAMBinding represents a single IAM binding (one role + one member)
type IAMBinding struct {
	Role   string `json:"role"`
	Member string `json:"member"`
}

// getService returns a source repo service client using cached session if available
func (s *SourceReposService) getService(ctx context.Context) (*sourcerepo.Service, error) {
	if s.session != nil {
		return sdk.CachedGetSourceRepoService(ctx, s.session)
	}
	return sourcerepo.NewService(ctx)
}

// ListRepos retrieves all Cloud Source Repositories in a project
func (s *SourceReposService) ListRepos(projectID string) ([]RepoInfo, error) {
	ctx := context.Background()
	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "sourcerepo.googleapis.com")
	}

	var repos []RepoInfo

	parent := fmt.Sprintf("projects/%s", projectID)
	resp, err := service.Projects.Repos.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "sourcerepo.googleapis.com")
	}

	for _, repo := range resp.Repos {
		info := s.parseRepo(repo, projectID)

		// Get IAM policy for this repo
		iamBindings := s.getRepoIAMBindings(service, repo.Name)
		info.IAMBindings = iamBindings

		repos = append(repos, info)
	}

	return repos, nil
}

// getRepoIAMBindings retrieves IAM bindings for a repository
func (s *SourceReposService) getRepoIAMBindings(service *sourcerepo.Service, repoName string) []IAMBinding {
	var bindings []IAMBinding

	policy, err := service.Projects.Repos.GetIamPolicy(repoName).OptionsRequestedPolicyVersion(3).Do()
	if err != nil {
		// Silently skip if we can't get IAM policy
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

func (s *SourceReposService) parseRepo(repo *sourcerepo.Repo, projectID string) RepoInfo {
	// Extract repo name from full path
	name := repo.Name
	if strings.Contains(name, "/") {
		parts := strings.Split(name, "/")
		name = parts[len(parts)-1]
	}

	info := RepoInfo{
		Name:      name,
		ProjectID: projectID,
		URL:       repo.Url,
		Size:      repo.Size,
	}

	// Check for mirror configuration
	if repo.MirrorConfig != nil {
		info.MirrorConfig = true
		info.MirrorURL = repo.MirrorConfig.Url
	}

	// Count pubsub configs
	if repo.PubsubConfigs != nil {
		info.PubsubConfigs = len(repo.PubsubConfigs)
	}

	return info
}

