// Package devopsservice provides Azure DevOps service abstractions
//
// This service layer abstracts Azure DevOps API calls from command modules,
// following the standardized pattern established in STANDARDIZATION.md.
package devopsservice

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	azinternal "github.com/BishopFox/cloudfox/internal/azure"
	"github.com/patrickmn/go-cache"
)

// serviceCache is the centralized cache for devops service calls
var serviceCache = cache.New(2*time.Hour, 10*time.Minute)

// cacheKey generates a consistent cache key from components
func cacheKey(parts ...string) string {
	result := "devopsservice"
	for _, part := range parts {
		result += "-" + part
	}
	return result
}

// DevOpsService provides methods for interacting with Azure DevOps
type DevOpsService struct {
	session      *azinternal.SafeSession
	organization string
}

// New creates a new DevOpsService instance
func New(session *azinternal.SafeSession, organization string) *DevOpsService {
	return &DevOpsService{
		session:      session,
		organization: organization,
	}
}

// NewWithSession creates a new DevOpsService with the given session
func NewWithSession(session *azinternal.SafeSession, organization string) *DevOpsService {
	return New(session, organization)
}

// ProjectInfo represents an Azure DevOps project
type ProjectInfo struct {
	ID          string
	Name        string
	Description string
	URL         string
	State       string
	Visibility  string
}

// RepositoryInfo represents a Git repository
type RepositoryInfo struct {
	ID            string
	Name          string
	ProjectName   string
	DefaultBranch string
	URL           string
	Size          int64
}

// PipelineInfo represents a build/release pipeline
type PipelineInfo struct {
	ID          int
	Name        string
	ProjectName string
	Folder      string
	URL         string
}

// AgentPoolInfo represents an agent pool
type AgentPoolInfo struct {
	ID       int
	Name     string
	PoolType string
	IsHosted bool
	Size     int
}

// AgentInfo represents a build agent
type AgentInfo struct {
	ID           int
	Name         string
	PoolName     string
	Status       string
	Version      string
	OSDescription string
	Enabled      bool
}

// ServiceConnectionInfo represents a service connection
type ServiceConnectionInfo struct {
	ID          string
	Name        string
	Type        string
	ProjectName string
	URL         string
	IsShared    bool
}

// VariableGroupInfo represents a variable group
type VariableGroupInfo struct {
	ID          int
	Name        string
	ProjectName string
	Description string
	Variables   map[string]string
}

// DevOpsResponse represents a generic Azure DevOps API response
type DevOpsResponse struct {
	Count int             `json:"count"`
	Value json.RawMessage `json:"value"`
}

// getDevOpsToken returns a token for Azure DevOps
func (s *DevOpsService) getDevOpsToken() (string, error) {
	token, err := s.session.GetTokenForResource("499b84ac-1321-427f-aa17-267ca6975798")
	if err != nil {
		return "", fmt.Errorf("failed to get DevOps token: %w", err)
	}
	return token, nil
}

// makeDevOpsRequest makes a request to the Azure DevOps API
func (s *DevOpsService) makeDevOpsRequest(ctx context.Context, url string) ([]byte, error) {
	token, err := s.getDevOpsToken()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("DevOps API error (status %d): %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// ListProjects returns all projects in the organization
func (s *DevOpsService) ListProjects(ctx context.Context) ([]ProjectInfo, error) {
	url := fmt.Sprintf("https://dev.azure.com/%s/_apis/projects?api-version=7.0", s.organization)

	body, err := s.makeDevOpsRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	var response DevOpsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var projects []ProjectInfo
	if err := json.Unmarshal(response.Value, &projects); err != nil {
		return nil, fmt.Errorf("failed to parse projects: %w", err)
	}

	return projects, nil
}

// ListRepositories returns all repositories in a project
func (s *DevOpsService) ListRepositories(ctx context.Context, projectName string) ([]RepositoryInfo, error) {
	url := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/git/repositories?api-version=7.0", s.organization, projectName)

	body, err := s.makeDevOpsRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	var response DevOpsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var repos []RepositoryInfo
	if err := json.Unmarshal(response.Value, &repos); err != nil {
		return nil, fmt.Errorf("failed to parse repositories: %w", err)
	}

	return repos, nil
}

// ListPipelines returns all pipelines in a project
func (s *DevOpsService) ListPipelines(ctx context.Context, projectName string) ([]PipelineInfo, error) {
	url := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/pipelines?api-version=7.0", s.organization, projectName)

	body, err := s.makeDevOpsRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	var response DevOpsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var pipelines []PipelineInfo
	if err := json.Unmarshal(response.Value, &pipelines); err != nil {
		return nil, fmt.Errorf("failed to parse pipelines: %w", err)
	}

	return pipelines, nil
}

// ListAgentPools returns all agent pools in the organization
func (s *DevOpsService) ListAgentPools(ctx context.Context) ([]AgentPoolInfo, error) {
	url := fmt.Sprintf("https://dev.azure.com/%s/_apis/distributedtask/pools?api-version=7.0", s.organization)

	body, err := s.makeDevOpsRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	var response DevOpsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var pools []AgentPoolInfo
	if err := json.Unmarshal(response.Value, &pools); err != nil {
		return nil, fmt.Errorf("failed to parse agent pools: %w", err)
	}

	return pools, nil
}

// ListAgents returns all agents in an agent pool
func (s *DevOpsService) ListAgents(ctx context.Context, poolID int) ([]AgentInfo, error) {
	url := fmt.Sprintf("https://dev.azure.com/%s/_apis/distributedtask/pools/%d/agents?api-version=7.0", s.organization, poolID)

	body, err := s.makeDevOpsRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	var response DevOpsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var agents []AgentInfo
	if err := json.Unmarshal(response.Value, &agents); err != nil {
		return nil, fmt.Errorf("failed to parse agents: %w", err)
	}

	return agents, nil
}

// ListServiceConnections returns all service connections in a project
func (s *DevOpsService) ListServiceConnections(ctx context.Context, projectName string) ([]ServiceConnectionInfo, error) {
	url := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/serviceendpoint/endpoints?api-version=7.0", s.organization, projectName)

	body, err := s.makeDevOpsRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	var response DevOpsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var connections []ServiceConnectionInfo
	if err := json.Unmarshal(response.Value, &connections); err != nil {
		return nil, fmt.Errorf("failed to parse service connections: %w", err)
	}

	return connections, nil
}

// ListVariableGroups returns all variable groups in a project
func (s *DevOpsService) ListVariableGroups(ctx context.Context, projectName string) ([]VariableGroupInfo, error) {
	url := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/distributedtask/variablegroups?api-version=7.0", s.organization, projectName)

	body, err := s.makeDevOpsRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	var response DevOpsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var groups []VariableGroupInfo
	if err := json.Unmarshal(response.Value, &groups); err != nil {
		return nil, fmt.Errorf("failed to parse variable groups: %w", err)
	}

	return groups, nil
}

// ============================================================================
// CACHED METHODS - Use these in command modules for better performance
// ============================================================================

// CachedListProjects returns cached Azure DevOps projects
func (s *DevOpsService) CachedListProjects(ctx context.Context) ([]ProjectInfo, error) {
	key := cacheKey("projects", s.organization)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]ProjectInfo), nil
	}

	result, err := s.ListProjects(ctx)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListRepositories returns cached repositories for a project
func (s *DevOpsService) CachedListRepositories(ctx context.Context, projectName string) ([]RepositoryInfo, error) {
	key := cacheKey("repos", s.organization, projectName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]RepositoryInfo), nil
	}

	result, err := s.ListRepositories(ctx, projectName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListPipelines returns cached pipelines for a project
func (s *DevOpsService) CachedListPipelines(ctx context.Context, projectName string) ([]PipelineInfo, error) {
	key := cacheKey("pipelines", s.organization, projectName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]PipelineInfo), nil
	}

	result, err := s.ListPipelines(ctx, projectName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListAgentPools returns cached agent pools
func (s *DevOpsService) CachedListAgentPools(ctx context.Context) ([]AgentPoolInfo, error) {
	key := cacheKey("agentpools", s.organization)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]AgentPoolInfo), nil
	}

	result, err := s.ListAgentPools(ctx)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListServiceConnections returns cached service connections for a project
func (s *DevOpsService) CachedListServiceConnections(ctx context.Context, projectName string) ([]ServiceConnectionInfo, error) {
	key := cacheKey("serviceconnections", s.organization, projectName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]ServiceConnectionInfo), nil
	}

	result, err := s.ListServiceConnections(ctx, projectName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}

// CachedListVariableGroups returns cached variable groups for a project
func (s *DevOpsService) CachedListVariableGroups(ctx context.Context, projectName string) ([]VariableGroupInfo, error) {
	key := cacheKey("variablegroups", s.organization, projectName)

	if cached, found := serviceCache.Get(key); found {
		return cached.([]VariableGroupInfo), nil
	}

	result, err := s.ListVariableGroups(ctx, projectName)
	if err != nil {
		return nil, err
	}

	serviceCache.Set(key, result, 0)
	return result, nil
}
