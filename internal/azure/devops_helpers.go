package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

var OrgFlag string
var PatFlag string

// RepoYAML struct
type RepoYAML struct {
	Path    string
	Content string
}

type Branch struct {
	Name             string
	LastCommitSHA    string
	LastCommitAuthor string
	LastCommitDate   string
}

// Tag represents a Git tag with commit info
type Tag struct {
	Name      string
	CommitSHA string
	Tagger    string // includes date
}

// FetchProjects retrieves all projects in the org
func FetchProjects(orgURL, pat string) []map[string]interface{} {
	url := fmt.Sprintf("%s/_apis/projects?api-version=6.0", orgURL)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return nil
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	if val, ok := result["value"].([]interface{}); ok {
		projects := []map[string]interface{}{}
		for _, v := range val {
			if p, ok := v.(map[string]interface{}); ok {
				projects = append(projects, p)
			}
		}
		return projects
	}
	return nil
}

// FetchPipelines retrieves all pipelines in a project
func FetchPipelines(orgURL, pat, project string) []map[string]interface{} {
	url := fmt.Sprintf("%s/%s/_apis/pipelines?api-version=6.0", orgURL, project)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return nil
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	if val, ok := result["value"].([]interface{}); ok {
		pipelines := []map[string]interface{}{}
		for _, v := range val {
			if p, ok := v.(map[string]interface{}); ok {
				pipelines = append(pipelines, p)
			}
		}
		return pipelines
	}
	return nil
}

// FetchPipelineYAML fetches the YAML definition of a pipeline
func FetchPipelineYAML(orgURL, pat, project string, pipelineID int) string {
	// Get the pipeline
	url := fmt.Sprintf("%s/%s/_apis/pipelines/%d/runs?api-version=6.0&$top=1", orgURL, project, pipelineID)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return ""
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	value, ok := result["value"].([]interface{})
	if !ok || len(value) == 0 {
		return ""
	}
	run, ok := value[0].(map[string]interface{})
	if !ok {
		return ""
	}
	config, ok := run["configuration"].(map[string]interface{})
	if !ok {
		return ""
	}
	if configType, ok := config["type"].(string); !ok || configType != "yaml" {
		return ""
	}
	if path, ok := config["path"].(string); ok {
		// Fetch the actual YAML file from the repo
		repo, ok := config["repository"].(map[string]interface{})
		if !ok {
			return ""
		}
		// Repo details
		repoType := repo["type"].(string)
		repoName := repo["name"].(string)
		defaultBranch := repo["defaultBranch"].(string)
		projectName := project
		if repoType == "azureReposGit" {
			return FetchRepoFileYAML(orgURL, pat, projectName, repoName, path, defaultBranch)
		}
	}
	return ""
}

// FetchRepoFileYAML downloads a YAML file from Azure Repos
func FetchRepoFileYAML(orgURL, pat, project, repo, path, branch string) string {
	// Azure DevOps API for file contents
	url := fmt.Sprintf("%s/%s/_apis/git/repositories/%s/items?path=%s&versionDescriptor.version=%s&api-version=6.0", orgURL, project, repo, path, strings.TrimPrefix(branch, "refs/heads/"))
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return ""
	}
	return string(respBody)
}

// AzureDevOpsGET helper with PAT auth and retry logic
func AzureDevOpsGET(url, pat string) []byte {
	// Configure retry for Azure DevOps API
	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	// Create a custom HTTP request function for DevOps (uses Basic Auth instead of Bearer token)
	body, err := devOpsRequestWithRetry(context.Background(), "GET", url, pat, config)
	if err != nil {
		return nil
	}
	return body
}

// devOpsRequestWithRetry is a helper for Azure DevOps API calls that use Basic Auth
func devOpsRequestWithRetry(ctx context.Context, method, url, pat string, config RateLimitConfig) ([]byte, error) {
	for attempt := 0; attempt < config.MaxRetries; attempt++ {
		// Apply delay before retry (skip first attempt)
		if attempt > 0 {
			delay := calculateDelay(attempt, config)
			select {
			case <-time.After(delay):
				// Continue after delay
			case <-ctx.Done():
				return nil, fmt.Errorf("request cancelled: %v", ctx.Err())
			}
		}

		// Create request
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			if attempt == config.MaxRetries-1 {
				return nil, fmt.Errorf("failed to create request: %v", err)
			}
			continue
		}

		// Set Basic Auth for DevOps (empty username, PAT as password)
		req.SetBasicAuth("", pat)
		req.Header.Set("Accept", "application/json")

		// Execute request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			if attempt == config.MaxRetries-1 {
				return nil, fmt.Errorf("request failed after %d attempts: %v", config.MaxRetries, err)
			}
			continue
		}

		// Read response body
		responseBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			if attempt == config.MaxRetries-1 {
				return nil, fmt.Errorf("failed to read response: %v", err)
			}
			continue
		}

		// Handle rate limiting (429)
		if resp.StatusCode == 429 {
			retryAfter := extractRetryAfter(resp, config)
			if attempt == config.MaxRetries-1 {
				return nil, fmt.Errorf("rate limited after %d retries", config.MaxRetries)
			}
			// Wait for the specified retry-after duration
			select {
			case <-time.After(retryAfter):
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf("request cancelled: %v", ctx.Err())
			}
		}

		// Handle server errors (5xx) - retryable
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			if attempt == config.MaxRetries-1 {
				return nil, fmt.Errorf("server error after %d retries: status %d", config.MaxRetries, resp.StatusCode)
			}
			continue
		}

		// Success (2xx)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return responseBody, nil
		}

		// Client errors (4xx except 429) - not retryable
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return nil, fmt.Errorf("client error: status %d", resp.StatusCode)
		}
	}

	return nil, fmt.Errorf("exceeded maximum retries (%d)", config.MaxRetries)
}

func FetchCurrentUser(pat string) (displayName, email string, err error) {
	url := "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=6.0"

	// Configure retry for Azure DevOps API
	config := DefaultRateLimitConfig()
	config.MaxRetries = 5
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 2 * time.Minute

	// Use retry logic
	body, err := devOpsRequestWithRetry(context.Background(), "GET", url, pat, config)
	if err != nil {
		return "", "", err
	}

	var profile struct {
		DisplayName string `json:"displayName"`
		Email       string `json:"emailAddress"`
	}
	if err := json.Unmarshal(body, &profile); err != nil {
		return "", "", err
	}

	return profile.DisplayName, profile.Email, nil
}

// FetchRepos retrieves all repositories in a project
func FetchRepos(orgURL, pat, project string) []map[string]interface{} {
	url := fmt.Sprintf("%s/%s/_apis/git/repositories?api-version=6.0", orgURL, project)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return nil
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	if val, ok := result["value"].([]interface{}); ok {
		repos := []map[string]interface{}{}
		for _, v := range val {
			if r, ok := v.(map[string]interface{}); ok {
				repos = append(repos, r)
			}
		}
		return repos
	}
	return nil
}

// FetchRepoYAMLFiles fetches YAML files in the repo
func FetchRepoYAMLFiles(orgURL, pat, project, repo string) []RepoYAML {
	url := fmt.Sprintf("%s/%s/_apis/git/repositories/%s/items?scopePath=/&recursionLevel=Full&includeContent=true&api-version=6.0", orgURL, project, repo)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return nil
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	yamls := []RepoYAML{}

	if val, ok := result["value"].([]interface{}); ok {
		for _, v := range val {
			if item, ok := v.(map[string]interface{}); ok {
				path, ok1 := item["path"].(string)
				content, ok2 := item["content"].(string)
				if ok1 && ok2 && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
					yamls = append(yamls, RepoYAML{Path: path, Content: content})
				}
			}
		}
	}
	return yamls
}

// FetchFeeds returns a list of all feeds in the organization
func FetchFeeds(orgURL, pat string) []map[string]interface{} {
	url := fmt.Sprintf("%s/_apis/packaging/feeds?api-version=6.0-preview.1", orgURL)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return nil
	}

	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	val, ok := result["value"].([]interface{})
	if !ok {
		return nil
	}

	feeds := []map[string]interface{}{}
	for _, v := range val {
		if feed, ok := v.(map[string]interface{}); ok {
			feeds = append(feeds, feed)
		}
	}

	return feeds
}

// FetchFeedPackages returns all packages within a feed
func FetchFeedPackages(orgURL, pat, feedName string) []map[string]interface{} {
	url := fmt.Sprintf("%s/_apis/packaging/feeds/%s/packages?api-version=6.0-preview.1", orgURL, feedName)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return nil
	}

	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	val, ok := result["value"].([]interface{})
	if !ok {
		return nil
	}

	packages := []map[string]interface{}{}
	for _, v := range val {
		if pkg, ok := v.(map[string]interface{}); ok {
			// Extract latest version if available
			if versions, ok := pkg["versions"].([]interface{}); ok && len(versions) > 0 {
				if latest, ok := versions[0].(map[string]interface{}); ok {
					pkg["version"] = latest["version"]
				}
			}
			packages = append(packages, pkg)
		}
	}

	return packages
}

// FetchPackageYAML fetches YAML or package metadata if applicable
func FetchPackageYAML(orgURL, pat, feedName, packageName, version string) string {
	// For generic packages, Azure DevOps doesn’t provide YAML, but we can fetch package metadata
	url := fmt.Sprintf("%s/_apis/packaging/feeds/%s/packages/%s/versions/%s?api-version=6.0-preview.1", orgURL, feedName, packageName, version)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return ""
	}

	// Pretty-print JSON metadata for loot file
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return ""
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	return string(b)
}

// FetchBranches fetches all branches for a repo in a project
func FetchBranches(orgURL, pat, project, repo string) []Branch {
	url := fmt.Sprintf("%s/%s/_apis/git/repositories/%s/refs?filter=heads/&api-version=6.0", orgURL, project, repo)
	body := AzureDevOpsGET(url, pat)
	if body == nil {
		return nil
	}

	var result struct {
		Value []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	branches := []Branch{}
	for _, b := range result.Value {
		branchName := strings.TrimPrefix(b.Name, "refs/heads/")
		lastCommitSHA, author, date := FetchCommitInfo(orgURL, pat, project, repo, b.ObjectID)
		branches = append(branches, Branch{
			Name:             branchName,
			LastCommitSHA:    lastCommitSHA,
			LastCommitAuthor: author,
			LastCommitDate:   date,
		})
	}

	return branches
}

// FetchTags fetches all tags for a repo in a project
func FetchTags(orgURL, pat, project, repo string) []Tag {
	url := fmt.Sprintf("%s/%s/_apis/git/repositories/%s/refs?filter=tags/&api-version=6.0", orgURL, project, repo)
	body := AzureDevOpsGET(url, pat)
	if body == nil {
		return nil
	}

	var result struct {
		Value []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	tags := []Tag{}
	for _, t := range result.Value {
		tagName := strings.TrimPrefix(t.Name, "refs/tags/")
		lastCommitSHA, tagger, date := FetchCommitInfo(orgURL, pat, project, repo, t.ObjectID)
		tags = append(tags, Tag{
			Name:      tagName,
			CommitSHA: lastCommitSHA,
			Tagger:    fmt.Sprintf("%s (%s)", tagger, date),
		})
	}

	return tags
}

// FetchCommitInfo fetches commit information for a commit SHA
func FetchCommitInfo(orgURL, pat, project, repo, commitSHA string) (string, string, string) {
	url := fmt.Sprintf("%s/%s/_apis/git/repositories/%s/commits/%s?api-version=6.0", orgURL, project, repo, commitSHA)
	body := AzureDevOpsGET(url, pat)
	if body == nil {
		return commitSHA, "", ""
	}

	var commit struct {
		CommitID string `json:"commitId"`
		Author   struct {
			Name string `json:"name"`
			Date string `json:"date"`
		} `json:"author"`
	}

	if err := json.Unmarshal(body, &commit); err != nil {
		return commitSHA, "", ""
	}

	return commit.CommitID, commit.Author.Name, commit.Author.Date
}

// ==================== PIPELINE SECURITY ENHANCEMENTS ====================

// FetchPipelineDefinition fetches full pipeline definition including variables
func FetchPipelineDefinition(orgURL, pat, project string, pipelineID int) map[string]interface{} {
	url := fmt.Sprintf("%s/%s/_apis/build/definitions/%d?api-version=7.1", orgURL, project, pipelineID)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return nil
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	return result
}

// FetchServiceConnections fetches all service connections in a project
func FetchServiceConnections(orgURL, pat, project string) []map[string]interface{} {
	url := fmt.Sprintf("%s/%s/_apis/serviceendpoint/endpoints?api-version=7.1", orgURL, project)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return nil
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	if val, ok := result["value"].([]interface{}); ok {
		connections := []map[string]interface{}{}
		for _, v := range val {
			if conn, ok := v.(map[string]interface{}); ok {
				connections = append(connections, conn)
			}
		}
		return connections
	}
	return nil
}

// FetchVariableGroups fetches all variable groups in a project
func FetchVariableGroups(orgURL, pat, project string) []map[string]interface{} {
	url := fmt.Sprintf("%s/%s/_apis/distributedtask/variablegroups?api-version=7.1", orgURL, project)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return nil
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	if val, ok := result["value"].([]interface{}); ok {
		groups := []map[string]interface{}{}
		for _, v := range val {
			if group, ok := v.(map[string]interface{}); ok {
				groups = append(groups, group)
			}
		}
		return groups
	}
	return nil
}

// FetchSecureFiles fetches all secure files in a project
func FetchSecureFiles(orgURL, pat, project string) []map[string]interface{} {
	url := fmt.Sprintf("%s/%s/_apis/distributedtask/securefiles?api-version=7.1", orgURL, project)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return nil
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	if val, ok := result["value"].([]interface{}); ok {
		files := []map[string]interface{}{}
		for _, v := range val {
			if file, ok := v.(map[string]interface{}); ok {
				files = append(files, file)
			}
		}
		return files
	}
	return nil
}

// FetchPipelineRuns fetches recent pipeline runs
func FetchPipelineRuns(orgURL, pat, project string, pipelineID int, top int) []map[string]interface{} {
	url := fmt.Sprintf("%s/%s/_apis/build/builds?definitions=%d&$top=%d&api-version=7.1", orgURL, project, pipelineID, top)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return nil
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	if val, ok := result["value"].([]interface{}); ok {
		runs := []map[string]interface{}{}
		for _, v := range val {
			if run, ok := v.(map[string]interface{}); ok {
				runs = append(runs, run)
			}
		}
		return runs
	}
	return nil
}

// FetchExtensions fetches all installed extensions in an organization
func FetchExtensions(orgURL, pat string) []map[string]interface{} {
	url := fmt.Sprintf("%s/_apis/extensionmanagement/installedextensions?api-version=7.1", orgURL)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return nil
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	if val, ok := result["value"].([]interface{}); ok {
		extensions := []map[string]interface{}{}
		for _, v := range val {
			if ext, ok := v.(map[string]interface{}); ok {
				extensions = append(extensions, ext)
			}
		}
		return extensions
	}
	return nil
}

// FetchRepositoryPolicies fetches all policy configurations for a project
func FetchRepositoryPolicies(orgURL, pat, project string) []map[string]interface{} {
	url := fmt.Sprintf("%s/%s/_apis/policy/configurations?api-version=7.1", orgURL, project)
	respBody := AzureDevOpsGET(url, pat)
	if respBody == nil {
		return nil
	}
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	if val, ok := result["value"].([]interface{}); ok {
		policies := []map[string]interface{}{}
		for _, v := range val {
			if policy, ok := v.(map[string]interface{}); ok {
				policies = append(policies, policy)
			}
		}
		return policies
	}
	return nil
}

// ==================== AZURE DEVOPS AUTHENTICATION ====================

// GetDevOpsAuthToken retrieves authentication token for Azure DevOps
// Priority: 1. AZDO_PAT environment variable, 2. Azure AD token from az login
// Returns the token string and the authentication method used
func GetDevOpsAuthToken(session *SafeSession) (token string, authMethod string, err error) {
	// First, check for AZDO_PAT environment variable (preferred method)
	pat := PatFlag
	if pat == "" {
		pat = os.Getenv("AZDO_PAT")
	}

	if pat != "" {
		return pat, "PAT", nil
	}

	// Fallback to Azure AD authentication (az login)
	if session != nil {
		// Get Azure AD token for Azure DevOps resource
		// Using the GUID scope: 499b84ac-1321-427f-b974-133d113dbe4b/.default
		aadToken, err := session.GetTokenForResource("499b84ac-1321-427f-b974-133d113dbe4b/.default")
		if err == nil && aadToken != "" {
			return aadToken, "Azure AD", nil
		}
	}

	return "", "", fmt.Errorf("no authentication available: set AZDO_PAT or run 'az login'")
}

// GetDevOpsAuthTokenSimple is a simplified version that doesn't require SafeSession
// It only checks for AZDO_PAT or tries to get an Azure AD token directly from az CLI
func GetDevOpsAuthTokenSimple() (token string, authMethod string, err error) {
	// First, check for AZDO_PAT environment variable (preferred method)
	pat := PatFlag
	if pat == "" {
		pat = os.Getenv("AZDO_PAT")
	}

	if pat != "" {
		return pat, "PAT", nil
	}

	// Fallback to Azure AD authentication via az CLI
	// Get token for Azure DevOps resource: 499b84ac-1321-427f-b974-133d113dbe4b
	out, err := exec.Command("az", "account", "get-access-token",
		"--resource", "499b84ac-1321-427f-b974-133d113dbe4b",
		"--query", "accessToken",
		"-o", "tsv").Output()

	if err != nil {
		return "", "", fmt.Errorf("no authentication available: set AZDO_PAT or run 'az login'")
	}

	aadToken := strings.TrimSpace(string(out))
	if aadToken == "" {
		return "", "", fmt.Errorf("no authentication available: set AZDO_PAT or run 'az login'")
	}

	return aadToken, "Azure AD", nil
}
