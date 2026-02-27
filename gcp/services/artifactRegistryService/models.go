package artifactregistryservice

import (
	"context"

	artifactregistrypb "cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"github.com/BishopFox/cloudfox/gcp/services/models"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/googleapis/gax-go/v2"
	locationpb "google.golang.org/genproto/googleapis/cloud/location"
)

// CombinedRepoArtifactInfo holds the combined information of repositories and their respective artifacts.
type CombinedRepoArtifactInfo struct {
	Repositories []RepositoryInfo `json:"repositories"`
	Artifacts    []ArtifactInfo   `json:"artifacts"`
}

// IAMBinding represents a single IAM binding on a repository
type IAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// ArtifactInfo represents the basic information of an artifact within a registry.
type ArtifactInfo struct {
	Name       string   `json:"name"`
	Format     string   `json:"format"`
	Version    string   `json:"version"`
	Location   string   `json:"location"`
	Repository string   `json:"repository"`
	SizeBytes  string   `json:"virtualSize"`
	Updated    string   `json:"updated"`
	Uploaded   string   `json:"uploaded"`
	BuildTime  string   `json:"buildTime"`
	Digest     string   `json:"digest"`
	ProjectID  string   `json:"projectID"`
	Tags       []string `json:"tags"`
	MediaType  string   `json:"mediaType"`
	URI        string   `json:"uri"`
}

// RepositoryInfo holds information about a repository and its artifacts.
type RepositoryInfo struct {
	// Basic info
	Name        string `json:"name"`
	Format      string `json:"format"`
	Description string `json:"description"`
	SizeBytes   string `json:"sizeBytes"`
	ProjectID   string `json:"projectID"`
	Location    string `json:"location"`

	// Security-relevant fields
	Mode             string            `json:"mode"`             // STANDARD_REPOSITORY, VIRTUAL_REPOSITORY, REMOTE_REPOSITORY
	EncryptionType   string            `json:"encryptionType"`   // "Google-managed" or "CMEK"
	KMSKeyName       string            `json:"kmsKeyName"`       // KMS key for CMEK
	CleanupPolicies  int               `json:"cleanupPolicies"`  // Number of cleanup policies
	Labels           map[string]string `json:"labels"`

	// Timestamps
	CreateTime       string            `json:"createTime"`
	UpdateTime       string            `json:"updateTime"`

	// IAM Policy
	IAMBindings      []IAMBinding      `json:"iamBindings"`
	IsPublic         bool              `json:"isPublic"`         // Has allUsers or allAuthenticatedUsers
	PublicAccess     string            `json:"publicAccess"`     // "None", "allUsers", "allAuthenticatedUsers", or "Both"

	// Registry type (for differentiating AR vs GCR)
	RegistryType     string            `json:"registryType"`     // "artifact-registry" or "container-registry"
}

// DockerImageDetails holds the extracted parts from a Docker image name.
type DockerImageDetails struct {
	ProjectID  string `json:"projectID"`
	Location   string `json:"location"`
	Repository string `json:"repository"`
	ImageName  string `json:"name"`
	Digest     string `json:"digest"`
}

// Function calls to the API are wrapped to facilitate mocking
type ArtifactRegistryClientWrapper struct {
	Closer            func() error
	RepositoryLister  func(ctx context.Context, req *artifactregistrypb.ListRepositoriesRequest, opts ...gax.CallOption) models.GenericIterator[artifactregistrypb.Repository]
	LocationLister    func(ctx context.Context, req *locationpb.ListLocationsRequest, opts ...gax.CallOption) models.GenericIterator[locationpb.Location]
	RepositoryGetter  func(ctx context.Context, req *artifactregistrypb.GetRepositoryRequest, opts ...gax.CallOption) (*artifactregistrypb.Repository, error)
	DockerImageLister func(ctx context.Context, req *artifactregistrypb.ListDockerImagesRequest, opts ...gax.CallOption) models.GenericIterator[artifactregistrypb.DockerImage]
	RawClient         interface{} // Store raw client for IAM operations
}

func (w *ArtifactRegistryClientWrapper) ListRepositories(ctx context.Context, req *artifactregistrypb.ListRepositoriesRequest, opts ...gax.CallOption) models.GenericIterator[artifactregistrypb.Repository] {
	return w.RepositoryLister(ctx, req, opts...)
}

func (w *ArtifactRegistryClientWrapper) ListLocations(ctx context.Context, req *locationpb.ListLocationsRequest, opts ...gax.CallOption) models.GenericIterator[locationpb.Location] {
	return w.LocationLister(ctx, req, opts...)
}

func (w *ArtifactRegistryClientWrapper) GetRepository(ctx context.Context, req *artifactregistrypb.GetRepositoryRequest, opts ...gax.CallOption) (*artifactregistrypb.Repository, error) {
	return w.RepositoryGetter(ctx, req, opts...)
}

func (w *ArtifactRegistryClientWrapper) ListDockerImages(ctx context.Context, req *artifactregistrypb.ListDockerImagesRequest, opts ...gax.CallOption) models.GenericIterator[artifactregistrypb.DockerImage] {
	return w.DockerImageLister(ctx, req, opts...)
}

// ArtifactRegistryService provides methods to interact with Artifact Registry resources.
type ArtifactRegistryService struct {
	Client  *ArtifactRegistryClientWrapper
	Session *gcpinternal.SafeSession
}
