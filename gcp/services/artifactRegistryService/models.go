package artifactregistryservice

import (
	"context"

	artifactregistrypb "cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"github.com/BishopFox/cloudfox/gcp/services/models"
	"github.com/googleapis/gax-go/v2"
	locationpb "google.golang.org/genproto/googleapis/cloud/location"
)

// CombinedRepoArtifactInfo holds the combined information of repositories and their respective artifacts.
type CombinedRepoArtifactInfo struct {
	Repositories []RepositoryInfo `json:"repositories"`
	Artifacts    []ArtifactInfo   `json:"artifacts"`
}

// ArtifactInfo represents the basic information of an artifact within a registry.
type ArtifactInfo struct {
	Name       string `json:"name"`
	Format     string `json:"format"`
	Version    string `json:"version"`
	Location   string `json:"location"`
	Repository string `json:"repository"`
	SizeBytes  string `json:"virtualSize"`
	Updated    string `json:"updated"`
	Digest     string `json:"digest"`
	ProjectID  string `json:"projectID"`
}

// RepositoryInfo holds information about a repository and its artifacts.
type RepositoryInfo struct {
	Name        string `json:"name"`
	Format      string `json:"format"`
	Description string `json:"description"`
	SizeBytes   string `json:"sizeBytes"`
	ProjectID   string `json:"projectID"`
	Location    string `json:"location"`
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
	Client *ArtifactRegistryClientWrapper
}
