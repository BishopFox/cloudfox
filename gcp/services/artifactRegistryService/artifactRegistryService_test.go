package artifactregistryservice_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	artifactRegistryService "github.com/BishopFox/cloudfox/gcp/services/artifactRegistryService"
	"github.com/BishopFox/cloudfox/gcp/services/models"

	artifactregistrypb "cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
	locationpb "google.golang.org/genproto/googleapis/cloud/location"
)

// Mock structure for ArtifactRegistryClientWrapper
type mockArtifactRegistryClient struct {
	repositories []*artifactregistrypb.Repository
	locations    []*locationpb.Location
	dockerImages []*artifactregistrypb.DockerImage
}

func (m *mockArtifactRegistryClient) Close() error {
	return nil
}

// Mock iterator for repositories
type mockRepoIterator struct {
	repositories []*artifactregistrypb.Repository
	index        int
}

func (it *mockRepoIterator) Next() (*artifactregistrypb.Repository, error) {
	if it.index < len(it.repositories) {
		repo := it.repositories[it.index]
		it.index++
		return repo, nil
	}
	return nil, iterator.Done
}

// Mock iterator for locations
type mockLocationIterator struct {
	locations []*locationpb.Location
	index     int
}

func (it *mockLocationIterator) Next() (*locationpb.Location, error) {
	if it.index < len(it.locations) {
		loc := it.locations[it.index]
		it.index++
		return loc, nil
	}
	return nil, iterator.Done
}

// Mock iterator for Docker images
type mockDockerImageIterator struct {
	dockerImages []*artifactregistrypb.DockerImage
	index        int
}

func (it *mockDockerImageIterator) Next() (*artifactregistrypb.DockerImage, error) {
	if it.index < len(it.dockerImages) {
		img := it.dockerImages[it.index]
		it.index++
		return img, nil
	}
	return nil, iterator.Done
}

// Mock methods
func (m *mockArtifactRegistryClient) ListRepositories(ctx context.Context, req *artifactregistrypb.ListRepositoriesRequest, opts ...gax.CallOption) models.GenericIterator[artifactregistrypb.Repository] {
	return &mockRepoIterator{repositories: m.repositories}
}

func (m *mockArtifactRegistryClient) ListLocations(ctx context.Context, req *locationpb.ListLocationsRequest, opts ...gax.CallOption) models.GenericIterator[locationpb.Location] {
	return &mockLocationIterator{locations: m.locations}
}

func (m *mockArtifactRegistryClient) GetRepository(ctx context.Context, req *artifactregistrypb.GetRepositoryRequest, opts ...gax.CallOption) (*artifactregistrypb.Repository, error) {
	for _, repo := range m.repositories {
		if repo.Name == req.Name {
			return repo, nil
		}
	}
	return nil, fmt.Errorf("repository not found")
}

func (m *mockArtifactRegistryClient) ListDockerImages(ctx context.Context, req *artifactregistrypb.ListDockerImagesRequest, opts ...gax.CallOption) models.GenericIterator[artifactregistrypb.DockerImage] {
	return &mockDockerImageIterator{dockerImages: m.dockerImages}
}

var mockClient = mockArtifactRegistryClient{}

var ars = artifactRegistryService.ArtifactRegistryService{
	Client: &artifactRegistryService.ArtifactRegistryClientWrapper{
		Closer: mockClient.Close,
		RepositoryLister: func(ctx context.Context, req *artifactregistrypb.ListRepositoriesRequest, opts ...gax.CallOption) models.GenericIterator[artifactregistrypb.Repository] {
			return mockClient.ListRepositories(ctx, req, opts...)
		},
		LocationLister: func(ctx context.Context, req *locationpb.ListLocationsRequest, opts ...gax.CallOption) models.GenericIterator[locationpb.Location] {
			return mockClient.ListLocations(ctx, req, opts...)
		},
		RepositoryGetter: func(ctx context.Context, req *artifactregistrypb.GetRepositoryRequest, opts ...gax.CallOption) (*artifactregistrypb.Repository, error) {
			return mockClient.GetRepository(ctx, req, opts...)
		},
		DockerImageLister: func(ctx context.Context, req *artifactregistrypb.ListDockerImagesRequest, opts ...gax.CallOption) models.GenericIterator[artifactregistrypb.DockerImage] {
			return mockClient.ListDockerImages(ctx, req, opts...)
		},
	},
}

// Tests go here
func TestArtifacts(t *testing.T) {
	cases := []struct {
		name              string
		projectID         string
		location          string
		repositoryName    string
		setupMockClient   func(client *mockArtifactRegistryClient)
		expectedArtifacts []artifactRegistryService.ArtifactInfo
		expectError       bool
	}{
		{
			name:           "Valid artifacts retrieval",
			projectID:      "project1",
			location:       "us-central1",
			repositoryName: "repo1",
			setupMockClient: func(client *mockArtifactRegistryClient) {
				client.dockerImages = []*artifactregistrypb.DockerImage{
					{
						Name:           "projects/project1/locations/us-central1/repositories/repo1/dockerImages/image1@sha256:e9954c1fc875017be1c3e36eca16be2d9e9bccc4bf072163515467d6a823c7cf",
						Uri:            "us-central1-docker.pkg.dev/project1/repo1/image1@sha256:e9954c1fc875017be1c3e36eca16be2d9e9bccc4bf072163515467d6a823c7cf",
						ImageSizeBytes: 1024,
					},
				}
				client.locations = []*locationpb.Location{
					{
						LocationId: "us-central1",
					},
				}
				client.repositories = []*artifactregistrypb.Repository{{
					Name:   "projects/project1/locations/us-central1/repositories/repo1",
					Format: artifactregistrypb.Repository_DOCKER,
				},
				}
			},
			expectedArtifacts: []artifactRegistryService.ArtifactInfo{
				{
					Name:       "image1",
					Format:     "DOCKER",
					Location:   "us-central1",
					Repository: "repo1",
					SizeBytes:  "1024",
					ProjectID:  "project1",
					Digest:     "sha256:e9954c1fc875017be1c3e36eca16be2d9e9bccc4bf072163515467d6a823c7cf",
					Updated:    "1970-01-01 00:00:00 +0000 UTC",
				},
			},
			expectError: false,
		},
		// Add more test cases here
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset mockClient state
			mockClient.repositories = nil
			mockClient.locations = nil
			mockClient.dockerImages = nil

			// Setup mock client for the current test case
			tc.setupMockClient(&mockClient)

			artifacts, err := ars.Artifacts(tc.projectID, tc.location, tc.repositoryName)
			if (err != nil) != tc.expectError {
				t.Errorf("Artifacts() error = %v, expectError %v", err, tc.expectError)
				return
			}

			if !reflect.DeepEqual(artifacts, tc.expectedArtifacts) {
				t.Errorf("Artifacts() = %v, expected %v", artifacts, tc.expectedArtifacts)
			}
		})
	}
}

func TestRepositories(t *testing.T) {
	cases := []struct {
		name                 string
		projectID            string
		setupMockClient      func(client *mockArtifactRegistryClient)
		expectedRepositories []artifactRegistryService.RepositoryInfo
		expectError          bool
	}{
		{
			name:      "Valid repositories retrieval",
			projectID: "project1",
			setupMockClient: func(client *mockArtifactRegistryClient) {
				client.repositories = []*artifactregistrypb.Repository{
					{
						Name:        "projects/project1/locations/us-central1/repositories/repo1",
						Format:      artifactregistrypb.Repository_DOCKER,
						Description: "Test repository",
					},
				}
				client.locations = []*locationpb.Location{
					{
						LocationId: "us-central1",
					},
				}
			},
			expectedRepositories: []artifactRegistryService.RepositoryInfo{
				{
					Name:        "projects/project1/locations/us-central1/repositories/repo1",
					Format:      "DOCKER",
					Description: "Test repository",
					SizeBytes:   "0",
					ProjectID:   "project1",
					Location:    "us-central1",
				},
			},
			expectError: false,
		},
		// Add more test cases here
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset mockClient state
			mockClient.repositories = nil
			mockClient.locations = nil
			mockClient.dockerImages = nil

			// Setup mock client for the current test case
			tc.setupMockClient(&mockClient)

			repositories, err := ars.Repositories(tc.projectID)
			if (err != nil) != tc.expectError {
				t.Errorf("Repositories() error = %v, expectError %v", err, tc.expectError)
				return
			}

			if !reflect.DeepEqual(repositories, tc.expectedRepositories) {
				t.Errorf("Repositories() = %v, expected %v", repositories, tc.expectedRepositories)
			}
		})
	}
}
