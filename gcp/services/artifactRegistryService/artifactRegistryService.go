package artifactregistryservice

import (
	"context"
	"fmt"
	"strings"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	artifactregistrypb "cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"github.com/BishopFox/cloudfox/gcp/services/models"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
	locationpb "google.golang.org/genproto/googleapis/cloud/location"
)

// New creates a new instance of the ArtifactRegistryService using an artifactregistry.Client
func New(client *artifactregistry.Client) ArtifactRegistryService {
	ars := ArtifactRegistryService{
		Client: &ArtifactRegistryClientWrapper{
			Closer: client.Close,
			RepositoryLister: func(ctx context.Context, req *artifactregistrypb.ListRepositoriesRequest, opts ...gax.CallOption) models.GenericIterator[artifactregistrypb.Repository] {
				return client.ListRepositories(ctx, req, opts...)
			},
			LocationLister: func(ctx context.Context, req *locationpb.ListLocationsRequest, opts ...gax.CallOption) models.GenericIterator[locationpb.Location] {
				return client.ListLocations(ctx, req, opts...)
			},
			RepositoryGetter: func(ctx context.Context, req *artifactregistrypb.GetRepositoryRequest, opts ...gax.CallOption) (*artifactregistrypb.Repository, error) {
				return client.GetRepository(ctx, req, opts...)
			},
			DockerImageLister: func(ctx context.Context, req *artifactregistrypb.ListDockerImagesRequest, opts ...gax.CallOption) models.GenericIterator[artifactregistrypb.DockerImage] {
				return client.ListDockerImages(ctx, req, opts...)
			},
		},
	}
	return ars
}

var logger internal.Logger

// RepositoriesAndArtifacts retrieves both repositories and their artifacts for a given projectID.
func (ars *ArtifactRegistryService) RepositoriesAndArtifacts(projectID string) (CombinedRepoArtifactInfo, error) {
	var combinedInfo CombinedRepoArtifactInfo

	// Retrieve repositories.
	repos, err := ars.Repositories(projectID)
	if err != nil {
		return combinedInfo, fmt.Errorf("failed to retrieve repositories: %v", err)
	}
	combinedInfo.Repositories = repos

	// Iterate over repositories to fetch artifacts.
	for _, repo := range repos {
		// Extract location and repository name from the repository Name.
		parts := strings.Split(repo.Name, "/")
		if len(parts) < 6 {
			logger.InfoM("Unexpected repository name format, skipping artifacts retrieval", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
			continue
		}
		location := parts[3]
		repositoryName := parts[5]

		// Fetch artifacts for the current repository.
		artifacts, err := ars.Artifacts(projectID, location, repositoryName)
		if err != nil {
			logger.InfoM(fmt.Sprintf("Failed to retrieve artifacts for repository %s: %v", repositoryName, err), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
			continue // Optionally continue to the next repository or handle error differently.
		}
		combinedInfo.Artifacts = append(combinedInfo.Artifacts, artifacts...)
	}

	return combinedInfo, nil
}

// RepositoriesAndArtifacts returns a list of repositories and artifacts given projectID.
// TODO consider putting location as input, so that we can put Locations iteration before it & potentially filter by location at top level of GCP module
func (ars *ArtifactRegistryService) Repositories(projectID string) ([]RepositoryInfo, error) {
	// Get the list of available locations for the given project.
	locations, err := ars.projectLocations(projectID)
	if err != nil {
		return nil, err
	}

	var repositories []RepositoryInfo
	ctx := context.Background()
	// Construct the request for listing repositories.
	for _, location := range locations {
		req := &artifactregistrypb.ListRepositoriesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectID, location),
		}

		it := ars.Client.ListRepositories(ctx, req)
		for {
			repo, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, err
			}

			repositories = append(repositories, RepositoryInfo{
				Name:        repo.Name,
				Format:      repo.Format.String(),
				Description: repo.Description,
				SizeBytes:   fmt.Sprintf("%d", repo.SizeBytes),
				ProjectID:   projectID,
				Location:    location,
			})
		}
	}

	return repositories, nil
}

// Artifacts fetches the artifacts for a given repository, handling different formats.
func (ars *ArtifactRegistryService) Artifacts(projectID string, location string, repositoryName string) ([]ArtifactInfo, error) {
	ctx := context.Background()
	// client, err := artifactregistry.NewClient(ctx)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create artifact registry client: %v", err)
	// }
	// defer client.Close()

	repoFullName := fmt.Sprintf("projects/%s/locations/%s/repositories/%s", projectID, location, repositoryName)

	// Fetch repository details to determine its format
	repo, err := ars.Client.GetRepository(ctx, &artifactregistrypb.GetRepositoryRequest{Name: repoFullName})
	if err != nil {
		return nil, fmt.Errorf("failed to get repository details: %v", err)
	}

	// Handle different repository formats
	switch repo.Format {
	case artifactregistrypb.Repository_DOCKER:
		return ars.DockerImages(repoFullName)
	// Placeholder for other formats
	// case artifactregistrypb.Repository_MAVEN:
	// 	return listMavenArtifacts(ctx, client, repoFullName)
	// case artifactregistrypb.Repository_NPM:
	// 	return listNpmPackages(ctx, client, repoFullName)
	default:
		logger.InfoM("Repository format is unsupported, so no artifacts were retrieved.", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		return nil, nil
	}
}

// parseDockerImageName parses the Docker image name string and returns the extracted details.
func parseDockerImageName(imageName string) DockerImageDetails {
	// Split the image name by '/'
	parts := strings.Split(imageName, "/")

	// Extract details based on the known structure of the image name.
	// Assuming the format is always consistent as described.
	projectID := parts[1]
	location := parts[3]
	repository := parts[5]
	// The image name and digest are after the last '/', separated by '@'
	imageAndDigest := strings.Split(parts[7], "@")
	imageName = imageAndDigest[0]
	digest := imageAndDigest[1]

	return DockerImageDetails{
		ProjectID:  projectID,
		Location:   location,
		Repository: repository,
		ImageName:  imageName,
		Digest:     digest,
	}
}

// listDockerImages specifically lists Docker images within a given repository.
func (ars *ArtifactRegistryService) DockerImages(repositoryName string) ([]ArtifactInfo, error) {
	ctx := context.Background()
	var artifacts []ArtifactInfo

	req := &artifactregistrypb.ListDockerImagesRequest{
		Parent: repositoryName,
	}

	it := ars.Client.ListDockerImages(ctx, req)
	for {
		image, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		// Parse image name to extract detailed information.
		details := parseDockerImageName(image.Name)

		// Populate the ArtifactInfo structure with Docker image details.
		artifacts = append(artifacts, ArtifactInfo{
			Name:       details.ImageName,
			Format:     "DOCKER",
			Location:   details.Location,
			Repository: details.Repository,
			SizeBytes:  fmt.Sprintf("%d", image.ImageSizeBytes),
			Updated:    image.UpdateTime.AsTime().String(),
			Digest:     details.Digest,
			ProjectID:  details.ProjectID,
		})
	}

	return artifacts, nil
}

// listProjectLocations returns a list of available locations for the given project ID.
func (ars *ArtifactRegistryService) projectLocations(projectID string) ([]string, error) {
	// Define the request to list locations.
	req := &locationpb.ListLocationsRequest{
		Name: fmt.Sprintf("projects/%s", projectID),
	}

	// Initialize an empty slice to hold the locations.
	var locations []string

	// Call the ListLocations method and handle pagination.
	ctx := context.Background()
	it := ars.Client.ListLocations(ctx, req)
	for {
		loc, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list locations: %w", err)
		}
		locations = append(locations, loc.LocationId)
	}

	return locations, nil
}
