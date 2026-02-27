package artifactregistryservice

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	artifactregistrypb "cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"github.com/BishopFox/cloudfox/gcp/services/models"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
	iampb "google.golang.org/genproto/googleapis/iam/v1"
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
			RawClient: client,
		},
	}
	return ars
}

// NewWithSession creates an ArtifactRegistryService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) (ArtifactRegistryService, error) {
	ctx := context.Background()
	var client *artifactregistry.Client
	var err error

	if session != nil {
		client, err = artifactregistry.NewClient(ctx, session.GetClientOption())
	} else {
		client, err = artifactregistry.NewClient(ctx)
	}
	if err != nil {
		return ArtifactRegistryService{}, gcpinternal.ParseGCPError(err, "artifactregistry.googleapis.com")
	}

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
			RawClient: client,
		},
		Session: session,
	}
	return ars, nil
}

var logger internal.Logger

// RepositoriesAndArtifacts retrieves both repositories and their artifacts for a given projectID.
func (ars *ArtifactRegistryService) RepositoriesAndArtifacts(projectID string) (CombinedRepoArtifactInfo, error) {
	var combinedInfo CombinedRepoArtifactInfo

	// Retrieve repositories.
	repos, err := ars.Repositories(projectID)
	if err != nil {
		return combinedInfo, gcpinternal.ParseGCPError(err, "artifactregistry.googleapis.com")
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
			parsedErr := gcpinternal.ParseGCPError(err, "artifactregistry.googleapis.com")
			gcpinternal.HandleGCPError(parsedErr, logger, globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME,
				fmt.Sprintf("Failed to retrieve artifacts for repository %s", repositoryName))
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

			repoInfo := RepositoryInfo{
				Name:         repo.Name,
				Format:       repo.Format.String(),
				Description:  repo.Description,
				SizeBytes:    fmt.Sprintf("%d", repo.SizeBytes),
				ProjectID:    projectID,
				Location:     location,
				Mode:         repo.Mode.String(),
				Labels:       repo.Labels,
				RegistryType: "artifact-registry",
			}

			// Parse encryption
			if repo.KmsKeyName != "" {
				repoInfo.EncryptionType = "CMEK"
				repoInfo.KMSKeyName = repo.KmsKeyName
			} else {
				repoInfo.EncryptionType = "Google-managed"
			}

			// Parse cleanup policies
			if repo.CleanupPolicies != nil {
				repoInfo.CleanupPolicies = len(repo.CleanupPolicies)
			}

			// Parse timestamps
			if repo.CreateTime != nil {
				repoInfo.CreateTime = repo.CreateTime.AsTime().Format(time.RFC3339)
			}
			if repo.UpdateTime != nil {
				repoInfo.UpdateTime = repo.UpdateTime.AsTime().Format(time.RFC3339)
			}

			// Get IAM policy for the repository
			iamBindings, isPublic, publicAccess := ars.getRepositoryIAMPolicy(ctx, repo.Name)
			repoInfo.IAMBindings = iamBindings
			repoInfo.IsPublic = isPublic
			repoInfo.PublicAccess = publicAccess

			repositories = append(repositories, repoInfo)
		}
	}

	return repositories, nil
}

// getRepositoryIAMPolicy retrieves the IAM policy for a repository
func (ars *ArtifactRegistryService) getRepositoryIAMPolicy(ctx context.Context, repoName string) ([]IAMBinding, bool, string) {
	var bindings []IAMBinding
	isPublic := false
	hasAllUsers := false
	hasAllAuthenticatedUsers := false

	// Get raw client for IAM operations
	client, ok := ars.Client.RawClient.(*artifactregistry.Client)
	if !ok || client == nil {
		return bindings, false, "Unknown"
	}

	// Get IAM policy
	req := &iampb.GetIamPolicyRequest{
		Resource: repoName,
	}

	policy, err := client.GetIamPolicy(ctx, req)
	if err != nil {
		// Return empty bindings if we can't get the policy
		return bindings, false, "Unknown"
	}

	// Convert IAM policy to our binding format
	for _, binding := range policy.Bindings {
		iamBinding := IAMBinding{
			Role:    binding.Role,
			Members: binding.Members,
		}
		bindings = append(bindings, iamBinding)

		// Check for public access
		for _, member := range binding.Members {
			if member == "allUsers" {
				hasAllUsers = true
				isPublic = true
			}
			if member == "allAuthenticatedUsers" {
				hasAllAuthenticatedUsers = true
				isPublic = true
			}
		}
	}

	// Determine public access level
	publicAccess := "None"
	if hasAllUsers && hasAllAuthenticatedUsers {
		publicAccess = "allUsers + allAuthenticatedUsers"
	} else if hasAllUsers {
		publicAccess = "allUsers"
	} else if hasAllAuthenticatedUsers {
		publicAccess = "allAuthenticatedUsers"
	}

	return bindings, isPublic, publicAccess
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
		return nil, gcpinternal.ParseGCPError(err, "artifactregistry.googleapis.com")
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

	// Validate expected format: projects/{project}/locations/{location}/repositories/{repo}/dockerImages/{image@digest}
	if len(parts) < 8 {
		return DockerImageDetails{ImageName: imageName}
	}

	projectID := parts[1]
	location := parts[3]
	repository := parts[5]
	// The image name and digest are after the last '/', separated by '@'
	imageAndDigest := strings.Split(parts[7], "@")
	imageName = imageAndDigest[0]
	digest := ""
	if len(imageAndDigest) > 1 {
		digest = imageAndDigest[1]
	}

	// URL-decode the image name (e.g., "library%2Fnginx" -> "library/nginx")
	decodedImageName, err := url.PathUnescape(imageName)
	if err != nil {
		decodedImageName = imageName // fallback to original if decode fails
	}

	return DockerImageDetails{
		ProjectID:  projectID,
		Location:   location,
		Repository: repository,
		ImageName:  decodedImageName,
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

		// Build version from tags or digest
		version := details.Digest
		if len(image.Tags) > 0 {
			version = image.Tags[0] // Use first tag as version
		}

		artifact := ArtifactInfo{
			Name:       details.ImageName,
			Format:     "DOCKER",
			Location:   details.Location,
			Repository: details.Repository,
			SizeBytes:  fmt.Sprintf("%d", image.ImageSizeBytes),
			Digest:     details.Digest,
			ProjectID:  details.ProjectID,
			Tags:       image.Tags,
			MediaType:  image.MediaType,
			URI:        image.Uri,
			Version:    version,
		}

		// Parse timestamps
		if image.UpdateTime != nil {
			artifact.Updated = image.UpdateTime.AsTime().Format(time.RFC3339)
		}
		if image.UploadTime != nil {
			artifact.Uploaded = image.UploadTime.AsTime().Format(time.RFC3339)
		}
		if image.BuildTime != nil {
			artifact.BuildTime = image.BuildTime.AsTime().Format(time.RFC3339)
		}

		artifacts = append(artifacts, artifact)
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
			return nil, gcpinternal.ParseGCPError(err, "artifactregistry.googleapis.com")
		}
		locations = append(locations, loc.LocationId)
	}

	return locations, nil
}

// ContainerRegistryRepositories enumerates legacy Container Registry (gcr.io) repositories
// Container Registry stores images in Cloud Storage buckets, so we check for those buckets
func (ars *ArtifactRegistryService) ContainerRegistryRepositories(projectID string) []RepositoryInfo {
	var repositories []RepositoryInfo

	// Container Registry uses specific bucket naming conventions:
	// - gcr.io -> artifacts.{project-id}.appspot.com (us multi-region)
	// - us.gcr.io -> us.artifacts.{project-id}.appspot.com
	// - eu.gcr.io -> eu.artifacts.{project-id}.appspot.com
	// - asia.gcr.io -> asia.artifacts.{project-id}.appspot.com

	gcrLocations := []struct {
		hostname string
		location string
	}{
		{"gcr.io", "us"},
		{"us.gcr.io", "us"},
		{"eu.gcr.io", "eu"},
		{"asia.gcr.io", "asia"},
	}

	for _, gcr := range gcrLocations {
		// Create a repository entry for potential GCR location
		// Note: We can't easily verify if the bucket exists without storage API access
		// This creates potential entries that the command can verify
		repo := RepositoryInfo{
			Name:           fmt.Sprintf("%s/%s", gcr.hostname, projectID),
			Format:         "DOCKER",
			Description:    fmt.Sprintf("Legacy Container Registry at %s", gcr.hostname),
			ProjectID:      projectID,
			Location:       gcr.location,
			Mode:           "STANDARD_REPOSITORY",
			EncryptionType: "Google-managed",
			RegistryType:   "container-registry",
			PublicAccess:   "Unknown", // Would need storage bucket IAM check
		}
		repositories = append(repositories, repo)
	}

	return repositories
}

// getMemberType extracts the member type from a GCP IAM member string
func GetMemberType(member string) string {
	switch {
	case member == "allUsers":
		return "PUBLIC"
	case member == "allAuthenticatedUsers":
		return "ALL_AUTHENTICATED"
	case strings.HasPrefix(member, "user:"):
		return "User"
	case strings.HasPrefix(member, "serviceAccount:"):
		return "ServiceAccount"
	case strings.HasPrefix(member, "group:"):
		return "Group"
	case strings.HasPrefix(member, "domain:"):
		return "Domain"
	case strings.HasPrefix(member, "projectOwner:"):
		return "ProjectOwner"
	case strings.HasPrefix(member, "projectEditor:"):
		return "ProjectEditor"
	case strings.HasPrefix(member, "projectViewer:"):
		return "ProjectViewer"
	case strings.HasPrefix(member, "deleted:"):
		return "Deleted"
	default:
		return "Unknown"
	}
}
