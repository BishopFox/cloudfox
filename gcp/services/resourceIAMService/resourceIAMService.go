package resourceiamservice

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	regionservice "github.com/BishopFox/cloudfox/gcp/services/regionService"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	run "google.golang.org/api/run/v1"
	secretmanager "google.golang.org/api/secretmanager/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	cloudfunctions "google.golang.org/api/cloudfunctions/v1"
)

// ResourceIAMService handles enumeration of resource-level IAM policies
type ResourceIAMService struct {
	session *gcpinternal.SafeSession
}

// New creates a new ResourceIAMService
func New() *ResourceIAMService {
	return &ResourceIAMService{}
}

// NewWithSession creates a ResourceIAMService with a SafeSession
func NewWithSession(session *gcpinternal.SafeSession) *ResourceIAMService {
	return &ResourceIAMService{session: session}
}

// getClientOption returns the appropriate client option based on session
func (s *ResourceIAMService) getClientOption() option.ClientOption {
	if s.session != nil {
		return s.session.GetClientOption()
	}
	return nil
}

// getSecretManagerService returns a cached Secret Manager service
func (s *ResourceIAMService) getSecretManagerService(ctx context.Context) (*secretmanager.Service, error) {
	if s.session != nil {
		return sdk.CachedGetSecretManagerService(ctx, s.session)
	}
	return secretmanager.NewService(ctx)
}

// getCloudFunctionsService returns a cached Cloud Functions service (v1)
func (s *ResourceIAMService) getCloudFunctionsService(ctx context.Context) (*cloudfunctions.Service, error) {
	if s.session != nil {
		return sdk.CachedGetCloudFunctionsService(ctx, s.session)
	}
	return cloudfunctions.NewService(ctx)
}

// getCloudRunService returns a cached Cloud Run service
func (s *ResourceIAMService) getCloudRunService(ctx context.Context) (*run.APIService, error) {
	if s.session != nil {
		return sdk.CachedGetCloudRunService(ctx, s.session)
	}
	return run.NewService(ctx)
}

// ResourceIAMBinding represents an IAM binding on a specific resource
type ResourceIAMBinding struct {
	ResourceType        string `json:"resourceType"`        // bucket, dataset, topic, secret, etc.
	ResourceName        string `json:"resourceName"`        // Full resource name
	ResourceID          string `json:"resourceId"`          // Short identifier
	ProjectID           string `json:"projectId"`
	Role                string `json:"role"`
	Member              string `json:"member"`
	MemberType          string `json:"memberType"`          // user, serviceAccount, group, allUsers, allAuthenticatedUsers
	MemberEmail         string `json:"memberEmail"`
	IsPublic            bool   `json:"isPublic"`            // allUsers or allAuthenticatedUsers
	HasCondition        bool   `json:"hasCondition"`
	ConditionTitle      string `json:"conditionTitle"`
	ConditionExpression string `json:"conditionExpression"` // Full CEL expression
}

// GetAllResourceIAM enumerates IAM policies across all supported resource types
func (s *ResourceIAMService) GetAllResourceIAM(ctx context.Context, projectID string) ([]ResourceIAMBinding, error) {
	var allBindings []ResourceIAMBinding

	// Get bucket IAM
	bucketBindings, err := s.GetBucketIAM(ctx, projectID)
	if err == nil {
		allBindings = append(allBindings, bucketBindings...)
	}

	// Get BigQuery dataset IAM
	bqBindings, err := s.GetBigQueryDatasetIAM(ctx, projectID)
	if err == nil {
		allBindings = append(allBindings, bqBindings...)
	}

	// Get Pub/Sub topic IAM
	pubsubBindings, err := s.GetPubSubIAM(ctx, projectID)
	if err == nil {
		allBindings = append(allBindings, pubsubBindings...)
	}

	// Get Secret Manager IAM
	secretBindings, err := s.GetSecretManagerIAM(ctx, projectID)
	if err == nil {
		allBindings = append(allBindings, secretBindings...)
	}

	// Get KMS IAM
	kmsBindings, err := s.GetKMSIAM(ctx, projectID)
	if err == nil {
		allBindings = append(allBindings, kmsBindings...)
	}

	// Get Cloud Functions IAM
	functionBindings, err := s.GetCloudFunctionsIAM(ctx, projectID)
	if err == nil {
		allBindings = append(allBindings, functionBindings...)
	}

	// Get Cloud Run IAM
	runBindings, err := s.GetCloudRunIAM(ctx, projectID)
	if err == nil {
		allBindings = append(allBindings, runBindings...)
	}

	return allBindings, nil
}

// GetBucketIAM enumerates IAM policies on Cloud Storage buckets
func (s *ResourceIAMService) GetBucketIAM(ctx context.Context, projectID string) ([]ResourceIAMBinding, error) {
	var bindings []ResourceIAMBinding

	var client *storage.Client
	var err error
	if s.session != nil {
		client, err = storage.NewClient(ctx, s.getClientOption())
	} else {
		client, err = storage.NewClient(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "storage.googleapis.com")
	}
	defer client.Close()

	// List buckets
	it := client.Buckets(ctx, projectID)
	for {
		bucketAttrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		// Get IAM policy for this bucket
		bucket := client.Bucket(bucketAttrs.Name)
		policy, err := bucket.IAM().Policy(ctx)
		if err != nil {
			continue
		}

		// Convert policy to bindings
		for _, role := range policy.Roles() {
			for _, member := range policy.Members(role) {
				binding := ResourceIAMBinding{
					ResourceType: "bucket",
					ResourceName: fmt.Sprintf("gs://%s", bucketAttrs.Name),
					ResourceID:   bucketAttrs.Name,
					ProjectID:    projectID,
					Role:         string(role),
					Member:       member,
					MemberType:   determineMemberType(member),
					MemberEmail:  extractEmail(member),
					IsPublic:     isPublicMember(member),
				}
				bindings = append(bindings, binding)
			}
		}
	}

	return bindings, nil
}

// GetBigQueryDatasetIAM enumerates IAM policies on BigQuery datasets
func (s *ResourceIAMService) GetBigQueryDatasetIAM(ctx context.Context, projectID string) ([]ResourceIAMBinding, error) {
	var bindings []ResourceIAMBinding

	var client *bigquery.Client
	var err error
	if s.session != nil {
		client, err = bigquery.NewClient(ctx, projectID, s.getClientOption())
	} else {
		client, err = bigquery.NewClient(ctx, projectID)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "bigquery.googleapis.com")
	}
	defer client.Close()

	// List datasets
	it := client.Datasets(ctx)
	for {
		dataset, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		// Get metadata which includes access entries (IAM-like)
		meta, err := dataset.Metadata(ctx)
		if err != nil {
			continue
		}

		// BigQuery uses Access entries instead of IAM policies
		for _, access := range meta.Access {
			member := access.Entity
			entityTypeStr := fmt.Sprintf("%v", access.EntityType)

			// Determine member type and if public based on entity type
			isPublic := false
			memberType := entityTypeStr

			switch access.EntityType {
			case bigquery.UserEmailEntity:
				memberType = "User"
				member = "user:" + access.Entity
			case bigquery.GroupEmailEntity:
				memberType = "Group"
				member = "group:" + access.Entity
			case bigquery.DomainEntity:
				memberType = "Domain"
				member = "domain:" + access.Entity
			case bigquery.SpecialGroupEntity:
				// Special groups include allAuthenticatedUsers
				if access.Entity == "allAuthenticatedUsers" {
					memberType = "allAuthenticatedUsers"
					member = "allAuthenticatedUsers"
					isPublic = true
				} else {
					memberType = "SpecialGroup"
				}
			case bigquery.IAMMemberEntity:
				memberType = determineMemberType(access.Entity)
				isPublic = isPublicMember(access.Entity)
			}

			if member == "" {
				continue
			}

			binding := ResourceIAMBinding{
				ResourceType: "dataset",
				ResourceName: fmt.Sprintf("%s.%s", projectID, dataset.DatasetID),
				ResourceID:   dataset.DatasetID,
				ProjectID:    projectID,
				Role:         string(access.Role),
				Member:       member,
				MemberType:   memberType,
				MemberEmail:  extractEmail(member),
				IsPublic:     isPublic,
			}
			bindings = append(bindings, binding)
		}
	}

	return bindings, nil
}

// GetPubSubIAM enumerates IAM policies on Pub/Sub topics and subscriptions
func (s *ResourceIAMService) GetPubSubIAM(ctx context.Context, projectID string) ([]ResourceIAMBinding, error) {
	var bindings []ResourceIAMBinding

	var client *pubsub.Client
	var err error
	if s.session != nil {
		client, err = pubsub.NewClient(ctx, projectID, s.getClientOption())
	} else {
		client, err = pubsub.NewClient(ctx, projectID)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "pubsub.googleapis.com")
	}
	defer client.Close()

	// List topics
	topicIt := client.Topics(ctx)
	for {
		topic, err := topicIt.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		// Get IAM policy for this topic
		policy, err := topic.IAM().Policy(ctx)
		if err != nil {
			continue
		}

		topicID := topic.ID()
		for _, role := range policy.Roles() {
			for _, member := range policy.Members(role) {
				binding := ResourceIAMBinding{
					ResourceType: "topic",
					ResourceName: fmt.Sprintf("projects/%s/topics/%s", projectID, topicID),
					ResourceID:   topicID,
					ProjectID:    projectID,
					Role:         string(role),
					Member:       member,
					MemberType:   determineMemberType(member),
					MemberEmail:  extractEmail(member),
					IsPublic:     isPublicMember(member),
				}
				bindings = append(bindings, binding)
			}
		}
	}

	// List subscriptions
	subIt := client.Subscriptions(ctx)
	for {
		sub, err := subIt.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		// Get IAM policy for this subscription
		policy, err := sub.IAM().Policy(ctx)
		if err != nil {
			continue
		}

		subID := sub.ID()
		for _, role := range policy.Roles() {
			for _, member := range policy.Members(role) {
				binding := ResourceIAMBinding{
					ResourceType: "subscription",
					ResourceName: fmt.Sprintf("projects/%s/subscriptions/%s", projectID, subID),
					ResourceID:   subID,
					ProjectID:    projectID,
					Role:         string(role),
					Member:       member,
					MemberType:   determineMemberType(member),
					MemberEmail:  extractEmail(member),
					IsPublic:     isPublicMember(member),
				}
				bindings = append(bindings, binding)
			}
		}
	}

	return bindings, nil
}

// GetSecretManagerIAM enumerates IAM policies on Secret Manager secrets
func (s *ResourceIAMService) GetSecretManagerIAM(ctx context.Context, projectID string) ([]ResourceIAMBinding, error) {
	var bindings []ResourceIAMBinding

	smService, err := s.getSecretManagerService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "secretmanager.googleapis.com")
	}

	// List secrets (with pagination)
	parent := fmt.Sprintf("projects/%s", projectID)
	pageToken := ""
	var allSecrets []*secretmanager.Secret
	for {
		call := smService.Projects.Secrets.List(parent).Context(ctx)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "secretmanager.googleapis.com")
		}
		allSecrets = append(allSecrets, resp.Secrets...)
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	for _, secret := range allSecrets {
		// Get IAM policy for this secret
		policy, err := smService.Projects.Secrets.GetIamPolicy(secret.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		secretID := extractSecretID(secret.Name)
		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				b := ResourceIAMBinding{
					ResourceType: "secret",
					ResourceName: secret.Name,
					ResourceID:   secretID,
					ProjectID:    projectID,
					Role:         binding.Role,
					Member:       member,
					MemberType:   determineMemberType(member),
					MemberEmail:  extractEmail(member),
					IsPublic:     isPublicMember(member),
				}
				if binding.Condition != nil {
					b.HasCondition = true
					b.ConditionTitle = binding.Condition.Title
					b.ConditionExpression = binding.Condition.Expression
				}
				bindings = append(bindings, b)
			}
		}
	}

	return bindings, nil
}

// GetKMSIAM enumerates IAM policies on KMS keys
func (s *ResourceIAMService) GetKMSIAM(ctx context.Context, projectID string) ([]ResourceIAMBinding, error) {
	var bindings []ResourceIAMBinding

	var client *kms.KeyManagementClient
	var err error
	if s.session != nil {
		client, err = kms.NewKeyManagementClient(ctx, s.getClientOption())
	} else {
		client, err = kms.NewKeyManagementClient(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudkms.googleapis.com")
	}
	defer client.Close()

	// Get regions from regionService (with automatic fallback) plus global and multi-region locations
	regions := regionservice.GetCachedRegionNames(ctx, projectID)
	// Add global and multi-region locations that KMS supports
	locations := append([]string{"global", "us", "eu", "asia"}, regions...)

	for _, location := range locations {
		parent := fmt.Sprintf("projects/%s/locations/%s", projectID, location)

		keyRingIt := client.ListKeyRings(ctx, &kmspb.ListKeyRingsRequest{Parent: parent})
		for {
			keyRing, err := keyRingIt.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}

			// List keys in this key ring
			keyIt := client.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: keyRing.Name})
			for {
				key, err := keyIt.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					break
				}

				// Get IAM policy for this key
				policy, err := client.ResourceIAM(key.Name).Policy(ctx)
				if err != nil {
					continue
				}

				keyID := extractKeyID(key.Name)
				for _, role := range policy.Roles() {
					for _, member := range policy.Members(role) {
						binding := ResourceIAMBinding{
							ResourceType: "cryptoKey",
							ResourceName: key.Name,
							ResourceID:   keyID,
							ProjectID:    projectID,
							Role:         string(role),
							Member:       member,
							MemberType:   determineMemberType(member),
							MemberEmail:  extractEmail(member),
							IsPublic:     isPublicMember(member),
						}
						bindings = append(bindings, binding)
					}
				}
			}
		}
	}

	return bindings, nil
}

// GetCloudFunctionsIAM enumerates IAM policies on Cloud Functions
func (s *ResourceIAMService) GetCloudFunctionsIAM(ctx context.Context, projectID string) ([]ResourceIAMBinding, error) {
	var bindings []ResourceIAMBinding

	cfService, err := s.getCloudFunctionsService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudfunctions.googleapis.com")
	}

	// List functions across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	resp, err := cfService.Projects.Locations.Functions.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudfunctions.googleapis.com")
	}

	for _, fn := range resp.Functions {
		// Get IAM policy for this function
		policy, err := cfService.Projects.Locations.Functions.GetIamPolicy(fn.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		fnID := extractFunctionID(fn.Name)
		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				b := ResourceIAMBinding{
					ResourceType: "function",
					ResourceName: fn.Name,
					ResourceID:   fnID,
					ProjectID:    projectID,
					Role:         binding.Role,
					Member:       member,
					MemberType:   determineMemberType(member),
					MemberEmail:  extractEmail(member),
					IsPublic:     isPublicMember(member),
				}
				if binding.Condition != nil {
					b.HasCondition = true
					b.ConditionTitle = binding.Condition.Title
					b.ConditionExpression = binding.Condition.Expression
				}
				bindings = append(bindings, b)
			}
		}
	}

	return bindings, nil
}

// GetCloudRunIAM enumerates IAM policies on Cloud Run services
func (s *ResourceIAMService) GetCloudRunIAM(ctx context.Context, projectID string) ([]ResourceIAMBinding, error) {
	var bindings []ResourceIAMBinding

	runService, err := s.getCloudRunService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "run.googleapis.com")
	}

	// List services across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	resp, err := runService.Projects.Locations.Services.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "run.googleapis.com")
	}

	for _, svc := range resp.Items {
		// Get IAM policy for this service
		policy, err := runService.Projects.Locations.Services.GetIamPolicy(svc.Metadata.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		svcID := svc.Metadata.Name
		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				b := ResourceIAMBinding{
					ResourceType: "cloudrun",
					ResourceName: svc.Metadata.Name,
					ResourceID:   svcID,
					ProjectID:    projectID,
					Role:         binding.Role,
					Member:       member,
					MemberType:   determineMemberType(member),
					MemberEmail:  extractEmail(member),
					IsPublic:     isPublicMember(member),
				}
				if binding.Condition != nil {
					b.HasCondition = true
					b.ConditionTitle = binding.Condition.Title
					b.ConditionExpression = binding.Condition.Expression
				}
				bindings = append(bindings, b)
			}
		}
	}

	return bindings, nil
}

// Helper functions

func determineMemberType(member string) string {
	switch {
	case member == "allUsers":
		return "allUsers"
	case member == "allAuthenticatedUsers":
		return "allAuthenticatedUsers"
	case strings.HasPrefix(member, "user:"):
		return "User"
	case strings.HasPrefix(member, "serviceAccount:"):
		return "ServiceAccount"
	case strings.HasPrefix(member, "group:"):
		return "Group"
	case strings.HasPrefix(member, "domain:"):
		return "Domain"
	case strings.HasPrefix(member, "principal:"):
		return "Federated"
	case strings.HasPrefix(member, "principalSet:"):
		return "FederatedSet"
	default:
		return "Unknown"
	}
}

func extractEmail(member string) string {
	if strings.Contains(member, ":") {
		parts := strings.SplitN(member, ":", 2)
		if len(parts) == 2 {
			return parts[1]
		}
	}
	return member
}

func isPublicMember(member string) bool {
	return member == "allUsers" || member == "allAuthenticatedUsers"
}

func extractSecretID(name string) string {
	// Format: projects/{project}/secrets/{secret}
	parts := strings.Split(name, "/")
	if len(parts) >= 4 {
		return parts[len(parts)-1]
	}
	return name
}

func extractKeyID(name string) string {
	// Format: projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}
	parts := strings.Split(name, "/")
	if len(parts) >= 8 {
		return parts[len(parts)-1]
	}
	return name
}

func extractFunctionID(name string) string {
	// Format: projects/{project}/locations/{location}/functions/{function}
	parts := strings.Split(name, "/")
	if len(parts) >= 6 {
		return parts[len(parts)-1]
	}
	return name
}
