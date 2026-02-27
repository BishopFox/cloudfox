package sdk

import (
	"context"

	"cloud.google.com/go/iam"
	"cloud.google.com/go/storage"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	cloudresourcemanagerv2 "google.golang.org/api/cloudresourcemanager/v2"
	compute "google.golang.org/api/compute/v1"
	iam_admin "google.golang.org/api/iam/v1"
	secretmanager "google.golang.org/api/secretmanager/v1"
)

// StorageClientInterface defines the interface for Cloud Storage operations
type StorageClientInterface interface {
	Buckets(ctx context.Context, projectID string) *storage.BucketIterator
	Bucket(name string) *storage.BucketHandle
	Close() error
}

// StorageBucketInterface defines the interface for bucket operations
type StorageBucketInterface interface {
	Attrs(ctx context.Context) (*storage.BucketAttrs, error)
	IAM() *iam.Handle
	Object(name string) *storage.ObjectHandle
	Objects(ctx context.Context, q *storage.Query) *storage.ObjectIterator
}

// ComputeServiceInterface defines the interface for Compute Engine operations
type ComputeServiceInterface interface {
	// Instances
	ListInstances(ctx context.Context, projectID, zone string) (*compute.InstanceList, error)
	AggregatedListInstances(ctx context.Context, projectID string) (*compute.InstanceAggregatedList, error)
	GetInstance(ctx context.Context, projectID, zone, instanceName string) (*compute.Instance, error)

	// Networks
	ListNetworks(ctx context.Context, projectID string) (*compute.NetworkList, error)
	GetNetwork(ctx context.Context, projectID, networkName string) (*compute.Network, error)

	// Firewalls
	ListFirewalls(ctx context.Context, projectID string) (*compute.FirewallList, error)

	// Zones
	ListZones(ctx context.Context, projectID string) (*compute.ZoneList, error)
}

// IAMServiceInterface defines the interface for IAM operations
type IAMServiceInterface interface {
	// Service Accounts
	ListServiceAccounts(ctx context.Context, projectID string) ([]*iam_admin.ServiceAccount, error)
	GetServiceAccount(ctx context.Context, name string) (*iam_admin.ServiceAccount, error)
	ListServiceAccountKeys(ctx context.Context, name string) ([]*iam_admin.ServiceAccountKey, error)

	// Roles
	ListRoles(ctx context.Context, projectID string) ([]*iam_admin.Role, error)
	GetRole(ctx context.Context, name string) (*iam_admin.Role, error)
}

// ResourceManagerServiceInterface defines the interface for Cloud Resource Manager operations
type ResourceManagerServiceInterface interface {
	// Projects
	ListProjects(ctx context.Context) ([]*cloudresourcemanager.Project, error)
	GetProject(ctx context.Context, projectID string) (*cloudresourcemanager.Project, error)
	GetProjectIAMPolicy(ctx context.Context, projectID string) (*cloudresourcemanager.Policy, error)

	// Organizations
	ListOrganizations(ctx context.Context) ([]*cloudresourcemanager.Organization, error)
	GetOrganization(ctx context.Context, name string) (*cloudresourcemanager.Organization, error)
	GetOrganizationIAMPolicy(ctx context.Context, resource string) (*cloudresourcemanager.Policy, error)

	// Folders
	ListFolders(ctx context.Context, parent string) ([]*cloudresourcemanagerv2.Folder, error)
}

// SecretManagerServiceInterface defines the interface for Secret Manager operations
type SecretManagerServiceInterface interface {
	// Secrets
	ListSecrets(ctx context.Context, projectID string) ([]*secretmanager.Secret, error)
	GetSecret(ctx context.Context, name string) (*secretmanager.Secret, error)
	ListSecretVersions(ctx context.Context, secretName string) ([]*secretmanager.SecretVersion, error)
	AccessSecretVersion(ctx context.Context, name string) (*secretmanager.AccessSecretVersionResponse, error)
}

// BigQueryServiceInterface defines the interface for BigQuery operations
type BigQueryServiceInterface interface {
	ListDatasets(ctx context.Context, projectID string) ([]string, error)
	ListTables(ctx context.Context, projectID, datasetID string) ([]string, error)
	GetDatasetIAMPolicy(ctx context.Context, projectID, datasetID string) (interface{}, error)
	GetTableIAMPolicy(ctx context.Context, projectID, datasetID, tableID string) (interface{}, error)
}

// ArtifactRegistryServiceInterface defines the interface for Artifact Registry operations
type ArtifactRegistryServiceInterface interface {
	ListRepositories(ctx context.Context, projectID, location string) ([]interface{}, error)
	GetRepository(ctx context.Context, name string) (interface{}, error)
	ListDockerImages(ctx context.Context, parent string) ([]interface{}, error)
}

// CloudFunctionsServiceInterface defines the interface for Cloud Functions operations
type CloudFunctionsServiceInterface interface {
	ListFunctions(ctx context.Context, projectID, location string) ([]interface{}, error)
	GetFunction(ctx context.Context, name string) (interface{}, error)
	GetFunctionIAMPolicy(ctx context.Context, resource string) (interface{}, error)
}

// CloudRunServiceInterface defines the interface for Cloud Run operations
type CloudRunServiceInterface interface {
	ListServices(ctx context.Context, projectID, location string) ([]interface{}, error)
	GetService(ctx context.Context, name string) (interface{}, error)
	GetServiceIAMPolicy(ctx context.Context, resource string) (interface{}, error)
}

// GKEServiceInterface defines the interface for GKE operations
type GKEServiceInterface interface {
	ListClusters(ctx context.Context, projectID, location string) ([]interface{}, error)
	GetCluster(ctx context.Context, name string) (interface{}, error)
}

// PubSubServiceInterface defines the interface for Pub/Sub operations
type PubSubServiceInterface interface {
	ListTopics(ctx context.Context, projectID string) ([]interface{}, error)
	ListSubscriptions(ctx context.Context, projectID string) ([]interface{}, error)
	GetTopicIAMPolicy(ctx context.Context, topic string) (interface{}, error)
}

// KMSServiceInterface defines the interface for KMS operations
type KMSServiceInterface interface {
	ListKeyRings(ctx context.Context, projectID, location string) ([]interface{}, error)
	ListCryptoKeys(ctx context.Context, keyRing string) ([]interface{}, error)
	GetCryptoKeyIAMPolicy(ctx context.Context, resource string) (interface{}, error)
}

// LoggingServiceInterface defines the interface for Cloud Logging operations
type LoggingServiceInterface interface {
	ListSinks(ctx context.Context, parent string) ([]interface{}, error)
	ListMetrics(ctx context.Context, parent string) ([]interface{}, error)
}
