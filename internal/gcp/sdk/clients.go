package sdk

import (
	"context"
	"fmt"

	// Go SDK clients (NewClient pattern)
	"cloud.google.com/go/artifactregistry/apiv1"
	"cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/resourcemanager/apiv3"
	secretmanagerclient "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/storage"

	// REST API services (NewService pattern)
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	accesscontextmanager "google.golang.org/api/accesscontextmanager/v1"
	apikeys "google.golang.org/api/apikeys/v2"
	artifactregistryapi "google.golang.org/api/artifactregistry/v1"
	beyondcorp "google.golang.org/api/beyondcorp/v1"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	bigtableadmin "google.golang.org/api/bigtableadmin/v2"
	certificatemanager "google.golang.org/api/certificatemanager/v1"
	cloudbuild "google.golang.org/api/cloudbuild/v1"
	cloudfunctions "google.golang.org/api/cloudfunctions/v1"
	cloudfunctionsv2 "google.golang.org/api/cloudfunctions/v2"
	cloudidentity "google.golang.org/api/cloudidentity/v1"
	cloudkms "google.golang.org/api/cloudkms/v1"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	cloudscheduler "google.golang.org/api/cloudscheduler/v1"
	composer "google.golang.org/api/composer/v1"
	compute "google.golang.org/api/compute/v1"
	container "google.golang.org/api/container/v1"
	dataflow "google.golang.org/api/dataflow/v1b3"
	dataproc "google.golang.org/api/dataproc/v1"
	dns "google.golang.org/api/dns/v1"
	file "google.golang.org/api/file/v1"
	iam "google.golang.org/api/iam/v1"
	iap "google.golang.org/api/iap/v1"
	logging "google.golang.org/api/logging/v2"
	notebooks "google.golang.org/api/notebooks/v1"
	orgpolicy "google.golang.org/api/orgpolicy/v2"
	pubsubapi "google.golang.org/api/pubsub/v1"
	redis "google.golang.org/api/redis/v1"
	run "google.golang.org/api/run/v1"
	runv2 "google.golang.org/api/run/v2"
	secretmanagerapi "google.golang.org/api/secretmanager/v1"
	servicenetworking "google.golang.org/api/servicenetworking/v1"
	sourcerepo "google.golang.org/api/sourcerepo/v1"
	spanner "google.golang.org/api/spanner/v1"
	sqladmin "google.golang.org/api/sqladmin/v1"
	sqladminbeta "google.golang.org/api/sqladmin/v1beta4"
	storageapi "google.golang.org/api/storage/v1"
)

// =============================================================================
// GO SDK CLIENTS (NewClient pattern) - These return *Client types
// =============================================================================

// GetStorageClient returns a Cloud Storage client (Go SDK)
func GetStorageClient(ctx context.Context, session *gcpinternal.SafeSession) (*storage.Client, error) {
	client, err := storage.NewClient(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %w", err)
	}
	return client, nil
}

// GetSecretManagerClient returns a Secret Manager client (Go SDK)
func GetSecretManagerClient(ctx context.Context, session *gcpinternal.SafeSession) (*secretmanagerclient.Client, error) {
	client, err := secretmanagerclient.NewClient(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %w", err)
	}
	return client, nil
}

// GetBigQueryClient returns a BigQuery client (Go SDK)
func GetBigQueryClient(ctx context.Context, session *gcpinternal.SafeSession, projectID string) (*bigquery.Client, error) {
	client, err := bigquery.NewClient(ctx, projectID, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create BigQuery client: %w", err)
	}
	return client, nil
}

// GetPubSubClient returns a Pub/Sub client (Go SDK)
func GetPubSubClient(ctx context.Context, session *gcpinternal.SafeSession, projectID string) (*pubsub.Client, error) {
	client, err := pubsub.NewClient(ctx, projectID, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Pub/Sub client: %w", err)
	}
	return client, nil
}

// GetAssetClient returns a Cloud Asset client (Go SDK)
func GetAssetClient(ctx context.Context, session *gcpinternal.SafeSession) (*asset.Client, error) {
	client, err := asset.NewClient(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create asset client: %w", err)
	}
	return client, nil
}

// GetArtifactRegistryClient returns an Artifact Registry client (Go SDK)
func GetArtifactRegistryClient(ctx context.Context, session *gcpinternal.SafeSession) (*artifactregistry.Client, error) {
	client, err := artifactregistry.NewClient(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create artifact registry client: %w", err)
	}
	return client, nil
}

// GetOrganizationsClient returns a Resource Manager Organizations client (Go SDK)
func GetOrganizationsClient(ctx context.Context, session *gcpinternal.SafeSession) (*resourcemanager.OrganizationsClient, error) {
	client, err := resourcemanager.NewOrganizationsClient(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create organizations client: %w", err)
	}
	return client, nil
}

// =============================================================================
// REST API SERVICES (NewService pattern) - These return *Service types
// =============================================================================

// GetComputeService returns a Compute Engine service
func GetComputeService(ctx context.Context, session *gcpinternal.SafeSession) (*compute.Service, error) {
	service, err := compute.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}
	return service, nil
}

// GetIAMService returns an IAM Admin service
func GetIAMService(ctx context.Context, session *gcpinternal.SafeSession) (*iam.Service, error) {
	service, err := iam.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM service: %w", err)
	}
	return service, nil
}

// GetResourceManagerService returns a Cloud Resource Manager service (v1)
func GetResourceManagerService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudresourcemanager.Service, error) {
	service, err := cloudresourcemanager.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}
	return service, nil
}

// GetSecretManagerService returns a Secret Manager service (REST API)
func GetSecretManagerService(ctx context.Context, session *gcpinternal.SafeSession) (*secretmanagerapi.Service, error) {
	service, err := secretmanagerapi.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager service: %w", err)
	}
	return service, nil
}

// GetBigQueryService returns a BigQuery service (REST API v2)
func GetBigQueryService(ctx context.Context, session *gcpinternal.SafeSession) (*bigqueryapi.Service, error) {
	service, err := bigqueryapi.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create BigQuery service: %w", err)
	}
	return service, nil
}

// GetStorageService returns a Cloud Storage service (REST API)
func GetStorageService(ctx context.Context, session *gcpinternal.SafeSession) (*storageapi.Service, error) {
	service, err := storageapi.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create storage service: %w", err)
	}
	return service, nil
}

// GetArtifactRegistryService returns an Artifact Registry service (REST API)
func GetArtifactRegistryService(ctx context.Context, session *gcpinternal.SafeSession) (*artifactregistryapi.Service, error) {
	service, err := artifactregistryapi.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Artifact Registry service: %w", err)
	}
	return service, nil
}

// GetContainerService returns a GKE Container service
func GetContainerService(ctx context.Context, session *gcpinternal.SafeSession) (*container.Service, error) {
	service, err := container.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create container service: %w", err)
	}
	return service, nil
}

// GetCloudRunService returns a Cloud Run service (v1)
func GetCloudRunService(ctx context.Context, session *gcpinternal.SafeSession) (*run.APIService, error) {
	service, err := run.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Run service: %w", err)
	}
	return service, nil
}

// GetCloudRunServiceV2 returns a Cloud Run service (v2)
func GetCloudRunServiceV2(ctx context.Context, session *gcpinternal.SafeSession) (*runv2.Service, error) {
	service, err := runv2.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Run v2 service: %w", err)
	}
	return service, nil
}

// GetCloudFunctionsService returns a Cloud Functions service (v1)
func GetCloudFunctionsService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudfunctions.Service, error) {
	service, err := cloudfunctions.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Functions service: %w", err)
	}
	return service, nil
}

// GetCloudFunctionsServiceV2 returns a Cloud Functions v2 service
func GetCloudFunctionsServiceV2(ctx context.Context, session *gcpinternal.SafeSession) (*cloudfunctionsv2.Service, error) {
	service, err := cloudfunctionsv2.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Functions v2 service: %w", err)
	}
	return service, nil
}

// GetCloudIdentityService returns a Cloud Identity service
func GetCloudIdentityService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudidentity.Service, error) {
	service, err := cloudidentity.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Identity service: %w", err)
	}
	return service, nil
}

// GetAccessContextManagerService returns an Access Context Manager service
func GetAccessContextManagerService(ctx context.Context, session *gcpinternal.SafeSession) (*accesscontextmanager.Service, error) {
	service, err := accesscontextmanager.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Access Context Manager service: %w", err)
	}
	return service, nil
}

// GetRedisService returns a Memorystore Redis service
func GetRedisService(ctx context.Context, session *gcpinternal.SafeSession) (*redis.Service, error) {
	service, err := redis.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis service: %w", err)
	}
	return service, nil
}

// GetServiceNetworkingService returns a Service Networking service
func GetServiceNetworkingService(ctx context.Context, session *gcpinternal.SafeSession) (*servicenetworking.APIService, error) {
	service, err := servicenetworking.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Service Networking service: %w", err)
	}
	return service, nil
}

// GetComposerService returns a Cloud Composer service
func GetComposerService(ctx context.Context, session *gcpinternal.SafeSession) (*composer.Service, error) {
	service, err := composer.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Composer service: %w", err)
	}
	return service, nil
}

// GetDataflowService returns a Dataflow service
func GetDataflowService(ctx context.Context, session *gcpinternal.SafeSession) (*dataflow.Service, error) {
	service, err := dataflow.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Dataflow service: %w", err)
	}
	return service, nil
}

// GetDataprocService returns a Dataproc service
func GetDataprocService(ctx context.Context, session *gcpinternal.SafeSession) (*dataproc.Service, error) {
	service, err := dataproc.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Dataproc service: %w", err)
	}
	return service, nil
}

// GetNotebooksService returns a Notebooks service
func GetNotebooksService(ctx context.Context, session *gcpinternal.SafeSession) (*notebooks.Service, error) {
	service, err := notebooks.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Notebooks service: %w", err)
	}
	return service, nil
}

// GetBeyondCorpService returns a BeyondCorp service
func GetBeyondCorpService(ctx context.Context, session *gcpinternal.SafeSession) (*beyondcorp.Service, error) {
	service, err := beyondcorp.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create BeyondCorp service: %w", err)
	}
	return service, nil
}

// GetIAPService returns an IAP service
func GetIAPService(ctx context.Context, session *gcpinternal.SafeSession) (*iap.Service, error) {
	service, err := iap.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create IAP service: %w", err)
	}
	return service, nil
}

// GetKMSService returns a Cloud KMS service
func GetKMSService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudkms.Service, error) {
	service, err := cloudkms.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS service: %w", err)
	}
	return service, nil
}

// GetSQLAdminService returns a Cloud SQL Admin service (v1)
func GetSQLAdminService(ctx context.Context, session *gcpinternal.SafeSession) (*sqladmin.Service, error) {
	service, err := sqladmin.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL Admin service: %w", err)
	}
	return service, nil
}

// GetSQLAdminServiceBeta returns a Cloud SQL Admin service (v1beta4)
func GetSQLAdminServiceBeta(ctx context.Context, session *gcpinternal.SafeSession) (*sqladminbeta.Service, error) {
	service, err := sqladminbeta.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL Admin beta service: %w", err)
	}
	return service, nil
}

// GetDNSService returns a Cloud DNS service
func GetDNSService(ctx context.Context, session *gcpinternal.SafeSession) (*dns.Service, error) {
	service, err := dns.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS service: %w", err)
	}
	return service, nil
}

// GetPubSubService returns a Pub/Sub service (REST API)
func GetPubSubService(ctx context.Context, session *gcpinternal.SafeSession) (*pubsubapi.Service, error) {
	service, err := pubsubapi.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Pub/Sub service: %w", err)
	}
	return service, nil
}

// GetLoggingService returns a Cloud Logging service
func GetLoggingService(ctx context.Context, session *gcpinternal.SafeSession) (*logging.Service, error) {
	service, err := logging.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Logging service: %w", err)
	}
	return service, nil
}

// GetSpannerService returns a Cloud Spanner service
func GetSpannerService(ctx context.Context, session *gcpinternal.SafeSession) (*spanner.Service, error) {
	service, err := spanner.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Spanner service: %w", err)
	}
	return service, nil
}

// GetBigtableAdminService returns a Bigtable Admin service
func GetBigtableAdminService(ctx context.Context, session *gcpinternal.SafeSession) (*bigtableadmin.Service, error) {
	service, err := bigtableadmin.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Bigtable Admin service: %w", err)
	}
	return service, nil
}

// GetFilestoreService returns a Filestore service
func GetFilestoreService(ctx context.Context, session *gcpinternal.SafeSession) (*file.Service, error) {
	service, err := file.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Filestore service: %w", err)
	}
	return service, nil
}

// GetSourceRepoService returns a Source Repositories service
func GetSourceRepoService(ctx context.Context, session *gcpinternal.SafeSession) (*sourcerepo.Service, error) {
	service, err := sourcerepo.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Source Repositories service: %w", err)
	}
	return service, nil
}

// GetCloudBuildService returns a Cloud Build service
func GetCloudBuildService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudbuild.Service, error) {
	service, err := cloudbuild.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Build service: %w", err)
	}
	return service, nil
}

// GetOrgPolicyService returns an Organization Policy service
func GetOrgPolicyService(ctx context.Context, session *gcpinternal.SafeSession) (*orgpolicy.Service, error) {
	service, err := orgpolicy.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Org Policy service: %w", err)
	}
	return service, nil
}

// GetSchedulerService returns a Cloud Scheduler service
func GetSchedulerService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudscheduler.Service, error) {
	service, err := cloudscheduler.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Scheduler service: %w", err)
	}
	return service, nil
}

// GetAPIKeysService returns an API Keys service
func GetAPIKeysService(ctx context.Context, session *gcpinternal.SafeSession) (*apikeys.Service, error) {
	service, err := apikeys.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create API Keys service: %w", err)
	}
	return service, nil
}

// GetCertificateManagerService returns a Certificate Manager service
func GetCertificateManagerService(ctx context.Context, session *gcpinternal.SafeSession) (*certificatemanager.Service, error) {
	service, err := certificatemanager.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Certificate Manager service: %w", err)
	}
	return service, nil
}

// =============================================================================
// CACHED CLIENT WRAPPERS - These cache clients for reuse
// =============================================================================

// CachedGetStorageClient returns a cached Storage client
func CachedGetStorageClient(ctx context.Context, session *gcpinternal.SafeSession) (*storage.Client, error) {
	cacheKey := CacheKey("client", "storage")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*storage.Client), nil
	}
	client, err := GetStorageClient(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, client, 0)
	return client, nil
}

// CachedGetComputeService returns a cached Compute Engine service
func CachedGetComputeService(ctx context.Context, session *gcpinternal.SafeSession) (*compute.Service, error) {
	cacheKey := CacheKey("client", "compute")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*compute.Service), nil
	}
	service, err := GetComputeService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetIAMService returns a cached IAM service
func CachedGetIAMService(ctx context.Context, session *gcpinternal.SafeSession) (*iam.Service, error) {
	cacheKey := CacheKey("client", "iam")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*iam.Service), nil
	}
	service, err := GetIAMService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetResourceManagerService returns a cached Resource Manager service
func CachedGetResourceManagerService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudresourcemanager.Service, error) {
	cacheKey := CacheKey("client", "resourcemanager")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*cloudresourcemanager.Service), nil
	}
	service, err := GetResourceManagerService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetSecretManagerService returns a cached Secret Manager service
func CachedGetSecretManagerService(ctx context.Context, session *gcpinternal.SafeSession) (*secretmanagerapi.Service, error) {
	cacheKey := CacheKey("client", "secretmanager")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*secretmanagerapi.Service), nil
	}
	service, err := GetSecretManagerService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetBigQueryService returns a cached BigQuery service
func CachedGetBigQueryService(ctx context.Context, session *gcpinternal.SafeSession) (*bigqueryapi.Service, error) {
	cacheKey := CacheKey("client", "bigquery")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*bigqueryapi.Service), nil
	}
	service, err := GetBigQueryService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetStorageService returns a cached Storage service (REST API)
func CachedGetStorageService(ctx context.Context, session *gcpinternal.SafeSession) (*storageapi.Service, error) {
	cacheKey := CacheKey("client", "storage-api")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*storageapi.Service), nil
	}
	service, err := GetStorageService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetContainerService returns a cached GKE Container service
func CachedGetContainerService(ctx context.Context, session *gcpinternal.SafeSession) (*container.Service, error) {
	cacheKey := CacheKey("client", "container")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*container.Service), nil
	}
	service, err := GetContainerService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetCloudRunService returns a cached Cloud Run service
func CachedGetCloudRunService(ctx context.Context, session *gcpinternal.SafeSession) (*run.APIService, error) {
	cacheKey := CacheKey("client", "cloudrun")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*run.APIService), nil
	}
	service, err := GetCloudRunService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetCloudFunctionsService returns a cached Cloud Functions service (v1)
func CachedGetCloudFunctionsService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudfunctions.Service, error) {
	cacheKey := CacheKey("client", "cloudfunctions")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*cloudfunctions.Service), nil
	}
	service, err := GetCloudFunctionsService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetCloudFunctionsServiceV2 returns a cached Cloud Functions v2 service
func CachedGetCloudFunctionsServiceV2(ctx context.Context, session *gcpinternal.SafeSession) (*cloudfunctionsv2.Service, error) {
	cacheKey := CacheKey("client", "cloudfunctionsv2")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*cloudfunctionsv2.Service), nil
	}
	service, err := GetCloudFunctionsServiceV2(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetDNSService returns a cached DNS service
func CachedGetDNSService(ctx context.Context, session *gcpinternal.SafeSession) (*dns.Service, error) {
	cacheKey := CacheKey("client", "dns")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*dns.Service), nil
	}
	service, err := GetDNSService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetLoggingService returns a cached Logging service
func CachedGetLoggingService(ctx context.Context, session *gcpinternal.SafeSession) (*logging.Service, error) {
	cacheKey := CacheKey("client", "logging")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*logging.Service), nil
	}
	service, err := GetLoggingService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetKMSService returns a cached KMS service
func CachedGetKMSService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudkms.Service, error) {
	cacheKey := CacheKey("client", "kms")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*cloudkms.Service), nil
	}
	service, err := GetKMSService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetSQLAdminService returns a cached SQL Admin service (v1)
func CachedGetSQLAdminService(ctx context.Context, session *gcpinternal.SafeSession) (*sqladmin.Service, error) {
	cacheKey := CacheKey("client", "sqladmin")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*sqladmin.Service), nil
	}
	service, err := GetSQLAdminService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetSQLAdminServiceBeta returns a cached SQL Admin service (v1beta4)
func CachedGetSQLAdminServiceBeta(ctx context.Context, session *gcpinternal.SafeSession) (*sqladminbeta.Service, error) {
	cacheKey := CacheKey("client", "sqladminbeta")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*sqladminbeta.Service), nil
	}
	service, err := GetSQLAdminServiceBeta(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetPubSubService returns a cached PubSub service
func CachedGetPubSubService(ctx context.Context, session *gcpinternal.SafeSession) (*pubsubapi.Service, error) {
	cacheKey := CacheKey("client", "pubsub")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*pubsubapi.Service), nil
	}
	service, err := GetPubSubService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetCloudIdentityService returns a cached Cloud Identity service
func CachedGetCloudIdentityService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudidentity.Service, error) {
	cacheKey := CacheKey("client", "cloudidentity")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*cloudidentity.Service), nil
	}
	service, err := GetCloudIdentityService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetAccessContextManagerService returns a cached Access Context Manager service
func CachedGetAccessContextManagerService(ctx context.Context, session *gcpinternal.SafeSession) (*accesscontextmanager.Service, error) {
	cacheKey := CacheKey("client", "accesscontextmanager")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*accesscontextmanager.Service), nil
	}
	service, err := GetAccessContextManagerService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetRedisService returns a cached Redis service
func CachedGetRedisService(ctx context.Context, session *gcpinternal.SafeSession) (*redis.Service, error) {
	cacheKey := CacheKey("client", "redis")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*redis.Service), nil
	}
	service, err := GetRedisService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetSpannerService returns a cached Spanner service
func CachedGetSpannerService(ctx context.Context, session *gcpinternal.SafeSession) (*spanner.Service, error) {
	cacheKey := CacheKey("client", "spanner")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*spanner.Service), nil
	}
	service, err := GetSpannerService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetBigtableAdminService returns a cached Bigtable Admin service
func CachedGetBigtableAdminService(ctx context.Context, session *gcpinternal.SafeSession) (*bigtableadmin.Service, error) {
	cacheKey := CacheKey("client", "bigtableadmin")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*bigtableadmin.Service), nil
	}
	service, err := GetBigtableAdminService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetFilestoreService returns a cached Filestore service
func CachedGetFilestoreService(ctx context.Context, session *gcpinternal.SafeSession) (*file.Service, error) {
	cacheKey := CacheKey("client", "filestore")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*file.Service), nil
	}
	service, err := GetFilestoreService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetCloudBuildService returns a cached Cloud Build service
func CachedGetCloudBuildService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudbuild.Service, error) {
	cacheKey := CacheKey("client", "cloudbuild")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*cloudbuild.Service), nil
	}
	service, err := GetCloudBuildService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetComposerService returns a cached Composer service
func CachedGetComposerService(ctx context.Context, session *gcpinternal.SafeSession) (*composer.Service, error) {
	cacheKey := CacheKey("client", "composer")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*composer.Service), nil
	}
	service, err := GetComposerService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetDataflowService returns a cached Dataflow service
func CachedGetDataflowService(ctx context.Context, session *gcpinternal.SafeSession) (*dataflow.Service, error) {
	cacheKey := CacheKey("client", "dataflow")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*dataflow.Service), nil
	}
	service, err := GetDataflowService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetDataprocService returns a cached Dataproc service
func CachedGetDataprocService(ctx context.Context, session *gcpinternal.SafeSession) (*dataproc.Service, error) {
	cacheKey := CacheKey("client", "dataproc")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*dataproc.Service), nil
	}
	service, err := GetDataprocService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetNotebooksService returns a cached Notebooks service
func CachedGetNotebooksService(ctx context.Context, session *gcpinternal.SafeSession) (*notebooks.Service, error) {
	cacheKey := CacheKey("client", "notebooks")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*notebooks.Service), nil
	}
	service, err := GetNotebooksService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetSchedulerService returns a cached Scheduler service
func CachedGetSchedulerService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudscheduler.Service, error) {
	cacheKey := CacheKey("client", "scheduler")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*cloudscheduler.Service), nil
	}
	service, err := GetSchedulerService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetAPIKeysService returns a cached API Keys service
func CachedGetAPIKeysService(ctx context.Context, session *gcpinternal.SafeSession) (*apikeys.Service, error) {
	cacheKey := CacheKey("client", "apikeys")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*apikeys.Service), nil
	}
	service, err := GetAPIKeysService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetOrgPolicyService returns a cached Org Policy service
func CachedGetOrgPolicyService(ctx context.Context, session *gcpinternal.SafeSession) (*orgpolicy.Service, error) {
	cacheKey := CacheKey("client", "orgpolicy")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*orgpolicy.Service), nil
	}
	service, err := GetOrgPolicyService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetSourceRepoService returns a cached Source Repo service
func CachedGetSourceRepoService(ctx context.Context, session *gcpinternal.SafeSession) (*sourcerepo.Service, error) {
	cacheKey := CacheKey("client", "sourcerepo")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*sourcerepo.Service), nil
	}
	service, err := GetSourceRepoService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetBeyondCorpService returns a cached BeyondCorp service
func CachedGetBeyondCorpService(ctx context.Context, session *gcpinternal.SafeSession) (*beyondcorp.Service, error) {
	cacheKey := CacheKey("client", "beyondcorp")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*beyondcorp.Service), nil
	}
	service, err := GetBeyondCorpService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetIAPService returns a cached IAP service
func CachedGetIAPService(ctx context.Context, session *gcpinternal.SafeSession) (*iap.Service, error) {
	cacheKey := CacheKey("client", "iap")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*iap.Service), nil
	}
	service, err := GetIAPService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetCertificateManagerService returns a cached Certificate Manager service
func CachedGetCertificateManagerService(ctx context.Context, session *gcpinternal.SafeSession) (*certificatemanager.Service, error) {
	cacheKey := CacheKey("client", "certificatemanager")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*certificatemanager.Service), nil
	}
	service, err := GetCertificateManagerService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetServiceNetworkingService returns a cached Service Networking service
func CachedGetServiceNetworkingService(ctx context.Context, session *gcpinternal.SafeSession) (*servicenetworking.APIService, error) {
	cacheKey := CacheKey("client", "servicenetworking")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*servicenetworking.APIService), nil
	}
	service, err := GetServiceNetworkingService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetArtifactRegistryService returns a cached Artifact Registry service
func CachedGetArtifactRegistryService(ctx context.Context, session *gcpinternal.SafeSession) (*artifactregistryapi.Service, error) {
	cacheKey := CacheKey("client", "artifactregistry")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*artifactregistryapi.Service), nil
	}
	service, err := GetArtifactRegistryService(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetCloudRunServiceV2 returns a cached Cloud Run v2 service
func CachedGetCloudRunServiceV2(ctx context.Context, session *gcpinternal.SafeSession) (*runv2.Service, error) {
	cacheKey := CacheKey("client", "cloudrunv2")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*runv2.Service), nil
	}
	service, err := GetCloudRunServiceV2(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetSecretManagerClient returns a cached Secret Manager client (Go SDK)
func CachedGetSecretManagerClient(ctx context.Context, session *gcpinternal.SafeSession) (*secretmanagerclient.Client, error) {
	cacheKey := CacheKey("client", "secretmanager-gosdk")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*secretmanagerclient.Client), nil
	}
	client, err := GetSecretManagerClient(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, client, 0)
	return client, nil
}

// CachedGetAssetClient returns a cached Asset client
func CachedGetAssetClient(ctx context.Context, session *gcpinternal.SafeSession) (*asset.Client, error) {
	cacheKey := CacheKey("client", "asset")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*asset.Client), nil
	}
	client, err := GetAssetClient(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, client, 0)
	return client, nil
}

// CachedGetArtifactRegistryClient returns a cached Artifact Registry client (Go SDK)
func CachedGetArtifactRegistryClient(ctx context.Context, session *gcpinternal.SafeSession) (*artifactregistry.Client, error) {
	cacheKey := CacheKey("client", "artifactregistry-gosdk")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*artifactregistry.Client), nil
	}
	client, err := GetArtifactRegistryClient(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, client, 0)
	return client, nil
}

// CachedGetOrganizationsClient returns a cached Organizations client
func CachedGetOrganizationsClient(ctx context.Context, session *gcpinternal.SafeSession) (*resourcemanager.OrganizationsClient, error) {
	cacheKey := CacheKey("client", "organizations")
	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*resourcemanager.OrganizationsClient), nil
	}
	client, err := GetOrganizationsClient(ctx, session)
	if err != nil {
		return nil, err
	}
	GCPSDKCache.Set(cacheKey, client, 0)
	return client, nil
}
