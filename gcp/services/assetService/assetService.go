package assetservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	asset "cloud.google.com/go/asset/apiv1"
	assetpb "cloud.google.com/go/asset/apiv1/assetpb"
	"google.golang.org/api/iterator"
)

type AssetService struct {
	session *gcpinternal.SafeSession
}

func New() *AssetService {
	return &AssetService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *AssetService {
	return &AssetService{session: session}
}

// IAMBinding represents an IAM binding
type IAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// AssetInfo represents a Cloud Asset
type AssetInfo struct {
	Name         string            `json:"name"`
	AssetType    string            `json:"assetType"`
	ProjectID    string            `json:"projectId"`
	Location     string            `json:"location"`
	DisplayName  string            `json:"displayName"`
	Description  string            `json:"description"`
	Labels       map[string]string `json:"labels"`
	State        string            `json:"state"`
	CreateTime   string            `json:"createTime"`
	UpdateTime   string            `json:"updateTime"`

	// IAM Policy details
	HasIAMPolicy   bool         `json:"hasIamPolicy"`
	IAMBindings    []IAMBinding `json:"iamBindings"`
	IAMBindingCount int         `json:"iamBindingCount"`
	PublicAccess   bool         `json:"publicAccess"`
}

// AssetTypeCount tracks count of assets by type
type AssetTypeCount struct {
	AssetType string `json:"assetType"`
	Count     int    `json:"count"`
}

// Common asset types for filtering
var CommonAssetTypes = []string{
	"compute.googleapis.com/Instance",
	"compute.googleapis.com/Disk",
	"compute.googleapis.com/Firewall",
	"compute.googleapis.com/Network",
	"compute.googleapis.com/Subnetwork",
	"storage.googleapis.com/Bucket",
	"iam.googleapis.com/ServiceAccount",
	"iam.googleapis.com/ServiceAccountKey",
	"secretmanager.googleapis.com/Secret",
	"cloudkms.googleapis.com/CryptoKey",
	"cloudfunctions.googleapis.com/Function",
	"run.googleapis.com/Service",
	"container.googleapis.com/Cluster",
	"sqladmin.googleapis.com/Instance",
	"pubsub.googleapis.com/Topic",
	"pubsub.googleapis.com/Subscription",
	"bigquery.googleapis.com/Dataset",
	"bigquery.googleapis.com/Table",
}

// ListAssets retrieves assets for a project, optionally filtered by type
func (s *AssetService) ListAssets(projectID string, assetTypes []string) ([]AssetInfo, error) {
	ctx := context.Background()
	var client *asset.Client
	var err error

	if s.session != nil {
		client, err = asset.NewClient(ctx, s.session.GetClientOption())
	} else {
		client, err = asset.NewClient(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudasset.googleapis.com")
	}
	defer client.Close()

	var assets []AssetInfo

	parent := fmt.Sprintf("projects/%s", projectID)

	req := &assetpb.ListAssetsRequest{
		Parent:      parent,
		ContentType: assetpb.ContentType_RESOURCE,
	}

	if len(assetTypes) > 0 {
		req.AssetTypes = assetTypes
	}

	it := client.ListAssets(ctx, req)
	for {
		assetResult, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "cloudasset.googleapis.com")
		}

		info := s.parseAsset(assetResult, projectID)
		assets = append(assets, info)
	}

	return assets, nil
}

// ListAssetsWithIAM retrieves assets with their IAM policies
func (s *AssetService) ListAssetsWithIAM(projectID string, assetTypes []string) ([]AssetInfo, error) {
	ctx := context.Background()
	var client *asset.Client
	var err error

	if s.session != nil {
		client, err = asset.NewClient(ctx, s.session.GetClientOption())
	} else {
		client, err = asset.NewClient(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudasset.googleapis.com")
	}
	defer client.Close()

	var assets []AssetInfo

	parent := fmt.Sprintf("projects/%s", projectID)

	req := &assetpb.ListAssetsRequest{
		Parent:      parent,
		ContentType: assetpb.ContentType_IAM_POLICY,
	}

	if len(assetTypes) > 0 {
		req.AssetTypes = assetTypes
	}

	it := client.ListAssets(ctx, req)
	for {
		assetResult, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "cloudasset.googleapis.com")
		}

		info := s.parseAssetWithIAM(assetResult, projectID)
		assets = append(assets, info)
	}

	return assets, nil
}

// GetAssetTypeCounts returns a summary of asset counts by type
func (s *AssetService) GetAssetTypeCounts(projectID string) ([]AssetTypeCount, error) {
	ctx := context.Background()
	var client *asset.Client
	var err error

	if s.session != nil {
		client, err = asset.NewClient(ctx, s.session.GetClientOption())
	} else {
		client, err = asset.NewClient(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudasset.googleapis.com")
	}
	defer client.Close()

	counts := make(map[string]int)

	parent := fmt.Sprintf("projects/%s", projectID)

	req := &assetpb.ListAssetsRequest{
		Parent:      parent,
		ContentType: assetpb.ContentType_RESOURCE,
	}

	it := client.ListAssets(ctx, req)
	for {
		assetResult, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "cloudasset.googleapis.com")
		}

		counts[assetResult.AssetType]++
	}

	var result []AssetTypeCount
	for assetType, count := range counts {
		result = append(result, AssetTypeCount{
			AssetType: assetType,
			Count:     count,
		})
	}

	return result, nil
}

// SearchAllResources searches for resources across the organization or project
func (s *AssetService) SearchAllResources(scope string, query string) ([]AssetInfo, error) {
	ctx := context.Background()
	var client *asset.Client
	var err error

	if s.session != nil {
		client, err = asset.NewClient(ctx, s.session.GetClientOption())
	} else {
		client, err = asset.NewClient(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudasset.googleapis.com")
	}
	defer client.Close()

	var assets []AssetInfo

	req := &assetpb.SearchAllResourcesRequest{
		Scope: scope,
		Query: query,
	}

	it := client.SearchAllResources(ctx, req)
	for {
		resource, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "cloudasset.googleapis.com")
		}

		info := AssetInfo{
			Name:        resource.Name,
			AssetType:   resource.AssetType,
			ProjectID:   resource.Project,
			Location:    resource.Location,
			DisplayName: resource.DisplayName,
			Description: resource.Description,
			Labels:      resource.Labels,
			State:       resource.State,
			CreateTime:  resource.CreateTime.String(),
			UpdateTime:  resource.UpdateTime.String(),
		}

		assets = append(assets, info)
	}

	return assets, nil
}

func (s *AssetService) parseAsset(assetResult *assetpb.Asset, projectID string) AssetInfo {
	info := AssetInfo{
		Name:      extractAssetName(assetResult.Name),
		AssetType: assetResult.AssetType,
		ProjectID: projectID,
	}

	if assetResult.Resource != nil {
		info.Location = assetResult.Resource.Location
	}

	return info
}

func (s *AssetService) parseAssetWithIAM(assetResult *assetpb.Asset, projectID string) AssetInfo {
	info := AssetInfo{
		Name:      extractAssetName(assetResult.Name),
		AssetType: assetResult.AssetType,
		ProjectID: projectID,
	}

	if assetResult.IamPolicy != nil {
		info.HasIAMPolicy = true
		info.IAMBindingCount = len(assetResult.IamPolicy.Bindings)

		// Store actual bindings and check for public access
		for _, binding := range assetResult.IamPolicy.Bindings {
			iamBinding := IAMBinding{
				Role:    binding.Role,
				Members: binding.Members,
			}
			info.IAMBindings = append(info.IAMBindings, iamBinding)

			// Check for public access
			for _, member := range binding.Members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					info.PublicAccess = true
				}
			}
		}
	}

	return info
}

func extractAssetName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// ExtractAssetTypeShort returns a shortened version of the asset type
func ExtractAssetTypeShort(assetType string) string {
	parts := strings.Split(assetType, "/")
	if len(parts) == 2 {
		return parts[1]
	}
	return assetType
}
