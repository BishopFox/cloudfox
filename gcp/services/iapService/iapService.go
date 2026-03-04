package iapservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	regionservice "github.com/BishopFox/cloudfox/gcp/services/regionService"
	iap "google.golang.org/api/iap/v1"
)

type IAPService struct {
	session *gcpinternal.SafeSession
}

func New() *IAPService {
	return &IAPService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *IAPService {
	return &IAPService{session: session}
}

// getService returns an IAP service client using cached session if available
func (s *IAPService) getService(ctx context.Context) (*iap.Service, error) {
	if s.session != nil {
		return sdk.CachedGetIAPService(ctx, s.session)
	}
	return iap.NewService(ctx)
}

// IAPSettingsInfo represents IAP settings for a resource
type IAPSettingsInfo struct {
	Name                    string   `json:"name"`
	ProjectID               string   `json:"projectId"`
	ResourceType            string   `json:"resourceType"` // compute, app-engine, etc.
	ResourceName            string   `json:"resourceName"`
	IAPEnabled              bool     `json:"iapEnabled"`
	OAuth2ClientID          string   `json:"oauth2ClientId"`
	OAuth2ClientSecretSha   string   `json:"oauth2ClientSecretSha"`
	AccessDeniedPageURI     string   `json:"accessDeniedPageUri"`
	CORSAllowedOrigins      []string `json:"corsAllowedOrigins"`
	GCIPTenantIDs           []string `json:"gcipTenantIds"`
	ReauthPolicy            string   `json:"reauthPolicy"`
}

// TunnelDestGroup represents an IAP tunnel destination group
type TunnelDestGroup struct {
	Name        string       `json:"name"`
	ProjectID   string       `json:"projectId"`
	Region      string       `json:"region"`
	CIDRs       []string     `json:"cidrs"`
	FQDNs       []string     `json:"fqdns"`
	IAMBindings []IAMBinding `json:"iamBindings"`
}

// IAMBinding represents a single IAM role binding
type IAMBinding struct {
	Role   string `json:"role"`
	Member string `json:"member"`
}

// ListTunnelDestGroups retrieves tunnel destination groups
func (s *IAPService) ListTunnelDestGroups(projectID string) ([]TunnelDestGroup, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "iap.googleapis.com")
	}

	var groups []TunnelDestGroup

	// Get regions from regionService (with automatic fallback)
	// Also try "-" wildcard in case it's supported
	regions := regionservice.GetCachedRegionNames(ctx, projectID)
	regions = append(regions, "-")

	for _, region := range regions {
		parent := fmt.Sprintf("projects/%s/iap_tunnel/locations/%s", projectID, region)
		resp, err := service.Projects.IapTunnel.Locations.DestGroups.List(parent).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, group := range resp.TunnelDestGroups {
			info := TunnelDestGroup{
				Name:      extractName(group.Name),
				ProjectID: projectID,
				Region:    region,
				CIDRs:     group.Cidrs,
				FQDNs:     group.Fqdns,
			}

			// Fetch IAM bindings for this tunnel dest group
			info.IAMBindings = s.getTunnelDestGroupIAMBindings(service, group.Name)

			groups = append(groups, info)
		}
	}

	return groups, nil
}

// getTunnelDestGroupIAMBindings retrieves IAM bindings for a tunnel destination group
func (s *IAPService) getTunnelDestGroupIAMBindings(service *iap.Service, resourceName string) []IAMBinding {
	ctx := context.Background()

	policy, err := service.V1.GetIamPolicy(resourceName, &iap.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return nil
	}

	var bindings []IAMBinding
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			bindings = append(bindings, IAMBinding{
				Role:   binding.Role,
				Member: member,
			})
		}
	}

	return bindings
}

// GetIAPSettings retrieves IAP settings for a resource
func (s *IAPService) GetIAPSettings(projectID, resourcePath string) (*IAPSettingsInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "iap.googleapis.com")
	}

	settings, err := service.V1.GetIapSettings(resourcePath).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "iap.googleapis.com")
	}

	info := &IAPSettingsInfo{
		Name:         settings.Name,
		ProjectID:    projectID,
		ResourceName: resourcePath,
	}

	if settings.AccessSettings != nil {
		if settings.AccessSettings.OauthSettings != nil {
			info.OAuth2ClientID = settings.AccessSettings.OauthSettings.LoginHint
		}
		// CorsSettings doesn't have AllowHttpOptions as a list - it's a bool
		// Skip CORS parsing for now
		if settings.AccessSettings.GcipSettings != nil {
			info.GCIPTenantIDs = settings.AccessSettings.GcipSettings.TenantIds
		}
		if settings.AccessSettings.ReauthSettings != nil {
			info.ReauthPolicy = settings.AccessSettings.ReauthSettings.Method
		}
	}

	return info, nil
}

func extractName(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullPath
}
