package vpcscservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	accesscontextmanager "google.golang.org/api/accesscontextmanager/v1"
)

type VPCSCService struct {
	session *gcpinternal.SafeSession
}

func New() *VPCSCService {
	return &VPCSCService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *VPCSCService {
	return &VPCSCService{session: session}
}

// getService returns an Access Context Manager service client using cached session if available
func (s *VPCSCService) getService(ctx context.Context) (*accesscontextmanager.Service, error) {
	if s.session != nil {
		return sdk.CachedGetAccessContextManagerService(ctx, s.session)
	}
	return accesscontextmanager.NewService(ctx)
}

// AccessPolicyInfo represents an access policy
type AccessPolicyInfo struct {
	Name       string `json:"name"`
	Title      string `json:"title"`
	Parent     string `json:"parent"`
	Etag       string `json:"etag"`
	CreateTime string `json:"createTime"`
	UpdateTime string `json:"updateTime"`
}

// ServicePerimeterInfo represents a VPC Service Control perimeter
type ServicePerimeterInfo struct {
	Name               string   `json:"name"`
	Title              string   `json:"title"`
	PolicyName         string   `json:"policyName"`
	PerimeterType      string   `json:"perimeterType"` // PERIMETER_TYPE_REGULAR or PERIMETER_TYPE_BRIDGE
	Description        string   `json:"description"`
	CreateTime         string   `json:"createTime"`
	UpdateTime         string   `json:"updateTime"`

	// Status configuration
	Resources             []string `json:"resources"`             // Projects in the perimeter
	RestrictedServices    []string `json:"restrictedServices"`    // Services protected
	AccessLevels          []string `json:"accessLevels"`          // Access levels allowed
	VPCAccessibleServices []string `json:"vpcAccessibleServices"`

	// Ingress/Egress policies
	IngressPolicyCount int  `json:"ingressPolicyCount"`
	EgressPolicyCount  int  `json:"egressPolicyCount"`
	HasIngressRules    bool `json:"hasIngressRules"`
	HasEgressRules     bool `json:"hasEgressRules"`
}

// AccessLevelInfo represents an access level
type AccessLevelInfo struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	PolicyName  string   `json:"policyName"`
	Description string   `json:"description"`
	CreateTime  string   `json:"createTime"`
	UpdateTime  string   `json:"updateTime"`

	// Conditions
	IPSubnetworks []string `json:"ipSubnetworks"`
	Regions       []string `json:"regions"`
	Members       []string `json:"members"`
}

// ListAccessPolicies retrieves all access policies for an organization
func (s *VPCSCService) ListAccessPolicies(orgID string) ([]AccessPolicyInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "accesscontextmanager.googleapis.com")
	}

	var policies []AccessPolicyInfo

	// List access policies for the organization
	parent := fmt.Sprintf("organizations/%s", orgID)
	req := service.AccessPolicies.List().Parent(parent)
	err = req.Pages(ctx, func(page *accesscontextmanager.ListAccessPoliciesResponse) error {
		for _, policy := range page.AccessPolicies {
			info := AccessPolicyInfo{
				Name:   extractPolicyName(policy.Name),
				Title:  policy.Title,
				Parent: policy.Parent,
				Etag:   policy.Etag,
			}
			policies = append(policies, info)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "accesscontextmanager.googleapis.com")
	}

	return policies, nil
}

// ListServicePerimeters retrieves all service perimeters for an access policy
func (s *VPCSCService) ListServicePerimeters(policyName string) ([]ServicePerimeterInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "accesscontextmanager.googleapis.com")
	}

	var perimeters []ServicePerimeterInfo

	parent := fmt.Sprintf("accessPolicies/%s", policyName)
	req := service.AccessPolicies.ServicePerimeters.List(parent)
	err = req.Pages(ctx, func(page *accesscontextmanager.ListServicePerimetersResponse) error {
		for _, perimeter := range page.ServicePerimeters {
			info := s.parsePerimeter(perimeter, policyName)
			perimeters = append(perimeters, info)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "accesscontextmanager.googleapis.com")
	}

	return perimeters, nil
}

// ListAccessLevels retrieves all access levels for an access policy
func (s *VPCSCService) ListAccessLevels(policyName string) ([]AccessLevelInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "accesscontextmanager.googleapis.com")
	}

	var levels []AccessLevelInfo

	parent := fmt.Sprintf("accessPolicies/%s", policyName)
	req := service.AccessPolicies.AccessLevels.List(parent)
	err = req.Pages(ctx, func(page *accesscontextmanager.ListAccessLevelsResponse) error {
		for _, level := range page.AccessLevels {
			info := s.parseAccessLevel(level, policyName)
			levels = append(levels, info)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "accesscontextmanager.googleapis.com")
	}

	return levels, nil
}

func (s *VPCSCService) parsePerimeter(perimeter *accesscontextmanager.ServicePerimeter, policyName string) ServicePerimeterInfo {
	info := ServicePerimeterInfo{
		Name:          extractPerimeterName(perimeter.Name),
		Title:         perimeter.Title,
		PolicyName:    policyName,
		PerimeterType: perimeter.PerimeterType,
		Description:   perimeter.Description,
	}

	// Parse status configuration
	if perimeter.Status != nil {
		info.Resources = perimeter.Status.Resources
		info.RestrictedServices = perimeter.Status.RestrictedServices
		info.AccessLevels = perimeter.Status.AccessLevels

		if perimeter.Status.VpcAccessibleServices != nil {
			info.VPCAccessibleServices = perimeter.Status.VpcAccessibleServices.AllowedServices
		}

		if len(perimeter.Status.IngressPolicies) > 0 {
			info.IngressPolicyCount = len(perimeter.Status.IngressPolicies)
			info.HasIngressRules = true
		}

		if len(perimeter.Status.EgressPolicies) > 0 {
			info.EgressPolicyCount = len(perimeter.Status.EgressPolicies)
			info.HasEgressRules = true
		}
	}

	return info
}

func (s *VPCSCService) parseAccessLevel(level *accesscontextmanager.AccessLevel, policyName string) AccessLevelInfo {
	info := AccessLevelInfo{
		Name:        extractLevelName(level.Name),
		Title:       level.Title,
		PolicyName:  policyName,
		Description: level.Description,
	}

	if level.Basic != nil && len(level.Basic.Conditions) > 0 {
		for _, condition := range level.Basic.Conditions {
			info.IPSubnetworks = append(info.IPSubnetworks, condition.IpSubnetworks...)
			info.Regions = append(info.Regions, condition.Regions...)
			info.Members = append(info.Members, condition.Members...)
		}
	}

	// Handle custom access levels (CEL expressions)
	if level.Custom != nil && level.Custom.Expr != nil && level.Custom.Expr.Expression != "" {
		info.Description = fmt.Sprintf("Custom CEL: %s", level.Custom.Expr.Expression)
	}

	return info
}

func extractPolicyName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return fullName
}

func extractPerimeterName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return fullName
}

func extractLevelName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return fullName
}
