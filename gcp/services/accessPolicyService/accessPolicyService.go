package accesspolicyservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	accesscontextmanager "google.golang.org/api/accesscontextmanager/v1"
)

type AccessPolicyService struct {
	session *gcpinternal.SafeSession
}

func New() *AccessPolicyService {
	return &AccessPolicyService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *AccessPolicyService {
	return &AccessPolicyService{session: session}
}

// getService returns an Access Context Manager service using cached session if available
func (s *AccessPolicyService) getService(ctx context.Context) (*accesscontextmanager.Service, error) {
	if s.session != nil {
		return sdk.CachedGetAccessContextManagerService(ctx, s.session)
	}
	return accesscontextmanager.NewService(ctx)
}

// AccessLevelInfo represents an access level (conditional access policy)
type AccessLevelInfo struct {
	Name           string   `json:"name"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	PolicyName     string   `json:"policyName"`

	// Basic level conditions
	CombiningFunction string   `json:"combiningFunction"` // AND or OR
	Conditions       []ConditionInfo `json:"conditions"`

	// Custom level
	HasCustomLevel  bool     `json:"hasCustomLevel"`
	CustomExpression string  `json:"customExpression"`

	// Analysis
	RiskLevel       string   `json:"riskLevel"`
	RiskReasons     []string `json:"riskReasons"`
}

// ConditionInfo represents a condition in an access level
type ConditionInfo struct {
	IPSubnetworks        []string `json:"ipSubnetworks"`
	DevicePolicy         *DevicePolicyInfo `json:"devicePolicy"`
	RequiredAccessLevels []string `json:"requiredAccessLevels"`
	Negate              bool     `json:"negate"`
	Members             []string `json:"members"`
	Regions             []string `json:"regions"`
}

// DevicePolicyInfo represents device policy requirements
type DevicePolicyInfo struct {
	RequireScreenLock    bool     `json:"requireScreenLock"`
	RequireAdminApproval bool     `json:"requireAdminApproval"`
	RequireCorpOwned     bool     `json:"requireCorpOwned"`
	AllowedEncryption    []string `json:"allowedEncryptionStatuses"`
	AllowedDeviceMgmt    []string `json:"allowedDeviceManagementLevels"`
	OSConstraints        []string `json:"osConstraints"`
}

// GCIPSettingsInfo represents Google Cloud Identity Platform settings
type GCIPSettingsInfo struct {
	TenantIDs       []string `json:"tenantIds"`
	LoginPageURI    string   `json:"loginPageUri"`
}

// ListAccessLevels retrieves all access levels for an organization's policy
func (s *AccessPolicyService) ListAccessLevels(orgID string) ([]AccessLevelInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "accesscontextmanager.googleapis.com")
	}

	var allLevels []AccessLevelInfo

	// First, get access policies for the org
	parent := fmt.Sprintf("organizations/%s", orgID)
	policiesReq := service.AccessPolicies.List().Parent(parent)
	err = policiesReq.Pages(ctx, func(page *accesscontextmanager.ListAccessPoliciesResponse) error {
		for _, policy := range page.AccessPolicies {
			policyName := extractPolicyName(policy.Name)

			// Get access levels for this policy
			levelsParent := fmt.Sprintf("accessPolicies/%s", policyName)
			levelsReq := service.AccessPolicies.AccessLevels.List(levelsParent)
			levelsReq.Pages(ctx, func(levelsPage *accesscontextmanager.ListAccessLevelsResponse) error {
				for _, level := range levelsPage.AccessLevels {
					info := s.parseAccessLevel(level, policyName)
					allLevels = append(allLevels, info)
				}
				return nil
			})
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "accesscontextmanager.googleapis.com")
	}

	return allLevels, nil
}

// ListAccessLevelsForPolicy retrieves access levels for a specific policy
func (s *AccessPolicyService) ListAccessLevelsForPolicy(policyName string) ([]AccessLevelInfo, error) {
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

func (s *AccessPolicyService) parseAccessLevel(level *accesscontextmanager.AccessLevel, policyName string) AccessLevelInfo {
	info := AccessLevelInfo{
		Name:        extractLevelName(level.Name),
		Title:       level.Title,
		Description: level.Description,
		PolicyName:  policyName,
		RiskReasons: []string{},
	}

	// Parse basic level
	if level.Basic != nil {
		info.CombiningFunction = level.Basic.CombiningFunction

		for _, condition := range level.Basic.Conditions {
			condInfo := ConditionInfo{
				IPSubnetworks: condition.IpSubnetworks,
				Negate:        condition.Negate,
				Members:       condition.Members,
				Regions:       condition.Regions,
			}

			for _, reqLevel := range condition.RequiredAccessLevels {
				condInfo.RequiredAccessLevels = append(condInfo.RequiredAccessLevels, extractLevelName(reqLevel))
			}

			// Parse device policy
			if condition.DevicePolicy != nil {
				dp := condition.DevicePolicy
				condInfo.DevicePolicy = &DevicePolicyInfo{
					RequireScreenLock:    dp.RequireScreenlock,
					RequireAdminApproval: dp.RequireAdminApproval,
					RequireCorpOwned:     dp.RequireCorpOwned,
					AllowedEncryption:    dp.AllowedEncryptionStatuses,
					AllowedDeviceMgmt:    dp.AllowedDeviceManagementLevels,
				}

				for _, os := range dp.OsConstraints {
					condInfo.DevicePolicy.OSConstraints = append(condInfo.DevicePolicy.OSConstraints,
						fmt.Sprintf("%s:%s", os.OsType, os.MinimumVersion))
				}
			}

			info.Conditions = append(info.Conditions, condInfo)
		}
	}

	// Parse custom level
	if level.Custom != nil && level.Custom.Expr != nil {
		info.HasCustomLevel = true
		info.CustomExpression = level.Custom.Expr.Expression
	}

	info.RiskLevel, info.RiskReasons = s.analyzeAccessLevelRisk(info)

	return info
}

func (s *AccessPolicyService) analyzeAccessLevelRisk(level AccessLevelInfo) (string, []string) {
	var reasons []string
	score := 0

	for _, condition := range level.Conditions {
		// Check for overly broad IP ranges
		for _, ip := range condition.IPSubnetworks {
			if ip == "0.0.0.0/0" || ip == "::/0" {
				reasons = append(reasons, "Access level allows all IP addresses (0.0.0.0/0)")
				score += 3
				break
			}
		}

		// Check for allUsers or allAuthenticatedUsers
		for _, member := range condition.Members {
			if member == "allUsers" {
				reasons = append(reasons, "Access level includes allUsers")
				score += 3
			} else if member == "allAuthenticatedUsers" {
				reasons = append(reasons, "Access level includes allAuthenticatedUsers")
				score += 2
			}
		}

		// No device policy requirements
		if condition.DevicePolicy == nil {
			reasons = append(reasons, "No device policy requirements")
			score += 1
		} else {
			// Weak device policy
			if !condition.DevicePolicy.RequireScreenLock {
				reasons = append(reasons, "Does not require screen lock")
				score += 1
			}
			if !condition.DevicePolicy.RequireCorpOwned {
				reasons = append(reasons, "Does not require corporate-owned device")
				score += 1
			}
		}
	}

	// No conditions at all
	if len(level.Conditions) == 0 && !level.HasCustomLevel {
		reasons = append(reasons, "Access level has no conditions defined")
		score += 2
	}

	// OR combining function is more permissive
	if level.CombiningFunction == "OR" && len(level.Conditions) > 1 {
		reasons = append(reasons, "Uses OR combining function (any condition grants access)")
		score += 1
	}

	if score >= 3 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func extractPolicyName(fullName string) string {
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
