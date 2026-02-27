package cloudarmorservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	compute "google.golang.org/api/compute/v1"
)

type CloudArmorService struct{
	session *gcpinternal.SafeSession
}

func New() *CloudArmorService {
	return &CloudArmorService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *CloudArmorService {
	return &CloudArmorService{
		session: session,
	}
}

// SecurityPolicy represents a Cloud Armor security policy
type SecurityPolicy struct {
	Name               string         `json:"name"`
	ProjectID          string         `json:"projectId"`
	Description        string         `json:"description"`
	Type               string         `json:"type"` // CLOUD_ARMOR, CLOUD_ARMOR_EDGE, CLOUD_ARMOR_NETWORK
	RuleCount          int            `json:"ruleCount"`
	Rules              []SecurityRule `json:"rules"`
	AdaptiveProtection bool           `json:"adaptiveProtection"`
	DDOSProtection     string         `json:"ddosProtection"`
	AttachedResources  []string       `json:"attachedResources"`
	Weaknesses         []string       `json:"weaknesses"`
}

// SecurityRule represents a rule within a security policy
type SecurityRule struct {
	Priority    int64    `json:"priority"`
	Description string   `json:"description"`
	Action      string   `json:"action"` // allow, deny, redirect, rate_based_ban, throttle
	Match       string   `json:"match"`  // Simplified match expression
	Preview     bool     `json:"preview"`
	RateLimitConfig *RateLimitInfo `json:"rateLimitConfig,omitempty"`
}

// RateLimitInfo contains rate limiting configuration
type RateLimitInfo struct {
	ThresholdCount int64  `json:"thresholdCount"`
	IntervalSec    int64  `json:"intervalSec"`
	ExceedAction   string `json:"exceedAction"`
}

// getService returns a Compute service client using cached session if available
func (s *CloudArmorService) getService(ctx context.Context) (*compute.Service, error) {
	if s.session != nil {
		return sdk.CachedGetComputeService(ctx, s.session)
	}
	return compute.NewService(ctx)
}

// GetSecurityPolicies retrieves all Cloud Armor security policies
func (s *CloudArmorService) GetSecurityPolicies(projectID string) ([]SecurityPolicy, error) {
	ctx := context.Background()
	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	var policies []SecurityPolicy

	// List security policies
	resp, err := service.SecurityPolicies.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	for _, policy := range resp.Items {
		sp := SecurityPolicy{
			Name:              policy.Name,
			ProjectID:         projectID,
			Description:       policy.Description,
			Type:              policy.Type,
			RuleCount:         len(policy.Rules),
			Rules:             []SecurityRule{},
			AttachedResources: []string{},
			Weaknesses:        []string{},
		}

		// Check adaptive protection
		if policy.AdaptiveProtectionConfig != nil &&
		   policy.AdaptiveProtectionConfig.Layer7DdosDefenseConfig != nil {
			sp.AdaptiveProtection = policy.AdaptiveProtectionConfig.Layer7DdosDefenseConfig.Enable
		}

		// Check DDoS protection
		if policy.DdosProtectionConfig != nil {
			sp.DDOSProtection = policy.DdosProtectionConfig.DdosProtection
		}

		// Parse rules
		for _, rule := range policy.Rules {
			sr := SecurityRule{
				Priority:    rule.Priority,
				Description: rule.Description,
				Action:      rule.Action,
				Preview:     rule.Preview,
			}

			// Parse match expression
			if rule.Match != nil {
				if rule.Match.Expr != nil {
					sr.Match = rule.Match.Expr.Expression
				} else if rule.Match.VersionedExpr != "" {
					sr.Match = rule.Match.VersionedExpr
				} else if rule.Match.Config != nil {
					// Source IP ranges
					if len(rule.Match.Config.SrcIpRanges) > 0 {
						sr.Match = fmt.Sprintf("srcIpRanges: %s", strings.Join(rule.Match.Config.SrcIpRanges, ", "))
					}
				}
			}

			// Rate limit config
			if rule.RateLimitOptions != nil {
				sr.RateLimitConfig = &RateLimitInfo{
					ExceedAction: rule.RateLimitOptions.ExceedAction,
				}
				if rule.RateLimitOptions.RateLimitThreshold != nil {
					sr.RateLimitConfig.ThresholdCount = rule.RateLimitOptions.RateLimitThreshold.Count
					sr.RateLimitConfig.IntervalSec = rule.RateLimitOptions.RateLimitThreshold.IntervalSec
				}
			}

			sp.Rules = append(sp.Rules, sr)
		}

		// Find attached resources (backend services using this policy)
		sp.AttachedResources = s.findAttachedResources(ctx, service, projectID, policy.Name)

		// Analyze for weaknesses
		sp.Weaknesses = s.analyzePolicy(sp)

		policies = append(policies, sp)
	}

	return policies, nil
}

// findAttachedResources finds backend services using this security policy
func (s *CloudArmorService) findAttachedResources(ctx context.Context, service *compute.Service, projectID, policyName string) []string {
	var resources []string

	// Check backend services
	backendServices, err := service.BackendServices.List(projectID).Context(ctx).Do()
	if err == nil {
		for _, bs := range backendServices.Items {
			if bs.SecurityPolicy != "" && strings.HasSuffix(bs.SecurityPolicy, "/"+policyName) {
				resources = append(resources, fmt.Sprintf("backend-service:%s", bs.Name))
			}
		}
	}

	return resources
}

// analyzePolicy checks for security weaknesses in the policy
func (s *CloudArmorService) analyzePolicy(policy SecurityPolicy) []string {
	var weaknesses []string

	// Check if policy is attached to anything
	if len(policy.AttachedResources) == 0 {
		weaknesses = append(weaknesses, "Policy not attached to any backend service")
	}

	// Check for overly permissive rules
	hasDefaultAllow := false
	hasDenyRules := false
	previewOnlyCount := 0
	allowAllIPsCount := 0

	for _, rule := range policy.Rules {
		if rule.Priority == 2147483647 && rule.Action == "allow" {
			hasDefaultAllow = true
		}
		if strings.HasPrefix(rule.Action, "deny") {
			hasDenyRules = true
		}
		if rule.Preview {
			previewOnlyCount++
		}
		// Check for allow rules that match all IPs
		if rule.Action == "allow" && (rule.Match == "*" || rule.Match == "srcIpRanges: *" ||
			strings.Contains(rule.Match, "0.0.0.0/0") || rule.Match == "true") {
			allowAllIPsCount++
		}
	}

	if hasDefaultAllow && !hasDenyRules {
		weaknesses = append(weaknesses, "Default allow rule with no deny rules")
	}

	if previewOnlyCount > 0 {
		weaknesses = append(weaknesses, fmt.Sprintf("%d rule(s) in preview mode", previewOnlyCount))
	}

	if allowAllIPsCount > 0 && !hasDenyRules {
		weaknesses = append(weaknesses, "Has allow-all rules without deny rules")
	}

	// Check adaptive protection
	if !policy.AdaptiveProtection {
		weaknesses = append(weaknesses, "Adaptive protection not enabled")
	}

	// Check for common WAF rules
	hasOWASPRules := false
	for _, rule := range policy.Rules {
		matchLower := strings.ToLower(rule.Match)
		if strings.Contains(matchLower, "sqli") || strings.Contains(matchLower, "xss") ||
			strings.Contains(matchLower, "rce") || strings.Contains(matchLower, "lfi") {
			hasOWASPRules = true
			break
		}
	}

	if !hasOWASPRules {
		weaknesses = append(weaknesses, "No OWASP/WAF rules detected")
	}

	return weaknesses
}

// GetUnprotectedLoadBalancers finds load balancers without Cloud Armor protection
func (s *CloudArmorService) GetUnprotectedLoadBalancers(projectID string) ([]string, error) {
	ctx := context.Background()
	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	var unprotected []string

	// Get all backend services
	backendServices, err := service.BackendServices.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	for _, bs := range backendServices.Items {
		if bs.SecurityPolicy == "" {
			unprotected = append(unprotected, bs.Name)
		}
	}

	return unprotected, nil
}
