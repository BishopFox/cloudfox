package apikeysservice

import (
	"context"
	"fmt"
	"strings"
	"time"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	apikeys "google.golang.org/api/apikeys/v2"
)

type APIKeysService struct {
	session *gcpinternal.SafeSession
}

// New creates a new APIKeysService
func New() *APIKeysService {
	return &APIKeysService{}
}

// NewWithSession creates an APIKeysService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) *APIKeysService {
	return &APIKeysService{session: session}
}

// getService returns an API Keys service client using cached session if available
func (s *APIKeysService) getService(ctx context.Context) (*apikeys.Service, error) {
	if s.session != nil {
		return sdk.CachedGetAPIKeysService(ctx, s.session)
	}
	return apikeys.NewService(ctx)
}

// APIKeyInfo represents information about an API key
type APIKeyInfo struct {
	Name           string            `json:"name"`           // Full resource name
	UID            string            `json:"uid"`            // Unique identifier
	DisplayName    string            `json:"displayName"`    // User-friendly name
	KeyString      string            `json:"keyString"`      // The actual key value (if accessible)
	ProjectID      string            `json:"projectId"`
	CreateTime     time.Time         `json:"createTime"`
	UpdateTime     time.Time         `json:"updateTime"`
	DeleteTime     time.Time         `json:"deleteTime"`
	Annotations    map[string]string `json:"annotations"`

	// Restrictions
	HasRestrictions    bool     `json:"hasRestrictions"`
	AllowedAPIs        []string `json:"allowedApis"`        // API targets
	AllowedReferers    []string `json:"allowedReferers"`    // HTTP referer restrictions
	AllowedIPs         []string `json:"allowedIps"`         // IP restrictions
	AllowedAndroidApps []string `json:"allowedAndroidApps"` // Android app restrictions
	AllowedIOSApps     []string `json:"allowedIosApps"`     // iOS app restrictions
	RestrictionType    string   `json:"restrictionType"`    // "browser", "server", "android", "ios", "none"

	// Security Analysis
	IsUnrestricted bool   `json:"isUnrestricted"` // No restrictions at all
	RiskLevel      string `json:"riskLevel"`      // HIGH, MEDIUM, LOW
	RiskReasons    []string `json:"riskReasons"`
}

// ListAPIKeys retrieves all API keys in a project
func (s *APIKeysService) ListAPIKeys(projectID string) ([]APIKeyInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "apikeys.googleapis.com")
	}

	var keys []APIKeyInfo
	parent := fmt.Sprintf("projects/%s/locations/global", projectID)

	req := service.Projects.Locations.Keys.List(parent)
	err = req.Pages(ctx, func(page *apikeys.V2ListKeysResponse) error {
		for _, key := range page.Keys {
			keyInfo := s.parseAPIKey(key, projectID)
			keys = append(keys, keyInfo)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "apikeys.googleapis.com")
	}

	return keys, nil
}

// GetAPIKey retrieves a single API key with its key string
func (s *APIKeysService) GetAPIKey(keyName string) (*APIKeyInfo, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "apikeys.googleapis.com")
	}

	key, err := service.Projects.Locations.Keys.Get(keyName).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "apikeys.googleapis.com")
	}

	// Extract project ID from key name
	// Format: projects/{project}/locations/global/keys/{key}
	parts := strings.Split(keyName, "/")
	projectID := ""
	if len(parts) >= 2 {
		projectID = parts[1]
	}

	keyInfo := s.parseAPIKey(key, projectID)
	return &keyInfo, nil
}

// GetKeyString retrieves the key string value for an API key
func (s *APIKeysService) GetKeyString(keyName string) (string, error) {
	ctx := context.Background()

	service, err := s.getService(ctx)
	if err != nil {
		return "", gcpinternal.ParseGCPError(err, "apikeys.googleapis.com")
	}

	resp, err := service.Projects.Locations.Keys.GetKeyString(keyName).Context(ctx).Do()
	if err != nil {
		return "", gcpinternal.ParseGCPError(err, "apikeys.googleapis.com")
	}

	return resp.KeyString, nil
}

// parseAPIKey converts an API key response to APIKeyInfo
func (s *APIKeysService) parseAPIKey(key *apikeys.V2Key, projectID string) APIKeyInfo {
	info := APIKeyInfo{
		Name:        key.Name,
		UID:         key.Uid,
		DisplayName: key.DisplayName,
		ProjectID:   projectID,
		Annotations: key.Annotations,
		RiskReasons: []string{},
	}

	// Parse times
	if key.CreateTime != "" {
		if t, err := time.Parse(time.RFC3339, key.CreateTime); err == nil {
			info.CreateTime = t
		}
	}
	if key.UpdateTime != "" {
		if t, err := time.Parse(time.RFC3339, key.UpdateTime); err == nil {
			info.UpdateTime = t
		}
	}
	if key.DeleteTime != "" {
		if t, err := time.Parse(time.RFC3339, key.DeleteTime); err == nil {
			info.DeleteTime = t
		}
	}

	// Parse restrictions
	if key.Restrictions != nil {
		info.HasRestrictions = true

		// API restrictions
		if key.Restrictions.ApiTargets != nil {
			for _, target := range key.Restrictions.ApiTargets {
				info.AllowedAPIs = append(info.AllowedAPIs, target.Service)
			}
		}

		// Browser restrictions (HTTP referers)
		if key.Restrictions.BrowserKeyRestrictions != nil {
			info.RestrictionType = "browser"
			info.AllowedReferers = key.Restrictions.BrowserKeyRestrictions.AllowedReferrers
		}

		// Server restrictions (IPs)
		if key.Restrictions.ServerKeyRestrictions != nil {
			info.RestrictionType = "server"
			info.AllowedIPs = key.Restrictions.ServerKeyRestrictions.AllowedIps
		}

		// Android restrictions
		if key.Restrictions.AndroidKeyRestrictions != nil {
			info.RestrictionType = "android"
			for _, app := range key.Restrictions.AndroidKeyRestrictions.AllowedApplications {
				info.AllowedAndroidApps = append(info.AllowedAndroidApps,
					fmt.Sprintf("%s:%s", app.PackageName, app.Sha1Fingerprint))
			}
		}

		// iOS restrictions
		if key.Restrictions.IosKeyRestrictions != nil {
			info.RestrictionType = "ios"
			info.AllowedIOSApps = key.Restrictions.IosKeyRestrictions.AllowedBundleIds
		}

		// Check if truly restricted
		if len(info.AllowedAPIs) == 0 &&
		   len(info.AllowedReferers) == 0 &&
		   len(info.AllowedIPs) == 0 &&
		   len(info.AllowedAndroidApps) == 0 &&
		   len(info.AllowedIOSApps) == 0 {
			info.HasRestrictions = false
			info.IsUnrestricted = true
		}
	} else {
		info.IsUnrestricted = true
		info.RestrictionType = "none"
	}

	// Security analysis
	info.RiskLevel, info.RiskReasons = s.analyzeAPIKeyRisk(info)

	return info
}

// analyzeAPIKeyRisk determines the risk level of an API key
func (s *APIKeysService) analyzeAPIKeyRisk(key APIKeyInfo) (string, []string) {
	var reasons []string
	score := 0

	// Unrestricted keys are high risk
	if key.IsUnrestricted {
		reasons = append(reasons, "No restrictions applied - key can be used from anywhere")
		score += 4
	}

	// No API restrictions
	if len(key.AllowedAPIs) == 0 && !key.IsUnrestricted {
		reasons = append(reasons, "No API restrictions - key can access all enabled APIs")
		score += 2
	}

	// Overly permissive API access
	for _, api := range key.AllowedAPIs {
		if strings.Contains(api, "admin") || strings.Contains(api, "iam") {
			reasons = append(reasons, fmt.Sprintf("Has access to sensitive API: %s", api))
			score += 2
		}
	}

	// Wildcard in referers
	for _, referer := range key.AllowedReferers {
		if referer == "*" || referer == "*.com" {
			reasons = append(reasons, fmt.Sprintf("Overly permissive referer: %s", referer))
			score += 2
		}
	}

	// 0.0.0.0/0 in IPs
	for _, ip := range key.AllowedIPs {
		if ip == "0.0.0.0/0" || ip == "::/0" {
			reasons = append(reasons, "Allows access from any IP (0.0.0.0/0)")
			score += 3
		}
	}

	// Old keys
	if !key.CreateTime.IsZero() {
		age := time.Since(key.CreateTime)
		if age > 365*24*time.Hour {
			reasons = append(reasons, fmt.Sprintf("Key is older than 1 year (%d days)", int(age.Hours()/24)))
			score += 1
		}
	}

	// Determine risk level
	if score >= 4 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}

	return "INFO", reasons
}

// ListAPIKeysWithKeyStrings retrieves all API keys with their key strings
func (s *APIKeysService) ListAPIKeysWithKeyStrings(projectID string) ([]APIKeyInfo, error) {
	keys, err := s.ListAPIKeys(projectID)
	if err != nil {
		return nil, err
	}

	// Try to get key strings for each key
	for i := range keys {
		keyString, err := s.GetKeyString(keys[i].Name)
		if err != nil {
			// Skip - we might not have permission to get key strings
			continue
		}
		keys[i].KeyString = keyString
	}

	return keys, nil
}
