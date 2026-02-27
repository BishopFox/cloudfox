package hmacservice

import (
	"context"
	"fmt"
	"time"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	"google.golang.org/api/storage/v1"
)

type HMACService struct {
	session *gcpinternal.SafeSession
}

func New() *HMACService {
	return &HMACService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *HMACService {
	return &HMACService{session: session}
}

// getStorageService returns a Storage service client using cached session if available
func (s *HMACService) getStorageService(ctx context.Context) (*storage.Service, error) {
	if s.session != nil {
		return sdk.CachedGetStorageService(ctx, s.session)
	}
	return storage.NewService(ctx)
}

// HMACKeyInfo represents a GCS HMAC key (S3-compatible access)
type HMACKeyInfo struct {
	AccessID           string    `json:"accessId"`
	ProjectID          string    `json:"projectId"`
	ServiceAccountEmail string   `json:"serviceAccountEmail"`
	State              string    `json:"state"`              // ACTIVE, INACTIVE, DELETED
	TimeCreated        time.Time `json:"timeCreated"`
	Updated            time.Time `json:"updated"`
	Etag               string    `json:"etag"`
	// Pentest-specific fields
	IsActive           bool      `json:"isActive"`
	RiskLevel          string    `json:"riskLevel"`
	RiskReasons        []string  `json:"riskReasons"`
}

// ListHMACKeys lists all HMAC keys in a project
func (s *HMACService) ListHMACKeys(projectID string) ([]HMACKeyInfo, error) {
	ctx := context.Background()

	storageService, err := s.getStorageService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "storage.googleapis.com")
	}

	var keys []HMACKeyInfo

	// List all HMAC keys for the project
	req := storageService.Projects.HmacKeys.List(projectID)
	err = req.Pages(ctx, func(page *storage.HmacKeysMetadata) error {
		for _, key := range page.Items {
			info := s.parseHMACKey(key, projectID)
			keys = append(keys, info)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "storage.googleapis.com")
	}

	return keys, nil
}

func (s *HMACService) parseHMACKey(key *storage.HmacKeyMetadata, projectID string) HMACKeyInfo {
	info := HMACKeyInfo{
		AccessID:            key.AccessId,
		ProjectID:           projectID,
		ServiceAccountEmail: key.ServiceAccountEmail,
		State:               key.State,
		Etag:                key.Etag,
		IsActive:            key.State == "ACTIVE",
		RiskReasons:         []string{},
	}

	// Parse timestamps
	if key.TimeCreated != "" {
		if t, err := time.Parse(time.RFC3339, key.TimeCreated); err == nil {
			info.TimeCreated = t
		}
	}
	if key.Updated != "" {
		if t, err := time.Parse(time.RFC3339, key.Updated); err == nil {
			info.Updated = t
		}
	}

	// Analyze risk
	info.RiskLevel, info.RiskReasons = s.analyzeHMACKeyRisk(info)

	return info
}

func (s *HMACService) analyzeHMACKeyRisk(key HMACKeyInfo) (string, []string) {
	var reasons []string
	score := 0

	// Active keys are more risky
	if key.IsActive {
		reasons = append(reasons, "HMAC key is ACTIVE (can be used for S3-compatible access)")
		score += 2
	}

	// Check key age
	if !key.TimeCreated.IsZero() {
		age := time.Since(key.TimeCreated)
		if age > 365*24*time.Hour {
			reasons = append(reasons, fmt.Sprintf("Key is over 1 year old (%d days)", int(age.Hours()/24)))
			score += 2
		} else if age > 90*24*time.Hour {
			reasons = append(reasons, fmt.Sprintf("Key is over 90 days old (%d days)", int(age.Hours()/24)))
			score += 1
		}
	}

	// Default compute SA HMAC keys are especially risky
	if key.ServiceAccountEmail != "" {
		if isDefaultComputeSA(key.ServiceAccountEmail) {
			reasons = append(reasons, "HMAC key belongs to default compute service account")
			score += 1
		}
	}

	if score >= 4 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func isDefaultComputeSA(email string) bool {
	// Check for default compute service account pattern
	return len(email) > 0 &&
		(contains(email, "-compute@developer.gserviceaccount.com") ||
		 contains(email, "@appspot.gserviceaccount.com"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
