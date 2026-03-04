package kmsservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	kms "google.golang.org/api/cloudkms/v1"
)

type KMSService struct{
	session *gcpinternal.SafeSession
}

func New() *KMSService {
	return &KMSService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *KMSService {
	return &KMSService{
		session: session,
	}
}

// getService returns a KMS service client using cached session if available
func (ks *KMSService) getService(ctx context.Context) (*kms.Service, error) {
	if ks.session != nil {
		return sdk.CachedGetKMSService(ctx, ks.session)
	}
	return kms.NewService(ctx)
}

// KeyRingInfo holds KMS key ring details
type KeyRingInfo struct {
	Name        string
	ProjectID   string
	Location    string
	CreateTime  string

	// Keys in this key ring
	KeyCount    int
}

// IAMBinding represents a single IAM role binding
type IAMBinding struct {
	Role   string
	Member string
}

// CryptoKeyInfo holds KMS crypto key details with security-relevant information
type CryptoKeyInfo struct {
	Name              string
	ProjectID         string
	Location          string
	KeyRing           string
	Purpose           string  // ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT, MAC
	CreateTime        string

	// Version info
	PrimaryVersion    string
	PrimaryState      string
	VersionCount      int

	// Security configuration
	RotationPeriod    string
	NextRotationTime  string
	DestroyScheduledDuration string
	ProtectionLevel   string  // SOFTWARE, HSM, EXTERNAL, EXTERNAL_VPC

	// Import info (indicates external key import)
	ImportOnly        bool

	// Labels
	Labels            map[string]string

	// IAM
	IAMBindings       []IAMBinding
	IsPublicEncrypt   bool
	IsPublicDecrypt   bool
}

// KeyRings retrieves all KMS key rings in a project
func (ks *KMSService) KeyRings(projectID string) ([]KeyRingInfo, error) {
	ctx := context.Background()

	service, err := ks.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudkms.googleapis.com")
	}

	var keyRings []KeyRingInfo

	// List key rings across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)

	call := service.Projects.Locations.KeyRings.List(parent)
	err = call.Pages(ctx, func(page *kms.ListKeyRingsResponse) error {
		for _, kr := range page.KeyRings {
			info := parseKeyRingInfo(kr, projectID)

			// Get key count for this key ring
			keyCount, _ := ks.getKeyCount(service, kr.Name)
			info.KeyCount = keyCount

			keyRings = append(keyRings, info)
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudkms.googleapis.com")
	}

	return keyRings, nil
}

// CryptoKeys retrieves all crypto keys in a project
func (ks *KMSService) CryptoKeys(projectID string) ([]CryptoKeyInfo, error) {
	ctx := context.Background()

	service, err := ks.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudkms.googleapis.com")
	}

	var keys []CryptoKeyInfo

	// First get all key rings
	keyRings, err := ks.KeyRings(projectID)
	if err != nil {
		return nil, err
	}

	// Then get keys from each key ring
	for _, kr := range keyRings {
		keyRingName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", projectID, kr.Location, kr.Name)

		call := service.Projects.Locations.KeyRings.CryptoKeys.List(keyRingName)
		err = call.Pages(ctx, func(page *kms.ListCryptoKeysResponse) error {
			for _, key := range page.CryptoKeys {
				info := parseCryptoKeyInfo(key, projectID, kr.Location, kr.Name)

				// Try to get IAM policy
				iamPolicy, iamErr := ks.getKeyIAMPolicy(service, key.Name)
				if iamErr == nil && iamPolicy != nil {
					info.IAMBindings, info.IsPublicEncrypt, info.IsPublicDecrypt = parseKeyBindings(iamPolicy)
				}

				keys = append(keys, info)
			}
			return nil
		})

		if err != nil {
			// Log but continue with other key rings
			_ = err // Error from listing keys in this key ring - permission or API issue
			continue
		}
	}

	return keys, nil
}

// parseKeyRingInfo extracts relevant information from a KMS key ring
func parseKeyRingInfo(kr *kms.KeyRing, projectID string) KeyRingInfo {
	info := KeyRingInfo{
		Name:       extractName(kr.Name),
		ProjectID:  projectID,
		CreateTime: kr.CreateTime,
	}

	// Extract location from key ring name
	// Format: projects/{project}/locations/{location}/keyRings/{keyRing}
	parts := strings.Split(kr.Name, "/")
	if len(parts) >= 4 {
		info.Location = parts[3]
	}

	return info
}

// parseCryptoKeyInfo extracts relevant information from a KMS crypto key
func parseCryptoKeyInfo(key *kms.CryptoKey, projectID, location, keyRing string) CryptoKeyInfo {
	info := CryptoKeyInfo{
		Name:        extractName(key.Name),
		ProjectID:   projectID,
		Location:    location,
		KeyRing:     keyRing,
		Purpose:     key.Purpose,
		CreateTime:  key.CreateTime,
		Labels:      key.Labels,
		ImportOnly:  key.ImportOnly,
	}

	// Rotation configuration
	if key.RotationPeriod != "" {
		info.RotationPeriod = key.RotationPeriod
	}
	if key.NextRotationTime != "" {
		info.NextRotationTime = key.NextRotationTime
	}

	// Destroy scheduled duration
	if key.DestroyScheduledDuration != "" {
		info.DestroyScheduledDuration = key.DestroyScheduledDuration
	}

	// Primary version info
	if key.Primary != nil {
		info.PrimaryVersion = extractVersionNumber(key.Primary.Name)
		info.PrimaryState = key.Primary.State
		info.ProtectionLevel = key.Primary.ProtectionLevel
	}

	// Version template for protection level
	if info.ProtectionLevel == "" && key.VersionTemplate != nil {
		info.ProtectionLevel = key.VersionTemplate.ProtectionLevel
	}

	return info
}

// getKeyCount gets the number of crypto keys in a key ring
func (ks *KMSService) getKeyCount(service *kms.Service, keyRingName string) (int, error) {
	ctx := context.Background()
	count := 0

	call := service.Projects.Locations.KeyRings.CryptoKeys.List(keyRingName)
	err := call.Pages(ctx, func(page *kms.ListCryptoKeysResponse) error {
		count += len(page.CryptoKeys)
		return nil
	})

	if err != nil {
		return 0, err
	}

	return count, nil
}

// getKeyIAMPolicy retrieves the IAM policy for a crypto key
func (ks *KMSService) getKeyIAMPolicy(service *kms.Service, keyName string) (*kms.Policy, error) {
	ctx := context.Background()

	policy, err := service.Projects.Locations.KeyRings.CryptoKeys.GetIamPolicy(keyName).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	return policy, nil
}

// parseKeyBindings extracts all IAM bindings and checks for public access
func parseKeyBindings(policy *kms.Policy) (bindings []IAMBinding, publicEncrypt bool, publicDecrypt bool) {
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			bindings = append(bindings, IAMBinding{
				Role:   binding.Role,
				Member: member,
			})

			// Check for public access on encrypt/decrypt roles
			if member == "allUsers" || member == "allAuthenticatedUsers" {
				switch binding.Role {
				case "roles/cloudkms.cryptoKeyEncrypter":
					publicEncrypt = true
				case "roles/cloudkms.cryptoKeyDecrypter":
					publicDecrypt = true
				case "roles/cloudkms.cryptoKeyEncrypterDecrypter":
					publicEncrypt = true
					publicDecrypt = true
				}
			}
		}
	}
	return
}

// extractName extracts just the resource name from the full resource name
func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// extractVersionNumber extracts the version number from a crypto key version name
func extractVersionNumber(versionName string) string {
	parts := strings.Split(versionName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return versionName
}
