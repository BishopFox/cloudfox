package bucketenumservice

import (
	"context"
	"fmt"
	"strings"

	"github.com/BishopFox/cloudfox/gcp/shared"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	"google.golang.org/api/iterator"
	"google.golang.org/api/storage/v1"
)

type BucketEnumService struct {
	session *gcpinternal.SafeSession
}

func New() *BucketEnumService {
	return &BucketEnumService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *BucketEnumService {
	return &BucketEnumService{session: session}
}

// getStorageService returns a Storage service client using cached session if available
func (s *BucketEnumService) getStorageService(ctx context.Context) (*storage.Service, error) {
	if s.session != nil {
		return sdk.CachedGetStorageService(ctx, s.session)
	}
	return storage.NewService(ctx)
}

// SensitiveFileInfo represents a potentially sensitive file in a bucket
type SensitiveFileInfo struct {
	BucketName   string `json:"bucketName"`
	ObjectName   string `json:"objectName"`
	ProjectID    string `json:"projectId"`
	Size         int64  `json:"size"`
	ContentType  string `json:"contentType"`
	Category     string `json:"category"`     // credential, secret, config, backup, etc.
	RiskLevel    string `json:"riskLevel"`    // CRITICAL, HIGH, MEDIUM, LOW
	Description  string `json:"description"`  // Why it's sensitive
	DownloadCmd  string `json:"downloadCmd"`  // gsutil command to download
	Updated      string `json:"updated"`
	StorageClass string `json:"storageClass"`
	IsPublic     bool   `json:"isPublic"`     // Whether the object has public access
	Encryption   string `json:"encryption"`   // Encryption type (Google-managed or CMEK key name)
}

// EnumerateBucketSensitiveFiles lists potentially sensitive files in a bucket
func (s *BucketEnumService) EnumerateBucketSensitiveFiles(bucketName, projectID string, maxObjects int) ([]SensitiveFileInfo, error) {
	ctx := context.Background()

	storageService, err := s.getStorageService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "storage.googleapis.com")
	}

	var sensitiveFiles []SensitiveFileInfo
	patterns := shared.GetFilePatterns()

	// List objects in the bucket
	req := storageService.Objects.List(bucketName)
	if maxObjects > 0 {
		req = req.MaxResults(int64(maxObjects))
	}

	err = req.Pages(ctx, func(objects *storage.Objects) error {
		for _, obj := range objects.Items {
			// Check against sensitive patterns
			if info := s.checkObjectSensitivity(obj, bucketName, projectID, patterns); info != nil {
				sensitiveFiles = append(sensitiveFiles, *info)
			}
		}
		return nil
	})

	if err != nil && err != iterator.Done {
		return nil, gcpinternal.ParseGCPError(err, "storage.googleapis.com")
	}

	return sensitiveFiles, nil
}

func (s *BucketEnumService) checkObjectSensitivity(obj *storage.Object, bucketName, projectID string, patterns []shared.SensitivePattern) *SensitiveFileInfo {
	if obj == nil {
		return nil
	}

	match := shared.MatchFileName(obj.Name, patterns)
	if match == nil {
		return nil
	}

	isPublic := s.isObjectPublic(obj)

	return &SensitiveFileInfo{
		BucketName:   bucketName,
		ObjectName:   obj.Name,
		ProjectID:    projectID,
		Size:         int64(obj.Size),
		ContentType:  obj.ContentType,
		Category:     match.Category,
		RiskLevel:    match.RiskLevel,
		Description:  match.Description,
		DownloadCmd:  fmt.Sprintf("gsutil cp gs://%s/%s .", bucketName, obj.Name),
		Updated:      obj.Updated,
		StorageClass: obj.StorageClass,
		IsPublic:     isPublic,
		Encryption:   s.getObjectEncryption(obj),
	}
}

// isObjectPublic checks if an object has public access via ACLs
func (s *BucketEnumService) isObjectPublic(obj *storage.Object) bool {
	if obj == nil || obj.Acl == nil {
		return false
	}

	for _, acl := range obj.Acl {
		// Check for public access entities
		if acl.Entity == "allUsers" || acl.Entity == "allAuthenticatedUsers" {
			return true
		}
	}

	return false
}

// getObjectEncryption returns the encryption type for an object
// Returns "CMEK (key-name)" if using customer-managed key, or "Google-managed" otherwise
func (s *BucketEnumService) getObjectEncryption(obj *storage.Object) string {
	if obj == nil {
		return "Google-managed"
	}

	// Check if the object uses a customer-managed encryption key (CMEK)
	if obj.KmsKeyName != "" {
		// Extract just the key name from the full resource path
		// Format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}/cryptoKeyVersions/{version}
		keyParts := strings.Split(obj.KmsKeyName, "/")
		if len(keyParts) >= 8 {
			// Get the key name (index 7 is cryptoKeys/{key})
			keyName := keyParts[7]
			return fmt.Sprintf("CMEK (%s)", keyName)
		}
		return "CMEK"
	}

	// Default is Google-managed encryption
	return "Google-managed"
}

// ObjectInfo represents any file in a bucket (for full enumeration)
type ObjectInfo struct {
	BucketName   string `json:"bucketName"`
	ObjectName   string `json:"objectName"`
	ProjectID    string `json:"projectId"`
	Size         int64  `json:"size"`
	ContentType  string `json:"contentType"`
	Updated      string `json:"updated"`
	StorageClass string `json:"storageClass"`
	IsPublic     bool   `json:"isPublic"`
	DownloadCmd  string `json:"downloadCmd"`
	Encryption   string `json:"encryption"` // Encryption type (Google-managed or CMEK key name)
}

// EnumerateAllBucketObjects lists ALL objects in a bucket (no filtering)
func (s *BucketEnumService) EnumerateAllBucketObjects(bucketName, projectID string, maxObjects int) ([]ObjectInfo, error) {
	ctx := context.Background()

	storageService, err := s.getStorageService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "storage.googleapis.com")
	}

	var objects []ObjectInfo
	objectCount := 0

	// List objects in the bucket
	req := storageService.Objects.List(bucketName)

	err = req.Pages(ctx, func(objList *storage.Objects) error {
		for _, obj := range objList.Items {
			if maxObjects > 0 && objectCount >= maxObjects {
				return iterator.Done
			}

			isPublic := s.isObjectPublic(obj)

			objects = append(objects, ObjectInfo{
				BucketName:   bucketName,
				ObjectName:   obj.Name,
				ProjectID:    projectID,
				Size:         int64(obj.Size),
				ContentType:  obj.ContentType,
				Updated:      obj.Updated,
				StorageClass: obj.StorageClass,
				IsPublic:     isPublic,
				DownloadCmd:  fmt.Sprintf("gsutil cp gs://%s/%s .", bucketName, obj.Name),
				Encryption:   s.getObjectEncryption(obj),
			})
			objectCount++
		}
		return nil
	})

	if err != nil && err != iterator.Done {
		return nil, gcpinternal.ParseGCPError(err, "storage.googleapis.com")
	}

	return objects, nil
}

// GetBucketsList lists all buckets in a project
func (s *BucketEnumService) GetBucketsList(projectID string) ([]string, error) {
	ctx := context.Background()

	storageService, err := s.getStorageService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "storage.googleapis.com")
	}

	var buckets []string
	err = storageService.Buckets.List(projectID).Pages(ctx, func(bucketList *storage.Buckets) error {
		for _, bucket := range bucketList.Items {
			buckets = append(buckets, bucket.Name)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "storage.googleapis.com")
	}

	return buckets, nil
}
