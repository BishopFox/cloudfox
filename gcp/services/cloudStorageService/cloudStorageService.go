package cloudstorageservice

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/iam"
	"cloud.google.com/go/storage"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	"google.golang.org/api/iterator"
	storageapi "google.golang.org/api/storage/v1"
)

type CloudStorageService struct {
	session *gcpinternal.SafeSession
}

// New creates a new CloudStorageService (requires session for SDK caching)
func New() *CloudStorageService {
	return &CloudStorageService{}
}

// NewWithSession creates a CloudStorageService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) *CloudStorageService {
	return &CloudStorageService{session: session}
}

// IAMBinding represents a single IAM binding on a bucket
type IAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// LifecycleRule represents a single lifecycle rule on a bucket
type LifecycleRule struct {
	Action              string `json:"action"`              // Delete, SetStorageClass, AbortIncompleteMultipartUpload
	StorageClass        string `json:"storageClass"`        // Target storage class (for SetStorageClass)
	AgeDays             int64  `json:"ageDays"`             // Age condition in days
	NumVersions         int64  `json:"numVersions"`         // Number of newer versions condition
	IsLive              *bool  `json:"isLive"`              // Whether object is live (vs archived)
	MatchesPrefix       string `json:"matchesPrefix"`       // Object name prefix match
	MatchesSuffix       string `json:"matchesSuffix"`       // Object name suffix match
	MatchesStorage      string `json:"matchesStorage"`      // Storage class match
	CreatedBefore       string `json:"createdBefore"`       // Created before date condition
	DaysSinceCustom     int64  `json:"daysSinceCustom"`     // Days since custom time
	DaysSinceNoncurrent int64  `json:"daysSinceNoncurrent"` // Days since became noncurrent
}

// BucketInfo contains bucket metadata and security-relevant configuration
type BucketInfo struct {
	// Basic info
	Name      string `json:"name"`
	Location  string `json:"location"`
	ProjectID string `json:"projectID"`

	// Security-relevant fields
	PublicAccessPrevention   string `json:"publicAccessPrevention"`   // "enforced", "inherited", or "unspecified"
	UniformBucketLevelAccess bool   `json:"uniformBucketLevelAccess"` // true = IAM only, no ACLs
	VersioningEnabled        bool   `json:"versioningEnabled"`        // Object versioning
	RequesterPays            bool   `json:"requesterPays"`            // Requester pays enabled
	DefaultEventBasedHold    bool   `json:"defaultEventBasedHold"`    // Event-based hold on new objects
	LoggingEnabled           bool   `json:"loggingEnabled"`           // Access logging enabled
	LogBucket                string `json:"logBucket"`                // Destination bucket for logs
	EncryptionType           string `json:"encryptionType"`           // "Google-managed", "CMEK", or "CSEK"
	KMSKeyName               string `json:"kmsKeyName"`               // KMS key for CMEK
	RetentionPolicyEnabled   bool   `json:"retentionPolicyEnabled"`   // Retention policy set
	RetentionPeriodDays      int64  `json:"retentionPeriodDays"`      // Retention period in days
	RetentionPolicyLocked    bool   `json:"retentionPolicyLocked"`    // Retention policy is locked (immutable)
	SoftDeleteEnabled        bool   `json:"softDeleteEnabled"`        // Soft delete policy enabled
	SoftDeleteRetentionDays  int64  `json:"softDeleteRetentionDays"`  // Soft delete retention in days
	StorageClass             string `json:"storageClass"`             // Default storage class
	AutoclassEnabled         bool   `json:"autoclassEnabled"`         // Autoclass feature enabled
	AutoclassTerminalClass   string `json:"autoclassTerminalClass"`   // Terminal storage class for autoclass

	// Lifecycle configuration
	LifecycleEnabled   bool            `json:"lifecycleEnabled"`   // Has lifecycle rules
	LifecycleRuleCount int             `json:"lifecycleRuleCount"` // Number of lifecycle rules
	LifecycleRules     []LifecycleRule `json:"lifecycleRules"`     // Parsed lifecycle rules
	HasDeleteRule      bool            `json:"hasDeleteRule"`      // Has a delete action rule
	HasArchiveRule     bool            `json:"hasArchiveRule"`     // Has a storage class transition rule
	ShortestDeleteDays int64           `json:"shortestDeleteDays"` // Shortest delete age in days
	TurboReplication   bool            `json:"turboReplication"`   // Turbo replication enabled (dual-region)
	LocationType       string          `json:"locationType"`       // "region", "dual-region", or "multi-region"

	// Public access indicators
	IsPublic     bool   `json:"isPublic"`     // Has allUsers or allAuthenticatedUsers
	PublicAccess string `json:"publicAccess"` // "None", "allUsers", "allAuthenticatedUsers", or "Both"

	// IAM Policy
	IAMBindings []IAMBinding `json:"iamBindings"` // IAM policy bindings on the bucket

	// Timestamps
	Created string `json:"created"`
	Updated string `json:"updated"`
}

func (cs *CloudStorageService) Buckets(projectID string) ([]BucketInfo, error) {
	ctx := context.Background()

	// Get cached client from SDK
	client, err := cs.getClient(ctx)
	if err != nil {
		return nil, err
	}

	var buckets []BucketInfo
	bucketIterator := client.Buckets(ctx, projectID)
	for {
		battrs, err := bucketIterator.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		bucket := BucketInfo{
			Name:      battrs.Name,
			Location:  battrs.Location,
			ProjectID: projectID,
		}

		// Security fields
		bucket.PublicAccessPrevention = publicAccessPreventionToString(battrs.PublicAccessPrevention)
		bucket.UniformBucketLevelAccess = battrs.UniformBucketLevelAccess.Enabled
		bucket.VersioningEnabled = battrs.VersioningEnabled
		bucket.RequesterPays = battrs.RequesterPays
		bucket.DefaultEventBasedHold = battrs.DefaultEventBasedHold
		bucket.StorageClass = battrs.StorageClass

		// Logging
		if battrs.Logging != nil {
			bucket.LoggingEnabled = battrs.Logging.LogBucket != ""
			bucket.LogBucket = battrs.Logging.LogBucket
		}

		// Encryption
		if battrs.Encryption != nil && battrs.Encryption.DefaultKMSKeyName != "" {
			bucket.EncryptionType = "CMEK"
			bucket.KMSKeyName = battrs.Encryption.DefaultKMSKeyName
		} else {
			bucket.EncryptionType = "Google-managed"
		}

		// Retention Policy
		if battrs.RetentionPolicy != nil {
			bucket.RetentionPolicyEnabled = true
			bucket.RetentionPeriodDays = int64(battrs.RetentionPolicy.RetentionPeriod.Hours() / 24)
			bucket.RetentionPolicyLocked = battrs.RetentionPolicy.IsLocked
		}

		// Autoclass
		if battrs.Autoclass != nil && battrs.Autoclass.Enabled {
			bucket.AutoclassEnabled = true
			bucket.AutoclassTerminalClass = battrs.Autoclass.TerminalStorageClass
		}

		// Timestamps
		if !battrs.Created.IsZero() {
			bucket.Created = battrs.Created.Format("2006-01-02")
		}

		// Get additional fields via REST API (SoftDeletePolicy, Updated)
		cs.enrichBucketFromRestAPI(ctx, &bucket)

		// Get IAM policy for the bucket
		iamBindings, isPublic, publicAccess := cs.getBucketIAMPolicy(ctx, client, battrs.Name)
		bucket.IAMBindings = iamBindings
		bucket.IsPublic = isPublic
		bucket.PublicAccess = publicAccess

		buckets = append(buckets, bucket)
	}
	return buckets, nil
}

// getClient returns a cached storage client from SDK
func (cs *CloudStorageService) getClient(ctx context.Context) (*storage.Client, error) {
	if cs.session != nil {
		return sdk.CachedGetStorageClient(ctx, cs.session)
	}
	// Fallback to direct creation for legacy usage (no caching)
	return storage.NewClient(ctx)
}

// getStorageService returns a cached storage REST API service from SDK
func (cs *CloudStorageService) getStorageService(ctx context.Context) (*storageapi.Service, error) {
	if cs.session != nil {
		return sdk.CachedGetStorageService(ctx, cs.session)
	}
	// Fallback to direct creation for legacy usage (no caching)
	return storageapi.NewService(ctx)
}

// getBucketIAMPolicy retrieves the IAM policy for a bucket and checks for public access
func (cs *CloudStorageService) getBucketIAMPolicy(ctx context.Context, client *storage.Client, bucketName string) ([]IAMBinding, bool, string) {
	var bindings []IAMBinding
	isPublic := false
	hasAllUsers := false
	hasAllAuthenticatedUsers := false

	policy, err := client.Bucket(bucketName).IAM().Policy(ctx)
	if err != nil {
		// Return empty bindings if we can't get the policy (permission denied, etc.)
		return bindings, false, "Unknown"
	}

	// Convert IAM policy to our binding format
	for _, role := range policy.Roles() {
		members := policy.Members(role)
		if len(members) > 0 {
			binding := IAMBinding{
				Role:    string(role),
				Members: make([]string, len(members)),
			}
			for i, member := range members {
				binding.Members[i] = member

				// Check for public access
				if member == string(iam.AllUsers) {
					hasAllUsers = true
					isPublic = true
				}
				if member == string(iam.AllAuthenticatedUsers) {
					hasAllAuthenticatedUsers = true
					isPublic = true
				}
			}
			bindings = append(bindings, binding)
		}
	}

	// Determine public access level
	publicAccess := "None"
	if hasAllUsers && hasAllAuthenticatedUsers {
		publicAccess = "allUsers + allAuthenticatedUsers"
	} else if hasAllUsers {
		publicAccess = "allUsers"
	} else if hasAllAuthenticatedUsers {
		publicAccess = "allAuthenticatedUsers"
	}

	return bindings, isPublic, publicAccess
}

// GetBucketIAMPolicyOnly retrieves just the IAM policy for a specific bucket
func (cs *CloudStorageService) GetBucketIAMPolicyOnly(bucketName string) ([]IAMBinding, error) {
	ctx := context.Background()

	client, err := cs.getClient(ctx)
	if err != nil {
		return nil, err
	}

	bindings, _, _ := cs.getBucketIAMPolicy(ctx, client, bucketName)
	return bindings, nil
}

// publicAccessPreventionToString converts the PublicAccessPrevention type to a readable string
func publicAccessPreventionToString(pap storage.PublicAccessPrevention) string {
	switch pap {
	case storage.PublicAccessPreventionEnforced:
		return "enforced"
	case storage.PublicAccessPreventionInherited:
		return "inherited"
	default:
		return "unspecified"
	}
}

// FormatIAMBindings formats IAM bindings for display
func FormatIAMBindings(bindings []IAMBinding) string {
	if len(bindings) == 0 {
		return "No IAM bindings"
	}

	var parts []string
	for _, binding := range bindings {
		memberStr := strings.Join(binding.Members, ", ")
		parts = append(parts, fmt.Sprintf("%s: [%s]", binding.Role, memberStr))
	}
	return strings.Join(parts, "; ")
}

// FormatIAMBindingsShort formats IAM bindings in a shorter format for table display
func FormatIAMBindingsShort(bindings []IAMBinding) string {
	if len(bindings) == 0 {
		return "-"
	}
	return fmt.Sprintf("%d binding(s)", len(bindings))
}

// enrichBucketFromRestAPI fetches additional bucket fields via the REST API
// that may not be available in the Go SDK version
func (cs *CloudStorageService) enrichBucketFromRestAPI(ctx context.Context, bucket *BucketInfo) {
	service, err := cs.getStorageService(ctx)
	if err != nil {
		// Silently fail - these are optional enrichments
		return
	}

	// Get bucket details via REST API
	restBucket, err := service.Buckets.Get(bucket.Name).Context(ctx).Do()
	if err != nil {
		// Silently fail - these are optional enrichments
		return
	}

	// Parse SoftDeletePolicy
	if restBucket.SoftDeletePolicy != nil {
		if restBucket.SoftDeletePolicy.RetentionDurationSeconds > 0 {
			bucket.SoftDeleteEnabled = true
			bucket.SoftDeleteRetentionDays = restBucket.SoftDeletePolicy.RetentionDurationSeconds / 86400 // seconds to days
		}
	}

	// Parse Updated timestamp
	if restBucket.Updated != "" {
		// REST API returns RFC3339 format
		if t, err := time.Parse(time.RFC3339, restBucket.Updated); err == nil {
			bucket.Updated = t.Format("2006-01-02")
		}
	}

	// Parse location type
	bucket.LocationType = restBucket.LocationType

	// Parse Turbo Replication (for dual-region buckets)
	if restBucket.Rpo == "ASYNC_TURBO" {
		bucket.TurboReplication = true
	}

	// Parse Lifecycle rules
	if restBucket.Lifecycle != nil && len(restBucket.Lifecycle.Rule) > 0 {
		bucket.LifecycleEnabled = true
		bucket.LifecycleRuleCount = len(restBucket.Lifecycle.Rule)
		bucket.ShortestDeleteDays = -1 // Initialize to -1 to indicate not set

		for _, rule := range restBucket.Lifecycle.Rule {
			lcRule := LifecycleRule{}

			// Parse action
			if rule.Action != nil {
				lcRule.Action = rule.Action.Type
				lcRule.StorageClass = rule.Action.StorageClass

				if rule.Action.Type == "Delete" {
					bucket.HasDeleteRule = true
				} else if rule.Action.Type == "SetStorageClass" {
					bucket.HasArchiveRule = true
				}
			}

			// Parse conditions
			if rule.Condition != nil {
				// Age is a pointer to int64
				if rule.Condition.Age != nil && *rule.Condition.Age > 0 {
					lcRule.AgeDays = *rule.Condition.Age
					// Track shortest delete age
					if lcRule.Action == "Delete" && (bucket.ShortestDeleteDays == -1 || *rule.Condition.Age < bucket.ShortestDeleteDays) {
						bucket.ShortestDeleteDays = *rule.Condition.Age
					}
				}
				if rule.Condition.NumNewerVersions > 0 {
					lcRule.NumVersions = rule.Condition.NumNewerVersions
				}
				if rule.Condition.IsLive != nil {
					lcRule.IsLive = rule.Condition.IsLive
				}
				if len(rule.Condition.MatchesPrefix) > 0 {
					lcRule.MatchesPrefix = strings.Join(rule.Condition.MatchesPrefix, ",")
				}
				if len(rule.Condition.MatchesSuffix) > 0 {
					lcRule.MatchesSuffix = strings.Join(rule.Condition.MatchesSuffix, ",")
				}
				if len(rule.Condition.MatchesStorageClass) > 0 {
					lcRule.MatchesStorage = strings.Join(rule.Condition.MatchesStorageClass, ",")
				}
				if rule.Condition.CreatedBefore != "" {
					lcRule.CreatedBefore = rule.Condition.CreatedBefore
				}
				if rule.Condition.DaysSinceCustomTime > 0 {
					lcRule.DaysSinceCustom = rule.Condition.DaysSinceCustomTime
				}
				if rule.Condition.DaysSinceNoncurrentTime > 0 {
					lcRule.DaysSinceNoncurrent = rule.Condition.DaysSinceNoncurrentTime
				}
			}

			bucket.LifecycleRules = append(bucket.LifecycleRules, lcRule)
		}

		// If no delete rule, reset to 0
		if bucket.ShortestDeleteDays == -1 {
			bucket.ShortestDeleteDays = 0
		}
	}
}
