package secretservice

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	"github.com/googleapis/gax-go/v2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
)

// Wrappers and abstracting types to facilitate mocking the client responses
type Iterator interface {
	Next() (*secretmanagerpb.Secret, error)
}

type SecretsManagerClientWrapper struct {
	Closer       func() error
	SecretLister func(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) Iterator
	IAMGetter    func(ctx context.Context, secretName string) (*secretmanagerpb.Secret, error)
	rawClient    *secretmanager.Client
}

func (w *SecretsManagerClientWrapper) Close() error {
	return w.Closer()
}

func (w *SecretsManagerClientWrapper) ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) Iterator {
	return w.SecretLister(ctx, req, opts...)
}

type SecretsService struct {
	Client  *SecretsManagerClientWrapper
	session *gcpinternal.SafeSession
}

// getClient returns a cached Secret Manager client
func (s *SecretsService) getClient(ctx context.Context) (*secretmanager.Client, error) {
	if s.session != nil {
		return sdk.CachedGetSecretManagerClient(ctx, s.session)
	}
	return secretmanager.NewClient(ctx)
}

// New creates a SecretsService with the provided client
func New(client *secretmanager.Client) SecretsService {
	ss := SecretsService{
		Client: &SecretsManagerClientWrapper{
			Closer: client.Close,
			SecretLister: func(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) Iterator {
				return client.ListSecrets(ctx, req, opts...)
			},
			rawClient: client,
		},
	}
	return ss
}

// NewWithSession creates a SecretsService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) (SecretsService, error) {
	ctx := context.Background()
	ss := SecretsService{
		session: session,
	}

	client, err := ss.getClient(ctx)
	if err != nil {
		return SecretsService{}, gcpinternal.ParseGCPError(err, "secretmanager.googleapis.com")
	}

	ss.Client = &SecretsManagerClientWrapper{
		Closer: client.Close,
		SecretLister: func(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) Iterator {
			return client.ListSecrets(ctx, req, opts...)
		},
		rawClient: client,
	}
	return ss, nil
}

// IAMBinding represents a single IAM binding on a secret
type IAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// SecretInfo contains secret metadata and security-relevant configuration
type SecretInfo struct {
	// Basic info
	Name      string `json:"name"`
	ProjectID string `json:"projectID"`

	// Timestamps
	CreationTime string `json:"creationTime"`

	// Replication
	ReplicationType string   `json:"replicationType"` // "automatic" or "user-managed"
	ReplicaLocations []string `json:"replicaLocations,omitempty"` // Locations for user-managed replication

	// Encryption
	EncryptionType string `json:"encryptionType"` // "Google-managed" or "CMEK"
	KMSKeyName     string `json:"kmsKeyName,omitempty"` // KMS key for CMEK

	// Expiration
	HasExpiration  bool   `json:"hasExpiration"`
	ExpireTime     string `json:"expireTime,omitempty"`
	TTL            string `json:"ttl,omitempty"`

	// Rotation
	Rotation         string `json:"rotation,omitempty"`
	NextRotationTime string `json:"nextRotationTime,omitempty"`
	RotationPeriod   string `json:"rotationPeriod,omitempty"`

	// Version Management
	VersionDestroyTTL string `json:"versionDestroyTtl,omitempty"` // Delayed destruction

	// Metadata
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`

	// Topics (Pub/Sub notifications)
	Topics []string `json:"topics,omitempty"`

	// Version Aliases
	VersionAliases map[string]int64 `json:"versionAliases,omitempty"`

	// IAM Policy
	IAMBindings []IAMBinding `json:"iamBindings,omitempty"`
}

func (ss *SecretsService) Secrets(projectID string) ([]SecretInfo, error) {
	var secrets []SecretInfo
	req := &secretmanagerpb.ListSecretsRequest{
		Parent: fmt.Sprintf("projects/%s", projectID),
	}

	ctx := context.Background()
	it := ss.Client.ListSecrets(ctx, req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, gcpinternal.ParseGCPError(err, "secretmanager.googleapis.com")
		}

		secret := SecretInfo{
			Name:         resp.Name,
			ProjectID:    projectID,
			CreationTime: resp.CreateTime.AsTime().Format(time.RFC3339),
			Labels:       resp.Labels,
			Annotations:  resp.Annotations,
		}

		// Parse replication type
		if resp.Replication != nil {
			switch r := resp.Replication.Replication.(type) {
			case *secretmanagerpb.Replication_Automatic_:
				secret.ReplicationType = "automatic"
				// Check for CMEK in automatic replication
				if r.Automatic != nil && r.Automatic.CustomerManagedEncryption != nil {
					secret.EncryptionType = "CMEK"
					secret.KMSKeyName = r.Automatic.CustomerManagedEncryption.KmsKeyName
				} else {
					secret.EncryptionType = "Google-managed"
				}
			case *secretmanagerpb.Replication_UserManaged_:
				secret.ReplicationType = "user-managed"
				if r.UserManaged != nil {
					for _, replica := range r.UserManaged.Replicas {
						secret.ReplicaLocations = append(secret.ReplicaLocations, replica.Location)
						// Check for CMEK in user-managed replication
						if replica.CustomerManagedEncryption != nil {
							secret.EncryptionType = "CMEK"
							secret.KMSKeyName = replica.CustomerManagedEncryption.KmsKeyName
						}
					}
				}
				if secret.EncryptionType == "" {
					secret.EncryptionType = "Google-managed"
				}
			}
		}

		// Parse expiration
		if resp.Expiration != nil {
			secret.HasExpiration = true
			switch e := resp.Expiration.(type) {
			case *secretmanagerpb.Secret_ExpireTime:
				if e.ExpireTime != nil {
					secret.ExpireTime = e.ExpireTime.AsTime().Format(time.RFC3339)
				}
			case *secretmanagerpb.Secret_Ttl:
				if e.Ttl != nil {
					secret.TTL = e.Ttl.AsDuration().String()
				}
			}
		}

		// Parse rotation
		if resp.Rotation != nil {
			secret.Rotation = "enabled"
			if resp.Rotation.NextRotationTime != nil {
				secret.NextRotationTime = resp.Rotation.NextRotationTime.AsTime().Format(time.RFC3339)
			}
			if resp.Rotation.RotationPeriod != nil {
				secret.RotationPeriod = resp.Rotation.RotationPeriod.AsDuration().String()
			}
		} else {
			secret.Rotation = "disabled"
		}

		// Get VersionDestroyTTL via REST API (may not be available in all SDK versions)
		ss.enrichSecretFromRestAPI(ctx, &secret)

		// Parse topics
		if len(resp.Topics) > 0 {
			for _, topic := range resp.Topics {
				secret.Topics = append(secret.Topics, topic.Name)
			}
		}

		// Parse version aliases
		if len(resp.VersionAliases) > 0 {
			secret.VersionAliases = resp.VersionAliases
		}

		// Get IAM policy for the secret
		iamBindings := ss.getSecretIAMPolicy(ctx, resp.Name)
		secret.IAMBindings = iamBindings

		secrets = append(secrets, secret)
	}
	return secrets, nil
}

// getSecretIAMPolicy retrieves the IAM policy for a secret
func (ss *SecretsService) getSecretIAMPolicy(ctx context.Context, secretName string) []IAMBinding {
	var bindings []IAMBinding

	if ss.Client.rawClient == nil {
		return bindings
	}

	// Get IAM policy using the raw client
	policy, err := ss.Client.rawClient.IAM(secretName).Policy(ctx)
	if err != nil {
		// Return empty bindings if we can't get the policy (permission denied, etc.)
		return bindings
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
			}
			bindings = append(bindings, binding)
		}
	}

	return bindings
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

// secretAPIResponse represents the raw JSON response from Secret Manager API
// to capture fields that may not be in the SDK yet
type secretAPIResponse struct {
	VersionDestroyTtl string `json:"versionDestroyTtl,omitempty"`
}

// enrichSecretFromRestAPI fetches additional secret fields via direct HTTP request
// that may not be available in the Go SDK version
func (ss *SecretsService) enrichSecretFromRestAPI(ctx context.Context, secret *SecretInfo) {
	var accessToken string

	// Try to use session token if available
	if ss.session != nil {
		token, err := ss.session.GetToken(ctx)
		if err == nil {
			accessToken = token
		}
	}

	// Fall back to default credentials if no session token
	if accessToken == "" {
		creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			return
		}
		token, err := creds.TokenSource.Token()
		if err != nil {
			return
		}
		accessToken = token.AccessToken
	}

	// Build the API URL
	// Secret name format: projects/{project}/secrets/{secret}
	url := fmt.Sprintf("https://secretmanager.googleapis.com/v1/%s", secret.Name)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Make request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	// Parse JSON
	var apiResp secretAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return
	}

	// Parse VersionDestroyTTL
	if apiResp.VersionDestroyTtl != "" {
		// Parse duration string (e.g., "86400s" for 1 day)
		if dur, err := time.ParseDuration(apiResp.VersionDestroyTtl); err == nil {
			secret.VersionDestroyTTL = dur.String()
		} else {
			// If parsing fails, use the raw value
			secret.VersionDestroyTTL = apiResp.VersionDestroyTtl
		}
	}
}
