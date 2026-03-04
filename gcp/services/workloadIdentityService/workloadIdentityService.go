package workloadidentityservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	iam "google.golang.org/api/iam/v1"
)

type WorkloadIdentityService struct{
	session *gcpinternal.SafeSession
}

func New() *WorkloadIdentityService {
	return &WorkloadIdentityService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *WorkloadIdentityService {
	return &WorkloadIdentityService{
		session: session,
	}
}

// getIAMService returns an IAM service client using cached session if available
func (s *WorkloadIdentityService) getIAMService(ctx context.Context) (*iam.Service, error) {
	if s.session != nil {
		return sdk.CachedGetIAMService(ctx, s.session)
	}
	return iam.NewService(ctx)
}

// WorkloadIdentityPool represents a Workload Identity Pool
type WorkloadIdentityPool struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	ProjectID   string `json:"projectId"`
	State       string `json:"state"`
	Disabled    bool   `json:"disabled"`
	PoolID      string `json:"poolId"`
}

// WorkloadIdentityProvider represents a Workload Identity Pool Provider
type WorkloadIdentityProvider struct {
	Name               string            `json:"name"`
	DisplayName        string            `json:"displayName"`
	Description        string            `json:"description"`
	PoolID             string            `json:"poolId"`
	ProviderID         string            `json:"providerId"`
	ProjectID          string            `json:"projectId"`
	ProviderType       string            `json:"providerType"` // aws, oidc, saml
	Disabled           bool              `json:"disabled"`
	AttributeMapping   map[string]string `json:"attributeMapping"`
	AttributeCondition string            `json:"attributeCondition"` // CEL expression
	// AWS specific
	AWSAccountID string `json:"awsAccountId"`
	// OIDC specific
	OIDCIssuerURI    string   `json:"oidcIssuerUri"`
	AllowedAudiences []string `json:"allowedAudiences"`
}

// FederatedIdentityBinding represents a binding from federated identity to GCP SA
type FederatedIdentityBinding struct {
	ProjectID          string `json:"projectId"`
	PoolID             string `json:"poolId"`
	ProviderID         string `json:"providerId"`
	GCPServiceAccount  string `json:"gcpServiceAccount"`
	ExternalSubject    string `json:"externalSubject"`
	AttributeCondition string `json:"attributeCondition"`
}

// ListWorkloadIdentityPools lists all Workload Identity Pools in a project
func (s *WorkloadIdentityService) ListWorkloadIdentityPools(projectID string) ([]WorkloadIdentityPool, error) {
	ctx := context.Background()

	iamService, err := s.getIAMService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "iam.googleapis.com")
	}

	var pools []WorkloadIdentityPool
	parent := fmt.Sprintf("projects/%s/locations/global", projectID)

	req := iamService.Projects.Locations.WorkloadIdentityPools.List(parent)
	err = req.Pages(ctx, func(page *iam.ListWorkloadIdentityPoolsResponse) error {
		for _, pool := range page.WorkloadIdentityPools {
			// Extract pool ID from name
			// Format: projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID
			poolID := extractLastPart(pool.Name)

			pools = append(pools, WorkloadIdentityPool{
				Name:        pool.Name,
				DisplayName: pool.DisplayName,
				Description: pool.Description,
				ProjectID:   projectID,
				State:       pool.State,
				Disabled:    pool.Disabled,
				PoolID:      poolID,
			})
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "iam.googleapis.com")
	}

	return pools, nil
}

// ListWorkloadIdentityProviders lists all providers in a pool
func (s *WorkloadIdentityService) ListWorkloadIdentityProviders(projectID, poolID string) ([]WorkloadIdentityProvider, error) {
	ctx := context.Background()

	iamService, err := s.getIAMService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "iam.googleapis.com")
	}

	var providers []WorkloadIdentityProvider
	parent := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s", projectID, poolID)

	req := iamService.Projects.Locations.WorkloadIdentityPools.Providers.List(parent)
	err = req.Pages(ctx, func(page *iam.ListWorkloadIdentityPoolProvidersResponse) error {
		for _, provider := range page.WorkloadIdentityPoolProviders {
			// Extract provider ID from name
			providerID := extractLastPart(provider.Name)

			wip := WorkloadIdentityProvider{
				Name:               provider.Name,
				DisplayName:        provider.DisplayName,
				Description:        provider.Description,
				PoolID:             poolID,
				ProviderID:         providerID,
				ProjectID:          projectID,
				Disabled:           provider.Disabled,
				AttributeMapping:   provider.AttributeMapping,
				AttributeCondition: provider.AttributeCondition,
			}

			// Determine provider type and extract specific config
			if provider.Aws != nil {
				wip.ProviderType = "AWS"
				wip.AWSAccountID = provider.Aws.AccountId
			} else if provider.Oidc != nil {
				wip.ProviderType = "OIDC"
				wip.OIDCIssuerURI = provider.Oidc.IssuerUri
				wip.AllowedAudiences = provider.Oidc.AllowedAudiences
			} else if provider.Saml != nil {
				wip.ProviderType = "SAML"
			}

			providers = append(providers, wip)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "iam.googleapis.com")
	}

	return providers, nil
}

// FindFederatedIdentityBindings finds all service accounts with federated identity bindings
func (s *WorkloadIdentityService) FindFederatedIdentityBindings(projectID string, pools []WorkloadIdentityPool) ([]FederatedIdentityBinding, error) {
	ctx := context.Background()

	iamService, err := s.getIAMService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "iam.googleapis.com")
	}

	var bindings []FederatedIdentityBinding

	// List all service accounts
	parent := fmt.Sprintf("projects/%s", projectID)
	saReq := iamService.Projects.ServiceAccounts.List(parent)
	err = saReq.Pages(ctx, func(page *iam.ListServiceAccountsResponse) error {
		for _, sa := range page.Accounts {
			// Get IAM policy for this service account
			policyReq := iamService.Projects.ServiceAccounts.GetIamPolicy(sa.Name)
			policy, pErr := policyReq.Do()
			if pErr != nil {
				continue
			}

			// Look for federated identity bindings
			for _, binding := range policy.Bindings {
				if binding.Role == "roles/iam.workloadIdentityUser" {
					for _, member := range binding.Members {
						// Check if this is a federated identity
						// Format: principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/subject/SUBJECT
						// Or: principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/attribute.ATTR/VALUE
						if strings.HasPrefix(member, "principal://") || strings.HasPrefix(member, "principalSet://") {
							fib := s.parseFederatedIdentityBinding(member, sa.Email, projectID)
							if fib != nil {
								bindings = append(bindings, *fib)
							}
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "iam.googleapis.com")
	}

	return bindings, nil
}

// parseFederatedIdentityBinding parses a federated identity member string
func (s *WorkloadIdentityService) parseFederatedIdentityBinding(member, gcpSA, projectID string) *FederatedIdentityBinding {
	// principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/subject/SUBJECT
	// principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/attribute.ATTR/VALUE

	fib := &FederatedIdentityBinding{
		ProjectID:         projectID,
		GCPServiceAccount: gcpSA,
		ExternalSubject:   member,
	}

	// Extract pool ID
	if idx := strings.Index(member, "workloadIdentityPools/"); idx != -1 {
		rest := member[idx+len("workloadIdentityPools/"):]
		if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
			fib.PoolID = rest[:slashIdx]
		}
	}

	return fib
}

// extractLastPart extracts the last part of a resource name
func extractLastPart(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return name
}
